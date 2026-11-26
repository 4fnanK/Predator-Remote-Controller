//! Minimal file logger with size-based rotation and secret redaction.
//!
//! * `predator.log`  — operational log (1 MiB, one rotated backup).
//! * `security.log`  — unauthorized Telegram access attempts, IPC denials, feature changes
//!   (1 MiB, three rotated backups). Lines caused by unauthenticated parties go through
//!   [`security_untrusted`], which is rate-limited per source and globally so nobody can flush
//!   the audit trail by flooding it.
//!
//! Every line passes through [`redact`] so a Telegram bot token can never be written to disk.
//! [`report_system_event`] writes to the Windows Application event log for failures that happen
//! before (or without) the file logger.
//!
//! Flood protection for the operational log ([`FloodGuard`]), so a bug that loops cannot burn CPU
//! on log I/O or rotate the useful history away:
//! * an identical consecutive line (same level and text) within [`REPEAT_WINDOW_SECS`] is only
//!   counted; "… previous message repeated N times" is written when the run ends (another line)
//!   or when the line recurs after the window (then it is written again with a fresh timestamp).
//!   There is no timer: a run that ends in silence is summarised with the next line, and such a
//!   late summary adds "(last at <time>)";
//! * at most [`SITE_LINES_PER_MINUTE`] lines per call site (`file:line` of the `log_*!` macro,
//!   or the text for direct [`log`] calls) per minute; the rest is counted and reported once the
//!   minute is over.
//!
//! Security lines ([`security`], [`security_untrusted`]) never pass through it: they keep their
//! own rules (never limited / per-source limits).
//!
//! Cost of a suppressed line: the `log_*!` macros first ask [`level_enabled`] (one relaxed atomic
//! load) and only then evaluate their arguments and format them (`format_args!`, no `String`
//! when the line is below the configured level, no logger lock).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

const MAX_LOG_BYTES: u64 = 1024 * 1024;
/// Rotated generations kept for `predator.log`.
const MAIN_BACKUPS: u32 = 1;
/// Rotated generations kept for `security.log` (`security.log.1` … `security.log.3`).
const SECURITY_BACKUPS: u32 = 3;

/// Lines per untrusted source per hour before further lines are only counted.
pub(crate) const UNTRUSTED_PER_SOURCE_PER_HOUR: u32 = 20;
/// Untrusted lines per minute over all sources.
pub(crate) const UNTRUSTED_GLOBAL_PER_MINUTE: u32 = 30;
/// Distinct sources tracked individually (the rest share one bucket), bounding memory.
const MAX_TRACKED_SOURCES: usize = 256;
const SOURCE_WINDOW_SECS: i64 = 3600;
const GLOBAL_WINDOW_SECS: i64 = 60;
/// Bucket for sources beyond [`MAX_TRACKED_SOURCES`].
const OVERFLOW_SOURCE: &str = "(other sources)";

/// Identical consecutive lines within this many seconds are counted instead of written.
pub(crate) const REPEAT_WINDOW_SECS: i64 = 60;
/// Lines per call site per minute before further lines from it are only counted.
pub(crate) const SITE_LINES_PER_MINUTE: u32 = 200;
const SITE_WINDOW_SECS: i64 = 60;
/// Distinct call sites tracked individually (the rest share one bucket), bounding memory.
const MAX_TRACKED_SITES: usize = 512;
/// Bucket for call sites beyond [`MAX_TRACKED_SITES`].
const OVERFLOW_SITE: &str = "(other call sites)";
/// Characters of a message shown when a direct [`log`] call (no call site) is rate-limited.
const TEXT_KEY_CHARS: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

/// Lowest level written (mirrors `Logger::min_level`, readable without the logger lock).
static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Would a line at `level` be written? One relaxed atomic load: the `log_*!` macros call it
/// before evaluating or formatting their arguments.
#[inline]
pub fn level_enabled(level: Level) -> bool {
    level as u8 >= MIN_LEVEL.load(Ordering::Relaxed)
}

/// Set the lowest level written (both the lock-free fast path and the logger itself).
fn set_min_level(l: &mut Logger, level: Level) {
    l.min_level = level;
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }
}

/// `<file>.N` for rotation generation `n` (e.g. `security.log.2`).
fn backup_path(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

struct Sink {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    backups: u32,
}

impl Sink {
    fn open(path: PathBuf, backups: u32) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(&path).ok();
        let written = file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()).unwrap_or(0);
        Self { path, file, written, backups: backups.max(1) }
    }

    fn rotate(&mut self) {
        self.file = None;
        let _ = std::fs::remove_file(backup_path(&self.path, self.backups));
        for n in (1..self.backups).rev() {
            let _ = std::fs::rename(backup_path(&self.path, n), backup_path(&self.path, n + 1));
        }
        let _ = std::fs::rename(&self.path, backup_path(&self.path, 1));
        *self = Sink::open(self.path.clone(), self.backups);
        self.written = 0;
    }

    fn write_line(&mut self, line: &str) {
        if self.written + line.len() as u64 > MAX_LOG_BYTES {
            self.rotate();
        }
        if let Some(f) = self.file.as_mut()
            && f.write_all(line.as_bytes()).is_ok()
        {
            self.written += line.len() as u64;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Rate limiting of security lines from unauthenticated sources
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct SourceWindow {
    start: i64,
    logged: u32,
    suppressed: u32,
}

/// Decision for one untrusted security line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitVerdict {
    /// Write the line itself.
    pub log: bool,
    /// Summary lines to write first (suppression counts of windows that just ended).
    pub summaries: Vec<String>,
}

/// Fixed-window limiter: at most [`UNTRUSTED_PER_SOURCE_PER_HOUR`] lines per source per hour and
/// [`UNTRUSTED_GLOBAL_PER_MINUTE`] lines per minute overall. Suppressed lines are counted and
/// reported as one summary line when their window ends (on the next untrusted line).
#[derive(Debug)]
pub(crate) struct SecurityLimiter {
    sources: BTreeMap<String, SourceWindow>,
    global: SourceWindow,
    last_sweep: i64,
}

impl SecurityLimiter {
    pub const fn new() -> Self {
        Self { sources: BTreeMap::new(), global: SourceWindow { start: 0, logged: 0, suppressed: 0 }, last_sweep: 0 }
    }

    fn expired(w: &SourceWindow, now: i64, len: i64) -> bool {
        now - w.start >= len || now < w.start
    }

    /// End expired per-source windows (at most once a minute): summaries for the suppressed ones.
    fn sweep(&mut self, now: i64, out: &mut Vec<String>) {
        if now - self.last_sweep < GLOBAL_WINDOW_SECS && now >= self.last_sweep {
            return;
        }
        self.last_sweep = now;
        self.sources.retain(|source, w| {
            if !Self::expired(w, now, SOURCE_WINDOW_SECS) {
                return true;
            }
            if w.suppressed > 0 {
                out.push(format!(
                    "rate limit: {} more security line(s) from {source} were not logged (limit {} per hour)",
                    w.suppressed, UNTRUSTED_PER_SOURCE_PER_HOUR
                ));
            }
            false
        });
    }

    pub fn check(&mut self, source: &str, now: i64) -> LimitVerdict {
        let mut summaries = Vec::new();
        self.sweep(now, &mut summaries);
        if Self::expired(&self.global, now, GLOBAL_WINDOW_SECS) {
            if self.global.suppressed > 0 {
                summaries.push(format!(
                    "rate limit: {} security line(s) from unauthenticated sources were not logged in the previous \
                     minute (limit {} per minute)",
                    self.global.suppressed, UNTRUSTED_GLOBAL_PER_MINUTE
                ));
            }
            self.global = SourceWindow { start: now, logged: 0, suppressed: 0 };
        }
        let key = if self.sources.contains_key(source) || self.sources.len() < MAX_TRACKED_SOURCES {
            source
        } else {
            OVERFLOW_SOURCE
        };
        let w = self.sources.entry(key.to_string()).or_insert(SourceWindow { start: now, logged: 0, suppressed: 0 });
        if Self::expired(w, now, SOURCE_WINDOW_SECS) {
            if w.suppressed > 0 {
                summaries.push(format!(
                    "rate limit: {} more security line(s) from {key} were not logged (limit {} per hour)",
                    w.suppressed, UNTRUSTED_PER_SOURCE_PER_HOUR
                ));
            }
            *w = SourceWindow { start: now, logged: 0, suppressed: 0 };
        }
        let log = if w.logged >= UNTRUSTED_PER_SOURCE_PER_HOUR {
            w.suppressed += 1;
            false
        } else if self.global.logged >= UNTRUSTED_GLOBAL_PER_MINUTE {
            // Counted globally only, so the per-source quota is not used up by unlogged lines.
            self.global.suppressed += 1;
            false
        } else {
            w.logged += 1;
            self.global.logged += 1;
            true
        };
        LimitVerdict { log, summaries }
    }
}

// ---------------------------------------------------------------------------------------------
// Flood protection of the operational log
// ---------------------------------------------------------------------------------------------

/// The last line written, and how often it was repeated since (not written).
#[derive(Debug)]
struct Run {
    level: Level,
    text: String,
    /// When the line was written (the repeat window starts here).
    start: i64,
    /// When it was last repeated.
    last: i64,
    repeats: u32,
}

/// Decision for one operational log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admission {
    /// Write the line itself.
    pub write: bool,
    /// Summary lines to write first (in order).
    pub before: Vec<(Level, String)>,
}

/// A repeat summary is only written when the next line arrives, which can be hours after the
/// last repeat; written this many seconds (or more) late, it names the time of the last repeat
/// so its own timestamp cannot be mistaken for when the repeats happened.
const LATE_SUMMARY_SECS: i64 = 2;

/// Summary of a run of `n` suppressed repeats, the last one at `last`, written at `now`.
fn repeated_text(n: u32, last: i64, now: i64) -> String {
    let mut s = format!("… previous message repeated {n} {}", if n == 1 { "time" } else { "times" });
    if now - last >= LATE_SUMMARY_SECS || now < last {
        s.push_str(&format!(" (last at {})", local_time(last)));
    }
    s
}

fn window_expired(start: i64, now: i64, len: i64) -> bool {
    now - start >= len || now < start
}

/// Suppresses identical consecutive lines and caps the lines per call site per minute. Pure
/// (time is passed in) so the rules are unit-testable; [`log_at`] applies it under the logger
/// lock.
#[derive(Debug)]
pub(crate) struct FloodGuard {
    run: Option<Run>,
    /// Per call site (or per message text) fixed one-minute windows.
    sites: BTreeMap<String, SourceWindow>,
    last_sweep: i64,
}

impl FloodGuard {
    pub const fn new() -> Self {
        Self { run: None, sites: BTreeMap::new(), last_sweep: 0 }
    }

    /// Label used in the rate-limit summary for a key.
    fn key_label(site: &str, text: &str) -> String {
        if site.is_empty() {
            format!("\"{}\"", crate::util::truncate_chars(text, TEXT_KEY_CHARS))
        } else {
            site.to_string()
        }
    }

    fn site_summary(label: &str, n: u32) -> (Level, String) {
        (
            Level::Warn,
            format!(
                "rate limit: {n} more line(s) from {label} were not logged in the previous minute (limit \
                 {SITE_LINES_PER_MINUTE} per minute)"
            ),
        )
    }

    /// End the current run of repeats: its summary (if any lines were suppressed) goes to `out`.
    fn end_run(&mut self, now: i64, out: &mut Vec<(Level, String)>) {
        if let Some(r) = self.run.take()
            && r.repeats > 0
        {
            out.push((r.level, repeated_text(r.repeats, r.last, now)));
        }
    }

    /// Report and forget expired per-site windows (at most once a minute).
    fn sweep(&mut self, now: i64, out: &mut Vec<(Level, String)>) {
        if !window_expired(self.last_sweep, now, SITE_WINDOW_SECS) {
            return;
        }
        self.last_sweep = now;
        self.sites.retain(|label, w| {
            if !window_expired(w.start, now, SITE_WINDOW_SECS) {
                return true;
            }
            if w.suppressed > 0 {
                out.push(Self::site_summary(label, w.suppressed));
            }
            false
        });
    }

    /// Decide about one line. `site` is the call site (`file:line`), empty when unknown (the
    /// text is the key then); `text` is the final (redacted) message.
    pub fn admit(&mut self, level: Level, site: &str, text: &str, now: i64) -> Admission {
        let mut before = Vec::new();
        // 1. identical consecutive line: count it while its window lasts
        if let Some(r) = self.run.as_mut()
            && r.level == level
            && r.text == text
            && !window_expired(r.start, now, REPEAT_WINDOW_SECS)
        {
            r.repeats = r.repeats.saturating_add(1);
            r.last = now;
            return Admission { write: false, before };
        }
        self.end_run(now, &mut before);
        self.sweep(now, &mut before);
        // 2. per-site cap
        let label = Self::key_label(site, text);
        let key = if self.sites.contains_key(&label) || self.sites.len() < MAX_TRACKED_SITES {
            label
        } else {
            OVERFLOW_SITE.to_string()
        };
        let w = self.sites.entry(key.clone()).or_insert(SourceWindow { start: now, logged: 0, suppressed: 0 });
        if window_expired(w.start, now, SITE_WINDOW_SECS) {
            if w.suppressed > 0 {
                before.push(Self::site_summary(&key, w.suppressed));
            }
            *w = SourceWindow { start: now, logged: 0, suppressed: 0 };
        }
        if w.logged >= SITE_LINES_PER_MINUTE {
            w.suppressed = w.suppressed.saturating_add(1);
            // a line that is not written cannot be "repeated": the next one starts afresh
            return Admission { write: false, before };
        }
        w.logged += 1;
        self.run = Some(Run { level, text: text.to_string(), start: now, last: now, repeats: 0 });
        Admission { write: true, before }
    }

    /// End the current run of repeats (e.g. before a security line interrupts the sequence) and
    /// return its summary line, if any.
    pub fn flush(&mut self, now: i64) -> Vec<(Level, String)> {
        let mut out = Vec::new();
        self.end_run(now, &mut out);
        out
    }
}

struct Logger {
    main: Option<Sink>,
    security: Option<Sink>,
    stderr: bool,
    min_level: Level,
    limiter: SecurityLimiter,
    guard: FloodGuard,
}

static LOGGER: Mutex<Logger> = Mutex::new(Logger {
    main: None,
    security: None,
    stderr: false,
    min_level: Level::Info,
    limiter: SecurityLimiter::new(),
    guard: FloodGuard::new(),
});

/// Initialise logging into `logs_dir`. When `also_stderr` is set (console mode) lines are echoed.
pub fn init(logs_dir: &Path, also_stderr: bool, verbose: bool) {
    let _ = std::fs::create_dir_all(logs_dir);
    let mut l = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    l.main = Some(Sink::open(logs_dir.join("predator.log"), MAIN_BACKUPS));
    l.security = Some(Sink::open(logs_dir.join("security.log"), SECURITY_BACKUPS));
    l.stderr = also_stderr;
    set_min_level(&mut l, if verbose { Level::Debug } else { Level::Info });
}

/// Echo to stderr only (CLI tools before the data directory is known).
pub fn init_stderr_only(verbose: bool) {
    let mut l = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    l.stderr = true;
    set_min_level(&mut l, if verbose { Level::Debug } else { Level::Info });
}

fn timestamp() -> String {
    local_time(crate::util::time::now_unix())
}

/// `YYYY-MM-DD hh:mm:ss` local time of a Unix time.
fn local_time(unix: i64) -> String {
    let t = crate::util::time::to_local(unix);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second)
}

/// Remove anything that looks like a Telegram bot token (`<digits>:<35 base64url chars>`).
pub fn redact(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        // find a run of digits followed by ':' and >= 30 token chars
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - i >= 6 && j < bytes.len() && bytes[j] == b':' {
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_' || bytes[k] == b'-') {
                    k += 1;
                }
                if k - (j + 1) >= 30 {
                    out.push_str("[REDACTED-TOKEN]");
                    i = k;
                    continue;
                }
            }
            out.push_str(&s[i..j]);
            i = j;
            continue;
        }
        let ch = s[i..].chars().next().unwrap_or('?');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Log a message at `level` (no call site: the flood guard keys the per-minute cap on the text).
pub fn log(level: Level, msg: &str) {
    log_at(level, "", msg);
}

/// Log a message at `level` from call site `site` (`file:line`).
pub fn log_at(level: Level, site: &str, msg: &str) {
    if !level_enabled(level) {
        return;
    }
    let now = crate::util::time::now_unix();
    let mut l = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    log_into(&mut l, level, site, msg, now);
}

/// Used by the `log_*!` macros (after their [`level_enabled`] check): formats `args` only now,
/// and without an allocation when the message is a plain literal.
pub fn log_args(level: Level, site: &str, args: std::fmt::Arguments<'_>) {
    if !level_enabled(level) {
        return;
    }
    match args.as_str() {
        Some(literal) => log_at(level, site, literal),
        None => log_at(level, site, &std::fmt::format(args)),
    }
}

/// Write one operational line through the flood guard (`now` = Unix seconds).
fn log_into(l: &mut Logger, level: Level, site: &str, msg: &str, now: i64) {
    if level < l.min_level {
        return;
    }
    let text = redact(msg);
    let adm = l.guard.admit(level, site, &text, now);
    if adm.before.is_empty() && !adm.write {
        return;
    }
    let ts = timestamp();
    for (lv, s) in &adm.before {
        write_main(l, &ts, *lv, s);
    }
    if adm.write {
        write_main(l, &ts, level, &text);
    }
}

/// Write an (already redacted) operational line to stderr (console mode) and `predator.log`.
fn write_main(l: &mut Logger, ts: &str, level: Level, text: &str) {
    let line = format!("{ts} {} {text}\r\n", level.as_str());
    if l.stderr {
        eprint!("{line}");
    }
    if let Some(s) = l.main.as_mut() {
        s.write_line(&line);
    }
}

fn write_security(l: &mut Logger, msg: &str) {
    // a security line interrupts any run of repeated operational lines: report it first
    let pending = l.guard.flush(crate::util::time::now_unix());
    if !pending.is_empty() {
        let ts = timestamp();
        for (lv, s) in &pending {
            write_main(l, &ts, *lv, s);
        }
    }
    let line = format!("{} SECURITY {}\r\n", timestamp(), redact(msg));
    if l.stderr {
        eprint!("{line}");
    }
    if let Some(s) = l.security.as_mut() {
        s.write_line(&line);
    }
    if let Some(s) = l.main.as_mut() {
        s.write_line(&line);
    }
}

/// Append to the security audit log (and the main log). For events caused by the owner, an
/// administrator or the service itself; never rate-limited.
pub fn security(msg: &str) {
    let mut l = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    write_security(&mut l, msg);
}

/// Append a security line caused by an unauthenticated party (an unknown Telegram user, a
/// denied IPC caller). `source` identifies that party (e.g. `tg:12345`, `ipc:S-1-5-21-…`).
/// Rate-limited per source and globally; suppressed lines are summarised later.
pub fn security_untrusted(source: &str, msg: &str) {
    let now = crate::util::time::now_unix();
    let mut l = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    let verdict = l.limiter.check(source, now);
    for s in &verdict.summaries {
        write_security(&mut l, s);
    }
    if verdict.log {
        write_security(&mut l, msg);
    }
}

/// Severity of a Windows event log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Error,
    Warning,
    Information,
}

/// Event id used for every entry (the source has no message file; the text is the insert string).
const EVENT_ID: u32 = 1000;

/// Write `msg` to the Windows Application event log (source `PredatorRemoteController`) and to
/// the debugger output. Used for failures that happen before the file logger works (e.g. the
/// data directory cannot be created), so a service that keeps failing to start is never silent.
/// Best effort: errors are ignored.
pub fn report_system_event(kind: EventKind, msg: &str) {
    use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
        RegisterEventSourceW, ReportEventW,
    };
    let text = crate::util::truncate_chars(&redact(msg), 16_000);
    let wide_text = crate::util::win::wide(&format!("{}: {text}", crate::paths::SERVICE_NAME));
    // SAFETY: NUL-terminated string.
    unsafe { OutputDebugStringW(wide_text.as_ptr()) };
    let source = crate::util::win::wide(crate::paths::SERVICE_NAME);
    // SAFETY: local event log (NULL server) and a NUL-terminated source name.
    let h = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if h.is_null() {
        return;
    }
    let ty = match kind {
        EventKind::Error => EVENTLOG_ERROR_TYPE,
        EventKind::Warning => EVENTLOG_WARNING_TYPE,
        EventKind::Information => EVENTLOG_INFORMATION_TYPE,
    };
    let body = crate::util::win::wide(&text);
    let strings = [body.as_ptr()];
    // SAFETY: valid event source handle; one NUL-terminated insert string; no raw data.
    unsafe {
        ReportEventW(h, ty, 0, EVENT_ID, std::ptr::null_mut(), 1, 0, strings.as_ptr(), std::ptr::null());
        DeregisterEventSource(h);
    }
}

// The macros pass their call site so the flood guard can cap a looping line per location. The
// level is checked first: a suppressed line neither evaluates nor formats its arguments.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_with_level {
    ($level:expr, $($t:tt)*) => {{
        if $crate::logging::level_enabled($level) {
            $crate::logging::log_args($level, concat!(file!(), ":", line!()), format_args!($($t)*));
        }
    }};
}
#[macro_export]
macro_rules! log_debug { ($($t:tt)*) => { $crate::__log_with_level!($crate::logging::Level::Debug, $($t)*) } }
#[macro_export]
macro_rules! log_info { ($($t:tt)*) => { $crate::__log_with_level!($crate::logging::Level::Info, $($t)*) } }
#[macro_export]
macro_rules! log_warn { ($($t:tt)*) => { $crate::__log_with_level!($crate::logging::Level::Warn, $($t)*) } }
#[macro_export]
macro_rules! log_error { ($($t:tt)*) => { $crate::__log_with_level!($crate::logging::Level::Error, $($t)*) } }

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that change the global minimum level run one at a time.
    static LEVEL_TESTS: Mutex<()> = Mutex::new(());

    /// The macros check the level before evaluating/formatting their arguments: a suppressed
    /// debug line costs one atomic load (no String, no lock, no side effects of the arguments).
    #[test]
    fn suppressed_levels_do_not_format() {
        use std::sync::atomic::AtomicU32;
        static EVALUATED: AtomicU32 = AtomicU32::new(0);
        fn costly() -> &'static str {
            EVALUATED.fetch_add(1, Ordering::SeqCst);
            "x"
        }
        // (the global logger has no sink in tests)
        let _serial = LEVEL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        MIN_LEVEL.store(Level::Info as u8, Ordering::Relaxed);
        assert!(!level_enabled(Level::Debug));
        assert!(level_enabled(Level::Info) && level_enabled(Level::Warn) && level_enabled(Level::Error));
        crate::log_debug!("not written {}", costly());
        assert_eq!(EVALUATED.load(Ordering::SeqCst), 0, "arguments of a suppressed line are not evaluated");
        crate::log_info!("written {}", costly());
        assert_eq!(EVALUATED.load(Ordering::SeqCst), 1);
        // verbose: debug lines are formatted and passed on
        MIN_LEVEL.store(Level::Debug as u8, Ordering::Relaxed);
        crate::log_debug!("now written {}", costly());
        assert_eq!(EVALUATED.load(Ordering::SeqCst), 2);
        // the macros still work in expression position (match arms) and with inline captures
        let level = "captured";
        let r: Result<(), ()> = Err(());
        match r {
            Ok(()) => crate::log_debug!("never"),
            Err(()) => crate::log_warn!("inline {level} {}", 5),
        }
        // the level-checked entry points agree with the macros
        log_args(Level::Debug, "t.rs:1", format_args!("literal"));
        MIN_LEVEL.store(Level::Error as u8, Ordering::Relaxed);
        assert!(!level_enabled(Level::Warn) && level_enabled(Level::Error));
        MIN_LEVEL.store(Level::Info as u8, Ordering::Relaxed);
    }

    #[test]
    fn set_min_level_updates_both_checks() {
        let _serial = LEVEL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("predator-lvl-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut l = test_logger(&dir);
        set_min_level(&mut l, Level::Debug);
        assert_eq!(l.min_level, Level::Debug);
        assert!(level_enabled(Level::Debug));
        log_into(&mut l, Level::Debug, "x.rs:1", "verbose line", T0);
        set_min_level(&mut l, Level::Info);
        assert!(!level_enabled(Level::Debug));
        log_into(&mut l, Level::Debug, "x.rs:2", "hidden line", T0 + 1);
        drop(l);
        let text = std::fs::read_to_string(dir.join("predator.log")).unwrap();
        assert!(text.contains("DEBUG verbose line") && !text.contains("hidden line"), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn redacts_tokens() {
        let t = "url https://api.telegram.org/bot1234567890:AAFakeTokenForTestsOnly_0123456789a/getMe failed";
        let r = redact(t);
        assert!(!r.contains("AAFakeTo"));
        assert!(r.contains("[REDACTED-TOKEN]"));
        assert_eq!(redact("user 12345 at 14:30:25"), "user 12345 at 14:30:25");
        assert_eq!(redact("ünïcødé 123"), "ünïcødé 123");
    }

    #[test]
    fn per_source_limit_and_summary() {
        let mut l = SecurityLimiter::new();
        let t0 = 1_800_000_000;
        // spread over time so the global per-minute cap does not interfere
        for i in 0..UNTRUSTED_PER_SOURCE_PER_HOUR {
            let v = l.check("ipc:S-1", t0 + i as i64 * 61);
            assert!(v.log && v.summaries.is_empty(), "line {i}");
        }
        let t1 = t0 + UNTRUSTED_PER_SOURCE_PER_HOUR as i64 * 61;
        for _ in 0..5 {
            assert!(!l.check("ipc:S-1", t1).log);
        }
        // other sources are unaffected
        assert!(l.check("tg:42", t1).log);
        // after the hour: one summary, logging resumes
        let v = l.check("ipc:S-1", t0 + SOURCE_WINDOW_SECS + 5);
        assert!(v.log);
        assert_eq!(v.summaries.len(), 1, "{:?}", v.summaries);
        assert!(v.summaries[0].contains("5 more") && v.summaries[0].contains("ipc:S-1"), "{:?}", v.summaries);
    }

    #[test]
    fn global_limit_per_minute() {
        let mut l = SecurityLimiter::new();
        let t0 = 1_800_000_000;
        let mut logged = 0;
        for i in 0..100 {
            if l.check(&format!("ipc:S-{i}"), t0).log {
                logged += 1;
            }
        }
        assert_eq!(logged, UNTRUSTED_GLOBAL_PER_MINUTE);
        let v = l.check("ipc:S-new", t0 + GLOBAL_WINDOW_SECS);
        assert!(v.log);
        assert!(v.summaries.iter().any(|s| s.contains("70 security line(s)")), "{:?}", v.summaries);
    }

    #[test]
    fn source_table_is_bounded() {
        let mut l = SecurityLimiter::new();
        let t0 = 1_800_000_000;
        for i in 0..(MAX_TRACKED_SOURCES + 50) {
            l.check(&format!("tg:{i}"), t0 + (i as i64 / 25) * 61);
        }
        assert!(l.sources.len() <= MAX_TRACKED_SOURCES + 1);
        assert!(l.sources.contains_key(OVERFLOW_SOURCE));
    }

    #[test]
    fn idle_sources_are_swept_with_a_summary() {
        let mut l = SecurityLimiter::new();
        let t0 = 1_800_000_000;
        for i in 0..(UNTRUSTED_PER_SOURCE_PER_HOUR + 3) {
            l.check("tg:7", t0 + i as i64 * 61);
        }
        // a different source after tg:7's window ended reports tg:7's suppressed lines
        let v = l.check("tg:8", t0 + 2 * SOURCE_WINDOW_SECS);
        assert!(v.log);
        assert!(v.summaries.iter().any(|s| s.contains("3 more") && s.contains("tg:7")), "{:?}", v.summaries);
        assert!(!l.sources.contains_key("tg:7"));
    }

    const T0: i64 = 1_800_000_000;

    fn written(a: &Admission) -> bool {
        a.write
    }

    #[test]
    fn identical_consecutive_lines_are_counted_and_summarised() {
        let mut g = FloodGuard::new();
        assert!(written(&g.admit(Level::Warn, "a.rs:1", "EvtNext failed", T0)));
        for i in 1..=4 {
            let a = g.admit(Level::Warn, "a.rs:1", "EvtNext failed", T0 + i);
            assert_eq!(a, Admission { write: false, before: vec![] }, "repeat {i}");
        }
        // the run ends with a different line: its summary comes first, at the run's level
        let a = g.admit(Level::Info, "b.rs:2", "something else", T0 + 5);
        assert!(a.write);
        assert_eq!(a.before, vec![(Level::Warn, "… previous message repeated 4 times".to_string())]);
        // a single repeat is reported in the singular
        g.admit(Level::Info, "b.rs:2", "something else", T0 + 6);
        let a = g.admit(Level::Info, "c.rs:3", "third", T0 + 7);
        assert_eq!(a.before, vec![(Level::Info, "… previous message repeated 1 time".to_string())]);
        // no repeats → no summary
        let a = g.admit(Level::Info, "d.rs:4", "fourth", T0 + 8);
        assert!(a.write && a.before.is_empty());
    }

    #[test]
    fn same_text_at_another_level_or_site_is_not_a_repeat() {
        let mut g = FloodGuard::new();
        assert!(g.admit(Level::Info, "a.rs:1", "x", T0).write);
        assert!(g.admit(Level::Warn, "a.rs:1", "x", T0).write, "other level");
        assert!(g.admit(Level::Warn, "a.rs:1", "y", T0).write, "other text");
        // the same text from another call site still counts as a repeat (identical line)
        assert!(!g.admit(Level::Warn, "z.rs:9", "y", T0).write);
    }

    #[test]
    fn a_sustained_repeat_writes_the_line_and_a_summary_once_per_window() {
        let mut g = FloodGuard::new();
        let mut lines = Vec::new();
        // 10 identical lines per second for three minutes
        for t in 0..(3 * 60 * 10) {
            let a = g.admit(Level::Warn, "loop.rs:7", "Cannot read the log", T0 + t / 10);
            lines.extend(a.before.into_iter().map(|(_, s)| s));
            if a.write {
                lines.push("LINE".to_string());
            }
        }
        lines.extend(g.flush(T0 + 180).into_iter().map(|(_, s)| s));
        assert_eq!(lines.iter().filter(|l| *l == "LINE").count(), 3, "{lines:?}");
        let summaries: Vec<&String> = lines.iter().filter(|l| l.starts_with('…')).collect();
        assert_eq!(summaries.len(), 3, "{lines:?}");
        assert_eq!(summaries[0], "… previous message repeated 599 times", "written in time: no extra time");
        assert_eq!(lines[0], "LINE");
    }

    /// A run that ends in silence is only summarised when the next line comes — maybe hours
    /// later; the summary then says when the repeats happened.
    #[test]
    fn a_late_summary_names_the_time_of_the_last_repeat() {
        let mut g = FloodGuard::new();
        assert!(g.admit(Level::Warn, "a.rs:1", "loop", T0).write);
        g.admit(Level::Warn, "a.rs:1", "loop", T0 + 1);
        g.admit(Level::Warn, "a.rs:1", "loop", T0 + 3);
        let a = g.admit(Level::Info, "b.rs:1", "hours later", T0 + 4 * 3600);
        assert!(a.write);
        assert_eq!(
            a.before,
            vec![(Level::Warn, format!("… previous message repeated 2 times (last at {})", local_time(T0 + 3)))]
        );
        // the same through a security line, and after a clock that went backwards
        g.admit(Level::Info, "b.rs:1", "hours later", T0 + 4 * 3600 + 1);
        let out = g.flush(T0);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.ends_with(&format!("1 time (last at {})", local_time(T0 + 4 * 3600 + 1))), "{out:?}");
    }

    #[test]
    fn line_after_a_quiet_minute_is_written_again() {
        let mut g = FloodGuard::new();
        assert!(g.admit(Level::Info, "a.rs:1", "monitoring Security", T0).write);
        let a = g.admit(Level::Info, "a.rs:1", "monitoring Security", T0 + REPEAT_WINDOW_SECS);
        assert!(a.write && a.before.is_empty(), "{a:?}");
        // a clock that jumped backwards ends the window too
        let a = g.admit(Level::Info, "a.rs:1", "monitoring Security", T0 - 10);
        assert!(a.write, "{a:?}");
    }

    #[test]
    fn per_site_cap_and_summary() {
        let mut g = FloodGuard::new();
        let mut written_lines = 0;
        for i in 0..250 {
            if g.admit(Level::Info, "spin.rs:42", &format!("event {i}"), T0).write {
                written_lines += 1;
            }
        }
        assert_eq!(written_lines, SITE_LINES_PER_MINUTE);
        // other call sites are unaffected
        assert!(g.admit(Level::Info, "other.rs:1", "fine", T0 + 1).write);
        // the next minute: summary for the capped site, then logging resumes
        let a = g.admit(Level::Info, "spin.rs:42", "event 999", T0 + SITE_WINDOW_SECS);
        assert!(a.write);
        assert_eq!(a.before.len(), 1, "{:?}", a.before);
        assert_eq!(a.before[0].0, Level::Warn);
        assert!(a.before[0].1.contains("50 more line(s) from spin.rs:42"), "{:?}", a.before);
    }

    #[test]
    fn a_capped_line_ends_the_run() {
        let mut g = FloodGuard::new();
        for i in 0..SITE_LINES_PER_MINUTE {
            assert!(g.admit(Level::Warn, "s.rs:1", &format!("l{i}"), T0).write);
        }
        // capped (not written) — so the next identical line must not count as its repeat
        assert!(!g.admit(Level::Warn, "s.rs:1", "capped", T0).write);
        let a = g.admit(Level::Warn, "s.rs:1", "capped", T0);
        assert!(!a.write && a.before.is_empty(), "{a:?}");
        assert!(g.flush(T0).is_empty(), "nothing was written, so nothing 'repeated'");
    }

    #[test]
    fn idle_capped_sites_are_swept_with_a_summary() {
        let mut g = FloodGuard::new();
        for i in 0..(SITE_LINES_PER_MINUTE + 7) {
            g.admit(Level::Warn, "burst.rs:3", &format!("b{i}"), T0);
        }
        // a different site two minutes later reports the burst that ended meanwhile
        let a = g.admit(Level::Info, "calm.rs:1", "hello", T0 + 2 * SITE_WINDOW_SECS);
        assert!(a.write);
        assert!(a.before.iter().any(|(_, s)| s.contains("7 more line(s) from burst.rs:3")), "{:?}", a.before);
        assert!(!g.sites.contains_key("burst.rs:3"));
    }

    #[test]
    fn direct_calls_are_keyed_by_text_and_the_table_is_bounded() {
        let mut g = FloodGuard::new();
        let long = "x".repeat(500);
        for _ in 0..(SITE_LINES_PER_MINUTE + 1) {
            // alternate so the repeat rule does not absorb them
            g.admit(Level::Info, "", &long, T0);
            g.admit(Level::Info, "", "other", T0);
        }
        let label = FloodGuard::key_label("", &long);
        assert!(label.chars().count() <= TEXT_KEY_CHARS + 2, "{label}");
        assert_eq!(g.sites.get(&label).map(|w| w.logged), Some(SITE_LINES_PER_MINUTE));
        for i in 0..(MAX_TRACKED_SITES + 50) {
            g.admit(Level::Info, &format!("gen.rs:{i}"), &format!("m{i}"), T0 + 1);
        }
        assert!(g.sites.len() <= MAX_TRACKED_SITES + 1);
        assert!(g.sites.contains_key(OVERFLOW_SITE));
    }

    fn test_logger(dir: &Path) -> Logger {
        Logger {
            main: Some(Sink::open(dir.join("predator.log"), MAIN_BACKUPS)),
            security: Some(Sink::open(dir.join("security.log"), SECURITY_BACKUPS)),
            stderr: false,
            min_level: Level::Info,
            limiter: SecurityLimiter::new(),
            guard: FloodGuard::new(),
        }
    }

    /// The production incident: a six-line cycle from three call sites at ~1000 lines/s.
    #[test]
    fn a_looping_bug_cannot_flood_the_log() {
        let dir = std::env::temp_dir().join(format!("predator-flood-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut l = test_logger(&dir);
        let cycle = [
            (Level::Warn, "mod.rs:982", "OpenSSH log: Cannot read the OpenSSH/Operational log (error 4317)"),
            (Level::Warn, "mod.rs:982", "OpenSSH admin log: Cannot read the OpenSSH/Admin log (error 4317)"),
            (Level::Warn, "mod.rs:982", "Security log: Cannot read the Security log (error 4317)"),
            (Level::Info, "mod.rs:957", "OpenSSH log: monitoring OpenSSH/Operational again"),
            (Level::Info, "mod.rs:957", "OpenSSH admin log: monitoring OpenSSH/Admin again"),
            (Level::Info, "mod.rs:957", "Security log: monitoring Security again"),
        ];
        // two minutes at 1000 lines/s
        for i in 0..120_000i64 {
            let (lv, site, msg) = cycle[(i % 6) as usize];
            log_into(&mut l, lv, site, msg, T0 + i / 1000);
        }
        // DEBUG lines below the threshold are dropped before counting
        log_into(&mut l, Level::Debug, "x.rs:1", "verbose only", T0 + 120);
        // a security line flushes nothing here (no run pending), and is never limited
        write_security(&mut l, "lock requested via Telegram: ok");
        drop(l);
        let text = std::fs::read_to_string(dir.join("predator.log")).unwrap();
        let n = text.lines().count();
        // per minute: 2 sites × 200 lines + at most a summary per site
        assert!(n <= 2 * (2 * SITE_LINES_PER_MINUTE as usize + 2) + 2, "{n} lines");
        assert!(n >= 2 * SITE_LINES_PER_MINUTE as usize, "{n} lines");
        assert!(text.contains("rate limit: ") && text.contains("from mod.rs:982"), "summary written");
        assert!(!text.contains("verbose only"));
        assert!(text.lines().last().unwrap().contains("SECURITY lock requested"));
        assert!(std::fs::read_to_string(dir.join("security.log")).unwrap().contains("lock requested"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn security_line_reports_a_pending_run_first_and_redaction_still_applies() {
        let dir = std::env::temp_dir().join(format!("predator-flood-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut l = test_logger(&dir);
        let token = "bot1234567890:AAFakeTokenForTestsOnly_0123456789a";
        for i in 0..5 {
            log_into(&mut l, Level::Warn, "net.rs:5", &format!("request {token} failed"), T0 + i);
        }
        write_security(&mut l, "feature x enabled");
        log_into(&mut l, Level::Warn, "net.rs:5", &format!("request {token} failed"), T0 + 6);
        drop(l);
        let text = std::fs::read_to_string(dir.join("predator.log")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains("WARN  request bot[REDACTED-TOKEN] failed"), "{lines:?}");
        assert!(lines[1].contains("WARN  … previous message repeated 4 times"), "{lines:?}");
        assert!(lines[2].contains("SECURITY feature x enabled"), "{lines:?}");
        assert!(lines[3].contains("[REDACTED-TOKEN]"), "the run was ended by the security line: {lines:?}");
        assert!(!text.contains("AAFakeTo"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn security_log_keeps_three_backups() {
        let dir = std::env::temp_dir().join(format!("predator-log-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("security.log");
        let mut s = Sink::open(p.clone(), SECURITY_BACKUPS);
        for g in 0..5u32 {
            s.write_line(&format!("generation {g}\r\n"));
            s.rotate();
        }
        assert!(backup_path(&p, 1).exists() && backup_path(&p, 2).exists() && backup_path(&p, 3).exists());
        assert!(!backup_path(&p, 4).exists());
        assert_eq!(std::fs::read_to_string(backup_path(&p, 1)).unwrap(), "generation 4\r\n");
        assert_eq!(std::fs::read_to_string(backup_path(&p, 3)).unwrap(), "generation 2\r\n");
        drop(s);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(backup_path(Path::new(r"C:\x\predator.log"), 1), PathBuf::from(r"C:\x\predator.log.1"));
    }
}
