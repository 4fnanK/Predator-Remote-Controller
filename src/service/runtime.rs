//! Service runtime wiring: startup, worker threads, lifecycle messages and the shutdown sequence.
//! Used identically by the SCM service and by `console` mode.

use std::any::Any;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::slot::{ObservedSystem, TelegramSlot, token_fingerprint};
use super::winsec::Secret;
use crate::config::SettingsStore;
use crate::context::AppContext;
use crate::monitor::Monitors;
use crate::net::connectivity::{self, ConnectivityWatcher};
use crate::notify::NotificationKind;
use crate::notify::history::LoginHistory;
use crate::notify::queue::NotificationQueue;
use crate::paths::DataPaths;
use crate::sys::{InternetStatus, RealSystem, SystemActions};
use crate::telegram::Telegram;
use crate::telegram::api::{TelegramApi, is_valid_token_format};
use crate::telegram::bot::Bot;
use crate::telegram::janitor::ChatJanitor;
use crate::util::Signal;
use crate::util::time::{fmt_datetime, fmt_duration, now_unix};
use crate::{log_debug, log_error, log_info, log_warn};

/// Telegram threads re-check a missing/invalid token this often.
pub(crate) const TOKEN_RECHECK: Duration = Duration::from_secs(30 * 60);
/// While the connectivity hint says "no internet", wait at most this long (or until the network
/// changes) and then try Telegram anyway: the hint is advisory and can be wrong (blocked NCSI
/// probe, active probing disabled by policy, some VPN setups).
pub(crate) const OFFLINE_RECHECK: Duration = Duration::from_secs(60);
/// Per-phase time limit (connect / send / receive) of the immediate "going offline" send.
const OFFLINE_SEND_TIMEOUT: Duration = Duration::from_secs(3);
/// Longest the stop sequence waits for that send (it stays queued if it does not finish).
pub(crate) const OFFLINE_SEND_BUDGET: Duration = Duration::from_secs(3);

/// The one-time working-set trim after start-up waits at least this long after the start (and
/// for the first successful getUpdates cycle, or for the poller to idle without a token).
pub(crate) const STARTUP_TRIM_DELAY: Duration = Duration::from_secs(60);
/// A trim after a burst needs this much quiet after the last activity (user commands, helper
/// processes, deliveries), so it never runs in the middle of an exchange.
pub(crate) const BURST_QUIET: Duration = Duration::from_secs(30);
/// Never trim more often than this (trimming on a period only causes page-fault churn).
pub(crate) const MIN_TRIM_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// A Tailscale status refreshed this recently (worker thread or IPC) counts as activity.
const TAILSCALE_ACTIVITY_SECS: i64 = 120;

// ---------------------------------------------------------------------------------------------
// Panic helpers
// ---------------------------------------------------------------------------------------------

thread_local! {
    static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record panic details (message + location) per thread without taking any lock, so that
/// [`catch`] can log them. In console mode the default hook still prints to stderr.
fn install_panic_hook(console: bool) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let text = info.to_string();
        let _ = LAST_PANIC.try_with(|p| {
            if let Ok(mut slot) = p.try_borrow_mut() {
                *slot = Some(text);
            }
        });
        if console {
            default(info);
        }
    }));
}

pub(crate) fn panic_message(p: &(dyn Any + Send)) -> String {
    let detail = LAST_PANIC.try_with(|s| s.try_borrow_mut().ok().and_then(|mut s| s.take())).ok().flatten();
    if let Some(d) = detail {
        return d;
    }
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".into()
    }
}

/// Run `f`, converting a panic into an error message.
pub(crate) fn catch<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|p| panic_message(&*p))
}

/// Spawn a named worker whose body is restarted (with growing delay) if it panics. The body is
/// expected to return only when the runtime stops.
pub(crate) fn spawn_supervised(
    name: &'static str,
    stack: usize,
    ctx: Arc<AppContext>,
    body: impl Fn() + Send + 'static,
) -> Result<(), String> {
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(stack)
        .spawn(move || {
            let mut delay = Duration::from_secs(5);
            loop {
                match catch(&body) {
                    Ok(()) => return,
                    Err(msg) => {
                        log_error!("thread '{name}' crashed: {msg}; restarting in {} s", delay.as_secs());
                        ctx.status.set_last_error(format!("{name} crashed (restarted)"));
                        if ctx.stop.sleep(delay) {
                            return;
                        }
                        delay = (delay * 2).min(Duration::from_secs(300));
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|e| format!("Cannot start thread {name}: {e}"))
}

// ---------------------------------------------------------------------------------------------
// Token loading
// ---------------------------------------------------------------------------------------------

/// Where the runtime reads the bot token from.
#[derive(Clone, Debug)]
pub(crate) enum TokenSource {
    /// DPAPI `token.dat` in the data directory.
    DataDir(PathBuf),
    /// `console --token-file F`: a DPAPI token file or a plain-text file containing the token.
    File(PathBuf),
}

pub(crate) enum TokenLoad {
    Missing(String),
    Loaded(Secret),
    Invalid(String),
}

pub(crate) fn load_token_from(src: &TokenSource) -> TokenLoad {
    let (path, plain_allowed) = match src {
        TokenSource::DataDir(p) => (p.as_path(), false),
        TokenSource::File(p) => (p.as_path(), true),
    };
    if !path.exists() {
        return TokenLoad::Missing(format!("{} not found", path.display()));
    }
    let token = if plain_allowed && !is_dpapi_file(path) {
        match read_plain_token(path) {
            Ok(t) => t,
            Err(e) => return TokenLoad::Invalid(e),
        }
    } else {
        match crate::secrets::load_token(path) {
            Ok(t) => Secret::new(t),
            Err(e) => return TokenLoad::Invalid(e),
        }
    };
    if !is_valid_token_format(token.expose()) {
        return TokenLoad::Invalid(format!("{} does not contain a valid Telegram bot token", path.display()));
    }
    TokenLoad::Loaded(token)
}

fn is_dpapi_file(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"PDT1"
}

/// First non-empty line of a small text file.
pub(crate) fn read_plain_token(path: &Path) -> Result<Secret, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    if meta.len() > 64 * 1024 {
        return Err(format!("{} is too large to be a token file", path.display()));
    }
    let raw = std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let text = String::from_utf8(raw).map_err(|_| format!("{} is not a UTF-8 text file", path.display()))?;
    let text = Secret::new(text);
    let line = text.expose().lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string();
    Ok(Secret::new(line))
}

// ---------------------------------------------------------------------------------------------
// Memory trim policy
// ---------------------------------------------------------------------------------------------

/// Why the working set is trimmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrimKind {
    /// Once, when start-up is complete (measured: WS 13.7 MB → about 3–5 MB on the installed
    /// service; most of it are start-up-only DLL and image pages).
    Startup,
    /// After an on-demand burst (commands, helper processes, backlog delivery) has ended.
    AfterBurst,
}

/// When to give memory back to Windows (pure: times are milliseconds on the runtime's monotonic
/// clock, passed in, so the rules are unit-testable). It is consulted only at quiet points of the
/// poller loop (a getUpdates cycle that returned no updates, or the token-less idle wait), so it
/// needs no timer of its own:
/// * the start-up trim: once, at least [`STARTUP_TRIM_DELAY`] after the start and
///   [`BURST_QUIET`] after the last activity;
/// * a burst trim: only when there was activity since the last trim, the last activity is at
///   least [`BURST_QUIET`] old and the last trim at least [`MIN_TRIM_INTERVAL`] — so an idle
///   service is never trimmed periodically.
#[derive(Debug, Default)]
pub(crate) struct TrimPolicy {
    last_trim_ms: Option<u64>,
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl TrimPolicy {
    /// Whether the start-up trim has happened.
    pub fn started(&self) -> bool {
        self.last_trim_ms.is_some()
    }

    /// Trim now? `last_activity_ms` is the time of the last activity (None = none so far).
    pub fn decide(&self, now_ms: u64, last_activity_ms: Option<u64>) -> Option<TrimKind> {
        let quiet = last_activity_ms.is_none_or(|a| now_ms.saturating_sub(a) >= ms(BURST_QUIET));
        if !quiet {
            return None;
        }
        match self.last_trim_ms {
            None => (now_ms >= ms(STARTUP_TRIM_DELAY)).then_some(TrimKind::Startup),
            Some(last) => {
                let active_since = last_activity_ms.is_some_and(|a| a > last);
                (active_since && now_ms.saturating_sub(last) >= ms(MIN_TRIM_INTERVAL)).then_some(TrimKind::AfterBurst)
            }
        }
    }

    /// A trim happened at `now_ms`.
    pub fn record(&mut self, now_ms: u64) {
        self.last_trim_ms = Some(now_ms);
    }

    /// While the start-up trim is pending: how long until [`decide`](Self::decide) would allow
    /// it (at least 1 s, so a caller that waits for it can never spin). `None` once it happened.
    pub fn startup_due_in(&self, now_ms: u64, last_activity_ms: Option<u64>) -> Option<Duration> {
        if self.started() {
            return None;
        }
        let after_start = ms(STARTUP_TRIM_DELAY).saturating_sub(now_ms);
        let after_quiet = last_activity_ms.map_or(0, |a| a.saturating_add(ms(BURST_QUIET)).saturating_sub(now_ms));
        Some(Duration::from_millis(after_start.max(after_quiet)).max(Duration::from_secs(1)))
    }
}

// ---------------------------------------------------------------------------------------------
// Shared runtime state
// ---------------------------------------------------------------------------------------------

/// Why the runtime is stopping (shown in the "going offline" message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    SystemShutdown,
    ServiceStopped,
    Console,
}

impl StopReason {
    pub fn label(self) -> &'static str {
        match self {
            StopReason::SystemShutdown => "System shutdown",
            StopReason::ServiceStopped => "Service stopped",
            StopReason::Console => "Console session ended",
        }
    }
}

/// State shared by every runtime thread.
pub(crate) struct Shared {
    pub ctx: Arc<AppContext>,
    pub tg: Arc<TelegramSlot>,
    pub sys: Arc<ObservedSystem>,
    pub bot: Bot,
    pub token_source: TokenSource,
    /// False in console mode (no SCM service to restart).
    pub is_service: bool,
    retry_epoch: AtomicU64,
    last_resume_unix: AtomicI64,
    /// Telegram answered while the connectivity hint said "no internet": the hint is ignored
    /// until the network changes or a request fails with a network error.
    hint_overridden: AtomicBool,
    /// Zero point of [`Shared::clock_ms`] (≈ runtime start).
    clock_base: Instant,
    /// Activity mark: [`Shared::clock_ms`] + 1 of the last on-demand activity (handled updates,
    /// helper processes, deliveries); 0 = none yet. Read by the memory trim policy.
    activity_mark: AtomicU64,
    /// The poller is inside a getUpdates request (only then is an interrupt useful).
    long_poll_active: AtomicBool,
    /// Bumped before every interrupt, so the poller can tell an interrupted request from a
    /// failure (no backoff, no warning).
    interrupts: AtomicU64,
}

impl Shared {
    fn build(
        ctx: Arc<AppContext>,
        tg: Arc<TelegramSlot>,
        sys: Arc<ObservedSystem>,
        bot: Bot,
        token_source: TokenSource,
        is_service: bool,
    ) -> Shared {
        Shared {
            ctx,
            tg,
            sys,
            bot,
            token_source,
            is_service,
            retry_epoch: AtomicU64::new(0),
            last_resume_unix: AtomicI64::new(0),
            hint_overridden: AtomicBool::new(false),
            clock_base: Instant::now(),
            activity_mark: AtomicU64::new(0),
            long_poll_active: AtomicBool::new(false),
            interrupts: AtomicU64::new(0),
        }
    }

    /// Milliseconds since the runtime started (monotonic).
    pub fn clock_ms(&self) -> u64 {
        ms(self.clock_base.elapsed())
    }

    /// Record on-demand activity now (cheap: one atomic store). Called by the poller after it
    /// handled updates and by the sender after a delivery.
    pub fn note_activity(&self) {
        self.activity_mark.store(self.clock_ms().saturating_add(1), Ordering::Relaxed);
    }

    /// [`Shared::clock_ms`] of the last activity, if any.
    pub fn last_activity_ms(&self) -> Option<u64> {
        self.activity_mark.load(Ordering::Relaxed).checked_sub(1)
    }

    /// At a quiet point of the poller loop: trim the working set (and release the heap caches
    /// first) when `policy` says so. Logged at DEBUG only. Returns what was done.
    pub(crate) fn maybe_trim(&self, policy: &mut TrimPolicy) -> Option<TrimKind> {
        if self.ctx.stop.is_stopped() {
            return None;
        }
        // Tailscale up/down run on worker threads and IPC can refresh the status: a status
        // remembered within the last two minutes means helper processes ran.
        if self.sys.cached_tailscale(TAILSCALE_ACTIVITY_SECS).is_some() {
            self.note_activity();
        }
        let now = self.clock_ms();
        let kind = policy.decide(now, self.last_activity_ms())?;
        policy.record(now);
        let debug = crate::logging::level_enabled(crate::logging::Level::Debug);
        let before = if debug { catch(crate::sys::sysinfo::process_memory).unwrap_or((0, 0)) } else { (0, 0) };
        let heap = crate::util::win::release_heap_caches();
        let trimmed = crate::util::win::trim_working_set();
        if debug {
            let after = catch(crate::sys::sysinfo::process_memory).unwrap_or((0, 0));
            log_debug!(
                "memory trim ({kind:?}): heap caches released: {heap}, working set trimmed: {trimmed}; private {} -> {} \
                 KB, working set {} -> {} KB",
                before.0 / 1024,
                after.0 / 1024,
                before.1 / 1024,
                after.1 / 1024
            );
        }
        Some(kind)
    }

    /// Count of interrupts requested so far (see [`Shared::interrupt_long_poll`]).
    pub fn interrupt_generation(&self) -> u64 {
        self.interrupts.load(Ordering::SeqCst)
    }

    /// The poller enters (`true`) or leaves (`false`) a getUpdates request.
    pub(crate) fn set_long_poll_active(&self, active: bool) {
        self.long_poll_active.store(active, Ordering::SeqCst);
    }

    /// Network change / resume: a long poll that is waiting on a connection that may be dead
    /// returns at once instead of after its 65 s receive timeout. Only done while the poller is
    /// inside getUpdates.
    ///
    /// The transport aborts *every* direct request in flight (not only the long poll), so callers
    /// interrupt **before** they wake the other threads ([`Shared::kick`]): a delivery that the
    /// wake-up itself starts must not be cancelled (a cancelled sendMessage that already reached
    /// Telegram would be sent twice). Not used on stop: nothing waits for the poller then (the
    /// process exits), and it would only cancel an alert being delivered and close the idle
    /// connection the "going offline" message could reuse.
    pub(crate) fn interrupt_long_poll(&self, why: &str) {
        // Once stopping, a network change (e.g. adapters going down at system shutdown) must not
        // cancel the "going offline" send that is in flight.
        if !self.long_poll_active.load(Ordering::SeqCst) || self.ctx.stop.is_stopped() {
            return;
        }
        let Some((api, _)) = self.tg.current() else { return };
        self.interrupts.fetch_add(1, Ordering::SeqCst);
        match catch(|| api.interrupt()) {
            Ok(_) => log_debug!("Telegram long poll interrupted ({why})"),
            Err(e) => log_error!("interrupting the Telegram long poll crashed: {e}"),
        }
    }

    pub fn retry_epoch(&self) -> u64 {
        self.retry_epoch.load(Ordering::SeqCst)
    }

    /// Network change / resume / new token: retry Telegram immediately (resets backoff waits).
    pub fn kick(&self) {
        self.retry_epoch.fetch_add(1, Ordering::SeqCst);
        self.ctx.network_changed();
    }

    /// A user just interacted with the bot: retry queued deliveries now.
    pub fn kick_sender(&self) {
        self.retry_epoch.fetch_add(1, Ordering::SeqCst);
        self.ctx.sender_wake.notify();
    }

    /// Sleep up to `d` on `signal`, returning early only on stop or [`Shared::kick`] (not on
    /// ordinary queue pushes, so a busy queue cannot defeat the backoff).
    pub fn wait_retry(&self, signal: &Signal, d: Duration) {
        let epoch = self.retry_epoch();
        let deadline = Instant::now() + d;
        let mut seen = signal.generation();
        loop {
            if self.ctx.stop.is_stopped() || self.retry_epoch() != epoch {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            seen = signal.wait_changed(seen, left);
        }
    }

    /// Re-read the token file; install a new client when it changed. Returns true if replaced.
    pub fn reload_token(&self) -> bool {
        match load_token_from(&self.token_source) {
            TokenLoad::Loaded(t) => {
                let fp = token_fingerprint(t.expose());
                if self.tg.fingerprint() == Some(fp) {
                    return false;
                }
                match TelegramApi::new(t.expose()) {
                    Ok(api) => {
                        log_info!("Telegram bot token loaded (HTTP transport: {})", api.transport_name());
                        self.tg.set(Some(api), fp);
                        self.ctx.status.token_invalid.store(false, Ordering::Relaxed);
                        self.kick();
                        true
                    }
                    Err(e) => {
                        log_warn!("cannot use the stored bot token: {e}");
                        false
                    }
                }
            }
            TokenLoad::Missing(_) | TokenLoad::Invalid(_) => false,
        }
    }

    /// Mark Telegram reachable (after any successful request).
    pub fn mark_online(&self) {
        let st = &self.ctx.status;
        st.telegram_online.store(true, Ordering::Relaxed);
        st.token_invalid.store(false, Ordering::Relaxed);
        st.last_telegram_ok_unix.store(now_unix(), Ordering::Relaxed);
        self.note_success_with_hint(connectivity_now());
    }

    /// A request succeeded while the hint was `hint`: when the hint claims "offline", stop
    /// trusting it. Returns true when the override was newly set.
    pub(crate) fn note_success_with_hint(&self, hint: InternetStatus) -> bool {
        if network_usable(hint) || self.hint_overridden.swap(true, Ordering::SeqCst) {
            return false;
        }
        log_warn!(
            "the Windows connectivity hint reports {hint:?}, but Telegram is reachable; ignoring the hint until the \
             network changes"
        );
        true
    }

    /// Trust the connectivity hint again (a network-level failure or a connectivity change).
    pub(crate) fn clear_hint_override(&self) {
        if self.hint_overridden.swap(false, Ordering::SeqCst) {
            log_debug!("connectivity hint trusted again");
        }
    }

    /// The connectivity watcher reported a change: re-evaluate the hint and retry immediately
    /// (a long poll on the previous network's connection is interrupted first, see
    /// [`Shared::interrupt_long_poll`] for why the order matters).
    pub(crate) fn connectivity_changed(&self) {
        self.clear_hint_override();
        self.interrupt_long_poll("network change");
        self.kick();
    }

    /// Should a Telegram request wait for the network, given the connectivity `hint`? Never a
    /// hard block: callers wait at most [`OFFLINE_RECHECK`] and then try anyway.
    pub(crate) fn hint_says_wait(&self, hint: InternetStatus) -> bool {
        !self.hint_overridden.load(Ordering::SeqCst) && !network_usable(hint)
    }

    /// [`Shared::hint_says_wait`] with the current hint (not queried while overridden).
    pub(crate) fn should_wait_for_network(&self) -> bool {
        !self.hint_overridden.load(Ordering::SeqCst) && self.hint_says_wait(connectivity_now())
    }

    /// A Telegram request failed with `e`: a network-level failure re-enables the hint.
    pub(crate) fn note_request_error(&self, e: &crate::telegram::TgError) {
        if matches!(e, crate::telegram::TgError::Network(_)) {
            self.clear_hint_override();
        }
    }

    /// "online" / "offline" / "invalid token" / "not configured".
    pub fn telegram_label(&self) -> String {
        if !self.tg.is_configured() && !self.ctx.status.token_invalid.load(Ordering::Relaxed) {
            "not configured".into()
        } else {
            self.ctx.status.telegram_label().into()
        }
    }
}

/// Connectivity level (Unknown if the probe itself fails).
pub(crate) fn connectivity_now() -> InternetStatus {
    catch(connectivity::current).unwrap_or(InternetStatus::Unknown)
}

/// Worth attempting a network request? (`Unknown`/captive portal: yes — the hint can be wrong.)
pub(crate) fn network_usable(s: InternetStatus) -> bool {
    !matches!(s, InternetStatus::Disconnected | InternetStatus::LocalOnly)
}

// ---------------------------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------------------------

pub(crate) struct RuntimeOptions {
    pub paths: DataPaths,
    pub console: bool,
    pub token_file: Option<PathBuf>,
    pub verbose: bool,
}

pub(crate) struct Runtime {
    pub shared: Arc<Shared>,
    monitors: Option<Monitors>,
    watcher: Option<ConnectivityWatcher>,
}

fn data_dir_error(paths: &DataPaths, e: &std::io::Error, what: &str) -> String {
    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
        " — access denied: run from an elevated (Administrator) prompt, or use --data-dir DIR"
    } else {
        ""
    };
    format!("Cannot {what} in {}: {e}{hint}", paths.root.display())
}

impl Runtime {
    /// Start everything. `progress` is called between steps (SCM START_PENDING checkpoints).
    pub fn start(opts: RuntimeOptions, progress: &dyn Fn()) -> Result<Runtime, String> {
        let paths = opts.paths.clone();
        let local_system = !opts.console && catch(crate::sys::sysinfo::is_local_system).unwrap_or(false);
        // As LocalSystem a missing data root is created atomically with its protected DACL, so
        // no other account can slip files into it between creation and the ACL reset below.
        if local_system {
            paths.ensure_dirs_secure().map_err(|e| data_dir_error(&paths, &e, "create the data directories"))?;
        } else {
            paths.ensure_dirs().map_err(|e| data_dir_error(&paths, &e, "create the data directories"))?;
        }
        let acl_result = if local_system { Some(super::winsec::secure_data_dir(&paths.root, true)) } else { None };
        crate::logging::init(&paths.logs_dir(), opts.console, opts.verbose);
        install_panic_hook(opts.console);
        log_info!(
            "{} {} starting (pid {}, {} mode, data: {})",
            crate::PRODUCT_NAME,
            crate::VERSION,
            std::process::id(),
            if opts.console { "console" } else { "service" },
            paths.root.display()
        );
        match acl_result {
            Some(Ok(true)) => log_info!("data directory ACL set to SYSTEM + Administrators only"),
            Some(Err(e)) => log_warn!("could not secure the data directory: {e}"),
            _ => {}
        }
        // A background process with short, I/O-bound bursts: let Windows run it on efficiency
        // cores / at an efficient clock (EcoQoS). Turned off again for the stop sequence.
        if crate::util::win::set_eco_qos(true) {
            log_debug!("EcoQoS (power throttling) enabled");
        } else {
            log_debug!("EcoQoS not available: {}", crate::util::win::error_message(crate::util::win::last_error()));
        }
        progress();

        let settings = Arc::new(
            SettingsStore::load(&paths.settings()).map_err(|e| data_dir_error(&paths, &e, "read settings.json"))?,
        );
        let queue = Arc::new(
            NotificationQueue::open(&paths.queue()).map_err(|e| data_dir_error(&paths, &e, "open queue.json"))?,
        );
        let history = Arc::new(
            LoginHistory::open(&paths.history()).map_err(|e| data_dir_error(&paths, &e, "open history.json"))?,
        );
        let computer = catch(crate::sys::sysinfo::computer_name)
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "PC".into());
        // Short-lived chat messages still waiting for deletion from before the restart.
        let janitor = Arc::new(ChatJanitor::open(&paths.chat_cleanup()));
        let ctx = AppContext::with_janitor(paths.clone(), settings, queue, history, janitor, computer, opts.console);

        let s = ctx.settings.get();
        let dry_run = s.dry_run || paths.dry_run_marker().exists() || opts.console;
        let sys = Arc::new(ObservedSystem::new(RealSystem::new(dry_run, ctx.started_unix)));
        let tg = Arc::new(TelegramSlot::new(opts.console));
        let token_source = match &opts.token_file {
            Some(f) => TokenSource::File(f.clone()),
            None => TokenSource::DataDir(paths.token()),
        };
        load_initial_token(&token_source, &tg, &ctx, opts.console);
        progress();

        let bot =
            catch(|| Bot::new(ctx.clone(), tg.clone() as Arc<dyn Telegram>, sys.clone() as Arc<dyn SystemActions>))
                .map_err(|e| format!("Cannot initialise the Telegram dispatcher: {e}"))?;
        let shared = Arc::new(Shared::build(ctx.clone(), tg, sys, bot, token_source, !opts.console));

        refresh_audit_status(&ctx);
        progress();

        let monitors = match catch(|| Monitors::start(ctx.clone())) {
            Ok(m) => Some(m),
            Err(e) => {
                log_error!("login monitors failed to start: {e}");
                ctx.status.set_last_error("login monitors failed to start");
                None
            }
        };
        progress();

        let watcher = start_connectivity_watcher(&shared);

        let sh = shared.clone();
        spawn_supervised("telegram-poller", 512 * 1024, ctx.clone(), move || super::poller::run(&sh))?;
        let sh = shared.clone();
        spawn_supervised("notify-sender", 256 * 1024, ctx.clone(), move || super::sender::run(&sh))?;
        let sh = shared.clone();
        spawn_supervised("ipc-server", 256 * 1024, ctx.clone(), move || super::ipc_server::run(&sh))?;
        progress();

        queue_online_message(&shared, dry_run);
        let users = match s.authorized_users.len() {
            0 => "none paired (run 'pair')".to_string(),
            1 => "1 user".to_string(),
            n => format!("{n} users"),
        };
        log_info!(
            "started: Telegram {}, authorized Telegram users: {users}, dry-run {}",
            shared.telegram_label(),
            if dry_run { "ON" } else { "off" }
        );
        Ok(Runtime { shared, monitors, watcher })
    }

    /// PBT_APMRESUMEAUTOMATIC: reconnect now and tell the users (at most once a minute).
    pub fn on_resume(&self) {
        let sh = &self.shared;
        let now = now_unix();
        let last = sh.last_resume_unix.swap(now, Ordering::SeqCst);
        // the connection of a long poll that started before the sleep is almost surely dead;
        // interrupted before the kick wakes the sender (see Shared::interrupt_long_poll)
        sh.interrupt_long_poll("resume");
        sh.kick();
        log_info!("system resumed from sleep/hibernation");
        if now - last < 60 {
            return;
        }
        let ctx = &sh.ctx;
        if !ctx.settings.get().lifecycle_notifications {
            return;
        }
        let lines = vec![
            ("Computer".to_string(), ctx.computer_name.clone()),
            ("Event".to_string(), "System resumed from sleep or hibernation".to_string()),
        ];
        match catch(|| ctx.emit_system("☀️", "PREDATOR RESUMED", &lines, now, Some(format!("resume:{now}")))) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log_warn!("cannot queue the resume notification: {e}"),
            Err(e) => log_error!("cannot render the resume notification: {e}"),
        }
    }

    /// SERVICE_CONTROL_SESSIONCHANGE → monitor fallback.
    pub fn on_session_change(&self, event_type: u32, session_id: u32) {
        let ctx = self.shared.ctx.clone();
        log_debug!("session change: event {event_type}, session {session_id}");
        if let Err(e) = catch(|| crate::monitor::on_session_change(&ctx, event_type, session_id)) {
            log_error!("session-change handler crashed: {e}");
        }
    }

    /// Stop everything: stop flag, "going offline" message, monitors. The direct send of the
    /// offline message runs on a helper thread while the monitors stop, and is awaited for at
    /// most [`OFFLINE_SEND_BUDGET`] (it stays queued otherwise), so the whole sequence fits the
    /// SCM stop / preshutdown budget. `checkpoint` is called at least once a second. Threads
    /// blocked in long polls are not joined — the caller exits the process.
    pub fn shutdown(mut self, reason: StopReason, checkpoint: &dyn Fn()) {
        let sh = self.shared.clone();
        log_info!("stopping: {}", reason.label());
        let deadline = Instant::now() + OFFLINE_SEND_BUDGET;
        // the stop sequence has a hard time budget: run it at full speed
        crate::util::win::set_eco_qos(false);
        sh.ctx.stop.stop();
        // No interrupt here: the long poll is not waited for (the process exits), and the
        // transport's interrupt would also cancel an alert the sender is delivering right now
        // (sent again after the restart) and close the kept-alive connection the offline send
        // below can reuse.
        checkpoint();
        let sending = start_offline_send(&sh, reason);
        checkpoint();
        if let Some(m) = self.monitors.take()
            && let Err(e) = catch(|| m.stop())
        {
            log_error!("monitor shutdown crashed: {e}");
        }
        checkpoint();
        if let Some(done) = sending
            && !wait_until(&done, deadline, checkpoint)
        {
            log_info!("the offline notification is still being sent; it stays queued for the next start");
        }
        // coalesced acks (recent deliveries not written yet) reach the disk before the process exits
        if let Err(e) = sh.ctx.queue.flush() {
            log_warn!("cannot write queue.json at stop: {e}; delivered alerts may be sent again after the restart");
        }
        drop(self.watcher.take());
        log_info!("{} stopped", crate::PRODUCT_NAME);
    }
}

/// Wait for one message on `done` until `deadline`, calling `checkpoint` at least once a second.
/// Returns false on timeout.
fn wait_until(done: &mpsc::Receiver<()>, deadline: Instant, checkpoint: &dyn Fn()) -> bool {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match done.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return true,
            Err(RecvTimeoutError::Timeout) => checkpoint(),
        }
    }
}

fn load_initial_token(src: &TokenSource, tg: &TelegramSlot, ctx: &AppContext, console: bool) {
    // The token file keeps its machine-scope protection (the CLI and installer must be able to
    // re-check it); the data directory ACL restricts it to SYSTEM and Administrators.
    match load_token_from(src) {
        TokenLoad::Loaded(token) => match TelegramApi::new(token.expose()) {
            Ok(api) => {
                log_info!("Telegram bot token loaded (HTTP transport: {})", api.transport_name());
                tg.set(Some(api), token_fingerprint(token.expose()));
            }
            Err(e) => {
                log_error!("the stored bot token cannot be used: {e}");
                ctx.status.token_invalid.store(true, Ordering::Relaxed);
                ctx.status.set_last_error("stored bot token cannot be used");
            }
        },
        TokenLoad::Missing(why) => {
            let how = if console {
                "'predator-service set-token --data-dir DIR' or 'console --token-file FILE'"
            } else {
                "'predator-service set-token'"
            };
            log_warn!(
                "No Telegram bot token configured ({why}). Telegram is disabled: the monitors keep running and alerts \
                 are queued until a token is stored with {how}."
            );
            ctx.status.set_last_error("no Telegram bot token configured");
        }
        TokenLoad::Invalid(e) => {
            log_error!("Cannot load the Telegram bot token: {e}");
            ctx.status.token_invalid.store(true, Ordering::Relaxed);
            ctx.status.set_last_error("Telegram bot token cannot be loaded");
        }
    }
}

fn refresh_audit_status(ctx: &AppContext) {
    match catch(crate::monitor::audit::describe) {
        Ok(Ok((text, sufficient))) => {
            if !sufficient {
                log_warn!("logon audit policy is incomplete ({text}); run 'predator-service audit enable'");
            }
            *ctx.status.audit_policy.lock().unwrap_or_else(|e| e.into_inner()) = Some(text);
        }
        Ok(Err(e)) => log_debug!("audit policy query failed: {e}"),
        Err(e) => log_debug!("audit policy query crashed: {e}"),
    }
}

fn start_connectivity_watcher(shared: &Arc<Shared>) -> Option<ConnectivityWatcher> {
    let weak = Arc::downgrade(shared);
    let cb: Arc<dyn Fn(InternetStatus) + Send + Sync> = Arc::new(move |status| {
        if let Some(sh) = weak.upgrade() {
            log_debug!("connectivity changed: {status:?}");
            sh.connectivity_changed();
        }
    });
    match catch(|| connectivity::watch(cb)) {
        Ok(Ok(w)) => Some(w),
        Ok(Err(e)) => {
            log_warn!("connectivity notifications unavailable ({e}); relying on retries");
            None
        }
        Err(e) => {
            log_error!("connectivity watcher crashed: {e}");
            None
        }
    }
}

fn queue_online_message(sh: &Shared, dry_run: bool) {
    let ctx = &sh.ctx;
    if !ctx.settings.get().lifecycle_notifications {
        return;
    }
    let mut lines = vec![
        ("Computer".to_string(), ctx.computer_name.clone()),
        ("Event".to_string(), if ctx.console_mode { "Console test session started" } else { "Service started" }.into()),
        ("Version".to_string(), crate::VERSION.to_string()),
    ];
    if let Ok(boot) = catch(crate::sys::sysinfo::boot_unix)
        && boot > 0
    {
        lines.push(("Boot time".to_string(), fmt_datetime(boot)));
    }
    if dry_run {
        lines.push((
            "Mode".to_string(),
            "🧪 DRY-RUN — power, lock, logout and Tailscale up/down are simulated".to_string(),
        ));
    }
    let key = Some(format!("online:{}", ctx.started_unix));
    match catch(|| ctx.emit_system("🟢", "PREDATOR ONLINE", &lines, ctx.started_unix, key)) {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => log_warn!("cannot queue the online notification: {e}"),
        Err(e) => log_error!("cannot render the online notification: {e}"),
    }
}

/// [`TelegramApi`] with the short per-phase time limit of the stop sequence for `sendMessage`
/// (the "going offline" notice); everything else is passed through.
struct StopTimeLimit<'a>(&'a TelegramApi);

impl Telegram for StopTimeLimit<'_> {
    fn send_message(
        &self,
        chat_id: i64,
        html: &str,
        keyboard: Option<&crate::telegram::types::InlineKeyboardMarkup>,
    ) -> Result<i64, crate::telegram::TgError> {
        self.0.send_message_with_timeout(chat_id, html, keyboard, OFFLINE_SEND_TIMEOUT)
    }

    fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        keyboard: Option<&crate::telegram::types::InlineKeyboardMarkup>,
    ) -> Result<(), crate::telegram::TgError> {
        self.0.edit_message(chat_id, message_id, html, keyboard)
    }

    fn answer_callback(
        &self,
        callback_id: &str,
        text: Option<&str>,
        show_alert: bool,
    ) -> Result<(), crate::telegram::TgError> {
        self.0.answer_callback(callback_id, text, show_alert)
    }

    fn leave_chat(&self, chat_id: i64) -> Result<(), crate::telegram::TgError> {
        self.0.leave_chat(chat_id)
    }
}

/// Queue the "going offline" message durably and start delivering it directly to every
/// authorized user on a helper thread (the sender thread has already stopped). Returns a receiver
/// that gets one message when the attempt finished, or `None` when nothing is being sent.
fn start_offline_send(sh: &Shared, reason: StopReason) -> Option<mpsc::Receiver<()>> {
    let ctx = &sh.ctx;
    if !ctx.settings.get().lifecycle_notifications {
        return None;
    }
    let now = now_unix();
    let lines = vec![
        ("Computer".to_string(), ctx.computer_name.clone()),
        ("Reason".to_string(), reason.label().to_string()),
        ("Uptime".to_string(), fmt_duration((now - ctx.started_unix).max(0) as u64)),
    ];
    let html = match catch(|| crate::notify::format::render_system("🔴", "PREDATOR GOING OFFLINE", &lines, now)) {
        Ok(h) => h,
        Err(e) => {
            log_error!("cannot render the offline notification: {e}");
            return None;
        }
    };
    let key = Some(format!("offline:{}", ctx.started_unix));
    let item = match ctx.queue.push(NotificationKind::System, now, html.clone(), key) {
        Ok(Some(id)) => ctx.queue.get(id),
        Ok(None) => return None,
        Err(e) => {
            log_warn!("cannot queue the offline notification: {e}");
            None
        }
    };
    // not queued (disk error): still try to send it once (ack / mark of an unknown id are no-ops)
    let item = item.unwrap_or(crate::notify::Notification {
        id: 0,
        kind: NotificationKind::System,
        event_unix: now,
        queued_unix: now,
        html,
        dedupe_key: None,
        delivered_to: Vec::new(),
    });
    // no client or nobody paired: the notice waits in the queue
    let (api, _) = sh.tg.current()?;
    ctx.settings.primary_user_id()?;
    if ctx.status.token_invalid.load(Ordering::Relaxed) || sh.should_wait_for_network() {
        log_info!("offline notification stays queued (Telegram unreachable)");
        return None;
    }
    let (tx, rx) = mpsc::channel();
    let ctx = ctx.clone();
    let spawned = std::thread::Builder::new().name("offline-send".into()).stack_size(256 * 1024).spawn(move || {
        // Every recipient reached is recorded and a delivered `System` notice is tracked for the
        // chat cleanup (deleted by the sweep after the next start).
        match catch(|| super::sender::deliver_pass(&ctx, &StopTimeLimit(&api), &item, now_unix())) {
            Ok(super::sender::Pass::Done { sent, .. }) => {
                if sent > 0 {
                    ctx.status.delivered.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(super::sender::Pass::Retry { error, .. } | super::sender::Pass::Blocked(error)) => {
                log_info!("offline notification not delivered to every user now ({error}); it stays queued")
            }
            Ok(other) => log_info!("offline notification not delivered: {other:?}"),
            Err(e) => log_error!("sending the offline notification crashed: {e}"),
        }
        // The process exits right after the stop sequence: write the (otherwise possibly
        // coalesced) ack and recipient marks now, so nobody gets the notice again after the restart.
        if let Err(e) = ctx.queue.flush() {
            log_warn!("cannot update queue.json: {e}");
        }
        let _ = tx.send(());
    });
    match spawned {
        Ok(_) => Some(rx),
        Err(e) => {
            log_warn!("cannot send the offline notification now ({e}); it stays queued");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_networks() {
        assert!(network_usable(InternetStatus::Connected));
        assert!(network_usable(InternetStatus::Unknown));
        assert!(network_usable(InternetStatus::CaptivePortal));
        assert!(!network_usable(InternetStatus::Disconnected));
        assert!(!network_usable(InternetStatus::LocalOnly));
    }

    #[test]
    fn catch_reports_message() {
        assert_eq!(catch(|| 5).unwrap(), 5);
        let e = catch(|| -> i32 { panic!("boom 42") }).unwrap_err();
        assert!(e.contains("boom 42"), "{e}");
    }

    #[test]
    fn token_sources() {
        let dir = std::env::temp_dir().join(format!("predator-rt-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let tok = "123456789:AAFakeTokenForTestsOnly_0123456789a";
        assert!(matches!(load_token_from(&TokenSource::DataDir(dir.join("token.dat"))), TokenLoad::Missing(_)));
        let plain = dir.join("tok.txt");
        std::fs::write(&plain, format!("\r\n  {tok}  \r\nignored")).unwrap();
        match load_token_from(&TokenSource::File(plain.clone())) {
            TokenLoad::Loaded(t) => assert_eq!(t.expose(), tok),
            _ => panic!("plain token not loaded"),
        }
        // plain text is not accepted where a DPAPI file is required
        assert!(matches!(load_token_from(&TokenSource::DataDir(plain)), TokenLoad::Invalid(_)));
        let dat = dir.join("token.dat");
        crate::secrets::save_token(&dat, tok, crate::secrets::Scope::CurrentUser).unwrap();
        assert!(matches!(load_token_from(&TokenSource::File(dat.clone())), TokenLoad::Loaded(_)));
        assert!(matches!(load_token_from(&TokenSource::DataDir(dat)), TokenLoad::Loaded(_)));
        let bad = dir.join("bad.txt");
        std::fs::write(&bad, "not a token").unwrap();
        assert!(matches!(load_token_from(&TokenSource::File(bad)), TokenLoad::Invalid(_)));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `Shared` over an in-memory context (no token, dry-run system).
    pub(crate) fn test_shared() -> Arc<Shared> {
        Arc::new(test_shared_value())
    }

    fn test_shared_value() -> Shared {
        let ctx = AppContext::for_tests();
        let sys = Arc::new(ObservedSystem::new(RealSystem::new(true, 0)));
        let tg = Arc::new(TelegramSlot::new(false));
        let bot = Bot::new(ctx.clone(), tg.clone() as Arc<dyn Telegram>, sys.clone() as Arc<dyn SystemActions>);
        Shared::build(ctx, tg, sys, bot, TokenSource::DataDir(PathBuf::from("nul")), false)
    }

    /// F07: a success while the hint says "offline" overrides the hint until a network failure
    /// or a connectivity change, so requests go out back-to-back instead of once per recheck.
    #[test]
    fn hint_is_advisory_and_overridden_by_success() {
        let sh = test_shared();
        assert!(sh.hint_says_wait(InternetStatus::LocalOnly));
        assert!(sh.hint_says_wait(InternetStatus::Disconnected));
        assert!(!sh.hint_says_wait(InternetStatus::Connected));
        // a success with a usable hint changes nothing
        assert!(!sh.note_success_with_hint(InternetStatus::Connected));
        assert!(sh.hint_says_wait(InternetStatus::LocalOnly));
        // a success while the hint says LocalOnly: the hint is ignored from now on
        assert!(sh.note_success_with_hint(InternetStatus::LocalOnly));
        assert!(!sh.note_success_with_hint(InternetStatus::LocalOnly), "logged once");
        for _ in 0..5 {
            assert!(!sh.hint_says_wait(InternetStatus::LocalOnly));
            assert!(!sh.should_wait_for_network());
        }
        // non-network errors keep the override
        sh.note_request_error(&crate::telegram::TgError::Server(502, "x".into()));
        assert!(!sh.hint_says_wait(InternetStatus::LocalOnly));
        // a network-level failure re-enables the hint
        sh.note_request_error(&crate::telegram::TgError::Network("timeout".into()));
        assert!(sh.hint_says_wait(InternetStatus::LocalOnly));
        // and so does a connectivity change (which also kicks the waiters)
        sh.note_success_with_hint(InternetStatus::Disconnected);
        let epoch = sh.retry_epoch();
        sh.connectivity_changed();
        assert!(sh.hint_says_wait(InternetStatus::Disconnected));
        assert_ne!(sh.retry_epoch(), epoch);
    }

    /// F07: the offline wait is capped, and queue pushes do not extend or shorten it.
    #[test]
    fn offline_wait_is_bounded() {
        const { assert!(OFFLINE_RECHECK.as_secs() <= 60) };
        let sh = test_shared();
        let sh2 = sh.clone();
        let pusher = std::thread::spawn(move || {
            for _ in 0..5 {
                std::thread::sleep(Duration::from_millis(20));
                sh2.ctx.sender_wake.notify();
            }
        });
        let start = Instant::now();
        sh.wait_retry(&sh.ctx.sender_wake, Duration::from_millis(250));
        let el = start.elapsed();
        pusher.join().unwrap();
        assert!(el >= Duration::from_millis(240) && el < Duration::from_secs(5), "{el:?}");
    }

    /// F21: the stop sequence never waits longer than its budget for the offline send.
    #[test]
    fn offline_send_wait_is_bounded_and_checkpointed() {
        const { assert!(OFFLINE_SEND_BUDGET.as_secs() <= 3 && OFFLINE_SEND_TIMEOUT.as_secs() <= 3) };
        let (tx, rx) = mpsc::channel::<()>();
        let ticks = std::sync::atomic::AtomicU32::new(0);
        let start = Instant::now();
        let done = wait_until(&rx, start + Duration::from_millis(2_300), &|| {
            ticks.fetch_add(1, Ordering::SeqCst);
        });
        assert!(!done);
        let el = start.elapsed();
        assert!(el >= Duration::from_millis(2_250) && el < Duration::from_secs(4), "{el:?}");
        assert!(ticks.load(Ordering::SeqCst) >= 2, "checkpoint at least once a second");
        // finished sends (or a vanished sender) end the wait at once
        tx.send(()).unwrap();
        assert!(wait_until(&rx, Instant::now() + Duration::from_secs(10), &|| {}));
        drop(tx);
        let t = Instant::now();
        assert!(wait_until(&rx, Instant::now() + Duration::from_secs(10), &|| {}));
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    const S: u64 = 1000; // one second in policy milliseconds

    /// Start-up trim: once, only after STARTUP_TRIM_DELAY and BURST_QUIET after any activity.
    #[test]
    fn startup_trim_waits_for_the_delay_and_for_quiet() {
        let mut p = TrimPolicy::default();
        assert!(!p.started());
        assert_eq!(p.decide(0, None), None);
        assert_eq!(p.decide(59 * S, None), None, "too early");
        assert_eq!(p.decide(60 * S, None), Some(TrimKind::Startup));
        // a user command 10 s ago postpones it until 30 s of quiet
        assert_eq!(p.decide(70 * S, Some(60 * S)), None);
        assert_eq!(p.decide(90 * S - 1, Some(60 * S)), None);
        assert_eq!(p.decide(90 * S, Some(60 * S)), Some(TrimKind::Startup));
        // activity long before the delay does not matter
        assert_eq!(p.decide(61 * S, Some(5 * S)), Some(TrimKind::Startup));
        p.record(61 * S);
        assert!(p.started());
        // never again without activity: no periodic trimming of an idle service
        for minutes in [11, 60, 600, 6000] {
            assert_eq!(p.decide(61 * S + minutes * 60 * S, Some(5 * S)), None, "{minutes} min");
            assert_eq!(p.decide(61 * S + minutes * 60 * S, None), None, "{minutes} min");
        }
    }

    /// Burst trim: activity since the last trim, BURST_QUIET after it, MIN_TRIM_INTERVAL after
    /// the last trim.
    #[test]
    fn burst_trim_needs_activity_quiet_and_interval() {
        let mut p = TrimPolicy::default();
        let t0 = 100 * S;
        p.record(t0); // the start-up trim
        // a command burst 2 minutes later
        let burst_end = t0 + 120 * S;
        assert_eq!(p.decide(burst_end + 10 * S, Some(burst_end)), None, "not quiet yet");
        assert_eq!(p.decide(burst_end + 30 * S, Some(burst_end)), None, "quiet, but last trim < 10 min ago");
        let due = t0 + 10 * 60 * S;
        assert_eq!(p.decide(due - 1, Some(burst_end)), None);
        assert_eq!(p.decide(due, Some(burst_end)), Some(TrimKind::AfterBurst));
        // a new burst right at the interval: wait for quiet again
        assert_eq!(p.decide(due, Some(due - 5 * S)), None);
        assert_eq!(p.decide(due + 25 * S, Some(due - 5 * S)), Some(TrimKind::AfterBurst));
        p.record(due + 25 * S);
        // the same burst does not trigger a second trim
        assert_eq!(p.decide(due + 3600 * S, Some(due - 5 * S)), None);
        // activity at the very millisecond of the trim does not count as "since"
        assert_eq!(p.decide(due + 3600 * S, Some(due + 25 * S)), None);
        assert_eq!(p.decide(due + 3600 * S, Some(due + 25 * S + 1)), Some(TrimKind::AfterBurst));
    }

    #[test]
    fn startup_due_in_never_spins() {
        let mut p = TrimPolicy::default();
        assert_eq!(p.startup_due_in(0, None), Some(Duration::from_secs(60)));
        assert_eq!(p.startup_due_in(45 * S, None), Some(Duration::from_secs(15)));
        // due already: the caller still waits at least a second
        assert_eq!(p.startup_due_in(80 * S, None), Some(Duration::from_secs(1)));
        // activity pushes it to BURST_QUIET after the activity
        assert_eq!(p.startup_due_in(70 * S, Some(65 * S)), Some(Duration::from_secs(25)));
        // and decide agrees with it at the due time
        let now = 70 * S;
        let due = p.startup_due_in(now, Some(65 * S)).unwrap();
        assert_eq!(p.decide(now + ms(due), Some(65 * S)), Some(TrimKind::Startup));
        p.record(100 * S);
        assert_eq!(p.startup_due_in(200 * S, None), None);
    }

    #[test]
    fn activity_mark_and_trim_on_the_running_process() {
        let fresh = test_shared_value();
        assert_eq!(fresh.last_activity_ms(), None);
        let before = fresh.clock_ms();
        fresh.note_activity();
        let mark = fresh.last_activity_ms().unwrap();
        assert!(mark >= before && mark <= fresh.clock_ms());
        // a runtime that has just started: too early for the start-up trim
        let mut p = TrimPolicy::default();
        assert_eq!(fresh.maybe_trim(&mut p), None);
        assert!(!p.started());

        // a runtime that started two minutes ago and is idle: trims once (this test process)
        let mut old = test_shared_value();
        let Some(base) = Instant::now().checked_sub(Duration::from_secs(120)) else { return };
        old.clock_base = base;
        assert_eq!(old.maybe_trim(&mut p), Some(TrimKind::Startup));
        assert!(p.started());
        assert_eq!(old.maybe_trim(&mut p), None, "not again without activity");
        // activity: nothing before BURST_QUIET (and MIN_TRIM_INTERVAL) has passed
        old.note_activity();
        assert_eq!(old.maybe_trim(&mut p), None);
        // nothing is trimmed once stopping
        let mut idle = test_shared_value();
        idle.clock_base = base;
        idle.ctx.stop.stop();
        assert_eq!(idle.maybe_trim(&mut TrimPolicy::default()), None);
    }

    /// Interrupts only reach the client while the poller is inside getUpdates, and the poller can
    /// tell an interrupted request from a failure by the generation.
    #[test]
    fn interrupt_only_while_long_polling() {
        let sh = test_shared();
        let g0 = sh.interrupt_generation();
        // no client configured: nothing to interrupt
        sh.set_long_poll_active(true);
        sh.interrupt_long_poll("test");
        assert_eq!(sh.interrupt_generation(), g0);
        // with a client but outside a long poll: nothing either
        let tok = "123456789:AAFakeTokenForTestsOnly_0123456789a";
        sh.tg.set(Some(TelegramApi::new(tok).unwrap()), token_fingerprint(tok));
        sh.set_long_poll_active(false);
        sh.connectivity_changed();
        assert_eq!(sh.interrupt_generation(), g0);
        // inside a long poll: the generation moves (before the client is interrupted)
        sh.set_long_poll_active(true);
        sh.connectivity_changed();
        assert_eq!(sh.interrupt_generation(), g0 + 1);
        let cancelled = crate::telegram::TgError::Network("request cancelled".into());
        assert!(super::super::poller::interrupted(g0, sh.interrupt_generation(), &cancelled));
        sh.set_long_poll_active(false);
    }

    /// The transport's interrupt cancels every request in flight, so it must happen before the
    /// sender and the poller are woken: a delivery started by that wake-up is never cancelled
    /// (a cancelled sendMessage that reached Telegram would be delivered twice).
    #[test]
    fn interrupt_happens_before_the_wake_up() {
        let tok = "123456789:AAFakeTokenForTestsOnly_0123456789a";
        for resume in [false, true] {
            let sh = test_shared();
            sh.tg.set(Some(TelegramApi::new(tok).unwrap()), token_fingerprint(tok));
            sh.set_long_poll_active(true);
            let g0 = sh.interrupt_generation();
            let seen = sh.ctx.sender_wake.generation();
            let sh2 = sh.clone();
            // the "sender": what is the interrupt generation the moment it is woken? (it spins
            // instead of blocking, so a wrong order is seen and not hidden by wake-up latency)
            let waiter = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    if sh2.ctx.sender_wake.generation() != seen {
                        return (true, sh2.interrupt_generation());
                    }
                    if Instant::now() >= deadline {
                        return (false, sh2.interrupt_generation());
                    }
                    std::hint::spin_loop();
                }
            });
            std::thread::sleep(Duration::from_millis(30));
            if resume {
                Runtime { shared: sh.clone(), monitors: None, watcher: None }.on_resume();
            } else {
                sh.connectivity_changed();
            }
            let (woken, generation) = waiter.join().unwrap();
            assert!(woken, "resume={resume}: the sender is woken");
            assert_eq!(generation, g0 + 1, "resume={resume}: interrupted before the wake-up");
            sh.set_long_poll_active(false);
        }
    }

    /// The stop sequence does not interrupt the client (an alert being delivered must not be
    /// cancelled, and nothing waits for the long poll).
    #[test]
    fn stop_does_not_interrupt() {
        let tok = "123456789:AAFakeTokenForTestsOnly_0123456789a";
        let sh = test_shared();
        sh.ctx.settings.update(|s| s.lifecycle_notifications = false).unwrap();
        sh.tg.set(Some(TelegramApi::new(tok).unwrap()), token_fingerprint(tok));
        sh.set_long_poll_active(true);
        let g0 = sh.interrupt_generation();
        Runtime { shared: sh.clone(), monitors: None, watcher: None }.shutdown(StopReason::Console, &|| {});
        assert!(sh.ctx.stop.is_stopped());
        assert_eq!(sh.interrupt_generation(), g0);
        // a network change while the stop sequence runs (adapters going down at shutdown) must
        // not cancel the "going offline" send either
        sh.connectivity_changed();
        assert_eq!(sh.interrupt_generation(), g0);
        sh.set_long_poll_active(false);
    }

    #[test]
    fn wait_retry_returns_on_kick_not_on_push() {
        let sh = test_shared();
        let sh2 = sh.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            sh2.ctx.sender_wake.notify(); // ordinary push: must not end the wait
            std::thread::sleep(Duration::from_millis(30));
            sh2.kick();
        });
        let start = Instant::now();
        sh.wait_retry(&sh.ctx.sender_wake, Duration::from_secs(10));
        let el = start.elapsed();
        t.join().unwrap();
        assert!(el >= Duration::from_millis(50) && el < Duration::from_secs(5), "{el:?}");
    }
}
