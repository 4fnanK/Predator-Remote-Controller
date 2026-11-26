//! Login monitoring: Security event log (4624/4625/4634/4647/4778/4779) and the OpenSSH
//! operational + admin logs, via persistent-bookmark event-log subscriptions. Event driven: the
//! monitor thread sleeps in WaitForMultipleObjects until Windows signals new matching events.
//!
//! Thread model: ONE thread ("monitor") waits on `[ctx.stop, own stop, settings-changed,
//! security signal, ssh signal, ssh-admin signal]`. Each wake drains the signalled pull-mode
//! subscriptions (`EvtNext`, 32 events per batch); every event is rendered, classified and handed to
//! `ctx.emit_event` — only after that succeeded is the in-memory bookmark advanced, and the
//! bookmark XML is persisted after each drained batch. A failed `emit_event` (queue not
//! persisted) keeps the event — with its cached classification — at the head of a small
//! pending queue and retries later, so no alert is lost or classified twice.
//!
//! Timers (no periodic wake at all while both monitors are off): EventLog-service watchdog and
//! sshd_config check every 5 min, audit-policy re-check every 10 min (and immediately on event
//! 4719), bookmark refresh hourly, plus one-shot deadlines (subscription retry with exponential
//! backoff, stalled-queue retry, held console disconnects, failed-login summary, history write).
//!
//! Reading: a channel is drained only when its own signal is set. Once a pull subscription was
//! read to the end, wevtapi answers every further `EvtNext` with 4317 until it signals new
//! records ([`eventlog::Fetch::Waiting`]); reading unsignalled channels — and taking that 4317
//! for a broken subscription — was the cause of a reopen spin at ~1000 iterations/s.
//!
//! Failure recovery ([`Supervisor`], a pure state machine): a read failure reopens the channel
//! at once at most once per 5 minutes, otherwise after an exponential backoff (5 s … 10 min);
//! the failure history is forgotten only after the channel worked for 5 minutes (one clean read
//! proves nothing). When every enabled channel fails with the same error 3 times in a row, all
//! subscriptions are closed and reopened together after a shared backoff (fresh wevtapi state);
//! meanwhile the monitors report an error so the session-change fallback reports logons.

pub mod audit;
pub mod eventlog;
pub mod logon;
pub mod ssh;
pub mod xml;

use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use windows_sys::Win32::Foundation::{ERROR_INVALID_OPERATION, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS, WTSClientAddress, WTSClientName, WTSDomainName, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSUserName,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

use crate::context::{AppContext, MonitorState};
use crate::features::Feature;
use crate::notify::{EventDetails, NotificationKind};
use crate::util::Backoff;
use crate::util::win::{OwnedEvent, WinError, error_message, from_wide_ptr};
use eventlog::{ErrorClass, EvtHandle, Fetch, Gap, Subscription};

/// Result of classifying one event record.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Nothing to report (short reason, for debug logs).
    Ignore(&'static str),
    /// A login-type event for `ctx.emit_event`.
    Event(EventDetails),
    /// A security alert for `ctx.emit_security` (e.g. the audit log was cleared).
    Security { title: String, lines: Vec<(String, String)> },
    /// The system audit policy changed (4719): re-check the logon audit policy now.
    AuditPolicyChanged,
}

/// EventLog-service watchdog (PID check) and sshd_config check period.
const WATCHDOG: Duration = Duration::from_secs(300);
/// Audit-policy re-check period (also re-checked at once when event 4719 arrives).
const AUDIT_RECHECK: Duration = Duration::from_secs(600);
/// Bookmark refresh / OpenSSH channel-configuration check period.
const HOURLY: Duration = Duration::from_secs(3600);
/// Retry period for deliveries that failed because the queue could not be written.
const STALL_RETRY: Duration = Duration::from_secs(60);
/// Exponential backoff for (re)subscribing after EvtSubscribe/EvtNext failures.
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(600);
/// Tolerance when checking whether a timer is due (the wait timeout is rounded).
const DUE_SLACK: Duration = Duration::from_millis(500);
/// Shortest wait (a due deadline that cannot be cleared must not turn into a busy loop).
const MIN_WAIT: Duration = Duration::from_secs(1);
/// Batches drained per wake before giving the wait loop (stop/settings) a turn.
const MAX_BATCHES_PER_WAKE: usize = 64;
/// Delay before the thread restarts after an internal panic.
const CRASH_RESTART_DELAY: Duration = Duration::from_secs(60);
/// A reopened channel is healthy again (failure count and backoff forgotten) only after it
/// worked this long without a read failure.
const HEALTHY_AFTER: Duration = Duration::from_secs(300);
/// At most one immediate reopen per channel in this period; other failures wait with backoff.
const IMMEDIATE_REOPEN_PERIOD: Duration = Duration::from_secs(300);
/// Consecutive same-error read failures of every enabled channel before all subscriptions are
/// closed and reopened together.
const GLOBAL_RESET_AFTER: u32 = 3;
/// A due retry also reopens other channels whose retry is due within this time (one wake).
const RETRY_COALESCE: Duration = Duration::from_secs(5);
/// Signalled drains in a row whose first read found nothing new (4317) before the subscription
/// is considered stuck and reopened (wevtapi signals only when it has new records).
const SPURIOUS_WAIT_LIMIT: u32 = 3;
/// `EvtNext` time-outs in one drain before draining is retried after [`STALL_RETRY`].
const MAX_TIMEOUTS_PER_DRAIN: usize = 3;

const AUDIT_OFF: &str = "Logon auditing is turned off in the Windows audit policy, so logins are not recorded — \
                         run 'predator-service audit enable' as administrator";
const QUEUE_STALLED: &str = "notifications cannot be saved to the queue (disk full or access denied?); retrying";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Security,
    Ssh,
    /// `OpenSSH/Admin` (MaxAuthTries and other `error:` lines). Optional: its state is not
    /// shown in the status (the OpenSSH monitor state is the Operational channel's).
    SshAdmin,
}

const ALL: [Which; 3] = [Which::Security, Which::Ssh, Which::SshAdmin];

impl Which {
    /// Index into per-channel arrays (same order as [`ALL`]).
    fn idx(self) -> usize {
        match self {
            Which::Security => 0,
            Which::Ssh => 1,
            Which::SshAdmin => 2,
        }
    }

    /// Bookmark file / dedupe-key prefix.
    fn key(self) -> &'static str {
        match self {
            Which::Security => "security",
            Which::Ssh => "openssh",
            Which::SshAdmin => "openssh-admin",
        }
    }

    fn channel(self) -> &'static str {
        match self {
            Which::Security => "Security",
            Which::Ssh => ssh::OPENSSH_CHANNEL,
            Which::SshAdmin => ssh::OPENSSH_ADMIN_CHANNEL,
        }
    }

    fn query(self) -> &'static str {
        match self {
            Which::Security => logon::SECURITY_QUERY,
            Which::Ssh => ssh::OPENSSH_QUERY,
            Which::SshAdmin => ssh::OPENSSH_ADMIN_QUERY,
        }
    }

    fn feature(self) -> Feature {
        match self {
            Which::Security => Feature::LoginMonitoring,
            Which::Ssh | Which::SshAdmin => Feature::SshMonitoring,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Which::Security => "Security log",
            Which::Ssh => "OpenSSH log",
            Which::SshAdmin => "OpenSSH admin log",
        }
    }
}

fn set_status(ctx: &AppContext, which: Which, st: MonitorState) {
    match which {
        Which::Security => ctx.status.set_security(st),
        Which::Ssh => ctx.status.set_ssh(st),
        Which::SshAdmin => {}
    }
}

/// Mark every enabled monitor as failed (thread could not start / crashed).
fn set_enabled_error(ctx: &AppContext, msg: &str) {
    let s = ctx.settings.get();
    for which in ALL {
        if s.features.is_enabled(which.feature()) {
            set_status(ctx, which, MonitorState::Error(msg.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Event processing pipeline (generic so the retry logic is unit-testable)
// ---------------------------------------------------------------------------------------------

/// Classifier for one channel's events.
trait Classify {
    fn classify_record(&mut self, rec: &xml::EventRecord) -> Outcome;
}

impl Classify for logon::LogonTracker {
    fn classify_record(&mut self, rec: &xml::EventRecord) -> Outcome {
        self.classify(rec)
    }
}

impl Classify for ssh::SshTracker {
    fn classify_record(&mut self, rec: &xml::EventRecord) -> Outcome {
        self.classify(rec)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Classified {
    outcome: Outcome,
    /// EventRecordID (0 when unknown).
    record_id: u64,
    /// TimeCreated as FILETIME: record ids restart at 1 after a log clear, so the idempotency
    /// key needs both.
    time_filetime: Option<u64>,
}

impl Classified {
    fn ignored(why: &'static str) -> Self {
        Self { outcome: Outcome::Ignore(why), record_id: 0, time_filetime: None }
    }
}

/// Idempotency key of an event-log record: `security:<EventRecordID>:<TimeCreated FILETIME>`.
/// A replay of the same record (resubscribe, crash before the bookmark was saved) yields the
/// same key; a reused record number in a cleared log does not.
fn dedupe_key(which: Which, c: &Classified) -> Option<String> {
    (c.record_id != 0).then(|| format!("{}:{}:{}", which.key(), c.record_id, c.time_filetime.unwrap_or(0)))
}

/// An event fetched from the log but not yet durably handled.
struct Pending<E> {
    ev: E,
    /// Cached classification: classifiers are stateful, so a retry must reuse it.
    classified: Option<Classified>,
}

impl<E> Pending<E> {
    fn new(ev: E) -> Self {
        Self { ev, classified: None }
    }
}

trait EventSink<E> {
    fn classify(&mut self, ev: &E) -> Classified;
    /// Hand the outcome over (queue it durably). `Err` = retry later.
    fn deliver(&mut self, c: &Classified) -> std::io::Result<()>;
    /// The event was handled: advance the bookmark past it.
    fn commit(&mut self, ev: &E);
}

/// Handle queued events in order. Stops at the first delivery error, leaving that event (with
/// its classification cached) at the front. Returns the number of events handled.
fn process_queue<E, S: EventSink<E>>(sink: &mut S, queue: &mut VecDeque<Pending<E>>) -> std::io::Result<usize> {
    let mut done = 0;
    while let Some(front) = queue.front_mut() {
        if front.classified.is_none() {
            front.classified = Some(sink.classify(&front.ev));
        }
        if let Some(c) = &front.classified {
            sink.deliver(c)?;
        }
        sink.commit(&front.ev);
        queue.pop_front();
        done += 1;
    }
    Ok(done)
}

/// Production sink: render + parse + classify, deliver through a callback, advance the bookmark.
struct LiveSink<'a> {
    sub: &'a mut Subscription,
    classifier: &'a mut dyn Classify,
    deliver: &'a mut dyn FnMut(&Classified) -> std::io::Result<()>,
    label: &'static str,
}

impl EventSink<EvtHandle> for LiveSink<'_> {
    fn classify(&mut self, ev: &EvtHandle) -> Classified {
        let xml = match self.sub.render_xml(ev) {
            Ok(x) => x,
            Err(e) => {
                crate::log_warn!("{}: cannot render an event ({e}); skipped", self.label);
                return Classified::ignored("render failed");
            }
        };
        let Some(rec) = xml::parse_event(&xml) else {
            crate::log_warn!("{}: unparsable event XML ({} chars); skipped", self.label, xml.len());
            return Classified::ignored("unparsable XML");
        };
        let outcome = self.classifier.classify_record(&rec);
        if let Outcome::Ignore(why) = &outcome {
            crate::log_debug!("{}: event {} (record {}) ignored: {why}", self.label, rec.event_id, rec.record_id);
        }
        Classified { outcome, record_id: rec.record_id, time_filetime: rec.time_filetime }
    }

    fn deliver(&mut self, c: &Classified) -> std::io::Result<()> {
        (self.deliver)(c)
    }

    fn commit(&mut self, ev: &EvtHandle) {
        if let Err(e) = self.sub.advance(ev) {
            crate::log_warn!("{}: {e}", self.label);
        }
    }
}

#[derive(Debug, Default)]
struct DrainStats {
    fetched: usize,
    handled: usize,
    /// Delivery failed; the front event stays pending.
    stalled: bool,
    /// Stopped early (batch limit or stop request); more events may be waiting.
    more: bool,
    /// `EvtNext` failed with this Win32 error: the subscription must be reopened.
    broken: Option<u32>,
    /// The drain was started by the signal, yet the very first read had nothing new (4317).
    spurious: bool,
    /// The server kept timing out ([`MAX_TIMEOUTS_PER_DRAIN`]): drain again later.
    timed_out: bool,
    save_error: Option<String>,
}

/// Drain one subscription: pending events first, then `EvtNext` batches until empty.
/// The bookmark is persisted after every handled batch. `signaled`: wevtapi (or the engine)
/// set the channel's signal before this drain.
fn drain_channel(
    sub: &mut Subscription,
    pending: &mut VecDeque<Pending<EvtHandle>>,
    classifier: &mut dyn Classify,
    deliver: &mut dyn FnMut(&Classified) -> std::io::Result<()>,
    should_stop: &dyn Fn() -> bool,
    signaled: bool,
    label: &'static str,
) -> DrainStats {
    let mut st = DrainStats::default();
    let mut batches = 0;
    let mut reads = 0usize;
    let mut timeouts = 0usize;
    loop {
        if !pending.is_empty() {
            let res = {
                let mut sink = LiveSink { sub: &mut *sub, classifier: &mut *classifier, deliver: &mut *deliver, label };
                process_queue(&mut sink, pending)
            };
            if let Err(e) = sub.save_bookmark() {
                st.save_error = Some(e);
            }
            match res {
                Ok(n) => st.handled += n,
                Err(e) => {
                    crate::log_error!("{label}: cannot queue a notification ({e}); will retry");
                    st.stalled = true;
                    return st;
                }
            }
        }
        if batches >= MAX_BATCHES_PER_WAKE || should_stop() {
            st.more = true;
            return st;
        }
        let mut batch = Vec::with_capacity(eventlog::BATCH);
        let fetched = sub.next_batch(&mut batch);
        reads += 1;
        match fetched {
            Ok(Fetch::Events) => {
                timeouts = 0;
                st.fetched += batch.len();
                batches += 1;
                pending.extend(batch.into_iter().map(Pending::new));
            }
            Ok(Fetch::Drained) => return st,
            Ok(Fetch::Waiting) => {
                // nothing new since the last drain: normal for an unsignalled read
                st.spurious = signaled && reads == 1;
                return st;
            }
            Ok(Fetch::Timeout) => {
                timeouts += 1;
                batches += 1;
                if timeouts >= MAX_TIMEOUTS_PER_DRAIN {
                    crate::log_debug!("{label}: the event log did not answer in time; reading again later");
                    st.timed_out = true;
                    return st;
                }
            }
            Err(code) => {
                st.broken = Some(code);
                return st;
            }
        }
    }
}

/// Deliver one classified event through the context (feature gating, history, rate limits and
/// durable queueing happen inside `emit_event`).
fn deliver_outcome(ctx: &AppContext, which: Which, c: &Classified) -> std::io::Result<()> {
    match &c.outcome {
        Outcome::Ignore(_) | Outcome::AuditPolicyChanged => Ok(()),
        Outcome::Event(d) => {
            let queued = ctx.emit_event(d.clone(), dedupe_key(which, c))?;
            let failure = matches!(d.kind, NotificationKind::FailedLogin | NotificationKind::SshFailed);
            if queued {
                crate::log_info!("{}: {:?} · {} · {}", which.label(), d.kind, d.user, d.method);
            } else if failure {
                // rate-limited / switched-off failures: counted and kept in the history, but a
                // password spray must not flood the log file
                crate::log_debug!("{}: {:?} · {} · {} (not sent)", which.label(), d.kind, d.user, d.method);
            } else {
                crate::log_info!(
                    "{}: {:?} · {} · {} (not sent: disabled or duplicate)",
                    which.label(),
                    d.kind,
                    d.user,
                    d.method
                );
            }
            Ok(())
        }
        Outcome::Security { title, lines } => {
            ctx.emit_security_keyed(title, lines, dedupe_key(which, c))?;
            crate::log_warn!("{}: security alert: {title}", which.label());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Failure recovery: a pure state machine (time is passed in, no Win32) used by the engine
// ---------------------------------------------------------------------------------------------

/// What to do after a read (`EvtNext`) failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// Reopen the channel now (at most once per [`IMMEDIATE_REOPEN_PERIOD`]).
    ReopenNow,
    /// Close the channel; it is reopened at this instant (exponential backoff).
    Retry(Instant),
    /// Every enabled channel keeps failing with `code`: close all subscriptions and reopen them
    /// together at `at`.
    ResetAll { at: Instant, code: u32 },
}

/// Next backoff delay WITHOUT the clock-derived jitter of [`Backoff::next_delay`]: the three
/// channels talk to one local service (no thundering herd), and channels that fail together
/// must also retry together — jitter would split one wake into three.
fn backoff_step(b: &mut Backoff) -> Duration {
    let d = b.current();
    let _ = b.next_delay();
    d
}

/// Failure history of one channel.
#[derive(Debug, Clone)]
struct Recovery {
    /// Failures (open or read) since the channel was last healthy.
    failures: u32,
    /// Code of the last read failure and how many read failures in a row had it.
    last_code: Option<u32>,
    same_code: u32,
    last_immediate: Option<Instant>,
    backoff: Backoff,
    /// When the current subscription was opened (`None` while closed).
    open_since: Option<Instant>,
    /// When to reopen the closed channel (`None`: not scheduled, or waiting for the global reset).
    retry_at: Option<Instant>,
    /// The last attempt to open failed (the channel is not part of a global reset).
    open_failing: bool,
}

impl Recovery {
    fn new() -> Self {
        Self {
            failures: 0,
            last_code: None,
            same_code: 0,
            last_immediate: None,
            backoff: Backoff::new(RETRY_MIN, RETRY_MAX),
            open_since: None,
            retry_at: None,
            open_failing: false,
        }
    }

    /// When the open subscription counts as healthy again (`None`: no incident, or closed).
    fn healthy_at(&self) -> Option<Instant> {
        if self.failures == 0 {
            return None;
        }
        self.open_since.map(|t| t + HEALTHY_AFTER)
    }

    /// Forget the failure history once the subscription worked for [`HEALTHY_AFTER`].
    /// Returns true when an incident ended.
    fn heal_if_due(&mut self, now: Instant) -> bool {
        let due = self.healthy_at().is_some_and(|t| t <= now + DUE_SLACK);
        if due {
            self.failures = 0;
            self.last_code = None;
            self.same_code = 0;
            self.backoff.reset();
        }
        due
    }
}

/// Recovery policy of the three channels (see the module docs). Never asks for more than one
/// immediate reopen per channel per 5 minutes; every other reopen waits ≥ 5 s, doubling to
/// 10 minutes, so no failure mode can spin.
#[derive(Debug)]
struct Supervisor {
    rec: [Recovery; 3],
    global_backoff: Backoff,
    /// All channels were closed together; reopen them at this instant.
    global_at: Option<Instant>,
}

impl Supervisor {
    fn new() -> Self {
        Self {
            rec: [Recovery::new(), Recovery::new(), Recovery::new()],
            global_backoff: Backoff::new(RETRY_MIN, RETRY_MAX),
            global_at: None,
        }
    }

    fn rec(&self, w: Which) -> &Recovery {
        &self.rec[w.idx()]
    }

    /// The channel was switched on or off: forget its history.
    fn reset(&mut self, w: Which) {
        self.rec[w.idx()] = Recovery::new();
        if self.rec.iter().all(|r| r.failures == 0) {
            self.global_at = None;
            self.global_backoff.reset();
        }
    }

    /// The subscription was opened.
    fn opened(&mut self, w: Which, now: Instant) {
        let r = &mut self.rec[w.idx()];
        r.open_since = Some(now);
        r.retry_at = None;
        r.open_failing = false;
    }

    /// Opening failed: retry after the backoff. Returns the retry instant.
    fn open_failed(&mut self, w: Which, now: Instant) -> Instant {
        let r = &mut self.rec[w.idx()];
        r.open_since = None;
        r.failures = r.failures.saturating_add(1);
        r.open_failing = true;
        let at = now + backoff_step(&mut r.backoff);
        r.retry_at = Some(at);
        at
    }

    /// Reading failed with `code`. `enabled[i]`: channel `i` is switched on.
    fn read_failed(&mut self, w: Which, code: u32, now: Instant, enabled: [bool; 3]) -> Decision {
        let r = &mut self.rec[w.idx()];
        // it worked long enough before this failure: a new incident, not a continuation
        r.heal_if_due(now);
        r.open_since = None;
        r.failures = r.failures.saturating_add(1);
        if r.last_code == Some(code) {
            r.same_code = r.same_code.saturating_add(1);
        } else {
            r.last_code = Some(code);
            r.same_code = 1;
        }
        if let Some(d) = self.global_reset(code, now, enabled) {
            return d;
        }
        let r = &mut self.rec[w.idx()];
        if r.last_immediate.is_none_or(|t| now.saturating_duration_since(t) >= IMMEDIATE_REOPEN_PERIOD) {
            r.last_immediate = Some(now);
            return Decision::ReopenNow;
        }
        let at = now + backoff_step(&mut r.backoff);
        r.retry_at = Some(at);
        Decision::Retry(at)
    }

    /// Channels that share the read path: switched on and openable.
    fn participants(&self, enabled: [bool; 3]) -> impl Iterator<Item = Which> + '_ {
        ALL.into_iter().filter(move |w| enabled[w.idx()] && !self.rec[w.idx()].open_failing)
    }

    /// All participants (at least two) failed [`GLOBAL_RESET_AFTER`] times in a row with
    /// `code`: schedule one shared reopen, never sooner than any of their own retries.
    fn global_reset(&mut self, code: u32, now: Instant, enabled: [bool; 3]) -> Option<Decision> {
        let parts: Vec<Which> = self.participants(enabled).collect();
        let all_alike = parts
            .iter()
            .all(|w| self.rec[w.idx()].last_code == Some(code) && self.rec[w.idx()].same_code >= GLOBAL_RESET_AFTER);
        if parts.len() < 2 || !all_alike {
            return None;
        }
        let mut at = now + backoff_step(&mut self.global_backoff);
        // reopened together, they should also back off in step (one wake instead of three)
        let slowest = parts.iter().map(|w| self.rec[w.idx()].backoff.clone()).max_by_key(Backoff::current);
        for w in parts {
            let r = &mut self.rec[w.idx()];
            if let Some(t) = r.retry_at.take() {
                at = at.max(t);
            }
            if let Some(b) = &slowest {
                r.backoff = b.clone();
            }
            r.same_code = 0;
            r.open_since = None;
        }
        self.global_at = Some(at);
        Some(Decision::ResetAll { at, code })
    }

    /// A healthy period ended an incident of channel `w` (call while it is open).
    fn heal_if_due(&mut self, w: Which, now: Instant) -> bool {
        let healed = self.rec[w.idx()].heal_if_due(now);
        if healed && self.rec.iter().all(|r| r.failures == 0) {
            self.global_backoff.reset();
        }
        healed
    }

    /// Channels to reopen now; `closed[i]`: channel `i` is switched on but has no subscription.
    /// A due retry also takes the retries due within [`RETRY_COALESCE`]. The bool is true when
    /// the shared (global) reopen is due.
    fn due_reopens(&mut self, now: Instant, closed: [bool; 3]) -> (Vec<Which>, bool) {
        let global_due = self.global_at.is_some_and(|t| t <= now + DUE_SLACK);
        if global_due {
            self.global_at = None;
        }
        let global_pending = self.global_at.is_some();
        let any_due =
            ALL.iter().any(|w| closed[w.idx()] && self.rec[w.idx()].retry_at.is_some_and(|t| t <= now + DUE_SLACK));
        let mut out = Vec::new();
        for w in ALL {
            if !closed[w.idx()] {
                continue;
            }
            let r = &mut self.rec[w.idx()];
            let take = match r.retry_at {
                // closed for the global reset (or never scheduled)
                None => !global_pending,
                Some(t) => any_due && t <= now + RETRY_COALESCE,
            };
            if take {
                r.retry_at = None;
                out.push(w);
            }
        }
        (out, global_due)
    }

    /// Next deadline: retries of closed channels, the shared reopen and the health check of
    /// reopened channels (`open[i]`: channel `i` has a subscription).
    fn next_deadline(&self, open: [bool; 3], closed: [bool; 3]) -> Option<Instant> {
        let mut next = self.global_at.filter(|_| closed.iter().any(|c| *c));
        for w in ALL {
            let r = &self.rec[w.idx()];
            if closed[w.idx()] {
                next = earliest(next, r.retry_at);
            }
            if open[w.idx()] {
                next = earliest(next, r.healthy_at());
            }
        }
        next
    }
}

// ---------------------------------------------------------------------------------------------
// Monitor engine (owned by the monitor thread)
// ---------------------------------------------------------------------------------------------

struct Channel {
    /// Manual-reset event passed to EvtSubscribe (created signaled; set again after each open).
    signal: OwnedEvent,
    enabled: bool,
    sub: Option<Subscription>,
    pending: VecDeque<Pending<EvtHandle>>,
    stalled: bool,
    /// When to retry delivering the stalled pending events.
    drain_retry_at: Option<Instant>,
    /// The last drain read everything that was available (no stall, no batch limit, no error).
    drained: bool,
    /// Subscription could not be opened / read (retrying).
    error: Option<String>,
    /// Open, but Windows will not log what we need (audit policy, sshd_config, disabled channel).
    problem: Option<String>,
    /// Signalled drains in a row whose first read had nothing new ([`SPURIOUS_WAIT_LIMIT`]).
    spurious_waits: u32,
    /// Problem that was logged and has not recovered yet (logging once per state change).
    incident: Option<String>,
    /// "monitoring <channel>" was logged.
    announced: bool,
    /// A gap notice that could not be queued yet.
    pending_gap: Option<Gap>,
    save_error: Option<String>,
}

impl Channel {
    fn new() -> Result<Self, WinError> {
        Ok(Self {
            signal: OwnedEvent::create(true, true)?,
            enabled: false,
            sub: None,
            pending: VecDeque::new(),
            stalled: false,
            drain_retry_at: None,
            drained: false,
            error: None,
            problem: None,
            spurious_waits: 0,
            incident: None,
            announced: false,
            pending_gap: None,
            save_error: None,
        })
    }

    fn state(&self) -> MonitorState {
        if !self.enabled {
            MonitorState::Disabled
        } else if let Some(e) = &self.error {
            MonitorState::Error(e.clone())
        } else if self.stalled {
            MonitorState::Error(QUEUE_STALLED.to_string())
        } else if let Some(p) = &self.problem {
            MonitorState::Error(p.clone())
        } else if self.sub.is_some() {
            MonitorState::Active
        } else {
            MonitorState::Starting
        }
    }

    /// Close the subscription (optionally persisting its bookmark) and drop pending events —
    /// they were not acknowledged, so they are re-read from the saved bookmark later.
    fn close(&mut self, save: bool) {
        if let Some(mut sub) = self.sub.take()
            && save
            && let Err(e) = sub.save_bookmark()
        {
            crate::log_warn!("{}: {e}", sub.channel());
        }
        self.pending.clear();
        self.stalled = false;
        self.drain_retry_at = None;
        self.drained = false;
        self.signal.reset();
    }

    /// Everything the subscription had was read to the end and handled, and wevtapi has not
    /// signalled new records since. Only then may the bookmark jump to the channel's newest
    /// record: after a drain that timed out, on a just reopened subscription (backlog not read
    /// yet) or with a record that was just signalled, unread records lie before that position
    /// and a restart would skip them.
    fn caught_up(&self) -> bool {
        self.sub.is_some()
            && self.drained
            && self.pending.is_empty()
            && !self.stalled
            && !self.signal.wait(Duration::ZERO)
    }

    /// Forget all failure state (channel switched on or off; the engine also resets its
    /// [`Supervisor`] entry).
    fn reset_state(&mut self) {
        self.error = None;
        self.problem = None;
        self.spurious_waits = 0;
        self.incident = None;
        self.announced = false;
        self.pending_gap = None;
    }
}

/// Events shared between `Monitors` (other threads) and the monitor thread.
struct Shared {
    stop: OwnedEvent,
    settings: OwnedEvent,
    stopping: AtomicBool,
}

struct Engine {
    ctx: Arc<AppContext>,
    shared: Arc<Shared>,
    sec: Channel,
    ssh: Channel,
    ssh_admin: Channel,
    /// Failure-recovery state of the three channels.
    sup: Supervisor,
    logon: logon::LogonTracker,
    /// Shared by the OpenSSH Operational and Admin channels.
    ssh_tracker: ssh::SshTracker,
    /// EventLog service PID when the subscriptions were opened (restart detection).
    eventlog_pid: Option<u32>,
    last_watchdog: Instant,
    last_audit: Instant,
    last_hourly: Instant,
    /// Gap notices / held events / failed-login summary could not be queued: retry after this.
    deferred_retry_at: Option<Instant>,
    audit_sufficient: Option<bool>,
    /// Logon success auditing at the last check (transition logging).
    logon_audit_on: Option<bool>,
    /// sshd_config modification time at the last check (`None` = never checked).
    sshd_cfg_stamp: Option<Option<SystemTime>>,
    sshd_cfg_problem: Option<String>,
    ssh_channel_problem: Option<String>,
}

fn position_at_newest(sub: &mut Subscription, which: Which) {
    match eventlog::newest_record(which.channel()) {
        Ok(Some(newest)) => {
            if let Err(e) = sub.advance(&newest) {
                crate::log_debug!("{}: cannot position the bookmark: {e}", which.label());
            } else if let Err(e) = sub.save_bookmark() {
                crate::log_warn!("{}: {e}", which.label());
            }
        }
        Ok(None) => {}
        Err(e) => crate::log_debug!("{}: cannot read the newest record ({e})", which.label()),
    }
}

fn open_error_text(which: Which, e: &WinError) -> String {
    match (eventlog::classify_error(e.code), which) {
        (ErrorClass::AccessDenied, Which::Security) => {
            "Access to the Security event log was denied — the service must run as LocalSystem".to_string()
        }
        (ErrorClass::AccessDenied, Which::Ssh | Which::SshAdmin) => {
            format!("Access to the {} event log was denied", which.channel())
        }
        (ErrorClass::ChannelNotFound, Which::Ssh) => "OpenSSH Server not installed".to_string(),
        (ErrorClass::ChannelNotFound, Which::SshAdmin) => "OpenSSH admin log not found".to_string(),
        (ErrorClass::ChannelNotFound, Which::Security) => "Security event log not found".to_string(),
        (ErrorClass::ServiceUnavailable, _) => {
            format!("Windows Event Log service unavailable ({}); retrying", error_message(e.code))
        }
        _ => format!("Cannot read the {} log: {} (error {})", which.channel(), error_message(e.code), e.code),
    }
}

/// EventLog service PID: `Some(0)` when it is not running, `None` when unknown.
fn query_eventlog_pid() -> Option<u32> {
    use crate::sys::ServiceState;
    match std::panic::catch_unwind(|| crate::sys::scm::query("EventLog")) {
        Ok((ServiceState::Running, pid)) if pid != 0 => Some(pid),
        Ok((ServiceState::Stopped | ServiceState::StopPending | ServiceState::StartPending, _)) => Some(0),
        _ => None,
    }
}

/// Earlier of two optional deadlines.
fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Instant of a wall-clock Unix time (`now` ↔ `now_unix`), never in the past.
fn instant_at(now: Instant, now_unix: i64, unix: i64) -> Instant {
    now + Duration::from_secs(u64::try_from(unix.saturating_sub(now_unix)).unwrap_or(0))
}

/// `WaitForMultipleObjects` timeout for the next deadline (`INFINITE` when there is none).
fn wait_ms(now: Instant, next: Option<Instant>) -> u32 {
    match next {
        None => INFINITE,
        Some(t) => {
            let d = t.saturating_duration_since(now).max(MIN_WAIT);
            u32::try_from(d.as_millis()).unwrap_or(INFINITE - 1).min(INFINITE - 1)
        }
    }
}

impl Engine {
    fn new(ctx: Arc<AppContext>, shared: Arc<Shared>) -> Result<Self, WinError> {
        let computer = ctx.computer_name.clone();
        let now = Instant::now();
        Ok(Self {
            sec: Channel::new()?,
            ssh: Channel::new()?,
            ssh_admin: Channel::new()?,
            sup: Supervisor::new(),
            logon: logon::LogonTracker::new(&computer),
            ssh_tracker: ssh::SshTracker::new(&computer),
            eventlog_pid: None,
            last_watchdog: now,
            last_audit: now,
            last_hourly: now,
            deferred_retry_at: None,
            audit_sufficient: None,
            logon_audit_on: None,
            sshd_cfg_stamp: None,
            sshd_cfg_problem: None,
            ssh_channel_problem: None,
            ctx,
            shared,
        })
    }

    fn chan(&mut self, which: Which) -> &mut Channel {
        match which {
            Which::Security => &mut self.sec,
            Which::Ssh => &mut self.ssh,
            Which::SshAdmin => &mut self.ssh_admin,
        }
    }

    fn chans(&self) -> [&Channel; 3] {
        [&self.sec, &self.ssh, &self.ssh_admin]
    }

    fn any_open(&self) -> bool {
        self.chans().iter().any(|c| c.sub.is_some())
    }

    /// Per channel (in [`ALL`] order): switched on.
    fn enabled_flags(&self) -> [bool; 3] {
        self.chans().map(|c| c.enabled)
    }

    /// Per channel: has a subscription.
    fn open_flags(&self) -> [bool; 3] {
        self.chans().map(|c| c.sub.is_some())
    }

    /// Per channel: switched on but without a subscription (waiting for a reopen).
    fn closed_flags(&self) -> [bool; 3] {
        self.chans().map(|c| c.enabled && c.sub.is_none())
    }

    fn stopping(&self) -> bool {
        self.ctx.stop.is_stopped() || self.shared.stopping.load(Ordering::SeqCst)
    }

    fn run(&mut self) {
        self.reconcile(true);
        loop {
            if self.stopping() {
                break;
            }
            let handles: [HANDLE; 6] = [
                self.ctx.stop.event_handle(),
                self.shared.stop.raw(),
                self.shared.settings.raw(),
                self.sec.signal.raw(),
                self.ssh.signal.raw(),
                self.ssh_admin.signal.raw(),
            ];
            let timeout = self.next_timeout_ms();
            // SAFETY: six valid event handles kept alive by `self` for the whole wait.
            let r = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout) };
            match r.wrapping_sub(WAIT_OBJECT_0) {
                0 | 1 => break,
                2 => {
                    self.shared.settings.reset();
                    self.reconcile(false);
                }
                3..=5 => {
                    // drain every signalled channel (a constantly signalled one must not starve
                    // the others), but never an unsignalled one: after a drain wevtapi has
                    // nothing to give until it signals (4317)
                    for which in ALL {
                        if self.chan(which).signal.wait(Duration::ZERO) {
                            self.drain(which);
                        }
                    }
                }
                _ if r == WAIT_TIMEOUT => {}
                _ => {
                    crate::log_error!("login monitor: {}", WinError::last("WaitForMultipleObjects"));
                    if self.ctx.stop.sleep(Duration::from_secs(5)) {
                        break;
                    }
                }
            }
            if self.stopping() {
                break;
            }
            self.tick();
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        for which in ALL {
            self.chan(which).close(true);
        }
        // console disconnects still held back are reported now (they would be lost otherwise)
        self.release_held(true);
        crate::log_info!("login monitor stopped");
    }

    /// Time until the next deadline; `INFINITE` when nothing is enabled, pending or retrying.
    fn next_timeout_ms(&self) -> u32 {
        let now = Instant::now();
        let now_unix = crate::util::time::now_unix();
        let any_open = self.any_open();
        let mut next: Option<Instant> = None;
        if any_open || self.ssh.enabled {
            next = earliest(next, Some(self.last_watchdog + WATCHDOG));
        }
        if self.sec.enabled {
            next = earliest(next, Some(self.last_audit + AUDIT_RECHECK));
        }
        if any_open {
            next = earliest(next, Some(self.last_hourly + HOURLY));
        }
        for ch in self.chans() {
            next = earliest(next, ch.drain_retry_at);
        }
        next = earliest(next, self.sup.next_deadline(self.open_flags(), self.closed_flags()));
        let mut deferred: Option<Instant> = None;
        if self.chans().iter().any(|c| c.pending_gap.is_some()) {
            deferred = Some(now);
        }
        if let Some(due) = self.logon.next_release() {
            deferred = earliest(deferred, Some(instant_at(now, now_unix, due)));
        }
        if let Some(due) = self.ctx.suppressed_flush_due() {
            deferred = earliest(deferred, Some(instant_at(now, now_unix, due)));
        }
        if let (Some(d), Some(blocked)) = (deferred, self.deferred_retry_at) {
            deferred = Some(d.max(blocked));
        }
        next = earliest(next, deferred);
        if let Some(d) = self.ctx.history.pending_flush_in() {
            next = earliest(next, Some(now + d));
        }
        wait_ms(now, next)
    }

    fn publish_status(&mut self) {
        self.ssh.problem = self.ssh_channel_problem.clone().or_else(|| self.sshd_cfg_problem.clone());
        self.ctx.status.set_security(self.sec.state());
        self.ctx.status.set_ssh(self.ssh.state());
    }

    /// Apply the feature switches: open newly enabled channels, close disabled ones (deleting
    /// their bookmark so that events of the disabled period are never replayed).
    fn reconcile(&mut self, initial: bool) {
        let s = self.ctx.settings.get();
        for which in ALL {
            let want = s.features.is_enabled(which.feature());
            let was = self.chan(which).enabled;
            if want && !was {
                if !self.chans().iter().any(|c| c.enabled) {
                    // the periodic timers were idle: start them from now
                    let now = Instant::now();
                    self.last_watchdog = now;
                    self.last_hourly = now;
                }
                {
                    let ch = self.chan(which);
                    ch.enabled = true;
                    ch.reset_state();
                }
                self.sup.reset(which);
                if !initial && which != Which::SshAdmin {
                    crate::log_info!("{}: monitoring enabled", which.label());
                }
                self.open_channel(which);
                match which {
                    Which::Security => self.audit_check(),
                    Which::Ssh => self.ssh_config_check(true),
                    Which::SshAdmin => {}
                }
            } else if !want && (was || initial) {
                {
                    let ch = self.chan(which);
                    ch.enabled = false;
                    ch.close(false);
                    ch.reset_state();
                }
                self.sup.reset(which);
                match which {
                    Which::Security => {
                        let dropped = self.logon.take_all();
                        if !dropped.is_empty() {
                            crate::log_debug!("Security log: {} held event(s) dropped (disabled)", dropped.len());
                        }
                    }
                    Which::Ssh => {
                        self.sshd_cfg_stamp = None;
                        self.sshd_cfg_problem = None;
                        self.ssh_channel_problem = None;
                    }
                    Which::SshAdmin => {}
                }
                eventlog::delete_bookmark(&self.ctx.paths.bookmark(which.key()));
                if was && which != Which::SshAdmin {
                    crate::log_info!("{}: monitoring disabled", which.label());
                }
            }
        }
        self.publish_status();
    }

    /// Log `msg` once per incident (state change), not on every retry.
    fn note_incident(&mut self, which: Which, msg: &str, detail: &str, quiet: bool) {
        let ch = self.chan(which);
        if ch.incident.as_deref() == Some(msg) {
            crate::log_debug!("{}: {msg} [{detail}] (still failing)", which.label());
            return;
        }
        ch.incident = Some(msg.to_string());
        if quiet {
            crate::log_debug!("{}: {msg} [{detail}]", which.label());
        } else {
            crate::log_warn!("{}: {msg} [{detail}]", which.label());
        }
    }

    /// Opening failed: close the channel and retry with exponential backoff (5 s … 10 min).
    fn fail(&mut self, which: Which, msg: String, err: &WinError) {
        let now = Instant::now();
        let at = self.sup.open_failed(which, now);
        self.retry_later(which, msg, err, at.saturating_duration_since(now));
    }

    /// Close the channel with `msg` as its error; the supervisor reopens it after `delay`.
    fn retry_later(&mut self, which: Which, msg: String, err: &WinError, delay: Duration) {
        self.chan(which).close(true);
        let quiet = which == Which::SshAdmin && eventlog::classify_error(err.code) == ErrorClass::ChannelNotFound;
        self.note_incident(which, &msg, &format!("{err}; retrying in {} s", delay.as_secs()), quiet);
        self.chan(which).error = Some(msg);
    }

    /// Every enabled channel kept failing with `code`: close every subscription; the supervisor
    /// reopens them together at `at`. Until then the monitors report the error (so the
    /// session-change fallback reports logons).
    fn reset_all(&mut self, at: Instant, code: u32) {
        let text = error_message(code);
        let secs = at.saturating_duration_since(Instant::now()).as_secs();
        crate::log_warn!(
            "login monitor: every monitored event log keeps failing with error {code} ({text}); closing all \
             subscriptions and reopening them together in {secs} s"
        );
        let msg = format!(
            "Reading the Windows event logs keeps failing ({text}, error {code}); all subscriptions are closed and \
             reopened together with backoff"
        );
        for which in ALL {
            let open_failing = self.sup.rec(which).open_failing;
            let ch = self.chan(which);
            ch.close(true);
            if ch.enabled && !open_failing {
                ch.error = Some(msg.clone());
                ch.incident = Some(msg.clone());
            }
        }
        self.publish_status();
    }

    fn set_ssh_channel_enabled(&mut self, enabled: bool) {
        let problem = (!enabled).then(|| {
            format!("The {0} event log is disabled — enable it with: wevtutil sl {0} /e:true", ssh::OPENSSH_CHANNEL)
        });
        if problem.is_some() && self.ssh_channel_problem.is_none() {
            crate::log_warn!("OpenSSH log: the {} channel is disabled", ssh::OPENSSH_CHANNEL);
        }
        self.ssh_channel_problem = problem;
    }

    /// (Re)open a channel from its saved bookmark; on failure schedule a retry with backoff.
    fn open_channel(&mut self, which: Which) {
        if matches!(which, Which::Ssh | Which::SshAdmin) {
            match eventlog::channel_enabled(which.channel()) {
                Err(e) if eventlog::classify_error(e.code) == ErrorClass::ChannelNotFound => {
                    self.fail(which, open_error_text(which, &e), &e);
                    self.publish_status();
                    return;
                }
                Ok(enabled) if which == Which::Ssh => self.set_ssh_channel_enabled(enabled),
                Ok(enabled) => {
                    if !enabled {
                        crate::log_debug!("the {} channel is disabled", which.channel());
                    }
                }
                Err(e) => crate::log_debug!("cannot read the {} channel configuration: {e}", which.channel()),
            }
        }
        let path = self.ctx.paths.bookmark(which.key());
        self.chan(which).close(true);
        let signal = self.chan(which).signal.raw();
        match Subscription::open(which.channel(), which.query(), signal, &path) {
            Ok((sub, gap)) => {
                self.sup.opened(which, Instant::now());
                let ch = self.chan(which);
                ch.sub = Some(sub);
                ch.error = None;
                ch.spurious_waits = 0;
                ch.signal.set(); // drain the backlog: wevtapi only signals new records
                if ch.incident.is_none() && !ch.announced {
                    ch.announced = true;
                    crate::log_info!("{}: monitoring {}", which.label(), which.channel());
                } else {
                    crate::log_debug!("{}: resubscribed to {}", which.label(), which.channel());
                }
                let had_gap = gap.is_some();
                // report the gap BEFORE the new position replaces the stale bookmark file
                let gap_pending = match gap {
                    Some(g) if !self.report_gap(which, &g) => {
                        self.chan(which).pending_gap = Some(g);
                        true
                    }
                    _ => false,
                };
                if let Some(sub) = self.chan(which).sub.as_mut()
                    && !sub.is_positioned()
                    && !gap_pending
                {
                    // fresh start: remember "now" so a restart resumes instead of skipping
                    position_at_newest(sub, which);
                    if had_gap && !sub.is_positioned() {
                        eventlog::delete_bookmark(&path); // nothing to replace the stale one
                    }
                }
                if self.eventlog_pid.is_none() {
                    self.eventlog_pid = query_eventlog_pid().filter(|p| *p != 0);
                }
            }
            Err(e) => {
                let msg = open_error_text(which, &e);
                self.fail(which, msg, &e);
            }
        }
        self.publish_status();
    }

    /// Queue the "monitoring gap" notice; false when it could not be queued (retried later).
    fn report_gap(&self, which: Which, gap: &Gap) -> bool {
        let mut lines = vec![("Log".to_string(), which.channel().to_string())];
        if let Some(r) = gap.last_record_id {
            lines.push(("Last processed record".to_string(), r.to_string()));
        }
        lines.push((
            "Details".to_string(),
            "The saved read position no longer exists (the log was cleared or rolled over while it was not \
             being read). Login events from that period may be missing; monitoring continues with new events."
                .to_string(),
        ));
        let key = gap.last_record_id.map(|r| format!("gap:{}:{r}", which.key()));
        match self.ctx.emit_system("⚠️", "LOGIN MONITOR GAP", &lines, crate::util::time::now_unix(), key) {
            Ok(_) => true,
            Err(e) => {
                crate::log_error!("{}: cannot queue the gap notice: {e}; will retry", which.label());
                false
            }
        }
    }

    /// Drain a channel; returns the number of events fetched from the log.
    fn drain(&mut self, which: Which) -> usize {
        let ctx = self.ctx.clone();
        let shared = self.shared.clone();
        let (ch, classifier): (&mut Channel, &mut dyn Classify) = match which {
            Which::Security => (&mut self.sec, &mut self.logon),
            Which::Ssh => (&mut self.ssh, &mut self.ssh_tracker),
            Which::SshAdmin => (&mut self.ssh_admin, &mut self.ssh_tracker),
        };
        // reset BEFORE draining so records written meanwhile signal again (no lost wake-up)
        let signaled = ch.signal.wait(Duration::ZERO);
        ch.signal.reset();
        let Some(sub) = ch.sub.as_mut() else {
            ch.pending.clear();
            return 0;
        };
        let mut audit_changed = false;
        let st = {
            let mut deliver = |c: &Classified| {
                if c.outcome == Outcome::AuditPolicyChanged {
                    audit_changed = true;
                    return Ok(());
                }
                deliver_outcome(&ctx, which, c)
            };
            let should_stop = || ctx.stop.is_stopped() || shared.stopping.load(Ordering::SeqCst);
            drain_channel(sub, &mut ch.pending, classifier, &mut deliver, &should_stop, signaled, which.label())
        };
        let was_stalled = ch.stalled;
        ch.stalled = st.stalled;
        ch.drain_retry_at = (st.stalled || st.timed_out).then(|| Instant::now() + STALL_RETRY);
        ch.drained = !st.more && !st.stalled && !st.timed_out && st.broken.is_none();
        if st.more {
            ch.signal.set(); // continue after the wait loop had a chance to see stop/settings
        }
        // wevtapi signals only when it has new records: a signalled drain that keeps finding
        // nothing means the subscription is stuck
        if signaled && st.broken.is_none() && !st.stalled {
            ch.spurious_waits = if st.spurious { ch.spurious_waits.saturating_add(1) } else { 0 };
        }
        let stuck = ch.spurious_waits >= SPURIOUS_WAIT_LIMIT;
        if stuck {
            ch.spurious_waits = 0;
        }
        match st.save_error {
            Some(e) => {
                if ch.save_error.as_deref() != Some(e.as_str()) {
                    crate::log_warn!("{}: {e}", which.label());
                }
                ch.save_error = Some(e);
            }
            None => ch.save_error = None,
        }
        if st.handled > 0 {
            crate::log_debug!("{}: handled {} event(s)", which.label(), st.handled);
        }
        // NOTE: a clean read does not end an incident — the supervisor declares the channel
        // healthy only after it worked for HEALTHY_AFTER (see `tick`)
        if let Some(code) = st.broken {
            self.read_failed(which, code);
        } else if stuck {
            crate::log_warn!(
                "{}: the {} subscription was signalled {SPURIOUS_WAIT_LIMIT} times without new records; resubscribing",
                which.label(),
                which.channel()
            );
            self.read_failed(which, ERROR_INVALID_OPERATION);
        } else if was_stalled != st.stalled {
            self.publish_status();
        }
        if audit_changed {
            crate::log_info!("audit policy changed (event 4719): re-checking the logon audit policy");
            self.audit_check();
        }
        st.fetched
    }

    /// An open channel that worked for [`HEALTHY_AFTER`] ends its incident ("monitoring X again").
    fn heal_if_due(&mut self, which: Which, now: Instant) {
        if self.chan(which).sub.is_none() || !self.sup.heal_if_due(which, now) {
            return;
        }
        let ch = self.chan(which);
        if let Some(prev) = ch.incident.take() {
            ch.announced = true;
            crate::log_info!("{}: monitoring {} again (after: {prev})", which.label(), which.channel());
        }
    }

    /// `EvtNext` failed: the [`Supervisor`] decides — reopen at once (at most once per 5 minutes
    /// per channel, typically an EventLog restart), retry with exponential backoff, or close all
    /// channels and reopen them together. No failure pattern can spin the CPU.
    fn read_failed(&mut self, which: Which, code: u32) {
        let err = WinError::new(code, "EvtNext");
        let msg = format!("Cannot read the {} log: {} (error {code}); retrying", which.channel(), error_message(code));
        let now = Instant::now();
        // it worked long enough before failing (its health check may not have run yet): the
        // earlier incident is over and this one is logged as new
        self.heal_if_due(which, now);
        match self.sup.read_failed(which, code, now, self.enabled_flags()) {
            Decision::ReopenNow => {
                self.note_incident(which, &msg, &format!("{err}; resubscribing"), false);
                self.chan(which).close(true);
                self.open_channel(which);
            }
            Decision::Retry(at) => {
                self.retry_later(which, msg, &err, at.saturating_duration_since(now));
                self.publish_status();
            }
            Decision::ResetAll { at, code } => self.reset_all(at, code),
        }
    }

    /// Periodic work. Every timer only runs when its feature needs it (see the module docs).
    fn tick(&mut self) {
        let now = Instant::now();
        let due = |last: Instant, period: Duration| now + DUE_SLACK >= last + period;
        let (reopen, global) = self.sup.due_reopens(now, self.closed_flags());
        if global && !reopen.is_empty() {
            crate::log_info!("login monitor: reopening all event-log subscriptions together");
        }
        for which in reopen {
            self.open_channel(which);
        }
        for which in ALL {
            self.heal_if_due(which, now);
        }
        for which in ALL {
            let retry = {
                let ch = self.chan(which);
                ch.sub.is_some() && ch.drain_retry_at.is_some_and(|t| t <= now + DUE_SLACK)
            };
            if retry {
                self.drain(which);
            }
        }
        if (self.any_open() || self.ssh.enabled) && due(self.last_watchdog, WATCHDOG) {
            self.last_watchdog = now;
            self.check_eventlog();
            if self.ssh.enabled {
                self.ssh_config_check(false);
            }
        }
        if self.sec.enabled && due(self.last_audit, AUDIT_RECHECK) {
            self.audit_check();
        }
        if self.any_open() && due(self.last_hourly, HOURLY) {
            self.last_hourly = now;
            if self.ssh.enabled && self.ssh.sub.is_some() {
                match eventlog::channel_enabled(ssh::OPENSSH_CHANNEL) {
                    Ok(enabled) => self.set_ssh_channel_enabled(enabled),
                    Err(e) => crate::log_debug!("cannot read the OpenSSH channel configuration: {e}"),
                }
                self.publish_status();
            }
            for which in ALL {
                self.refresh_bookmark(which);
            }
        }
        self.deferred_tasks();
        self.ctx.history.flush_if_due();
    }

    /// Gap notices that could not be queued, held console disconnects whose window passed and
    /// the failed-login summary once its window closed. Failures are retried after STALL_RETRY.
    fn deferred_tasks(&mut self) {
        let now = Instant::now();
        if self.deferred_retry_at.is_some_and(|t| now < t) {
            return;
        }
        let mut ok = true;
        for which in ALL {
            let Some(g) = self.chan(which).pending_gap.clone() else { continue };
            if self.report_gap(which, &g) {
                let path = self.ctx.paths.bookmark(which.key());
                let ch = self.chan(which);
                ch.pending_gap = None;
                if ch.sub.as_ref().is_some_and(|s| !s.is_positioned()) {
                    eventlog::delete_bookmark(&path); // the stale position must not be resumed
                }
            } else {
                ok = false;
            }
        }
        ok &= self.release_held(false);
        match self.ctx.flush_suppressed(crate::util::time::now_unix()) {
            Ok(true) => crate::log_info!("failed-login summary queued"),
            Ok(false) => {}
            Err(e) => {
                crate::log_error!("cannot queue the failed-login summary: {e}; will retry");
                ok = false;
            }
        }
        self.deferred_retry_at = (!ok).then(|| now + STALL_RETRY);
    }

    /// Report held console disconnects whose correlation window has passed (`force`: all of
    /// them). The window is judged by event time; wall-clock time counts only once the
    /// Security log was read to the end (so a backlog cannot release them too early).
    /// Returns false when a report could not be queued (they stay held).
    fn release_held(&mut self, force: bool) -> bool {
        let latest = self.logon.latest_event_time();
        let caught_up = self.sec.sub.is_none() || self.sec.drained;
        let now = if force || caught_up { latest.max(crate::util::time::now_unix()) } else { latest };
        let due = if force { self.logon.take_all() } else { self.logon.take_expired(now) };
        let mut due: VecDeque<logon::HeldEvent> = due.into();
        while let Some(h) = due.pop_front() {
            let c = Classified {
                outcome: Outcome::Event(h.details.clone()),
                record_id: h.record_id,
                time_filetime: h.time_filetime,
            };
            if let Err(e) = deliver_outcome(&self.ctx, Which::Security, &c) {
                crate::log_error!("Security log: cannot queue a console-disconnect alert ({e}); will retry");
                due.push_front(h);
                self.logon.requeue(due.into());
                return false;
            }
        }
        true
    }

    /// Subscriptions die with the EventLog service (RPC context handles): when its PID changes
    /// (or it stopped), resubscribe from the saved bookmarks.
    fn check_eventlog(&mut self) {
        if !self.any_open() {
            return;
        }
        let Some(pid) = query_eventlog_pid() else { return };
        let prev = self.eventlog_pid;
        self.eventlog_pid = (pid != 0).then_some(pid);
        let restarted = pid == 0 || prev.is_some_and(|p| p != pid);
        if !restarted {
            return;
        }
        crate::log_warn!(
            "Windows Event Log service {} (PID {} → {pid}); resubscribing from the saved positions",
            if pid == 0 { "is not running" } else { "restarted" },
            prev.unwrap_or(0)
        );
        for which in ALL {
            if self.chan(which).sub.is_some() {
                self.chan(which).close(true);
                self.open_channel(which);
            }
        }
    }

    /// Hourly, while idle: move the bookmark to the newest record of the channel so that the
    /// saved position stays inside the (circular) log even when nothing matched for days.
    fn refresh_bookmark(&mut self, which: Which) {
        {
            let ch = self.chan(which);
            if ch.sub.is_none() || ch.stalled || !ch.pending.is_empty() {
                return;
            }
        }
        let newest = match eventlog::newest_record(which.channel()) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(e) => {
                crate::log_debug!("{}: bookmark refresh skipped ({e})", which.label());
                return;
            }
        };
        // anything that matched up to `newest` must be handled first
        if self.drain(which) != 0 {
            return;
        }
        let label = which.label();
        let ch = self.chan(which);
        // the drain may have timed out or reopened the subscription (its backlog is unread)
        if !ch.caught_up() {
            crate::log_debug!("{label}: bookmark refresh skipped (not caught up)");
            return;
        }
        if let Some(sub) = ch.sub.as_mut() {
            match sub.advance(&newest) {
                Ok(()) => {
                    if let Err(e) = sub.save_bookmark() {
                        crate::log_warn!("{label}: {e}");
                    }
                }
                Err(e) => crate::log_debug!("{label}: bookmark refresh failed ({e})"),
            }
        }
    }

    /// Read the logon audit policy (never changes it), publish it, and notify once when it is
    /// (or became) insufficient. Runs every 10 minutes and on event 4719.
    fn audit_check(&mut self) {
        self.last_audit = Instant::now();
        match audit::query_values() {
            Ok(values) => {
                let (text, sufficient) = audit::describe_values(&values);
                *self.ctx.status.audit_policy.lock().unwrap_or_else(|e| e.into_inner()) = Some(text.clone());
                let logon_on = audit::logon_success_enabled(&values);
                match (self.logon_audit_on, logon_on) {
                    (Some(false), true) => crate::log_info!(
                        "logon auditing is on again: Security-log login alerts resume (session-notification fallback off)"
                    ),
                    (Some(true), false) => crate::log_warn!(
                        "logon auditing was switched off: logins are reported from session notifications only"
                    ),
                    _ => {}
                }
                self.logon_audit_on = Some(logon_on);
                self.sec.problem = (!logon_on).then(|| AUDIT_OFF.to_string());
                if !sufficient && self.audit_sufficient != Some(false) {
                    crate::log_warn!("audit policy is insufficient for login monitoring: {text}");
                    let lines = vec![
                        ("Audit policy".to_string(), text),
                        (
                            "Impact".to_string(),
                            "Windows does not record some logon/logoff events, so no alert can be sent for them."
                                .to_string(),
                        ),
                        ("Fix".to_string(), "Run 'predator-service audit enable' as administrator.".to_string()),
                    ];
                    let now = crate::util::time::now_unix();
                    if let Err(e) = self.ctx.emit_system("⚠️", "AUDIT POLICY INSUFFICIENT", &lines, now, None) {
                        crate::log_error!("cannot queue the audit-policy notice: {e}");
                    }
                } else if sufficient && self.audit_sufficient == Some(false) {
                    crate::log_info!("audit policy is sufficient again: {text}");
                }
                self.audit_sufficient = Some(sufficient);
            }
            Err(e) => {
                crate::log_debug!("audit policy query failed: {e}");
                *self.ctx.status.audit_policy.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(format!("Unknown — {e}"));
            }
        }
        self.publish_status();
    }

    /// Re-check sshd_config when it changed (or `force`).
    fn ssh_config_check(&mut self, force: bool) {
        let path = ssh::sshd_config_path();
        let stamp = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if !force && self.sshd_cfg_stamp == Some(stamp) {
            return;
        }
        self.sshd_cfg_stamp = Some(stamp);
        let problem = match std::fs::read(&path) {
            Ok(bytes) => ssh::check_sshd_config(&String::from_utf8_lossy(&bytes), &path.display().to_string()).err(),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    crate::log_debug!("cannot read {}: {e}", path.display());
                }
                None
            }
        };
        if problem != self.sshd_cfg_problem {
            match &problem {
                Some(p) => crate::log_warn!("OpenSSH log: {p}"),
                None => crate::log_info!("OpenSSH log: sshd_config logging settings are fine now"),
            }
        }
        self.sshd_cfg_problem = problem;
        self.publish_status();
    }
}

fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Wait until a stop is requested or `d` elapses; true = stop.
fn wait_for_stop(ctx: &AppContext, shared: &Shared, d: Duration) -> bool {
    let handles = [ctx.stop.event_handle(), shared.stop.raw()];
    let ms = u32::try_from(d.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: two valid event handles kept alive by `ctx` / `shared`.
    let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) };
    if r == WAIT_FAILED {
        std::thread::sleep(d);
    }
    ctx.stop.is_stopped() || shared.stopping.load(Ordering::SeqCst)
}

fn thread_main(ctx: Arc<AppContext>, shared: Arc<Shared>) {
    loop {
        let run = std::panic::catch_unwind(AssertUnwindSafe(|| match Engine::new(ctx.clone(), shared.clone()) {
            Ok(mut engine) => {
                engine.run();
                true
            }
            Err(e) => {
                crate::log_error!("login monitor cannot start: {e}");
                false
            }
        }));
        match run {
            Ok(true) => break,
            Ok(false) => set_enabled_error(&ctx, "cannot start the monitor; retrying"),
            Err(p) => {
                crate::log_error!("login monitor crashed: {}; restarting in 60 s", panic_text(p.as_ref()));
                set_enabled_error(&ctx, "internal error; restarting");
            }
        }
        if wait_for_stop(&ctx, &shared, CRASH_RESTART_DELAY) {
            break;
        }
    }
}

/// Handle to the running monitor thread.
pub struct Monitors {
    ctx: Arc<AppContext>,
    shared: Option<Arc<Shared>>,
    thread: Option<JoinHandle<()>>,
}

impl Monitors {
    /// Start the monitor thread. It subscribes/unsubscribes immediately when the
    /// `LoginMonitoring` / `SshMonitoring` features change (via `SettingsStore::on_change`),
    /// resumes from saved bookmarks after restarts, and never panics the process.
    pub fn start(ctx: Arc<AppContext>) -> Monitors {
        let shared = match (OwnedEvent::new_manual(), OwnedEvent::new_manual()) {
            (Ok(stop), Ok(settings)) => Arc::new(Shared { stop, settings, stopping: AtomicBool::new(false) }),
            (Err(e), _) | (_, Err(e)) => {
                crate::log_error!("login monitor cannot start: {e}");
                set_enabled_error(&ctx, &format!("cannot start ({e})"));
                return Monitors { ctx, shared: None, thread: None };
            }
        };
        {
            let s = shared.clone();
            ctx.settings.on_change(move |_| s.settings.set());
        }
        let settings = ctx.settings.get();
        for which in ALL {
            let st = if settings.features.is_enabled(which.feature()) {
                MonitorState::Starting
            } else {
                MonitorState::Disabled
            };
            set_status(&ctx, which, st);
        }
        let (c, s) = (ctx.clone(), shared.clone());
        let thread = match std::thread::Builder::new().name("monitor".into()).spawn(move || thread_main(c, s)) {
            Ok(h) => Some(h),
            Err(e) => {
                crate::log_error!("cannot spawn the login monitor thread: {e}");
                set_enabled_error(&ctx, "cannot start the monitor thread");
                None
            }
        };
        Monitors { ctx, shared: Some(shared), thread }
    }

    /// Stop: close subscriptions (waits for in-flight processing) and join the thread, then
    /// queue a pending failed-login summary and write the login history.
    pub fn stop(self) {
        if let Some(s) = &self.shared {
            s.stopping.store(true, Ordering::SeqCst);
            s.stop.set();
        }
        if let Some(t) = self.thread
            && t.join().is_err()
        {
            crate::log_error!("login monitor thread panicked while stopping");
        }
        let ctx = self.ctx;
        if std::panic::catch_unwind(AssertUnwindSafe(|| ctx.flush_pending())).is_err() {
            crate::log_error!("could not flush the login history / failed-login summary while stopping");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SERVICE_CONTROL_SESSIONCHANGE fallback
// ---------------------------------------------------------------------------------------------

const WTS_REMOTE_CONNECT: u32 = 3;
const WTS_SESSION_LOGON: u32 = 5;
const WTS_SESSION_LOGOFF: u32 = 6;
const WTS_SESSION_UNLOCK: u32 = 8;

/// Notification kind and method label for the session events the fallback reports.
fn session_event(event_type: u32) -> Option<(NotificationKind, &'static str)> {
    match event_type {
        WTS_SESSION_LOGON => Some((NotificationKind::Login, "Interactive (session notification)")),
        WTS_SESSION_LOGOFF => Some((NotificationKind::Logout, "Windows session (session notification)")),
        WTS_REMOTE_CONNECT => Some((NotificationKind::Login, "Remote Desktop (session notification)")),
        WTS_SESSION_UNLOCK => Some((NotificationKind::Login, "Unlock (session notification)")),
        _ => None,
    }
}

/// The Security subscription is open and reading (its only possible problem: audit policy).
fn security_subscription_open(security: &MonitorState) -> bool {
    match security {
        MonitorState::Active => true,
        MonitorState::Error(e) => e == AUDIT_OFF,
        _ => false,
    }
}

/// The fallback reports only while login monitoring is on and the Security log cannot deliver
/// the logon: its monitor is not reading the log, or logon auditing is off. `live_logon_audit`
/// is the audit policy read at the time of the session event (`None` = unknown); it overrides
/// the monitor's last periodic check, so a policy change is never reported twice or missed.
fn fallback_active(login_monitoring: bool, security: &MonitorState, live_logon_audit: Option<bool>) -> bool {
    if !login_monitoring {
        return false;
    }
    if !security_subscription_open(security) {
        return true;
    }
    match live_logon_audit {
        Some(on) => !on,
        None => *security != MonitorState::Active,
    }
}

fn wts_string(session_id: u32, class: WTS_INFO_CLASS) -> Option<String> {
    let mut buf: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut bytes: u32 = 0;
    // SAFETY: valid out-pointers; the returned buffer is freed with WTSFreeMemory below.
    let ok = unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, class, &mut buf, &mut bytes) };
    if ok == 0 || buf.is_null() {
        return None;
    }
    // SAFETY: string info classes return a NUL-terminated UTF-16 string.
    let s = unsafe { from_wide_ptr(buf) };
    // SAFETY: allocated by WTSQuerySessionInformationW, freed exactly once.
    unsafe { WTSFreeMemory(buf.cast()) };
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Decode `WTS_CLIENT_ADDRESS.Address` (the 20-byte array after `AddressFamily`) to an IP
/// address string. Microsoft documents for `WTSClientAddress` that "the IP address is offset by
/// two bytes from the start of the Address member" (the first two bytes are the port slot of a
/// sockaddr), so IPv4 is `Address[2..6]` and IPv6 `Address[2..18]`. Other families and the
/// unspecified address give `None`; loopback is returned (callers decide whether to show it).
///
/// This is the one decoder for the structure (the session-listing code should use it too).
pub fn decode_wts_client_address(family: u32, bytes: &[u8]) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if family == u32::from(AF_INET) {
        let b: [u8; 4] = bytes.get(2..6)?.try_into().ok()?;
        let ip = Ipv4Addr::from(b);
        (!ip.is_unspecified()).then(|| ip.to_string())
    } else if family == u32::from(AF_INET6) {
        let b: [u8; 16] = bytes.get(2..18)?.try_into().ok()?;
        let ip = Ipv6Addr::from(b);
        (!ip.is_unspecified()).then(|| ip.to_string())
    } else {
        None
    }
}

fn wts_client_address(session_id: u32) -> Option<String> {
    let mut buf: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut bytes: u32 = 0;
    // SAFETY: valid out-pointers; the returned buffer is freed with WTSFreeMemory below.
    let ok = unsafe {
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, WTSClientAddress, &mut buf, &mut bytes)
    };
    if ok == 0 || buf.is_null() {
        return None;
    }
    let len = (bytes as usize).min(64);
    // SAFETY: the buffer holds `bytes` bytes (a WTS_CLIENT_ADDRESS); we read at most that.
    let raw = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) }.to_vec();
    // SAFETY: allocated by WTSQuerySessionInformationW, freed exactly once.
    unsafe { WTSFreeMemory(buf.cast()) };
    if raw.len() < 24 {
        return None;
    }
    let family = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    decode_wts_client_address(family, &raw[4..24]).and_then(|ip| logon::source_ip(&ip))
}

fn session_fallback(ctx: &AppContext, event_type: u32, session_id: u32) {
    let Some((kind, method)) = session_event(event_type) else { return };
    let login_monitoring = ctx.settings.feature(Feature::LoginMonitoring);
    if !login_monitoring {
        return;
    }
    let security = ctx.status.security();
    // the monitor re-checks the policy only every 10 minutes: decide from the live value
    let live = if security_subscription_open(&security) {
        match audit::query_values() {
            Ok(v) => Some(audit::logon_success_enabled(&v)),
            Err(e) => {
                crate::log_debug!("session notification fallback: audit policy unknown ({e})");
                None
            }
        }
    } else {
        None
    };
    if !fallback_active(login_monitoring, &security, live) {
        return;
    }
    let user = match (wts_string(session_id, WTSUserName), kind) {
        (Some(u), _) => u,
        (None, NotificationKind::Logout) => format!("(session {session_id})"),
        (None, _) => {
            crate::log_debug!("session {session_id}: no user for session event {event_type}");
            return;
        }
    };
    let domain = wts_string(session_id, WTSDomainName).unwrap_or_default();
    let mut d = EventDetails {
        kind,
        computer: ctx.computer_name.clone(),
        user: logon::display_account(&user, &domain, &ctx.computer_name, ""),
        method: method.to_string(),
        event_unix: crate::util::time::now_unix(),
        success: true,
        ..EventDetails::default()
    };
    if kind == NotificationKind::Logout {
        d.reason = Some("Logoff".to_string());
    }
    if event_type == WTS_REMOTE_CONNECT {
        d.source_ip = wts_client_address(session_id);
        d.source_host = wts_string(session_id, WTSClientName).filter(|h| !h.eq_ignore_ascii_case(&ctx.computer_name));
    }
    match ctx.emit_event(d, None) {
        Ok(_) => crate::log_info!("session notification fallback: event {event_type}, session {session_id}"),
        Err(e) => crate::log_error!("session notification fallback: cannot queue the alert: {e}"),
    }
}

/// Fallback signal from the service control handler (SERVICE_CONTROL_SESSIONCHANGE). Used to
/// report logons/logoffs when the Security-log monitor is unavailable (audit policy off, access
/// denied ...). Must not duplicate alerts when the Security monitor is active.
/// `event_type` = WTS_SESSION_LOGON (5), WTS_SESSION_LOGOFF (6), WTS_SESSION_LOCK (7),
/// WTS_SESSION_UNLOCK (8), WTS_REMOTE_CONNECT (3), WTS_REMOTE_DISCONNECT (4), ...
pub fn on_session_change(ctx: &Arc<AppContext>, event_type: u32, session_id: u32) {
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| session_fallback(ctx, event_type, session_id)));
    if r.is_err() {
        crate::log_error!("session-change fallback failed (event {event_type}, session {session_id})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Mock sink: events are strings; delivery fails while `fail_on` names the event.
    struct MockSink {
        classified: Vec<String>,
        delivered: Vec<String>,
        committed: Vec<String>,
        fail_on: Option<String>,
    }

    impl EventSink<String> for MockSink {
        fn classify(&mut self, ev: &String) -> Classified {
            self.classified.push(ev.clone());
            let outcome = if ev.starts_with("ignore") {
                Outcome::Ignore("test")
            } else {
                Outcome::Event(EventDetails { user: ev.clone(), ..EventDetails::default() })
            };
            Classified { outcome, record_id: 1, time_filetime: None }
        }
        fn deliver(&mut self, c: &Classified) -> io::Result<()> {
            if let Outcome::Event(d) = &c.outcome {
                if self.fail_on.as_deref() == Some(d.user.as_str()) {
                    return Err(io::Error::other("disk full"));
                }
                self.delivered.push(d.user.clone());
            }
            Ok(())
        }
        fn commit(&mut self, ev: &String) {
            self.committed.push(ev.clone());
        }
    }

    #[test]
    fn queue_retries_without_reclassifying() {
        let mut q: VecDeque<Pending<String>> =
            ["a", "ignore-x", "b", "c"].iter().map(|s| Pending::new(s.to_string())).collect();
        let mut sink = MockSink { classified: vec![], delivered: vec![], committed: vec![], fail_on: Some("b".into()) };
        assert!(process_queue(&mut sink, &mut q).is_err());
        assert_eq!(sink.delivered, vec!["a"]);
        assert_eq!(sink.committed, vec!["a", "ignore-x"], "bookmark must not pass the failed event");
        assert_eq!(q.len(), 2);
        assert!(q.front().is_some_and(|p| p.classified.is_some()), "classification cached");
        sink.fail_on = None;
        assert_eq!(process_queue(&mut sink, &mut q).unwrap(), 2);
        assert_eq!(sink.delivered, vec!["a", "b", "c"]);
        assert_eq!(sink.committed, vec!["a", "ignore-x", "b", "c"]);
        assert_eq!(sink.classified, vec!["a", "ignore-x", "b", "c"], "each event classified exactly once");
        assert!(q.is_empty());
    }

    #[test]
    fn session_events_and_gating() {
        assert_eq!(session_event(5), Some((NotificationKind::Login, "Interactive (session notification)")));
        assert_eq!(session_event(6).map(|e| e.0), Some(NotificationKind::Logout));
        assert_eq!(session_event(3), Some((NotificationKind::Login, "Remote Desktop (session notification)")));
        assert_eq!(session_event(8), Some((NotificationKind::Login, "Unlock (session notification)")));
        assert_eq!(session_event(7), None);
        assert_eq!(session_event(4), None);
        let audit_off = MonitorState::Error(AUDIT_OFF.into());
        // monitor not reading the log → always report
        assert!(fallback_active(true, &MonitorState::Error("access denied".into()), None));
        assert!(fallback_active(true, &MonitorState::Error("access denied".into()), Some(true)));
        assert!(fallback_active(true, &MonitorState::Starting, None));
        assert!(fallback_active(true, &MonitorState::Disabled, None));
        // reading the log: the live audit policy decides (no double report, nothing missed)
        assert!(!fallback_active(true, &MonitorState::Active, Some(true)));
        assert!(fallback_active(true, &MonitorState::Active, Some(false)), "auditing switched off since last check");
        assert!(!fallback_active(true, &audit_off, Some(true)), "auditing switched on since last check");
        assert!(fallback_active(true, &audit_off, Some(false)));
        // live policy unknown: the monitor's last check decides
        assert!(!fallback_active(true, &MonitorState::Active, None));
        assert!(fallback_active(true, &audit_off, None));
        // login monitoring off → never
        assert!(!fallback_active(false, &MonitorState::Error("x".into()), Some(false)));
        assert!(!fallback_active(false, &audit_off, Some(false)));
    }

    #[test]
    fn client_address_decoding() {
        let mut a = [0u8; 20];
        a[2..6].copy_from_slice(&[192, 168, 1, 20]);
        assert_eq!(decode_wts_client_address(2, &a).as_deref(), Some("192.168.1.20"));
        assert_eq!(decode_wts_client_address(2, &[0u8; 20]), None, "unspecified");
        // IPv6 starts at offset 2 as well: fd7a:115c:a1e0::1 (a Tailscale address)
        let mut v6 = [0u8; 20];
        v6[2..18].copy_from_slice(&[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(decode_wts_client_address(23, &v6).as_deref(), Some("fd7a:115c:a1e0::1"));
        assert_eq!(decode_wts_client_address(23, &[0u8; 20]), None);
        let mut lo = [0u8; 20];
        lo[2..6].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(decode_wts_client_address(2, &lo).as_deref(), Some("127.0.0.1"), "callers filter loopback");
        assert_eq!(decode_wts_client_address(99, &a), None);
        assert_eq!(decode_wts_client_address(2, &a[..3]), None, "too short");
        assert_eq!(decode_wts_client_address(23, &v6[..17]), None, "too short");
    }

    #[test]
    fn dedupe_keys_survive_log_clears() {
        let c =
            |rid: u64, ft: Option<u64>| Classified { outcome: Outcome::Ignore("x"), record_id: rid, time_filetime: ft };
        let a = dedupe_key(Which::Security, &c(5, Some(134_400_621_151_884_769)));
        assert_eq!(a.as_deref(), Some("security:5:134400621151884769"));
        // same record replayed → same key; same record number after a clear → different key
        assert_eq!(a, dedupe_key(Which::Security, &c(5, Some(134_400_621_151_884_769))));
        assert_ne!(a, dedupe_key(Which::Security, &c(5, Some(134_400_621_151_884_770))));
        assert_ne!(dedupe_key(Which::Ssh, &c(5, Some(1))), dedupe_key(Which::SshAdmin, &c(5, Some(1))));
        assert_eq!(dedupe_key(Which::Ssh, &c(0, Some(1))), None);
    }

    #[test]
    fn same_record_number_after_a_clear_is_delivered() {
        let ctx = AppContext::for_tests();
        let login = |user: &str| EventDetails {
            kind: NotificationKind::SshLogin,
            user: user.into(),
            method: "SSH (password)".into(),
            event_unix: 1_795_588_515,
            ..EventDetails::default()
        };
        let before = Classified { outcome: Outcome::Event(login("alex")), record_id: 5, time_filetime: Some(100) };
        deliver_outcome(&ctx, Which::Ssh, &before).unwrap();
        let id = ctx.queue.front().unwrap().id;
        ctx.queue.ack(id).unwrap();
        // replay of the delivered record: dropped
        deliver_outcome(&ctx, Which::Ssh, &before).unwrap();
        assert!(ctx.queue.is_empty());
        // the log was cleared and record 5 is a NEW login
        let after = Classified { outcome: Outcome::Event(login("mallory")), record_id: 5, time_filetime: Some(900) };
        deliver_outcome(&ctx, Which::Ssh, &after).unwrap();
        assert_eq!(ctx.queue.len(), 1);
        assert!(ctx.queue.front().unwrap().html.contains("mallory"));
    }

    #[test]
    fn channel_state_priority() {
        let mut ch = Channel::new().unwrap();
        assert_eq!(ch.state(), MonitorState::Disabled);
        ch.enabled = true;
        assert_eq!(ch.state(), MonitorState::Starting);
        ch.problem = Some("audit off".into());
        assert_eq!(ch.state(), MonitorState::Error("audit off".into()));
        ch.stalled = true;
        assert_eq!(ch.state(), MonitorState::Error(QUEUE_STALLED.into()));
        ch.error = Some("denied".into());
        assert_eq!(ch.state(), MonitorState::Error("denied".into()));
        ch.reset_state();
        assert_eq!(ch.error, None);
        assert_eq!(ch.problem, None);
    }

    #[test]
    fn channel_constants() {
        assert_eq!(Which::Security.key(), "security");
        assert_eq!(Which::Ssh.key(), "openssh");
        assert_eq!(Which::SshAdmin.key(), "openssh-admin");
        assert_eq!(Which::Ssh.channel(), "OpenSSH/Operational");
        assert_eq!(Which::SshAdmin.channel(), "OpenSSH/Admin");
        assert_eq!(Which::Security.feature(), Feature::LoginMonitoring);
        assert_eq!(Which::Ssh.feature(), Feature::SshMonitoring);
        assert_eq!(Which::SshAdmin.feature(), Feature::SshMonitoring);
        assert!(Which::Security.query().contains("4624"));
        assert!(Which::SshAdmin.query().contains("OpenSSH/Admin"));
        let e = WinError::new(5, "EvtSubscribe");
        assert!(open_error_text(Which::Security, &e).contains("LocalSystem"));
        assert_eq!(open_error_text(Which::Ssh, &WinError::new(15007, "x")), "OpenSSH Server not installed");
        assert_eq!(open_error_text(Which::SshAdmin, &WinError::new(15007, "x")), "OpenSSH admin log not found");
        assert!(open_error_text(Which::Ssh, &WinError::new(1722, "x")).contains("Event Log service unavailable"));
    }

    #[test]
    fn wait_timeouts() {
        let now = Instant::now();
        assert_eq!(wait_ms(now, None), INFINITE, "nothing to do: no periodic wake");
        assert_eq!(wait_ms(now, Some(now)), 1_000, "due deadlines never busy-loop");
        assert_eq!(wait_ms(now, Some(now + Duration::from_secs(300))), 300_000);
        assert_eq!(earliest(None, None), None);
        assert_eq!(earliest(Some(now), None), Some(now));
        let later = now + Duration::from_secs(5);
        assert_eq!(earliest(Some(later), Some(now)), Some(now));
        assert_eq!(instant_at(now, 1_000, 1_010), now + Duration::from_secs(10));
        assert_eq!(instant_at(now, 1_000, 900), now, "past deadlines are due now");
    }

    fn test_engine(ctx: Arc<AppContext>) -> Engine {
        let shared = Arc::new(Shared {
            stop: OwnedEvent::new_manual().unwrap(),
            settings: OwnedEvent::new_manual().unwrap(),
            stopping: AtomicBool::new(false),
        });
        Engine::new(ctx, shared).unwrap()
    }

    #[test]
    fn idle_engine_never_wakes_periodically() {
        let ctx = AppContext::for_tests();
        let mut e = test_engine(ctx.clone());
        // both monitors disabled, nothing pending
        assert_eq!(e.next_timeout_ms(), INFINITE);
        // a pending failed-login summary schedules exactly one wake
        ctx.settings.set_feature(Feature::FailedLoginNotifications, true).unwrap();
        let t0 = crate::util::time::now_unix();
        let fail =
            |t: i64| EventDetails { kind: NotificationKind::FailedLogin, event_unix: t, ..EventDetails::default() };
        for i in 0..12 {
            ctx.emit_event(fail(t0 - 700 + i), None).unwrap();
        }
        let ms = e.next_timeout_ms();
        assert!(ms <= 1_000, "summary already due: {ms}");
        e.tick();
        assert_eq!(ctx.suppressed_flush_due(), None, "summary emitted by the monitor wake");
        assert_eq!(e.next_timeout_ms(), INFINITE);
        // an enabled channel that failed to open retries with backoff, then nothing else
        e.sec.enabled = true;
        e.sup.rec[Which::Security.idx()].retry_at = Some(Instant::now() + Duration::from_secs(5));
        e.last_audit = Instant::now();
        let ms = e.next_timeout_ms();
        assert!((1_000..=5_000).contains(&ms), "retry deadline: {ms}");
    }

    #[test]
    fn repeated_read_failures_back_off() {
        let ctx = AppContext::for_tests();
        let mut e = test_engine(ctx.clone());
        e.ssh.enabled = true;
        // the immediate reopen of this 5-minute period was already used
        e.sup.rec[Which::Ssh.idx()].last_immediate = Some(Instant::now());
        let t0 = Instant::now();
        e.read_failed(Which::Ssh, 1734);
        let first = e.sup.rec(Which::Ssh).retry_at.expect("retry scheduled") - t0;
        assert!(first >= RETRY_MIN && first < RETRY_MIN * 2, "{first:?}");
        assert!(e.ssh.sub.is_none(), "closed until the retry");
        assert!(matches!(ctx.status.ssh(), MonitorState::Error(m) if m.contains("error 1734")));
        let incident = e.ssh.incident.clone();
        assert!(incident.is_some());
        e.read_failed(Which::Ssh, 1734);
        let second = e.sup.rec(Which::Ssh).retry_at.unwrap() - t0;
        assert!(second >= RETRY_MIN * 2, "doubles: {second:?}");
        for _ in 0..20 {
            e.read_failed(Which::Ssh, 1734);
        }
        let capped = e.sup.rec(Which::Ssh).retry_at.unwrap().saturating_duration_since(Instant::now());
        assert!(capped <= RETRY_MAX + RETRY_MAX / 10, "capped at 10 minutes: {capped:?}");
        assert!(capped >= RETRY_MAX - Duration::from_secs(5));
        assert_eq!(e.ssh.incident, incident, "one incident, logged once");
        assert!(e.next_timeout_ms() as u128 <= capped.as_millis() + 1_000);
        assert_eq!(e.sup.global_at, None, "a single channel is never reset 'together'");
        // switching the channel off forgets the failure state
        e.ssh.reset_state();
        e.sup.reset(Which::Ssh);
        assert_eq!(e.sup.rec(Which::Ssh).failures, 0);
        assert_eq!(e.sup.rec(Which::Ssh).retry_at, None);
        assert_eq!(e.ssh.incident, None);
    }

    // ---- failure recovery: the pure state machine -------------------------------------------

    const ON: [bool; 3] = [true, true, true];
    const ONLY_SSH: [bool; 3] = [false, true, false];

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Delay of a `Retry` decision taken at `now`.
    fn retry_delay(d: Decision, now: Instant) -> Duration {
        match d {
            Decision::Retry(at) => at.saturating_duration_since(now),
            other => panic!("expected a retry, got {other:?}"),
        }
    }

    fn assert_delay(d: Duration, base: Duration) {
        assert!(d >= base && d <= base + base / 10 + Duration::from_millis(1), "{d:?} (base {base:?})");
    }

    #[test]
    fn backoff_steps_are_deterministic_and_capped() {
        let mut b = Backoff::new(RETRY_MIN, RETRY_MAX);
        let steps: Vec<u64> = (0..10).map(|_| backoff_step(&mut b).as_secs()).collect();
        assert_eq!(steps, vec![5, 10, 20, 40, 80, 160, 320, 600, 600, 600]);
    }

    #[test]
    fn immediate_reopen_at_most_once_per_five_minutes() {
        let mut s = Supervisor::new();
        let w = Which::Ssh;
        let t0 = Instant::now();
        s.opened(w, t0);
        assert_eq!(s.read_failed(w, 4317, t0, ONLY_SSH), Decision::ReopenNow);
        s.opened(w, t0);
        // the reopen read cleanly once — that proves nothing: the next failure backs off
        let t = t0 + secs(1);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(5));
        s.opened(w, t + secs(5));
        let t = t0 + secs(7);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(10));
        s.opened(w, t + secs(10));
        let t = t0 + secs(299);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(20));
        // five minutes after the last immediate reopen another one is allowed …
        s.opened(w, t0 + secs(300));
        assert_eq!(s.read_failed(w, 4317, t0 + secs(301), ONLY_SSH), Decision::ReopenNow);
        // … but the backoff was not forgotten (the channel never worked for 5 minutes)
        s.opened(w, t0 + secs(301));
        let t = t0 + secs(302);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(40));
        assert_eq!(s.rec(w).failures, 6);
    }

    #[test]
    fn healthy_only_after_five_minutes_of_work() {
        let mut s = Supervisor::new();
        let w = Which::Security;
        let only = [true, false, false];
        let t0 = Instant::now();
        assert_eq!(s.read_failed(w, 1722, t0, only), Decision::ReopenNow);
        s.opened(w, t0);
        let t = t0 + secs(1);
        assert_delay(retry_delay(s.read_failed(w, 1722, t, only), t), secs(5));
        let reopened = t0 + secs(6);
        s.opened(w, reopened);
        assert_eq!(s.rec(w).healthy_at(), Some(reopened + HEALTHY_AFTER));
        assert_eq!(s.next_deadline([true, false, false], [false; 3]), Some(reopened + HEALTHY_AFTER));
        assert!(!s.heal_if_due(w, reopened + secs(60)), "one minute is not enough");
        assert_eq!(s.rec(w).failures, 2);
        assert!(s.heal_if_due(w, reopened + HEALTHY_AFTER));
        assert_eq!(s.rec(w).failures, 0);
        assert_eq!(s.rec(w).healthy_at(), None, "no further health wake");
        assert_eq!(s.next_deadline([true, false, false], [false; 3]), None);
        // a new incident starts from scratch: immediate reopen, then 5 s again
        let t = reopened + HEALTHY_AFTER + secs(60);
        assert_eq!(s.read_failed(w, 1722, t, only), Decision::ReopenNow);
        s.opened(w, t);
        let t = t + secs(1);
        assert_delay(retry_delay(s.read_failed(w, 1722, t, only), t), secs(5));
    }

    #[test]
    fn a_failure_after_five_quiet_minutes_starts_a_new_incident() {
        let mut s = Supervisor::new();
        let w = Which::Ssh;
        let t0 = Instant::now();
        assert_eq!(s.read_failed(w, 4317, t0, ONLY_SSH), Decision::ReopenNow);
        s.opened(w, t0);
        let t = t0 + secs(1);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(5));
        s.opened(w, t0 + secs(6));
        let t = t0 + secs(7);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(10));
        // reopened, then it worked for six minutes without anybody calling heal_if_due
        s.opened(w, t0 + secs(17));
        let t = t0 + secs(17 + 360);
        assert_eq!(s.read_failed(w, 4317, t, ONLY_SSH), Decision::ReopenNow);
        assert_eq!(s.rec(w).failures, 1);
        s.opened(w, t);
        let t = t + secs(1);
        assert_delay(retry_delay(s.read_failed(w, 4317, t, ONLY_SSH), t), secs(5));
    }

    /// Fail each of `chans` once at `now` (reopening those told to reopen now).
    fn fail_round(s: &mut Supervisor, chans: &[Which], code: u32, now: Instant, enabled: [bool; 3]) -> Vec<Decision> {
        chans
            .iter()
            .map(|&w| {
                let d = s.read_failed(w, code, now, enabled);
                if d == Decision::ReopenNow {
                    s.opened(w, now);
                }
                d
            })
            .collect()
    }

    #[test]
    fn all_channels_failing_alike_are_reset_together() {
        let mut s = Supervisor::new();
        let t0 = Instant::now();
        for w in ALL {
            s.opened(w, t0);
        }
        assert_eq!(fail_round(&mut s, &ALL, 4317, t0, ON), vec![Decision::ReopenNow; 3]);
        let r2 = fail_round(&mut s, &ALL, 4317, t0 + secs(1), ON);
        assert!(r2.iter().all(|d| matches!(d, Decision::Retry(_))), "{r2:?}");
        let now = t0 + secs(7);
        for w in ALL {
            s.opened(w, now);
        }
        let r3 = fail_round(&mut s, &ALL, 4317, now, ON);
        assert!(matches!(r3[0], Decision::Retry(_)) && matches!(r3[1], Decision::Retry(_)), "{r3:?}");
        let Decision::ResetAll { at, code } = r3[2] else { panic!("expected a global reset: {r3:?}") };
        assert_eq!(code, 4317);
        // never sooner than the channels' own backoff (10 s) — and one shared deadline
        let own = [r3[0], r3[1]].map(|d| match d {
            Decision::Retry(t) => t,
            _ => unreachable!(),
        });
        assert!(at >= own[0] && at >= own[1] && at >= now + RETRY_MIN, "{at:?} vs {own:?}");
        assert_eq!(s.global_at, Some(at));
        assert!(ALL.iter().all(|w| s.rec(*w).retry_at.is_none() && s.rec(*w).same_code == 0));
        // the channel that triggered the reset is not a backoff step behind the others
        assert!(ALL.iter().all(|w| s.rec(*w).backoff.current() == secs(20)), "backoffs in step");
        let closed = [true; 3];
        assert_eq!(s.next_deadline([false; 3], closed), Some(at));
        // not yet due: nothing is reopened (one by one) before the shared reopen
        assert_eq!(s.due_reopens(at - secs(2), closed), (vec![], false));
        assert_eq!(s.due_reopens(at, closed), (ALL.to_vec(), true));
        assert_eq!(s.global_at, None);
        // healthy again → the shared backoff starts from 5 s again
        for w in ALL {
            s.opened(w, at);
        }
        let later = at + HEALTHY_AFTER;
        assert!(ALL.iter().all(|w| s.heal_if_due(*w, later)));
        assert_eq!(s.global_backoff.current(), RETRY_MIN);
    }

    #[test]
    fn no_global_reset_for_different_codes_a_single_channel_or_a_working_one() {
        let t0 = Instant::now();
        // different codes
        let mut s = Supervisor::new();
        for i in 0..6u64 {
            let now = t0 + secs(i * 700); // also past the immediate-reopen period every time
            for (w, code) in [(Which::Security, 1722), (Which::Ssh, 4317), (Which::SshAdmin, 4317)] {
                s.opened(w, now);
                assert!(!matches!(s.read_failed(w, code, now, ON), Decision::ResetAll { .. }));
            }
        }
        // a single enabled channel: plain per-channel backoff
        let mut s = Supervisor::new();
        for i in 0..10u64 {
            assert!(!matches!(s.read_failed(Which::Ssh, 4317, t0 + secs(i), ONLY_SSH), Decision::ResetAll { .. }));
        }
        // one enabled channel (OpenSSH/Admin) keeps working
        let both = [Which::Security, Which::Ssh];
        let mut s = Supervisor::new();
        for i in 0..10u64 {
            let d = fail_round(&mut s, &both, 4317, t0 + secs(i), ON);
            assert!(!d.iter().any(|d| matches!(d, Decision::ResetAll { .. })), "{d:?}");
        }
        // … but a channel that cannot even be opened (not installed) does not block it
        let mut s = Supervisor::new();
        s.open_failed(Which::SshAdmin, t0);
        let d: Vec<Decision> = (0..3u64).flat_map(|i| fail_round(&mut s, &both, 4317, t0 + secs(i), ON)).collect();
        assert!(matches!(d.last(), Some(Decision::ResetAll { code: 4317, .. })), "absent channel excluded: {d:?}");
        // the open-failing channel keeps its own retry
        assert!(s.rec(Which::SshAdmin).retry_at.is_some());
    }

    #[test]
    fn due_retries_are_coalesced_into_one_wake() {
        let mut s = Supervisor::new();
        let t0 = Instant::now();
        s.rec[0].retry_at = Some(t0);
        s.rec[1].retry_at = Some(t0 + secs(3));
        s.rec[2].retry_at = Some(t0 + secs(60));
        let closed = [true; 3];
        assert_eq!(s.next_deadline([false; 3], closed), Some(t0));
        assert_eq!(s.due_reopens(t0 - secs(2), closed), (vec![], false), "nothing due yet");
        assert_eq!(s.due_reopens(t0, closed), (vec![Which::Security, Which::Ssh], false));
        assert_eq!(s.next_deadline([true, true, false], [false, false, true]), Some(t0 + secs(60)));
        // a channel that is switched off (not "closed") is never reopened
        s.rec[2].retry_at = Some(t0);
        assert_eq!(s.due_reopens(t0, [false; 3]), (vec![], false));
    }

    /// Discrete-event model of the engine's recovery glue with a fake clock: a timer wake runs
    /// `due_reopens`/`heal_if_due` (like `tick`), every (re)open sets the signal, and a signalled
    /// wake reads each signalled channel (`fails(channel, now)` → error code of that read).
    /// Returns the wake-ups per minute.
    fn simulate(
        start: Instant,
        minutes: usize,
        enabled: [bool; 3],
        fails: impl Fn(Which, Instant) -> Option<u32>,
    ) -> (Vec<u32>, Supervisor) {
        let mut s = Supervisor::new();
        let end = start + secs(60 * minutes as u64);
        let mut now = start;
        let mut open = [false; 3];
        let mut signal = [false; 3];
        for w in ALL {
            if enabled[w.idx()] {
                open[w.idx()] = true;
                signal[w.idx()] = true;
                s.opened(w, now);
            }
        }
        let mut wakes = vec![0u32; minutes];
        while now < end {
            let minute = (now - start).as_secs() as usize / 60;
            if signal.iter().any(|x| *x) {
                wakes[minute] += 1;
                for w in ALL {
                    let i = w.idx();
                    if !std::mem::take(&mut signal[i]) || !open[i] {
                        continue;
                    }
                    let Some(code) = fails(w, now) else { continue };
                    open[i] = false;
                    match s.read_failed(w, code, now, enabled) {
                        Decision::ReopenNow => {
                            open[i] = true;
                            signal[i] = true;
                            s.opened(w, now);
                        }
                        Decision::Retry(_) => {}
                        Decision::ResetAll { .. } => {
                            open = [false; 3];
                            signal = [false; 3];
                        }
                    }
                }
                continue;
            }
            let closed = [0, 1, 2].map(|i| enabled[i] && !open[i]);
            let Some(t) = s.next_deadline(open, closed) else { break };
            now = t.max(now + MIN_WAIT);
            if now >= end {
                break;
            }
            wakes[(now - start).as_secs() as usize / 60] += 1;
            let (due, _) = s.due_reopens(now, closed);
            for w in due {
                open[w.idx()] = true;
                signal[w.idx()] = true;
                s.opened(w, now);
            }
            for w in ALL {
                if open[w.idx()] {
                    s.heal_if_due(w, now);
                }
            }
        }
        (wakes, s)
    }

    /// The production incident's shape — every channel fails every read with the same code —
    /// must never become a spin: a handful of wake-ups per minute at most, decaying.
    #[test]
    fn a_persistent_failure_on_all_channels_never_spins() {
        let start = Instant::now();
        let (wakes, s) = simulate(start, 120, ON, |_, _| Some(4317));
        println!("wake-ups per minute: {wakes:?}");
        // measured: [8, 2, 2, 0, 0, 3, 0, …] — the old code did ~1000 per SECOND
        assert!(wakes[0] <= 10, "first minute: {wakes:?}");
        assert!(wakes.iter().skip(1).all(|n| *n <= 4), "{wakes:?}");
        let total: u32 = wakes.iter().sum();
        assert!(total <= 80, "two hours: {total} wake-ups");
        assert!(wakes[60..].iter().sum::<u32>() <= 25, "decays to the 10-minute cap: {wakes:?}");
        assert!(ALL.iter().all(|w| s.rec(*w).failures > 0), "still failing, still reported");
    }

    #[test]
    fn a_persistent_failure_on_one_channel_never_spins_and_spares_the_others() {
        let start = Instant::now();
        let (wakes, s) = simulate(start, 60, ON, |w, _| (w == Which::Ssh).then_some(1734));
        assert!(wakes[0] <= 8, "{wakes:?}");
        assert!(wakes.iter().skip(1).all(|n| *n <= 4), "{wakes:?}");
        assert_eq!(s.global_at, None, "no global reset for one channel");
        assert_eq!(s.rec(Which::Security).failures, 0);
        assert_eq!(s.rec(Which::SshAdmin).failures, 0);
    }

    #[test]
    fn recovery_is_declared_only_after_five_minutes_and_then_stays_quiet() {
        let start = Instant::now();
        let broken_until = start + secs(120);
        let (wakes, s) = simulate(start, 30, ON, |_, t| (t < broken_until).then_some(4317));
        assert!(ALL.iter().all(|w| s.rec(*w).failures == 0), "healthy after working 5 minutes");
        assert_eq!(s.global_at, None);
        assert_eq!(s.global_backoff.current(), RETRY_MIN);
        // after the health check nothing wakes the engine any more
        assert!(wakes[12..].iter().all(|n| *n == 0), "{wakes:?}");
    }

    // ---- failure recovery: the engine glue -------------------------------------------------

    #[test]
    fn engine_closes_and_reopens_all_channels_together() {
        let ctx = AppContext::for_tests();
        let mut e = test_engine(ctx.clone());
        let now = Instant::now();
        for w in ALL {
            e.chan(w).enabled = true;
            // no immediate reopen (that would open real subscriptions in a unit test)
            e.sup.rec[w.idx()].last_immediate = Some(now);
        }
        for _ in 0..GLOBAL_RESET_AFTER {
            for w in ALL {
                e.read_failed(w, 4317);
            }
        }
        let at = e.sup.global_at.expect("global reset scheduled");
        for w in ALL {
            let ch = e.chan(w);
            assert!(ch.sub.is_none());
            assert!(ch.error.as_deref().is_some_and(|m| m.contains("error 4317") && m.contains("together")), "{w:?}");
            assert_eq!(e.sup.rec(w).retry_at, None, "{w:?} waits for the shared reopen");
        }
        let sec = ctx.status.security();
        assert!(matches!(&sec, MonitorState::Error(m) if m.contains("reopened together")), "{sec:?}");
        assert!(matches!(ctx.status.ssh(), MonitorState::Error(_)));
        assert!(fallback_active(true, &sec, Some(true)), "the session-change fallback reports logons meanwhile");
        let ms = e.next_timeout_ms() as u128;
        assert!(ms <= at.saturating_duration_since(Instant::now()).as_millis() + 1_000, "{ms}");
        assert!(ms >= 1_000, "{ms}");
    }

    /// A private data directory (bookmarks) for tests that open real subscriptions.
    fn private_ctx(tag: &str) -> (Arc<AppContext>, std::path::PathBuf) {
        use crate::config::{Settings, SettingsStore};
        use crate::notify::history::LoginHistory;
        use crate::notify::queue::NotificationQueue;
        use crate::paths::DataPaths;
        let dir = temp_dir(tag);
        let paths = DataPaths::new(&dir);
        paths.ensure_dirs().unwrap();
        let ctx = AppContext::new(
            paths,
            Arc::new(SettingsStore::in_memory(Settings::default())),
            Arc::new(NotificationQueue::in_memory()),
            Arc::new(LoginHistory::in_memory()),
            "TESTPC".into(),
            true,
        );
        (ctx, dir)
    }

    /// A System-log query that never matches anything (a subscription that always is "idle").
    const IDLE_SYSTEM_QUERY: &str = "<QueryList><Query Id=\"0\" Path=\"System\"><Select Path=\"System\">\
         *[System[Provider[@Name='Predator-No-Such-Provider'] and EventID=65001]]</Select></Query></QueryList>";

    #[test]
    fn engine_ends_an_incident_only_after_five_healthy_minutes() {
        let (ctx, dir) = private_ctx("heal");
        let mut e = test_engine(ctx.clone());
        let sub = Subscription::open_at_oldest("System", IDLE_SYSTEM_QUERY, e.sec.signal.raw(), &dir.join("x.xml"));
        e.sec.enabled = true;
        e.sec.sub = Some(sub.unwrap());
        e.sec.incident = Some("Cannot read the Security log".into());
        let t = Instant::now();
        e.sup.rec[Which::Security.idx()].failures = 2;
        e.sup.opened(Which::Security, t);
        assert_eq!(e.sup.next_deadline(e.open_flags(), e.closed_flags()), Some(t + HEALTHY_AFTER));
        e.heal_if_due(Which::Security, t + secs(60));
        assert!(e.sec.incident.is_some(), "one minute of work is not enough");
        e.heal_if_due(Which::Security, t + HEALTHY_AFTER);
        assert!(e.sec.incident.is_none() && e.sec.announced);
        assert_eq!(e.sup.rec(Which::Security).failures, 0);
        assert_eq!(e.sup.next_deadline(e.open_flags(), e.closed_flags()), None, "no further wake");
        drop(e);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The root cause, end to end: an unsignalled drain after the end was read (hourly bookmark
    /// refresh, or the old "drain every channel on any signal") is NOT a failure. A subscription
    /// that is signalled but never has anything (stuck) is reopened through the supervisor.
    #[test]
    fn unsignalled_drain_is_not_a_failure_but_a_stuck_signal_is() {
        let (ctx, dir) = private_ctx("drain");
        let mut e = test_engine(ctx.clone());
        let sub =
            Subscription::open_at_oldest("System", IDLE_SYSTEM_QUERY, e.sec.signal.raw(), &dir.join("x.xml")).unwrap();
        e.sec.enabled = true;
        e.sec.sub = Some(sub);
        e.sup.opened(Which::Security, Instant::now());
        e.sec.signal.set(); // as after an open
        assert_eq!(e.drain(Which::Security), 0);
        assert!(e.sec.drained);
        // unsignalled reads after the end: wevtapi answers 4317 — not an error
        for _ in 0..5 {
            assert_eq!(e.drain(Which::Security), 0);
        }
        assert!(e.sec.sub.is_some() && e.sec.error.is_none() && e.sec.incident.is_none());
        assert_eq!(e.sup.rec(Which::Security).failures, 0);
        assert_eq!(e.sec.spurious_waits, 0, "unsignalled reads are not 'spurious'");
        // signalled without new records, again and again: stuck → resubscribe (with backoff here)
        e.sup.rec[Which::Security.idx()].last_immediate = Some(Instant::now());
        for i in 1..SPURIOUS_WAIT_LIMIT {
            e.sec.signal.set();
            e.drain(Which::Security);
            assert_eq!(e.sec.spurious_waits, i);
            assert!(e.sec.sub.is_some());
        }
        e.sec.signal.set();
        e.drain(Which::Security);
        assert!(e.sec.sub.is_none(), "reopened later");
        assert!(e.sec.error.as_deref().is_some_and(|m| m.contains("4317")), "{:?}", e.sec.error);
        assert!(e.sup.rec(Which::Security).retry_at.is_some());
        assert_eq!(e.sup.rec(Which::Security).failures, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The hourly bookmark jump to the newest record happens only when no record before it can
    /// still be unread (otherwise a restart would resume after records that were never handled).
    #[test]
    fn bookmark_jumps_to_the_newest_record_only_when_caught_up() {
        let dir = temp_dir("caught-up");
        let mut e = test_engine(AppContext::for_tests());
        assert!(!e.sec.caught_up(), "no subscription");
        let sub =
            Subscription::open_at_oldest("System", IDLE_SYSTEM_QUERY, e.sec.signal.raw(), &dir.join("x.xml")).unwrap();
        e.sec.enabled = true;
        e.sec.sub = Some(sub);
        e.sup.opened(Which::Security, Instant::now());
        e.sec.signal.reset();
        assert!(!e.sec.caught_up(), "a fresh or reopened subscription whose backlog was not read yet");
        e.sec.signal.set(); // as after an open
        e.drain(Which::Security);
        assert!(e.sec.caught_up(), "read to the end");
        // the refresh's own (unsignalled) drain: 4317 = nothing new, still caught up
        e.drain(Which::Security);
        assert!(e.sec.caught_up());
        e.sec.signal.set();
        assert!(!e.sec.caught_up(), "wevtapi signalled a new record meanwhile");
        e.drain(Which::Security);
        assert!(e.sec.caught_up());
        e.sec.drained = false; // what a drain that timed out leaves behind
        assert!(!e.sec.caught_up());
        e.sec.drained = true;
        e.sec.stalled = true;
        assert!(!e.sec.caught_up(), "undelivered events");
        e.sec.stalled = false;
        assert!(e.sec.caught_up());
        e.sec.close(true);
        assert!(!e.sec.caught_up(), "closed (e.g. for a reopen)");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn held_console_disconnect_is_released_by_the_engine() {
        let ctx = AppContext::for_tests();
        ctx.settings.set_feature(Feature::LogoutNotifications, true).unwrap();
        let mut e = test_engine(ctx.clone());
        let xml = "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4779</EventID><TimeCreated SystemTime='2025-06-01T10:00:00.1234567Z'/><EventRecordID>77</EventRecordID><Channel>Security</Channel><Computer>TESTPC</Computer></System><EventData><Data Name='AccountName'>alex</Data><Data Name='AccountDomain'>TESTPC</Data><Data Name='SessionName'>Console</Data><Data Name='ClientName'>Unknown</Data><Data Name='ClientAddress'>LOCAL</Data></EventData></Event>";
        let rec = xml::parse_event(xml).unwrap();
        assert!(matches!(e.logon.classify(&rec), Outcome::Ignore(_)));
        assert!(e.next_timeout_ms() <= 1_000, "held event is overdue (old event time)");
        e.tick();
        assert_eq!(e.logon.next_release(), None);
        assert_eq!(ctx.queue.len(), 1, "console disconnect reported after its window");
        assert!(ctx.queue.front().unwrap().html.contains("Console session"));
        assert!(ctx.queue.contains_key(&format!("security:77:{}", rec.time_filetime.unwrap())));
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("predator-mon-{tag}-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Live: drain the real OpenSSH/Operational log from its oldest record through the parser.
    /// Run with `cargo test --lib monitor::tests::live_openssh -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_openssh_from_oldest() {
        let dir = temp_dir("ssh");
        let bm = dir.join("openssh.xml");
        let signal = OwnedEvent::create(true, true).unwrap();
        let mut sub = match Subscription::open_at_oldest(ssh::OPENSSH_CHANNEL, ssh::OPENSSH_QUERY, signal.raw(), &bm) {
            Ok(s) => s,
            Err(e) => {
                println!("OpenSSH/Operational not available: {e}");
                return;
            }
        };
        let mut tracker = ssh::SshTracker::new("DESKTOP-01");
        let mut pending = VecDeque::new();
        let mut seen: Vec<Classified> = Vec::new();
        let mut deliver = |c: &Classified| {
            seen.push(c.clone());
            Ok(())
        };
        let st = drain_channel(&mut sub, &mut pending, &mut tracker, &mut deliver, &|| false, true, "OpenSSH log");
        println!("fetched={} handled={} broken={:?} save_error={:?}", st.fetched, st.handled, st.broken, st.save_error);
        assert!(st.broken.is_none());
        assert!(pending.is_empty());
        assert_eq!(st.fetched, st.handled);
        let mut ignored = 0;
        for c in &seen {
            match &c.outcome {
                Outcome::Event(d) => println!(
                    "record {:>5}: {:?} user={} method={} ip={:?} reason={:?} extra={:?}",
                    c.record_id, d.kind, d.user, d.method, d.source_ip, d.reason, d.extra
                ),
                Outcome::Ignore(_) => ignored += 1,
                Outcome::Security { title, .. } => println!("record {}: security {title}", c.record_id),
                Outcome::AuditPolicyChanged => println!("record {}: audit policy changed", c.record_id),
            }
        }
        println!("ignored (unrelated lines): {ignored}");
        if st.handled > 0 {
            let saved = std::fs::read_to_string(&bm).unwrap();
            println!("saved bookmark: {}", saved.replace("\r\n", " "));
            let last = seen.iter().map(|c| c.record_id).max().unwrap_or(0);
            assert_eq!(eventlog::bookmark_record_id(&saved), Some(last));
            // resuming from the saved bookmark must work (Strict) and deliver nothing old
            let sig2 = OwnedEvent::create(true, true).unwrap();
            let (mut resumed, gap) =
                Subscription::open(ssh::OPENSSH_CHANNEL, ssh::OPENSSH_QUERY, sig2.raw(), &bm).unwrap();
            assert!(gap.is_none());
            let mut more = Vec::new();
            resumed.next_batch(&mut more).unwrap();
            println!("events after resume: {}", more.len());
            assert!(more.is_empty());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Live: the OpenSSH/Admin channel through its own single-channel subscription; a bookmark
    /// taken from it must resume with Strict.
    #[test]
    #[ignore]
    fn live_openssh_admin_from_oldest() {
        let dir = temp_dir("ssh-admin");
        let bm = dir.join("openssh-admin.xml");
        let signal = OwnedEvent::create(true, true).unwrap();
        let mut sub =
            match Subscription::open_at_oldest(ssh::OPENSSH_ADMIN_CHANNEL, ssh::OPENSSH_ADMIN_QUERY, signal.raw(), &bm)
            {
                Ok(s) => s,
                Err(e) => {
                    println!("OpenSSH/Admin not available: {e}");
                    return;
                }
            };
        let mut tracker = ssh::SshTracker::new("DESKTOP-01");
        let mut pending = VecDeque::new();
        let mut seen: Vec<Classified> = Vec::new();
        let mut deliver = |c: &Classified| {
            seen.push(c.clone());
            Ok(())
        };
        let st =
            drain_channel(&mut sub, &mut pending, &mut tracker, &mut deliver, &|| false, true, "OpenSSH admin log");
        println!("fetched={} handled={} outcomes={:?}", st.fetched, st.handled, seen);
        assert!(st.broken.is_none());
        if st.handled > 0 {
            let sig2 = OwnedEvent::create(true, true).unwrap();
            let (mut resumed, gap) =
                Subscription::open(ssh::OPENSSH_ADMIN_CHANNEL, ssh::OPENSSH_ADMIN_QUERY, sig2.raw(), &bm).unwrap();
            assert!(gap.is_none(), "single-channel bookmark resumes with Strict");
            let mut more = Vec::new();
            resumed.next_batch(&mut more).unwrap();
            assert!(more.is_empty());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Live: a non-elevated process must get a clean "access denied" for the Security log.
    #[test]
    #[ignore]
    fn live_security_access_denied() {
        let dir = temp_dir("sec");
        let signal = OwnedEvent::create(true, true).unwrap();
        match Subscription::open("Security", logon::SECURITY_QUERY, signal.raw(), &dir.join("security.xml")) {
            Ok(_) => println!("Security log subscription succeeded (elevated shell)"),
            Err(e) => {
                println!("error: {e}");
                println!("status text: {}", open_error_text(Which::Security, &e));
                assert_eq!(e.code, 5);
            }
        }
        // a missing channel in a structured query
        let q = ssh::OPENSSH_QUERY.replace("OpenSSH/Operational", "Predator-No-Such/Operational");
        match Subscription::open("Predator-No-Such/Operational", &q, signal.raw(), &dir.join("x.xml")) {
            Ok(_) => panic!("missing channel accepted"),
            Err(e) => println!("missing channel: {e} → {}", open_error_text(Which::Ssh, &e)),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// CPU time (user + kernel) of this process.
    fn process_cpu() -> Duration {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let z = || FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut x, mut k, mut u) = (z(), z(), z(), z());
        // SAFETY: valid out-pointers; the pseudo handle needs no closing.
        unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut x, &mut k, &mut u) };
        let t = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
        Duration::from_nanos((t(k) + t(u)) * 100)
    }

    /// Live, end to end: the real engine loop with both OpenSSH channels while failed SSH logins
    /// arrive on ONE of them (the trigger of the production spin: a signal on one channel used to
    /// read the others too, and their 4317 was taken for a failure). Generates harmless failed
    /// logins for the fake user `predator-spin-test` against the local sshd.
    /// Run with `cargo test --lib monitor::tests::live_engine_no_spin -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_engine_no_spin_on_cross_channel_signals() {
        let (ctx, dir) = private_ctx("run");
        ctx.settings.set_feature(Feature::SshMonitoring, true).unwrap();
        ctx.settings.set_feature(Feature::LoginMonitoring, false).unwrap();
        let shared = Arc::new(Shared {
            stop: OwnedEvent::new_manual().unwrap(),
            settings: OwnedEvent::new_manual().unwrap(),
            stopping: AtomicBool::new(false),
        });
        let (c, s) = (ctx.clone(), shared.clone());
        let engine = std::thread::spawn(move || {
            let mut e = Engine::new(c, s).unwrap();
            e.run();
        });
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(ctx.status.ssh(), MonitorState::Active, "OpenSSH/Operational must be readable");
        let before = ctx.history.len();
        let cpu0 = process_cpu();
        for _ in 0..4 {
            let _ = std::process::Command::new(r"C:\Windows\System32\OpenSSH\ssh.exe")
                .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL"])
                .arg("predator-spin-test@127.0.0.1")
                .arg("exit")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            std::thread::sleep(Duration::from_secs(1));
        }
        std::thread::sleep(Duration::from_secs(3));
        let cpu = process_cpu().saturating_sub(cpu0);
        let got = ctx.history.len() - before;
        shared.stopping.store(true, Ordering::SeqCst);
        shared.stop.set();
        engine.join().unwrap();
        println!("failed SSH logins seen: {got}; process CPU over ~7 s: {cpu:?}; ssh state: {:?}", ctx.status.ssh());
        assert!(got >= 4, "every failed login reached the history: {got}");
        assert!(cpu < Duration::from_millis(1500), "no spin: {cpu:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Live: the engine's reconcile/open/close path with a private data directory.
    #[test]
    #[ignore]
    fn live_engine_reconcile() {
        use crate::config::{Settings, SettingsStore};
        use crate::notify::history::LoginHistory;
        use crate::notify::queue::NotificationQueue;
        use crate::paths::DataPaths;
        let dir = temp_dir("engine");
        let paths = DataPaths::new(&dir);
        paths.ensure_dirs().unwrap();
        let settings = Arc::new(SettingsStore::in_memory(Settings::default()));
        let ctx = AppContext::new(
            paths.clone(),
            settings.clone(),
            Arc::new(NotificationQueue::in_memory()),
            Arc::new(LoginHistory::in_memory()),
            "DESKTOP-01".into(),
            true,
        );
        let mut e = test_engine(ctx.clone());
        e.reconcile(true);
        println!("security: {}", ctx.status.security().label());
        println!("ssh: {}", ctx.status.ssh().label());
        println!("audit: {:?}", ctx.status.audit_policy.lock().unwrap());
        println!("next wake in {} ms", e.next_timeout_ms());
        let ssh_bm = paths.bookmark("openssh");
        let admin_bm = paths.bookmark("openssh-admin");
        if ctx.status.ssh() == MonitorState::Active {
            println!("openssh bookmark: {:?}", std::fs::read_to_string(&ssh_bm).ok().map(|s| s.replace("\r\n", " ")));
            println!("admin bookmark: {:?}", std::fs::read_to_string(&admin_bm).ok().map(|s| s.replace("\r\n", " ")));
            assert!(ssh_bm.exists(), "fresh subscription positioned at the newest record");
            e.drain(Which::Ssh);
            e.drain(Which::SshAdmin);
        }
        settings.set_feature(Feature::SshMonitoring, false).unwrap();
        e.reconcile(false);
        assert_eq!(ctx.status.ssh(), MonitorState::Disabled);
        assert!(!ssh_bm.exists(), "disabling deletes the bookmark");
        assert!(!admin_bm.exists());
        e.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }
}
