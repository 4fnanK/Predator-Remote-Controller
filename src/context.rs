//! Shared runtime context handed to every subsystem of the service.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::SettingsStore;
use crate::features::Feature;
use crate::notify::history::LoginHistory;
use crate::notify::queue::NotificationQueue;
use crate::notify::{EventDetails, NotificationKind, format};
use crate::pairing::PairingSlot;
use crate::paths::DataPaths;
use crate::telegram::janitor::{ChatJanitor, clamp_clean_after};
use crate::util::{Signal, StopFlag};

/// Telegram user id of the admin in [`AppContext::for_tests`].
pub const TEST_USER_ID: i64 = 1000;

/// Health of one monitor (Security log, OpenSSH log).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum MonitorState {
    /// Feature switched off.
    #[default]
    Disabled,
    Starting,
    Active,
    /// Not running because of an error (retrying).
    Error(String),
}

impl MonitorState {
    pub fn label(&self) -> String {
        match self {
            MonitorState::Disabled => "Disabled".into(),
            MonitorState::Starting => "Starting".into(),
            MonitorState::Active => "Active".into(),
            MonitorState::Error(e) => format!("Error: {e}"),
        }
    }
}

/// Live status counters shown in /status, the tray and logs.
#[derive(Default)]
pub struct RuntimeStatus {
    /// Last Telegram request succeeded.
    pub telegram_online: AtomicBool,
    /// Telegram returned 401 — token invalid/revoked.
    pub token_invalid: AtomicBool,
    /// Unix time of the last successful Telegram request.
    pub last_telegram_ok_unix: AtomicI64,
    /// Number of notifications delivered since start.
    pub delivered: AtomicU64,
    pub security_monitor: Mutex<MonitorState>,
    pub ssh_monitor: Mutex<MonitorState>,
    /// Audit policy status text (e.g. "Logon: Success+Failure ...").
    pub audit_policy: Mutex<Option<String>>,
    /// Last error worth surfacing (sanitized).
    pub last_error: Mutex<Option<String>>,
}

impl RuntimeStatus {
    pub fn set_security(&self, s: MonitorState) {
        *self.security_monitor.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }
    pub fn set_ssh(&self, s: MonitorState) {
        *self.ssh_monitor.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }
    pub fn security(&self) -> MonitorState {
        self.security_monitor.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn ssh(&self) -> MonitorState {
        self.ssh_monitor.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn set_last_error(&self, e: impl Into<String>) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.into());
    }
    /// "online" / "offline" / "invalid token".
    pub fn telegram_label(&self) -> &'static str {
        if self.token_invalid.load(Ordering::Relaxed) {
            "invalid token"
        } else if self.telegram_online.load(Ordering::Relaxed) {
            "online"
        } else {
            "offline"
        }
    }
}

/// At most this many failed-login alerts per window; the rest are summarized.
const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW_SECS: i64 = 600;

/// Failed-login attempts that were not alerted individually.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Suppressed {
    count: u32,
    /// Event time of the earliest / latest suppressed attempt.
    first: i64,
    last: i64,
}

/// One global fixed-window limiter for failed-login alerts (Windows and SSH). The window is
/// keyed by EVENT time, so a backlog replayed after an outage is limited like the original
/// burst. Out-of-order (older) events count in the current window instead of opening a new one.
#[derive(Debug, Default)]
struct FailureLimiter {
    /// Event time of the first alert of the current window.
    window_start: Option<i64>,
    sent_in_window: u32,
    /// Attempts suppressed in the current window and not yet summarized.
    pending: Option<Suppressed>,
}

impl FailureLimiter {
    /// Count one failed attempt at event time `t`: whether it may be alerted, plus the summary
    /// of the previous window when `t` opened a new one.
    fn admit(&mut self, t: i64) -> (bool, Option<Suppressed>) {
        let new_window = self.window_start.is_none_or(|ws| t - ws >= FAIL_WINDOW_SECS);
        if new_window {
            let summary = self.pending.take();
            self.window_start = Some(t);
            self.sent_in_window = 1;
            return (true, summary);
        }
        if self.sent_in_window < FAIL_LIMIT {
            self.sent_in_window += 1;
            return (true, None);
        }
        self.add(Suppressed { count: 1, first: t, last: t });
        (false, None)
    }

    fn add(&mut self, s: Suppressed) {
        self.pending = Some(match self.pending {
            None => s,
            Some(p) => Suppressed {
                count: p.count.saturating_add(s.count),
                first: p.first.min(s.first),
                last: p.last.max(s.last),
            },
        });
    }

    /// Unix time (wall clock) at which the pending summary is due: when its window has closed.
    fn due_at(&self) -> Option<i64> {
        self.pending.and(self.window_start).map(|ws| ws + FAIL_WINDOW_SECS)
    }

    /// The pending summary if its window has closed by `now` (or unconditionally with `force`).
    /// The window itself stays, so later attempts of the same window are still limited.
    fn take_due(&mut self, now: i64, force: bool) -> Option<Suppressed> {
        if force || self.due_at().is_some_and(|due| now >= due) { self.pending.take() } else { None }
    }
}

/// `"40 failed login attempts suppressed between 14:02 and 14:09"` (local time; the date is
/// added when the range spans midnight).
fn suppressed_text(s: Suppressed) -> String {
    use crate::util::time::{fmt_date, to_local};
    let (a, b) = (to_local(s.first), to_local(s.last));
    let hm = |t: &crate::util::time::LocalTime| format!("{:02}:{:02}", t.hour, t.minute);
    let (from, to) = if (a.year, a.month, a.day) == (b.year, b.month, b.day) {
        (hm(&a), hm(&b))
    } else {
        (format!("{} {}", fmt_date(s.first), hm(&a)), format!("{} {}", fmt_date(s.last), hm(&b)))
    };
    match s.count {
        1 => format!("1 failed login attempt suppressed at {from}"),
        n if from == to => format!("{n} failed login attempts suppressed at {from}"),
        n => format!("{n} failed login attempts suppressed between {from} and {to}"),
    }
}

pub struct AppContext {
    pub paths: DataPaths,
    pub settings: Arc<SettingsStore>,
    pub queue: Arc<NotificationQueue>,
    pub history: Arc<LoginHistory>,
    pub stop: Arc<StopFlag>,
    /// Wakes the notification sender (queue push, network change, resume, stop).
    pub sender_wake: Arc<Signal>,
    /// Wakes the Telegram poller backoff (network change, resume, stop).
    pub poller_wake: Arc<Signal>,
    pub status: RuntimeStatus,
    pub computer_name: String,
    pub started_unix: i64,
    /// True when running in console/test mode (not under the SCM).
    pub console_mode: bool,
    /// Short-lived Telegram messages waiting for automatic deletion (see
    /// [`crate::telegram::janitor`]).
    pub janitor: Arc<ChatJanitor>,
    /// The single active pairing code for adding Telegram accounts (in memory only).
    pub pairing: PairingSlot,
    limiter: Mutex<FailureLimiter>,
}

impl AppContext {
    /// Context with an in-memory chat janitor (nothing about the chat cleanup is persisted).
    pub fn new(
        paths: DataPaths,
        settings: Arc<SettingsStore>,
        queue: Arc<NotificationQueue>,
        history: Arc<LoginHistory>,
        computer_name: String,
        console_mode: bool,
    ) -> Arc<Self> {
        let janitor = Arc::new(ChatJanitor::in_memory());
        Self::with_janitor(paths, settings, queue, history, janitor, computer_name, console_mode)
    }

    /// [`AppContext::new`] with a given (usually persistent) chat janitor.
    pub fn with_janitor(
        paths: DataPaths,
        settings: Arc<SettingsStore>,
        queue: Arc<NotificationQueue>,
        history: Arc<LoginHistory>,
        janitor: Arc<ChatJanitor>,
        computer_name: String,
        console_mode: bool,
    ) -> Arc<Self> {
        let stop = Arc::new(StopFlag::new());
        let sender_wake = Arc::new(Signal::new());
        let poller_wake = Arc::new(Signal::new());
        stop.register(sender_wake.clone());
        stop.register(poller_wake.clone());
        queue.set_waker(sender_wake.clone());
        Arc::new(Self {
            paths,
            settings,
            queue,
            history,
            stop,
            sender_wake,
            poller_wake,
            status: RuntimeStatus::default(),
            computer_name,
            started_unix: crate::util::time::now_unix(),
            console_mode,
            janitor,
            pairing: PairingSlot::new(),
            limiter: Mutex::new(FailureLimiter::default()),
        })
    }

    /// Seconds of inactivity after which short-lived chat messages are deleted, or `None` when
    /// automatic chat cleaning is switched off (`auto_clean_chat`).
    pub fn auto_clean_after(&self) -> Option<u64> {
        let s = self.settings.get();
        s.auto_clean_chat.then(|| clamp_clean_after(s.chat_clean_after_secs))
    }

    /// Track a short-lived message for automatic deletion. Does nothing (returns false) when
    /// automatic chat cleaning is off.
    pub fn track_chat_message(&self, chat_id: i64, message_id: i64, sent_unix: i64) -> bool {
        if self.auto_clean_after().is_none() {
            return false;
        }
        self.janitor.track(chat_id, message_id, sent_unix, crate::util::time::now_unix());
        true
    }

    /// In-memory context for unit tests: one authorized Telegram user, admin
    /// [`TEST_USER_ID`] ("owner").
    pub fn for_tests() -> Arc<Self> {
        use crate::config::{AuthorizedUser, Settings, UserRole};
        let settings = Settings {
            authorized_users: vec![AuthorizedUser::new(TEST_USER_ID, "owner", UserRole::Admin, 0)],
            ..Settings::default()
        };
        Self::new(
            DataPaths::new(std::env::temp_dir().join("predator-test-ctx")),
            Arc::new(SettingsStore::in_memory(settings)),
            Arc::new(NotificationQueue::in_memory()),
            Arc::new(LoginHistory::in_memory()),
            "TESTPC".into(),
            true,
        )
    }

    /// Network connectivity changed or the system resumed: retry Telegram immediately.
    pub fn network_changed(&self) {
        self.sender_wake.notify();
        self.poller_wake.notify();
    }

    /// Which feature switches gate a given event kind: (monitor feature, notification feature).
    fn gates(kind: NotificationKind) -> (Option<Feature>, Option<Feature>) {
        match kind {
            NotificationKind::Login => (Some(Feature::LoginMonitoring), Some(Feature::LoginNotifications)),
            NotificationKind::FailedLogin => (Some(Feature::LoginMonitoring), Some(Feature::FailedLoginNotifications)),
            NotificationKind::Logout => (Some(Feature::LoginMonitoring), Some(Feature::LogoutNotifications)),
            NotificationKind::SshLogin => (Some(Feature::SshMonitoring), Some(Feature::LoginNotifications)),
            NotificationKind::SshFailed => (Some(Feature::SshMonitoring), Some(Feature::FailedLoginNotifications)),
            NotificationKind::SshLogout => (Some(Feature::SshMonitoring), Some(Feature::LogoutNotifications)),
            NotificationKind::System | NotificationKind::Security => (None, None),
        }
    }

    /// Entry point for every monitor: record history (when monitoring is on), apply notification
    /// feature switches and rate limits, render and durably queue the Telegram message.
    ///
    /// An event whose `dedupe_key` is already queued or was delivered recently (a replay after
    /// a crash, a retry) is dropped before ANY side effect, and the history ignores a key it
    /// already holds, so retries never duplicate history entries or rate-limit counts.
    ///
    /// Returns `Ok(true)` if a notification was queued, `Ok(false)` if suppressed by settings,
    /// rate limits or deduplication. `Err` only when the queue could not be persisted (the caller
    /// must then NOT advance its event-log bookmark).
    pub fn emit_event(&self, d: EventDetails, dedupe_key: Option<String>) -> std::io::Result<bool> {
        let (monitor, notif) = Self::gates(d.kind);
        let s = self.settings.get();
        if let Some(m) = monitor
            && !s.features.is_enabled(m)
        {
            return Ok(false); // monitoring disabled: completely ignored
        }
        if let Some(k) = dedupe_key.as_deref()
            && self.queue.contains_key(k)
        {
            return Ok(false); // already handled (replayed event)
        }
        if d.kind.is_history() {
            self.history.record_keyed(d.clone(), dedupe_key.as_deref());
        }
        if let Some(n) = notif
            && !s.features.is_enabled(n)
        {
            return Ok(false);
        }
        if matches!(d.kind, NotificationKind::FailedLogin | NotificationKind::SshFailed)
            && !self.allow_failure_alert(d.event_unix)?
        {
            return Ok(false);
        }
        let html = format::render_event(&d);
        Ok(self.queue.push(d.kind, d.event_unix, html, dedupe_key)?.is_some())
    }

    /// Queue a system/lifecycle message (always delivered, not feature-gated).
    pub fn emit_system(
        &self,
        emoji: &str,
        title: &str,
        lines: &[(String, String)],
        event_unix: i64,
        dedupe_key: Option<String>,
    ) -> std::io::Result<bool> {
        self.emit_rendered(NotificationKind::System, emoji, title, lines, event_unix, dedupe_key)
    }

    /// Queue a summary-style message (rendered like a system message) under `kind`, which
    /// decides whether it is kept in the chat (login-related kinds) or auto-deleted (`System`).
    /// Not feature-gated.
    pub fn emit_rendered(
        &self,
        kind: NotificationKind,
        emoji: &str,
        title: &str,
        lines: &[(String, String)],
        event_unix: i64,
        dedupe_key: Option<String>,
    ) -> std::io::Result<bool> {
        let html = format::render_system(emoji, title, lines, event_unix);
        Ok(self.queue.push(kind, event_unix, html, dedupe_key)?.is_some())
    }

    /// Queue a security message (unauthorized access etc.) for every authorized user.
    pub fn emit_security(&self, title: &str, lines: &[(String, String)]) -> std::io::Result<bool> {
        self.emit_security_keyed(title, lines, None)
    }

    /// Queue a message rendered like a system message (stamped now) for every authorized user
    /// except the chats in `exclude` (e.g. "new user paired" goes to everyone but the new user).
    /// Not feature-gated.
    pub fn emit_notice(
        &self,
        kind: NotificationKind,
        emoji: &str,
        title: &str,
        lines: &[(String, String)],
        exclude: &[i64],
    ) -> std::io::Result<bool> {
        let now = crate::util::time::now_unix();
        let html = format::render_system(emoji, title, lines, now);
        Ok(self.queue.push_excluding(kind, now, html, None, exclude)?.is_some())
    }

    /// [`AppContext::emit_security`] with an idempotency key (security alerts derived from
    /// event-log records, so a replayed record does not alert twice).
    pub fn emit_security_keyed(
        &self,
        title: &str,
        lines: &[(String, String)],
        dedupe_key: Option<String>,
    ) -> std::io::Result<bool> {
        let now = crate::util::time::now_unix();
        let html = format::render_system("🚨", title, lines, now);
        Ok(self.queue.push(NotificationKind::Security, now, html, dedupe_key)?.is_some())
    }

    fn lock_limiter(&self) -> std::sync::MutexGuard<'_, FailureLimiter> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn allow_failure_alert(&self, event_unix: i64) -> std::io::Result<bool> {
        let (allowed, summary) = self.lock_limiter().admit(event_unix);
        if let Some(s) = summary {
            self.emit_summary(s)?;
        }
        Ok(allowed)
    }

    /// Queue the "alerts suppressed" summary, stamped with the latest suppressed attempt. It is
    /// login-related, so it is queued as `FailedLogin` and kept in the chat (never auto-deleted).
    /// On failure the count goes back into the limiter (summarized later, never lost silently).
    fn emit_summary(&self, s: Suppressed) -> std::io::Result<bool> {
        let lines = [
            ("Suppressed".to_string(), suppressed_text(s)),
            (
                "Limit".to_string(),
                format!("at most {FAIL_LIMIT} failed-login alerts are sent per {} minutes", FAIL_WINDOW_SECS / 60),
            ),
        ];
        match self.emit_rendered(
            NotificationKind::FailedLogin,
            "⚠️",
            "FAILED LOGIN ALERTS SUPPRESSED",
            &lines,
            s.last,
            None,
        ) {
            Ok(q) => Ok(q),
            Err(e) => {
                self.lock_limiter().add(s);
                Err(e)
            }
        }
    }

    /// Emit the pending "failed login alerts suppressed" summary once its 10-minute window has
    /// closed by `now_unix` (called from the monitor thread, so a summary never waits for the
    /// next failure). Returns whether a summary was queued.
    pub fn flush_suppressed(&self, now_unix: i64) -> std::io::Result<bool> {
        let due = self.lock_limiter().take_due(now_unix, false);
        match due {
            Some(s) => self.emit_summary(s),
            None => Ok(false),
        }
    }

    /// Unix time at which [`AppContext::flush_suppressed`] has a summary to emit (`None` when
    /// no attempt is waiting to be summarized).
    pub fn suppressed_flush_due(&self) -> Option<i64> {
        self.lock_limiter().due_at()
    }

    /// Service stop: queue any pending suppression summary (even if its window is still open)
    /// and write the login history. Idempotent; errors are logged.
    pub fn flush_pending(&self) {
        let pending = self.lock_limiter().take_due(0, true);
        if let Some(s) = pending
            && let Err(e) = self.emit_summary(s)
        {
            crate::log_warn!("cannot queue the failed-login summary: {e}");
        }
        if let Err(e) = self.history.flush() {
            crate::log_warn!("cannot save the login history: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::EventDetails;

    fn failed(user: &str, ip: &str, t: i64) -> EventDetails {
        EventDetails {
            kind: NotificationKind::FailedLogin,
            computer: "TESTPC".into(),
            user: user.into(),
            method: "Network".into(),
            source_ip: Some(ip.into()),
            reason: Some("Wrong password".into()),
            event_unix: t,
            ..EventDetails::default()
        }
    }

    fn ctx_with_failures() -> Arc<AppContext> {
        let ctx = AppContext::for_tests();
        ctx.settings.set_feature(Feature::FailedLoginNotifications, true).unwrap();
        ctx
    }

    fn summaries(ctx: &AppContext) -> Vec<crate::notify::Notification> {
        let mut out = Vec::new();
        while let Some(n) = ctx.queue.front() {
            ctx.queue.ack(n.id).unwrap();
            if n.html.contains("FAILED LOGIN ALERTS SUPPRESSED") {
                out.push(n);
            }
        }
        out
    }

    const T0: i64 = 1_795_588_515;

    #[test]
    fn limiter_windows_by_event_time() {
        let mut l = FailureLimiter::default();
        for i in 0..FAIL_LIMIT {
            assert_eq!(l.admit(T0 + i64::from(i)), (true, None));
        }
        assert_eq!(l.admit(T0 + 20), (false, None));
        assert_eq!(l.admit(T0 - 30), (false, None), "an older event counts in the current window");
        assert_eq!(l.admit(T0 + 40), (false, None));
        assert_eq!(l.due_at(), Some(T0 + FAIL_WINDOW_SECS));
        assert_eq!(l.take_due(T0 + 599, false), None, "window still open");
        // the next failure after the window opens a new one and carries the summary
        let (ok, s) = l.admit(T0 + 700);
        assert!(ok);
        assert_eq!(s, Some(Suppressed { count: 3, first: T0 - 30, last: T0 + 40 }));
        assert_eq!(l.due_at(), None);
    }

    #[test]
    fn summary_is_flushed_when_the_window_closes() {
        let ctx = ctx_with_failures();
        let mut queued = 0;
        for i in 0..50 {
            if ctx.emit_event(failed("administrator", "203.0.113.9", T0 + i), None).unwrap() {
                queued += 1;
            }
        }
        assert_eq!(queued, FAIL_LIMIT);
        assert_eq!(ctx.queue.len(), FAIL_LIMIT as usize, "no summary while the window is open");
        assert!(!ctx.flush_suppressed(T0 + 100).unwrap());
        assert_eq!(ctx.suppressed_flush_due(), Some(T0 + FAIL_WINDOW_SECS));
        // no further failure ever arrives: the monitor's next wake after the window emits it
        assert!(ctx.flush_suppressed(T0 + FAIL_WINDOW_SECS).unwrap());
        assert_eq!(ctx.suppressed_flush_due(), None);
        assert!(!ctx.flush_suppressed(T0 + 10_000).unwrap(), "emitted exactly once");
        let s = summaries(&ctx);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].event_unix, T0 + 49, "stamped with the last suppressed attempt");
        // login-related: queued under a kept kind, so the chat cleanup never deletes it
        assert_eq!(s[0].kind, NotificationKind::FailedLogin);
        assert!(!crate::telegram::janitor::is_ephemeral_kind(s[0].kind));
        let expected = suppressed_text(Suppressed { count: 40, first: T0 + 10, last: T0 + 49 });
        assert!(expected.starts_with("40 failed login attempts suppressed"), "{expected}");
        assert!(s[0].html.contains(&crate::notify::format::escape_html(&expected)), "{}", s[0].html);
        assert!(!s[0].html.contains("previous 10 minutes"));
    }

    #[test]
    fn summary_is_emitted_before_the_next_failure() {
        let ctx = ctx_with_failures();
        for i in 0..12 {
            ctx.emit_event(failed("a", "1.2.3.4", T0 + i), None).unwrap();
        }
        assert!(ctx.emit_event(failed("a", "1.2.3.4", T0 + 86_400), None).unwrap());
        let s = summaries(&ctx);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].event_unix, T0 + 11, "not the time of the unrelated later failure");
    }

    #[test]
    fn flush_pending_summarizes_an_open_window() {
        let ctx = ctx_with_failures();
        for i in 0..11 {
            ctx.emit_event(failed("a", "1.2.3.4", T0 + i), None).unwrap();
        }
        ctx.flush_pending();
        assert_eq!(summaries(&ctx).len(), 1);
        ctx.flush_pending(); // nothing left
        assert!(ctx.queue.is_empty());
    }

    #[test]
    fn suppressed_text_wording() {
        let one = suppressed_text(Suppressed { count: 1, first: T0, last: T0 });
        assert!(one.starts_with("1 failed login attempt suppressed at "), "{one}");
        let many = suppressed_text(Suppressed { count: 7, first: T0, last: T0 + 300 });
        assert!(many.starts_with("7 failed login attempts suppressed between "), "{many}");
        assert!(many.contains(" and "));
        let days = suppressed_text(Suppressed { count: 2, first: T0, last: T0 + 2 * 86_400 });
        assert!(days.contains(&crate::util::time::fmt_date(T0)), "{days}");
    }

    #[test]
    fn system_and_rendered_kinds() {
        let ctx = AppContext::for_tests();
        assert!(ctx.emit_system("🟢", "VIGIL ONLINE", &[], T0, None).unwrap());
        assert!(ctx.emit_rendered(NotificationKind::Security, "🚨", "X", &[], T0, None).unwrap());
        let a = ctx.queue.front().unwrap();
        ctx.queue.ack(a.id).unwrap();
        let b = ctx.queue.front().unwrap();
        assert_eq!((a.kind, b.kind), (NotificationKind::System, NotificationKind::Security));
        assert!(a.html.contains("VIGIL ONLINE"));
    }

    #[test]
    fn notices_can_exclude_recipients() {
        let ctx = AppContext::for_tests();
        assert!(ctx.pairing.redeem("12345678", 5, T0).is_err(), "no code is active in a fresh context");
        let lines = [("User ID".to_string(), "5000".to_string())];
        assert!(
            ctx.emit_notice(NotificationKind::Security, "👤", "NEW TELEGRAM USER PAIRED", &lines, &[5000]).unwrap()
        );
        let n = ctx.queue.front().unwrap();
        assert_eq!(n.kind, NotificationKind::Security);
        assert_eq!(n.delivered_to, vec![5000]);
        assert!(n.html.starts_with("👤 <b>NEW TELEGRAM USER PAIRED</b>"), "{}", n.html);
        // everything else goes to every user
        ctx.queue.ack(n.id).unwrap();
        ctx.emit_security("UNAUTHORIZED ACCESS ATTEMPT", &[]).unwrap();
        assert!(ctx.queue.front().unwrap().delivered_to.is_empty());
        assert!(ctx.settings.is_authorized(TEST_USER_ID));
    }

    #[test]
    fn chat_cleanup_switch() {
        let ctx = AppContext::for_tests();
        assert_eq!(ctx.auto_clean_after(), Some(600), "on by default, 10 minutes");
        ctx.settings.update(|s| s.chat_clean_after_secs = 5).unwrap();
        assert_eq!(ctx.auto_clean_after(), Some(crate::telegram::janitor::MIN_CLEAN_AFTER_SECS));
        assert!(ctx.track_chat_message(1000, 7, crate::util::time::now_unix()));
        assert!(ctx.janitor.contains(1000, 7));
        // switched off: nothing is tracked
        ctx.settings.update(|s| s.auto_clean_chat = false).unwrap();
        assert_eq!(ctx.auto_clean_after(), None);
        assert!(!ctx.track_chat_message(1000, 8, crate::util::time::now_unix()));
        assert!(!ctx.janitor.contains(1000, 8));
        assert_eq!(ctx.janitor.len(), 1);
    }

    #[test]
    fn replayed_events_have_no_side_effects() {
        let ctx = AppContext::for_tests();
        let login = EventDetails {
            kind: NotificationKind::Login,
            user: "alice".into(),
            method: "Interactive".into(),
            event_unix: T0,
            ..EventDetails::default()
        };
        assert!(ctx.emit_event(login.clone(), Some("security:5:100".into())).unwrap());
        assert!(!ctx.emit_event(login.clone(), Some("security:5:100".into())).unwrap());
        assert_eq!(ctx.history.len(), 1, "a replay is not recorded twice");
        // same record id after a log clear, different TimeCreated: a new event
        assert!(ctx.emit_event(login.clone(), Some("security:5:200".into())).unwrap());
        assert_eq!(ctx.history.len(), 2);
        // failures that are only recorded (alerts off) are not duplicated by replays either
        ctx.emit_event(failed("x", "1.1.1.1", T0), Some("security:6:1".into())).unwrap();
        ctx.emit_event(failed("x", "1.1.1.1", T0), Some("security:6:1".into())).unwrap();
        assert_eq!(ctx.history.len(), 3);
    }
}
