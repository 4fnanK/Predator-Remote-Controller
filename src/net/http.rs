//! HTTPS client used by the Telegram API: the neutral request/response types and the backend
//! facade [`HttpClient`].
//!
//! Backends:
//! * **direct** ([`super::direct::DirectClient`]): TcpStream + SChannel, HTTP/1.1 keep-alive, no
//!   background threads. The normal path; `winhttp.dll` is never loaded on it (the service
//!   delay-loads it, see `build.rs`).
//! * **WinHTTP** ([`super::winhttp::WinHttpClient`]): only for proxies. Created lazily, the first
//!   time a request is routed to it.
//!
//! Selection ([`Selector`], pure and unit-tested):
//! 1. At creation: `PREDATOR_HTTP_TRANSPORT=direct|winhttp` forces a backend (no automatic
//!    switching between them). Otherwise a static WinHTTP proxy (`netsh winhttp`) starts on WinHTTP
//!    with `DEFAULT_PROXY`, a manual proxy / PAC URL in the Internet Settings on WinHTTP with
//!    `AUTOMATIC_PROXY`, and everything else on the direct client ([`super::proxy`]).
//! 2. At run time the backend only changes when another one is *shown* to work: after
//!    [`TRIAL_FIRST`] consecutive connect-level failures of the current backend, spread over at
//!    least [`TRIAL_MIN_SPAN`] (failures while Windows reports no network at all do not count),
//!    the next request is sent as a single trial through WinHTTP with automatic proxy detection
//!    (WPAD / PAC / Internet Settings). Only if that trial reaches the server — and no request of
//!    the current backend has reached it in the meantime — does the client switch to it, for the
//!    rest of the process (one warning). A failed trial leaves the backend alone; the next one
//!    comes after twice as many failures, up to [`TRIAL_MAX`]. This applies to the direct client
//!    (unless forced) and to WinHTTP with `DEFAULT_PROXY`; `AUTOMATIC_PROXY` is the last step.
//!
//!    So an ordinary outage (ISP or DNS down while Windows still reports internet access) never
//!    moves the service onto WinHTTP for good: the trial fails like everything else, and the
//!    direct client carries on once the network is back.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::direct::{DirectClient, DirectError, Phase};
use super::proxy::{self, Initial, Override, Start, SystemProxy};
use super::winhttp::{ProxyMode, WinHttpClient};
use crate::sys::InternetStatus;

pub use super::proxy::TRANSPORT_ENV;

/// Transport failure. Texts never contain the host or the path (the Telegram path carries the bot
/// token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Socket/TLS/WinHTTP level failure (code = Win32, WinSock, SSPI or WinHTTP error).
    Network {
        code: u32,
        message: String,
    },
    Timeout,
    Other(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Network { code, message } if (12_000..=12_999).contains(code) => {
                write!(f, "{message} (WinHTTP error {code})")
            }
            HttpError::Network { code, message } if *code >= 0x8000_0000 => write!(f, "{message} (error {code:#010X})"),
            HttpError::Network { code, message } => write!(f, "{message} (error {code})"),
            HttpError::Timeout => write!(f, "request timed out"),
            HttpError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// How [`HttpClient::interrupt`] may stop a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interruptible {
    /// At any point. For requests that are harmless to repeat (the `getUpdates` long poll, edits,
    /// deletions, ...).
    Always,
    /// Only while connecting or sending. Once the request has been completely sent it runs to its
    /// response or its time limit, so a request that may already have taken effect
    /// (`sendMessage`) is never reported as failed because of an interrupt — and then sent a
    /// second time by its caller.
    UntilSent,
}

/// Largest response body we accept (Telegram replies are far smaller; this bounds RAM use).
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// `transport_name` values.
pub const TRANSPORT_DIRECT: &str = "direct (SChannel)";
pub const TRANSPORT_WINHTTP: &str = "WinHTTP (default proxy)";
pub const TRANSPORT_WINHTTP_AUTO: &str = "WinHTTP (automatic proxy)";

/// Consecutive connect-level failures before the first WinHTTP trial request.
pub const TRIAL_FIRST: u32 = 3;
/// Largest gap between WinHTTP trial requests, in failures.
pub const TRIAL_MAX: u32 = 48;
/// A failure streak must last at least this long before the first trial: a short network blip
/// (Wi-Fi roaming, router restart) must not load WinHTTP and run a WPAD discovery.
pub const TRIAL_MIN_SPAN: Duration = Duration::from_secs(60);

/// One line, no trailing period/whitespace.
pub(crate) fn clean_message(raw: &str) -> String {
    let joined = raw.split(['\r', '\n']).map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    joined.trim_end_matches(['.', ' ']).to_string()
}

/// `prefix: <system text>` for an I/O error. Uses only the error code (system message table) or
/// the error kind, never the error's own text, so no host/path can leak into it.
pub(crate) fn io_error(prefix: &str, e: &io::Error) -> HttpError {
    match e.raw_os_error() {
        Some(raw) => {
            let code = raw as u32;
            let text = clean_message(&crate::util::win::error_message(code));
            HttpError::Network { code, message: format!("{prefix}: {text}") }
        }
        None => HttpError::Other(format!("{prefix}: {}", e.kind())),
    }
}

// ---------------------------------------------------------------------------------------------
// Backend selection (pure)
// ---------------------------------------------------------------------------------------------

/// The backend requests normally go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Direct,
    WinHttp(ProxyMode),
}

/// Where the next request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Direct,
    WinHttp(ProxyMode),
    /// One request through WinHTTP to find out whether it reaches the server where the current
    /// backend does not.
    Trial(ProxyMode),
}

/// Result of a direct request, as far as backend selection is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectOutcome {
    /// A response arrived.
    Success,
    /// The TLS connection was up but the exchange failed (time-out, reset, bad response).
    ServerReached,
    /// Name resolution, TCP connect or TLS handshake failed.
    ConnectFailure,
    /// Says nothing about the network (cancelled, invalid input).
    Neutral,
}

impl DirectOutcome {
    fn of(r: &Result<HttpResponse, DirectError>) -> Self {
        match r {
            Ok(_) => Self::Success,
            Err(e) if e.phase.is_connect_level() => Self::ConnectFailure,
            Err(e) if e.phase == Phase::Exchange => Self::ServerReached,
            Err(_) => Self::Neutral,
        }
    }
}

/// Result of a WinHTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinOutcome {
    Success,
    /// `HttpError::Network` / `Timeout`.
    NetworkFailure,
    /// `HttpError::Other` (local problems, oversized replies).
    Neutral,
}

impl WinOutcome {
    fn of(r: &Result<HttpResponse, HttpError>) -> Self {
        match r {
            Ok(_) => Self::Success,
            Err(HttpError::Network { .. } | HttpError::Timeout) => Self::NetworkFailure,
            Err(HttpError::Other(_)) => Self::Neutral,
        }
    }
}

/// The end of a trial: one log line and, for some, an action on the clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// A trial reached the server while `from` kept failing: switched to WinHTTP with automatic
    /// proxy detection for good.
    Switched { from: Backend },
    /// A trial did not show a better path; the next one comes after `next_after` more failures.
    TrialFailed { next_after: u32 },
    /// The current backend reached the server while the trial ran: nothing to change.
    TrialNotNeeded,
}

#[derive(Debug, Clone)]
pub(crate) struct Selector {
    forced: bool,
    backend: Backend,
    /// Consecutive connect-level failures of the current backend since the last trial.
    failures: u32,
    /// Start of the current failure streak (cleared when a request reaches the server).
    streak_since: Option<Instant>,
    trial_threshold: u32,
    trial_pending: bool,
    trial_running: bool,
    /// The current backend reached the server while the trial was running.
    trial_superseded: bool,
}

impl Selector {
    pub(crate) fn new(initial: Initial) -> Self {
        let backend = match initial.start {
            Start::Direct => Backend::Direct,
            Start::WinHttp(mode) => Backend::WinHttp(mode),
        };
        Self {
            forced: initial.forced,
            backend,
            failures: 0,
            streak_since: None,
            trial_threshold: TRIAL_FIRST,
            trial_pending: false,
            trial_running: false,
            trial_superseded: false,
        }
    }

    pub(crate) fn route(&mut self) -> Route {
        if self.trial_pending && !self.trial_running {
            self.trial_pending = false;
            self.trial_running = true;
            self.trial_superseded = false;
            return Route::Trial(ProxyMode::Automatic);
        }
        match self.backend {
            Backend::Direct => Route::Direct,
            Backend::WinHttp(mode) => Route::WinHttp(mode),
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        match self.backend {
            Backend::Direct => TRANSPORT_DIRECT,
            Backend::WinHttp(ProxyMode::Default) => TRANSPORT_WINHTTP,
            Backend::WinHttp(ProxyMode::Automatic) => TRANSPORT_WINHTTP_AUTO,
        }
    }

    /// The WinHTTP mode of the backend in use, if it is WinHTTP.
    fn winhttp_mode(&self) -> Option<ProxyMode> {
        match self.backend {
            Backend::Direct => None,
            Backend::WinHttp(mode) => Some(mode),
        }
    }

    /// A trial could lead somewhere: direct (unless forced by the environment) and WinHTTP with
    /// `DEFAULT_PROXY` may move on to `AUTOMATIC_PROXY`, which is the last step.
    fn can_trial(&self) -> bool {
        match self.backend {
            Backend::Direct => !self.forced,
            Backend::WinHttp(ProxyMode::Default) => true,
            Backend::WinHttp(ProxyMode::Automatic) => false,
        }
    }

    /// The current backend reached the server.
    fn reached(&mut self) {
        self.failures = 0;
        self.streak_since = None;
        self.trial_threshold = TRIAL_FIRST;
        self.trial_pending = false;
        if self.trial_running {
            self.trial_superseded = true;
        }
    }

    /// A connect-level failure of the current backend at `now` (not while disconnected).
    fn failed(&mut self, now: Instant) {
        if !self.can_trial() {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        let since = *self.streak_since.get_or_insert(now);
        if self.failures >= self.trial_threshold
            && now.saturating_duration_since(since) >= TRIAL_MIN_SPAN
            && !self.trial_running
        {
            self.trial_pending = true;
        }
    }

    pub(crate) fn record_direct(&mut self, outcome: DirectOutcome, hint: InternetStatus, now: Instant) {
        if self.backend != Backend::Direct {
            return; // a late result from before a switch
        }
        match outcome {
            DirectOutcome::Success | DirectOutcome::ServerReached => self.reached(),
            DirectOutcome::ConnectFailure if hint != InternetStatus::Disconnected => self.failed(now),
            DirectOutcome::ConnectFailure | DirectOutcome::Neutral => {}
        }
    }

    /// `mode` = the mode the request was made with (a result for an outdated mode is ignored).
    pub(crate) fn record_winhttp(&mut self, mode: ProxyMode, outcome: WinOutcome, hint: InternetStatus, now: Instant) {
        if self.backend != Backend::WinHttp(mode) {
            return;
        }
        match outcome {
            WinOutcome::Success => self.reached(),
            WinOutcome::NetworkFailure if hint != InternetStatus::Disconnected => self.failed(now),
            WinOutcome::NetworkFailure | WinOutcome::Neutral => {}
        }
    }

    pub(crate) fn record_trial(&mut self, outcome: WinOutcome) -> Event {
        self.trial_running = false;
        self.failures = 0;
        let superseded = std::mem::take(&mut self.trial_superseded);
        match outcome {
            WinOutcome::Success if superseded => Event::TrialNotNeeded,
            WinOutcome::Success if self.can_trial() => {
                let from = self.backend;
                self.backend = Backend::WinHttp(ProxyMode::Automatic);
                self.streak_since = None;
                self.trial_threshold = TRIAL_FIRST;
                self.trial_pending = false;
                Event::Switched { from }
            }
            // Also an inconclusive trial (WinHTTP unusable locally, ...) backs off, so that a broken
            // WinHTTP cannot cause a trial (and a log line) every few failures for ever.
            WinOutcome::NetworkFailure | WinOutcome::Neutral | WinOutcome::Success => {
                self.trial_threshold = self.trial_threshold.saturating_mul(2).min(TRIAL_MAX);
                Event::TrialFailed { next_after: self.trial_threshold }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Facade
// ---------------------------------------------------------------------------------------------

/// HTTPS client shared by every thread (poller, sender, bot replies). See the module docs.
pub struct HttpClient {
    user_agent: String,
    direct: DirectClient,
    /// Created on first use only, so `winhttp.dll` stays unloaded on the direct path.
    winhttp: Mutex<Option<(ProxyMode, Arc<WinHttpClient>)>>,
    selector: Mutex<Selector>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpClient { .. }")
    }
}

impl HttpClient {
    /// Create a client with the given User-Agent. No network I/O; reads the
    /// `PREDATOR_HTTP_TRANSPORT` variable and the proxy configuration (registry).
    pub fn new(user_agent: &str) -> Result<Self, HttpError> {
        let raw = std::env::var(TRANSPORT_ENV).ok();
        let (over, unknown) = proxy::parse_override(raw.as_deref());
        if unknown {
            let shown = crate::util::truncate_chars(raw.as_deref().unwrap_or_default(), 32);
            crate::log_warn!("{TRANSPORT_ENV}={shown:?} is not recognised (use direct or winhttp); ignored");
        }
        let sys = if over == Override::Direct { SystemProxy::default() } else { proxy::detect() };
        Ok(Self::with_initial(user_agent, proxy::initial_choice(over, sys)))
    }

    fn with_initial(user_agent: &str, initial: Initial) -> Self {
        let selector = Selector::new(initial);
        match initial.start {
            Start::Direct => crate::log_debug!("HTTPS transport: {} ({})", selector.name(), initial.reason),
            Start::WinHttp(_) => crate::log_info!("HTTPS transport: {} ({})", selector.name(), initial.reason),
        }
        Self {
            user_agent: user_agent.to_owned(),
            direct: DirectClient::new(user_agent),
            winhttp: Mutex::new(None),
            selector: Mutex::new(selector),
        }
    }

    /// HTTPS POST `body` as `application/json` to `https://{host}{path}` and read the full
    /// response. `timeout` bounds the wait for the response (long polls pass ~65 s); connect,
    /// TLS handshake and send use 15 s each, capped at `timeout`. [`HttpClient::interrupt`] may
    /// stop it at any point ([`Interruptible::Always`]).
    pub fn post_json(&self, host: &str, path: &str, body: &[u8], timeout: Duration) -> Result<HttpResponse, HttpError> {
        self.post_json_with(host, path, body, timeout, Interruptible::Always)
    }

    /// [`HttpClient::post_json`] with an explicit [`Interruptible`] policy.
    pub fn post_json_with(
        &self,
        host: &str,
        path: &str,
        body: &[u8],
        timeout: Duration,
        when: Interruptible,
    ) -> Result<HttpResponse, HttpError> {
        let route = lock(&self.selector).route();
        match route {
            Route::Direct => {
                let result = self.direct.post_classified(host, path, body, timeout, when);
                let outcome = DirectOutcome::of(&result);
                if outcome != DirectOutcome::Neutral {
                    // The connectivity hint is only consulted for a failure that counts.
                    let hint = if outcome == DirectOutcome::ConnectFailure {
                        super::connectivity::current()
                    } else {
                        InternetStatus::Connected
                    };
                    lock(&self.selector).record_direct(outcome, hint, Instant::now());
                }
                result.map_err(|e| e.error)
            }
            Route::WinHttp(mode) => {
                let result = self.winhttp_post(mode, host, path, body, timeout);
                let outcome = WinOutcome::of(&result);
                let hint = if outcome == WinOutcome::NetworkFailure {
                    super::connectivity::current()
                } else {
                    InternetStatus::Connected
                };
                lock(&self.selector).record_winhttp(mode, outcome, hint, Instant::now());
                result
            }
            Route::Trial(mode) => {
                let result = self.winhttp_post(mode, host, path, body, timeout);
                let event = lock(&self.selector).record_trial(WinOutcome::of(&result));
                self.handle(event);
                result
            }
        }
    }

    /// Stop the direct requests in flight at once (network change, resume) and close the idle
    /// connections: a blocked long poll returns immediately with a network error. A request sent
    /// with [`Interruptible::UntilSent`] is only stopped while it is still connecting or sending.
    /// WinHTTP requests are not affected (no-op on that backend).
    pub fn interrupt(&self) {
        self.direct.interrupt();
    }

    /// The backend in use now: [`TRANSPORT_DIRECT`], [`TRANSPORT_WINHTTP`] or
    /// [`TRANSPORT_WINHTTP_AUTO`] (for status and selftest output).
    pub fn transport_name(&self) -> &'static str {
        lock(&self.selector).name()
    }

    /// One WinHTTP request; a panic cannot escape (it would also leave a trial marked running).
    fn winhttp_post(
        &self,
        mode: ProxyMode,
        host: &str,
        path: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, HttpError> {
        catch_unwind(AssertUnwindSafe(|| {
            self.winhttp_client(mode).and_then(|c| c.post_json(host, path, body, timeout))
        }))
        .unwrap_or_else(|_| Err(HttpError::Other("internal error in the WinHTTP client".into())))
    }

    /// The WinHTTP client for `mode`, created (and `winhttp.dll` loaded) on first use.
    fn winhttp_client(&self, mode: ProxyMode) -> Result<Arc<WinHttpClient>, HttpError> {
        let mut slot = lock(&self.winhttp);
        if let Some((m, client)) = slot.as_ref()
            && *m == mode
        {
            return Ok(Arc::clone(client));
        }
        let client = Arc::new(WinHttpClient::with_mode(&self.user_agent, mode)?);
        // A client of another mode is dropped here (requests still using it hold their own Arc).
        *slot = Some((mode, Arc::clone(&client)));
        Ok(client)
    }

    fn handle(&self, event: Event) {
        match event {
            Event::Switched { from: Backend::Direct } => {
                self.direct.close_idle();
                crate::log_warn!(
                    "HTTPS: the direct connection to the server kept failing while WinHTTP with automatic proxy \
                     detection reached it; using WinHTTP (system proxy support) until the service restarts"
                );
            }
            Event::Switched { from: _ } => crate::log_warn!(
                "HTTPS: WinHTTP with the default proxy setting kept failing while automatic proxy detection \
                 (WPAD/PAC) reached the server; using it until the service restarts"
            ),
            Event::TrialFailed { next_after } => {
                self.drop_trial_client();
                crate::log_info!(
                    "HTTPS: WinHTTP with automatic proxy detection did not reach the server either; keeping the \
                     current connection method (next check after {next_after} more connection failures)"
                );
            }
            Event::TrialNotNeeded => {
                self.drop_trial_client();
                crate::log_debug!("HTTPS: the server is reachable again; the WinHTTP trial was not needed");
            }
        }
    }

    /// Close the session a trial created, unless the backend in use is that same session (its
    /// `WinHttpCloseHandle` runs outside the lock).
    fn drop_trial_client(&self) {
        let keep = lock(&self.selector).winhttp_mode();
        let unused = {
            let mut slot = lock(&self.winhttp);
            match slot.as_ref() {
                Some((m, _)) if Some(*m) != keep => slot.take(),
                _ => None,
            }
        };
        drop(unused);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTO_DIRECT: Initial = Initial { start: Start::Direct, forced: false, reason: "test" };
    const C: InternetStatus = InternetStatus::Connected;
    const MIN: Duration = TRIAL_MIN_SPAN;

    fn sel() -> Selector {
        Selector::new(AUTO_DIRECT)
    }

    /// `n` direct connect failures with `hint`, the last one at `t0 + span`.
    fn fail_direct(s: &mut Selector, n: u32, hint: InternetStatus, t0: Instant, span: Duration) {
        for i in 0..n {
            let at = if i + 1 == n { t0 + span } else { t0 + span * i / n.max(1) };
            s.record_direct(DirectOutcome::ConnectFailure, hint, at);
        }
    }

    #[test]
    fn client_is_send_sync_and_starts_without_network() {
        fn check<T: Send + Sync>() {}
        check::<HttpClient>();
        let c = HttpClient::with_initial("PredatorTest/1.0", AUTO_DIRECT);
        assert_eq!(format!("{c:?}"), "HttpClient { .. }");
        assert_eq!(c.transport_name(), TRANSPORT_DIRECT);
        assert!(lock(&c.winhttp).is_none(), "no WinHTTP session on the direct path");
        c.interrupt(); // nothing in flight: harmless
        let forced = HttpClient::with_initial(
            "PredatorTest/1.0",
            Initial { start: Start::WinHttp(ProxyMode::Default), forced: true, reason: "test" },
        );
        assert_eq!(forced.transport_name(), TRANSPORT_WINHTTP);
    }

    #[test]
    fn invalid_target_is_neutral_and_never_echoed() {
        let c = HttpClient::with_initial("PredatorTest/1.0", AUTO_DIRECT);
        for when in [Interruptible::Always, Interruptible::UntilSent] {
            for _ in 0..5 {
                let e = c
                    .post_json_with("api.telegram.org", "/bot123:SECRET x/getMe", b"{}", Duration::from_secs(1), when)
                    .unwrap_err();
                assert!(!e.to_string().contains("SECRET"), "{e}");
            }
        }
        assert_eq!(c.transport_name(), TRANSPORT_DIRECT, "local errors never switch the backend");
        assert_eq!(lock(&c.selector).failures, 0);
    }

    #[test]
    fn a_failed_trial_closes_its_session_but_never_the_one_in_use() {
        // WinHttpOpen only (no network): the session a trial opened is closed again, so a direct
        // client keeps no WinHTTP session (and its worker threads) after a failed trial.
        let c = HttpClient::with_initial("PredatorTest/1.0", AUTO_DIRECT);
        c.winhttp_client(ProxyMode::Automatic).expect("WinHttpOpen");
        c.handle(Event::TrialFailed { next_after: 6 });
        assert!(lock(&c.winhttp).is_none());
        c.winhttp_client(ProxyMode::Automatic).expect("WinHttpOpen");
        c.handle(Event::TrialNotNeeded);
        assert!(lock(&c.winhttp).is_none());
        // on WinHTTP (default proxy): its own session stays, a trial's session goes
        let w = HttpClient::with_initial(
            "PredatorTest/1.0",
            Initial { start: Start::WinHttp(ProxyMode::Default), forced: false, reason: "test" },
        );
        w.winhttp_client(ProxyMode::Default).expect("WinHttpOpen");
        w.handle(Event::TrialFailed { next_after: 6 });
        assert!(matches!(lock(&w.winhttp).as_ref(), Some((ProxyMode::Default, _))));
        w.winhttp_client(ProxyMode::Automatic).expect("WinHttpOpen");
        w.handle(Event::TrialFailed { next_after: 6 });
        assert!(lock(&w.winhttp).is_none());
    }

    #[test]
    fn connect_failures_lead_to_a_trial_never_to_a_blind_switch() {
        // An outage while Windows still says "connected": the trial fails too, direct stays.
        let t0 = Instant::now();
        let mut s = sel();
        fail_direct(&mut s, TRIAL_FIRST, C, t0, MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        assert_eq!(s.name(), TRANSPORT_DIRECT, "no switch before the trial has shown anything");
        assert_eq!(s.record_trial(WinOutcome::NetworkFailure), Event::TrialFailed { next_after: 6 });
        assert_eq!(s.route(), Route::Direct);
        assert_eq!(s.name(), TRANSPORT_DIRECT);
        // ... and many more failures only bring more (spaced) trials, never a switch
        let mut trials = 0;
        for i in 0..200u32 {
            s.record_direct(DirectOutcome::ConnectFailure, C, t0 + MIN + Duration::from_secs(u64::from(i)));
            if let Route::Trial(_) = s.route() {
                trials += 1;
                s.record_trial(WinOutcome::NetworkFailure);
            }
        }
        assert_eq!(s.name(), TRANSPORT_DIRECT);
        assert!((4..=6).contains(&trials), "{trials} trials in 200 failures");
        // back online: everything resets
        s.record_direct(DirectOutcome::Success, C, t0);
        assert_eq!((s.failures, s.trial_threshold, s.streak_since), (0, TRIAL_FIRST, None));
    }

    #[test]
    fn a_trial_that_reaches_the_server_switches_for_good() {
        let t0 = Instant::now();
        let mut s = sel();
        fail_direct(&mut s, TRIAL_FIRST, InternetStatus::LocalOnly, t0, MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        assert_eq!(s.record_trial(WinOutcome::Success), Event::Switched { from: Backend::Direct });
        assert_eq!(s.route(), Route::WinHttp(ProxyMode::Automatic));
        assert_eq!(s.name(), TRANSPORT_WINHTTP_AUTO);
        // sticky: late direct results and WinHTTP failures change nothing, no more trials
        s.record_direct(DirectOutcome::Success, C, t0);
        for i in 0..100u64 {
            s.record_winhttp(ProxyMode::Automatic, WinOutcome::NetworkFailure, C, t0 + Duration::from_secs(i * 10));
            assert_eq!(s.route(), Route::WinHttp(ProxyMode::Automatic));
        }
    }

    #[test]
    fn short_blips_do_not_trigger_a_trial() {
        let t0 = Instant::now();
        let mut s = sel();
        // many fast failures within the first minute: no trial yet
        for i in 0..20u64 {
            s.record_direct(DirectOutcome::ConnectFailure, C, t0 + Duration::from_secs(i * 2));
            assert_eq!(s.route(), Route::Direct, "failure {i}");
        }
        // the streak reaches the minimum span: the next request is the trial
        s.record_direct(DirectOutcome::ConnectFailure, C, t0 + MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        // a blip that ends before the span: the streak starts over
        let mut s = sel();
        fail_direct(&mut s, 5, C, t0, Duration::from_secs(30));
        s.record_direct(DirectOutcome::ServerReached, C, t0 + Duration::from_secs(31));
        fail_direct(&mut s, 5, C, t0 + Duration::from_secs(40), Duration::from_secs(50));
        assert_eq!(s.route(), Route::Direct);
    }

    #[test]
    fn success_or_server_reached_resets_the_count() {
        let t0 = Instant::now();
        for reset in [DirectOutcome::Success, DirectOutcome::ServerReached] {
            let mut s = sel();
            fail_direct(&mut s, 2, C, t0, MIN);
            s.record_direct(reset, C, t0 + MIN);
            fail_direct(&mut s, 2, C, t0 + MIN, MIN * 2);
            assert_eq!(s.route(), Route::Direct, "{reset:?}");
        }
        // neutral outcomes (cancelled, invalid input) neither count nor reset
        let mut s = sel();
        s.record_direct(DirectOutcome::ConnectFailure, C, t0);
        s.record_direct(DirectOutcome::Neutral, C, t0);
        s.record_direct(DirectOutcome::ConnectFailure, C, t0);
        s.record_direct(DirectOutcome::ConnectFailure, C, t0 + MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
    }

    #[test]
    fn disconnected_failures_do_not_count() {
        let t0 = Instant::now();
        let mut s = sel();
        for i in 0..100u64 {
            s.record_direct(DirectOutcome::ConnectFailure, InternetStatus::Disconnected, t0 + Duration::from_secs(i));
            assert_eq!(s.route(), Route::Direct);
        }
        assert_eq!(s.failures, 0);
    }

    #[test]
    fn forced_direct_never_tries_winhttp() {
        let t0 = Instant::now();
        let mut s = Selector::new(Initial { start: Start::Direct, forced: true, reason: "test" });
        for hint in [C, InternetStatus::LocalOnly, InternetStatus::Unknown] {
            for i in 0..100u64 {
                s.record_direct(DirectOutcome::ConnectFailure, hint, t0 + Duration::from_secs(i * 10));
                assert_eq!(s.route(), Route::Direct);
            }
        }
    }

    #[test]
    fn one_trial_at_a_time() {
        let t0 = Instant::now();
        let mut s = sel();
        fail_direct(&mut s, TRIAL_FIRST, InternetStatus::CaptivePortal, t0, MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        assert_eq!(s.route(), Route::Direct, "only one trial at a time");
        // concurrent direct failures while the trial runs do not queue another one
        fail_direct(&mut s, 10, InternetStatus::Unknown, t0 + MIN, MIN);
        assert_eq!(s.route(), Route::Direct);
        assert_eq!(s.record_trial(WinOutcome::NetworkFailure), Event::TrialFailed { next_after: 6 });
        assert_eq!(s.failures, 0, "the gap is counted from the end of the trial");
        for i in 0..5u64 {
            s.record_direct(DirectOutcome::ConnectFailure, C, t0 + MIN * 3 + Duration::from_secs(i));
            assert_eq!(s.route(), Route::Direct);
        }
        s.record_direct(DirectOutcome::ConnectFailure, C, t0 + MIN * 4);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
    }

    #[test]
    fn trial_gap_doubles_up_to_the_cap() {
        let t0 = Instant::now();
        let mut s = sel();
        let mut gaps = Vec::new();
        let mut clock = 0u64;
        for _ in 0..8 {
            let mut n = 0;
            loop {
                n += 1;
                clock += 30;
                s.record_direct(
                    DirectOutcome::ConnectFailure,
                    InternetStatus::LocalOnly,
                    t0 + Duration::from_secs(clock),
                );
                if let Route::Trial(_) = s.route() {
                    break;
                }
                assert!(n < 1000);
            }
            gaps.push(n);
            s.record_trial(WinOutcome::NetworkFailure);
        }
        // the first trial waits for the minimum span (30 s apart: 3 failures, then 60 s)
        assert_eq!(gaps, vec![3, 6, 12, 24, 48, 48, 48, 48]);
        // an inconclusive trial (WinHTTP unusable locally) backs off as well, and so does a
        // trial whose success cannot be used (nothing to switch to)
        let mut s = sel();
        fail_direct(&mut s, TRIAL_FIRST, InternetStatus::Unknown, t0, MIN);
        assert!(matches!(s.route(), Route::Trial(_)));
        assert_eq!(s.record_trial(WinOutcome::Neutral), Event::TrialFailed { next_after: 6 });
        let mut f = Selector::new(Initial { start: Start::Direct, forced: true, reason: "t" });
        assert_eq!(f.record_trial(WinOutcome::Success), Event::TrialFailed { next_after: 6 });
        assert_eq!(f.name(), TRANSPORT_DIRECT, "forced direct never switches");
    }

    #[test]
    fn a_trial_overtaken_by_a_direct_success_does_not_switch() {
        // The network came back while the (slow, WPAD) trial ran: both succeed, direct stays.
        let t0 = Instant::now();
        let mut s = sel();
        fail_direct(&mut s, TRIAL_FIRST, C, t0, MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        s.record_direct(DirectOutcome::Success, C, t0 + MIN);
        assert_eq!(s.record_trial(WinOutcome::Success), Event::TrialNotNeeded);
        assert_eq!(s.name(), TRANSPORT_DIRECT);
        assert_eq!(s.route(), Route::Direct);
        // the flag does not leak into the next trial
        fail_direct(&mut s, TRIAL_FIRST, C, t0 + MIN * 2, MIN);
        assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
        assert_eq!(s.record_trial(WinOutcome::Success), Event::Switched { from: Backend::Direct });
    }

    #[test]
    fn winhttp_default_proxy_moves_to_automatic_only_when_shown_to_work() {
        let t0 = Instant::now();
        let d = ProxyMode::Default;
        for forced in [false, true] {
            let mut s = Selector::new(Initial { start: Start::WinHttp(d), forced, reason: "t" });
            assert_eq!(s.route(), Route::WinHttp(d));
            // successes reset, neutral and disconnected results do not count
            s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0);
            s.record_winhttp(d, WinOutcome::Success, C, t0);
            s.record_winhttp(d, WinOutcome::NetworkFailure, InternetStatus::Disconnected, t0);
            s.record_winhttp(d, WinOutcome::Neutral, C, t0);
            s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0);
            s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0 + Duration::from_secs(1));
            assert_eq!(s.route(), Route::WinHttp(d));
            s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0 + MIN);
            assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic), "forced={forced}");
            // the outage case: automatic fails too, default stays
            assert_eq!(s.record_trial(WinOutcome::NetworkFailure), Event::TrialFailed { next_after: 6 });
            assert_eq!(s.route(), Route::WinHttp(d));
            for i in 0..6u64 {
                s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0 + MIN * 2 + Duration::from_secs(i));
            }
            assert_eq!(s.route(), Route::Trial(ProxyMode::Automatic));
            assert_eq!(s.record_trial(WinOutcome::Success), Event::Switched { from: Backend::WinHttp(d) });
            assert_eq!(s.route(), Route::WinHttp(ProxyMode::Automatic));
            assert_eq!(s.name(), TRANSPORT_WINHTTP_AUTO);
            // automatic is the last step; late results of the old mode are ignored
            for i in 0..50u64 {
                s.record_winhttp(d, WinOutcome::NetworkFailure, C, t0 + MIN * 3 + Duration::from_secs(i * 60));
                s.record_winhttp(
                    ProxyMode::Automatic,
                    WinOutcome::NetworkFailure,
                    C,
                    t0 + MIN * 3 + Duration::from_secs(i * 60),
                );
                assert_eq!(s.route(), Route::WinHttp(ProxyMode::Automatic));
            }
        }
    }

    #[test]
    fn outcome_classification() {
        let err = |phase| Err(DirectError::new(phase, HttpError::Other("x".into())));
        assert_eq!(DirectOutcome::of(&Ok(HttpResponse { status: 401, body: vec![] })), DirectOutcome::Success);
        for p in [Phase::Resolve, Phase::Connect, Phase::Tls] {
            assert_eq!(DirectOutcome::of(&err(p)), DirectOutcome::ConnectFailure, "{p:?}");
        }
        assert_eq!(DirectOutcome::of(&err(Phase::Exchange)), DirectOutcome::ServerReached);
        assert_eq!(DirectOutcome::of(&err(Phase::Cancelled)), DirectOutcome::Neutral);
        assert_eq!(DirectOutcome::of(&err(Phase::Local)), DirectOutcome::Neutral);
        assert_eq!(WinOutcome::of(&Err(HttpError::Timeout)), WinOutcome::NetworkFailure);
        assert_eq!(
            WinOutcome::of(&Err(HttpError::Network { code: 12029, message: "x".into() })),
            WinOutcome::NetworkFailure
        );
        assert_eq!(WinOutcome::of(&Err(HttpError::Other("x".into()))), WinOutcome::Neutral);
    }

    #[test]
    fn error_display() {
        let w = HttpError::Network { code: 12007, message: "name not resolved".into() };
        assert_eq!(w.to_string(), "name not resolved (WinHTTP error 12007)");
        let s = HttpError::Network { code: 10061, message: "refused".into() };
        assert_eq!(s.to_string(), "refused (error 10061)");
        let h = HttpError::Network { code: 0x800B_0101, message: "expired".into() };
        assert_eq!(h.to_string(), "expired (error 0x800B0101)");
        assert_eq!(HttpError::Timeout.to_string(), "request timed out");
    }

    #[test]
    fn io_errors_use_only_code_or_kind() {
        let e = io_error("cannot connect to the server", &io::Error::from_raw_os_error(10061));
        let HttpError::Network { code, message } = &e else { panic!("{e:?}") };
        assert_eq!(*code, 10061);
        assert!(message.starts_with("cannot connect to the server: ") && message.len() > 32, "{message}");
        assert!(!message.ends_with('.') && !message.contains('\n'));
        let cert = io_error("server certificate rejected", &io::Error::from_raw_os_error(0x800B_0101u32 as i32));
        assert!(cert.to_string().contains("0x800B0101"), "{cert}");
        // a custom message (which could contain anything) is never used
        let custom = io_error("x", &io::Error::new(io::ErrorKind::TimedOut, "secret /bot123:abc/getMe"));
        assert_eq!(custom, HttpError::Other("x: timed out".into()));
        assert_eq!(clean_message("Line one.\r\nLine two.\r\n"), "Line one. Line two");
    }
}
