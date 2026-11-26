//! Pure tray logic (no Win32 calls): status snapshot → tooltip text, icon choice, context-menu
//! model, menu-id ↔ action mapping, status report text, the pairing and Telegram-user dialogs
//! and IPC reply classification.
//!
//! Everything in here is deterministic and unit-tested; `ui.rs` only turns these values into
//! Win32 calls.

use std::ffi::OsStr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SUCCESS};
use windows_sys::Win32::System::Services::{
    SERVICE_CONTINUE_PENDING, SERVICE_NOTIFY, SERVICE_NOTIFY_CONTINUE_PENDING, SERVICE_NOTIFY_DELETE_PENDING,
    SERVICE_NOTIFY_PAUSE_PENDING, SERVICE_NOTIFY_PAUSED, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING,
    SERVICE_NOTIFY_STOP_PENDING, SERVICE_NOTIFY_STOPPED, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED,
};
use windows_sys::Win32::UI::Shell::{NIN_SELECT, NINF_KEY};
use windows_sys::Win32::UI::WindowsAndMessaging::WM_CONTEXTMENU;

use crate::features::Feature;
use crate::ipc::{IpcRequest, IpcResponse, ServiceStatusInfo};
use crate::sys::ServiceState;
use crate::util::time::fmt_duration;

/// Window title, tooltip first line and dialog caption.
pub const APP_TITLE: &str = crate::PRODUCT_NAME;
/// `NOTIFYICONDATAW::szTip` holds 128 UTF-16 units including the terminating NUL.
pub const TOOLTIP_MAX_UNITS: usize = 127;
/// Keyboard activation of the icon (`NIN_SELECT | NINF_KEY`; not exported by windows-sys).
pub const NIN_KEYSELECT: u32 = NIN_SELECT | NINF_KEY;
/// Tray clicks arriving this soon after a menu closed are the click that dismissed it (or the
/// shell's duplicate keyboard notification) and must not reopen the menu.
pub const MENU_REOPEN_GUARD: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------------------------
// Snapshot of the service state
// ---------------------------------------------------------------------------------------------

/// What the tray knows about the service after a refresh.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    /// SCM state of the Predator service.
    pub service: ServiceState,
    /// PID reported by the SCM (0 when not running).
    pub pid: u32,
    /// Status reported by the service over IPC (only when running and it answered).
    pub status: Option<ServiceStatusInfo>,
    /// Why `status` is missing although the service is running.
    pub status_error: Option<String>,
    /// SCM state of the `Tailscale` service (`Unknown` = not queried or the query failed).
    pub tailscale_service: ServiceState,
}

/// The service answered `Denied`: this user is not the configured owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessDenied;

/// Result of an `IpcRequest::Status` round trip.
// Short-lived value moved once per refresh; boxing would only add an allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum StatusFetch {
    Info(ServiceStatusInfo),
    Denied,
    Unavailable(String),
}

impl Snapshot {
    /// Combine the SCM state with the (optional) IPC status reply.
    /// `fetch` is ignored unless the service is running.
    pub fn from_parts(service: ServiceState, pid: u32, fetch: Option<StatusFetch>) -> Result<Snapshot, AccessDenied> {
        let mut snap = Snapshot { service, pid, ..Snapshot::default() };
        if snap.running() {
            match fetch {
                Some(StatusFetch::Info(info)) => snap.status = Some(info),
                Some(StatusFetch::Denied) => return Err(AccessDenied),
                Some(StatusFetch::Unavailable(e)) => snap.status_error = Some(e),
                None => snap.status_error = Some("The service status was not queried.".into()),
            }
        }
        Ok(snap)
    }

    pub fn running(&self) -> bool {
        self.service == ServiceState::Running
    }

    /// Running and answered the status request: feature toggles are usable.
    pub fn online(&self) -> bool {
        self.running() && self.status.is_some()
    }

    /// The service reports that no Telegram account is paired yet (the next one becomes an
    /// Admin). False while unknown.
    pub fn no_telegram_user(&self) -> bool {
        self.status.as_ref().is_some_and(|i| !i.owner_configured)
    }

    /// Feature state as reported by the service (None = unknown).
    pub fn feature(&self, f: Feature) -> Option<bool> {
        self.status.as_ref().and_then(|s| feature_enabled(s, f))
    }

    /// The service answered and reports its Telegram connection as `offline` (not connected yet
    /// or the network is down; not "invalid token" / "not configured", which do not heal alone).
    pub fn telegram_offline(&self) -> bool {
        self.status.as_ref().is_some_and(|i| one_line(&i.telegram).eq_ignore_ascii_case("offline"))
    }

    /// Attach the SCM state of the `Tailscale` service.
    pub fn with_tailscale_service(mut self, state: ServiceState) -> Snapshot {
        self.tailscale_service = state;
        self
    }

    /// False when the service reports Tailscale Management as disabled: like the service (which
    /// refuses Tailscale requests then), the tray neither queries nor shows the Tailscale state.
    /// True while the feature state is unknown (service stopped / not answering).
    pub fn tailscale_wanted(&self) -> bool {
        self.feature(Feature::TailscaleManagement) != Some(false)
    }

    /// The "Service Status" dialog may ask the service for a live `TailscaleStatus` (which runs
    /// the Tailscale CLI): only when the service answers, the feature is on and Tailscale is
    /// installed. Never used by the periodic refresh.
    pub fn live_tailscale_query(&self) -> bool {
        self.online() && self.tailscale_wanted() && self.tailscale_service != ServiceState::NotInstalled
    }

    /// Value of the "Tailscale:" line (tooltip and dialog fallback), from the cheap SCM query
    /// plus the service's cached connection summary.
    pub fn tailscale_line(&self) -> String {
        if !self.tailscale_wanted() {
            return "management disabled".into();
        }
        let cached = self.status.as_ref().and_then(|i| i.tailscale.as_deref());
        tailscale_line(&self.tailscale_service, cached)
    }
}

/// `service running · Connected · 100.64.0.5`, `service stopped`, `not installed`, `unknown` …
///
/// `svc` is the live SCM state of the `Tailscale` service; `cached` is the service's last known
/// connection summary (passive cache, possibly old). The live SCM state always wins: the cached
/// summary is only added while the service runs, and only when it describes the connection —
/// summaries that describe the service or the installation (e.g. `Disconnected (service
/// stopped)`, `Not installed`) were taken in another service state and are dropped. When the
/// SCM query failed, the cached summary is the best information available.
pub fn tailscale_line(svc: &ServiceState, cached: Option<&str>) -> String {
    let cached = cached.map(one_line).filter(|c| !c.is_empty());
    match svc {
        ServiceState::NotInstalled => "not installed".into(),
        ServiceState::Running => match cached.filter(|c| is_connection_summary(c)) {
            Some(c) => format!("service running · {c}"),
            None => "service running".into(),
        },
        ServiceState::Unknown => cached.unwrap_or_else(|| "unknown".into()),
        other => format!("service {}", other.label().to_lowercase()),
    }
}

/// True for a cached summary that is about the Tailscale connection, not about its service or
/// installation (which the live SCM state supersedes).
fn is_connection_summary(summary: &str) -> bool {
    let s = summary.to_lowercase();
    !s.contains("service") && !s.contains("not installed")
}

/// Look a feature up in the service's feature list by key.
pub fn feature_enabled(info: &ServiceStatusInfo, f: Feature) -> Option<bool> {
    info.features.iter().find(|fs| Feature::from_key(&fs.key) == Some(f)).map(|fs| fs.enabled)
}

/// Classify the reply to `IpcRequest::Status`.
pub fn classify_status(resp: Result<IpcResponse, String>) -> StatusFetch {
    match resp {
        Ok(IpcResponse::Status(info)) => StatusFetch::Info(info),
        Ok(IpcResponse::Denied { .. }) => StatusFetch::Denied,
        Ok(IpcResponse::Error { message }) => StatusFetch::Unavailable(message),
        Ok(_) => StatusFetch::Unavailable("Unexpected reply from the service.".into()),
        Err(e) => StatusFetch::Unavailable(e),
    }
}

/// Outcome of a state-changing request (`SetFeature`, `RestartService`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    Done,
    Denied,
    Failed(String),
}

pub fn classify_action(resp: Result<IpcResponse, String>) -> ActionOutcome {
    match resp {
        Ok(IpcResponse::Ok { .. }) | Ok(IpcResponse::Status(_)) => ActionOutcome::Done,
        Ok(IpcResponse::Denied { .. }) => ActionOutcome::Denied,
        Ok(IpcResponse::Error { message }) => {
            ActionOutcome::Failed(non_empty_or(message, "The service reported an error."))
        }
        Ok(_) => ActionOutcome::Failed("Unexpected reply from the service.".into()),
        Err(e) => ActionOutcome::Failed(non_empty_or(e, "The service did not answer.")),
    }
}

/// Result of the (user-initiated) live `IpcRequest::TailscaleStatus` query of the status dialog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TailscaleLive {
    /// One-line summary from the service, e.g. `Connected · 100.64.0.5`.
    Summary(String),
    /// The query failed (reason); the dialog falls back to the SCM-based line.
    Unavailable(String),
}

/// Classify the reply to `IpcRequest::TailscaleStatus`.
pub fn classify_tailscale(resp: Result<IpcResponse, String>) -> Result<TailscaleLive, AccessDenied> {
    match resp {
        Ok(IpcResponse::Tailscale { summary, .. }) => {
            Ok(TailscaleLive::Summary(non_empty_or(one_line(&summary), "unknown")))
        }
        Ok(IpcResponse::Denied { .. }) => Err(AccessDenied),
        Ok(IpcResponse::Error { message }) => {
            Ok(TailscaleLive::Unavailable(non_empty_or(one_line(&message), "the service reported an error")))
        }
        Ok(_) => Ok(TailscaleLive::Unavailable("unexpected reply from the service".into())),
        Err(e) => Ok(TailscaleLive::Unavailable(non_empty_or(one_line(&e), "the service did not answer"))),
    }
}

/// `SetFeature` request that flips `f` from the state the user saw (`current`).
pub fn set_feature_request(f: Feature, current: bool) -> IpcRequest {
    IpcRequest::SetFeature { feature: f.key().to_string(), enabled: !current }
}

// ---------------------------------------------------------------------------------------------
// Pairing a Telegram account / the list of accounts
// ---------------------------------------------------------------------------------------------

/// Lifetime of a pairing code created from the tray.
pub const PAIRING_TTL_SECS: u64 = 600;
/// While a code from the tray is active, the service is asked this often whether it was used
/// (only then; no timer runs otherwise).
pub const PAIRING_CHECK: Duration = Duration::from_secs(5);
/// After the expiry, a service that does not answer is given this long before the tray stops
/// asking.
pub const PAIRING_GRACE_SECS: i64 = 30;

/// "Pair Telegram User…": a code for a User-role account (the first account of an empty list
/// becomes an Admin anyway; Admin codes are created in the setup menu or with the CLI).
pub fn start_pairing_request() -> IpcRequest {
    IpcRequest::StartPairing { ttl_secs: PAIRING_TTL_SECS, admin: false }
}

/// A code the service created for the tray.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingStarted {
    pub code: String,
    pub expires_unix: i64,
    pub bot_username: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingStart {
    Started(PairingStarted),
    Denied,
    Failed(String),
}

/// Classify the reply to `StartPairing`.
pub fn classify_pairing_start(resp: Result<IpcResponse, String>) -> PairingStart {
    match resp {
        Ok(IpcResponse::Pairing { code, expires_unix, bot_username }) => match crate::pairing::normalize_code(&code) {
            Some(code) => PairingStart::Started(PairingStarted { code, expires_unix, bot_username }),
            None => PairingStart::Failed("The service returned an invalid pairing code.".into()),
        },
        Ok(IpcResponse::Denied { .. }) => PairingStart::Denied,
        Ok(IpcResponse::Error { message }) => {
            PairingStart::Failed(non_empty_or(one_line(&message), "The service reported an error."))
        }
        Ok(_) => PairingStart::Failed("Unexpected reply from the service (is it an older version?).".into()),
        Err(e) => PairingStart::Failed(non_empty_or(one_line(&e), "The service did not answer.")),
    }
}

/// Body of the pairing dialog. `fallback_bot` = the last bot username the tray saw; `until` =
/// the local expiry time; `first_account` = nobody is paired yet (that account becomes an Admin).
pub fn pairing_dialog_text(
    p: &PairingStarted,
    fallback_bot: Option<&str>,
    now: i64,
    until: &str,
    first_account: bool,
) -> String {
    let bot = p
        .bot_username
        .as_deref()
        .and_then(crate::ipc::bot_username)
        .or(fallback_bot.and_then(crate::ipc::bot_username));
    let minutes = (p.expires_unix.saturating_sub(now).max(0) + 59) / 60;
    let mut lines = vec![
        "Pair a Telegram account with this PC".to_string(),
        String::new(),
        format!("Pairing code:   {}", crate::ipc::spaced_code(&p.code)),
        format!("Valid for {minutes} min (until {}), once.", one_line(until)),
        String::new(),
        "On the phone with the Telegram account to add:".to_string(),
    ];
    match bot.and_then(|b| crate::ipc::pairing_deep_link(b, &p.code).map(|l| (b, l))) {
        Some((b, link)) => {
            lines.push(format!("•  open {link} and press Start, or"));
            lines.push(format!("•  send this message to @{b}:"));
        }
        None => lines.push("•  send this message to the bot:".to_string()),
    }
    lines.push(format!("        /pair {}", p.code));
    lines.push(String::new());
    lines.push(if first_account {
        "It is the first account, so it becomes an Admin (it can also remove accounts).".to_string()
    } else {
        "The account gets the role User. Admins can remove accounts in Telegram with /users.".to_string()
    });
    lines.push("Keep the code private: whoever sends it first gets access to this PC.".to_string());
    lines.push("A notification appears here when the account is paired. (Ctrl+C copies this text.)".to_string());
    lines.join("\n")
}

/// What the tray does after a `PairingStatus` reply for the code it created (expiring at `ours`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingCheck {
    KeepWaiting,
    Paired {
        name: String,
        id: i64,
    },
    Expired,
    /// Cancelled, invalidated after too many wrong guesses, or lost with a service restart.
    Invalidated,
    /// Stop asking without a notification (another code replaced ours, or the service stayed
    /// unreachable past the expiry).
    Stop,
    Denied,
}

pub fn classify_pairing_check(resp: Result<IpcResponse, String>, ours: i64, now: i64) -> PairingCheck {
    use crate::ipc::PairingProgress as P;
    let progress = match &resp {
        Ok(IpcResponse::Denied { .. }) => return PairingCheck::Denied,
        Ok(r) => crate::ipc::progress_of(r, ours, now),
        Err(_) => None,
    };
    match progress {
        Some(P::Waiting) => PairingCheck::KeepWaiting,
        Some(P::Paired { name, id }) => PairingCheck::Paired { name, id },
        Some(P::Expired) => PairingCheck::Expired,
        Some(P::Invalidated) => PairingCheck::Invalidated,
        Some(P::Replaced) => PairingCheck::Stop,
        // no usable answer (service restarting, busy …): keep asking until shortly after the expiry
        None if now >= ours.saturating_add(PAIRING_GRACE_SECS) => PairingCheck::Stop,
        None => PairingCheck::KeepWaiting,
    }
}

/// Notification kind of a tray balloon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonKind {
    Info,
    Warning,
}

/// The balloon for the end of a pairing (None = nothing to show).
pub fn pairing_balloon(c: &PairingCheck) -> Option<(String, String, BalloonKind)> {
    match c {
        PairingCheck::Paired { name, id } => Some((
            "Telegram account paired".into(),
            format!("Paired: {} (Telegram id {id}). It can use the bot now.", non_empty_or(one_line(name), "?")),
            BalloonKind::Info,
        )),
        PairingCheck::Expired => Some((
            "Pairing code expired".into(),
            format!("The code was not used. Choose \"{LABEL_PAIR_USER}\" to create a new one."),
            BalloonKind::Info,
        )),
        PairingCheck::Invalidated => Some((
            "Pairing code no longer valid".into(),
            "It was cancelled, invalidated after too many wrong attempts, or the service restarted.".into(),
            BalloonKind::Warning,
        )),
        PairingCheck::KeepWaiting | PairingCheck::Stop | PairingCheck::Denied => None,
    }
}

/// Reply to `ListUsers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsersFetch {
    Users(Vec<crate::ipc::UserInfo>),
    Denied,
    Failed(String),
}

pub fn classify_users(resp: Result<IpcResponse, String>) -> UsersFetch {
    match resp {
        Ok(IpcResponse::Users { users }) => UsersFetch::Users(users),
        Ok(IpcResponse::Denied { .. }) => UsersFetch::Denied,
        Ok(IpcResponse::Error { message }) => {
            UsersFetch::Failed(non_empty_or(one_line(&message), "The service reported an error."))
        }
        Ok(_) => UsersFetch::Failed("Unexpected reply from the service (is it an older version?).".into()),
        Err(e) => UsersFetch::Failed(non_empty_or(one_line(&e), "The service did not answer.")),
    }
}

/// Body of the "Telegram Users" dialog (`date` formats `added_unix` > 0).
pub fn users_report(users: &[crate::ipc::UserInfo], date: &dyn Fn(i64) -> String) -> String {
    let mut lines = Vec::new();
    if users.is_empty() {
        lines.push("No Telegram account is paired yet.".to_string());
        lines.push(String::new());
        lines.push(format!("Choose \"{LABEL_PAIR_USER}\" to add one (the first account becomes an Admin)."));
        return lines.join("\n");
    }
    lines.push(format!(
        "Telegram accounts that can use the bot ({} of {}):",
        users.len(),
        crate::config::MAX_AUTHORIZED_USERS
    ));
    lines.push(String::new());
    for u in users {
        let added = if u.added_unix > 0 { format!(" · added {}", date(u.added_unix)) } else { String::new() };
        lines.push(format!("{} · {} · id {}{added}", u.display_name(), u.role_label(), u.id));
    }
    lines.push(String::new());
    lines.push("Access is decided by the numeric Telegram id only; names are for display.".to_string());
    lines.push(
        "To remove an account, send /users to the bot from an Admin account, or use the setup menu \
         (run predator-service.exe as administrator)."
            .to_string(),
    );
    lines.join("\n")
}

// ---------------------------------------------------------------------------------------------
// Icon + tooltip
// ---------------------------------------------------------------------------------------------

/// Which tray icon to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconKind {
    /// Service running (resource id 1).
    Normal,
    /// Service stopped / not installed / unknown (resource id 2).
    Stopped,
}

impl IconKind {
    /// Icon resource ids to try, in order (the stopped variant falls back to the normal icon).
    pub fn resource_candidates(self) -> &'static [u16] {
        match self {
            IconKind::Normal => &[1],
            IconKind::Stopped => &[2, 1],
        }
    }
}

pub fn icon_kind(s: &Snapshot) -> IconKind {
    if s.running() { IconKind::Normal } else { IconKind::Stopped }
}

/// Tooltip, e.g. `Predator Remote Controller\nService: Running\nTelegram: online\nTailscale:
/// service running · Connected · 100.64.0.5`, limited to [`TOOLTIP_MAX_UNITS`] UTF-16 units.
/// The Tailscale line is always present (see [`Snapshot::tailscale_line`]).
pub fn tooltip_text(s: &Snapshot) -> String {
    let mut lines = vec![APP_TITLE.to_string()];
    match (&s.service, &s.status) {
        (ServiceState::Running, Some(info)) => {
            lines.push("Service: Running".into());
            lines.push(format!("Telegram: {}", non_empty_or(one_line(&info.telegram), "unknown")));
        }
        (ServiceState::Running, None) => lines.push("Service: Running (not responding)".into()),
        (state, _) => lines.push(format!("Service: {}", state.label())),
    }
    lines.push(format!("Tailscale: {}", s.tailscale_line()));
    truncate_utf16(&lines.join("\n"), TOOLTIP_MAX_UNITS)
}

/// Truncate `s` to at most `max_units` UTF-16 code units without splitting a surrogate pair,
/// ending with `…` when something was cut.
pub fn truncate_utf16(s: &str, max_units: usize) -> String {
    if s.encode_utf16().count() <= max_units {
        return s.to_string();
    }
    let budget = max_units.saturating_sub(1); // room for the ellipsis
    let mut used = 0usize;
    let mut out = String::new();
    for ch in s.chars() {
        let n = ch.len_utf16();
        if used + n > budget {
            break;
        }
        used += n;
        out.push(ch);
    }
    if max_units > 0 {
        out.push('…');
    }
    out
}

/// Copy `s` into a fixed UTF-16 buffer (e.g. `szTip`), truncated to fit and NUL-terminated.
pub fn fill_wide(dst: &mut [u16], s: &str) {
    let Some(capacity) = dst.len().checked_sub(1) else { return };
    let text = truncate_utf16(s, capacity);
    let mut n = 0usize;
    for (slot, unit) in dst.iter_mut().zip(text.encode_utf16()) {
        *slot = unit;
        n += 1;
    }
    for slot in &mut dst[n..] {
        *slot = 0;
    }
}

// ---------------------------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------------------------

pub const ID_OPEN_DASHBOARD: u32 = 1;
pub const ID_SERVICE_STATUS: u32 = 2;
pub const ID_RESTART_SERVICE: u32 = 3;
pub const ID_START_SERVICE: u32 = 4;
pub const ID_EXIT: u32 = 5;
pub const ID_PAIR_USER: u32 = 6;
pub const ID_TELEGRAM_USERS: u32 = 7;
/// Quick toggles: base + `Feature::index()`.
pub const ID_QUICK_TOGGLE_BASE: u32 = 100;
/// "Feature Settings" submenu: base + `Feature::index()`.
pub const ID_FEATURE_SETTINGS_BASE: u32 = 200;

// The tray menu labels, plus the extra "Start Service (admin)…" item that is
// only shown while the service is not running.
pub const LABEL_OPEN_DASHBOARD: &str = "Open Dashboard";
pub const LABEL_SERVICE_STATUS: &str = "Service Status";
pub const LABEL_FEATURE_SETTINGS: &str = "Feature Settings";
pub const LABEL_RESTART_SERVICE: &str = "Restart Service";
pub const LABEL_START_SERVICE: &str = "Start Service (admin)…";
pub const LABEL_EXIT: &str = "Exit Tray Application";
/// Multi-user items (enabled while the service answers).
pub const LABEL_PAIR_USER: &str = "Pair Telegram User…";
pub const LABEL_TELEGRAM_USERS: &str = "Telegram Users…";

/// The quick toggles shown directly in the context menu, with the feature name used in their
/// "Enable …" / "Disable …" label (see [`toggle_label`]).
pub const QUICK_TOGGLES: [(Feature, &str); 5] = [
    (Feature::LoginMonitoring, "Login Monitoring"),
    (Feature::SshMonitoring, "SSH Monitoring"),
    (Feature::LoginNotifications, "Notifications"),
    (Feature::PowerManagement, "Power Management"),
    (Feature::TailscaleManagement, "Tailscale"),
];

/// What a menu command does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuAction {
    OpenDashboard,
    ServiceStatus,
    PairUser,
    TelegramUsers,
    ToggleFeature(Feature),
    RestartService,
    StartService,
    Exit,
}

impl MenuAction {
    /// Map a command id returned by `TrackPopupMenuEx` (0 = cancelled → None).
    pub fn from_id(id: u32) -> Option<MenuAction> {
        match id {
            ID_OPEN_DASHBOARD => Some(MenuAction::OpenDashboard),
            ID_SERVICE_STATUS => Some(MenuAction::ServiceStatus),
            ID_PAIR_USER => Some(MenuAction::PairUser),
            ID_TELEGRAM_USERS => Some(MenuAction::TelegramUsers),
            ID_RESTART_SERVICE => Some(MenuAction::RestartService),
            ID_START_SERVICE => Some(MenuAction::StartService),
            ID_EXIT => Some(MenuAction::Exit),
            _ => [ID_QUICK_TOGGLE_BASE, ID_FEATURE_SETTINGS_BASE]
                .iter()
                .find_map(|base| id.checked_sub(*base).and_then(|i| Feature::from_index(i as usize)))
                .map(MenuAction::ToggleFeature),
        }
    }
}

pub fn quick_toggle_id(f: Feature) -> u32 {
    ID_QUICK_TOGGLE_BASE + f.index() as u32
}

pub fn feature_settings_id(f: Feature) -> u32 {
    ID_FEATURE_SETTINGS_BASE + f.index() as u32
}

/// One entry of the context menu model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MenuEntry {
    Item { id: u32, label: String, enabled: bool, checked: bool },
    Separator,
    Submenu { label: String, enabled: bool, items: Vec<MenuEntry> },
}

fn item(id: u32, label: &str, enabled: bool, checked: bool) -> MenuEntry {
    MenuEntry::Item { id, label: label.to_string(), enabled, checked }
}

/// Feature state usable for a toggle: only while the service answers (None = unknown).
fn toggle_state(s: &Snapshot, f: Feature) -> Option<bool> {
    if s.online() { s.feature(f) } else { None }
}

/// Quick-toggle label ("Enable/Disable X"): `Disable X` while enabled,
/// `Enable X` while disabled — i.e. what clicking it does — and the literal `Enable/Disable X`
/// while the state is unknown (the item is greyed then).
pub fn toggle_label(name: &str, state: Option<bool>) -> String {
    match state {
        Some(true) => format!("Disable {name}"),
        Some(false) => format!("Enable {name}"),
        None => format!("Enable/Disable {name}"),
    }
}

/// Build the context menu for a snapshot. `bot_username` is the last known bot username.
///
/// Quick toggles are labelled with the action they perform and carry a check mark showing the
/// current state; the "Feature Settings" submenu lists all features by name with check marks.
/// "Pair Telegram User…" and "Telegram Users…" need the service to answer.
pub fn build_menu(s: &Snapshot, bot_username: Option<&str>) -> Vec<MenuEntry> {
    let dashboard = bot_username.and_then(dashboard_url).is_some();
    let mut menu = vec![
        item(ID_OPEN_DASHBOARD, LABEL_OPEN_DASHBOARD, dashboard, false),
        item(ID_SERVICE_STATUS, LABEL_SERVICE_STATUS, true, false),
        item(ID_PAIR_USER, LABEL_PAIR_USER, s.online(), false),
        item(ID_TELEGRAM_USERS, LABEL_TELEGRAM_USERS, s.online(), false),
        MenuEntry::Separator,
    ];
    for (f, name) in QUICK_TOGGLES {
        let state = toggle_state(s, f);
        menu.push(item(quick_toggle_id(f), &toggle_label(name, state), state.is_some(), state == Some(true)));
    }
    menu.push(MenuEntry::Submenu {
        label: LABEL_FEATURE_SETTINGS.to_string(),
        enabled: s.online(),
        items: Feature::ALL
            .iter()
            .map(|&f| {
                let state = toggle_state(s, f);
                item(feature_settings_id(f), f.label(), state.is_some(), state == Some(true))
            })
            .collect(),
    });
    menu.push(MenuEntry::Separator);
    if let Some(start) = start_service_item(&s.service) {
        menu.push(start);
    }
    menu.push(item(ID_RESTART_SERVICE, LABEL_RESTART_SERVICE, s.running(), false));
    menu.push(item(ID_EXIT, LABEL_EXIT, true, false));
    menu
}

/// "Start Service (admin)…" while the service is not running (greyed when it is not installed);
/// absent while it runs or changes state. "Restart Service" is always listed (greyed unless the
/// service runs), so the menu always shows every item.
fn start_service_item(state: &ServiceState) -> Option<MenuEntry> {
    match state {
        ServiceState::Running | ServiceState::StartPending | ServiceState::StopPending => None,
        ServiceState::NotInstalled => Some(item(ID_START_SERVICE, LABEL_START_SERVICE, false, false)),
        ServiceState::Stopped | ServiceState::Paused | ServiceState::Unknown => {
            Some(item(ID_START_SERVICE, LABEL_START_SERVICE, true, false))
        }
    }
}

/// Menu text is parsed for `&` mnemonics; show a literal ampersand instead.
pub fn escape_menu_label(label: &str) -> String {
    label.replace('&', "&&")
}

/// `https://t.me/<bot>` for a syntactically valid bot username (letters, digits, `_`).
pub fn dashboard_url(username: &str) -> Option<String> {
    let u = username.trim().trim_start_matches('@');
    let valid = !u.is_empty() && u.len() <= 64 && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    valid.then(|| format!("https://t.me/{u}"))
}

// ---------------------------------------------------------------------------------------------
// Tray callback decoding (NOTIFYICON_VERSION_4)
// ---------------------------------------------------------------------------------------------

/// `(event, icon id)` = `(LOWORD(lParam), HIWORD(lParam))`.
pub fn split_tray_lparam(lparam: isize) -> (u32, u32) {
    let v = lparam as usize;
    ((v & 0xFFFF) as u32, ((v >> 16) & 0xFFFF) as u32)
}

/// Anchor point `(GET_X_LPARAM(wParam), GET_Y_LPARAM(wParam))` in screen coordinates (signed).
pub fn anchor_from_wparam(wparam: usize) -> (i32, i32) {
    let x = (wparam & 0xFFFF) as u16 as i16 as i32;
    let y = ((wparam >> 16) & 0xFFFF) as u16 as i16 as i32;
    (x, y)
}

/// Right click / context-menu key, left click, Enter/Space on the focused icon open the menu.
/// (`WM_LBUTTONUP` is ignored: version 4 sends `NIN_SELECT` right after it.)
pub fn opens_menu(event: u32) -> bool {
    matches!(event, WM_CONTEXTMENU | NIN_SELECT | NIN_KEYSELECT)
}

/// False while `since_last_close` is inside [`MENU_REOPEN_GUARD`].
pub fn menu_allowed(since_last_close: Option<Duration>) -> bool {
    since_last_close.is_none_or(|d| d >= MENU_REOPEN_GUARD)
}

// ---------------------------------------------------------------------------------------------
// `--lock` helper
// ---------------------------------------------------------------------------------------------

/// True when the first command-line argument (after the program name) is `--lock`.
pub fn is_lock_invocation<S: AsRef<OsStr>>(args: &[S]) -> bool {
    args.first().and_then(|a| a.as_ref().to_str()).is_some_and(|a| a.eq_ignore_ascii_case("--lock"))
}

/// Process exit code of the `--lock` helper: 0 on success, otherwise the Win32 error
/// (never 0 on failure).
pub fn lock_exit_code(ok: bool, last_error: u32) -> i32 {
    match (ok, last_error) {
        (true, _) => 0,
        (false, 0) => 1,
        (false, e) => e as i32,
    }
}

// ---------------------------------------------------------------------------------------------
// Status dialog
// ---------------------------------------------------------------------------------------------

/// `3.2 MB`
pub fn fmt_mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// The dialog's "Tailscale:" line: the live summary when it was fetched, otherwise the SCM-based
/// line (with the reason when the live query failed).
fn tailscale_report_line(s: &Snapshot, live: Option<&TailscaleLive>) -> String {
    match live {
        Some(TailscaleLive::Summary(text)) => format!("Tailscale: {}", non_empty_or(one_line(text), "unknown")),
        Some(TailscaleLive::Unavailable(why)) => format!(
            "Tailscale: {} (live status unavailable: {})",
            s.tailscale_line(),
            non_empty_or(one_line(why), "unknown error")
        ),
        None => format!("Tailscale: {}", s.tailscale_line()),
    }
}

/// Body of the "Service Status" message box. `tailscale` is the result of the live Tailscale
/// query (None when not queried, see [`Snapshot::live_tailscale_query`]).
pub fn status_report(s: &Snapshot, tailscale: Option<&TailscaleLive>, tray_version: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    match (&s.service, &s.status) {
        (ServiceState::Running, Some(i)) => {
            let pid = if i.pid != 0 { i.pid } else { s.pid };
            lines.push(format!("Service: Running (PID {pid})"));
            lines.push(format!("Version: {}", non_empty_or(one_line(&i.version), "unknown")));
            lines.push(format!("Uptime: {}", fmt_duration(i.uptime_secs)));
            let telegram = non_empty_or(one_line(&i.telegram), "unknown");
            match i.bot_username.as_deref().map(|u| u.trim().trim_start_matches('@')).filter(|u| !u.is_empty()) {
                Some(bot) => lines.push(format!("Telegram: {telegram} (@{})", one_line(bot))),
                None => lines.push(format!("Telegram: {telegram}")),
            }
            if !i.owner_configured {
                lines.push(format!("Telegram users: none paired yet (use \"{LABEL_PAIR_USER}\")"));
            }
            lines.push(format!("Login monitor: {}", non_empty_or(one_line(&i.security_monitor), "unknown")));
            lines.push(format!("SSH monitor: {}", non_empty_or(one_line(&i.ssh_monitor), "unknown")));
            lines.push(format!("Queued alerts: {}", i.queued_notifications));
            lines.push(format!(
                "RAM: {} private · {} working set",
                fmt_mb(i.private_bytes),
                fmt_mb(i.working_set_bytes)
            ));
            lines.push(format!(
                "Dry-run: {}",
                if i.dry_run { "ON (power, lock, logout and Tailscale up/down are only simulated)" } else { "off" }
            ));
            lines.push(String::new());
            lines.push("Features:".into());
            if i.features.is_empty() {
                lines.push("(not reported)".into());
            }
            for fs in &i.features {
                let label =
                    Feature::from_key(&fs.key).map(|f| f.label().to_string()).unwrap_or_else(|| one_line(&fs.label));
                lines.push(format!("{} {label}", if fs.enabled { "✓" } else { "✗" }));
            }
        }
        (ServiceState::Running, None) => {
            lines.push(format!("Service: Running (PID {})", s.pid));
            let why = s.status_error.as_deref().map(one_line).unwrap_or_default();
            lines.push(format!("Status unavailable: {}", non_empty_or(why, "the service did not answer.")));
        }
        (ServiceState::NotInstalled, _) => {
            lines.push("Service: Not installed".into());
            lines.push("Install it by starting PredatorRemoteController.exe (it runs the setup).".into());
        }
        (ServiceState::StartPending | ServiceState::StopPending, _) => {
            lines.push(format!("Service: {}", s.service.label()));
            lines.push("The service is changing state. Try again in a few seconds.".into());
        }
        (state, _) => {
            lines.push(format!("Service: {}", state.label()));
            lines.push(format!(
                "The service is not running. Use \"{LABEL_START_SERVICE}\" in the tray menu to start it."
            ));
        }
    }
    lines.push(String::new());
    lines.push(tailscale_report_line(s, tailscale));
    lines.push(String::new());
    lines.push(format!("Tray app version: {tray_version}"));
    lines.join("\n")
}

// ---------------------------------------------------------------------------------------------
// Event-driven refresh: service status notifications + refresh timer
// ---------------------------------------------------------------------------------------------

/// Periodic refresh while the Predator service is watched (`NotifyServiceStatusChangeW`): only
/// for the details the SCM does not report (Telegram connection, feature states, Tailscale
/// summary). Service state changes arrive as notifications instead.
pub const SAFETY_REFRESH: Duration = Duration::from_secs(5 * 60);
/// Allowed drift of the safety refresh (`SetCoalescableTimer` tolerance), so Windows can batch the
/// wake-up with other timers.
pub const SAFETY_TOLERANCE: Duration = Duration::from_secs(30);
/// Polling interval while the Predator service cannot be watched (not installed, being deleted,
/// the watch failed or was backed off) or while it runs without answering the status request.
pub const POLL_REFRESH: Duration = Duration::from_secs(60);
/// Allowed drift of the polling refresh.
pub const POLL_TOLERANCE: Duration = Duration::from_secs(5);
/// A watch that could not be opened/armed, or was closed because the service is being deleted,
/// is tried again after this long (the polling refresh covers the gap). A little shorter than
/// [`POLL_REFRESH`]: a USER timer can fire a few milliseconds early, and the next polling refresh
/// must find the delay over (otherwise one more minute passes without a watch).
pub const WATCH_RETRY: Duration = Duration::from_secs(55);
/// Notification storm guard: more than [`STORM_LIMIT`] notifications within [`STORM_WINDOW`]
/// close the watch for [`STORM_BACKOFF`] (a flapping service, or an SCM that re-queues the
/// callback immediately). A normal service restart produces about 4–6 notifications.
pub const STORM_WINDOW: Duration = Duration::from_secs(60);
pub const STORM_LIMIT: u32 = 30;
pub const STORM_BACKOFF: Duration = Duration::from_secs(10 * 60);

/// Every state change plus "marked for deletion" (the watch must then close its handle, or it
/// would keep the service from being deleted).
pub const WATCH_MASK: SERVICE_NOTIFY = SERVICE_NOTIFY_STOPPED
    | SERVICE_NOTIFY_START_PENDING
    | SERVICE_NOTIFY_STOP_PENDING
    | SERVICE_NOTIFY_RUNNING
    | SERVICE_NOTIFY_CONTINUE_PENDING
    | SERVICE_NOTIFY_PAUSE_PENDING
    | SERVICE_NOTIFY_PAUSED
    | SERVICE_NOTIFY_DELETE_PENDING;

/// A service whose SCM state the tray watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchTarget {
    /// The Predator service (icon, tooltip, menu).
    Predator,
    /// The `Tailscale` service (tooltip line), only while the tray shows it.
    Tailscale,
}

impl WatchTarget {
    pub const ALL: [WatchTarget; 2] = [WatchTarget::Predator, WatchTarget::Tailscale];

    pub fn index(self) -> usize {
        match self {
            WatchTarget::Predator => 0,
            WatchTarget::Tailscale => 1,
        }
    }

    pub fn from_index(i: usize) -> Option<WatchTarget> {
        WatchTarget::ALL.get(i).copied()
    }
}

/// Whether `target` should be watched for this snapshot. A service known to be missing is not
/// opened (the polling/safety refresh notices an installation); the Tailscale service only while
/// its line is shown and its state is known.
pub fn should_watch(target: WatchTarget, s: &Snapshot) -> bool {
    match target {
        WatchTarget::Predator => s.service != ServiceState::NotInstalled,
        WatchTarget::Tailscale => {
            s.tailscale_wanted() && !matches!(s.tailscale_service, ServiceState::NotInstalled | ServiceState::Unknown)
        }
    }
}

/// The state (and PID, where the tray shows it) the snapshot holds for `target`.
pub fn known_state(target: WatchTarget, s: &Snapshot) -> (ServiceState, Option<u32>) {
    match target {
        WatchTarget::Predator => (s.service.clone(), Some(s.pid)),
        WatchTarget::Tailscale => (s.tailscale_service.clone(), None),
    }
}

/// `SERVICE_STATUS_PROCESS::dwCurrentState` → [`ServiceState`] (same mapping as `sys::scm`).
pub fn service_state_from_raw(state: u32) -> ServiceState {
    match state {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => ServiceState::StartPending,
        SERVICE_STOP_PENDING => ServiceState::StopPending,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_PAUSED | SERVICE_PAUSE_PENDING => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

/// What a status-change notification reported (copied out of `SERVICE_NOTIFY_2W` by the callback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyEvent {
    /// `dwNotificationStatus` (`ERROR_SUCCESS` or why the notification failed).
    pub status: u32,
    /// `dwNotificationTriggered` (`SERVICE_NOTIFY_*` bit that fired).
    pub triggered: u32,
    /// `ServiceStatus.dwCurrentState` (raw `SERVICE_*` value).
    pub state: u32,
    /// `ServiceStatus.dwProcessId`.
    pub pid: u32,
}

/// What the tray does after a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyAction {
    /// Nothing the tray shows changed (e.g. the notification Windows queues right after arming a
    /// new watch, reporting the current state): re-arm only.
    Rearm,
    /// The state (or the PID: a restart) changed: refresh, then re-arm.
    RefreshAndRearm,
    /// The SCM lost track of this client (`ERROR_SERVICE_NOTIFY_CLIENT_LAGGING`): close the
    /// handle, refresh and open a new watch.
    Reopen,
    /// The service is being deleted, or the notification failed: close the handle (an open handle
    /// would keep a deleted service alive), refresh, and let the polling refresh retry later.
    Close,
}

/// Decide what to do with a notification for a service the snapshot knows as
/// `known_state` / `known_pid` (`None` = the PID is not shown, e.g. Tailscale).
pub fn notify_action(ev: &NotifyEvent, known_state: &ServiceState, known_pid: Option<u32>) -> NotifyAction {
    match ev.status {
        ERROR_SUCCESS if ev.triggered & SERVICE_NOTIFY_DELETE_PENDING != 0 => NotifyAction::Close,
        ERROR_SUCCESS => {
            let same_state = service_state_from_raw(ev.state) == *known_state;
            let same_pid = known_pid.is_none_or(|pid| pid == ev.pid);
            if same_state && same_pid { NotifyAction::Rearm } else { NotifyAction::RefreshAndRearm }
        }
        ERROR_SERVICE_NOTIFY_CLIENT_LAGGING => NotifyAction::Reopen,
        // ERROR_SERVICE_MARKED_FOR_DELETE and anything unexpected.
        _ => NotifyAction::Close,
    }
}

/// What to do when `NotifyServiceStatusChangeW` itself fails with `code`.
pub fn arm_failure_action(code: u32) -> NotifyAction {
    if code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING { NotifyAction::Reopen } else { NotifyAction::Close }
}

/// Per-target retry/back-off bookkeeping of a watch (storm guard + retry delay).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchPolicy {
    window_start: Option<Instant>,
    in_window: u32,
    blocked_until: Option<Instant>,
}

impl WatchPolicy {
    /// May the watch be opened/armed at `now`?
    pub fn may_arm(&self, now: Instant) -> bool {
        self.blocked_until.is_none_or(|until| now >= until)
    }

    /// Opening/arming failed, or the watch had to be closed: wait [`WATCH_RETRY`].
    pub fn failed(&mut self, now: Instant) {
        self.block(now, WATCH_RETRY);
    }

    /// Count one notification. False = storm: the caller closes the watch, which stays closed for
    /// [`STORM_BACKOFF`] (the polling refresh takes over meanwhile).
    pub fn notified(&mut self, now: Instant) -> bool {
        match self.window_start {
            Some(start) if now.saturating_duration_since(start) < STORM_WINDOW => {
                self.in_window = self.in_window.saturating_add(1);
            }
            _ => {
                self.window_start = Some(now);
                self.in_window = 1;
            }
        }
        if self.in_window > STORM_LIMIT {
            self.window_start = None;
            self.in_window = 0;
            self.block(now, STORM_BACKOFF);
            return false;
        }
        true
    }

    fn block(&mut self, now: Instant, delay: Duration) {
        let until = now.checked_add(delay).unwrap_or(now);
        self.blocked_until = Some(self.blocked_until.map_or(until, |current| current.max(until)));
    }
}

/// Which periodic refresh the tray needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshPeriod {
    /// Service watched and answering: [`SAFETY_REFRESH`].
    Safety,
    /// No watch, or the running service did not answer: [`POLL_REFRESH`].
    Poll,
}

impl RefreshPeriod {
    pub fn interval_ms(self) -> u32 {
        duration_ms(match self {
            RefreshPeriod::Safety => SAFETY_REFRESH,
            RefreshPeriod::Poll => POLL_REFRESH,
        })
    }

    pub fn tolerance_ms(self) -> u32 {
        duration_ms(match self {
            RefreshPeriod::Safety => SAFETY_TOLERANCE,
            RefreshPeriod::Poll => POLL_TOLERANCE,
        })
    }
}

fn duration_ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// The refresh period for the current watch state and snapshot. A running service that did not
/// answer (e.g. its pipe is not up yet right after a start), or that answers that Telegram is
/// offline (it has not reached Telegram yet after a start, e.g. at boot before the network is up,
/// or the network is down), is polled every minute until it is fully up, so the tooltip shows
/// the recovery as quickly as before instead of up to [`SAFETY_REFRESH`] late. Lasting states
/// ("invalid token", "not configured") keep the slow refresh.
pub fn refresh_period(predator_watched: bool, s: &Snapshot) -> RefreshPeriod {
    let settling = s.running() && (!s.online() || s.telegram_offline());
    if !predator_watched || settling { RefreshPeriod::Poll } else { RefreshPeriod::Safety }
}

/// Re-set the refresh timer after a refresh (the next periodic refresh then comes one full period
/// after the last one) or when the period changes.
pub fn reschedule_timer(refreshed: bool, current: Option<RefreshPeriod>, wanted: RefreshPeriod) -> bool {
    refreshed || current != Some(wanted)
}

/// After a notification-driven refresh: the service has just (re)started (it was not running, or
/// it runs under a new PID). Its Telegram connection is still being set up, so one follow-up
/// refresh shortly afterwards shows the settled state.
pub fn settle_refresh_wanted(before: &ServiceState, before_pid: u32, after: &Snapshot) -> bool {
    after.running() && (*before != ServiceState::Running || before_pid != after.pid)
}

// ---------------------------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------------------------

/// Collapse control characters (incl. newlines) to spaces and trim, so a value from the service
/// can never add lines to the tooltip or dialog.
fn one_line(s: &str) -> String {
    let cleaned: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    cleaned.trim().to_string()
}

fn non_empty_or(s: String, fallback: &str) -> String {
    if s.trim().is_empty() { fallback.to_string() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureSet;
    use crate::ipc::FeatureState;
    use windows_sys::Win32::UI::WindowsAndMessaging::{WM_LBUTTONUP, WM_MOUSEMOVE};

    fn info() -> ServiceStatusInfo {
        let fs = FeatureSet::default();
        ServiceStatusInfo {
            version: "1.0.0".into(),
            pid: 4242,
            uptime_secs: 2 * 3600 + 5 * 60,
            telegram: "online".into(),
            bot_username: Some("ExampleBot".into()),
            owner_configured: true,
            features: fs
                .iter()
                .map(|(f, on)| FeatureState { key: f.key().into(), label: f.label().into(), enabled: on })
                .collect(),
            security_monitor: "Active".into(),
            ssh_monitor: "Active".into(),
            queued_notifications: 3,
            private_bytes: 3 * 1024 * 1024 + 200 * 1024,
            working_set_bytes: 5 * 1024 * 1024,
            tailscale: Some("Connected".into()),
            dry_run: false,
            transport: Some("direct (SChannel)".into()),
        }
    }

    fn running() -> Snapshot {
        Snapshot::from_parts(ServiceState::Running, 4242, Some(StatusFetch::Info(info())))
            .unwrap()
            .with_tailscale_service(ServiceState::Running)
    }

    fn set_feature(s: &mut Snapshot, f: Feature, on: bool) {
        if let Some(fs) = s.status.as_mut().and_then(|i| i.features.iter_mut().find(|fs| fs.key == f.key())) {
            fs.enabled = on;
        }
    }

    fn state(st: ServiceState) -> Snapshot {
        Snapshot::from_parts(st, 0, None).unwrap()
    }

    fn find_item(menu: &[MenuEntry], id: u32) -> Option<(String, bool, bool)> {
        menu.iter().find_map(|e| match e {
            MenuEntry::Item { id: i, label, enabled, checked } if *i == id => Some((label.clone(), *enabled, *checked)),
            MenuEntry::Submenu { items, .. } => find_item(items, id),
            _ => None,
        })
    }

    #[test]
    fn snapshot_from_parts() {
        let s = running();
        assert!(s.running() && s.online());
        assert_eq!(s.feature(Feature::FailedLoginNotifications), Some(false));
        assert_eq!(s.feature(Feature::SshMonitoring), Some(true));

        let denied = Snapshot::from_parts(ServiceState::Running, 1, Some(StatusFetch::Denied));
        assert_eq!(denied, Err(AccessDenied));

        let s =
            Snapshot::from_parts(ServiceState::Running, 7, Some(StatusFetch::Unavailable("pipe busy".into()))).unwrap();
        assert!(s.running() && !s.online());
        assert_eq!(s.status_error.as_deref(), Some("pipe busy"));

        // A stopped service ignores any (stale) fetch result, even Denied.
        let s = Snapshot::from_parts(ServiceState::Stopped, 0, Some(StatusFetch::Denied)).unwrap();
        assert!(!s.running() && s.status.is_none() && s.status_error.is_none());
    }

    #[test]
    fn classify_replies() {
        assert_eq!(classify_status(Ok(IpcResponse::Status(info()))), StatusFetch::Info(info()));
        assert_eq!(classify_status(Ok(IpcResponse::Denied { reason: "x".into() })), StatusFetch::Denied);
        assert_eq!(
            classify_status(Ok(IpcResponse::Error { message: "boom".into() })),
            StatusFetch::Unavailable("boom".into())
        );
        assert!(matches!(classify_status(Ok(IpcResponse::Ok { message: String::new() })), StatusFetch::Unavailable(_)));
        assert_eq!(classify_status(Err("no pipe".into())), StatusFetch::Unavailable("no pipe".into()));

        assert_eq!(classify_action(Ok(IpcResponse::Ok { message: "done".into() })), ActionOutcome::Done);
        assert_eq!(classify_action(Ok(IpcResponse::Denied { reason: String::new() })), ActionOutcome::Denied);
        assert_eq!(
            classify_action(Ok(IpcResponse::Error { message: "disk full".into() })),
            ActionOutcome::Failed("disk full".into())
        );
        assert_eq!(
            classify_action(Ok(IpcResponse::Error { message: " ".into() })),
            ActionOutcome::Failed("The service reported an error.".into())
        );
        assert!(matches!(
            classify_action(Ok(IpcResponse::Tailscale { summary: String::new(), connected: true })),
            ActionOutcome::Failed(_)
        ));
        assert_eq!(classify_action(Err("timeout".into())), ActionOutcome::Failed("timeout".into()));

        assert_eq!(
            classify_tailscale(Ok(IpcResponse::Tailscale {
                summary: "Connected · 100.64.0.5".into(),
                connected: true
            })),
            Ok(TailscaleLive::Summary("Connected · 100.64.0.5".into()))
        );
        assert_eq!(
            classify_tailscale(Ok(IpcResponse::Tailscale { summary: " \n".into(), connected: false })),
            Ok(TailscaleLive::Summary("unknown".into()))
        );
        assert_eq!(classify_tailscale(Ok(IpcResponse::Denied { reason: String::new() })), Err(AccessDenied));
        assert_eq!(
            classify_tailscale(Ok(IpcResponse::Error { message: "not installed".into() })),
            Ok(TailscaleLive::Unavailable("not installed".into()))
        );
        assert_eq!(
            classify_tailscale(Ok(IpcResponse::Ok { message: String::new() })),
            Ok(TailscaleLive::Unavailable("unexpected reply from the service".into()))
        );
        assert_eq!(classify_tailscale(Err("timed out".into())), Ok(TailscaleLive::Unavailable("timed out".into())));
        assert_eq!(
            classify_tailscale(Err(String::new())),
            Ok(TailscaleLive::Unavailable("the service did not answer".into()))
        );
    }

    #[test]
    fn set_feature_flips_current_state() {
        let r = set_feature_request(Feature::SshMonitoring, true);
        assert_eq!(r, IpcRequest::SetFeature { feature: "ssh_monitoring".into(), enabled: false });
        let json = serde_json::to_string(&set_feature_request(Feature::TailscaleManagement, false)).unwrap();
        assert_eq!(json, r#"{"cmd":"set_feature","feature":"tailscale_management","enabled":true}"#);
    }

    #[test]
    fn icon_choice() {
        assert_eq!(icon_kind(&running()), IconKind::Normal);
        assert_eq!(icon_kind(&state(ServiceState::Stopped)), IconKind::Stopped);
        assert_eq!(icon_kind(&state(ServiceState::NotInstalled)), IconKind::Stopped);
        assert_eq!(icon_kind(&state(ServiceState::StartPending)), IconKind::Stopped);
        assert_eq!(IconKind::Normal.resource_candidates(), &[1]);
        assert_eq!(IconKind::Stopped.resource_candidates(), &[2, 1]);
    }

    #[test]
    fn tooltip_matches_spec() {
        assert_eq!(
            tooltip_text(&running()),
            "Predator Remote Controller\nService: Running\nTelegram: online\nTailscale: service running · Connected"
        );
        // No cached connection summary (nobody asked for a while): the SCM state alone, never dropped.
        let mut s = running();
        if let Some(i) = s.status.as_mut() {
            i.tailscale = None;
        }
        assert_eq!(
            tooltip_text(&s),
            "Predator Remote Controller\nService: Running\nTelegram: online\nTailscale: service running"
        );
        let s = running().with_tailscale_service(ServiceState::Stopped);
        assert_eq!(
            tooltip_text(&s),
            "Predator Remote Controller\nService: Running\nTelegram: online\nTailscale: service stopped"
        );
        // Predator stopped: the Tailscale line comes from the SCM only.
        assert_eq!(
            tooltip_text(&state(ServiceState::Stopped).with_tailscale_service(ServiceState::Running)),
            "Predator Remote Controller\nService: Stopped\nTailscale: service running"
        );
        assert_eq!(
            tooltip_text(&state(ServiceState::NotInstalled).with_tailscale_service(ServiceState::NotInstalled)),
            "Predator Remote Controller\nService: Not installed\nTailscale: not installed"
        );
        assert_eq!(
            tooltip_text(&state(ServiceState::Stopped)),
            "Predator Remote Controller\nService: Stopped\nTailscale: unknown"
        );
        let s = Snapshot::from_parts(ServiceState::Running, 1, Some(StatusFetch::Unavailable("x".into())))
            .unwrap()
            .with_tailscale_service(ServiceState::StartPending);
        assert_eq!(
            tooltip_text(&s),
            "Predator Remote Controller\nService: Running (not responding)\nTailscale: service starting"
        );
        // Tailscale Management disabled: mirrors the service, which refuses Tailscale requests.
        let mut s = running();
        set_feature(&mut s, Feature::TailscaleManagement, false);
        assert_eq!(
            tooltip_text(&s),
            "Predator Remote Controller\nService: Running\nTelegram: online\nTailscale: management disabled"
        );
    }

    #[test]
    fn tooltip_fits_with_a_long_tailscale_line() {
        let mut s = running();
        if let Some(i) = s.status.as_mut() {
            i.tailscale = Some("Connected · 100.100.100.100".into());
        }
        let t = tooltip_text(&s);
        assert!(t.encode_utf16().count() <= TOOLTIP_MAX_UNITS);
        assert!(t.ends_with("Tailscale: service running · Connected · 100.100.100.100"), "{t}");
    }

    #[test]
    fn tailscale_line_prefers_the_live_scm_state() {
        use ServiceState::*;
        assert_eq!(tailscale_line(&Running, None), "service running");
        assert_eq!(
            tailscale_line(&Running, Some("Connected · 100.64.0.5")),
            "service running · Connected · 100.64.0.5"
        );
        assert_eq!(tailscale_line(&Running, Some("Needs login")), "service running · Needs login");
        assert_eq!(tailscale_line(&Running, Some("  ")), "service running");
        assert_eq!(tailscale_line(&Running, Some("Connected\nInjected")), "service running · Connected Injected");
        // Summaries taken while the service was in another state are superseded by the SCM.
        assert_eq!(tailscale_line(&Running, Some("Disconnected (service stopped)")), "service running");
        assert_eq!(tailscale_line(&Running, Some("Not installed")), "service running");
        // Stopped / pending / not installed: the cache can only be stale.
        assert_eq!(tailscale_line(&Stopped, Some("Connected · 100.64.0.5")), "service stopped");
        assert_eq!(tailscale_line(&StartPending, None), "service starting");
        assert_eq!(tailscale_line(&StopPending, Some("Connected")), "service stopping");
        assert_eq!(tailscale_line(&Paused, None), "service paused");
        assert_eq!(tailscale_line(&NotInstalled, Some("Connected")), "not installed");
        // SCM query failed: the cached summary is the best there is.
        assert_eq!(tailscale_line(&Unknown, Some("Connected · 100.64.0.5")), "Connected · 100.64.0.5");
        assert_eq!(tailscale_line(&Unknown, None), "unknown");
    }

    #[test]
    fn live_tailscale_query_gating() {
        assert!(running().live_tailscale_query());
        assert!(running().with_tailscale_service(ServiceState::Stopped).live_tailscale_query());
        assert!(!running().with_tailscale_service(ServiceState::NotInstalled).live_tailscale_query());
        let mut s = running();
        set_feature(&mut s, Feature::TailscaleManagement, false);
        assert!(!s.tailscale_wanted());
        assert!(!s.live_tailscale_query());
        // Unknown feature state (service stopped / not answering): SCM line yes, live query no.
        let s = state(ServiceState::Stopped).with_tailscale_service(ServiceState::Running);
        assert!(s.tailscale_wanted());
        assert!(!s.live_tailscale_query());
        let s = Snapshot::from_parts(ServiceState::Running, 1, Some(StatusFetch::Unavailable("x".into())))
            .unwrap()
            .with_tailscale_service(ServiceState::Running);
        assert!(s.tailscale_wanted());
        assert!(!s.live_tailscale_query());
    }

    #[test]
    fn tooltip_is_sanitized_and_bounded() {
        let mut s = running();
        if let Some(i) = s.status.as_mut() {
            i.telegram = "online\nInjected: line".into();
            i.tailscale = Some("🛡".repeat(100));
        }
        let t = tooltip_text(&s);
        assert!(t.encode_utf16().count() <= TOOLTIP_MAX_UNITS);
        assert!(t.contains("Telegram: online Injected: line"));
        assert_eq!(t.lines().count(), 4);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn utf16_truncation() {
        assert_eq!(truncate_utf16("short", 127), "short");
        assert_eq!(truncate_utf16("abcdef", 4), "abc…");
        // "😀" is a surrogate pair (2 units): never split it.
        let t = truncate_utf16("a😀😀", 4);
        assert_eq!(t, "a😀…");
        assert_eq!(t.encode_utf16().count(), 4);
        let t = truncate_utf16("😀😀😀", 4);
        assert_eq!(t, "😀…");
        assert_eq!(truncate_utf16("abc", 0), "");
        let exact = "x".repeat(127);
        assert_eq!(truncate_utf16(&exact, 127), exact);
    }

    #[test]
    fn fill_wide_terminates_and_truncates() {
        let mut buf = [0xFFFFu16; 8];
        fill_wide(&mut buf, "hello");
        assert_eq!(&buf[..6], &[104, 101, 108, 108, 111, 0]);
        assert!(buf[6..].iter().all(|&u| u == 0));

        let mut buf = [0xFFFFu16; 5];
        fill_wide(&mut buf, "abcdefgh");
        assert_eq!(String::from_utf16_lossy(&buf[..4]), "abc…");
        assert_eq!(buf[4], 0);

        let mut empty: [u16; 0] = [];
        fill_wide(&mut empty, "x"); // must not panic

        let mut tip = [0u16; 128];
        fill_wide(&mut tip, &"y".repeat(500));
        assert_eq!(tip[127], 0);
        assert_eq!(tip.iter().position(|&u| u == 0), Some(127));
    }

    #[test]
    fn menu_ids_roundtrip() {
        for f in Feature::ALL {
            assert_eq!(MenuAction::from_id(quick_toggle_id(f)), Some(MenuAction::ToggleFeature(f)));
            assert_eq!(MenuAction::from_id(feature_settings_id(f)), Some(MenuAction::ToggleFeature(f)));
        }
        assert_eq!(MenuAction::from_id(ID_OPEN_DASHBOARD), Some(MenuAction::OpenDashboard));
        assert_eq!(MenuAction::from_id(ID_SERVICE_STATUS), Some(MenuAction::ServiceStatus));
        assert_eq!(MenuAction::from_id(ID_RESTART_SERVICE), Some(MenuAction::RestartService));
        assert_eq!(MenuAction::from_id(ID_START_SERVICE), Some(MenuAction::StartService));
        assert_eq!(MenuAction::from_id(ID_EXIT), Some(MenuAction::Exit));
        assert_eq!(MenuAction::from_id(ID_PAIR_USER), Some(MenuAction::PairUser));
        assert_eq!(MenuAction::from_id(ID_TELEGRAM_USERS), Some(MenuAction::TelegramUsers));
        for bad in [0, 8, 99, 109, 150, 199, 209, 300, u32::MAX] {
            assert_eq!(MenuAction::from_id(bad), None, "id {bad}");
        }
    }

    fn labels(menu: &[MenuEntry]) -> Vec<String> {
        menu.iter()
            .map(|e| match e {
                MenuEntry::Item { label, .. } | MenuEntry::Submenu { label, .. } => label.clone(),
                MenuEntry::Separator => "-".into(),
            })
            .collect()
    }

    #[test]
    fn menu_ids_are_unique() {
        fn collect(menu: &[MenuEntry], out: &mut Vec<u32>) {
            for e in menu {
                match e {
                    MenuEntry::Item { id, .. } => out.push(*id),
                    MenuEntry::Submenu { items, .. } => collect(items, out),
                    MenuEntry::Separator => {}
                }
            }
        }
        for s in [running(), state(ServiceState::Stopped), state(ServiceState::NotInstalled)] {
            let mut ids = Vec::new();
            collect(&build_menu(&s, Some("bot")), &mut ids);
            let n = ids.len();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), n);
            assert!(!ids.contains(&0));
        }
    }

    #[test]
    fn toggle_labels() {
        assert_eq!(toggle_label("SSH Monitoring", Some(true)), "Disable SSH Monitoring");
        assert_eq!(toggle_label("SSH Monitoring", Some(false)), "Enable SSH Monitoring");
        assert_eq!(toggle_label("SSH Monitoring", None), "Enable/Disable SSH Monitoring");
    }

    #[test]
    fn menu_when_running_matches_requirements() {
        // The full menu (all quick-toggle features on → "Disable …", checked).
        let mut s = running();
        set_feature(&mut s, Feature::FailedLoginNotifications, true);
        let menu = build_menu(&s, Some("ExampleBot"));
        assert_eq!(
            labels(&menu),
            [
                "Open Dashboard",
                "Service Status",
                "Pair Telegram User…",
                "Telegram Users…",
                "-",
                "Disable Login Monitoring",
                "Disable SSH Monitoring",
                "Disable Notifications",
                "Disable Power Management",
                "Disable Tailscale",
                "Feature Settings",
                "-",
                "Restart Service",
                "Exit Tray Application"
            ]
        );
        assert_eq!(find_item(&menu, ID_OPEN_DASHBOARD), Some(("Open Dashboard".into(), true, false)));
        assert_eq!(find_item(&menu, ID_SERVICE_STATUS), Some(("Service Status".into(), true, false)));
        assert_eq!(find_item(&menu, ID_PAIR_USER), Some(("Pair Telegram User…".into(), true, false)));
        assert_eq!(find_item(&menu, ID_TELEGRAM_USERS), Some(("Telegram Users…".into(), true, false)));
        for (f, name) in QUICK_TOGGLES {
            assert_eq!(find_item(&menu, quick_toggle_id(f)), Some((format!("Disable {name}"), true, true)));
        }
        assert_eq!(find_item(&menu, ID_RESTART_SERVICE), Some(("Restart Service".into(), true, false)));
        assert_eq!(find_item(&menu, ID_START_SERVICE), None);
        assert_eq!(find_item(&menu, ID_EXIT), Some(("Exit Tray Application".into(), true, false)));
        match &menu[10] {
            MenuEntry::Submenu { label, enabled, items } => {
                assert_eq!(label, "Feature Settings");
                assert!(*enabled);
                assert_eq!(items.len(), 9);
            }
            other => panic!("expected submenu, got {other:?}"),
        }
    }

    #[test]
    fn menu_toggle_label_follows_state() {
        let mut s = running();
        set_feature(&mut s, Feature::LoginMonitoring, false);
        set_feature(&mut s, Feature::TailscaleManagement, false);
        let menu = build_menu(&s, None);
        // Disabled → "Enable X", unchecked; enabled → "Disable X", checked.
        assert_eq!(
            find_item(&menu, quick_toggle_id(Feature::LoginMonitoring)),
            Some(("Enable Login Monitoring".into(), true, false))
        );
        assert_eq!(
            find_item(&menu, quick_toggle_id(Feature::TailscaleManagement)),
            Some(("Enable Tailscale".into(), true, false))
        );
        assert_eq!(
            find_item(&menu, quick_toggle_id(Feature::LoginNotifications)),
            Some(("Disable Notifications".into(), true, true))
        );
        // The submenu lists features by name with a check mark.
        assert_eq!(
            find_item(&menu, feature_settings_id(Feature::FailedLoginNotifications)),
            Some(("Failed Login Notifications".into(), true, false))
        );
        assert_eq!(
            find_item(&menu, feature_settings_id(Feature::LoginMonitoring)),
            Some(("Windows Login Monitoring".into(), true, false))
        );
        assert_eq!(
            find_item(&menu, feature_settings_id(Feature::SshMonitoring)),
            Some(("SSH Monitoring".into(), true, true))
        );
        // Clicking "Enable Login Monitoring" enables it (flips the state the label was built from).
        assert_eq!(
            s.feature(Feature::LoginMonitoring).map(|cur| set_feature_request(Feature::LoginMonitoring, cur)),
            Some(IpcRequest::SetFeature { feature: "login_monitoring".into(), enabled: true })
        );
    }

    #[test]
    fn menu_when_stopped_or_missing() {
        let menu = build_menu(&state(ServiceState::Stopped), Some("ExampleBot"));
        assert_eq!(
            labels(&menu),
            [
                "Open Dashboard",
                "Service Status",
                "Pair Telegram User…",
                "Telegram Users…",
                "-",
                "Enable/Disable Login Monitoring",
                "Enable/Disable SSH Monitoring",
                "Enable/Disable Notifications",
                "Enable/Disable Power Management",
                "Enable/Disable Tailscale",
                "Feature Settings",
                "-",
                "Start Service (admin)…",
                "Restart Service",
                "Exit Tray Application"
            ]
        );
        // Dashboard still works with the last known username; toggles are greyed and unchecked.
        assert_eq!(find_item(&menu, ID_OPEN_DASHBOARD), Some(("Open Dashboard".into(), true, false)));
        assert_eq!(find_item(&menu, ID_SERVICE_STATUS), Some(("Service Status".into(), true, false)));
        for (f, name) in QUICK_TOGGLES {
            assert_eq!(find_item(&menu, quick_toggle_id(f)), Some((format!("Enable/Disable {name}"), false, false)));
        }
        // pairing and the user list need the service
        assert_eq!(find_item(&menu, ID_PAIR_USER), Some(("Pair Telegram User…".into(), false, false)));
        assert_eq!(find_item(&menu, ID_TELEGRAM_USERS), Some(("Telegram Users…".into(), false, false)));
        assert!(matches!(&menu[10], MenuEntry::Submenu { enabled: false, .. }));
        assert_eq!(find_item(&menu, ID_START_SERVICE), Some(("Start Service (admin)…".into(), true, false)));
        assert_eq!(find_item(&menu, ID_RESTART_SERVICE), Some(("Restart Service".into(), false, false)));
        assert_eq!(find_item(&menu, ID_EXIT), Some(("Exit Tray Application".into(), true, false)));

        let menu = build_menu(&state(ServiceState::NotInstalled), None);
        assert_eq!(find_item(&menu, ID_OPEN_DASHBOARD), Some(("Open Dashboard".into(), false, false)));
        assert_eq!(find_item(&menu, ID_START_SERVICE), Some(("Start Service (admin)…".into(), false, false)));
        assert_eq!(find_item(&menu, ID_RESTART_SERVICE), Some(("Restart Service".into(), false, false)));

        for pending in [ServiceState::StartPending, ServiceState::StopPending] {
            let menu = build_menu(&state(pending), None);
            assert_eq!(find_item(&menu, ID_RESTART_SERVICE), Some(("Restart Service".into(), false, false)));
            assert_eq!(find_item(&menu, ID_START_SERVICE), None);
        }

        // Running but not answering: toggles greyed, restart still offered, no start item.
        let s = Snapshot::from_parts(ServiceState::Running, 1, Some(StatusFetch::Unavailable("x".into()))).unwrap();
        let menu = build_menu(&s, None);
        assert_eq!(
            find_item(&menu, quick_toggle_id(Feature::SshMonitoring)),
            Some(("Enable/Disable SSH Monitoring".into(), false, false))
        );
        assert_eq!(find_item(&menu, ID_RESTART_SERVICE), Some(("Restart Service".into(), true, false)));
        assert_eq!(find_item(&menu, ID_START_SERVICE), None);
        assert_eq!(find_item(&menu, ID_PAIR_USER), Some(("Pair Telegram User…".into(), false, false)));
    }

    #[test]
    fn menu_feature_missing_from_service_list_is_greyed() {
        let mut s = running();
        if let Some(i) = s.status.as_mut() {
            i.features.retain(|f| f.key != "power_management");
        }
        let menu = build_menu(&s, None);
        assert_eq!(
            find_item(&menu, quick_toggle_id(Feature::PowerManagement)),
            Some(("Enable/Disable Power Management".into(), false, false))
        );
    }

    #[test]
    fn dashboard_urls() {
        assert_eq!(dashboard_url("ExampleBot").as_deref(), Some("https://t.me/ExampleBot"));
        assert_eq!(dashboard_url("@my_bot").as_deref(), Some("https://t.me/my_bot"));
        assert_eq!(dashboard_url(""), None);
        assert_eq!(dashboard_url("@"), None);
        assert_eq!(dashboard_url("evil/../x"), None);
        assert_eq!(dashboard_url("a b"), None);
        assert_eq!(dashboard_url("bot\" & calc"), None);
        assert_eq!(dashboard_url(&"b".repeat(65)), None);
    }

    #[test]
    fn menu_label_escaping() {
        assert_eq!(escape_menu_label("A & B"), "A && B");
        assert_eq!(escape_menu_label("plain"), "plain");
    }

    #[test]
    fn tray_callback_decoding() {
        let lparam = ((1u32 << 16) | WM_CONTEXTMENU) as isize;
        assert_eq!(split_tray_lparam(lparam), (WM_CONTEXTMENU, 1));
        assert_eq!(split_tray_lparam(((7u32 << 16) | NIN_SELECT) as isize), (NIN_SELECT, 7));

        assert_eq!(anchor_from_wparam((200usize << 16) | 100), (100, 200));
        // Monitors left of / above the primary one give negative coordinates.
        let x = (-1500i16) as u16 as usize;
        let y = (-20i16) as u16 as usize;
        assert_eq!(anchor_from_wparam((y << 16) | x), (-1500, -20));

        assert!(opens_menu(WM_CONTEXTMENU));
        assert!(opens_menu(NIN_SELECT));
        assert!(opens_menu(NIN_KEYSELECT));
        assert_eq!(NIN_KEYSELECT, 0x401);
        assert!(!opens_menu(WM_LBUTTONUP));
        assert!(!opens_menu(WM_MOUSEMOVE));
    }

    #[test]
    fn menu_reopen_guard() {
        assert!(menu_allowed(None));
        assert!(!menu_allowed(Some(Duration::from_millis(50))));
        assert!(menu_allowed(Some(Duration::from_millis(300))));
        assert!(menu_allowed(Some(Duration::from_secs(5))));
    }

    #[test]
    fn lock_arguments_and_exit_codes() {
        assert!(is_lock_invocation(&["--lock"]));
        assert!(is_lock_invocation(&["--LOCK", "extra"]));
        assert!(!is_lock_invocation::<&str>(&[]));
        assert!(!is_lock_invocation(&["--locked"]));
        assert!(!is_lock_invocation(&["x", "--lock"]));
        assert!(is_lock_invocation(&[std::ffi::OsString::from("--lock")]));

        assert_eq!(lock_exit_code(true, 5), 0);
        assert_eq!(lock_exit_code(false, 5), 5);
        assert_eq!(lock_exit_code(false, 0), 1);
    }

    #[test]
    fn megabytes() {
        assert_eq!(fmt_mb(0), "0.0 MB");
        assert_eq!(fmt_mb(3 * 1024 * 1024 + 200 * 1024), "3.2 MB");
    }

    #[test]
    fn status_report_running() {
        let live = TailscaleLive::Summary("Connected · 100.64.0.5".into());
        let text = status_report(&running(), Some(&live), "1.0.0");
        for needle in [
            "Service: Running (PID 4242)",
            "Version: 1.0.0",
            "Uptime: 2h 5m",
            "Telegram: online (@ExampleBot)",
            "Login monitor: Active",
            "SSH monitor: Active",
            "Queued alerts: 3",
            "RAM: 3.2 MB private · 5.0 MB working set",
            "Dry-run: off",
            "✓ Windows Login Monitoring",
            "✗ Failed Login Notifications",
            "\nTailscale: Connected · 100.64.0.5\n",
            "Tray app version: 1.0.0",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert!(!text.contains("Telegram users:"));
        assert_eq!(text.matches('✓').count() + text.matches('✗').count(), 9);
        assert_eq!(text.matches("Tailscale:").count(), 1);

        let mut s = running();
        if let Some(i) = s.status.as_mut() {
            i.dry_run = true;
            i.owner_configured = false;
            i.bot_username = None;
        }
        // Not queried live: the SCM line enriched with the cached summary.
        let text = status_report(&s, None, "1.0.0");
        assert!(text.contains("Dry-run: ON (power, lock, logout and Tailscale up/down are only simulated)"));
        assert!(text.contains("Telegram users: none paired yet (use \"Pair Telegram User…\")"), "{text}");
        assert!(text.contains("Telegram: online\n"));
        assert!(text.contains("\nTailscale: service running · Connected\n"), "{text}");
    }

    #[test]
    fn status_report_tailscale_fallbacks() {
        // The live query failed: SCM-based line plus the reason.
        let s = running().with_tailscale_service(ServiceState::Stopped);
        let live = TailscaleLive::Unavailable("timed out".into());
        let text = status_report(&s, Some(&live), "1.0.0");
        assert!(text.contains("\nTailscale: service stopped (live status unavailable: timed out)\n"), "{text}");

        // Feature disabled: mirrors the service instead of reporting a Tailscale state.
        let mut s = running();
        set_feature(&mut s, Feature::TailscaleManagement, false);
        let text = status_report(&s, None, "1.0.0");
        assert!(text.contains("\nTailscale: management disabled\n"), "{text}");

        // Predator not running: the Tailscale state still comes from the SCM.
        let s = state(ServiceState::Stopped).with_tailscale_service(ServiceState::Running);
        let text = status_report(&s, None, "1.0.0");
        assert!(text.contains("\nTailscale: service running\n"), "{text}");
        let s = state(ServiceState::NotInstalled).with_tailscale_service(ServiceState::NotInstalled);
        let text = status_report(&s, None, "1.0.0");
        assert!(text.contains("\nTailscale: not installed\n"), "{text}");

        // Values from the service can never add lines.
        let live = TailscaleLive::Summary("Connected\nInjected: line".into());
        let text = status_report(&running(), Some(&live), "1.0.0");
        assert!(text.contains("\nTailscale: Connected Injected: line\n"), "{text}");
    }

    fn ev(status: u32, triggered: u32, state: u32, pid: u32) -> NotifyEvent {
        NotifyEvent { status, triggered, state, pid }
    }

    #[test]
    fn raw_service_states() {
        assert_eq!(service_state_from_raw(SERVICE_STOPPED), ServiceState::Stopped);
        assert_eq!(service_state_from_raw(SERVICE_START_PENDING), ServiceState::StartPending);
        assert_eq!(service_state_from_raw(SERVICE_CONTINUE_PENDING), ServiceState::StartPending);
        assert_eq!(service_state_from_raw(SERVICE_STOP_PENDING), ServiceState::StopPending);
        assert_eq!(service_state_from_raw(SERVICE_RUNNING), ServiceState::Running);
        assert_eq!(service_state_from_raw(SERVICE_PAUSED), ServiceState::Paused);
        assert_eq!(service_state_from_raw(SERVICE_PAUSE_PENDING), ServiceState::Paused);
        assert_eq!(service_state_from_raw(0), ServiceState::Unknown);
        assert_eq!(service_state_from_raw(99), ServiceState::Unknown);
    }

    #[test]
    fn watch_targets() {
        for t in WatchTarget::ALL {
            assert_eq!(WatchTarget::from_index(t.index()), Some(t));
        }
        assert_eq!(WatchTarget::from_index(2), None);
        assert_eq!(WatchTarget::from_index(usize::MAX), None);
        // Every state is watched, plus "marked for deletion"; never CREATED/DELETED (SCM handles only).
        assert_eq!(WATCH_MASK, 0x7F | SERVICE_NOTIFY_DELETE_PENDING);
    }

    #[test]
    fn which_services_are_watched() {
        use WatchTarget::*;
        assert!(should_watch(Predator, &running()));
        assert!(should_watch(Predator, &state(ServiceState::Stopped)));
        assert!(should_watch(Predator, &state(ServiceState::Unknown))); // query failed: try anyway
        assert!(!should_watch(Predator, &state(ServiceState::NotInstalled)));

        assert!(should_watch(Tailscale, &running()));
        assert!(should_watch(Tailscale, &running().with_tailscale_service(ServiceState::Stopped)));
        assert!(!should_watch(Tailscale, &running().with_tailscale_service(ServiceState::NotInstalled)));
        assert!(!should_watch(Tailscale, &running().with_tailscale_service(ServiceState::Unknown)));
        // Tailscale Management disabled: the line is not shown, so the service is not watched.
        let mut s = running();
        set_feature(&mut s, Feature::TailscaleManagement, false);
        assert!(!should_watch(Tailscale, &s));
        // Predator stopped (feature state unknown): the SCM line is still shown → watched.
        assert!(should_watch(Tailscale, &state(ServiceState::Stopped).with_tailscale_service(ServiceState::Running)));
    }

    #[test]
    fn known_states() {
        assert_eq!(known_state(WatchTarget::Predator, &running()), (ServiceState::Running, Some(4242)));
        let s = state(ServiceState::Stopped).with_tailscale_service(ServiceState::StopPending);
        assert_eq!(known_state(WatchTarget::Tailscale, &s), (ServiceState::StopPending, None));
    }

    #[test]
    fn notification_decisions() {
        use NotifyAction::*;
        let running = ServiceState::Running;
        // The notification queued right after arming reports what the tray already shows.
        assert_eq!(notify_action(&ev(0, SERVICE_NOTIFY_RUNNING, SERVICE_RUNNING, 42), &running, Some(42)), Rearm);
        // State change.
        assert_eq!(
            notify_action(&ev(0, SERVICE_NOTIFY_STOP_PENDING, SERVICE_STOP_PENDING, 42), &running, Some(42)),
            RefreshAndRearm
        );
        assert_eq!(
            notify_action(&ev(0, SERVICE_NOTIFY_STOPPED, SERVICE_STOPPED, 0), &running, Some(42)),
            RefreshAndRearm
        );
        // Same state, new PID: the service restarted between two notifications.
        assert_eq!(
            notify_action(&ev(0, SERVICE_NOTIFY_RUNNING, SERVICE_RUNNING, 43), &running, Some(42)),
            RefreshAndRearm
        );
        // PID not shown (Tailscale): only the state counts.
        assert_eq!(notify_action(&ev(0, SERVICE_NOTIFY_RUNNING, SERVICE_RUNNING, 7), &running, None), Rearm);
        // Marked for deletion: close the handle so the service can go away.
        assert_eq!(
            notify_action(&ev(0, SERVICE_NOTIFY_DELETE_PENDING, SERVICE_RUNNING, 42), &running, Some(42)),
            Close
        );
        assert_eq!(
            notify_action(
                &ev(0, SERVICE_NOTIFY_DELETE_PENDING | SERVICE_NOTIFY_STOPPED, SERVICE_STOPPED, 0),
                &ServiceState::Stopped,
                Some(0)
            ),
            Close
        );
        assert_eq!(notify_action(&ev(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, 0, 0, 0), &running, Some(42)), Reopen);
        assert_eq!(notify_action(&ev(1072, 0, 0, 0), &running, Some(42)), Close); // marked for delete
        assert_eq!(notify_action(&ev(5, 0, 0, 0), &running, Some(42)), Close);

        assert_eq!(arm_failure_action(ERROR_SERVICE_NOTIFY_CLIENT_LAGGING), Reopen);
        assert_eq!(arm_failure_action(1072), Close);
        assert_eq!(arm_failure_action(5), Close);
    }

    #[test]
    fn watch_policy_retry_delay() {
        let t0 = Instant::now();
        let mut p = WatchPolicy::default();
        assert!(p.may_arm(t0));
        p.failed(t0);
        assert!(!p.may_arm(t0));
        assert!(!p.may_arm(t0 + WATCH_RETRY - Duration::from_millis(1)));
        assert!(p.may_arm(t0 + WATCH_RETRY));
        // The next polling refresh (one POLL_REFRESH later, even if its timer fires a little
        // early) finds the retry delay over.
        assert!(WATCH_RETRY + Duration::from_secs(1) < POLL_REFRESH);
        assert!(p.may_arm(t0 + POLL_REFRESH - Duration::from_millis(100)));
        // A later failure never shortens an existing block.
        let mut p = WatchPolicy::default();
        for _ in 0..=STORM_LIMIT {
            p.notified(t0);
        }
        p.failed(t0);
        assert!(!p.may_arm(t0 + WATCH_RETRY));
        assert!(p.may_arm(t0 + STORM_BACKOFF));
    }

    #[test]
    fn watch_policy_storm_guard() {
        let t0 = Instant::now();
        let mut p = WatchPolicy::default();
        // A service restart (and a few re-arms) is far below the limit.
        for i in 0..STORM_LIMIT {
            assert!(p.notified(t0 + Duration::from_millis(u64::from(i))), "notification {i}");
        }
        assert!(p.may_arm(t0));
        // One more inside the window: storm → back off.
        let t1 = t0 + Duration::from_secs(1);
        assert!(!p.notified(t1));
        assert!(!p.may_arm(t1));
        assert!(!p.may_arm(t1 + STORM_BACKOFF - Duration::from_secs(1)));
        assert!(p.may_arm(t1 + STORM_BACKOFF));
        // After the back-off the counting starts afresh.
        let t2 = t1 + STORM_BACKOFF;
        assert!(p.notified(t2));

        // Spread out over time, any number of notifications is fine.
        let mut p = WatchPolicy::default();
        for i in 0..10 * STORM_LIMIT {
            let t = t0 + Duration::from_secs(5 * u64::from(i));
            assert!(p.notified(t), "notification {i}");
            assert!(p.may_arm(t));
        }
    }

    #[test]
    fn refresh_periods() {
        assert_eq!(RefreshPeriod::Safety.interval_ms(), 300_000);
        assert_eq!(RefreshPeriod::Safety.tolerance_ms(), 30_000);
        assert_eq!(RefreshPeriod::Poll.interval_ms(), 60_000);
        assert_eq!(RefreshPeriod::Poll.tolerance_ms(), 5_000);
        // Tolerance must stay well below the interval (and below SetCoalescableTimer's 0x7FFFFFF5 limit).
        for p in [RefreshPeriod::Safety, RefreshPeriod::Poll] {
            assert!(p.tolerance_ms() < p.interval_ms() / 5);
        }

        assert_eq!(refresh_period(true, &running()), RefreshPeriod::Safety);
        assert_eq!(refresh_period(true, &state(ServiceState::Stopped)), RefreshPeriod::Safety);
        assert_eq!(refresh_period(false, &running()), RefreshPeriod::Poll);
        assert_eq!(refresh_period(false, &state(ServiceState::NotInstalled)), RefreshPeriod::Poll);
        // Running but not answering (pipe not up yet): poll until it answers.
        let s = Snapshot::from_parts(ServiceState::Running, 1, Some(StatusFetch::Unavailable("x".into()))).unwrap();
        assert_eq!(refresh_period(true, &s), RefreshPeriod::Poll);
        // Answering, but Telegram not reached yet (boot before the network is up) or the network
        // is down: poll until online, so the recovery shows within a minute.
        let with_telegram = |label: &str| {
            let mut s = running();
            if let Some(i) = s.status.as_mut() {
                i.telegram = label.into();
            }
            s
        };
        for offline in ["offline", " Offline\n"] {
            assert!(with_telegram(offline).telegram_offline(), "{offline:?}");
            assert_eq!(refresh_period(true, &with_telegram(offline)), RefreshPeriod::Poll, "{offline:?}");
        }
        // Lasting states do not heal by themselves: the slow refresh is enough.
        for lasting in ["online", "invalid token", "not configured", ""] {
            assert!(!with_telegram(lasting).telegram_offline(), "{lasting:?}");
            assert_eq!(refresh_period(true, &with_telegram(lasting)), RefreshPeriod::Safety, "{lasting:?}");
        }
        // Without a status reply the Telegram state is unknown, not "offline".
        assert!(!state(ServiceState::Stopped).telegram_offline());
        assert_eq!(refresh_period(false, &with_telegram("online")), RefreshPeriod::Poll);

        assert!(reschedule_timer(true, Some(RefreshPeriod::Safety), RefreshPeriod::Safety));
        assert!(reschedule_timer(false, None, RefreshPeriod::Safety));
        assert!(reschedule_timer(false, Some(RefreshPeriod::Poll), RefreshPeriod::Safety));
        assert!(!reschedule_timer(false, Some(RefreshPeriod::Safety), RefreshPeriod::Safety));
        assert!(!reschedule_timer(false, Some(RefreshPeriod::Poll), RefreshPeriod::Poll));
    }

    #[test]
    fn settle_refresh_after_a_start() {
        let after = running(); // PID 4242
        assert!(settle_refresh_wanted(&ServiceState::StartPending, 0, &after));
        assert!(settle_refresh_wanted(&ServiceState::Stopped, 0, &after));
        assert!(settle_refresh_wanted(&ServiceState::Running, 17, &after)); // restarted
        assert!(!settle_refresh_wanted(&ServiceState::Running, 4242, &after));
        assert!(!settle_refresh_wanted(&ServiceState::Running, 4242, &state(ServiceState::Stopped)));
        assert!(!settle_refresh_wanted(&ServiceState::Stopped, 0, &state(ServiceState::StartPending)));
    }

    /// One idle hour with the service watched: the tray refreshes 12 times (safety timer) instead
    /// of 60, and a restart costs one refresh per state change plus one settle refresh.
    #[test]
    fn idle_hour_refresh_count() {
        let watched = true;
        let snap = running();
        let period = refresh_period(watched, &snap);
        let per_hour = 3_600_000 / period.interval_ms();
        assert_eq!(per_hour, 12);
        let old_per_hour = 3_600_000 / POLL_REFRESH.as_millis() as u32;
        assert_eq!(old_per_hour, 60);

        // Restart: StopPending, Stopped, StartPending, Running (new PID).
        let mut known = (ServiceState::Running, 4242u32);
        let mut refreshes = 0;
        let mut settles = 0;
        for (raw, pid) in
            [(SERVICE_STOP_PENDING, 4242), (SERVICE_STOPPED, 0), (SERVICE_START_PENDING, 0), (SERVICE_RUNNING, 5000)]
        {
            let e = ev(0, 0, raw, pid);
            if notify_action(&e, &known.0, Some(known.1)) == NotifyAction::RefreshAndRearm {
                refreshes += 1;
                let after = Snapshot::from_parts(service_state_from_raw(raw), pid, None).unwrap();
                if settle_refresh_wanted(&known.0, known.1, &after) {
                    settles += 1;
                }
                known = (after.service, after.pid);
            }
            // The immediate re-check after re-arming reports the same state: no extra refresh.
            assert_eq!(notify_action(&e, &known.0, Some(known.1)), NotifyAction::Rearm);
        }
        assert_eq!((refreshes, settles), (4, 1));
    }

    #[test]
    fn status_report_not_running() {
        let text = status_report(&state(ServiceState::Stopped), None, "1.0.0");
        assert!(text.starts_with("Service: Stopped\n"));
        assert!(text.contains("Start Service (admin)…"));
        assert!(text.contains("Tailscale: unknown"));
        let text = status_report(&state(ServiceState::NotInstalled), None, "1.0.0");
        assert!(text.contains("PredatorRemoteController.exe"));
        let text = status_report(&state(ServiceState::StopPending), None, "1.0.0");
        assert!(text.contains("Service: Stopping"));
        let s = Snapshot::from_parts(ServiceState::Running, 77, Some(StatusFetch::Unavailable("pipe timeout".into())))
            .unwrap();
        let text = status_report(&s, None, "1.0.0");
        assert!(text.contains("Service: Running (PID 77)"));
        assert!(text.contains("Status unavailable: pipe timeout"));
    }

    const T0: i64 = 1_800_000_000;

    fn started(bot: Option<&str>) -> PairingStarted {
        PairingStarted { code: "12345678".into(), expires_unix: T0 + 600, bot_username: bot.map(str::to_string) }
    }

    #[test]
    fn pairing_request_and_start_reply() {
        assert_eq!(
            serde_json::to_string(&start_pairing_request()).unwrap(),
            r#"{"cmd":"start_pairing","ttl_secs":600,"admin":false}"#
        );
        let reply = |code: &str| {
            Ok(IpcResponse::Pairing {
                code: code.into(),
                expires_unix: T0 + 600,
                bot_username: Some("ExampleBot".into()),
            })
        };
        assert_eq!(classify_pairing_start(reply("12345678")), PairingStart::Started(started(Some("ExampleBot"))));
        assert!(matches!(classify_pairing_start(reply("12ab")), PairingStart::Failed(_)), "never shows junk");
        assert_eq!(classify_pairing_start(Ok(IpcResponse::Denied { reason: String::new() })), PairingStart::Denied);
        assert_eq!(
            classify_pairing_start(Ok(IpcResponse::Error { message: "20 Telegram accounts are paired".into() })),
            PairingStart::Failed("20 Telegram accounts are paired".into())
        );
        // an older service that does not know the request answers Error (parse failure)
        assert!(matches!(
            classify_pairing_start(Ok(IpcResponse::Ok { message: String::new() })),
            PairingStart::Failed(_)
        ));
        assert_eq!(classify_pairing_start(Err("timeout".into())), PairingStart::Failed("timeout".into()));
    }

    #[test]
    fn pairing_dialog() {
        let text = pairing_dialog_text(&started(Some("ExampleBot")), None, T0, "14:35", false);
        for needle in [
            "Pairing code:   1234 5678",
            "Valid for 10 min (until 14:35), once.",
            "open https://t.me/ExampleBot?start=pair-12345678 and press Start",
            "send this message to @ExampleBot:",
            "        /pair 12345678",
            "role User",
            "Keep the code private",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        // the first account becomes an Admin
        let text = pairing_dialog_text(&started(Some("ExampleBot")), None, T0, "14:35", true);
        assert!(text.contains("becomes an Admin"), "{text}");
        // the reply carries no bot name: the last known one is used, else no link at all
        let text = pairing_dialog_text(&started(None), Some("@example_bot"), T0 + 590, "14:35", false);
        assert!(text.contains("https://t.me/example_bot?start=pair-12345678"), "{text}");
        assert!(text.contains("Valid for 1 min"), "{text}");
        let text = pairing_dialog_text(&started(Some("bad name")), None, T0, "14:35", false);
        assert!(!text.contains("https://") && text.contains("send this message to the bot:"), "{text}");
        assert!(text.contains("/pair 12345678"));
    }

    fn pairing_reply(active: bool, expires: Option<i64>, paired: Option<(&str, i64)>) -> Result<IpcResponse, String> {
        Ok(IpcResponse::PairingState {
            active,
            expires_unix: expires,
            paired_name: paired.map(|(n, _)| n.to_string()),
            paired_id: paired.map(|(_, id)| id),
            paired_unix: paired.map(|_| T0 + 5),
        })
    }

    #[test]
    fn pairing_checks() {
        use PairingCheck::*;
        let ours = T0 + 600;
        assert_eq!(classify_pairing_check(pairing_reply(true, Some(ours), None), ours, T0 + 10), KeepWaiting);
        assert_eq!(
            classify_pairing_check(pairing_reply(false, None, Some(("@alice", 123456789))), ours, T0 + 10),
            Paired { name: "@alice".into(), id: 123456789 }
        );
        assert_eq!(classify_pairing_check(pairing_reply(false, None, None), ours, ours), Expired);
        assert_eq!(classify_pairing_check(pairing_reply(false, None, None), ours, T0 + 10), Invalidated);
        assert_eq!(classify_pairing_check(pairing_reply(true, Some(ours + 5), None), ours, T0 + 10), Stop);
        assert_eq!(classify_pairing_check(Ok(IpcResponse::Denied { reason: String::new() }), ours, T0), Denied);
        // no usable answer: keep asking until shortly after the expiry
        for unusable in [Err("busy".to_string()), Ok(IpcResponse::Error { message: "x".into() })] {
            assert_eq!(classify_pairing_check(unusable.clone(), ours, T0 + 10), KeepWaiting);
            assert_eq!(classify_pairing_check(unusable, ours, ours + PAIRING_GRACE_SECS), Stop);
        }
        // the check runs only while a code is active and is not frequent
        assert!(PAIRING_CHECK >= Duration::from_secs(2));
        assert!(PAIRING_TTL_SECS / PAIRING_CHECK.as_secs() <= 300);
    }

    #[test]
    fn pairing_balloons() {
        let (title, text, kind) =
            pairing_balloon(&PairingCheck::Paired { name: "@alice\nx".into(), id: 123456789 }).unwrap();
        assert_eq!(title, "Telegram account paired");
        assert!(text.starts_with("Paired: @alice x (Telegram id 123456789)"), "{text}");
        assert_eq!(kind, BalloonKind::Info);
        assert_eq!(pairing_balloon(&PairingCheck::Expired).unwrap().2, BalloonKind::Info);
        assert_eq!(pairing_balloon(&PairingCheck::Invalidated).unwrap().2, BalloonKind::Warning);
        for quiet in [PairingCheck::KeepWaiting, PairingCheck::Stop, PairingCheck::Denied] {
            assert_eq!(pairing_balloon(&quiet), None);
        }
    }

    #[test]
    fn users_dialog() {
        use crate::ipc::UserInfo;
        let users = vec![
            UserInfo { id: 123456789, name: "@alice".into(), role: "admin".into(), added_unix: T0 },
            UserInfo { id: 987654321, name: "bob\r\nInjected".into(), role: "user".into(), added_unix: 0 },
        ];
        assert_eq!(classify_users(Ok(IpcResponse::Users { users: users.clone() })), UsersFetch::Users(users.clone()));
        assert_eq!(classify_users(Ok(IpcResponse::Denied { reason: String::new() })), UsersFetch::Denied);
        assert!(matches!(classify_users(Ok(IpcResponse::Ok { message: String::new() })), UsersFetch::Failed(_)));
        assert_eq!(classify_users(Err("no pipe".into())), UsersFetch::Failed("no pipe".into()));

        let text = users_report(&users, &|_| "25 Nov 2026".to_string());
        assert!(text.starts_with("Telegram accounts that can use the bot (2 of 20):"), "{text}");
        assert!(text.contains("\n@alice · Admin · id 123456789 · added 25 Nov 2026\n"), "{text}");
        assert!(text.contains("\nbob Injected · User · id 987654321\n"), "{text}");
        assert!(text.contains("/users"));
        let empty = users_report(&[], &|_| String::new());
        assert!(empty.contains("No Telegram account is paired yet") && empty.contains("Pair Telegram User…"));

        let mut s = running();
        assert!(!s.no_telegram_user());
        if let Some(i) = s.status.as_mut() {
            i.owner_configured = false;
        }
        assert!(s.no_telegram_user());
        assert!(!state(ServiceState::Stopped).no_telegram_user(), "unknown is not 'none'");
    }
}
