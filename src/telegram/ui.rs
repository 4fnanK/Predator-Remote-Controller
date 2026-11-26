//! Message/keyboard builders for every screen of the Telegram UI (pure functions).
//!
//! Every builder returns a [`Screen`] — Telegram HTML text plus an optional inline keyboard — and
//! performs no I/O, so the whole UI is unit-testable. Every dynamic value goes through
//! [`esc`] (truncate + strip control characters + HTML-escape).
//!
//! Callback data scheme (all ≤ 64 bytes, see [`CallbackAction`]):
//! `nav:<screen>` · `ft:<feature index>` · `pw:<power action>` · `act:lock|logout` ·
//! `ts:up|down` · `cf:<nonce>` (confirm) · `cx:<nonce>` (cancel) · `um:ls` (user list) ·
//! `um:rm:<telegram user id>` (remove a user, admins only).

use super::types::{InlineKeyboardButton, InlineKeyboardMarkup};
use crate::config::{AuthorizedUser, MAX_AUTHORIZED_USERS};
use crate::context::MonitorState;
use crate::features::{Feature, FeatureSet};
use crate::notify::format::{esc, fmt_short_datetime, fmt_time_relative};
use crate::notify::{EventDetails, NotificationKind};
use crate::sys::{
    AcStatus, BatteryInfo, ConnectionType, InternetStatus, NetworkInfo, PowerAction, ServiceState, SessionInfo,
    SystemStatus, TailscaleOpResult, TailscaleStatus,
};
use crate::util::time::fmt_duration;

/// HTML text + optional inline keyboard.
pub type Screen = (String, Option<InlineKeyboardMarkup>);

/// Telegram's hard limit for `callback_data`.
pub const MAX_CALLBACK_DATA: usize = 64;
/// Longest nonce accepted in `cf:`/`cx:` callback data.
const MAX_NONCE_LEN: usize = 48;

/// Reply to unauthorized private messages (rate limited by the bot).
pub const ACCESS_DENIED: &str = "⛔ Access denied. This bot is private.";
/// Callback answer for unauthorized button presses.
pub const NOT_AUTHORIZED: &str = "⛔ Not authorized";
/// Callback alert for a used, replaced or unknown confirmation.
pub const CONFIRMATION_INVALID: &str = "This confirmation is no longer valid.";
/// Callback answer for unrecognised callback data.
pub const UNKNOWN_BUTTON: &str = "❓ Unknown button. Send /menu to open a fresh menu.";
/// Reply to an unknown slash command.
pub const UNKNOWN_COMMAND: &str = "❓ Unknown command. Send /help for the list.";
/// Reply when a Tailscale up/down is already running.
pub const TAILSCALE_BUSY: &str = "⏳ A Tailscale operation is already running.";
/// Shown instead of running a state-changing button press that Telegram delivered from its
/// backlog (pressed while PREDATOR was offline / not polling).
pub const BACKLOG_IGNORED: &str =
    "⌛ Ignored a button press that was queued while PREDATOR was offline. Press it again if you still want this.";
/// The scope of the Power Management feature (every action it gates).
pub const POWER_MANAGEMENT_SCOPE: &str = "shutdown, restart, sleep, hibernate, lock and logout";
/// Reply to a pairing code (`/pair CODE`, `/start pair-CODE`) from an account that is paired.
pub const ALREADY_PAIRED: &str = "ℹ️ You are already paired.";
/// Callback alert when a non-admin presses a remove button.
pub const ONLY_ADMINS: &str = "Only admins can remove users.";
/// Callback alert for an admin pressing remove on their own entry.
pub const CANNOT_REMOVE_SELF: &str = "You cannot remove your own account here. Ask another admin, or remove it on the PC \
     (PredatorRemoteController.exe → Telegram users, or 'predator-service users remove ID').";
/// How a new account is added (help, user list, `/pair` from a paired account).
pub const HOW_TO_PAIR: &str = "To add a Telegram account, start pairing on the PC (tray menu <b>Pair Telegram \
                               User…</b> or the setup menu), then send <code>/pair CODE</code> from the new account \
                               — or open the link shown on the PC.";

// Field limits (characters, before escaping).
const MAX_SHORT: usize = 64;
const MAX_MEDIUM: usize = 128;
const MAX_LONG: usize = 300;
const MAX_SESSIONS: usize = 10;
const MAX_HEALTH: usize = 3;
const MAX_STEPS: usize = 12;

// ───────────────────────────── callback data ─────────────────────────────

/// Screens reachable through `nav:*` callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Nav {
    Main,
    Status,
    Network,
    Battery,
    History,
    Features,
    Tailscale,
    Help,
}

impl Nav {
    pub const ALL: [Nav; 8] =
        [Nav::Main, Nav::Status, Nav::Network, Nav::Battery, Nav::History, Nav::Features, Nav::Tailscale, Nav::Help];

    /// Callback data (`nav:main`, ...).
    pub fn data(self) -> &'static str {
        match self {
            Nav::Main => "nav:main",
            Nav::Status => "nav:status",
            Nav::Network => "nav:net",
            Nav::Battery => "nav:bat",
            Nav::History => "nav:hist",
            Nav::Features => "nav:feat",
            Nav::Tailscale => "nav:ts",
            Nav::Help => "nav:help",
        }
    }

    pub fn from_data(data: &str) -> Option<Nav> {
        Self::ALL.iter().copied().find(|n| n.data() == data)
    }
}

/// Every action a button can trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackAction {
    Nav(Nav),
    ToggleFeature(Feature),
    /// Request a power action (shows the confirmation dialog).
    Power(PowerAction),
    Lock,
    Logout,
    TailscaleUp,
    TailscaleDown,
    /// Confirm the pending power action with this nonce.
    Confirm(String),
    /// Cancel the pending power action with this nonce.
    Cancel(String),
    /// Show (refresh) the list of authorized Telegram users.
    UsersRefresh,
    /// Remove this Telegram user id from the authorized users (admins only, immediate).
    RemoveUser(i64),
}

fn is_nonce(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NONCE_LEN && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A positive Telegram user id written as plain digits (no sign, no leading zero).
fn parse_user_id(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 19 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok().filter(|id| *id > 0)
}

impl CallbackAction {
    /// Serialized callback data.
    pub fn data(&self) -> String {
        match self {
            CallbackAction::Nav(n) => n.data().to_string(),
            CallbackAction::ToggleFeature(f) => format!("ft:{}", f.index()),
            CallbackAction::Power(a) => format!("pw:{}", a.key()),
            CallbackAction::Lock => "act:lock".into(),
            CallbackAction::Logout => "act:logout".into(),
            CallbackAction::TailscaleUp => "ts:up".into(),
            CallbackAction::TailscaleDown => "ts:down".into(),
            CallbackAction::Confirm(n) => format!("cf:{n}"),
            CallbackAction::Cancel(n) => format!("cx:{n}"),
            CallbackAction::UsersRefresh => "um:ls".into(),
            CallbackAction::RemoveUser(id) => format!("um:rm:{id}"),
        }
    }

    /// Strict parser: anything malformed or unknown yields `None`.
    pub fn parse(data: &str) -> Option<CallbackAction> {
        if data.is_empty() || data.len() > MAX_CALLBACK_DATA {
            return None;
        }
        let (prefix, rest) = data.split_once(':')?;
        match prefix {
            "nav" => Nav::from_data(data).map(CallbackAction::Nav),
            "ft" => {
                if rest.is_empty() || rest.len() > 2 || !rest.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                rest.parse::<usize>().ok().and_then(Feature::from_index).map(CallbackAction::ToggleFeature)
            }
            "pw" => PowerAction::from_key(rest).map(CallbackAction::Power),
            "act" => match rest {
                "lock" => Some(CallbackAction::Lock),
                "logout" => Some(CallbackAction::Logout),
                _ => None,
            },
            "ts" => match rest {
                "up" => Some(CallbackAction::TailscaleUp),
                "down" => Some(CallbackAction::TailscaleDown),
                _ => None,
            },
            "cf" if is_nonce(rest) => Some(CallbackAction::Confirm(rest.to_string())),
            "cx" if is_nonce(rest) => Some(CallbackAction::Cancel(rest.to_string())),
            "um" => match rest.split_once(':') {
                None if rest == "ls" => Some(CallbackAction::UsersRefresh),
                Some(("rm", id)) => parse_user_id(id).map(CallbackAction::RemoveUser),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether pressing this button changes something on the PC or in the settings (or starts
    /// doing so, like opening a power confirmation). Such presses are refused when Telegram
    /// delivers them from its backlog. Navigation and cancelling a confirmation are harmless.
    pub fn changes_state(&self) -> bool {
        match self {
            CallbackAction::Nav(_) | CallbackAction::Cancel(_) | CallbackAction::UsersRefresh => false,
            CallbackAction::ToggleFeature(_)
            | CallbackAction::Power(_)
            | CallbackAction::Lock
            | CallbackAction::Logout
            | CallbackAction::TailscaleUp
            | CallbackAction::TailscaleDown
            | CallbackAction::Confirm(_)
            | CallbackAction::RemoveUser(_) => true,
        }
    }

    /// Callback data for log lines; confirmation nonces are never logged.
    pub fn log_label(&self) -> String {
        match self {
            CallbackAction::Confirm(_) => "cf:…".into(),
            CallbackAction::Cancel(_) => "cx:…".into(),
            other => other.data(),
        }
    }
}

fn btn(text: &str, action: CallbackAction) -> InlineKeyboardButton {
    InlineKeyboardButton::callback(text, action.data())
}

fn nav_btn(text: &str, nav: Nav) -> InlineKeyboardButton {
    InlineKeyboardButton::callback(text, nav.data())
}

/// `[🔄 Refresh] [⬅️ Back]` for sub-screens.
fn refresh_back_row(nav: Nav) -> Vec<InlineKeyboardButton> {
    vec![nav_btn("🔄 Refresh", nav), nav_btn("⬅️ Back", Nav::Main)]
}

fn back_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![vec![nav_btn("⬅️ Back", Nav::Main)]])
}

/// Single `[🏠 Main menu]` button.
pub fn menu_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![vec![nav_btn("🏠 Main menu", Nav::Main)]])
}

fn refresh_back_keyboard(nav: Nav) -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![refresh_back_row(nav)])
}

// ───────────────────────────── shared helpers ─────────────────────────────

fn monitor_badge(m: &MonitorState) -> &'static str {
    match m {
        MonitorState::Active => "🟢 Active",
        MonitorState::Starting => "🟡 Starting",
        MonitorState::Disabled => "⚪ Disabled",
        MonitorState::Error(_) => "🔴 Error",
    }
}

fn monitor_detail(m: &MonitorState) -> String {
    match m {
        MonitorState::Error(e) => format!("🔴 Error: {}", esc(e, MAX_LONG)),
        other => monitor_badge(other).to_string(),
    }
}

fn telegram_badge(label: &str) -> String {
    match label {
        "online" => "🟢 Online".into(),
        "offline" => "🔴 Offline".into(),
        "invalid token" => "🔴 Invalid token".into(),
        other => esc(other, MAX_SHORT),
    }
}

/// Human duration between two unix times (`unknown` if inconsistent).
fn since(start: i64, now: i64) -> String {
    if start <= 0 || start > now { "unknown".into() } else { fmt_duration((now - start) as u64) }
}

fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

fn cpu_time(ms: u64) -> String {
    if ms < 60_000 { format!("{:.1} s", ms as f64 / 1000.0) } else { fmt_duration(ms / 1000) }
}

/// `5 minutes`, `1 minute`, `90 seconds`.
pub fn fmt_span_words(secs: u64) -> String {
    if secs >= 60 && secs.is_multiple_of(60) {
        let m = secs / 60;
        if m == 1 { "1 minute".into() } else { format!("{m} minutes") }
    } else if secs == 1 {
        "1 second".into()
    } else {
        format!("{secs} seconds")
    }
}

fn dry_run_banner() -> &'static str {
    "🧪 <i>DRY-RUN mode — power, lock, logout and Tailscale up/down are simulated.</i>"
}

// ───────────────────────────── main menu ─────────────────────────────

/// Data shown in the main menu header.
#[derive(Clone, Debug, Default)]
pub struct MenuView {
    pub computer: String,
    pub boot_unix: i64,
    pub service_start_unix: i64,
    pub now_unix: i64,
    pub security: MonitorState,
    pub ssh: MonitorState,
    pub queued: usize,
    pub dry_run: bool,
}

/// The main menu keyboard (exact layout of the spec).
pub fn main_keyboard() -> InlineKeyboardMarkup {
    use CallbackAction as A;
    InlineKeyboardMarkup::new(vec![
        vec![nav_btn("📊 System Status", Nav::Status)],
        vec![nav_btn("🌐 Network", Nav::Network), nav_btn("🔋 Battery", Nav::Battery)],
        vec![nav_btn("📜 Login History", Nav::History), nav_btn("⚙️ Features", Nav::Features)],
        vec![btn("⏻ Shutdown", A::Power(PowerAction::Shutdown)), btn("🔄 Restart", A::Power(PowerAction::Restart))],
        vec![btn("💤 Sleep", A::Power(PowerAction::Sleep)), btn("🌙 Hibernate", A::Power(PowerAction::Hibernate))],
        vec![btn("🔒 Lock", A::Lock), btn("🚪 Logout", A::Logout)],
        vec![nav_btn("🛡 Tailscale", Nav::Tailscale)],
        vec![nav_btn("❓ Help", Nav::Help)],
    ])
}

pub fn main_menu(v: &MenuView) -> Screen {
    let mut s = String::with_capacity(400);
    s.push_str("🖥 <b>PREDATOR REMOTE CONTROL</b>\n━━━━━━━━━━━━━━━━━━\n");
    s.push_str(&format!("🟢 <b>Online</b> · <code>{}</code>\n", esc(&v.computer, MAX_SHORT)));
    s.push_str(&format!(
        "⏱ Uptime: {} · Service: {}\n",
        since(v.boot_unix, v.now_unix),
        since(v.service_start_unix, v.now_unix)
    ));
    s.push_str(&format!("🔐 Login monitor: {} · SSH: {}\n", monitor_badge(&v.security), monitor_badge(&v.ssh)));
    s.push_str(&format!("📬 Queued alerts: {}", v.queued));
    if v.dry_run {
        s.push_str("\n\n");
        s.push_str(dry_run_banner());
    }
    (s, Some(main_keyboard()))
}

// ───────────────────────────── system status ─────────────────────────────

/// Everything the System Status screen shows.
#[derive(Clone, Debug, Default)]
pub struct StatusView {
    pub sys: SystemStatus,
    /// `RuntimeStatus::telegram_label()`.
    pub telegram: String,
    pub security: MonitorState,
    pub ssh: MonitorState,
    pub audit_policy: Option<String>,
    pub queued: usize,
    pub delivered: u64,
    pub dry_run: bool,
    pub now_unix: i64,
    pub version: String,
}

fn station_label(station: &str) -> String {
    let s = station.trim();
    if s.eq_ignore_ascii_case("console") {
        "Console".into()
    } else if s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("rdp")) {
        "RDP".into()
    } else if s.is_empty() {
        "Unknown".into()
    } else {
        esc(s, MAX_SHORT)
    }
}

fn session_line(si: &SessionInfo) -> String {
    let user = if si.user.trim().is_empty() { "(no user)" } else { si.user.as_str() };
    let mut line = format!("• {} · {} · {}", esc(user, MAX_SHORT), station_label(&si.station), esc(&si.state, 32));
    if let Some(addr) = si.client_address.as_deref().filter(|a| !a.trim().is_empty()) {
        line.push_str(&format!(" · from {}", esc(addr, MAX_SHORT)));
    }
    if si.locked == Some(true) {
        line.push_str(" · 🔒");
    }
    line
}

pub fn status_screen(v: &StatusView) -> Screen {
    let st = &v.sys;
    let mut s = String::with_capacity(1024);
    s.push_str("📊 <b>SYSTEM STATUS</b>\n");
    if v.dry_run {
        s.push('\n');
        s.push_str(dry_run_banner());
        s.push('\n');
    }
    s.push_str(&format!("\n🖥 Computer: <code>{}</code>", esc(&st.computer, MAX_SHORT)));
    let os = if st.os_version.trim().is_empty() { "Windows (version unknown)" } else { st.os_version.as_str() };
    s.push_str(&format!("\n🪟 OS: {}", esc(os, MAX_MEDIUM)));
    s.push_str(&format!("\n⏱ Uptime: {}", since(st.boot_unix, v.now_unix)));
    let service_line = format!("\n⚙️ Service uptime: {}", since(st.service_start_unix, v.now_unix));
    s.push_str(&service_line);
    if !v.version.is_empty() {
        s.push_str(&format!(" · v{}", esc(&v.version, 32)));
    }
    s.push_str(&format!(
        "\n💾 Service RAM: {} private · {} working set",
        mb(st.service_private_bytes),
        mb(st.service_working_set_bytes)
    ));
    s.push_str(&format!("\n🧮 Service CPU time: {}", cpu_time(st.service_cpu_ms)));
    s.push_str(&format!("\n📡 Telegram: {}", telegram_badge(&v.telegram)));
    s.push_str(&format!("\n🔐 Login monitor: {}", monitor_detail(&v.security)));
    s.push_str(&format!("\n🔑 SSH monitor: {}", monitor_detail(&v.ssh)));
    let audit = v.audit_policy.as_deref().filter(|a| !a.trim().is_empty()).unwrap_or("unknown");
    s.push_str(&format!("\n📋 Audit policy: {}", esc(audit, MAX_LONG)));
    s.push_str(&format!("\n📬 Queued alerts: {} · Delivered: {}", v.queued, v.delivered));

    s.push_str("\n\n👥 <b>Sessions</b>");
    if st.sessions.is_empty() {
        s.push_str("\n• No user is logged in.");
    } else {
        for si in st.sessions.iter().take(MAX_SESSIONS) {
            s.push('\n');
            s.push_str(&session_line(si));
        }
        if st.sessions.len() > MAX_SESSIONS {
            s.push_str(&format!("\n• … and {} more", st.sessions.len() - MAX_SESSIONS));
        }
    }
    (s, Some(refresh_back_keyboard(Nav::Status)))
}

// ───────────────────────────── network ─────────────────────────────

fn connection_label(c: &ConnectionType) -> String {
    match c {
        ConnectionType::WiFi => "Wi-Fi".into(),
        ConnectionType::Ethernet => "Ethernet".into(),
        ConnectionType::Cellular => "Cellular".into(),
        ConnectionType::Other(d) if !d.trim().is_empty() => esc(d, MAX_SHORT),
        ConnectionType::Other(_) => "Other".into(),
        ConnectionType::None => "None (not connected)".into(),
    }
}

fn internet_label(i: InternetStatus) -> &'static str {
    match i {
        InternetStatus::Connected => "🟢 Connected",
        InternetStatus::LocalOnly => "🟡 Local network only",
        InternetStatus::CaptivePortal => "🟡 Captive portal (sign-in required)",
        InternetStatus::Disconnected => "🔴 Disconnected",
        InternetStatus::Unknown => "⚪ Unknown",
    }
}

pub fn network_screen(r: &Result<NetworkInfo, String>) -> Screen {
    let mut s = String::from("🌐 <b>NETWORK STATUS</b>\n");
    match r {
        Ok(n) => {
            s.push_str(&format!("\nConnection: {}", connection_label(&n.connection)));
            if n.connection == ConnectionType::WiFi {
                match n.ssid.as_deref().filter(|x| !x.is_empty()) {
                    Some(ssid) => s.push_str(&format!("\nSSID: {}", esc(ssid, MAX_SHORT))),
                    None => {
                        let note = n.ssid_note.as_deref().filter(|x| !x.trim().is_empty()).unwrap_or("unavailable");
                        s.push_str(&format!("\nSSID: <i>{}</i>", esc(note, MAX_LONG)));
                    }
                }
            }
            let ip = n.ipv4.as_deref().filter(|x| !x.trim().is_empty()).unwrap_or("not available");
            s.push_str(&format!("\nIP Address: {}", esc(ip, MAX_SHORT)));
            s.push_str(&format!("\nInternet: {}", internet_label(n.internet)));
            if let Some(vpn) = n.vpn.as_deref().filter(|x| !x.trim().is_empty()) {
                s.push_str(&format!("\nVPN: {}", esc(vpn, MAX_SHORT)));
            }
        }
        Err(e) => s.push_str(&format!("\n❌ Could not read the network status: {}", esc(e, MAX_LONG))),
    }
    (s, Some(refresh_back_keyboard(Nav::Network)))
}

// ───────────────────────────── battery ─────────────────────────────

fn remaining(secs: u32) -> String {
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    if h > 0 { format!("{h}h {m}m") } else { format!("{m}m") }
}

pub fn battery_screen(r: &Result<BatteryInfo, String>) -> Screen {
    let mut s = String::from("🔋 <b>BATTERY STATUS</b>\n");
    match r {
        Ok(b) if !b.present => s.push_str("\n🔌 No battery detected — this PC runs on AC power."),
        Ok(b) => {
            let pct = b.percent.map(|p| format!("{}%", p.min(100))).unwrap_or_else(|| "unknown".into());
            s.push_str(&format!("\nBattery: {pct}"));
            let status = if b.full {
                "Fully charged".to_string()
            } else if b.charging {
                "Charging".to_string()
            } else if b.ac == AcStatus::Connected {
                "Not charging (plugged in)".to_string()
            } else {
                match b.seconds_left {
                    Some(left) if left > 0 => format!("Discharging (≈ {} left)", remaining(left)),
                    _ => "Discharging".to_string(),
                }
            };
            s.push_str(&format!("\nStatus: {status}"));
            let power = match b.ac {
                AcStatus::Connected => "AC Connected",
                AcStatus::Disconnected => "On battery",
                AcStatus::Unknown => "Unknown",
            };
            s.push_str(&format!("\nPower: {power}"));
            if b.battery_saver {
                s.push_str("\nBattery saver: On");
            }
        }
        Err(e) => s.push_str(&format!("\n❌ Could not read the battery status: {}", esc(e, MAX_LONG))),
    }
    (s, Some(refresh_back_keyboard(Nav::Battery)))
}

// ───────────────────────────── login history ─────────────────────────────

/// One compact history line, e.g. `🟢 25 Nov 14:30 · alice · Interactive`.
pub fn history_line(e: &EventDetails) -> String {
    let when = fmt_short_datetime(e.event_unix);
    let user = if e.user.trim().is_empty() { "unknown" } else { e.user.as_str() };
    let user = esc(user, 40);
    let ip = e.source_ip.as_deref().filter(|x| !x.trim().is_empty()).map(|x| esc(x, 45));
    let method = if e.method.trim().is_empty() { "login".to_string() } else { esc(&e.method, 40) };
    let with_ip = |base: String| match &ip {
        Some(ip) => format!("{base} · {ip}"),
        None => base,
    };
    match e.kind {
        NotificationKind::Login => with_ip(format!("🟢 {when} · {user} · {method}")),
        NotificationKind::FailedLogin => with_ip(format!("🔴 {when} · {user} · failed")),
        NotificationKind::Logout => format!("🚪 {when} · {user} · logout"),
        NotificationKind::SshLogin => match &ip {
            Some(ip) => format!("🔐 {when} · {user} · SSH {ip}"),
            None => format!("🔐 {when} · {user} · SSH"),
        },
        NotificationKind::SshFailed => match &ip {
            Some(ip) => format!("🔴 {when} · {user} · SSH failed {ip}"),
            None => format!("🔴 {when} · {user} · SSH failed"),
        },
        NotificationKind::SshLogout => format!("🚪 {when} · {user} · SSH logout"),
        NotificationKind::System | NotificationKind::Security => format!("ℹ️ {when} · {user} · {method}"),
    }
}

/// `entries` newest first (callers pass `LoginHistory::recent(10)`).
pub fn history_screen(entries: &[EventDetails]) -> Screen {
    let mut s = String::from("📜 <b>LOGIN HISTORY</b>\n");
    if entries.is_empty() {
        s.push_str("\n<i>No login events recorded yet.</i>");
    } else {
        s.push_str(&format!("<i>Last {} events, newest first</i>\n", entries.len()));
        for e in entries {
            s.push('\n');
            s.push_str(&history_line(e));
        }
    }
    (s, Some(refresh_back_keyboard(Nav::History)))
}

// ───────────────────────────── features ─────────────────────────────

fn dot(on: bool) -> &'static str {
    if on { "🟢" } else { "🔴" }
}

pub fn features_keyboard(fs: &FeatureSet) -> InlineKeyboardMarkup {
    let buttons: Vec<InlineKeyboardButton> = fs
        .iter()
        .map(|(f, on)| btn(&format!("{} {}", dot(on), f.short_label()), CallbackAction::ToggleFeature(f)))
        .collect();
    let mut rows: Vec<Vec<InlineKeyboardButton>> = buttons.chunks(2).map(<[InlineKeyboardButton]>::to_vec).collect();
    rows.push(vec![nav_btn("⬅️ Back", Nav::Main)]);
    InlineKeyboardMarkup::new(rows)
}

pub fn features_screen(fs: &FeatureSet) -> Screen {
    let mut s = String::from("⚙️ <b>PREDATOR FEATURES</b>\n");
    for (f, on) in fs.iter() {
        s.push_str(&format!("\n{} {}", dot(on), f.label()));
    }
    s.push_str("\n\n<i>Tap a button to switch a feature on or off (takes effect immediately).</i>");
    s.push_str(&format!("\n<i>{} covers {POWER_MANAGEMENT_SCOPE}.</i>", Feature::PowerManagement.label()));
    (s, Some(features_keyboard(fs)))
}

/// Callback answer after a toggle, e.g. `SSH Monitoring disabled`.
pub fn feature_toggled_text(f: Feature, on: bool) -> String {
    format!("{} {}", f.label(), if on { "enabled" } else { "disabled" })
}

/// Rejection for a command/button whose feature is switched off.
pub fn disabled_screen(f: Feature) -> Screen {
    let kb =
        InlineKeyboardMarkup::new(vec![vec![nav_btn("⚙️ Features", Nav::Features), nav_btn("⬅️ Back", Nav::Main)]]);
    (format!("🚫 <b>{} is disabled.</b>\nEnable it in /features.", f.label()), Some(kb))
}

// ───────────────────────────── tailscale ─────────────────────────────

/// Why Tailscale cannot be connected because its Windows service is not running, e.g.
/// `stopped`; `None` while the service runs (or its state is unknown). `sys::tailscale` reports
/// a non-running service as a backend state such as `Service stopped`, which is recognised too.
fn tailscale_service_down(st: &TailscaleStatus) -> Option<String> {
    let reason = match st.service {
        ServiceState::Running | ServiceState::Unknown => None,
        ServiceState::Stopped => Some("stopped"),
        ServiceState::StartPending => Some("starting"),
        ServiceState::StopPending => Some("stopping"),
        ServiceState::Paused => Some("paused"),
        ServiceState::NotInstalled => Some("not installed"),
    };
    if let Some(r) = reason {
        return Some(r.to_string());
    }
    // "Service stopped", "Service not installed", ... (never a real tailscaled BackendState).
    let backend = st.backend_state.as_deref().map(str::trim).unwrap_or_default();
    let (head, rest) = (backend.get(..7)?, backend.get(7..)?);
    if !head.eq_ignore_ascii_case("service") || !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
        return None;
    }
    let rest = rest.trim();
    Some(if rest.is_empty() { "stopped".to_string() } else { esc(&rest.to_lowercase(), 32) })
}

/// The `Connection:` line. 🔴 whenever the Tailscale service is not running (also right after a
/// successful `/tailscale down`); 🟡 only for states that resolve themselves or need a user
/// (starting, connecting, needs login/approval) while the service runs.
fn tailscale_connection(st: &TailscaleStatus) -> String {
    if let Some(why) = tailscale_service_down(st) {
        return format!("🔴 Disconnected (Tailscale service {why})");
    }
    if st.connected {
        return "🟢 Connected".into();
    }
    match st.backend_state.as_deref().map(str::trim) {
        Some("Running") => "🟢 Connected".into(),
        Some("Stopped") => "🔴 Disconnected".into(),
        Some("NeedsLogin") => "🟡 Needs login".into(),
        Some("NeedsMachineAuth") => "🟡 Needs admin approval (tailnet admin must approve this device)".into(),
        Some("InUseOtherUser") => "🟡 In use by another Windows user".into(),
        Some("Starting") => "🟡 Starting…".into(),
        Some("NoState") => "🟡 Connecting…".into(),
        Some(other) if !other.is_empty() => format!("⚪ {}", esc(other, 32)),
        _ => {
            if st.service == ServiceState::Running {
                "⚪ Unknown".into()
            } else {
                "🔴 Disconnected".into()
            }
        }
    }
}

/// The `App:` line: is the Tailscale app (`tailscale-ipn.exe`, which connects tailscaled for the
/// logged-on user) running?
fn tailscale_app(st: &TailscaleStatus) -> &'static str {
    if st.app_running { "🟢 Running" } else { "⚪ Not running" }
}

fn tailscale_body(st: &TailscaleStatus) -> String {
    let mut s = String::new();
    if !st.installed {
        s.push_str("\nInstalled: ❌ No — Tailscale is not installed on this PC.");
        if let Some(e) = st.error.as_deref().filter(|e| !e.trim().is_empty()) {
            s.push_str(&format!("\n❗ {}", esc(e, MAX_LONG)));
        }
        return s;
    }
    match st.version.as_deref().filter(|v| !v.trim().is_empty()) {
        Some(v) => s.push_str(&format!("\nInstalled: ✅ Yes (v{})", esc(v, 32))),
        None => s.push_str("\nInstalled: ✅ Yes"),
    }
    s.push_str(&format!("\nService: {}", st.service.label()));
    s.push_str(&format!("\nApp: {}", tailscale_app(st)));
    s.push_str(&format!("\nConnection: {}", tailscale_connection(st)));
    if let Some(ip) = st.ipv4.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!("\nTailscale IP: <code>{}</code>", esc(ip, MAX_SHORT)));
    }
    if let Some(h) = st.hostname.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!("\nHostname: <code>{}</code>", esc(h, MAX_SHORT)));
    }
    if let Some(t) = st.tailnet.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!("\nTailnet: {}", esc(t, MAX_SHORT)));
    }
    let health: Vec<&String> = st.health.iter().filter(|h| !h.trim().is_empty()).collect();
    if !health.is_empty() {
        s.push_str("\n⚠️ Health:");
        for h in health.iter().take(MAX_HEALTH) {
            s.push_str(&format!("\n• {}", esc(h, MAX_LONG)));
        }
        if health.len() > MAX_HEALTH {
            s.push_str(&format!("\n• … and {} more", health.len() - MAX_HEALTH));
        }
    }
    if let Some(url) = st.auth_url.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!(
            "\n🔗 Login URL: {}\n<i>Whoever opens this link binds this PC to their tailnet.</i>",
            esc(url, MAX_LONG)
        ));
    }
    if let Some(e) = st.error.as_deref().filter(|e| !e.trim().is_empty()) {
        s.push_str(&format!("\n❗ {}", esc(e, MAX_LONG)));
    }
    s
}

pub fn tailscale_keyboard(st: &TailscaleStatus) -> InlineKeyboardMarkup {
    let mut rows = Vec::with_capacity(2);
    if st.installed {
        rows.push(vec![btn("▶️ Up", CallbackAction::TailscaleUp), btn("⏹ Down", CallbackAction::TailscaleDown)]);
    }
    rows.push(refresh_back_row(Nav::Tailscale));
    InlineKeyboardMarkup::new(rows)
}

pub fn tailscale_screen(st: &TailscaleStatus) -> Screen {
    let mut s = String::from("🛡 <b>TAILSCALE</b>\n");
    s.push_str(&tailscale_body(st));
    (s, Some(tailscale_keyboard(st)))
}

/// `⏳ Bringing Tailscale up…` (no keyboard while the worker runs).
pub fn tailscale_progress(up: bool) -> Screen {
    (format!("⏳ Bringing Tailscale {}…", if up { "up" } else { "down" }), None)
}

pub fn tailscale_result(up: bool, r: &TailscaleOpResult) -> Screen {
    let dir = if up { "up" } else { "down" };
    let mut s = if r.success {
        format!("✅ <b>Tailscale {dir} completed</b>\n")
    } else {
        format!("❌ <b>Tailscale {dir} failed</b>\n")
    };
    if !r.steps.is_empty() {
        for step in r.steps.iter().take(MAX_STEPS) {
            s.push_str(&format!("\n{}", esc(step, MAX_LONG)));
        }
        if r.steps.len() > MAX_STEPS {
            s.push_str(&format!("\n… and {} more steps", r.steps.len() - MAX_STEPS));
        }
        s.push('\n');
    }
    if let Some(e) = r.error.as_deref().filter(|e| !e.trim().is_empty()) {
        s.push_str(&format!("\n❗ {}\n", esc(e, MAX_LONG)));
    }
    s.push_str("\n<b>Current status</b>");
    s.push_str(&tailscale_body(&r.status));
    (s, Some(tailscale_keyboard(&r.status)))
}

/// Shown when the worker could not run at all.
pub fn tailscale_failed(up: bool, error: &str) -> Screen {
    (
        format!("❌ <b>Tailscale {} failed</b>\n\n{}", if up { "up" } else { "down" }, esc(error, MAX_LONG)),
        Some(refresh_back_keyboard(Nav::Tailscale)),
    )
}

/// `/tailscale` with an unknown sub-command.
pub fn tailscale_usage() -> Screen {
    (
        "ℹ️ Usage: <code>/tailscale</code>, <code>/tailscale status</code>, <code>/tailscale up</code> or \
         <code>/tailscale down</code>."
            .into(),
        None,
    )
}

// ───────────────────────────── help ─────────────────────────────

pub fn help_screen(confirm_secs: u64, stale_secs: u64) -> Screen {
    help_screen_with(confirm_secs, stale_secs, None)
}

/// The "Chat" section of the help: what is cleaned automatically (`clean_after` = seconds of
/// inactivity, `None` when automatic cleaning is switched off) and what is always kept.
fn chat_help(clean_after: Option<u64>) -> String {
    match clean_after {
        Some(secs) => format!(
            "/clear — delete menus, replies and your commands from this chat now\n\
             <i>🧹 They are also deleted automatically when you send the next command or after {} without \
             use, like status notices (online, offline …). Login, logout and security alerts are always kept.</i>",
            fmt_span_words(secs)
        ),
        None => "/clear — delete menus and replies from this chat\n\
                 🧹 Automatic chat cleaning is switched off (<code>auto_clean_chat</code> in settings.json)."
            .to_string(),
    }
}

/// Help screen; `clean_after` describes the automatic chat cleaning (see [`chat_help`]).
pub fn help_screen_with(confirm_secs: u64, stale_secs: u64, clean_after: Option<u64>) -> Screen {
    let s = format!(
        "❓ <b>HELP — PREDATOR REMOTE CONTROL</b>\n\
         \n<b>Information</b>\n\
         /menu — control panel with buttons\n\
         /status — system status\n\
         /network — network information\n\
         /battery — battery status\n\
         /history — last 10 login events\n\
         /features — switch features on or off\n\
         \n<b>Power</b> (asks for confirmation)\n\
         /shutdown · /restart · /sleep · /hibernate\n\
         /cancel — cancel a pending confirmation\n\
         \n<b>Session</b> (immediate)\n\
         /lock — lock the PC\n\
         /logout — log off the active user\n\
         <i>The {power} feature covers {scope}: switching it off disables all six.</i>\n\
         \n<b>Tailscale</b> ({tailscale} feature)\n\
         /tailscale — status with Up/Down buttons\n\
         /tailscale status · /tailscale up · /tailscale down\n\
         \n<b>Users</b>\n\
         /users — paired Telegram accounts (admins can remove them)\n\
         /pair CODE — pair a new account with the code shown on the PC\n\
         <i>{how_to_pair}</i>\n\
         \n<b>Chat</b>\n\
         {chat}\n\
         \n<b>Confirmation policy</b>\n\
         Only shutdown, restart, sleep and hibernate ask for confirmation; a confirmation expires after {confirm} \
         and can only be confirmed by the user who asked for it. Everything else (lock, logout, Tailscale, \
         feature switches, removing a user) runs immediately.\n\
         \n<b>Security</b>\n\
         🔐 Only paired Telegram accounts (checked by numeric user ID) can use this bot. Everyone else is \
         refused and reported to every paired user. Commands that change something are ignored when they are \
         older than {stale} (for example, sent while the PC was offline). Button presses that change something \
         are ignored when Telegram delivers them late, after PREDATOR was offline — press them again.",
        power = Feature::PowerManagement.label(),
        scope = POWER_MANAGEMENT_SCOPE,
        tailscale = Feature::TailscaleManagement.label(),
        how_to_pair = HOW_TO_PAIR,
        chat = chat_help(clean_after),
        confirm = fmt_span_words(confirm_secs),
        stale = fmt_span_words(stale_secs),
    );
    (s, Some(back_keyboard()))
}

// ───────────────────────────── users / pairing ─────────────────────────────

/// Longest user name inside a button label (button texts are plain text, not HTML).
const MAX_BUTTON_NAME: usize = 32;

fn user_line(u: &AuthorizedUser, viewer: i64) -> String {
    let badge = if u.role.is_admin() { "👑" } else { "👤" };
    let added = if u.added_unix > 0 {
        format!(" · added {}", crate::util::time::fmt_date(u.added_unix))
    } else {
        String::new()
    };
    let you = if u.id == viewer { " <i>(you)</i>" } else { "" };
    format!("{badge} <b>{}</b> · <code>{}</code> · {}{added}{you}", esc(&u.label(), MAX_SHORT), u.id, u.role.label())
}

/// `/users`: every authorized account (`name · id · role · added date`). An admin `viewer` gets
/// one `🗑 Remove <name>` button (`um:rm:<id>`) per OTHER user; everyone gets Refresh + Back.
pub fn users_screen(users: &[AuthorizedUser], viewer: i64) -> Screen {
    let viewer_is_admin = users.iter().any(|u| u.id == viewer && u.role.is_admin());
    let mut s = format!("👥 <b>TELEGRAM USERS</b> ({} of {MAX_AUTHORIZED_USERS})\n", users.len());
    if users.is_empty() {
        s.push_str("\n<i>Nobody is paired.</i>");
    }
    for u in users {
        s.push('\n');
        s.push_str(&user_line(u, viewer));
    }
    s.push_str("\n\n<i>Every user can use every command; admins can also remove users. ");
    s.push_str(if viewer_is_admin {
        "Removing takes effect at once. The last admin cannot be removed.</i>"
    } else {
        "Ask an admin to remove an account.</i>"
    });
    s.push_str(&format!("\n<i>{HOW_TO_PAIR}</i>"));
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    if viewer_is_admin {
        for u in users.iter().filter(|u| u.id != viewer) {
            let name = crate::util::truncate_chars(&u.label(), MAX_BUTTON_NAME);
            rows.push(vec![btn(&format!("🗑 Remove {name}"), CallbackAction::RemoveUser(u.id))]);
        }
    }
    rows.push(vec![btn("🔄 Refresh", CallbackAction::UsersRefresh), nav_btn("⬅️ Back", Nav::Main)]);
    (s, Some(InlineKeyboardMarkup::new(rows)))
}

/// Reply to a successful pairing.
pub fn paired_screen(computer: &str) -> Screen {
    (
        format!("✅ Paired with {}. Send /menu to start.", esc(computer, MAX_SHORT)),
        Some(InlineKeyboardMarkup::new(vec![vec![nav_btn("🏠 Open Menu", Nav::Main)]])),
    )
}

/// Reply to `/pair …` (or a pairing deep link) from an account that is already paired.
pub fn already_paired_screen() -> Screen {
    (format!("{ALREADY_PAIRED}\n\n<i>{HOW_TO_PAIR}</i>"), Some(menu_keyboard()))
}

// ───────────────────────────── power confirmation ─────────────────────────────

fn power_warning(action: PowerAction) -> &'static str {
    match action {
        PowerAction::Shutdown | PowerAction::Restart => "Open apps will be closed. Unsaved work may be lost.",
        PowerAction::Sleep => "The PC will be unreachable until it wakes up.",
        PowerAction::Hibernate => {
            "The PC will save its state to disk and power off; it is unreachable until it is switched on."
        }
    }
}

/// The confirmation dialog (`[✅ Confirm Shutdown] [❌ Cancel]`).
pub fn confirm_screen(action: PowerAction, computer: &str, timeout_secs: u64, nonce: &str) -> Screen {
    let s = format!(
        "⚠️ <b>CONFIRM {}</b>\n\n🖥 Computer: <code>{}</code>\n{}\n⏳ Expires in {}.",
        action.label().to_uppercase(),
        esc(computer, MAX_SHORT),
        power_warning(action),
        fmt_span_words(timeout_secs),
    );
    let kb = InlineKeyboardMarkup::new(vec![vec![
        btn(&format!("✅ Confirm {}", action.label()), CallbackAction::Confirm(nonce.to_string())),
        btn("❌ Cancel", CallbackAction::Cancel(nonce.to_string())),
    ]]);
    (s, Some(kb))
}

/// Shown between confirmation and the system call.
pub fn power_progress(action: PowerAction) -> Screen {
    let s = match action {
        PowerAction::Shutdown => "⏳ Shutting down…",
        PowerAction::Restart => "⏳ Restarting…",
        PowerAction::Sleep => "⏳ Going to sleep…",
        PowerAction::Hibernate => "⏳ Hibernating…",
    };
    (s.into(), None)
}

/// Final message after `execute_power`.
pub fn power_result(
    action: PowerAction,
    computer: &str,
    grace_secs: u32,
    r: &Result<String, String>,
    dry_run: bool,
) -> Screen {
    let pc = esc(computer, MAX_SHORT);
    match r {
        Ok(msg) if dry_run => (format!("🧪 <b>DRY-RUN</b>\n{}", esc(msg, MAX_LONG)), Some(menu_keyboard())),
        Ok(_) => {
            let s = match action {
                PowerAction::Shutdown => {
                    format!("✅ Shutdown initiated — {pc} will power off in {}.", fmt_span_words(grace_secs.into()))
                }
                PowerAction::Restart => {
                    format!("✅ Restart initiated — {pc} will restart in {}.", fmt_span_words(grace_secs.into()))
                }
                PowerAction::Sleep => format!("💤 {pc} is going to sleep now."),
                PowerAction::Hibernate => format!("🌙 {pc} is hibernating now."),
            };
            (s, None)
        }
        Err(e) => (format!("❌ {} failed: {}", action.label(), esc(e, MAX_LONG)), Some(menu_keyboard())),
    }
}

/// `check_power` refused the action.
pub fn power_unavailable(action: PowerAction, error: &str) -> Screen {
    (format!("❌ {} is not available: {}", action.label(), esc(error, MAX_LONG)), Some(menu_keyboard()))
}

pub fn power_expired(action: PowerAction) -> Screen {
    (format!("⌛ Confirmation expired. Send /{} again.", action.key()), Some(menu_keyboard()))
}

pub fn power_cancelled(action: PowerAction) -> Screen {
    (format!("❌ {} cancelled.", action.label()), Some(menu_keyboard()))
}

/// The previous confirmation message after a newer request replaced it.
pub fn superseded(action: PowerAction) -> Screen {
    (format!("⏭ <i>Superseded — this {} request was replaced by a newer one.</i>", action.key()), None)
}

pub fn nothing_to_cancel() -> Screen {
    ("ℹ️ Nothing to cancel.".into(), None)
}

/// `/clear` while automatic chat cleaning is switched off (nothing is tracked, so nothing can
/// be deleted).
pub fn clear_disabled() -> Screen {
    (
        "🧹 Automatic chat cleaning is switched off (<code>auto_clean_chat</code> in settings.json), so PREDATOR \
         keeps no list of messages to delete."
            .into(),
        None,
    )
}

// ───────────────────────────── lock / logout ─────────────────────────────

pub fn lock_result(r: &Result<String, String>) -> Screen {
    match r {
        Ok(msg) => (format!("🔒 {}", esc(msg, MAX_LONG)), Some(menu_keyboard())),
        Err(e) => (format!("❌ Lock failed: {}", esc(e, MAX_LONG)), Some(menu_keyboard())),
    }
}

pub fn logout_result(r: &Result<String, String>) -> Screen {
    match r {
        Ok(msg) => (format!("🚪 {}", esc(msg, MAX_LONG)), Some(menu_keyboard())),
        Err(e) => (format!("❌ Logout failed: {}", esc(e, MAX_LONG)), Some(menu_keyboard())),
    }
}

// ───────────────────────────── misc ─────────────────────────────

/// `⌛ Ignored /lock sent at 14:02:11 — older than 5 minutes (sent while the PC was offline?)`.
pub fn stale_text(command: &str, sent_unix: i64, now_unix: i64, stale_secs: u64) -> String {
    format!(
        "⌛ Ignored {} sent at {} — older than {} (sent while the PC was offline?)",
        esc(command, MAX_SHORT),
        fmt_time_relative(sent_unix, now_unix),
        fmt_span_words(stale_secs)
    )
}

/// Replaces the message of a state-changing button press that was delivered from Telegram's
/// backlog ([`BACKLOG_IGNORED`]). The keyboard offers the same button again so the user can
/// repeat the press: the features toggles (with their current state) for `ft:*`, the Tailscale
/// screen for `ts:*`, the user list for `um:rm:*`, the main menu for everything else.
pub fn backlog_ignored_screen(action: &CallbackAction, features: &FeatureSet) -> Screen {
    let kb = match action {
        CallbackAction::ToggleFeature(_) => features_keyboard(features),
        CallbackAction::TailscaleUp | CallbackAction::TailscaleDown => {
            InlineKeyboardMarkup::new(vec![vec![nav_btn("🛡 Tailscale", Nav::Tailscale), nav_btn("⬅️ Back", Nav::Main)]])
        }
        CallbackAction::RemoveUser(_) => InlineKeyboardMarkup::new(vec![vec![
            btn("👥 Users", CallbackAction::UsersRefresh),
            nav_btn("⬅️ Back", Nav::Main),
        ]]),
        _ => main_keyboard(),
    };
    (BACKLOG_IGNORED.to_string(), Some(kb))
}

pub fn unknown_command() -> Screen {
    (UNKNOWN_COMMAND.into(), None)
}

/// Reply to plain (non-command) text.
pub fn plain_text_hint() -> Screen {
    (
        "ℹ️ I only understand commands. Open the control panel with /menu or see /help.".into(),
        Some(InlineKeyboardMarkup::new(vec![vec![nav_btn("🏠 Open Menu", Nav::Main)]])),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::ServiceState;

    const T: i64 = 1_795_588_515;

    fn datas(s: &Screen) -> Vec<String> {
        s.1.as_ref().map(|k| k.callback_datas()).unwrap_or_default()
    }

    fn ts_full() -> TailscaleStatus {
        TailscaleStatus {
            installed: true,
            version: Some("1.104.6".into()),
            service: ServiceState::Running,
            backend_state: Some("Running".into()),
            connected: true,
            ipv4: Some("100.64.0.5".into()),
            hostname: Some("my-pc".into()),
            tailnet: Some("example.ts.net".into()),
            health: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            auth_url: Some("https://login.tailscale.com/a/x?y=1&z=2".into()),
            ..Default::default()
        }
    }

    #[test]
    fn callback_roundtrip_and_size() {
        let mut all = vec![
            CallbackAction::Lock,
            CallbackAction::Logout,
            CallbackAction::TailscaleUp,
            CallbackAction::TailscaleDown,
            CallbackAction::Confirm("0123456789abcdef0123456789abcdef".into()),
            CallbackAction::Cancel("0123456789abcdef0123456789abcdef".into()),
            CallbackAction::UsersRefresh,
            CallbackAction::RemoveUser(123_456_789),
            CallbackAction::RemoveUser(i64::MAX),
        ];
        all.extend(Nav::ALL.iter().map(|n| CallbackAction::Nav(*n)));
        all.extend(Feature::ALL.iter().map(|f| CallbackAction::ToggleFeature(*f)));
        all.extend(PowerAction::ALL.iter().map(|a| CallbackAction::Power(*a)));
        for a in all {
            let d = a.data();
            assert!(d.len() <= MAX_CALLBACK_DATA, "{d}");
            assert_eq!(CallbackAction::parse(&d), Some(a), "{d}");
        }
    }

    #[test]
    fn callback_parse_rejects_garbage() {
        for bad in [
            "",
            "nav",
            "nav:",
            "nav:xyz",
            "ft:",
            "ft:9",
            "ft:99",
            "ft:-1",
            "ft:01x",
            "ft:+1",
            "pw:reboot",
            "act:shutdown",
            "ts:restart",
            "cf:",
            "cf:XYZ",
            "cf:ABCDEF",
            "cf:../../",
            "cx: ",
            "zz:main",
            "nav:main:extra",
            "um",
            "um:",
            "um:list",
            "um:ls:x",
            "um:rm",
            "um:rm:",
            "um:rm:0",
            "um:rm:-5",
            "um:rm:+5",
            "um:rm:0123",
            "um:rm:12a",
            "um:rm:1:2",
            "um:rm:99999999999999999999",
            "um:add:5",
        ] {
            assert_eq!(CallbackAction::parse(bad), None, "{bad:?}");
        }
        assert_eq!(CallbackAction::parse(&format!("cf:{}", "a".repeat(49))), None);
        assert_eq!(CallbackAction::parse(&"x".repeat(65)), None);
    }

    #[test]
    fn main_menu_layout() {
        let v = MenuView {
            computer: "MY-PC".into(),
            boot_unix: T - (3 * 3600 + 12 * 60),
            service_start_unix: T - (2 * 3600 + 5 * 60),
            now_unix: T,
            security: MonitorState::Active,
            ssh: MonitorState::Active,
            queued: 0,
            dry_run: false,
        };
        let (s, kb) = main_menu(&v);
        assert_eq!(
            s,
            "🖥 <b>PREDATOR REMOTE CONTROL</b>\n━━━━━━━━━━━━━━━━━━\n🟢 <b>Online</b> · <code>MY-PC</code>\n\
             ⏱ Uptime: 3h 12m · Service: 2h 5m\n🔐 Login monitor: 🟢 Active · SSH: 🟢 Active\n📬 Queued alerts: 0"
        );
        let kb = kb.unwrap();
        let rows: Vec<Vec<&str>> = kb
            .inline_keyboard
            .iter()
            .map(|r| r.iter().map(|b| b.callback_data.as_deref().unwrap()).collect())
            .collect();
        assert_eq!(
            rows,
            vec![
                vec!["nav:status"],
                vec!["nav:net", "nav:bat"],
                vec!["nav:hist", "nav:feat"],
                vec!["pw:shutdown", "pw:restart"],
                vec!["pw:sleep", "pw:hibernate"],
                vec!["act:lock", "act:logout"],
                vec!["nav:ts"],
                vec!["nav:help"],
            ]
        );
        let (s, _) = main_menu(&MenuView { dry_run: true, computer: "<x>".into(), ..v });
        assert!(s.contains("DRY-RUN"));
        assert!(s.contains("<code>&lt;x&gt;</code>"));
    }

    #[test]
    fn network_exact_layout() {
        let n = NetworkInfo {
            connection: ConnectionType::WiFi,
            ssid: Some("MyHomeWiFi".into()),
            ipv4: Some("192.168.1.105".into()),
            internet: InternetStatus::Connected,
            ..Default::default()
        };
        let (s, kb) = network_screen(&Ok(n.clone()));
        assert_eq!(
            s,
            "🌐 <b>NETWORK STATUS</b>\n\nConnection: Wi-Fi\nSSID: MyHomeWiFi\nIP Address: 192.168.1.105\n\
             Internet: 🟢 Connected"
        );
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:net", "nav:main"]);

        let eth = NetworkInfo { connection: ConnectionType::Ethernet, ssid: None, vpn: Some("Tailscale".into()), ..n };
        let (s, _) = network_screen(&Ok(eth.clone()));
        assert!(s.contains("Connection: Ethernet"));
        assert!(!s.contains("SSID"));
        assert!(s.contains("\nVPN: Tailscale"));

        let wifi_no_ssid = NetworkInfo {
            connection: ConnectionType::WiFi,
            ssid: None,
            ssid_note: Some("Location services are off".into()),
            ..eth
        };
        let (s, _) = network_screen(&Ok(wifi_no_ssid));
        assert!(s.contains("\nSSID: <i>Location services are off</i>"));

        let (s, _) = network_screen(&Err("adapter <x> failed".into()));
        assert!(s.contains("adapter &lt;x&gt; failed"));
    }

    #[test]
    fn battery_variants() {
        let b = BatteryInfo {
            present: true,
            percent: Some(85),
            charging: true,
            ac: AcStatus::Connected,
            ..Default::default()
        };
        let (s, _) = battery_screen(&Ok(b.clone()));
        assert_eq!(s, "🔋 <b>BATTERY STATUS</b>\n\nBattery: 85%\nStatus: Charging\nPower: AC Connected");
        let (s, _) = battery_screen(&Ok(BatteryInfo { full: true, charging: false, ..b.clone() }));
        assert!(s.contains("Status: Fully charged"));
        let dis = BatteryInfo {
            charging: false,
            ac: AcStatus::Disconnected,
            seconds_left: Some(2 * 3600 + 10 * 60),
            ..b.clone()
        };
        let (s, _) = battery_screen(&Ok(dis));
        assert!(s.contains("Status: Discharging (≈ 2h 10m left)"));
        assert!(s.contains("Power: On battery"));
        let (s, _) = battery_screen(&Ok(BatteryInfo { present: false, ..b }));
        assert!(s.contains("🔌 No battery detected — this PC runs on AC power."));
        assert!(!s.contains("Battery:"));
    }

    #[test]
    fn history_lines() {
        let base =
            EventDetails { user: "alice".into(), method: "Interactive".into(), event_unix: T, ..Default::default() };
        let when = fmt_short_datetime(T);
        assert_eq!(history_line(&base), format!("🟢 {when} · alice · Interactive"));
        let failed = EventDetails { kind: NotificationKind::FailedLogin, ..base.clone() };
        assert_eq!(history_line(&failed), format!("🔴 {when} · alice · failed"));
        let logout = EventDetails { kind: NotificationKind::Logout, ..base.clone() };
        assert_eq!(history_line(&logout), format!("🚪 {when} · alice · logout"));
        let ssh = EventDetails { kind: NotificationKind::SshLogin, source_ip: Some("1.2.3.4".into()), ..base.clone() };
        assert_eq!(history_line(&ssh), format!("🔐 {when} · alice · SSH 1.2.3.4"));
        let evil = EventDetails { user: "<b>evil&".into(), ..base.clone() };
        assert!(history_line(&evil).contains("&lt;b&gt;evil&amp;"));

        let (s, kb) = history_screen(&[]);
        assert!(s.contains("No login events"));
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:hist", "nav:main"]);
        let many: Vec<EventDetails> = (0..10).map(|_| EventDetails { user: "u".repeat(500), ..base.clone() }).collect();
        let (s, _) = history_screen(&many);
        assert!(s.chars().count() < 4096);
    }

    #[test]
    fn features_layout() {
        let fs = FeatureSet::default();
        let (s, kb) = features_screen(&fs);
        assert!(s.starts_with("⚙️ <b>PREDATOR FEATURES</b>\n"));
        assert!(s.contains("\n🟢 Windows Login Monitoring"));
        assert!(s.contains("\n🔴 Failed Login Notifications"));
        let kb = kb.unwrap();
        assert_eq!(kb.inline_keyboard.len(), 6); // 9 toggles in rows of 2 + back
        assert!(kb.inline_keyboard[..5].iter().all(|r| r.len() <= 2));
        assert_eq!(kb.inline_keyboard[0][0].text, "🟢 Login Monitor");
        assert_eq!(kb.inline_keyboard[1][1].text, "🔴 Failed Logins");
        assert_eq!(kb.inline_keyboard[0][0].callback_data.as_deref(), Some("ft:0"));
        assert_eq!(kb.inline_keyboard[5][0].callback_data.as_deref(), Some("nav:main"));
        assert_eq!(feature_toggled_text(Feature::SshMonitoring, false), "SSH Monitoring disabled");
    }

    #[test]
    fn disabled_text() {
        let (s, kb) = disabled_screen(Feature::BatteryInfo);
        assert_eq!(s, "🚫 <b>Battery Information is disabled.</b>\nEnable it in /features.");
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:feat", "nav:main"]);
    }

    #[test]
    fn tailscale_screens() {
        let st = TailscaleStatus { app_running: true, ..ts_full() };
        let (s, kb) = tailscale_screen(&st);
        assert!(s.contains("Installed: ✅ Yes (v1.104.6)"));
        // the App line sits right below the Service line, above the connection line
        assert!(s.contains("\nService: Running\nApp: 🟢 Running\nConnection: 🟢 Connected"), "{s}");
        assert!(s.contains("Tailscale IP: <code>100.64.0.5</code>"));
        assert!(s.contains("Hostname: <code>my-pc</code>"));
        assert_eq!(s.matches("\n• ").count(), 4); // 3 warnings + "and 1 more"
        assert!(s.contains("x?y=1&amp;z=2"));
        assert_eq!(kb.unwrap().callback_datas(), vec!["ts:up", "ts:down", "nav:ts", "nav:main"]);

        let stopped = TailscaleStatus {
            connected: false,
            backend_state: Some("Stopped".into()),
            health: vec![],
            auth_url: None,
            ..st.clone()
        };
        assert!(tailscale_screen(&stopped).0.contains("Connection: 🔴 Disconnected"));
        let login = TailscaleStatus { backend_state: Some("NeedsLogin".into()), ..stopped.clone() };
        assert!(tailscale_screen(&login).0.contains("\nConnection: 🟡 Needs login"));

        // the app is not running: tailscaled waits for it (NoState) → 🟡 Connecting…
        let no_app = TailscaleStatus { app_running: false, backend_state: Some("NoState".into()), ..stopped.clone() };
        let s = tailscale_screen(&no_app).0;
        assert!(s.contains("\nService: Running\nApp: ⚪ Not running\nConnection: 🟡 Connecting…"), "{s}");
        assert_eq!(tailscale_app(&no_app), "⚪ Not running");
        assert_eq!(tailscale_app(&st), "🟢 Running");

        let missing = TailscaleStatus::default();
        let (s, kb) = tailscale_screen(&missing);
        assert!(s.contains("not installed"));
        assert!(!s.contains("App:"), "{s}");
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:ts", "nav:main"]);

        assert_eq!(tailscale_progress(true).0, "⏳ Bringing Tailscale up…");
        assert_eq!(tailscale_progress(false).0, "⏳ Bringing Tailscale down…");
        let r = TailscaleOpResult {
            success: true,
            steps: vec!["✅ Service started".into(), "✅ tailscale up: Success.".into()],
            status: st,
            error: None,
        };
        let (s, kb) = tailscale_result(true, &r);
        assert!(s.starts_with("✅ <b>Tailscale up completed</b>"));
        assert!(s.contains("\n✅ Service started\n✅ tailscale up: Success.\n"));
        assert!(s.contains("\nApp: 🟢 Running\nConnection: 🟢 Connected"), "{s}");
        assert!(kb.is_some());
        // the step lines sys::tailscale::up() adds for the app are shown as they are
        let r2 = TailscaleOpResult {
            steps: vec![
                "✅ Tailscale app started for alice".into(),
                "ℹ️ No user is logged in — relying on Tailscale Unattended mode".into(),
            ],
            ..r.clone()
        };
        let s = tailscale_result(true, &r2).0;
        assert!(
            s.contains(
                "\n✅ Tailscale app started for alice\nℹ️ No user is logged in — relying on Tailscale Unattended mode\n"
            ),
            "{s}"
        );
        let failed = TailscaleOpResult { success: false, error: Some("boom".into()), ..r };
        let (s, _) = tailscale_result(false, &failed);
        assert!(s.starts_with("❌ <b>Tailscale down failed</b>"));
        assert!(s.contains("❗ boom"));
    }

    #[test]
    fn tailscale_connection_states() {
        let running = TailscaleStatus {
            installed: true,
            service: ServiceState::Running,
            backend_state: Some("Running".into()),
            connected: true,
            ..Default::default()
        };
        let line = |st: &TailscaleStatus| tailscale_connection(st);
        let with = |service: ServiceState, backend: Option<&str>| TailscaleStatus {
            service,
            backend_state: backend.map(str::to_string),
            connected: false,
            ..running.clone()
        };
        assert_eq!(line(&running), "🟢 Connected");

        // service not running: always 🔴, whatever the backend state says (never 🟡)
        let stopped_msg = "🔴 Disconnected (Tailscale service stopped)";
        assert_eq!(line(&with(ServiceState::Stopped, Some("Service stopped"))), stopped_msg);
        assert_eq!(line(&with(ServiceState::Stopped, None)), stopped_msg);
        assert_eq!(line(&with(ServiceState::Stopped, Some("NeedsLogin"))), stopped_msg);
        assert_eq!(line(&with(ServiceState::Stopped, Some("Starting"))), stopped_msg);
        assert_eq!(line(&TailscaleStatus { connected: true, ..with(ServiceState::Stopped, None) }), stopped_msg);
        assert_eq!(
            line(&with(ServiceState::StartPending, Some("Service starting"))),
            "🔴 Disconnected (Tailscale service starting)"
        );
        assert_eq!(line(&with(ServiceState::StopPending, None)), "🔴 Disconnected (Tailscale service stopping)");
        assert_eq!(line(&with(ServiceState::Paused, None)), "🔴 Disconnected (Tailscale service paused)");
        assert_eq!(line(&with(ServiceState::NotInstalled, None)), "🔴 Disconnected (Tailscale service not installed)");
        // service state unknown, but the status layer labelled the backend "Service …"
        assert_eq!(line(&with(ServiceState::Unknown, Some("Service stopped"))), stopped_msg);
        assert_eq!(line(&with(ServiceState::Unknown, Some("service"))), stopped_msg);
        assert_eq!(
            line(&with(ServiceState::Unknown, Some("Service <paused>"))),
            "🔴 Disconnected (Tailscale service &lt;paused&gt;)"
        );
        // ... a word that merely starts with "Service" is not such a label
        assert_eq!(line(&with(ServiceState::Unknown, Some("ServiceX"))), "⚪ ServiceX");

        // service running: transient states and states that need the owner are 🟡
        assert_eq!(line(&with(ServiceState::Running, Some("Stopped"))), "🔴 Disconnected");
        assert_eq!(line(&with(ServiceState::Running, Some("Starting"))), "🟡 Starting…");
        assert_eq!(line(&with(ServiceState::Running, Some("NoState"))), "🟡 Connecting…");
        assert_eq!(line(&with(ServiceState::Running, Some("NeedsLogin"))), "🟡 Needs login");
        assert!(line(&with(ServiceState::Running, Some("NeedsMachineAuth"))).starts_with("🟡 Needs admin approval"));
        assert_eq!(line(&with(ServiceState::Running, Some("Running"))), "🟢 Connected");
        assert_eq!(line(&with(ServiceState::Running, Some("<Weird>"))), "⚪ &lt;Weird&gt;");
        assert_eq!(line(&with(ServiceState::Running, None)), "⚪ Unknown");
        assert_eq!(line(&with(ServiceState::Unknown, None)), "🔴 Disconnected");
        assert_eq!(line(&with(ServiceState::Unknown, Some("NeedsLogin"))), "🟡 Needs login");
    }

    #[test]
    fn tailscale_down_result_shows_red_disconnected() {
        // what sys::tailscale::down() returns after a successful down: the service is stopped
        let after_down = TailscaleStatus {
            installed: true,
            version: Some("1.104.6".into()),
            service: ServiceState::Stopped,
            backend_state: Some("Service stopped".into()),
            connected: false,
            ..Default::default()
        };
        let r = TailscaleOpResult {
            success: true,
            steps: vec!["✅ tailscale down".into(), "✅ Tailscale app closed".into(), "✅ Service stopped".into()],
            status: after_down.clone(),
            error: None,
        };
        let (s, _) = tailscale_result(false, &r);
        assert!(s.starts_with("✅ <b>Tailscale down completed</b>"));
        assert!(s.contains("\n✅ Tailscale app closed\n"), "{s}");
        assert!(
            s.contains(
                "\nService: Stopped\nApp: ⚪ Not running\nConnection: 🔴 Disconnected (Tailscale service stopped)"
            ),
            "{s}"
        );
        assert!(!s.contains('🟡'), "{s}");
        let (s, _) = tailscale_screen(&after_down);
        assert!(s.contains("\nConnection: 🔴 Disconnected (Tailscale service stopped)"), "{s}");
        assert!(!s.contains('🟡'), "{s}");
    }

    #[test]
    fn callback_state_classification() {
        let nonce = "0123456789abcdef0123456789abcdef".to_string();
        for nav in Nav::ALL {
            assert!(!CallbackAction::Nav(nav).changes_state(), "{nav:?}");
        }
        assert!(!CallbackAction::Cancel(nonce.clone()).changes_state());
        assert!(!CallbackAction::UsersRefresh.changes_state());
        let mut changing = vec![
            CallbackAction::Lock,
            CallbackAction::Logout,
            CallbackAction::TailscaleUp,
            CallbackAction::TailscaleDown,
            CallbackAction::Confirm(nonce.clone()),
            CallbackAction::RemoveUser(5),
        ];
        changing.extend(Feature::ALL.iter().map(|f| CallbackAction::ToggleFeature(*f)));
        changing.extend(PowerAction::ALL.iter().map(|a| CallbackAction::Power(*a)));
        for a in changing {
            assert!(a.changes_state(), "{a:?}");
        }
        // nonces never reach the log
        assert_eq!(CallbackAction::Confirm(nonce.clone()).log_label(), "cf:…");
        assert_eq!(CallbackAction::Cancel(nonce).log_label(), "cx:…");
        assert_eq!(CallbackAction::Lock.log_label(), "act:lock");
        assert_eq!(CallbackAction::ToggleFeature(Feature::SshMonitoring).log_label(), "ft:1");
    }

    #[test]
    fn backlog_ignored_screens_offer_the_button_again() {
        let fs = FeatureSet::default();
        let cases = [
            (CallbackAction::Lock, "act:lock"),
            (CallbackAction::Logout, "act:logout"),
            (CallbackAction::Power(PowerAction::Shutdown), "pw:shutdown"),
            (CallbackAction::Confirm("abc".into()), "pw:shutdown"),
            (CallbackAction::ToggleFeature(Feature::SshMonitoring), "ft:1"),
            (CallbackAction::TailscaleUp, "nav:ts"),
            (CallbackAction::TailscaleDown, "nav:ts"),
            (CallbackAction::RemoveUser(5), "um:ls"),
        ];
        for (action, retry) in cases {
            let sc = backlog_ignored_screen(&action, &fs);
            assert_eq!(sc.0, BACKLOG_IGNORED);
            let d = datas(&sc);
            assert!(d.iter().any(|x| x == retry), "{action:?}: {d:?}");
            // a way out: Back to the menu, or the main menu keyboard itself
            assert!(d.iter().any(|x| x == "nav:main" || x == "nav:status"), "{action:?}: {d:?}");
            for x in d {
                assert!(CallbackAction::parse(&x).is_some(), "{x}");
            }
        }
        // the features keyboard shows the current (unchanged) state
        let sc = backlog_ignored_screen(&CallbackAction::ToggleFeature(Feature::SshMonitoring), &fs);
        let kb = sc.1.unwrap();
        assert_eq!(
            kb.inline_keyboard[0][1].text,
            format!("{} SSH Monitor", dot(fs.is_enabled(Feature::SshMonitoring)))
        );
        assert_eq!(
            BACKLOG_IGNORED,
            "⌛ Ignored a button press that was queued while PREDATOR was offline. Press it again if you still \
             want this."
        );
    }

    #[test]
    fn help_explains_the_chat_cleanup() {
        let (on, kb) = help_screen_with(60, 300, Some(600));
        assert!(on.contains("<b>Chat</b>\n/clear — "), "{on}");
        assert!(on.contains("after 10 minutes without use"), "{on}");
        assert!(on.contains("Login, logout and security alerts are always kept"), "{on}");
        assert!(!on.contains("switched off"));
        assert_eq!(kb, Some(back_keyboard()));
        let (off, _) = help_screen_with(60, 300, None);
        assert!(off.contains("/clear"));
        assert!(off.contains("Automatic chat cleaning is switched off (<code>auto_clean_chat</code>"), "{off}");
        assert_eq!(help_screen(60, 300), help_screen_with(60, 300, None));
        // the rest of the help is unchanged
        assert!(on.contains("Confirmation policy") && off.contains("Confirmation policy"));
        let (t, kb) = clear_disabled();
        assert!(t.starts_with("🧹 Automatic chat cleaning is switched off") && kb.is_none());
    }

    fn users() -> Vec<AuthorizedUser> {
        use crate::config::UserRole;
        vec![
            AuthorizedUser::new(123_456_789, "@alice", UserRole::Admin, T),
            AuthorizedUser::new(987_654_321, "<b>bob&", UserRole::User, 0),
            AuthorizedUser::new(555_000_111, &"c".repeat(60), UserRole::User, T),
        ]
    }

    #[test]
    fn users_screen_lists_everyone_and_gives_admins_remove_buttons() {
        let list = users();
        let (s, kb) = users_screen(&list, 123_456_789);
        assert!(s.starts_with("👥 <b>TELEGRAM USERS</b> (3 of 20)\n"), "{s}");
        let date = crate::util::time::fmt_date(T);
        assert!(
            s.contains(&format!("👑 <b>@alice</b> · <code>123456789</code> · Admin · added {date} <i>(you)</i>")),
            "{s}"
        );
        assert!(s.contains("👤 <b>&lt;b&gt;bob&amp;</b> · <code>987654321</code> · User\n"), "{s}");
        assert!(!s.contains("<b>bob"), "names are escaped");
        assert!(s.contains("The last admin cannot be removed"));
        assert!(s.contains("Pair Telegram User…"));
        let kb = kb.unwrap();
        assert_eq!(kb.callback_datas(), vec!["um:rm:987654321", "um:rm:555000111", "um:ls", "nav:main"]);
        // one button per other user, never for the admin themselves; plain-text label, truncated
        assert_eq!(kb.inline_keyboard[0][0].text, "🗑 Remove <b>bob&");
        assert!(kb.inline_keyboard[1][0].text.chars().count() <= "🗑 Remove ".chars().count() + MAX_BUTTON_NAME);
        // a plain user sees the list but no remove buttons
        let (s, kb) = users_screen(&list, 987_654_321);
        assert!(s.contains("<code>987654321</code> · User <i>(you)</i>"), "{s}");
        assert!(s.contains("Ask an admin"));
        assert_eq!(kb.unwrap().callback_datas(), vec!["um:ls", "nav:main"]);
        // nobody paired (only reachable through the console)
        let (s, _) = users_screen(&[], 1);
        assert!(s.contains("Nobody is paired"));
        for d in datas(&users_screen(&list, 123_456_789)) {
            assert!(CallbackAction::parse(&d).is_some(), "{d}");
        }
    }

    #[test]
    fn pairing_texts() {
        let (s, kb) = paired_screen("MY-PC");
        assert_eq!(s, "✅ Paired with MY-PC. Send /menu to start.");
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:main"]);
        assert!(paired_screen("<x>").0.contains("&lt;x&gt;"));
        let (s, _) = already_paired_screen();
        assert!(s.starts_with(ALREADY_PAIRED), "{s}");
        assert_eq!(ALREADY_PAIRED, "ℹ️ You are already paired.");
        let (help, _) = help_screen(60, 300);
        assert!(help.contains("<b>Users</b>\n/users — "), "{help}");
        assert!(help.contains("/pair CODE — "), "{help}");
        assert!(help.contains("can only be confirmed by the user who asked for it"));
        assert!(help.contains("Only paired Telegram accounts (checked by numeric user ID)"));
    }

    #[test]
    fn labels_match_the_code() {
        // Power Management gates lock and logout too (bot.rs lock_screen / logout_screen)
        let (help, _) = help_screen(60, 300);
        assert!(help.contains("Power Management feature covers shutdown, restart, sleep, hibernate, lock and logout"));
        assert!(help.contains("<b>Tailscale</b> (Tailscale Management feature)"));
        assert!(help.contains("older than 5 minutes"));
        assert!(help.contains("expires after 1 minute"));
        assert!(help.contains("Button presses that change something are ignored when Telegram delivers them late"));
        let (features, _) = features_screen(&FeatureSet::default());
        assert!(features.contains("Power Management covers shutdown, restart, sleep, hibernate, lock and logout."));
        // DRY-RUN simulates power, lock, logout and Tailscale up/down (sys::RealSystem)
        assert_eq!(
            dry_run_banner(),
            "🧪 <i>DRY-RUN mode — power, lock, logout and Tailscale up/down are simulated.</i>"
        );
        let (menu, _) = main_menu(&MenuView { dry_run: true, ..Default::default() });
        assert!(menu.contains(dry_run_banner()));
        let (status, _) = status_screen(&StatusView { dry_run: true, ..Default::default() });
        assert!(status.contains(dry_run_banner()));
    }

    #[test]
    fn confirmation_layout() {
        let nonce = "00112233445566778899aabbccddeeff";
        let (s, kb) = confirm_screen(PowerAction::Shutdown, "MY-PC", 60, nonce);
        assert_eq!(
            s,
            "⚠️ <b>CONFIRM SHUTDOWN</b>\n\n🖥 Computer: <code>MY-PC</code>\n\
             Open apps will be closed. Unsaved work may be lost.\n⏳ Expires in 1 minute."
        );
        let kb = kb.unwrap();
        assert_eq!(kb.inline_keyboard[0][0].text, "✅ Confirm Shutdown");
        assert_eq!(kb.inline_keyboard[0][1].text, "❌ Cancel");
        assert_eq!(kb.callback_datas(), vec![format!("cf:{nonce}"), format!("cx:{nonce}")]);
        assert!(confirm_screen(PowerAction::Restart, "PC", 90, nonce).0.contains("Expires in 90 seconds."));

        assert_eq!(power_progress(PowerAction::Shutdown).0, "⏳ Shutting down…");
        assert_eq!(
            power_result(PowerAction::Shutdown, "MY-PC", 5, &Ok("x".into()), false).0,
            "✅ Shutdown initiated — MY-PC will power off in 5 seconds."
        );
        assert_eq!(
            power_result(PowerAction::Sleep, "MY-PC", 5, &Ok("x".into()), false).0,
            "💤 MY-PC is going to sleep now."
        );
        assert_eq!(
            power_result(PowerAction::Shutdown, "MY-PC", 5, &Err("no <privilege>".into()), false).0,
            "❌ Shutdown failed: no &lt;privilege&gt;"
        );
        let (s, _) = power_result(PowerAction::Restart, "P", 5, &Ok("DRY-RUN: Restart was simulated".into()), true);
        assert!(s.contains("DRY-RUN: Restart was simulated"));
        assert_eq!(power_expired(PowerAction::Shutdown).0, "⌛ Confirmation expired. Send /shutdown again.");
        assert_eq!(power_cancelled(PowerAction::Shutdown).0, "❌ Shutdown cancelled.");
        assert!(superseded(PowerAction::Sleep).0.contains("Superseded"));
    }

    #[test]
    fn stale_message() {
        let s = stale_text("/lock", T - 600, T, 300);
        assert!(s.starts_with("⌛ Ignored /lock sent at "));
        assert!(s.ends_with(" — older than 5 minutes (sent while the PC was offline?)"));
        assert!(s.contains(&crate::util::time::fmt_time(T - 600)));
    }

    #[test]
    fn span_words() {
        assert_eq!(fmt_span_words(300), "5 minutes");
        assert_eq!(fmt_span_words(60), "1 minute");
        assert_eq!(fmt_span_words(90), "90 seconds");
        assert_eq!(fmt_span_words(5), "5 seconds");
        assert_eq!(fmt_span_words(1), "1 second");
    }

    #[test]
    fn status_layout() {
        let v = StatusView {
            sys: SystemStatus {
                computer: "MY-PC".into(),
                os_version: "Windows 11 Pro 25H2 (26200)".into(),
                boot_unix: T - 3600,
                service_start_unix: T - 60,
                service_private_bytes: 3 * 1024 * 1024 + 300 * 1024,
                service_working_set_bytes: 6 * 1024 * 1024,
                service_cpu_ms: 1300,
                sessions: vec![
                    SessionInfo {
                        user: "alice".into(),
                        state: "Active".into(),
                        station: "Console".into(),
                        locked: Some(true),
                        ..Default::default()
                    },
                    SessionInfo {
                        user: "<bob>".into(),
                        state: "Disconnected".into(),
                        station: "RDP-Tcp#0".into(),
                        client_address: Some("10.0.0.2".into()),
                        ..Default::default()
                    },
                ],
            },
            telegram: "online".into(),
            security: MonitorState::Active,
            ssh: MonitorState::Error("access <denied>".into()),
            audit_policy: Some("Logon: Success+Failure".into()),
            queued: 2,
            delivered: 7,
            dry_run: true,
            now_unix: T,
            version: "1.0.0".into(),
        };
        let (s, kb) = status_screen(&v);
        for needle in [
            "📊 <b>SYSTEM STATUS</b>",
            "DRY-RUN",
            "🖥 Computer: <code>MY-PC</code>",
            "🪟 OS: Windows 11 Pro 25H2 (26200)",
            "⏱ Uptime: 1h 0m",
            "⚙️ Service uptime: 1m 0s · v1.0.0",
            "💾 Service RAM: 3.3 MB private · 6.0 MB working set",
            "🧮 Service CPU time: 1.3 s",
            "📡 Telegram: 🟢 Online",
            "🔐 Login monitor: 🟢 Active",
            "🔑 SSH monitor: 🔴 Error: access &lt;denied&gt;",
            "📋 Audit policy: Logon: Success+Failure",
            "📬 Queued alerts: 2 · Delivered: 7",
            "• alice · Console · Active · 🔒",
            "• &lt;bob&gt; · RDP · Disconnected · from 10.0.0.2",
        ] {
            assert!(s.contains(needle), "missing {needle:?} in\n{s}");
        }
        assert_eq!(kb.unwrap().callback_datas(), vec!["nav:status", "nav:main"]);
    }

    #[test]
    fn every_builder_keyboard_is_valid() {
        let screens = vec![
            main_menu(&MenuView::default()),
            status_screen(&StatusView::default()),
            network_screen(&Err("x".into())),
            battery_screen(&Err("x".into())),
            history_screen(&[]),
            features_screen(&FeatureSet::default()),
            tailscale_screen(&ts_full()),
            help_screen(60, 300),
            confirm_screen(PowerAction::Hibernate, "PC", 60, "abc"),
            disabled_screen(Feature::NetworkInfo),
            plain_text_hint(),
            lock_result(&Ok("ok".into())),
            logout_result(&Err("x".into())),
            power_cancelled(PowerAction::Sleep),
        ];
        for sc in &screens {
            for d in datas(sc) {
                assert!(d.len() <= MAX_CALLBACK_DATA);
                assert!(CallbackAction::parse(&d).is_some(), "{d}");
            }
            assert!(sc.0.chars().count() < 4096);
        }
    }
}
