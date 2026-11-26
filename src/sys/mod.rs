//! Windows system operations behind an explicit allowlist ([`SystemActions`]).
//!
//! Nothing in this crate ever executes a command string received from Telegram: every action is
//! a fixed Rust function, and the only programs ever started from here are the Tailscale CLI
//! (`tailscale.exe status --json --peers=false | up | down`, discovered from the registry/service
//! config), our own `predator-tray.exe --lock` session helper and our own
//! `predator-service.exe ssid-helper` (Wi-Fi SSID lookup kept out of the service process) — all
//! with fixed argument lists, created under `process::SPAWN_LOCK`.

pub mod battery;
pub mod network;
pub mod power;
pub mod privilege;
pub mod process;
pub mod scm;
pub mod session;
pub mod sysinfo;
pub mod tailscale;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The four power actions that require confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PowerAction {
    Shutdown,
    Restart,
    Sleep,
    Hibernate,
}

impl PowerAction {
    pub const ALL: [PowerAction; 4] =
        [PowerAction::Shutdown, PowerAction::Restart, PowerAction::Sleep, PowerAction::Hibernate];

    pub fn key(self) -> &'static str {
        match self {
            PowerAction::Shutdown => "shutdown",
            PowerAction::Restart => "restart",
            PowerAction::Sleep => "sleep",
            PowerAction::Hibernate => "hibernate",
        }
    }

    pub fn from_key(k: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.key() == k)
    }

    pub fn label(self) -> &'static str {
        match self {
            PowerAction::Shutdown => "Shutdown",
            PowerAction::Restart => "Restart",
            PowerAction::Sleep => "Sleep",
            PowerAction::Hibernate => "Hibernate",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            PowerAction::Shutdown => "⏻",
            PowerAction::Restart => "🔄",
            PowerAction::Sleep => "💤",
            PowerAction::Hibernate => "🌙",
        }
    }
}

/// Physical medium of the primary connection.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ConnectionType {
    WiFi,
    Ethernet,
    Cellular,
    /// Virtual/tunnel or unknown medium, with a description.
    Other(String),
    #[default]
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InternetStatus {
    Connected,
    LocalOnly,
    CaptivePortal,
    Disconnected,
    #[default]
    Unknown,
}

/// Result of `/network` (deliberately minimal: no passwords, no scan results, no BSSIDs).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkInfo {
    pub connection: ConnectionType,
    /// Adapter friendly name (e.g. `WiFi`, `Ethernet`).
    pub adapter: Option<String>,
    /// Connected Wi-Fi SSID (Wi-Fi only).
    pub ssid: Option<String>,
    /// Explanation when the SSID could not be read (e.g. location services off).
    pub ssid_note: Option<String>,
    /// Local IPv4 address of the primary interface.
    pub ipv4: Option<String>,
    pub internet: InternetStatus,
    /// When the default route goes through a VPN/tunnel (e.g. Tailscale exit node), its name.
    pub vpn: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AcStatus {
    Connected,
    Disconnected,
    #[default]
    Unknown,
}

/// Result of `/battery`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BatteryInfo {
    /// False on desktops without a battery.
    pub present: bool,
    pub percent: Option<u8>,
    pub charging: bool,
    /// Fully charged on AC (not charging, but not discharging either).
    pub full: bool,
    pub ac: AcStatus,
    /// Estimated remaining seconds when discharging.
    pub seconds_left: Option<u32>,
    pub battery_saver: bool,
}

/// State of a Windows service as seen by the SCM.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Paused,
    #[default]
    Unknown,
}

impl ServiceState {
    pub fn label(&self) -> &'static str {
        match self {
            ServiceState::NotInstalled => "Not installed",
            ServiceState::Stopped => "Stopped",
            ServiceState::StartPending => "Starting",
            ServiceState::StopPending => "Stopping",
            ServiceState::Running => "Running",
            ServiceState::Paused => "Paused",
            ServiceState::Unknown => "Unknown",
        }
    }
}

/// Result of `/tailscale status`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TailscaleStatus {
    pub installed: bool,
    pub exe_path: Option<PathBuf>,
    pub version: Option<String>,
    pub service: ServiceState,
    /// The Tailscale app (`tailscale-ipn.exe`, the GUI that connects a user to tailscaled) runs in
    /// some session. Without it (and without Unattended mode) the backend stays in `NoState`.
    pub app_running: bool,
    /// Raw BackendState from `tailscale status --json` (`Running`, `Stopped`, `NeedsLogin`, `NoState`, `Starting` ...).
    pub backend_state: Option<String>,
    /// True when BackendState == Running.
    pub connected: bool,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: Option<String>,
    pub tailnet: Option<String>,
    /// Health warnings reported by tailscaled.
    pub health: Vec<String>,
    /// Login URL when NeedsLogin.
    pub auth_url: Option<String>,
    /// Error text when the status could not be obtained.
    pub error: Option<String>,
}

/// Result of `/tailscale up` / `/tailscale down`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TailscaleOpResult {
    pub success: bool,
    /// Human-readable step log (`✅ Service started`, `✅ tailscale up: Success.` ...).
    pub steps: Vec<String>,
    /// Final verified status.
    pub status: TailscaleStatus,
    pub error: Option<String>,
}

/// An interactive Windows session (console or RDP).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionInfo {
    pub id: u32,
    pub user: String,
    pub domain: String,
    /// `Active`, `Disconnected`, ...
    pub state: String,
    /// `Console`, `RDP-Tcp#0`, ...
    pub station: String,
    /// Lock state when known.
    pub locked: Option<bool>,
    /// RDP client address when known.
    pub client_address: Option<String>,
}

/// Result of the System Status screen.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SystemStatus {
    pub computer: String,
    pub os_version: String,
    /// Unix time of the last boot.
    pub boot_unix: i64,
    /// Unix time the service started.
    pub service_start_unix: i64,
    /// Private bytes of the service process.
    pub service_private_bytes: u64,
    /// Working set of the service process.
    pub service_working_set_bytes: u64,
    /// Total CPU time consumed by the service process (ms).
    pub service_cpu_ms: u64,
    pub sessions: Vec<SessionInfo>,
}

/// Every system operation the bot can perform. Implemented by [`RealSystem`] and by mocks.
pub trait SystemActions: Send + Sync {
    /// Is this power action supported right now (capabilities, hibernation enabled ...)?
    fn check_power(&self, action: PowerAction) -> Result<(), String>;
    /// Execute an (already confirmed) power action. Returns a success message once Windows has
    /// accepted the request. Sleep/hibernate return immediately and suspend on a worker thread.
    fn execute_power(&self, action: PowerAction) -> Result<String, String>;
    /// Lock every active interactive session.
    fn lock(&self) -> Result<String, String>;
    /// Log off the active interactive user session.
    fn logout(&self) -> Result<String, String>;
    fn network(&self) -> Result<NetworkInfo, String>;
    fn battery(&self) -> Result<BatteryInfo, String>;
    fn tailscale_status(&self) -> TailscaleStatus;
    fn tailscale_up(&self) -> TailscaleOpResult;
    fn tailscale_down(&self) -> TailscaleOpResult;
    fn system_status(&self) -> SystemStatus;
    /// True when power, lock, logout and Tailscale up/down are simulated.
    fn is_dry_run(&self) -> bool;
}

/// Grace period (seconds) between accepting shutdown/restart and Windows starting it, so the
/// Telegram confirmation edit is delivered first.
pub const SHUTDOWN_GRACE_SECS: u32 = 5;

/// The production implementation. With `dry_run` every destructive action (power, lock, logout,
/// tailscale up/down) is simulated and only reported.
pub struct RealSystem {
    dry_run: bool,
    service_start_unix: i64,
    /// Cache of the last Tailscale status (time, value) — status is relatively expensive
    /// (spawns tailscale.exe) so the tray/menus reuse a recent value.
    ts_cache: Mutex<Option<(i64, TailscaleStatus)>>,
}

impl RealSystem {
    pub fn new(dry_run: bool, service_start_unix: i64) -> Arc<Self> {
        Arc::new(Self { dry_run, service_start_unix, ts_cache: Mutex::new(None) })
    }

    /// Cached Tailscale status if younger than `max_age_secs`, otherwise refreshed.
    pub fn tailscale_status_cached(&self, max_age_secs: i64) -> TailscaleStatus {
        let now = crate::util::time::now_unix();
        if let Some((t, s)) = self.ts_cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            && now - *t <= max_age_secs
        {
            return s.clone();
        }
        self.tailscale_status()
    }

    fn remember_ts(&self, s: &TailscaleStatus) {
        *self.ts_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((crate::util::time::now_unix(), s.clone()));
    }
}

impl SystemActions for RealSystem {
    fn check_power(&self, action: PowerAction) -> Result<(), String> {
        power::capability(action)
    }

    fn execute_power(&self, action: PowerAction) -> Result<String, String> {
        power::capability(action)?;
        if self.dry_run {
            return Ok(format!("DRY-RUN: {} was simulated (nothing happened).", action.label()));
        }
        power::execute(action, SHUTDOWN_GRACE_SECS)
    }

    fn lock(&self) -> Result<String, String> {
        if self.dry_run {
            let n = session::list_sessions().into_iter().filter(|s| s.state == "Active" && !s.user.is_empty()).count();
            return Ok(format!("DRY-RUN: would lock {n} active session(s)."));
        }
        session::lock_active_sessions(&crate::paths::tray_exe_path())
    }

    fn logout(&self) -> Result<String, String> {
        if self.dry_run {
            return match session::active_user_session() {
                Some(s) => Ok(format!("DRY-RUN: would log off {} (session {}).", s.user, s.id)),
                None => Err("No user is logged in.".into()),
            };
        }
        session::logoff_active_user()
    }

    fn network(&self) -> Result<NetworkInfo, String> {
        network::network_info()
    }

    fn battery(&self) -> Result<BatteryInfo, String> {
        battery::battery_info()
    }

    fn tailscale_status(&self) -> TailscaleStatus {
        let s = tailscale::status();
        self.remember_ts(&s);
        s
    }

    fn tailscale_up(&self) -> TailscaleOpResult {
        if self.dry_run {
            let st = self.tailscale_status();
            return TailscaleOpResult {
                success: true,
                steps: vec![
                    "DRY-RUN: would start the Tailscale service and the Tailscale app, then run `tailscale up`".into(),
                ],
                status: st,
                error: None,
            };
        }
        let r = tailscale::up();
        self.remember_ts(&r.status);
        r
    }

    fn tailscale_down(&self) -> TailscaleOpResult {
        if self.dry_run {
            let st = self.tailscale_status();
            return TailscaleOpResult {
                success: true,
                steps: vec![
                    "DRY-RUN: would run `tailscale down`, close the Tailscale app and stop the Tailscale service"
                        .into(),
                ],
                status: st,
                error: None,
            };
        }
        let r = tailscale::down();
        self.remember_ts(&r.status);
        r
    }

    fn system_status(&self) -> SystemStatus {
        let (private, ws) = sysinfo::process_memory();
        SystemStatus {
            computer: sysinfo::computer_name(),
            os_version: sysinfo::os_version(),
            boot_unix: sysinfo::boot_unix(),
            service_start_unix: self.service_start_unix,
            service_private_bytes: private,
            service_working_set_bytes: ws,
            service_cpu_ms: sysinfo::process_cpu_ms(),
            sessions: session::list_sessions(),
        }
    }

    fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}
