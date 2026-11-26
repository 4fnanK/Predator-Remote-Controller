//! `selftest`: read-only health report. Changes nothing, starts nothing (Tailscale is only
//! queried with `--tailscale`). Every check is isolated so one failure cannot hide the others.

use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows_sys::Win32::System::EventLog::{
    EVT_VARIANT, EvtChannelConfigEnabled, EvtClose, EvtGetChannelConfigProperty, EvtNext, EvtOpenChannelConfig,
    EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
};

use super::commands::{DataCtx, is_elevated};
use super::runtime::catch;
use super::winsec;
use crate::features::Feature;
use crate::paths::{SERVICE_NAME, TRAY_RUN_VALUE};
use crate::sys::{AcStatus, ConnectionType, ServiceState};
use crate::util::win::{WinError, last_error, wide, wide_path};

#[derive(Default)]
struct Report {
    ok: u32,
    warn: u32,
    fail: u32,
}

impl Report {
    fn line(&mut self, tag: &str, text: &str) {
        match tag {
            "OK" => self.ok += 1,
            "WARN" => self.warn += 1,
            "FAIL" => self.fail += 1,
            _ => {}
        }
        let mut lines = text.lines();
        println!("[{tag:^4}] {}", lines.next().unwrap_or(""));
        for l in lines {
            println!("       {l}");
        }
    }
    fn ok(&mut self, t: &str) {
        self.line("OK", t)
    }
    fn warn(&mut self, t: &str) {
        self.line("WARN", t)
    }
    fn fail(&mut self, t: &str) {
        self.line("FAIL", t)
    }
    fn info(&mut self, t: &str) {
        self.line("INFO", t)
    }
}

/// Logging-related settings of sshd_config (first value wins, global section only).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SshdLogging {
    pub syslog_facility: Option<String>,
    pub log_level: Option<String>,
    pub has_match_blocks: bool,
}

pub(crate) fn parse_sshd_logging(text: &str) -> SshdLogging {
    let mut r = SshdLogging::default();
    let mut in_match = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim(), v.trim().trim_start_matches('=').trim()),
            None => (line, ""),
        };
        let key = key.to_ascii_lowercase();
        if key == "match" {
            in_match = true;
            r.has_match_blocks = true;
            continue;
        }
        if in_match {
            continue;
        }
        let value = value.split_whitespace().next().unwrap_or("").to_string();
        match key.as_str() {
            "syslogfacility" if r.syslog_facility.is_none() && !value.is_empty() => r.syslog_facility = Some(value),
            "loglevel" if r.log_level.is_none() && !value.is_empty() => r.log_level = Some(value),
            _ => {}
        }
    }
    r
}

/// `major.minor.build.revision` from a PE version resource (no process is started).
pub(crate) fn file_version(path: &Path) -> Option<String> {
    let w = wide_path(path);
    let mut handle = 0u32;
    // SAFETY: NUL-terminated path.
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` has `size` bytes.
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let root = wide("\\");
    let mut info: *mut std::ffi::c_void = null_mut();
    let mut len = 0u32;
    // SAFETY: `buf` holds the version resource; `info` points into it.
    if unsafe { VerQueryValueW(buf.as_ptr().cast(), root.as_ptr(), &mut info, &mut len) } == 0
        || info.is_null()
        || (len as usize) < size_of::<VS_FIXEDFILEINFO>()
    {
        return None;
    }
    // SAFETY: VerQueryValueW returned a VS_FIXEDFILEINFO inside `buf` (unaligned read).
    let fi = unsafe { std::ptr::read_unaligned(info as *const VS_FIXEDFILEINFO) };
    Some(format!(
        "{}.{}.{}.{}",
        fi.dwFileVersionMS >> 16,
        fi.dwFileVersionMS & 0xffff,
        fi.dwFileVersionLS >> 16,
        fi.dwFileVersionLS & 0xffff
    ))
}

/// Can we read one record from the Security log?
fn security_log_readable() -> Result<(), String> {
    let path = wide("Security");
    let query = wide("*");
    // SAFETY: local session, NUL-terminated strings.
    let h = unsafe { EvtQuery(0, path.as_ptr(), query.as_ptr(), EvtQueryChannelPath | EvtQueryReverseDirection) };
    if h == 0 {
        return Err(WinError::last("EvtQuery").to_string());
    }
    let mut ev: isize = 0;
    let mut returned = 0u32;
    // SAFETY: valid result set; room for one handle.
    let ok = unsafe { EvtNext(h, 1, &mut ev, 2000, 0, &mut returned) };
    let err = last_error();
    // SAFETY: handles from EvtQuery/EvtNext, closed once.
    unsafe {
        if ok != 0 && ev != 0 {
            EvtClose(ev);
        }
        EvtClose(h);
    }
    if ok == 0 {
        return Err(WinError::new(err, "EvtNext").to_string());
    }
    Ok(())
}

/// Is an event-log channel enabled? `Ok(None)` when it does not exist.
fn channel_enabled(channel: &str) -> Result<Option<bool>, String> {
    let w = wide(channel);
    // SAFETY: local session, NUL-terminated channel path.
    let h = unsafe { EvtOpenChannelConfig(0, w.as_ptr(), 0) };
    if h == 0 {
        let e = last_error();
        return if e == windows_sys::Win32::Foundation::ERROR_EVT_CHANNEL_NOT_FOUND {
            Ok(None)
        } else {
            Err(WinError::new(e, "EvtOpenChannelConfig").to_string())
        };
    }
    // SAFETY: zeroed EVT_VARIANT is a valid out buffer of the given size.
    let mut v: EVT_VARIANT = unsafe { std::mem::zeroed() };
    let mut used = 0u32;
    // SAFETY: valid config handle and buffer.
    let ok = unsafe {
        EvtGetChannelConfigProperty(h, EvtChannelConfigEnabled, 0, size_of::<EVT_VARIANT>() as u32, &mut v, &mut used)
    };
    let err = last_error();
    // SAFETY: handle from EvtOpenChannelConfig.
    unsafe { EvtClose(h) };
    if ok == 0 {
        return Err(WinError::new(err, "EvtGetChannelConfigProperty").to_string());
    }
    // SAFETY: EvtChannelConfigEnabled is returned as EvtVarTypeBoolean.
    Ok(Some(unsafe { v.Anonymous.BooleanVal } != 0))
}

/// `Telegram users: 2 authorized` + one line per user (`alice · id 123456789 · Admin`); `None`
/// when nobody is paired.
pub(crate) fn telegram_users_line(users: &[crate::config::AuthorizedUser]) -> Option<String> {
    if users.is_empty() {
        return None;
    }
    let mut s = format!("Telegram users: {} authorized", users.len());
    for u in users {
        s.push_str(&format!("\n{} · id {} · {}", u.label(), u.id, u.role.label()));
    }
    Some(s)
}

fn check<T>(r: &mut Report, name: &str, f: impl FnOnce() -> T) -> Option<T> {
    match catch(f) {
        Ok(v) => Some(v),
        Err(e) => {
            r.fail(&format!("{name}: internal error ({e})"));
            None
        }
    }
}

pub(crate) fn run(data: &DataCtx, tailscale: bool) -> i32 {
    let mut r = Report::default();
    println!("{} {} — self-test (read-only)\n", crate::PRODUCT_NAME, crate::VERSION);

    // Process / account
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "?".into());
    r.info(&format!("Executable: {exe}"));
    let elevated = is_elevated();
    match winsec::current_process_facts() {
        Some(f) => r.info(&format!(
            "Running as {} ({}) · elevated: {}",
            f.account.unwrap_or_else(|| "?".into()),
            f.sid,
            if elevated { "yes" } else { "no" }
        )),
        None => r.warn("Cannot query the current account"),
    }
    if !elevated {
        r.warn("Not elevated: the data directory, token, Security log and audit policy checks need an Administrator prompt");
    }

    // Data directory
    let root = &data.paths.root;
    if !root.exists() {
        if data.is_default {
            r.fail(&format!("Data directory {} does not exist — run 'predator-service install'", root.display()));
        } else {
            r.warn(&format!("Data directory {} does not exist", root.display()));
        }
    } else {
        match winsec::path_sddl(root) {
            Ok(sddl) if winsec::is_secure_data_dir_sddl(&sddl) => {
                r.ok(&format!("Data directory {} (SYSTEM + Administrators only)", root.display()))
            }
            Ok(sddl) if data.is_default => r.warn(&format!(
                "Data directory {} has an unexpected ACL: {sddl}\nRun 'predator-service install' to fix it",
                root.display()
            )),
            Ok(_) => r.info(&format!("Data directory {} (custom location, ACL not enforced)", root.display())),
            Err(e) => r.warn(&format!("Data directory {}: ACL not readable ({e})", root.display())),
        }
    }

    // Settings
    let settings = match data.settings() {
        Ok(s) => Some(s.get()),
        Err(e) if !elevated => {
            r.warn(&format!("settings.json not readable from this prompt: {e}"));
            None
        }
        Err(e) => {
            r.fail(&format!("settings.json: {e}"));
            None
        }
    };
    if let Some(s) = &settings {
        match telegram_users_line(&s.authorized_users) {
            Some(line) => r.ok(&line),
            None => r.warn("No Telegram user paired — run 'predator-service pair'"),
        }
        if !s.authorized_users.is_empty() && s.admin_count() == 0 {
            r.warn("No Telegram user is an admin: nobody can remove users from Telegram");
        }
        match &s.owner_windows_sid {
            Some(sid) => r.ok(&format!(
                "Tray owner: {} ({sid})",
                winsec::account_name_of(sid).unwrap_or_else(|| "unresolved account".into())
            )),
            None => r.info("Tray owner SID not set (only elevated administrators can use the tray controls)"),
        }
        let marker = data.paths.dry_run_marker().exists();
        if s.dry_run || marker {
            r.warn(&format!(
                "DRY-RUN is on ({}) — power, lock, logout and Tailscale up/down are simulated",
                if marker { "DRY_RUN file" } else { "settings" }
            ));
        }
        let on: Vec<&str> = Feature::ALL.iter().filter(|f| s.features.is_enabled(**f)).map(|f| f.key()).collect();
        let off: Vec<&str> = Feature::ALL.iter().filter(|f| !s.features.is_enabled(**f)).map(|f| f.key()).collect();
        r.info(&format!(
            "Features on: {}\nFeatures off: {}",
            if on.is_empty() { "-".into() } else { on.join(", ") },
            if off.is_empty() { "-".into() } else { off.join(", ") }
        ));
    }

    // Token
    let token_path = data.paths.token();
    let scope = check(&mut r, "token", || crate::secrets::stored_scope(&token_path));
    if let Some(res) = scope {
        match res {
            Ok(None) => r.fail("No bot token stored — run 'predator-service set-token'"),
            Err(e) if !elevated => r.warn(&format!("Bot token not checked: {e}")),
            Err(e) => r.fail(&e),
            Ok(Some(scope)) => match crate::secrets::load_token(&token_path) {
                Ok(token) => {
                    let api = crate::telegram::api::TelegramApi::new(&token);
                    drop(winsec::Secret::new(token));
                    if let Ok(api) = &api {
                        r.info(&format!("Telegram HTTP transport: {}", api.transport_name()));
                    }
                    let verdict = api.and_then(|api| api.get_me());
                    match verdict {
                        Ok(me) => r.ok(&format!(
                            "Bot token valid: @{} ({})",
                            me.username.unwrap_or_else(|| me.first_name.clone()),
                            scope.describe()
                        )),
                        Err(e) => {
                            r.fail(&format!("Bot token check failed: {}", super::commands::describe_token_error(&e)))
                        }
                    }
                }
                Err(e) if scope == crate::secrets::Scope::CurrentUser => r.info(&format!(
                    "Bot token stored for the service account only (cannot be verified from here): {e}"
                )),
                Err(e) => r.fail(&e),
            },
        }
    }

    // Telegram state
    let (st, bot_id) = super::poller::PollState::load_with_bot(&data.paths.telegram_state());
    if st.last_update_id > 0 {
        r.info(&format!(
            "Last processed Telegram update: {} ({}{})",
            st.last_update_id,
            crate::util::time::fmt_datetime(st.updated_unix),
            bot_id.map(|b| format!(", bot id {b}")).unwrap_or_default()
        ));
    }

    // Audit policy
    if let Some(res) = check(&mut r, "audit policy", crate::monitor::audit::describe) {
        match res {
            Ok((text, true)) => r.ok(&format!("Logon audit policy: {text}")),
            Ok((text, false)) => {
                r.warn(&format!("Logon audit policy incomplete: {text}\nRun 'predator-service audit enable'"))
            }
            Err(e) => r.warn(&format!("Audit policy not readable: {e}")),
        }
    }

    // Security log
    if let Some(res) = check(&mut r, "Security log", security_log_readable) {
        match res {
            Ok(()) => r.ok("Security event log readable"),
            Err(e) if !elevated => r.info(&format!(
                "Security event log not readable from this prompt ({e}); the service reads it as LocalSystem"
            )),
            Err(e) => r.fail(&format!("Security event log not readable: {e}")),
        }
    }

    // OpenSSH
    let sshd = check(&mut r, "sshd service", || crate::sys::scm::query("sshd").0).unwrap_or_default();
    if sshd == ServiceState::NotInstalled {
        r.info("OpenSSH server not installed (SSH monitoring has nothing to watch)");
    } else {
        r.info(&format!("OpenSSH server (sshd): {}", sshd.label()));
        match check(&mut r, "OpenSSH channel", || channel_enabled("OpenSSH/Operational")).unwrap_or(Ok(None)) {
            Ok(Some(true)) => r.ok("OpenSSH/Operational event channel enabled"),
            Ok(Some(false)) => r.warn("OpenSSH/Operational event channel is DISABLED — SSH logins will not be seen"),
            Ok(None) => r.warn("OpenSSH/Operational event channel not found"),
            Err(e) => r.warn(&format!("OpenSSH/Operational channel: {e}")),
        }
        let program_data =
            std::env::var_os("ProgramData").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
        let cfg = program_data.join("ssh").join("sshd_config");
        match std::fs::read_to_string(&cfg) {
            Ok(text) => {
                let l = parse_sshd_logging(&text);
                let facility = l.syslog_facility.clone().unwrap_or_else(|| "default (ETW)".into());
                let level = l.log_level.clone().unwrap_or_else(|| "default (INFO)".into());
                let quiet = l
                    .log_level
                    .as_deref()
                    .map(|v| matches!(v.to_ascii_uppercase().as_str(), "QUIET" | "FATAL" | "ERROR"))
                    .unwrap_or(false);
                let local0 = l.syslog_facility.as_deref().map(|v| v.eq_ignore_ascii_case("LOCAL0")).unwrap_or(false);
                let text = format!("sshd_config logging: SyslogFacility {facility}, LogLevel {level}");
                if quiet {
                    r.warn(&format!("{text}\nLogLevel too low: logins are not logged"));
                } else if local0 {
                    r.warn(&format!(
                        "{text}\nLOCAL0 writes to a file instead of the event log: SSH logins will not be seen"
                    ));
                } else {
                    r.ok(&text);
                }
            }
            Err(e) => r.info(&format!("{}: {e}", cfg.display())),
        }
    }

    // Network / battery
    match check(&mut r, "network", crate::sys::network::network_info) {
        Some(Ok(n)) => {
            let medium = match &n.connection {
                ConnectionType::WiFi => "Wi-Fi".to_string(),
                ConnectionType::Ethernet => "Ethernet".to_string(),
                ConnectionType::Cellular => "Cellular".to_string(),
                ConnectionType::Other(d) => d.clone(),
                ConnectionType::None => "none".to_string(),
            };
            r.ok(&format!(
                "Network: {medium}{} · IPv4 {} · internet {:?}{}",
                n.ssid.map(|s| format!(" ({s})")).unwrap_or_default(),
                n.ipv4.unwrap_or_else(|| "-".into()),
                n.internet,
                n.vpn.map(|v| format!(" · VPN {v}")).unwrap_or_default()
            ));
        }
        Some(Err(e)) => r.warn(&format!("Network information: {e}")),
        None => {}
    }
    if let Some(level) = check(&mut r, "connectivity", crate::net::connectivity::current) {
        r.info(&format!("Connectivity hint: {level:?}"));
    }
    match check(&mut r, "battery", crate::sys::battery::battery_info) {
        Some(Ok(b)) if !b.present => r.ok("Battery: none (AC powered desktop)"),
        Some(Ok(b)) => r.ok(&format!(
            "Battery: {}% · {} · AC {}",
            b.percent.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
            if b.charging {
                "charging"
            } else if b.full {
                "full"
            } else {
                "discharging"
            },
            match b.ac {
                AcStatus::Connected => "connected",
                AcStatus::Disconnected => "disconnected",
                AcStatus::Unknown => "unknown",
            }
        )),
        Some(Err(e)) => r.warn(&format!("Battery information: {e}")),
        None => {}
    }

    // Tailscale
    match check(&mut r, "Tailscale", crate::sys::tailscale::find_cli) {
        Some(Some(cli)) => {
            let ver = file_version(&cli).unwrap_or_else(|| "unknown version".into());
            let svc =
                check(&mut r, "Tailscale service", || crate::sys::scm::query(crate::sys::tailscale::SERVICE_NAME).0)
                    .unwrap_or_default();
            r.ok(&format!("Tailscale CLI: {} ({ver}) · service {}", cli.display(), svc.label()));
            if tailscale && let Some(s) = check(&mut r, "tailscale status", crate::sys::tailscale::status) {
                r.info(&format!("Tailscale status: {}", super::slot::tailscale_summary(&s)));
            }
        }
        Some(None) => r.info("Tailscale not installed"),
        None => {}
    }

    // Our service + tray autostart
    let (state, pid) = super::commands::service_state();
    match &state {
        ServiceState::NotInstalled => r.warn(&format!("Service {SERVICE_NAME} not installed")),
        ServiceState::Running => r.ok(&format!("Service {SERVICE_NAME}: Running (PID {pid})")),
        other => r.warn(&format!("Service {SERVICE_NAME}: {}", other.label())),
    }
    match winsec::get_run_value(TRAY_RUN_VALUE) {
        Some(v) => r.ok(&format!("Tray autostart: {v}")),
        None if state == ServiceState::NotInstalled => {}
        None => r.warn("Tray autostart (HKLM Run\\PredatorTray) missing"),
    }

    println!("\nSummary: {} OK, {} warning(s), {} failure(s)", r.ok, r.warn, r.fail);
    if r.fail > 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_config_logging() {
        let cfg = "# comment\nPort 22\nsyslogfacility LOCAL0\nLogLevel=VERBOSE\nLogLevel QUIET\n\
                   Match Group administrators\n  LogLevel ERROR\n  AuthorizedKeysFile x\n";
        let l = parse_sshd_logging(cfg);
        assert_eq!(l.syslog_facility.as_deref(), Some("LOCAL0"));
        assert_eq!(l.log_level.as_deref(), Some("VERBOSE"));
        assert!(l.has_match_blocks);
        assert_eq!(parse_sshd_logging(""), SshdLogging::default());
        assert_eq!(parse_sshd_logging("LogLevel = DEBUG3").log_level.as_deref(), Some("DEBUG3"));
    }

    #[test]
    fn telegram_users_report() {
        use crate::config::{AuthorizedUser, UserRole};
        assert_eq!(telegram_users_line(&[]), None);
        let users = [
            AuthorizedUser::new(123_456_789, "@alice", UserRole::Admin, 0),
            AuthorizedUser::new(987_654_321, "", UserRole::User, 0),
        ];
        assert_eq!(
            telegram_users_line(&users).unwrap(),
            "Telegram users: 2 authorized\n@alice · id 123456789 · Admin\nuser 987654321 · id 987654321 · User"
        );
    }

    #[test]
    fn version_of_a_system_file() {
        let sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let v = file_version(&Path::new(&sys32).join("System32").join("kernel32.dll")).unwrap();
        // kernel32 may report a compatibility version (6.2.x) to unmanifested test binaries
        let parts: Vec<&str> = v.split('.').collect();
        assert_eq!(parts.len(), 4, "{v}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()), "{v}");
        assert!(file_version(Path::new(r"C:\definitely\missing.exe")).is_none());
    }
}
