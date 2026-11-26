//! Service Control Manager helpers for *other* services (Tailscale) and status queries of ours.
//!

use std::path::PathBuf;
use std::ptr::null;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_DEPENDENT_SERVICES_RUNNING, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_NAME,
    ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DEPENDENCY_FAIL,
    ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_LOGON_FAILED, ERROR_SERVICE_MARKED_FOR_DELETE,
    ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_REQUEST_TIMEOUT, ERROR_SERVICE_SPECIFIC_ERROR,
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING,
    SERVICE_CONTROL_STOP, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
};

use super::ServiceState;
use crate::util::win::{error_message, from_wide, from_wide_ptr, last_error, wide};

/// Polling bounds while waiting for a pending state to settle.
const POLL_MIN: Duration = Duration::from_millis(250);
const POLL_MAX: Duration = Duration::from_millis(500);

/// A service-control handle closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed exactly once.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// An open service plus the manager it was opened from (field order = drop order).
struct Service {
    svc: ScHandle,
    _mgr: ScHandle,
}

/// Snapshot of `SERVICE_STATUS_PROCESS`.
#[derive(Clone, Copy, Debug)]
struct Status {
    state: u32,
    pid: u32,
    wait_hint_ms: u32,
    checkpoint: u32,
    win32_exit: u32,
    specific_exit: u32,
}

fn open_service(name: &str, access: u32) -> Result<Service, u32> {
    if name.is_empty() || name.contains('\0') {
        return Err(ERROR_INVALID_NAME);
    }
    // SAFETY: local machine, default database, connect right only.
    let mgr = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if mgr.is_null() {
        return Err(last_error());
    }
    let mgr = ScHandle(mgr);
    let wname = wide(name);
    // SAFETY: valid manager handle and NUL-terminated name.
    let svc = unsafe { OpenServiceW(mgr.0, wname.as_ptr(), access) };
    if svc.is_null() {
        return Err(last_error());
    }
    Ok(Service { svc: ScHandle(svc), _mgr: mgr })
}

fn query_status(svc: &Service) -> Result<Status, u32> {
    let mut sp = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: `sp` is a SERVICE_STATUS_PROCESS and its size is passed.
    let ok = unsafe {
        QueryServiceStatusEx(
            svc.svc.0,
            SC_STATUS_PROCESS_INFO,
            (&mut sp as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(Status {
        state: sp.dwCurrentState,
        pid: sp.dwProcessId,
        wait_hint_ms: sp.dwWaitHint,
        checkpoint: sp.dwCheckPoint,
        win32_exit: sp.dwWin32ExitCode,
        specific_exit: sp.dwServiceSpecificExitCode,
    })
}

/// Map a `SERVICE_*` state value to [`ServiceState`].
fn map_state(state: u32) -> ServiceState {
    match state {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => ServiceState::StartPending,
        SERVICE_STOP_PENDING => ServiceState::StopPending,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_PAUSED | SERVICE_PAUSE_PENDING => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

/// Poll interval derived from the service's wait hint (a tenth of it, clamped to 250–500 ms).
fn poll_interval(wait_hint_ms: u32) -> Duration {
    Duration::from_millis(u64::from(wait_hint_ms / 10)).clamp(POLL_MIN, POLL_MAX)
}

/// Sleep one poll interval, never past `deadline`. Returns false when the deadline has passed.
fn sleep_until_next_poll(deadline: Instant, wait_hint_ms: u32) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    std::thread::sleep(poll_interval(wait_hint_ms).min(deadline - now));
    true
}

/// User-facing message for a failed SCM operation (`action` = "query", "start", "stop", ...).
fn describe_error(code: u32, name: &str, action: &str) -> String {
    match code {
        ERROR_ACCESS_DENIED => {
            format!("Permission denied: controlling the {name} service requires administrator/SYSTEM rights")
        }
        ERROR_SERVICE_DOES_NOT_EXIST | ERROR_INVALID_NAME => format!("The {name} service is not installed"),
        ERROR_SERVICE_DISABLED => format!("The {name} service is disabled (startup type = Disabled)"),
        ERROR_SERVICE_MARKED_FOR_DELETE => format!("The {name} service is being uninstalled"),
        ERROR_DEPENDENT_SERVICES_RUNNING => {
            format!("Cannot stop the {name} service: other running services depend on it")
        }
        ERROR_SERVICE_DEPENDENCY_FAIL => format!("Cannot start the {name} service: a service it depends on failed"),
        ERROR_SERVICE_LOGON_FAILED => format!("Cannot start the {name} service: its logon account was rejected"),
        ERROR_SERVICE_REQUEST_TIMEOUT => {
            format!("The {name} service did not respond to the {action} request in time")
        }
        _ => format!("Could not {action} the {name} service: {} (error {code})", error_message(code)),
    }
}

/// Explanation when a service went back to STOPPED while we waited for RUNNING.
fn describe_start_failure(name: &str, win32_exit: u32, specific_exit: u32) -> String {
    match win32_exit {
        0 => format!("The {name} service stopped right after starting"),
        ERROR_SERVICE_SPECIFIC_ERROR => {
            format!("The {name} service failed to start (service-specific error {specific_exit})")
        }
        code => format!("The {name} service failed to start: {} (error {code})", error_message(code)),
    }
}

/// Current state and PID (0 if not running) of a service.
pub fn query(name: &str) -> (ServiceState, u32) {
    let svc = match open_service(name, SERVICE_QUERY_STATUS) {
        Ok(s) => s,
        Err(ERROR_SERVICE_DOES_NOT_EXIST | ERROR_INVALID_NAME) => return (ServiceState::NotInstalled, 0),
        Err(_) => return (ServiceState::Unknown, 0),
    };
    match query_status(&svc) {
        Ok(st) => (map_state(st.state), st.pid),
        Err(_) => (ServiceState::Unknown, 0),
    }
}

/// Start a service and wait until RUNNING (or error/timeout). Already running = Ok.
pub fn start_and_wait(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let svc = open_service(name, SERVICE_START | SERVICE_QUERY_STATUS).map_err(|c| describe_error(c, name, "start"))?;
    let mut start_sent = false;
    loop {
        let st = query_status(&svc).map_err(|c| describe_error(c, name, "query"))?;
        match st.state {
            SERVICE_RUNNING => return Ok(()),
            SERVICE_STOPPED if start_sent => {
                return Err(describe_start_failure(name, st.win32_exit, st.specific_exit));
            }
            SERVICE_PAUSED => return Err(format!("The {name} service is paused")),
            SERVICE_STOPPED => {
                // SAFETY: valid service handle; no arguments.
                if unsafe { StartServiceW(svc.svc.0, 0, null()) } == 0 {
                    let code = last_error();
                    if code != ERROR_SERVICE_ALREADY_RUNNING {
                        return Err(describe_error(code, name, "start"));
                    }
                }
                start_sent = true;
                continue;
            }
            // START/STOP/CONTINUE/PAUSE pending: wait for the state to settle.
            _ => {}
        }
        if !sleep_until_next_poll(deadline, st.wait_hint_ms) {
            return Err(format!(
                "Timed out after {} s waiting for the {name} service to start (state: {})",
                timeout.as_secs(),
                map_state(st.state).label()
            ));
        }
    }
}

/// Stop a service and wait until STOPPED (or error/timeout). Already stopped = Ok.
pub fn stop_and_wait(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let svc = open_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS).map_err(|c| describe_error(c, name, "stop"))?;
    let mut stop_sent = false;
    let mut last_checkpoint = None;
    loop {
        let st = query_status(&svc).map_err(|c| describe_error(c, name, "query"))?;
        match st.state {
            SERVICE_STOPPED => return Ok(()),
            SERVICE_RUNNING | SERVICE_PAUSED if !stop_sent => {
                let mut ss = SERVICE_STATUS::default();
                // SAFETY: valid service handle opened with SERVICE_STOP; `ss` is a valid out-parameter.
                if unsafe { ControlService(svc.svc.0, SERVICE_CONTROL_STOP, &mut ss) } == 0 {
                    match last_error() {
                        // Raced with the service stopping by itself, or in a pending state that
                        // cannot take controls yet: wait one poll interval and re-check.
                        ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_CANNOT_ACCEPT_CTRL => {}
                        code => return Err(describe_error(code, name, "stop")),
                    }
                } else {
                    stop_sent = true;
                    continue;
                }
            }
            _ => {}
        }
        if st.state == SERVICE_STOP_PENDING {
            last_checkpoint = Some(st.checkpoint);
        }
        if !sleep_until_next_poll(deadline, st.wait_hint_ms) {
            let progress = last_checkpoint.map(|c| format!(", checkpoint {c}")).unwrap_or_default();
            return Err(format!(
                "Timed out after {} s waiting for the {name} service to stop (state: {}{progress})",
                timeout.as_secs(),
                map_state(st.state).label()
            ));
        }
    }
}

/// Binary path (unquoted, without arguments) from the service configuration.
pub fn binary_path(name: &str) -> Option<PathBuf> {
    let svc = open_service(name, SERVICE_QUERY_CONFIG).ok()?;
    let mut needed = 0u32;
    // SAFETY: size query with a null buffer.
    let ok = unsafe { QueryServiceConfigW(svc.svc.0, std::ptr::null_mut(), 0, &mut needed) };
    if ok != 0 || last_error() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
        return None;
    }
    // 8-byte aligned buffer; QUERY_SERVICE_CONFIGW is followed by the strings it points to.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let len = (buf.len() * 8).min(u32::MAX as usize) as u32;
    // SAFETY: `buf` is `len` bytes long and suitably aligned for QUERY_SERVICE_CONFIGW.
    let ok = unsafe { QueryServiceConfigW(svc.svc.0, buf.as_mut_ptr().cast(), len, &mut needed) };
    if ok == 0 {
        return None;
    }
    // SAFETY: the buffer holds a QUERY_SERVICE_CONFIGW whose string pointers point into `buf`.
    let raw = unsafe {
        let cfg = &*(buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>());
        from_wide_ptr(cfg.lpBinaryPathName)
    };
    let expanded = if raw.contains('%') { expand_env(&raw).unwrap_or(raw) } else { raw };
    parse_image_path(&expanded, &system_root())
}

fn system_root() -> String {
    std::env::var("SystemRoot").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| r"C:\Windows".to_string())
}

fn expand_env(s: &str) -> Option<String> {
    let src = wide(s);
    let mut buf = vec![0u16; 512];
    for _ in 0..3 {
        // SAFETY: `buf` is valid for `buf.len()` UTF-16 units.
        let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 {
            return None;
        }
        if n <= buf.len() {
            return Some(from_wide(&buf));
        }
        buf.resize(n, 0);
    }
    None
}

/// Extract the executable path from a service `ImagePath` / `lpBinaryPathName`.
///
/// Handles quoted paths with arguments, unquoted paths containing spaces (cut after the first
/// `.exe`/`.sys` followed by whitespace or the end), the NT prefixes `\??\` and `\SystemRoot\`,
/// and `system32\...` driver paths relative to the Windows directory.
pub fn parse_image_path(image: &str, system_root: &str) -> Option<PathBuf> {
    let s = image.trim();
    let path = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).trim()
    } else {
        let lower = s.to_ascii_lowercase();
        let mut cut = None;
        for ext in [".exe", ".sys"] {
            let mut from = 0;
            while let Some(i) = lower[from..].find(ext) {
                let end = from + i + ext.len();
                if end == s.len() || s[end..].starts_with(char::is_whitespace) {
                    cut = Some(cut.map_or(end, |c: usize| c.min(end)));
                    break;
                }
                from = end;
            }
        }
        match cut {
            Some(end) => &s[..end],
            None => s.split_whitespace().next().unwrap_or(""),
        }
    };
    if path.is_empty() {
        return None;
    }
    let root = system_root.trim_end_matches('\\');
    let path = if let Some(p) = path.strip_prefix(r"\??\") {
        p.to_string()
    } else if let Some(rest) = strip_prefix_ci(path, r"\SystemRoot\") {
        format!(r"{root}\{rest}")
    } else if strip_prefix_ci(path, r"system32\").is_some() {
        format!(r"{root}\{path}")
    } else {
        path.to_string()
    };
    Some(PathBuf::from(path))
}

/// ASCII case-insensitive `strip_prefix` that never slices inside a multi-byte character.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r"C:\WINDOWS";

    fn p(s: &str) -> Option<PathBuf> {
        parse_image_path(s, ROOT)
    }

    #[test]
    fn image_path_parsing() {
        assert_eq!(
            p(r#""C:\Program Files\Tailscale\tailscaled.exe""#),
            Some(PathBuf::from(r"C:\Program Files\Tailscale\tailscaled.exe"))
        );
        assert_eq!(
            p(r#""C:\Program Files\Foo Bar\svc.exe" --service -x "a b""#),
            Some(PathBuf::from(r"C:\Program Files\Foo Bar\svc.exe"))
        );
        assert_eq!(
            p(r"C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p"),
            Some(PathBuf::from(r"C:\WINDOWS\system32\svchost.exe"))
        );
        // Unquoted path with spaces (bad practice, but it exists in the wild).
        assert_eq!(
            p(r"C:\Program Files\Vendor App\agent.exe /run now"),
            Some(PathBuf::from(r"C:\Program Files\Vendor App\agent.exe"))
        );
        // ".exe" inside a directory name is not the end of the path.
        assert_eq!(p(r"C:\tools\my.exe.d\real.exe -a"), Some(PathBuf::from(r"C:\tools\my.exe.d\real.exe")));
        assert_eq!(p(r"C:\X\APP.EXE"), Some(PathBuf::from(r"C:\X\APP.EXE")));
        assert_eq!(
            p(r"\SystemRoot\System32\drivers\tcpip.sys"),
            Some(PathBuf::from(r"C:\WINDOWS\System32\drivers\tcpip.sys"))
        );
        assert_eq!(p(r"system32\DRIVERS\foo.sys"), Some(PathBuf::from(r"C:\WINDOWS\system32\DRIVERS\foo.sys")));
        assert_eq!(p(r"\??\C:\Drivers\x.sys"), Some(PathBuf::from(r"C:\Drivers\x.sys")));
        assert_eq!(p("  "), None);
        assert_eq!(p(r#""""#), None);
        // Unterminated quote: take the rest.
        assert_eq!(p(r#""C:\a b\c.exe"#), Some(PathBuf::from(r"C:\a b\c.exe")));
    }

    #[test]
    fn state_mapping() {
        assert_eq!(map_state(SERVICE_STOPPED), ServiceState::Stopped);
        assert_eq!(map_state(SERVICE_START_PENDING), ServiceState::StartPending);
        assert_eq!(map_state(SERVICE_CONTINUE_PENDING), ServiceState::StartPending);
        assert_eq!(map_state(SERVICE_STOP_PENDING), ServiceState::StopPending);
        assert_eq!(map_state(SERVICE_RUNNING), ServiceState::Running);
        assert_eq!(map_state(SERVICE_PAUSED), ServiceState::Paused);
        assert_eq!(map_state(SERVICE_PAUSE_PENDING), ServiceState::Paused);
        assert_eq!(map_state(99), ServiceState::Unknown);
    }

    #[test]
    fn poll_interval_bounds() {
        assert_eq!(poll_interval(0), POLL_MIN);
        assert_eq!(poll_interval(3_000), Duration::from_millis(300));
        assert_eq!(poll_interval(30_000), POLL_MAX);
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            describe_error(ERROR_ACCESS_DENIED, "Tailscale", "stop"),
            "Permission denied: controlling the Tailscale service requires administrator/SYSTEM rights"
        );
        assert_eq!(describe_error(ERROR_SERVICE_DOES_NOT_EXIST, "X", "start"), "The X service is not installed");
        assert!(describe_error(ERROR_SERVICE_DISABLED, "X", "start").contains("disabled"));
        assert!(describe_error(ERROR_DEPENDENT_SERVICES_RUNNING, "X", "stop").contains("depend"));
        let generic = describe_error(2, "X", "start");
        assert!(generic.starts_with("Could not start the X service:") && generic.ends_with("(error 2)"), "{generic}");
        assert_eq!(describe_start_failure("X", 0, 0), "The X service stopped right after starting");
        assert!(describe_start_failure("X", ERROR_SERVICE_SPECIFIC_ERROR, 42).contains("42"));
    }

    #[test]
    fn live_query_eventlog_running() {
        let (state, pid) = query("EventLog");
        assert_eq!(state, ServiceState::Running);
        assert!(pid > 0);
    }

    #[test]
    fn live_query_missing_service() {
        assert_eq!(query("NoSuchService123"), (ServiceState::NotInstalled, 0));
        assert_eq!(query(""), (ServiceState::NotInstalled, 0));
        assert_eq!(binary_path("NoSuchService123"), None);
    }

    #[test]
    fn live_binary_path_tailscale() {
        // Read-only: only the service configuration is queried.
        if query("Tailscale").0 == ServiceState::NotInstalled {
            eprintln!("Tailscale not installed — skipping");
            return;
        }
        let p = binary_path("Tailscale").expect("Tailscale ImagePath");
        assert!(p.ends_with("tailscaled.exe"), "{}", p.display());
        assert!(p.is_file(), "{}", p.display());
        println!("Tailscale binary: {}", p.display());
    }

    #[test]
    fn live_binary_path_svchost_service() {
        let p = binary_path("EventLog").expect("EventLog ImagePath");
        assert!(p.to_string_lossy().to_ascii_lowercase().ends_with("svchost.exe"), "{}", p.display());
        assert!(p.is_file());
    }

    #[test]
    fn live_start_stop_missing_service_fail_cleanly() {
        // Only a non-existent service is used: no real service is ever started or stopped by tests.
        let r = start_and_wait("NoSuchService123", Duration::from_secs(1));
        assert_eq!(r, Err("The NoSuchService123 service is not installed".to_string()));
        let r = stop_and_wait("NoSuchService123", Duration::from_secs(1));
        assert_eq!(r, Err("The NoSuchService123 service is not installed".to_string()));
    }

    #[test]
    fn prefix_helper_is_char_safe() {
        assert_eq!(strip_prefix_ci(r"\SYSTEMROOT\x", r"\SystemRoot\"), Some("x"));
        assert_eq!(strip_prefix_ci("ÜÜÜÜÜÜÜ", r"\SystemRoot\"), None);
        assert_eq!(p("C:\\Programme\\Übung\\ä.exe -x"), Some(PathBuf::from("C:\\Programme\\Übung\\ä.exe")));
    }
}
