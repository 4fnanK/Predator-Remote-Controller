//! Shutdown / restart / sleep / hibernate.
//!
//! * Shutdown/restart: `InitiateShutdownW` from session 0 with `FORCE_OTHERS | FORCE_SELF` (every
//!   interactive user is "other" for a service; FORCE_SELF is required with a grace period) and a
//!   planned "Other" reason code. The function returns the Win32 error code directly.
//! * Sleep/hibernate: `SetSuspendState` blocks until the system resumes, so it runs on a detached
//!   worker thread after a short delay that lets the Telegram reply go out first.
//! * Capabilities come from `GetPwrCapabilities` (IsPwrHibernateAllowed is deprecated).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NOT_READY, ERROR_SHUTDOWN_IN_PROGRESS, ERROR_SHUTDOWN_IS_SCHEDULED,
    ERROR_SHUTDOWN_USERS_LOGGED_ON,
};
use windows_sys::Win32::System::Power::{GetPwrCapabilities, SYSTEM_POWER_CAPABILITIES, SetSuspendState};
use windows_sys::Win32::System::Shutdown::{
    InitiateShutdownW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER,
    SHUTDOWN_FORCE_OTHERS, SHUTDOWN_FORCE_SELF, SHUTDOWN_POWEROFF, SHUTDOWN_RESTART,
};
use windows_sys::Win32::System::SystemServices::HIBERFILE_TYPE_REDUCED;
use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

use super::PowerAction;
use super::privilege::enable_privilege;
use crate::util::win::{WinError, error_message, from_wide, last_error, wide};
use crate::{log_error, log_info, log_warn};

/// `MAX_SHUTDOWN_TIMEOUT` from winreg.h (10 years, in seconds).
const MAX_SHUTDOWN_TIMEOUT: u32 = 10 * 365 * 24 * 60 * 60;
/// Planned, "Other (Planned)" in the Shutdown Event Tracker. Never 0 (logged as unplanned).
const SHUTDOWN_REASON: u32 = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED;
/// Delay before suspending so the Telegram reply is delivered first.
const SUSPEND_DELAY: Duration = Duration::from_secs(3);
/// Delay before the single retry after ERROR_NOT_READY.
const NOT_READY_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Message shown by Windows in the shutdown notification.
const SHUTDOWN_NOTICE: &str = "Requested remotely via Vigil.";

pub(crate) const SHUTDOWN_PRIVILEGE: &str = "SeShutdownPrivilege";

/// Set while a sleep/hibernate worker is waiting or suspended, so requests cannot stack up.
static SUSPEND_PENDING: AtomicBool = AtomicBool::new(false);

/// Whether `action` is currently possible (sleep states available, hibernation enabled ...).
pub fn capability(action: PowerAction) -> Result<(), String> {
    match action {
        PowerAction::Shutdown | PowerAction::Restart => Ok(()),
        PowerAction::Sleep | PowerAction::Hibernate => check_caps(action, &query_caps()?),
    }
}

/// Execute a power action (privilege enabled internally). Shutdown/restart use InitiateShutdownW
/// with `grace_secs`; sleep/hibernate call SetSuspendState on a detached worker thread after a
/// short delay and return immediately. Returns a human readable success message.
pub fn execute(action: PowerAction, grace_secs: u32) -> Result<String, String> {
    capability(action)?;
    enable_privilege(SHUTDOWN_PRIVILEGE).map_err(|e| {
        log_error!("power: cannot enable {SHUTDOWN_PRIVILEGE}: {e}");
        format!("Permission denied — cannot enable {SHUTDOWN_PRIVILEGE} ({e}).")
    })?;
    match action {
        PowerAction::Shutdown | PowerAction::Restart => initiate_shutdown(action, grace_secs),
        PowerAction::Sleep | PowerAction::Hibernate => start_suspend(action),
    }
}

// ---------------------------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------------------------

/// The subset of `SYSTEM_POWER_CAPABILITIES` that decides sleep/hibernate availability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PowerCaps {
    s1: bool,
    s2: bool,
    s3: bool,
    s4: bool,
    hiber_file_present: bool,
    /// Modern Standby (S0 low-power idle) — S1–S3 are not used.
    aoac: bool,
    /// `HIBERFILE_TYPE_*` (0 = none/unknown, 1 = reduced (Fast Startup only), 2 = full).
    hiber_file_type: u8,
}

impl From<&SYSTEM_POWER_CAPABILITIES> for PowerCaps {
    fn from(c: &SYSTEM_POWER_CAPABILITIES) -> Self {
        Self {
            s1: c.SystemS1,
            s2: c.SystemS2,
            s3: c.SystemS3,
            s4: c.SystemS4,
            hiber_file_present: c.HiberFilePresent,
            aoac: c.AoAc,
            hiber_file_type: c.HiberFileType,
        }
    }
}

fn query_caps() -> Result<PowerCaps, String> {
    let mut caps = SYSTEM_POWER_CAPABILITIES::default();
    // SAFETY: `caps` is a valid, writable SYSTEM_POWER_CAPABILITIES.
    if !unsafe { GetPwrCapabilities(&mut caps) } {
        let e = WinError::last("GetPwrCapabilities");
        log_warn!("power: {e}");
        return Err(format!("Cannot query the power capabilities of this PC ({e})."));
    }
    Ok(PowerCaps::from(&caps))
}

/// Pure capability decision for sleep/hibernate.
fn check_caps(action: PowerAction, caps: &PowerCaps) -> Result<(), String> {
    match action {
        PowerAction::Shutdown | PowerAction::Restart => Ok(()),
        PowerAction::Sleep => {
            if caps.aoac {
                Err("This PC uses Modern Standby; sleep via API is not supported.".into())
            } else if !(caps.s1 || caps.s2 || caps.s3) {
                Err("Sleep is not supported on this PC (no S1–S3 sleep state is available).".into())
            } else {
                Ok(())
            }
        }
        PowerAction::Hibernate => {
            if !(caps.s4 && caps.hiber_file_present) {
                Err("Hibernation is disabled (powercfg /hibernate on).".into())
            } else if u32::from(caps.hiber_file_type) == HIBERFILE_TYPE_REDUCED {
                Err("Hibernation is disabled: the hibernation file is the reduced Fast-Startup-only type \
                     (powercfg /hibernate /type full)."
                    .into())
            } else {
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Shutdown / restart
// ---------------------------------------------------------------------------------------------

/// `InitiateShutdownW` flags for shutdown/restart (`None` for sleep/hibernate).
fn shutdown_flags(action: PowerAction) -> Option<u32> {
    let force = SHUTDOWN_FORCE_OTHERS | SHUTDOWN_FORCE_SELF;
    match action {
        PowerAction::Shutdown => Some(SHUTDOWN_POWEROFF | force),
        PowerAction::Restart => Some(SHUTDOWN_RESTART | force),
        PowerAction::Sleep | PowerAction::Hibernate => None,
    }
}

fn clamp_grace(grace_secs: u32) -> u32 {
    grace_secs.min(MAX_SHUTDOWN_TIMEOUT)
}

/// Retry policy: ERROR_NOT_READY (21) is retried exactly once.
fn should_retry(code: u32, attempt: u32) -> bool {
    code == ERROR_NOT_READY && attempt == 0
}

fn initiate_shutdown(action: PowerAction, grace_secs: u32) -> Result<String, String> {
    let flags = shutdown_flags(action).ok_or_else(|| format!("{} is not a shutdown action.", action.label()))?;
    let grace = clamp_grace(grace_secs);
    let notice = wide(SHUTDOWN_NOTICE);
    let mut attempt = 0u32;
    loop {
        // SAFETY: null machine name = local computer; `notice` is NUL-terminated and outlives the
        // call. InitiateShutdownW returns the Win32 error code (GetLastError is not used).
        let rc = unsafe { InitiateShutdownW(std::ptr::null(), notice.as_ptr(), grace, flags, SHUTDOWN_REASON) };
        if rc == 0 {
            log_info!("power: {} accepted by Windows (grace {grace} s, flags {flags:#x})", action.label());
            return Ok(shutdown_success_message(action, &computer_name(), grace));
        }
        if should_retry(rc, attempt) {
            attempt += 1;
            log_warn!("power: InitiateShutdownW returned {rc} (not ready); retrying once");
            std::thread::sleep(NOT_READY_RETRY_DELAY);
            continue;
        }
        log_error!("power: InitiateShutdownW({}) failed: {} (error {rc})", action.key(), error_message(rc));
        return Err(shutdown_error_message(action, rc));
    }
}

/// User-facing text for an `InitiateShutdownW` error code.
fn shutdown_error_message(action: PowerAction, code: u32) -> String {
    let verb = match action {
        PowerAction::Restart => "restart",
        _ => "shut down",
    };
    match code {
        ERROR_SHUTDOWN_IN_PROGRESS => "A shutdown is already in progress.".into(),
        ERROR_SHUTDOWN_IS_SCHEDULED => {
            "A shutdown is already scheduled on this PC (cancel it first with: shutdown /a).".into()
        }
        ERROR_ACCESS_DENIED => "Permission denied (SeShutdownPrivilege is not available to the service).".into(),
        ERROR_NOT_READY => format!("Windows is not ready to {verb} right now (error 21). Try again in a few seconds."),
        ERROR_SHUTDOWN_USERS_LOGGED_ON => "Other users are logged on and could not be signed out (error 1191).".into(),
        _ => format!("{} (error {code}).", error_message(code)),
    }
}

/// `DESKTOP-01 will power off in 5 seconds.`
fn shutdown_success_message(action: PowerAction, computer: &str, grace: u32) -> String {
    let (soon, now) = match action {
        PowerAction::Restart => ("restart", "is restarting"),
        _ => ("power off", "is powering off"),
    };
    match grace {
        0 => format!("{computer} {now} now."),
        1 => format!("{computer} will {soon} in 1 second."),
        n => format!("{computer} will {soon} in {n} seconds."),
    }
}

// ---------------------------------------------------------------------------------------------
// Sleep / hibernate
// ---------------------------------------------------------------------------------------------

/// `DESKTOP-01 is going to sleep now.` / `DESKTOP-01 is hibernating now.`
fn suspend_message(action: PowerAction, computer: &str) -> String {
    match action {
        PowerAction::Hibernate => format!("{computer} is hibernating now."),
        _ => format!("{computer} is going to sleep now."),
    }
}

/// Clears [`SUSPEND_PENDING`] when the worker ends (also when it panics).
struct PendingGuard;

impl Drop for PendingGuard {
    fn drop(&mut self) {
        SUSPEND_PENDING.store(false, Ordering::SeqCst);
    }
}

fn start_suspend(action: PowerAction) -> Result<String, String> {
    let hibernate = action == PowerAction::Hibernate;
    if SUSPEND_PENDING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err("A sleep/hibernate request is already in progress.".into());
    }
    let guard = PendingGuard;
    let spawned = std::thread::Builder::new().name("power-suspend".into()).stack_size(64 * 1024).spawn(move || {
        let _guard = guard;
        if std::panic::catch_unwind(|| suspend_worker(hibernate)).is_err() {
            log_error!("power: suspend worker panicked");
        }
    });
    match spawned {
        // Detached on purpose: SetSuspendState returns only after the system resumes.
        Ok(_) => Ok(suspend_message(action, &computer_name())),
        Err(e) => {
            // The closure (and its guard) has normally been dropped already; make sure anyway.
            SUSPEND_PENDING.store(false, Ordering::SeqCst);
            Err(format!("Could not start the {} worker thread: {e}", action.label().to_lowercase()))
        }
    }
}

fn suspend_worker(hibernate: bool) {
    let what = if hibernate { "hibernate" } else { "sleep" };
    std::thread::sleep(SUSPEND_DELAY);
    log_info!("power: entering {what} (SetSuspendState)");
    // SAFETY: plain call; bForce has no effect, wake events stay enabled.
    let ok = unsafe { SetSuspendState(hibernate, false, false) };
    let err = last_error();
    if ok {
        log_info!("power: system resumed from {what}");
    } else {
        log_error!("power: SetSuspendState({what}) failed: {}", WinError::new(err, "SetSuspendState"));
    }
}

// ---------------------------------------------------------------------------------------------

/// NetBIOS computer name (local helper so this module has no runtime dependency on `sysinfo`).
fn computer_name() -> String {
    let mut buf = [0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is writable for `len` UTF-16 units.
    if unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) } != 0 {
        let name = from_wide(&buf[..(len as usize).min(buf.len())]);
        if !name.is_empty() {
            return name;
        }
    }
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "This PC".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP: PowerCaps = PowerCaps {
        s1: false,
        s2: false,
        s3: true,
        s4: true,
        hiber_file_present: true,
        aoac: false,
        hiber_file_type: 2,
    };

    #[test]
    fn flags_and_reason() {
        assert_eq!(shutdown_flags(PowerAction::Shutdown), Some(0x0B));
        assert_eq!(shutdown_flags(PowerAction::Restart), Some(0x07));
        assert_eq!(shutdown_flags(PowerAction::Sleep), None);
        assert_eq!(shutdown_flags(PowerAction::Hibernate), None);
        assert_eq!(SHUTDOWN_REASON, 0x8000_0000);
        assert_eq!(MAX_SHUTDOWN_TIMEOUT, 315_360_000);
        assert_eq!(clamp_grace(5), 5);
        assert_eq!(clamp_grace(u32::MAX), 315_360_000);
    }

    #[test]
    fn sleep_capability() {
        assert_eq!(check_caps(PowerAction::Sleep, &DESKTOP), Ok(()));
        let s1_only = PowerCaps { s3: false, s1: true, ..DESKTOP };
        assert_eq!(check_caps(PowerAction::Sleep, &s1_only), Ok(()));
        let modern = PowerCaps { aoac: true, ..DESKTOP };
        let e = check_caps(PowerAction::Sleep, &modern).unwrap_err();
        assert!(e.contains("Modern Standby"), "{e}");
        let none = PowerCaps { s1: false, s2: false, s3: false, ..DESKTOP };
        assert!(check_caps(PowerAction::Sleep, &none).unwrap_err().contains("not supported"));
    }

    #[test]
    fn hibernate_capability() {
        assert_eq!(check_caps(PowerAction::Hibernate, &DESKTOP), Ok(()));
        // Old OS builds report 0 (unknown) for the type: still allowed.
        assert_eq!(check_caps(PowerAction::Hibernate, &PowerCaps { hiber_file_type: 0, ..DESKTOP }), Ok(()));
        let off = PowerCaps { hiber_file_present: false, ..DESKTOP };
        assert!(check_caps(PowerAction::Hibernate, &off).unwrap_err().contains("powercfg /hibernate on"));
        let no_s4 = PowerCaps { s4: false, ..DESKTOP };
        assert!(check_caps(PowerAction::Hibernate, &no_s4).is_err());
        let reduced = PowerCaps { hiber_file_type: 1, ..DESKTOP };
        assert!(check_caps(PowerAction::Hibernate, &reduced).unwrap_err().contains("/type full"));
        // Modern Standby does not prevent hibernate.
        assert_eq!(check_caps(PowerAction::Hibernate, &PowerCaps { aoac: true, ..DESKTOP }), Ok(()));
    }

    #[test]
    fn shutdown_and_restart_always_capable() {
        let nothing = PowerCaps::default();
        assert_eq!(check_caps(PowerAction::Shutdown, &nothing), Ok(()));
        assert_eq!(check_caps(PowerAction::Restart, &nothing), Ok(()));
        assert_eq!(capability(PowerAction::Shutdown), Ok(()));
        assert_eq!(capability(PowerAction::Restart), Ok(()));
    }

    #[test]
    fn live_capabilities_are_consistent() {
        // Read-only probe of this machine.
        let caps = query_caps().expect("GetPwrCapabilities");
        println!("power caps: {caps:?}");
        assert_eq!(capability(PowerAction::Sleep), check_caps(PowerAction::Sleep, &caps));
        assert_eq!(capability(PowerAction::Hibernate), check_caps(PowerAction::Hibernate, &caps));
    }

    #[test]
    fn error_mapping() {
        assert!(shutdown_error_message(PowerAction::Shutdown, 1115).contains("already in progress"));
        assert!(shutdown_error_message(PowerAction::Shutdown, 1190).contains("already scheduled"));
        assert!(shutdown_error_message(PowerAction::Restart, 5).contains("Permission denied"));
        assert!(shutdown_error_message(PowerAction::Restart, 5).contains("SeShutdownPrivilege"));
        assert!(shutdown_error_message(PowerAction::Restart, 21).contains("not ready to restart"));
        assert!(shutdown_error_message(PowerAction::Shutdown, 21).contains("not ready to shut down"));
        let other = shutdown_error_message(PowerAction::Shutdown, 87);
        assert!(other.contains("error 87"), "{other}");
    }

    #[test]
    fn retry_policy() {
        assert!(should_retry(21, 0));
        assert!(!should_retry(21, 1));
        assert!(!should_retry(1115, 0));
        assert!(!should_retry(5, 0));
    }

    #[test]
    fn messages() {
        assert_eq!(
            shutdown_success_message(PowerAction::Shutdown, "DESKTOP-01", 5),
            "DESKTOP-01 will power off in 5 seconds."
        );
        assert_eq!(
            shutdown_success_message(PowerAction::Restart, "DESKTOP-01", 5),
            "DESKTOP-01 will restart in 5 seconds."
        );
        assert_eq!(
            shutdown_success_message(PowerAction::Restart, "DESKTOP-01", 1),
            "DESKTOP-01 will restart in 1 second."
        );
        assert_eq!(shutdown_success_message(PowerAction::Shutdown, "DESKTOP-01", 0), "DESKTOP-01 is powering off now.");
        assert_eq!(suspend_message(PowerAction::Sleep, "DESKTOP-01"), "DESKTOP-01 is going to sleep now.");
        assert_eq!(suspend_message(PowerAction::Hibernate, "DESKTOP-01"), "DESKTOP-01 is hibernating now.");
    }

    #[test]
    fn computer_name_matches_environment() {
        let n = computer_name();
        assert!(!n.is_empty());
        if let Ok(env) = std::env::var("COMPUTERNAME") {
            assert!(n.eq_ignore_ascii_case(&env), "{n} vs {env}");
        }
    }
}
