//! SCM plumbing (no windows-service crate): dispatcher, `ServiceMain`, the extended control
//! handler and status reporting with checkpoints.
//!
//! The control handler only copies `(control, event type, session id)` into a channel and
//! returns; the service main thread (orchestrator) does the actual work.

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::mpsc::{Sender, channel};

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SESSIONCHANGE,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_PRESHUTDOWN,
    SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND};
use windows_sys::core::PWSTR;

use super::runtime::{OFFLINE_SEND_BUDGET, Runtime, RuntimeOptions, StopReason, catch};
use crate::logging::{EventKind, report_system_event};
use crate::paths::{DataPaths, SERVICE_NAME};
use crate::util::win::{last_error, wide};
use crate::{log_error, log_info};

/// Service-specific exit codes (shown by `sc query` and in SCM event 7024).
const EXIT_START_FAILED: u32 = 1;
const EXIT_CRASHED: u32 = 2;
const EXIT_NO_HANDLER: u32 = 3;
/// START_PENDING wait hint between checkpoints.
const START_WAIT_HINT_MS: u32 = 30_000;
/// STOP_PENDING wait hint between checkpoints. The stop sequence reports a checkpoint at least
/// once a second while it waits for the "going offline" send (≤ OFFLINE_SEND_BUDGET), so this
/// mainly covers stopping the monitors; the whole sequence stays well inside the 15 s
/// preshutdown timeout.
const STOP_WAIT_HINT_MS: u32 = 8_000;
const _: () = assert!(OFFLINE_SEND_BUDGET.as_millis() < STOP_WAIT_HINT_MS as u128);

/// A control request copied out of the handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlEvent {
    Stop,
    Preshutdown,
    Resume,
    Suspend,
    SessionChange { event_type: u32, session_id: u32 },
}

static CONTROL_TX: Mutex<Option<Sender<ControlEvent>>> = Mutex::new(None);
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);
/// Data directory override (`predator-service.exe --data-dir D` as the service binary path).
static DATA_ROOT: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

const ACCEPTED: u32 =
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE;

/// Pure mapping of a control request to (event to forward, handler return code).
pub(crate) fn classify_control(control: u32, event_type: u32, session_id: Option<u32>) -> (Option<ControlEvent>, u32) {
    match control {
        SERVICE_CONTROL_STOP => (Some(ControlEvent::Stop), NO_ERROR),
        SERVICE_CONTROL_PRESHUTDOWN => (Some(ControlEvent::Preshutdown), NO_ERROR),
        SERVICE_CONTROL_INTERROGATE => (None, NO_ERROR),
        SERVICE_CONTROL_POWEREVENT => match event_type {
            PBT_APMRESUMEAUTOMATIC => (Some(ControlEvent::Resume), NO_ERROR),
            PBT_APMSUSPEND => (Some(ControlEvent::Suspend), NO_ERROR),
            _ => (None, NO_ERROR),
        },
        SERVICE_CONTROL_SESSIONCHANGE => match session_id {
            Some(id) => (Some(ControlEvent::SessionChange { event_type, session_id: id }), NO_ERROR),
            None => (None, NO_ERROR),
        },
        _ => (None, ERROR_CALL_NOT_IMPLEMENTED),
    }
}

/// HandlerEx: copy and return immediately. Never panics across the FFI boundary.
unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    std::panic::catch_unwind(|| {
        let session_id = if control == SERVICE_CONTROL_SESSIONCHANGE && !event_data.is_null() {
            // SAFETY: for SESSIONCHANGE the SCM passes a WTSSESSION_NOTIFICATION valid during the call.
            Some(unsafe { (*(event_data as *const WTSSESSION_NOTIFICATION)).dwSessionId })
        } else {
            None
        };
        let (event, rc) = classify_control(control, event_type, session_id);
        if let Some(ev) = event
            && let Some(tx) = CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
        {
            let _ = tx.send(ev);
        }
        rc
    })
    .unwrap_or(NO_ERROR)
}

fn report(state: u32, wait_hint_ms: u32, win32_exit: u32, specific_exit: u32) {
    let handle: SERVICE_STATUS_HANDLE = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { ACCEPTED } else { 0 },
        dwWin32ExitCode: win32_exit,
        dwServiceSpecificExitCode: specific_exit,
        dwCheckPoint: if pending { CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1 } else { 0 },
        dwWaitHint: if pending { wait_hint_ms } else { 0 },
    };
    // SAFETY: handle from RegisterServiceCtrlHandlerExW; `status` is fully initialised.
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        log_error!("SetServiceStatus({state}) failed: error {}", last_error());
    }
}

/// Run under the SCM. Returns `Err(win32 error)` when not started by the SCM
/// (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) or the dispatcher fails.
pub(crate) fn run_dispatcher(data_root: Option<std::path::PathBuf>) -> Result<(), u32> {
    *DATA_ROOT.lock().unwrap_or_else(|e| e.into_inner()) = data_root;
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    // SAFETY: NUL-terminated table; blocks until the service stops (or fails immediately).
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Text written to the Application event log when the service cannot run.
pub(crate) fn failure_event_text(what: &str, detail: &str, code: u32) -> String {
    format!(
        "{} {what}: {detail}\r\n\r\nThe service stopped with service-specific error {code}. Windows restarts it \
         automatically according to its recovery settings; fix the cause above (details may also be in \
         %ProgramData%\\Predator\\logs\\predator.log) or check 'predator-service.exe selftest' from an elevated prompt.",
        crate::PRODUCT_NAME
    )
}

/// Record a fatal service error everywhere it can be seen: the file log (when it is already
/// open) and the Application event log (always — the file log may be what failed).
fn report_fatal(what: &str, detail: &str, code: u32) {
    log_error!("{what}: {detail}");
    report_system_event(EventKind::Error, &failure_event_text(what, detail, code));
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let result = catch(service_body);
    if let Err(e) = result {
        let _ = catch(|| report_fatal("crashed", &e, EXIT_CRASHED));
        report(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, EXIT_CRASHED);
        std::process::exit(EXIT_CRASHED as i32);
    }
}

fn service_body() {
    let (tx, rx) = channel();
    *CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    let name = wide(SERVICE_NAME);
    // SAFETY: NUL-terminated name and a handler that lives for the whole process.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null()) };
    if handle.is_null() {
        // No status handle to report to; the SCM notices the process exiting.
        let err = last_error();
        report_fatal(
            "could not register its service control handler",
            &format!("RegisterServiceCtrlHandlerExW failed with error {err}"),
            EXIT_NO_HANDLER,
        );
        std::process::exit(EXIT_NO_HANDLER as i32);
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    report(SERVICE_START_PENDING, START_WAIT_HINT_MS, NO_ERROR, 0);

    let root = DATA_ROOT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let paths = root.map(DataPaths::new).unwrap_or_else(DataPaths::default_paths);
    let opts = RuntimeOptions { paths, console: false, token_file: None, verbose: false };
    let progress = || report(SERVICE_START_PENDING, START_WAIT_HINT_MS, NO_ERROR, 0);
    let runtime = match Runtime::start(opts, &progress) {
        Ok(rt) => rt,
        Err(e) => {
            // Failures before the file logger exists (e.g. the data directory cannot be created)
            // would otherwise leave no trace except the generic SCM event.
            report_fatal("could not start", &e, EXIT_START_FAILED);
            // Non-zero exit + failure-actions flag → the SCM applies the restart policy.
            report(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, EXIT_START_FAILED);
            std::process::exit(EXIT_START_FAILED as i32);
        }
    };
    report(SERVICE_RUNNING, 0, NO_ERROR, 0);
    log_info!("service running");

    let reason = loop {
        match rx.recv() {
            Ok(ControlEvent::Stop) => break StopReason::ServiceStopped,
            Ok(ControlEvent::Preshutdown) => break StopReason::SystemShutdown,
            Ok(ControlEvent::Resume) => runtime.on_resume(),
            Ok(ControlEvent::Suspend) => log_info!("system is suspending"),
            Ok(ControlEvent::SessionChange { event_type, session_id }) => {
                runtime.on_session_change(event_type, session_id)
            }
            Err(_) => break StopReason::ServiceStopped,
        }
    };
    let checkpoint = || report(SERVICE_STOP_PENDING, STOP_WAIT_HINT_MS, NO_ERROR, 0);
    checkpoint();
    runtime.shutdown(reason, &checkpoint);
    report(SERVICE_STOPPED, 0, NO_ERROR, 0);
    // Long-poll threads are not joined; all state is already persisted.
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_mapping() {
        assert_eq!(classify_control(SERVICE_CONTROL_STOP, 0, None), (Some(ControlEvent::Stop), NO_ERROR));
        assert_eq!(classify_control(SERVICE_CONTROL_PRESHUTDOWN, 0, None), (Some(ControlEvent::Preshutdown), NO_ERROR));
        assert_eq!(classify_control(SERVICE_CONTROL_INTERROGATE, 0, None), (None, NO_ERROR));
        assert_eq!(
            classify_control(SERVICE_CONTROL_POWEREVENT, PBT_APMRESUMEAUTOMATIC, None),
            (Some(ControlEvent::Resume), NO_ERROR)
        );
        assert_eq!(
            classify_control(SERVICE_CONTROL_POWEREVENT, PBT_APMSUSPEND, None),
            (Some(ControlEvent::Suspend), NO_ERROR)
        );
        assert_eq!(classify_control(SERVICE_CONTROL_POWEREVENT, 0xA, None), (None, NO_ERROR));
        assert_eq!(
            classify_control(SERVICE_CONTROL_SESSIONCHANGE, 5, Some(2)),
            (Some(ControlEvent::SessionChange { event_type: 5, session_id: 2 }), NO_ERROR)
        );
        assert_eq!(classify_control(0x2 /* PAUSE */, 0, None), (None, ERROR_CALL_NOT_IMPLEMENTED));
        assert_eq!(ACCEPTED, 0x1C1);
    }

    #[test]
    fn failure_text_is_actionable() {
        let t = failure_event_text("could not start", "Cannot create the data directories in C:\\x: denied", 1);
        assert!(t.starts_with(crate::PRODUCT_NAME));
        assert!(t.contains("could not start: Cannot create the data directories"));
        assert!(t.contains("service-specific error 1"));
        assert!(t.contains("selftest"));
        let codes = [EXIT_START_FAILED, EXIT_CRASHED, EXIT_NO_HANDLER];
        assert!(codes.iter().all(|c| *c != 0));
    }

    #[test]
    fn dispatcher_outside_scm_fails_cleanly() {
        // Not started by the SCM: must return ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, not hang.
        assert_eq!(run_dispatcher(None), Err(windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT));
    }
}
