//! Notification-area (system tray) companion app. Talks to the service only via [`crate::ipc`].
//! Also hosts the `--lock` session helper (LockWorkStation in the user's session).
//!
//! * `predator-tray.exe --lock` → `LockWorkStation()`; exit code 0 or the Win32 error. No window,
//!   no mutex, nothing else (launched by the service inside the user's session).
//! * `predator-tray.exe` → one tray icon per session (named mutex), hidden window, context menu,
//!   status refresh on menu open / after actions / when the Vigil or `Tailscale` service
//!   changes state (`NotifyServiceStatusChangeW`, no polling) / every 5 minutes for the details
//!   the SCM does not report (every 60 s while the service cannot be watched, does not answer or
//!   reports Telegram as offline, e.g. right after a start or while the network is down).
//!   A refresh = SCM queries of both services + IPC Status; it never spawns tailscale.exe. Exits
//!   silently when the service says this user is not the owner. The IME is disabled for the
//!   process (no text input), so the Text Services Framework is never loaded.
//!
//! [`model`] holds the pure, unit-tested logic; `ui` and `watch` the Win32 plumbing.

pub mod model;
mod ui;
mod watch;

use windows_sys::Win32::System::Shutdown::LockWorkStation;

use crate::util::win::last_error;

/// Entry point of `predator-tray.exe` (GUI subsystem). Returns the process exit code.
pub fn main_entry() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if model::is_lock_invocation(&args) {
        return lock_workstation();
    }
    // A panic outside the window procedure (which has its own guard) must not abort with a
    // console-less crash dialog: report a failure exit code instead.
    std::panic::catch_unwind(ui::run).unwrap_or(1)
}

/// Session helper: lock this session's workstation and report the result as the exit code.
fn lock_workstation() -> i32 {
    // SAFETY: no arguments; documented to work only for processes on the interactive desktop,
    // which is where the service launches us (failure is reported via GetLastError).
    let ok = unsafe { LockWorkStation() } != 0;
    let err = if ok { 0 } else { last_error() };
    model::lock_exit_code(ok, err)
}
