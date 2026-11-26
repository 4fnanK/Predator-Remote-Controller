//! Interactive sessions (WTS): enumeration, lock (via session helper), logoff, running a program
//! inside a user's session and launching a GUI program there.
//!
//! Notes:
//! * `LockWorkStation` only works on the interactive desktop, so the service starts our own
//!   `predator-tray.exe --lock` in the target session with the user's token
//!   (`WTSQueryUserToken` + `CreateEnvironmentBlock` + `CreateProcessAsUserW` on
//!   `winsta0\default`). That requires LocalSystem (SeTcbPrivilege); in console/test mode the
//!   helper is started directly when the target is our own session.
//! * Every child is created suspended, offered to a kill-on-close job, then resumed. Job objects
//!   are per session ("all processes within a job must run within the same session as the
//!   job"), so a child started in a user session from the session-0 service normally cannot join
//!   the service's job: `AssignProcessToJobObject` fails, which is expected and logged at debug
//!   level only. Such a child (the lock helper, or the Tailscale CLI as the user) runs without
//!   kill-on-close / die-on-unhandled-exception; on timeout only that process is terminated.
//!   Neither of those programs starts children of its own.
//! * [`launch_in_session`] is the one exception: it starts a long-lived GUI program (the Tailscale
//!   app) that must outlive the call and the service, so it gets no job, no inherited handle and
//!   is not waited for.
//! * Handle inheritance: the child's pipe ends are created non-inheritable, flagged inheritable
//!   only while [`process::SPAWN_LOCK`] is held, passed through
//!   `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, and closed again before the lock is released, so no
//!   concurrent spawn in this process can inherit them.
//! * Lock state comes from `WTSSessionInfoEx` (`SessionFlags`: 0 = locked, 1 = unlocked on
//!   Windows 8+; the values were only reversed on Windows 7 / Server 2008 R2, which we do not support).

use std::ffi::c_void;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::FromRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, ERROR_PRIVILEGE_NOT_HELD, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CLIENT_ADDRESS, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
    WTS_SESSION_INFOW, WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK, WTSActive, WTSClientAddress, WTSConnectQuery,
    WTSConnected, WTSDisconnected, WTSDomainName, WTSDown, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSGetActiveConsoleSessionId, WTSINFOEXW, WTSIdle, WTSInit, WTSListen, WTSLogoffSession,
    WTSQuerySessionInformationW, WTSQueryUserToken, WTSReset, WTSSessionInfoEx, WTSShadow, WTSUserName,
    WTSWinStationName,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_DEFAULT_ERROR_MODE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DETACHED_PROCESS, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcessId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW, UpdateProcThreadAttribute,
};

use super::SessionInfo;
use super::process::{self, Job, OutputReaders, ProcessOutput};
use crate::util::win::{OwnedHandle, WinError, error_message, from_wide, from_wide_ptr, wide, wide_path};
use crate::{log_debug, log_error, log_info, log_warn};

/// `SessionInfo::state` label of an active session.
const STATE_ACTIVE: &str = "Active";
/// How long the lock helper may take.
const LOCK_HELPER_TIMEOUT: Duration = Duration::from_secs(5);
/// Desktop for processes started in a user session (interactive window station).
const INTERACTIVE_DESKTOP: &str = "winsta0\\default";
/// `CreateProcess` command-line limit (32,767 UTF-16 units including the NUL).
const MAX_COMMAND_LINE_UNITS: usize = 32_766;
/// `WTSGetActiveConsoleSessionId` while no session is attached to the console.
const NO_CONSOLE_SESSION: u32 = 0xFFFF_FFFF;
/// Creation flags of a program started by [`launch_in_session`]: no console of ours (a console
/// program gets none at all), its own process group (no Ctrl+C from our console) and the
/// default error mode instead of the service's.
const LAUNCH_FLAGS: PROCESS_CREATION_FLAGS = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_DEFAULT_ERROR_MODE;

/// All user sessions (console + RDP), excluding session 0 and sessions without a user.
pub fn list_sessions() -> Vec<SessionInfo> {
    let mut p: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut n = 0u32;
    // SAFETY: valid out pointers; the buffer is freed by the guard below.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut p, &mut n) } == 0 {
        log_warn!("session: {}", WinError::last("WTSEnumerateSessionsW"));
        return Vec::new();
    }
    let _guard = WtsMemory(p.cast());
    if p.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: WTSEnumerateSessionsW returned `n` contiguous WTS_SESSION_INFOW entries at `p`,
    // valid until WTSFreeMemory (the guard outlives this slice).
    let entries = unsafe { std::slice::from_raw_parts(p, n as usize) };
    entries
        .iter()
        .filter(|e| e.SessionId != 0)
        .filter_map(|e| {
            let id = e.SessionId;
            let user = query_string(id, WTSUserName).unwrap_or_default();
            if user.is_empty() {
                return None;
            }
            // SAFETY: pWinStationName is null or a NUL-terminated string inside the WTS buffer.
            let mut station = unsafe { from_wide_ptr(e.pWinStationName) };
            if station.is_empty() {
                station = query_string(id, WTSWinStationName).unwrap_or_default();
            }
            let client_address = if station.eq_ignore_ascii_case("Console") { None } else { query_client_address(id) };
            Some(SessionInfo {
                id,
                domain: query_string(id, WTSDomainName).unwrap_or_default(),
                user,
                state: state_label(e.State).to_string(),
                station,
                locked: query_lock_state(id),
                client_address,
            })
        })
        .collect()
}

/// The active console session's user, else the first active RDP session with a user.
pub fn active_user_session() -> Option<SessionInfo> {
    // SAFETY: trivial call.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    pick_active(&list_sessions(), console)
}

/// Lock every active user session by launching `helper_exe --lock` in each session as that user
/// (WTSQueryUserToken + CreateProcessAsUserW on winsta0\default). Returns a summary message.
pub fn lock_active_sessions(helper_exe: &Path) -> Result<String, String> {
    check_helper(helper_exe)?;
    let outcomes: Vec<LockOutcome> = list_sessions()
        .iter()
        .filter(|s| is_active_user_session(s))
        .map(|s| {
            let label = session_label(s);
            let result = if s.locked == Some(true) {
                LockResult::AlreadyLocked
            } else {
                match lock_session(s, helper_exe) {
                    Ok(()) => LockResult::Locked,
                    Err(e) => {
                        log_warn!("session: locking session {} failed: {e}", s.id);
                        LockResult::Failed(e)
                    }
                }
            };
            LockOutcome { label, result }
        })
        .collect();
    let summary = lock_summary(&outcomes);
    match &summary {
        Ok(m) => log_info!("session: {m}"),
        Err(e) => log_error!("session: lock failed: {e}"),
    }
    summary
}

/// Log off the active user session (WTSLogoffSession). Returns a summary message.
pub fn logoff_active_user() -> Result<String, String> {
    let s = active_user_session().ok_or_else(|| "No user is logged in — nothing to log off.".to_string())?;
    // SAFETY: plain call; bWait = FALSE so it returns as soon as the logoff has been started.
    if unsafe { WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, s.id, 0) } == 0 {
        let e = WinError::last("WTSLogoffSession");
        log_error!("session: logoff of session {} failed: {e}", s.id);
        return Err(format!("Could not log off {} (session {}): {e}", s.user, s.id));
    }
    log_info!("session: logoff of {} (session {}) initiated", s.user, s.id);
    Ok(format!("Logged off {} (session {}).", s.user, s.id))
}

/// Run `exe args...` inside `session_id` as the logged-on user with a hidden window, capturing
/// output, killed after `timeout`. Requires LocalSystem (SeTcbPrivilege).
pub fn run_as_session_user(
    session_id: u32,
    exe: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    let command_line = build_command_line(exe, args)?;
    match query_user_token(session_id) {
        Ok(token) => {
            let child = spawn_with_token(token.raw(), exe, &command_line, true)?;
            drop(token);
            child.finish(timeout)
        }
        Err(e) if e.code == ERROR_PRIVILEGE_NOT_HELD && current_session_id() == Some(session_id) => {
            // Console/test mode: we already run as a user inside that session.
            log_debug!("session: not LocalSystem; running {} directly in session {session_id}", exe.display());
            process::run_with_timeout(exe, args, timeout)
        }
        Err(e) => Err(token_error_text(session_id, &e)),
    }
}

/// Start the GUI program `exe args...` (absolute path) inside `session_id` as the session's user
/// on `winsta0\default` and return its PID without waiting for it. Unlike the helpers above the
/// program is meant to keep running on its own: it gets no job object (it breaks away from a job
/// this process may be in, when that job allows it), inherits no handle, gets the user's
/// environment and its own directory as working directory; our process/thread handles are closed
/// right away. Requires LocalSystem (SeTcbPrivilege); in console/test mode a program for our own
/// session is started directly instead.
pub fn launch_in_session(session_id: u32, exe: &Path, args: &[&str]) -> Result<u32, String> {
    check_launch_target(exe)?;
    let command_line = build_command_line(exe, args)?;
    let pid = match query_user_token(session_id) {
        Ok(token) => launch_with_token(token.raw(), exe, &command_line)?,
        Err(e) if e.code == ERROR_PRIVILEGE_NOT_HELD && current_session_id() == Some(session_id) => {
            // Console/test mode: we already run as a user inside that session.
            log_debug!("session: not LocalSystem; launching {} directly in session {session_id}", exe.display());
            launch_direct(exe, args)?
        }
        Err(e) => return Err(token_error_text(session_id, &e)),
    };
    log_info!("session: launched {} in session {session_id} (pid {pid})", exe_name(exe));
    Ok(pid)
}

/// String SID of the user logged on to `session_id`.
pub fn session_user_sid(session_id: u32) -> Option<String> {
    match query_user_token(session_id) {
        Ok(token) => token_user_sid(token.raw()).or_else(|| sid_from_session_names(session_id)),
        // Nobody is logged on to that session.
        Err(e) if e.code == ERROR_NO_TOKEN => None,
        // Not LocalSystem (console/test mode): resolve the session's DOMAIN\user name instead.
        Err(_) => sid_from_session_names(session_id),
    }
}

/// Build a `CreateProcess` command line: the quoted program path followed by the arguments,
/// quoted so that `CommandLineToArgvW` / the MSVC CRT parse them back unchanged.
pub fn build_command_line(exe: &Path, args: &[&str]) -> Result<String, String> {
    let program = exe.to_string_lossy();
    if program.is_empty() || program.contains('"') || program.contains('\0') {
        return Err(format!("Invalid program path: {}", exe.display()));
    }
    let mut s = String::with_capacity(program.len() + 2 + args.iter().map(|a| a.len() + 3).sum::<usize>());
    s.push('"');
    s.push_str(&program);
    s.push('"');
    for a in args {
        if a.contains('\0') {
            return Err("A command-line argument contains a NUL character.".into());
        }
        s.push(' ');
        quote_arg(a, &mut s);
    }
    if s.encode_utf16().count() > MAX_COMMAND_LINE_UNITS {
        return Err("The command line is too long.".into());
    }
    Ok(s)
}

// ---------------------------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------------------------

/// `WTS_CONNECTSTATE_CLASS` value → label.
const STATE_LABELS: [(WTS_CONNECTSTATE_CLASS, &str); 10] = [
    (WTSActive, STATE_ACTIVE),
    (WTSConnected, "Connected"),
    (WTSConnectQuery, "ConnectQuery"),
    (WTSShadow, "Shadow"),
    (WTSDisconnected, "Disconnected"),
    (WTSIdle, "Idle"),
    (WTSListen, "Listen"),
    (WTSReset, "Reset"),
    (WTSDown, "Down"),
    (WTSInit, "Init"),
];

/// Label of a `WTS_CONNECTSTATE_CLASS` value.
fn state_label(state: WTS_CONNECTSTATE_CLASS) -> &'static str {
    STATE_LABELS.iter().find(|(v, _)| *v == state).map_or("Unknown", |(_, label)| label)
}

/// `WTSINFOEX_LEVEL1_W::SessionFlags` → locked? (Windows 8+ semantics.)
fn lock_state_from_flags(flags: i32) -> Option<bool> {
    match flags as u32 {
        WTS_SESSIONSTATE_LOCK => Some(true),
        WTS_SESSIONSTATE_UNLOCK => Some(false),
        _ => None,
    }
}

/// Offset of the IP address inside `WTS_CLIENT_ADDRESS::Address`. Microsoft documents that "the IP
/// address is offset by two bytes from the start of the Address member" (the first two bytes are
/// the port slot of a sockaddr), for IPv4 and IPv6 alike.
const CLIENT_ADDRESS_OFFSET: usize = 2;

/// Format a `WTS_CLIENT_ADDRESS` (`AddressFamily`, `Address`): AF_INET → `Address[2..6]`,
/// AF_INET6 → `Address[2..18]`. IPv4-mapped IPv6 addresses are shown as IPv4. `None` for other
/// families and for the unspecified address. Shared decoder for every WTS client address.
pub(crate) fn format_client_address(family: u32, addr: &[u8; 20]) -> Option<String> {
    const V4: std::ops::Range<usize> = CLIENT_ADDRESS_OFFSET..CLIENT_ADDRESS_OFFSET + 4;
    const V6: std::ops::Range<usize> = CLIENT_ADDRESS_OFFSET..CLIENT_ADDRESS_OFFSET + 16;
    let ip: IpAddr = if family == u32::from(AF_INET) {
        let b: [u8; 4] = addr[V4].try_into().ok()?;
        IpAddr::V4(Ipv4Addr::from(b))
    } else if family == u32::from(AF_INET6) {
        let b: [u8; 16] = addr[V6].try_into().ok()?;
        Ipv6Addr::from(b).to_canonical()
    } else {
        return None;
    };
    (!ip.is_unspecified()).then(|| ip.to_string())
}

fn is_active_user_session(s: &SessionInfo) -> bool {
    s.state == STATE_ACTIVE && !s.user.is_empty()
}

/// The console session if it is active with a user, else the first active session with a user.
fn pick_active(sessions: &[SessionInfo], console: u32) -> Option<SessionInfo> {
    if console != NO_CONSOLE_SESSION
        && let Some(s) = sessions.iter().find(|s| s.id == console && is_active_user_session(s))
    {
        return Some(s.clone());
    }
    sessions.iter().find(|s| is_active_user_session(s)).cloned()
}

/// `alex (Console)` / `alex (session 3)`.
fn session_label(s: &SessionInfo) -> String {
    if s.station.is_empty() { format!("{} (session {})", s.user, s.id) } else { format!("{} ({})", s.user, s.station) }
}

/// File name of `exe` for messages (`tailscale-ipn.exe`), else the full path.
fn exe_name(exe: &Path) -> String {
    exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| exe.display().to_string())
}

/// [`launch_in_session`] only starts an existing program given by its full path.
fn check_launch_target(exe: &Path) -> Result<(), String> {
    if !exe.is_absolute() {
        return Err(format!("Cannot start {}: not a full path", exe.display()));
    }
    if !exe.is_file() {
        return Err(format!("Cannot start {}: {} does not exist", exe_name(exe), exe.display()));
    }
    Ok(())
}

/// Run `create` with `CREATE_BREAKAWAY_FROM_JOB` (no effect while this process is in no job). A
/// job that forbids breakaway makes process creation fail with `ERROR_ACCESS_DENIED`: then the
/// program is started without the flag (it stays in that job, which is not ours).
fn with_breakaway<T, E: std::fmt::Display>(
    mut create: impl FnMut(PROCESS_CREATION_FLAGS) -> Result<T, E>,
    error_code: impl Fn(&E) -> Option<u32>,
) -> Result<T, E> {
    match create(CREATE_BREAKAWAY_FROM_JOB) {
        Err(e) if error_code(&e) == Some(ERROR_ACCESS_DENIED) => {
            log_debug!("session: breaking away from the job was refused ({e}); starting without it");
            create(0)
        }
        r => r,
    }
}

fn check_helper(helper_exe: &Path) -> Result<(), String> {
    if helper_exe.is_file() {
        return Ok(());
    }
    let name = helper_exe.file_name().map(|n| n.to_string_lossy().into_owned());
    log_warn!("session: lock helper missing: {}", helper_exe.display());
    Err(format!(
        "Session helper unavailable: {} not found next to the service",
        name.as_deref().unwrap_or(crate::paths::TRAY_EXE)
    ))
}

#[derive(Clone, Debug, PartialEq)]
enum LockResult {
    Locked,
    AlreadyLocked,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
struct LockOutcome {
    label: String,
    result: LockResult,
}

/// Summary such as `Locked 1 session: alex (Console)`. Err when nothing could be locked.
fn lock_summary(outcomes: &[LockOutcome]) -> Result<String, String> {
    if outcomes.is_empty() {
        return Err("No user is logged in — nothing to lock.".into());
    }
    let pick = |want: fn(&LockResult) -> bool| -> Vec<&str> {
        outcomes.iter().filter(|o| want(&o.result)).map(|o| o.label.as_str()).collect()
    };
    let locked = pick(|r| *r == LockResult::Locked);
    let already = pick(|r| *r == LockResult::AlreadyLocked);
    let failed: Vec<String> = outcomes
        .iter()
        .filter_map(|o| match &o.result {
            LockResult::Failed(e) => Some(format!("{} — {e}", o.label)),
            _ => None,
        })
        .collect();

    if locked.is_empty() && already.is_empty() {
        return Err(format!("Could not lock {}", failed.join("; ")));
    }
    let mut parts = Vec::new();
    if !locked.is_empty() {
        let n = locked.len();
        parts.push(format!("Locked {n} session{}: {}", if n == 1 { "" } else { "s" }, locked.join(", ")));
    }
    if !already.is_empty() {
        let head = if parts.is_empty() { "Already locked" } else { "already locked" };
        parts.push(format!("{head}: {}", already.join(", ")));
    }
    if !failed.is_empty() {
        parts.push(format!("failed: {}", failed.join("; ")));
    }
    Ok(parts.join("; "))
}

/// Interpret the lock helper's result (exit code 0 = locked).
fn lock_exit_result(out: &ProcessOutput) -> Result<(), String> {
    if out.timed_out {
        return Err(format!("the lock helper did not finish within {} seconds", LOCK_HELPER_TIMEOUT.as_secs()));
    }
    match out.exit_code {
        Some(0) => Ok(()),
        // Small codes are most likely Win32 errors from LockWorkStation (GetLastError).
        Some(code @ 2..=15_999) => Err(format!("the lock helper failed: {} (code {code})", error_message(code))),
        Some(code) => Err(format!("the lock helper failed with exit code {code}")),
        None => Err("the lock helper ended without an exit code".into()),
    }
}

fn token_error_text(session_id: u32, e: &WinError) -> String {
    match e.code {
        ERROR_PRIVILEGE_NOT_HELD => {
            format!("the service is not running as LocalSystem, so it cannot act in session {session_id}")
        }
        ERROR_NO_TOKEN => format!("no user is logged on to session {session_id}"),
        _ => format!("cannot get the user token of session {session_id}: {e}"),
    }
}

/// Append `arg` quoted for `CommandLineToArgvW` (MSVC CRT rules).
fn quote_arg(arg: &str, out: &mut String) {
    let needs_quotes = arg.is_empty() || arg.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"'));
    if !needs_quotes {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Backslashes before a quote are doubled, and the quote itself is escaped.
                push_repeated(out, '\\', backslashes * 2 + 1);
                out.push('"');
                backslashes = 0;
            }
            _ => {
                push_repeated(out, '\\', backslashes);
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Backslashes before the closing quote are doubled.
    push_repeated(out, '\\', backslashes * 2);
    out.push('"');
}

fn push_repeated(out: &mut String, c: char, n: usize) {
    out.extend(std::iter::repeat_n(c, n));
}

// ---------------------------------------------------------------------------------------------
// WTS queries
// ---------------------------------------------------------------------------------------------

/// Memory returned by WTS functions, released with `WTSFreeMemory`.
struct WtsMemory(*mut c_void);

impl Drop for WtsMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was allocated by a WTS function and is freed exactly once.
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

/// A `WTSQuerySessionInformationW` result buffer.
struct WtsBuffer {
    mem: WtsMemory,
    bytes: usize,
}

impl WtsBuffer {
    fn query(session_id: u32, class: WTS_INFO_CLASS) -> Option<Self> {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let mut bytes = 0u32;
        // SAFETY: valid out pointers; the buffer is owned by the returned guard.
        let ok =
            unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, class, &mut buf, &mut bytes) };
        if ok == 0 || buf.is_null() {
            return None;
        }
        Some(Self { mem: WtsMemory(buf.cast()), bytes: bytes as usize })
    }

    fn string(&self) -> String {
        let units = self.bytes / 2;
        if units == 0 {
            return String::new();
        }
        // SAFETY: the buffer holds `bytes` bytes of UTF-16 text (NUL-terminated within).
        from_wide(unsafe { std::slice::from_raw_parts(self.mem.0 as *const u16, units) })
    }

    /// Copy a fixed-size structure out of the buffer if it is large enough.
    fn read<T: Copy>(&self) -> Option<T> {
        if self.bytes < std::mem::size_of::<T>() {
            return None;
        }
        // SAFETY: at least size_of::<T>() bytes are valid; T is plain old data (Copy, repr(C)).
        Some(unsafe { std::ptr::read_unaligned(self.mem.0 as *const T) })
    }
}

fn query_string(session_id: u32, class: WTS_INFO_CLASS) -> Option<String> {
    WtsBuffer::query(session_id, class).map(|b| b.string())
}

fn query_lock_state(session_id: u32) -> Option<bool> {
    let info: WTSINFOEXW = WtsBuffer::query(session_id, WTSSessionInfoEx)?.read()?;
    if info.Level != 1 {
        return None;
    }
    // SAFETY: Level 1 means the union holds WTSINFOEX_LEVEL1_W.
    let flags = unsafe { info.Data.WTSInfoExLevel1.SessionFlags };
    lock_state_from_flags(flags)
}

fn query_client_address(session_id: u32) -> Option<String> {
    let a: WTS_CLIENT_ADDRESS = WtsBuffer::query(session_id, WTSClientAddress)?.read()?;
    format_client_address(a.AddressFamily, &a.Address)
}

fn current_session_id() -> Option<u32> {
    // SAFETY: trivial call.
    process_session_id(unsafe { GetCurrentProcessId() })
}

fn query_user_token(session_id: u32) -> Result<OwnedHandle, WinError> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out pointer; the token is owned by the returned handle.
    if unsafe { WTSQueryUserToken(session_id, &mut token) } == 0 {
        return Err(WinError::last(format!("WTSQueryUserToken(session {session_id})")));
    }
    Ok(OwnedHandle(token))
}

// ---------------------------------------------------------------------------------------------
// SIDs
// ---------------------------------------------------------------------------------------------

fn token_user_sid(token: HANDLE) -> Option<String> {
    let mut len = 0u32;
    // SAFETY: size query (expected to fail with ERROR_INSUFFICIENT_BUFFER and set `len`).
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` provides at least `len` writable, 8-aligned bytes.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return None;
    }
    // SAFETY: the buffer starts with a TOKEN_USER whose SID pointer points into the buffer.
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    sid_to_string(tu.User.Sid)
}

fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut p: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; the string is LocalAlloc'ed and freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 || p.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated string from ConvertSidToStringSidW.
    let s = unsafe { from_wide_ptr(p) };
    // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe { LocalFree(p.cast()) };
    (!s.is_empty()).then_some(s)
}

/// SID of an account name (`DOMAIN\user` or `user`).
fn account_sid(account: &str) -> Option<String> {
    let name = wide(account);
    let mut sid_len = 0u32;
    let mut dom_len = 0u32;
    let mut sid_use: SID_NAME_USE = 0;
    // SAFETY: size query with null buffers.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if sid_len == 0 {
        return None;
    }
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut domain = vec![0u16; dom_len.max(1) as usize];
    dom_len = domain.len() as u32;
    // SAFETY: buffers are sized as reported by the first call.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        return None;
    }
    sid_to_string(sid.as_mut_ptr().cast())
}

fn sid_from_session_names(session_id: u32) -> Option<String> {
    let user = query_string(session_id, WTSUserName).filter(|u| !u.is_empty())?;
    let domain = query_string(session_id, WTSDomainName).unwrap_or_default();
    let account = if domain.is_empty() { user } else { format!("{domain}\\{user}") };
    account_sid(&account)
}

// ---------------------------------------------------------------------------------------------
// Starting a process with a user token
// ---------------------------------------------------------------------------------------------

/// The user's environment block (or null → the child inherits ours).
struct EnvironmentBlock(*mut c_void);

impl EnvironmentBlock {
    fn for_token(token: HANDLE) -> Self {
        let mut env: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid token; `env` is destroyed in Drop.
        if unsafe { CreateEnvironmentBlock(&mut env, token, 0) } == 0 {
            log_warn!("session: {}; no environment block for the user", WinError::last("CreateEnvironmentBlock"));
            env = std::ptr::null_mut();
        }
        Self(env)
    }
}

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: created by CreateEnvironmentBlock, destroyed once.
            unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
}

/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` restricting inheritance to exactly the child's std handles.
struct HandleListAttribute {
    /// Attribute list storage (8-byte aligned).
    buf: Vec<u64>,
    /// Must stay at a stable address until the list is deleted.
    handles: Box<[HANDLE; 3]>,
    initialized: bool,
}

impl HandleListAttribute {
    fn new(handles: [HANDLE; 3]) -> Result<Self, WinError> {
        let mut size = 0usize;
        // SAFETY: size query (fails with ERROR_INSUFFICIENT_BUFFER by design).
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        if size == 0 {
            return Err(WinError::last("InitializeProcThreadAttributeList"));
        }
        let mut me = Self { buf: vec![0u64; size.div_ceil(8)], handles: Box::new(handles), initialized: false };
        let list = me.as_ptr();
        // SAFETY: `list` points to at least `size` writable bytes.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(WinError::last("InitializeProcThreadAttributeList"));
        }
        me.initialized = true;
        let value: *const c_void = me.handles.as_ptr().cast();
        // SAFETY: `value` points to 3 handles that live (boxed) as long as the list.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                value,
                std::mem::size_of::<[HANDLE; 3]>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(WinError::last("UpdateProcThreadAttribute"));
        }
        Ok(me)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for HandleListAttribute {
    fn drop(&mut self) {
        if self.initialized {
            let list = self.as_ptr();
            // SAFETY: initialised list, deleted once.
            unsafe { DeleteProcThreadAttributeList(list) };
        }
    }
}

/// Anonymous pipes for stdout/stderr plus a NUL stdin. Child ends are created non-inheritable
/// and only flagged inheritable under [`process::SPAWN_LOCK`], right before
/// `CreateProcessAsUserW`; they are closed again before the lock is released.
struct StdPipes {
    parent_stdout: OwnedHandle,
    child_stdout: OwnedHandle,
    parent_stderr: OwnedHandle,
    child_stderr: OwnedHandle,
    child_stdin: OwnedHandle,
}

impl StdPipes {
    fn create() -> Result<Self, WinError> {
        let (parent_stdout, child_stdout) = anonymous_pipe()?;
        let (parent_stderr, child_stderr) = anonymous_pipe()?;
        let nul = wide("NUL");
        // SAFETY: NUL-terminated name, default security, no template.
        let stdin = unsafe {
            CreateFileW(
                nul.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if stdin == INVALID_HANDLE_VALUE {
            return Err(WinError::last("CreateFileW(NUL)"));
        }
        Ok(Self { parent_stdout, child_stdout, parent_stderr, child_stderr, child_stdin: OwnedHandle(stdin) })
    }

    fn child_handles(&self) -> [HANDLE; 3] {
        [self.child_stdin.raw(), self.child_stdout.raw(), self.child_stderr.raw()]
    }

    fn make_child_ends_inheritable(&self) -> Result<(), WinError> {
        for h in self.child_handles() {
            // SAFETY: valid handle owned by self.
            if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
                return Err(WinError::last("SetHandleInformation"));
            }
        }
        Ok(())
    }

    /// Close the child ends (so EOF arrives when the child exits) and return the read ends.
    fn into_parent_ends(self) -> (File, File) {
        let StdPipes { parent_stdout, parent_stderr, .. } = self;
        (into_file(parent_stdout), into_file(parent_stderr))
    }
}

fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), WinError> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out pointers; default (non-inheritable) security attributes.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(WinError::last("CreatePipe"));
    }
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

/// Transfer ownership of a handle into a `File` (closed when the File is dropped).
fn into_file(mut h: OwnedHandle) -> File {
    let raw = std::mem::replace(&mut h.0, std::ptr::null_mut());
    // SAFETY: `raw` is a valid handle we own; `h` no longer closes it.
    unsafe { File::from_raw_handle(raw) }
}

/// `C:\Windows\System32` as a NUL-terminated wide string.
fn system_directory() -> Option<Vec<u16>> {
    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is writable for its length.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    buf.truncate(n);
    buf.push(0);
    Some(buf)
}

/// A process started with a user token: suspended → job → resumed.
struct UserChild {
    process: OwnedHandle,
    pid: u32,
    /// Kill-on-close job (dropped after the process has been supervised).
    job: Option<Job>,
    readers: OutputReaders,
}

impl UserChild {
    fn finish(self, timeout: Duration) -> Result<ProcessOutput, String> {
        let UserChild { process, pid, job, readers } = self;
        let out = process::supervise(process.raw(), job.as_ref(), readers, timeout);
        if let Ok(o) = &out {
            log_debug!("session: child pid {pid} finished: exit {:?}, timed out {}", o.exit_code, o.timed_out);
        }
        out
    }
}

/// Start `exe` (full path) with `command_line` as the user of `token` on `winsta0\default`,
/// hidden, with the user's environment and the system directory as working directory.
fn spawn_with_token(token: HANDLE, exe: &Path, command_line: &str, capture: bool) -> Result<UserChild, String> {
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| exe.display().to_string());
    let app = wide_path(exe);
    let mut cmd = wide(command_line);
    let mut desktop = wide(INTERACTIVE_DESKTOP);
    let sysdir = system_directory();
    let env = EnvironmentBlock::for_token(token);
    let pipes = if capture {
        Some(StdPipes::create().map_err(|e| format!("Cannot create output pipes for {name}: {e}"))?)
    } else {
        None
    };

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    let mut flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED;
    let mut inherit = 0;
    let mut attributes = None;
    if let Some(p) = &pipes {
        let mut list = HandleListAttribute::new(p.child_handles())
            .map_err(|e| format!("Cannot prepare handle inheritance for {name}: {e}"))?;
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = p.child_stdin.raw();
        si.StartupInfo.hStdOutput = p.child_stdout.raw();
        si.StartupInfo.hStdError = p.child_stderr.raw();
        si.lpAttributeList = list.as_ptr();
        attributes = Some(list);
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        inherit = 1;
    } else {
        // "You cannot inherit handles across sessions": no inheritance without captured output.
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    }

    let mut pi = PROCESS_INFORMATION::default();
    let mut create = |pi: &mut PROCESS_INFORMATION| -> Result<(), WinError> {
        // SAFETY: every pointer refers to a live, NUL-terminated buffer or structure of this
        // frame; `cmd` is writable as required by the W variant; the attribute list (if any)
        // and the handles it names are alive.
        let ok = unsafe {
            CreateProcessAsUserW(
                token,
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit,
                flags,
                env.0.cast_const(),
                sysdir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                &si.StartupInfo,
                pi,
            )
        };
        if ok == 0 { Err(WinError::last("CreateProcessAsUserW")) } else { Ok(()) }
    };
    // The inheritable window: flag the child ends, create the process, close our copies of the
    // child ends (the readers only see EOF once they are closed) — all under the crate-wide
    // spawn lock, so no other spawn of this process can inherit them. `pipes` is consumed inside
    // this block (no early return), i.e. before the guard is released.
    let (created, parent_ends) = {
        let _spawn = process::spawn_lock();
        let created = match &pipes {
            Some(p) => p
                .make_child_ends_inheritable()
                .map_err(|e| format!("Cannot prepare output pipes for {name}: {e}"))
                .and_then(|()| create(&mut pi).map_err(|e| start_error(&name, &e))),
            None => create(&mut pi).map_err(|e| start_error(&name, &e)),
        };
        (created, pipes.map(StdPipes::into_parent_ends))
    };
    drop(attributes);
    drop(env);
    created?;
    let process = OwnedHandle(pi.hProcess);
    let thread = OwnedHandle(pi.hThread);

    let job = attach_job(process.raw(), pi.dwProcessId, &name);
    // SAFETY: valid thread handle of the suspended main thread.
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let e = WinError::last("ResumeThread");
        process::kill(process.raw(), job.as_ref());
        return Err(format!("Cannot start {name}: {e}"));
    }
    drop(thread);

    let readers = match parent_ends {
        Some((out, err)) => match OutputReaders::start(Some(out), Some(err)) {
            Ok(r) => r,
            Err(e) => {
                process::kill(process.raw(), job.as_ref());
                return Err(e);
            }
        },
        None => OutputReaders::none(),
    };
    log_debug!("session: started {name} as pid {}", pi.dwProcessId);
    Ok(UserChild { process, pid: pi.dwProcessId, job, readers })
}

fn start_error(name: &str, e: &WinError) -> String {
    log_warn!("session: cannot start {name} in the user session: {e}");
    format!("Cannot start {name} in the user session: {e}")
}

/// Working directory of a launched program: its own folder (NUL-terminated), if any.
fn launch_directory(exe: &Path) -> Option<Vec<u16>> {
    exe.parent().filter(|d| !d.as_os_str().is_empty()).map(wide_path)
}

/// [`launch_in_session`] with a user token: `CreateProcessAsUserW` on `winsta0\default`, no
/// inherited handles, no job of ours, nothing waited for. Returns the PID.
fn launch_with_token(token: HANDLE, exe: &Path, command_line: &str) -> Result<u32, String> {
    let name = exe_name(exe);
    let app = wide_path(exe);
    let mut desktop = wide(INTERACTIVE_DESKTOP);
    let cwd = launch_directory(exe);
    let env = EnvironmentBlock::for_token(token);
    if env.0.is_null() {
        // A long-lived program must not inherit the service's (SYSTEM) environment: its profile
        // folders (APPDATA, LOCALAPPDATA, TEMP ...) would point into the system profile.
        return Err(format!("Cannot start {name} in the user session: the user's environment is not available"));
    }
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: desktop.as_mut_ptr(),
        ..Default::default()
    };
    let create = |extra: PROCESS_CREATION_FLAGS| -> Result<PROCESS_INFORMATION, WinError> {
        // A fresh, writable copy per attempt (the W variant may modify the buffer).
        let mut cmd = wide(command_line);
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: every pointer refers to a live, NUL-terminated buffer or structure of this
        // frame; bInheritHandles = FALSE, so no handle of this process reaches the program.
        let ok = unsafe {
            CreateProcessAsUserW(
                token,
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                LAUNCH_FLAGS | CREATE_UNICODE_ENVIRONMENT | extra,
                env.0.cast_const(),
                cwd.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                &si,
                &mut pi,
            )
        };
        if ok == 0 { Err(WinError::last("CreateProcessAsUserW")) } else { Ok(pi) }
    };
    let created = {
        // Nothing is inherited, but every spawn of this crate is serialised by the lock.
        let _spawn = process::spawn_lock();
        with_breakaway(create, |e: &WinError| Some(e.code))
    };
    drop(env);
    let pi = created.map_err(|e| start_error(&name, &e))?;
    // The program runs on its own: close both handles at once.
    drop(OwnedHandle(pi.hThread));
    drop(OwnedHandle(pi.hProcess));
    Ok(pi.dwProcessId)
}

/// [`launch_in_session`] without a token (console/test mode, our own session): a detached child
/// with NUL standard handles that is not waited for. Returns the PID.
fn launch_direct(exe: &Path, args: &[&str]) -> Result<u32, String> {
    let name = exe_name(exe);
    let spawn = |extra: PROCESS_CREATION_FLAGS| -> std::io::Result<std::process::Child> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .creation_flags(LAUNCH_FLAGS | extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(dir) = exe.parent().filter(|d| !d.as_os_str().is_empty()) {
            cmd.current_dir(dir);
        }
        cmd.spawn()
    };
    let child = {
        let _spawn = process::spawn_lock();
        with_breakaway(spawn, |e: &std::io::Error| e.raw_os_error().map(|c| c as u32))
    }
    .map_err(|e| {
        log_warn!("session: cannot start {name}: {e}");
        format!("Cannot start {name}: {e}")
    })?;
    let pid = child.id();
    // Dropping a `Child` only closes our handles; the program keeps running (no zombies on Windows).
    drop(child);
    Ok(pid)
}

/// Offer a (still suspended) child to a fresh kill-on-close job. Returns `None` when that is not
/// possible; across sessions this is the normal case (job objects are per session).
fn attach_job(process: HANDLE, pid: u32, name: &str) -> Option<Job> {
    let job = match Job::new() {
        Ok(j) => j,
        Err(e) => {
            log_warn!("session: no kill-on-close job for {name} (pid {pid}): {e}");
            return None;
        }
    };
    match job.assign(process) {
        Ok(()) => Some(job),
        Err(e) => {
            let (own, child) = (current_session_id(), process_session_id(pid));
            if job_failure_expected(own, child) {
                log_debug!(
                    "session: {name} (pid {pid}) runs in session {} and cannot join a job of session {} ({e}); \
                     it runs without kill-on-close, a timeout terminates only that process",
                    child.unwrap_or_default(),
                    own.unwrap_or_default()
                );
            } else {
                log_warn!("session: no kill-on-close job for {name} (pid {pid}): {e}");
            }
            None
        }
    }
}

/// A failed `AssignProcessToJobObject` is expected when the child runs in another session than
/// the process that created the job ("all processes within a job must run within the same
/// session as the job").
fn job_failure_expected(own_session: Option<u32>, child_session: Option<u32>) -> bool {
    matches!((own_session, child_session), (Some(a), Some(b)) if a != b)
}

fn process_session_id(pid: u32) -> Option<u32> {
    let mut id = 0u32;
    // SAFETY: valid out pointer.
    (unsafe { ProcessIdToSessionId(pid, &mut id) } != 0).then_some(id)
}

/// Lock one session by running the helper in it.
fn lock_session(s: &SessionInfo, helper: &Path) -> Result<(), String> {
    const ARGS: [&str; 1] = ["--lock"];
    let out = match query_user_token(s.id) {
        Ok(token) => {
            let command_line = build_command_line(helper, &ARGS)?;
            let child = spawn_with_token(token.raw(), helper, &command_line, false)?;
            drop(token);
            child.finish(LOCK_HELPER_TIMEOUT)?
        }
        Err(e) if e.code == ERROR_PRIVILEGE_NOT_HELD && current_session_id() == Some(s.id) => {
            log_info!("session: not LocalSystem; starting the lock helper directly in session {}", s.id);
            process::run_with_timeout(helper, &ARGS, LOCK_HELPER_TIMEOUT)?
        }
        Err(e) => return Err(token_error_text(s.id, &e)),
    };
    lock_exit_result(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use windows_sys::Win32::Security::{TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    fn system32(exe: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        root.join("System32").join(exe)
    }

    fn sess(id: u32, user: &str, state: &str, station: &str) -> SessionInfo {
        SessionInfo {
            id,
            user: user.into(),
            domain: "DESKTOP-01".into(),
            state: state.into(),
            station: station.into(),
            locked: None,
            client_address: None,
        }
    }

    /// Parse a command line with the real Windows parser.
    fn parse_with_windows(cmdline: &str) -> Vec<String> {
        let w = wide(cmdline);
        let mut argc = 0i32;
        let argv = unsafe { CommandLineToArgvW(w.as_ptr(), &mut argc) };
        assert!(!argv.is_null());
        let args = (0..argc as usize).map(|i| unsafe { from_wide_ptr(*argv.add(i)) }).collect();
        unsafe { LocalFree(argv.cast()) };
        args
    }

    fn own_primary_token() -> OwnedHandle {
        let mut t: HANDLE = std::ptr::null_mut();
        let access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE;
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut t) }, 0);
        OwnedHandle(t)
    }

    #[test]
    fn state_labels() {
        let expected = [
            (WTSActive, "Active"),
            (WTSConnected, "Connected"),
            (WTSConnectQuery, "ConnectQuery"),
            (WTSShadow, "Shadow"),
            (WTSDisconnected, "Disconnected"),
            (WTSIdle, "Idle"),
            (WTSListen, "Listen"),
            (WTSReset, "Reset"),
            (WTSDown, "Down"),
            (WTSInit, "Init"),
        ];
        for (v, l) in expected {
            assert_eq!(state_label(v), l);
        }
        assert_eq!(state_label(42), "Unknown");
    }

    #[test]
    fn lock_state_mapping() {
        assert_eq!(lock_state_from_flags(0), Some(true));
        assert_eq!(lock_state_from_flags(1), Some(false));
        assert_eq!(lock_state_from_flags(-1), None); // WTS_SESSIONSTATE_UNKNOWN
        assert_eq!(lock_state_from_flags(7), None);
    }

    /// `WTS_CLIENT_ADDRESS::Address` as termsrv fills it: two port-slot bytes, then the address.
    fn wts_address(ip: &[u8]) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[CLIENT_ADDRESS_OFFSET..CLIENT_ADDRESS_OFFSET + ip.len()].copy_from_slice(ip);
        a
    }

    #[test]
    fn client_addresses_ipv4() {
        let af_inet = u32::from(AF_INET);
        assert_eq!(af_inet, 2);
        let mut a = wts_address(&[100, 64, 1, 7]);
        assert_eq!(format_client_address(af_inet, &a).as_deref(), Some("100.64.1.7"));
        // Bytes 0..2 (port slot) and 6.. are not part of the IPv4 address.
        a[0] = 0x0d;
        a[1] = 0x3d;
        a[6..].fill(0xAB);
        assert_eq!(format_client_address(af_inet, &a).as_deref(), Some("100.64.1.7"));
        assert_eq!(format_client_address(af_inet, &wts_address(&[192, 168, 1, 20])).as_deref(), Some("192.168.1.20"));
        assert_eq!(format_client_address(af_inet, &[0u8; 20]), None);
    }

    #[test]
    fn client_addresses_ipv6() {
        let af_inet6 = u32::from(AF_INET6);
        assert_eq!(af_inet6, 23);
        // Tailscale ULA fd7a:115c:a1e0:ab12:4843:cd96:6258:b240 at Address[2..18].
        let ip: Ipv6Addr = "fd7a:115c:a1e0:ab12:4843:cd96:6258:b240".parse().unwrap();
        let mut a = wts_address(&ip.octets());
        assert_eq!(format_client_address(af_inet6, &a).as_deref(), Some("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240"));
        // The port slot and the two trailing bytes are ignored.
        a[0] = 0xff;
        a[1] = 0xff;
        a[18] = 0xee;
        a[19] = 0xee;
        assert_eq!(format_client_address(af_inet6, &a).as_deref(), Some("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240"));
        // Reading from offset 0 instead would have produced a different (wrong) address.
        let mut wrong = [0u8; 16];
        wrong.copy_from_slice(&a[..16]);
        assert_ne!(Ipv6Addr::from(wrong), ip);
        let short: Ipv6Addr = "fd7a::1".parse().unwrap();
        assert_eq!(format_client_address(af_inet6, &wts_address(&short.octets())).as_deref(), Some("fd7a::1"));
        // IPv4-mapped (dual-stack listener) → plain IPv4.
        let mapped = Ipv4Addr::new(100, 64, 1, 7).to_ipv6_mapped();
        assert_eq!(format_client_address(af_inet6, &wts_address(&mapped.octets())).as_deref(), Some("100.64.1.7"));
        assert_eq!(format_client_address(af_inet6, &[0u8; 20]), None);
    }

    #[test]
    fn client_addresses_other_families() {
        let a = wts_address(&[100, 64, 1, 7]);
        assert_eq!(format_client_address(0, &a), None); // AF_UNSPEC
        assert_eq!(format_client_address(6, &a), None); // AF_IPX
        assert_eq!(format_client_address(u32::MAX, &a), None);
    }

    #[test]
    fn job_failures_expected_only_across_sessions() {
        assert!(job_failure_expected(Some(0), Some(1)));
        assert!(job_failure_expected(Some(2), Some(1)));
        assert!(!job_failure_expected(Some(1), Some(1)));
        assert!(!job_failure_expected(None, Some(1)));
        assert!(!job_failure_expected(Some(0), None));
        assert_eq!(process_session_id(unsafe { GetCurrentProcessId() }), current_session_id());
        assert_eq!(process_session_id(0xFFFF_FFF0), None);
    }

    #[test]
    fn child_pipe_ends_are_inheritable_only_on_demand() {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        let flags = |h: HANDLE| {
            let mut f = 0u32;
            assert_ne!(unsafe { GetHandleInformation(h, &mut f) }, 0);
            f & HANDLE_FLAG_INHERIT
        };
        let pipes = StdPipes::create().unwrap();
        for h in pipes.child_handles() {
            assert_eq!(flags(h), 0, "child ends must be created non-inheritable");
        }
        assert_eq!(flags(pipes.parent_stdout.raw()), 0);
        pipes.make_child_ends_inheritable().unwrap();
        for h in pipes.child_handles() {
            assert_eq!(flags(h), HANDLE_FLAG_INHERIT);
        }
        // The parent's read ends never become inheritable.
        assert_eq!(flags(pipes.parent_stdout.raw()), 0);
        assert_eq!(flags(pipes.parent_stderr.raw()), 0);
    }

    #[test]
    fn spawn_with_token_waits_for_the_spawn_lock() {
        let guard = process::spawn_lock();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let token = own_primary_token();
            let exe = system32("hostname.exe");
            let line = build_command_line(&exe, &[]).unwrap();
            let r = spawn_with_token(token.raw(), &exe, &line, true).map(|c| c.finish(Duration::from_secs(10)));
            let _ = tx.send(std::time::Instant::now());
            r
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(400)).is_err(),
            "the user child was created while the spawn lock was held"
        );
        let released = std::time::Instant::now();
        drop(guard);
        let finished = rx.recv_timeout(Duration::from_secs(10)).expect("spawn never completed");
        assert!(finished >= released);
        match worker.join().unwrap() {
            Ok(out) => assert_eq!(out.unwrap().exit_code, Some(0)),
            Err(e) if e.contains("1314") => println!("skipped: {e}"),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn picks_active_session() {
        let list = vec![
            sess(2, "bob", "Active", "RDP-Tcp#0"),
            sess(1, "alex", "Active", "Console"),
            sess(3, "carol", "Disconnected", ""),
        ];
        assert_eq!(pick_active(&list, 1).unwrap().user, "alex");
        // Console has no user / is not in the list → first active.
        assert_eq!(pick_active(&list, 5).unwrap().user, "bob");
        assert_eq!(pick_active(&list, NO_CONSOLE_SESSION).unwrap().user, "bob");
        // Console session disconnected → fall back.
        let list2 = vec![sess(3, "carol", "Disconnected", ""), sess(4, "dave", "Active", "RDP-Tcp#1")];
        assert_eq!(pick_active(&list2, 3).unwrap().user, "dave");
        assert!(pick_active(&[sess(3, "carol", "Disconnected", "")], 3).is_none());
        assert!(pick_active(&[], 1).is_none());
    }

    #[test]
    fn labels() {
        assert_eq!(session_label(&sess(1, "alex", "Active", "Console")), "alex (Console)");
        assert_eq!(session_label(&sess(3, "carol", "Active", "")), "carol (session 3)");
    }

    #[test]
    fn lock_summaries() {
        let o = |label: &str, result: LockResult| LockOutcome { label: label.into(), result };
        assert_eq!(
            lock_summary(&[o("alex (Console)", LockResult::Locked)]).unwrap(),
            "Locked 1 session: alex (Console)"
        );
        assert_eq!(
            lock_summary(&[o("a (Console)", LockResult::Locked), o("b (RDP-Tcp#0)", LockResult::Locked)]).unwrap(),
            "Locked 2 sessions: a (Console), b (RDP-Tcp#0)"
        );
        assert_eq!(
            lock_summary(&[o("a (Console)", LockResult::AlreadyLocked)]).unwrap(),
            "Already locked: a (Console)"
        );
        assert_eq!(
            lock_summary(&[
                o("a (Console)", LockResult::Locked),
                o("b (RDP-Tcp#0)", LockResult::AlreadyLocked),
                o("c (RDP-Tcp#1)", LockResult::Failed("boom".into())),
            ])
            .unwrap(),
            "Locked 1 session: a (Console); already locked: b (RDP-Tcp#0); failed: c (RDP-Tcp#1) — boom"
        );
        assert_eq!(
            lock_summary(&[o("a (Console)", LockResult::Failed("no token".into()))]).unwrap_err(),
            "Could not lock a (Console) — no token"
        );
        assert_eq!(lock_summary(&[]).unwrap_err(), "No user is logged in — nothing to lock.");
    }

    #[test]
    fn lock_exit_codes() {
        let out = |exit_code, timed_out| ProcessOutput { exit_code, timed_out, ..Default::default() };
        assert_eq!(lock_exit_result(&out(Some(0), false)), Ok(()));
        assert!(lock_exit_result(&out(None, true)).unwrap_err().contains("5 seconds"));
        assert!(lock_exit_result(&out(Some(5), false)).unwrap_err().contains("code 5"));
        assert!(lock_exit_result(&out(Some(0xC000_0142), false)).unwrap_err().contains("exit code"));
        assert!(lock_exit_result(&out(None, false)).is_err());
    }

    #[test]
    fn token_errors() {
        assert!(token_error_text(1, &WinError::new(1314, "x")).contains("LocalSystem"));
        assert!(token_error_text(1, &WinError::new(1008, "x")).contains("no user is logged on to session 1"));
        assert!(token_error_text(1, &WinError::new(5, "x")).contains("session 1"));
    }

    #[test]
    fn missing_helper_message() {
        let e = check_helper(Path::new(r"C:\definitely\not\here\predator-tray.exe")).unwrap_err();
        assert_eq!(e, "Session helper unavailable: predator-tray.exe not found next to the service");
        assert!(check_helper(&system32("hostname.exe")).is_ok());
    }

    #[test]
    fn command_line_quoting_roundtrip() {
        let exe = Path::new(r"C:\Program Files\Predator\predator-tray.exe");
        let cases: &[&[&str]] = &[
            &[],
            &["--lock"],
            &[""],
            &["with space", "tab\there"],
            &[r#"quote"inside"#, r#""leading"#, r#"trailing""#],
            &[r"C:\path\with\trailing\", r"C:\Program Files\x\"],
            &[r"\\server\share\", r#"a\\"b"#, r#"a\"b"#, r"a\\b"],
            &["naïve ✓ ünïcødé", "--json", "--peers=false"],
            &["  ", "\\", "\"", "\\\"", "a b\\"],
        ];
        for args in cases {
            let line = build_command_line(exe, args).unwrap();
            let parsed = parse_with_windows(&line);
            let mut expected = vec![exe.to_string_lossy().into_owned()];
            expected.extend(args.iter().map(|s| s.to_string()));
            assert_eq!(parsed, expected, "command line: {line}");
        }
        assert_eq!(build_command_line(exe, &["--lock"]).unwrap(), format!("\"{}\" --lock", exe.display()));
        assert!(build_command_line(Path::new("bad\"path.exe"), &[]).is_err());
        assert!(build_command_line(exe, &["nul\0byte"]).is_err());
        let huge = "x".repeat(40_000);
        assert!(build_command_line(exe, &[huge.as_str()]).is_err());
    }

    #[test]
    fn lists_current_user_session() {
        let Some(my_session) = current_session_id() else { panic!("ProcessIdToSessionId failed") };
        let sessions = list_sessions();
        println!("sessions: {sessions:#?}");
        assert!(sessions.iter().all(|s| s.id != 0 && !s.user.is_empty()));
        if my_session == 0 {
            return; // running as a service / over SSH: nothing interactive to check
        }
        let me = sessions.iter().find(|s| s.id == my_session).expect("own session listed");
        if let Ok(user) = std::env::var("USERNAME") {
            assert!(me.user.eq_ignore_ascii_case(&user), "{} vs {user}", me.user);
        }
        assert!(!me.state.is_empty());
        assert!(!me.station.is_empty() || me.state != "Active");
        if sessions.iter().any(is_active_user_session) {
            assert!(active_user_session().is_some());
        }
    }

    #[test]
    fn session_sid_matches_own_token() {
        let Some(my_session) = current_session_id() else { return };
        if my_session == 0 {
            return;
        }
        let token = own_primary_token();
        let own = token_user_sid(token.raw()).expect("own SID");
        assert!(own.starts_with("S-1-5-"), "{own}");
        let sid = session_user_sid(my_session).expect("session SID");
        // Same user unless the test runs under a different account than the session owner.
        if std::env::var("USERNAME").map(|u| !u.ends_with('$')).unwrap_or(true) {
            assert_eq!(sid, own);
        }
        assert_eq!(session_user_sid(0x7FFF_FFF0), None);
    }

    #[test]
    fn spawn_with_own_token_captures_output() {
        // Exercises the CreateProcessAsUserW path (pipes, handle list, environment, job) using
        // this process's own primary token, which needs no special privilege.
        let token = own_primary_token();
        let exe = system32("hostname.exe");
        let line = build_command_line(&exe, &[]).unwrap();
        let child = match spawn_with_token(token.raw(), &exe, &line, true) {
            Ok(c) => c,
            Err(e) if e.contains("1314") => {
                println!("skipped: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        // Same session as this process: the child joined the kill-on-close job before it ran.
        assert!(child.job.is_some(), "same-session child must be in the job");
        let out = child.finish(Duration::from_secs(10)).unwrap();
        assert_eq!(out.exit_code, Some(0), "{out:?}");
        assert!(!out.timed_out);
        let expected = std::env::var("COMPUTERNAME").unwrap_or_default();
        assert!(out.stdout.trim().eq_ignore_ascii_case(&expected), "{out:?}");
    }

    #[test]
    fn spawn_with_own_token_times_out() {
        let token = own_primary_token();
        let exe = system32("PING.EXE");
        let line = build_command_line(&exe, &["-n", "30", "127.0.0.1"]).unwrap();
        let child = match spawn_with_token(token.raw(), &exe, &line, true) {
            Ok(c) => c,
            Err(e) if e.contains("1314") => return,
            Err(e) => panic!("{e}"),
        };
        let pid = child.pid;
        let started = std::time::Instant::now();
        let out = child.finish(Duration::from_secs(1)).unwrap();
        assert!(out.timed_out);
        assert_eq!(out.exit_code, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!process::find_processes("ping.exe").contains(&pid));
    }

    #[test]
    fn spawn_without_capture_reports_exit_code() {
        let token = own_primary_token();
        let exe = system32("hostname.exe");
        let line = build_command_line(&exe, &[]).unwrap();
        let child = match spawn_with_token(token.raw(), &exe, &line, false) {
            Ok(c) => c,
            Err(e) if e.contains("1314") => return,
            Err(e) => panic!("{e}"),
        };
        let out = child.finish(Duration::from_secs(10)).unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.is_empty());
        assert!(lock_exit_result(&out).is_ok());
    }

    fn self_in_job() -> bool {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let mut r = 0;
        assert_ne!(unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut r) }, 0);
        r != 0
    }

    /// Open a launched PID, report whether it runs in a job, wait for it (≤ 10 s) and return its
    /// exit code. `None` when it already exited before it could be opened.
    fn watch_launched(pid: u32) -> Option<(bool, Option<u32>)> {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if raw.is_null() {
            return None;
        }
        let h = OwnedHandle(raw);
        let mut in_job = 0;
        assert_ne!(unsafe { IsProcessInJob(h.raw(), std::ptr::null_mut(), &mut in_job) }, 0);
        assert_eq!(process::wait_handle(h.raw(), Duration::from_secs(10)), process::WaitOutcome::Signaled);
        Some((in_job != 0, process::exit_code_of(h.raw())))
    }

    /// `PING -n 3 127.0.0.1`: a harmless program that lives for about two seconds.
    fn short_ping() -> (PathBuf, [&'static str; 3]) {
        (system32("PING.EXE"), ["-n", "3", "127.0.0.1"])
    }

    #[test]
    fn breakaway_is_retried_without_the_flag_only_when_refused() {
        let run = |first: Result<u32, u32>| {
            let mut calls = Vec::new();
            let r = with_breakaway(
                |flags| {
                    calls.push(flags);
                    if calls.len() == 1 { first.map_err(|c| WinError::new(c, "CreateProcessAsUserW")) } else { Ok(99) }
                },
                |e: &WinError| Some(e.code),
            );
            (r.map_err(|e| e.code), calls)
        };
        assert_eq!(run(Ok(1)), (Ok(1), vec![CREATE_BREAKAWAY_FROM_JOB]));
        assert_eq!(run(Err(ERROR_ACCESS_DENIED)), (Ok(99), vec![CREATE_BREAKAWAY_FROM_JOB, 0]));
        assert_eq!(run(Err(2)), (Err(2), vec![CREATE_BREAKAWAY_FROM_JOB]));
        // An error without a Win32 code is never retried.
        let mut n = 0;
        let r: Result<(), std::io::Error> = with_breakaway(
            |_| {
                n += 1;
                Err(std::io::Error::other("x"))
            },
            |e: &std::io::Error| e.raw_os_error().map(|c| c as u32),
        );
        assert!(r.is_err());
        assert_eq!(n, 1);
    }

    #[test]
    fn launch_flags_start_a_detached_running_program() {
        assert_eq!(LAUNCH_FLAGS & CREATE_SUSPENDED, 0, "a launched program is never left suspended");
        assert_eq!(LAUNCH_FLAGS & CREATE_BREAKAWAY_FROM_JOB, 0, "breakaway is added per attempt");
        for f in [DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP, CREATE_DEFAULT_ERROR_MODE] {
            assert_ne!(LAUNCH_FLAGS & f, 0, "{f:#x}");
        }
        let exe = system32("PING.EXE");
        assert_eq!(launch_directory(&exe), Some(wide_path(exe.parent().unwrap())));
        assert_eq!(launch_directory(Path::new("PING.EXE")), None);
        assert_eq!(exe_name(&exe), "PING.EXE");
    }

    #[test]
    fn launch_rejects_bad_targets() {
        let e = launch_in_session(1, Path::new(r"relative\tailscale-ipn.exe"), &[]).unwrap_err();
        assert!(e.contains("not a full path"), "{e}");
        let e = launch_in_session(1, Path::new(r"C:\definitely\not\here\tailscale-ipn.exe"), &[]).unwrap_err();
        assert_eq!(e, r"Cannot start tailscale-ipn.exe: C:\definitely\not\here\tailscale-ipn.exe does not exist");
        let dir = system32("PING.EXE").parent().unwrap().to_path_buf();
        assert!(launch_in_session(1, &dir, &[]).unwrap_err().contains("does not exist"));
        // A session that does not exist (and is not ours) is refused before anything starts.
        let (exe, args) = short_ping();
        let e = launch_in_session(0x7FFF_FFF0, &exe, &args).unwrap_err();
        assert!(e.contains("session 2147483632"), "{e}");
    }

    #[test]
    fn launch_in_own_session_returns_the_pid_without_waiting() {
        let Some(my_session) = current_session_id() else { return };
        let (exe, args) = short_ping();
        let started = std::time::Instant::now();
        let pid = match launch_in_session(my_session, &exe, &args) {
            Ok(pid) => pid,
            // Running as LocalSystem in session 0: nobody is logged on to that session.
            Err(e) if e.contains("no user is logged on") => return,
            Err(e) => panic!("{e}"),
        };
        assert!(started.elapsed() < Duration::from_millis(1500), "launch waited for the program");
        assert_ne!(pid, 0);
        if let Some((in_job, exit)) = watch_launched(pid) {
            assert!(!in_job || self_in_job(), "the launched program was put into a job");
            assert_eq!(exit, Some(0));
        }
    }

    #[test]
    fn launch_with_own_token_runs_without_a_job() {
        // Exercises the CreateProcessAsUserW path with this process's own primary token.
        let token = own_primary_token();
        let (exe, args) = short_ping();
        let line = build_command_line(&exe, &args).unwrap();
        let pid = match launch_with_token(token.raw(), &exe, &line) {
            Ok(pid) => pid,
            Err(e) if e.contains("1314") => {
                println!("skipped: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_ne!(pid, 0);
        let (in_job, exit) = watch_launched(pid).expect("ping lives for about two seconds");
        assert!(!in_job || self_in_job(), "the launched program was put into a job");
        assert_eq!(exit, Some(0));
    }

    #[test]
    fn launch_refuses_to_run_without_the_users_environment() {
        // A handle that is not a token: CreateEnvironmentBlock fails, so the program must not be
        // started with this process's environment (and CreateProcessAsUserW is never reached).
        let (not_a_token, _write_end) = anonymous_pipe().unwrap();
        let (exe, args) = short_ping();
        let line = build_command_line(&exe, &args).unwrap();
        let e = launch_with_token(not_a_token.raw(), &exe, &line).unwrap_err();
        assert_eq!(e, "Cannot start PING.EXE in the user session: the user's environment is not available");
    }

    #[test]
    fn launch_waits_for_the_spawn_lock() {
        let Some(my_session) = current_session_id() else { return };
        let guard = process::spawn_lock();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (exe, args) = short_ping();
            let r = launch_in_session(my_session, &exe, &args);
            let _ = tx.send(std::time::Instant::now());
            r
        });
        assert!(rx.recv_timeout(Duration::from_millis(400)).is_err(), "launched while the spawn lock was held");
        let released = std::time::Instant::now();
        drop(guard);
        let finished = rx.recv_timeout(Duration::from_secs(10)).expect("launch never completed");
        assert!(finished >= released);
        match worker.join().unwrap() {
            Ok(pid) => {
                let _ = watch_launched(pid);
            }
            Err(e) if e.contains("no user is logged on") => {}
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn run_as_own_session_user() {
        let Some(my_session) = current_session_id() else { return };
        if my_session == 0 {
            return;
        }
        let out = run_as_session_user(my_session, &system32("hostname.exe"), &[], Duration::from_secs(10)).unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(!out.stdout.trim().is_empty());
        // Another session (that does not exist) fails cleanly.
        let e = run_as_session_user(0x7FFF_FFF0, &system32("hostname.exe"), &[], Duration::from_secs(1)).unwrap_err();
        assert!(e.contains("session"), "{e}");
    }
}
