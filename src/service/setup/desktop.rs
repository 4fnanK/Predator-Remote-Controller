//! What the elevated setup does on the signed-in user's desktop WITHOUT elevation: start the tray
//! app and open the bot link. Both are handed to `explorer.exe`, which passes them to the shell
//! that is already running in this session, so they start as the signed-in user at normal
//! integrity (the "explorer.exe trick"). That only works when the shell belongs to the same
//! account as this process; otherwise nothing is started (the tray then starts at the next
//! sign-in through its Run value).
//!
//! Also: small process queries (image path, session, owner) used to find the installed tray.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};

use crate::paths::TRAY_EXE;
use crate::util::win::{OwnedHandle, WinError, from_wide};

/// Full image path of the process behind `h` (opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION).
fn image_of(h: HANDLE) -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: valid process handle; `buf` holds `len` UTF-16 units.
    if unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(PathBuf::from(from_wide(&buf)))
}

/// Full image path of a running process (`None` when it cannot be opened, e.g. it exited).
pub(crate) fn process_image(pid: u32) -> Option<PathBuf> {
    // SAFETY: plain OpenProcess; the handle is owned below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return None;
    }
    let h = OwnedHandle(raw);
    image_of(h.raw())
}

/// Stop process `pid` if — and only if — it runs exactly `image`. The image check and the
/// termination use the same process handle, so a process id that was reused in between is never
/// hit, and this process is never stopped. `Ok(false)` = another program (or already gone).
pub(crate) fn stop_if_image(pid: u32, image: &Path) -> Result<bool, String> {
    // SAFETY: trivial query of the current process id.
    if pid == unsafe { GetCurrentProcessId() } {
        return Ok(false);
    }
    // SAFETY: plain OpenProcess; the handle is owned below.
    let raw =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let err = WinError::last("OpenProcess");
        // Only worth reporting when it is that program (it may still be opened for the query).
        return match process_image(pid) {
            Some(p) if same_path(&p, image) => Err(format!("Cannot stop process {pid} ({}): {err}", p.display())),
            _ => Ok(false),
        };
    }
    let h = OwnedHandle(raw);
    if !image_of(h.raw()).is_some_and(|p| same_path(&p, image)) {
        return Ok(false);
    }
    // SAFETY: valid handle opened with PROCESS_TERMINATE.
    if unsafe { TerminateProcess(h.raw(), 1) } == 0 {
        let err = WinError::last("TerminateProcess");
        // A process that is exiting already refuses the termination: that counts as stopped.
        // SAFETY: valid handle opened with SYNCHRONIZE.
        if unsafe { WaitForSingleObject(h.raw(), 0) } == WAIT_OBJECT_0 {
            return Ok(true);
        }
        return Err(format!("Cannot stop process {pid} ({}): {err}", image.display()));
    }
    // Wait until it is really gone (its image is then free to be replaced).
    // SAFETY: valid handle opened with SYNCHRONIZE.
    unsafe { WaitForSingleObject(h.raw(), 5_000) };
    Ok(true)
}

/// Windows session of a process.
pub(crate) fn process_session(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: valid out pointer.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// String SID of the account a process runs as.
pub(crate) fn process_owner_sid(pid: u32) -> Option<String> {
    // SAFETY: plain OpenProcess / OpenProcessToken; both handles are owned below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return None;
    }
    let process = OwnedHandle(raw);
    let mut token = std::ptr::null_mut();
    // SAFETY: valid process handle; `token` receives a handle owned below.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle(token);
    std::panic::catch_unwind(|| crate::sys::sysinfo::token_user_sid(token.raw())).ok().flatten()
}

/// Case-insensitive path comparison (`\\?\` prefix and `/` vs `\` ignored).
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    fn norm(p: &Path) -> String {
        let s = p.to_string_lossy().replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s).trim_end_matches('\\').to_string();
        s.to_lowercase()
    }
    norm(a) == norm(b)
}

/// PIDs of `predator-tray.exe` processes started from exactly `tray` (any session).
pub(crate) fn tray_processes(tray: &Path) -> Vec<u32> {
    crate::sys::process::find_processes(TRAY_EXE)
        .into_iter()
        .filter(|pid| process_image(*pid).is_some_and(|img| same_path(&img, tray)))
        .collect()
}

fn windows_dir() -> PathBuf {
    let mut buf = [0u16; 260];
    // SAFETY: `buf` holds 260 UTF-16 units.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(r"C:\Windows");
    }
    PathBuf::from(from_wide(&buf[..n]))
}

/// Whether the shell trick works here: an Explorer shell runs in this process's session and
/// belongs to `my_sid`. `Err` says why not.
fn check_shell(my_sid: &str) -> Result<(), String> {
    // SAFETY: trivial query of the current process id.
    let me = unsafe { GetCurrentProcessId() };
    let session = process_session(me).ok_or("the Windows session cannot be determined")?;
    if session == 0 {
        return Err("this window has no desktop (session 0)".into());
    }
    let shells: Vec<u32> = crate::sys::process::find_processes("explorer.exe")
        .into_iter()
        .filter(|pid| process_session(*pid) == Some(session))
        .collect();
    if shells.is_empty() {
        return Err("no Explorer shell runs in this session".into());
    }
    if shells.iter().any(|pid| process_owner_sid(*pid).is_some_and(|s| s.eq_ignore_ascii_case(my_sid))) {
        Ok(())
    } else {
        Err("the desktop belongs to another Windows account than this setup window".into())
    }
}

/// `explorer.exe <target>` (a program path or an https URL), not waited for.
fn run_via_shell(target: &str) -> Result<(), String> {
    let explorer = windows_dir().join("explorer.exe");
    let _spawn = crate::sys::process::spawn_lock();
    std::process::Command::new(&explorer)
        .arg(target)
        .spawn()
        .map(drop)
        .map_err(|e| format!("cannot start {}: {e}", explorer.display()))
}

/// Result of [`start_tray`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TrayStart {
    Started,
    AlreadyRunning,
    /// Started through the shell, but no process showed up within a few seconds.
    NotConfirmed,
    /// Not started; the text says why.
    Skipped(String),
}

impl TrayStart {
    pub(crate) fn describe(&self) -> String {
        match self {
            TrayStart::Started => "started (not elevated)".into(),
            TrayStart::AlreadyRunning => "already running".into(),
            TrayStart::NotConfirmed => {
                "start requested; it may take a moment to appear (it also starts at every sign-in)".into()
            }
            TrayStart::Skipped(why) => format!("starts at the next sign-in ({why})"),
        }
    }
}

/// Start the installed tray app in this session as the signed-in (non-elevated) user.
pub(crate) fn start_tray(tray: &Path, my_sid: Option<&str>) -> TrayStart {
    let Some(my_sid) = my_sid else { return TrayStart::Skipped("the account of this window is unknown".into()) };
    if !tray.is_file() {
        return TrayStart::Skipped(format!("{} is missing", tray.display()));
    }
    if let Err(why) = check_shell(my_sid) {
        return TrayStart::Skipped(why);
    }
    // SAFETY: trivial query of the current process id.
    let session = process_session(unsafe { GetCurrentProcessId() });
    let running_here = || tray_processes(tray).into_iter().any(|pid| process_session(pid) == session);
    if running_here() {
        return TrayStart::AlreadyRunning;
    }
    if let Err(e) = run_via_shell(&tray.display().to_string()) {
        return TrayStart::Skipped(e);
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        if running_here() {
            return TrayStart::Started;
        }
    }
    TrayStart::NotConfirmed
}

/// `https://t.me/<username>` when the username has Telegram's form (5–32 of `[A-Za-z0-9_]`).
pub(crate) fn bot_link(username: &str) -> Option<String> {
    let u = username.trim().trim_start_matches('@');
    let ok = (5..=32).contains(&u.len()) && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    ok.then(|| format!("https://t.me/{u}"))
}

/// Open an https link in the signed-in user's default browser (never in an elevated one).
pub(crate) fn open_link(url: &str, my_sid: Option<&str>) -> Result<(), String> {
    if !url.starts_with("https://") || url.contains([' ', '"']) {
        return Err("not an https link".into());
    }
    let my_sid = my_sid.ok_or("the account of this window is unknown")?;
    check_shell(my_sid)?;
    run_via_shell(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_comparison() {
        assert!(same_path(
            Path::new(r"C:\Program Files\Predator\predator-tray.exe"),
            Path::new(r"c:\program files\predator\PREDATOR-TRAY.EXE")
        ));
        assert!(same_path(Path::new(r"\\?\C:\X\a.exe"), Path::new(r"C:\X\a.exe")));
        assert!(same_path(Path::new("C:/X/a.exe"), Path::new(r"C:\X\a.exe")));
        assert!(same_path(Path::new(r"C:\X\"), Path::new(r"C:\X")));
        assert!(!same_path(Path::new(r"C:\X\a.exe"), Path::new(r"C:\Y\a.exe")));
        assert!(!same_path(Path::new(r"C:\X\a.exe"), Path::new(r"C:\X\a.exe.old")));
    }

    #[test]
    fn stop_if_image_only_stops_that_program() {
        // A child that waits for input (no grandchildren): cmd.exe reading a pipe.
        let cmd = windows_dir().join("System32").join("cmd.exe");
        let mut child = {
            let _spawn = crate::sys::process::spawn_lock();
            std::process::Command::new(&cmd)
                .arg("/q")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let pid = child.id();
        // Another image path: untouched.
        assert_eq!(stop_if_image(pid, Path::new(r"C:\nonexistent\predator-tray.exe")), Ok(false));
        assert!(child.try_wait().unwrap().is_none(), "the other program still runs");
        // This process is never stopped.
        // SAFETY: trivial query.
        let me = unsafe { GetCurrentProcessId() };
        assert_eq!(stop_if_image(me, &std::env::current_exe().unwrap()), Ok(false));
        // The matching image is stopped (and waited for).
        assert_eq!(stop_if_image(pid, &cmd), Ok(true));
        assert!(child.wait().unwrap().code().is_some());
        // Gone (its last handle closed): nothing to stop.
        drop(child);
        assert_eq!(stop_if_image(pid, &cmd), Ok(false));
    }

    #[test]
    fn bot_links() {
        assert_eq!(bot_link("ExampleBot").as_deref(), Some("https://t.me/ExampleBot"));
        assert_eq!(bot_link("@Example_bot").as_deref(), Some("https://t.me/Example_bot"));
        assert_eq!(bot_link("abc"), None, "too short");
        assert_eq!(bot_link("evil.com/x"), None);
        assert_eq!(bot_link("a b c d e"), None);
        assert_eq!(bot_link(&"x".repeat(33)), None);
    }

    #[test]
    fn process_queries_for_this_process() {
        // SAFETY: trivial query.
        let me = unsafe { GetCurrentProcessId() };
        let img = process_image(me).unwrap();
        assert!(same_path(&img, &std::env::current_exe().unwrap()), "{}", img.display());
        assert!(process_session(me).is_some());
        let sid = process_owner_sid(me).unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
        assert!(windows_dir().join("explorer.exe").is_file());
        assert!(open_link("http://example.com", Some(&sid)).unwrap_err().contains("https"));
        assert!(tray_processes(Path::new(r"C:\nonexistent\predator-tray.exe")).is_empty());
        assert!(matches!(
            start_tray(Path::new(r"C:\nonexistent\predator-tray.exe"), Some(&sid)),
            TrayStart::Skipped(_)
        ));
    }
}
