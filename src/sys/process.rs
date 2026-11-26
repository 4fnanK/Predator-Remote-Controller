//! Running the few allowlisted external programs with a hard timeout, hidden window and output
//! capture; process lookup helpers.
//!
//! Design:
//! * the child is started directly (no shell) with `CREATE_NO_WINDOW`, stdin = NUL and piped
//!   stdout/stderr, and is put into a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so
//!   neither it nor anything it starts can outlive the call;
//! * every child process of this crate is created while holding [`SPAWN_LOCK`]: handles are only
//!   ever inheritable while that lock is held (see `session.rs`), so no concurrent spawn can
//!   inherit another child's pipe ends (KB315939);
//! * two short-lived reader threads (small stacks) drain the pipes, keeping at most
//!   [`MAX_CAPTURE_BYTES`] per stream (the rest is read and discarded so the child never blocks);
//! * the calling thread blocks in `WaitForSingleObject` on the process handle (no polling) and
//!   terminates the whole job when the timeout expires.

use std::io::{ErrorKind, Read};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, GetCurrentProcessId, GetExitCodeProcess, INFINITE, OpenProcess, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::util::win::{OwnedHandle, WinError, from_wide, last_error};
use crate::{log_debug, log_warn};

/// Crate-wide lock held by every code path that creates a child process (and for as long as any
/// handle of this process is inheritable). `std::process::Command` serialises only its own
/// spawns; without this lock a concurrent spawn with `bInheritHandles = TRUE` could inherit the
/// pipe ends prepared for another child, which then never sees EOF on its output pipes.
///
/// Use [`spawn_lock`] to acquire it (poison-tolerant).
pub(crate) static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`SPAWN_LOCK`]. A poisoned lock is still usable: it guards no data, only ordering.
pub(crate) fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Maximum number of bytes kept per captured stream (stdout / stderr).
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
/// Stack size of the short-lived pipe reader threads.
const READER_STACK_BYTES: usize = 64 * 1024;
/// Read chunk size of the pipe readers.
const READ_CHUNK_BYTES: usize = 4096;
/// After the main process exited: how long the readers may take to reach EOF before leftover
/// processes of the job (which still hold the pipes) are killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// After a kill: how long to wait for the process to disappear and the readers to finish.
const KILL_GRACE: Duration = Duration::from_secs(3);
/// Exit code given to processes we terminate.
const KILLED_EXIT_CODE: u32 = 1;
/// How long `terminate_process` waits for the victim to actually disappear.
const TERMINATE_WAIT: Duration = Duration::from_secs(5);

/// Captured result of a child process.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessOutput {
    /// Exit code, `None` when killed due to timeout.
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl ProcessOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
    /// stdout + stderr joined, trimmed.
    pub fn combined(&self) -> String {
        let mut s = self.stdout.trim().to_string();
        let e = self.stderr.trim();
        if !e.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(e);
        }
        s
    }
}

/// Run `exe args...` (no shell!) with CREATE_NO_WINDOW, inside a kill-on-close job object,
/// capturing stdout/stderr; kill it after `timeout`.
pub fn run_with_timeout(exe: &Path, args: &[&str], timeout: Duration) -> Result<ProcessOutput, String> {
    run_impl(exe, args, timeout, MAX_CAPTURE_BYTES).map(|(out, _pid)| out)
}

/// [`run_with_timeout`] keeping up to `max_capture_bytes` per stream instead of
/// [`MAX_CAPTURE_BYTES`] (for the rare caller that must accept a larger, still bounded, output).
pub fn run_with_timeout_capped(
    exe: &Path,
    args: &[&str],
    timeout: Duration,
    max_capture_bytes: usize,
) -> Result<ProcessOutput, String> {
    run_impl(exe, args, timeout, max_capture_bytes).map(|(out, _pid)| out)
}

/// [`run_with_timeout_capped`] that also reports the child's PID (used by tests).
fn run_impl(exe: &Path, args: &[&str], timeout: Duration, cap: usize) -> Result<(ProcessOutput, u32), String> {
    let name = display_name(exe);
    // Create the job first: if that fails we have not started anything yet.
    let mut job = match Job::new() {
        Ok(j) => Some(j),
        Err(e) => {
            log_warn!("process: no job object for {name} ({e}); falling back to TerminateProcess");
            None
        }
    };

    let mut child = spawn_piped(exe, args).map_err(|e| spawn_error_text(&name, &e))?;
    let pid = child.id();
    let handle = child.as_raw_handle() as HANDLE;

    if let Some(j) = &job
        && let Err(e) = j.assign(handle)
    {
        log_warn!("process: cannot put {name} (pid {pid}) into a job ({e}); falling back to TerminateProcess");
        job = None;
    }

    let readers = match OutputReaders::start_capped(child.stdout.take(), child.stderr.take(), cap) {
        Ok(r) => r,
        Err(e) => {
            kill(handle, job.as_ref());
            let _ = child.wait();
            return Err(e);
        }
    };

    let result = supervise(handle, job.as_ref(), readers, timeout);
    // Reap (the process has exited or was killed by now; this only closes bookkeeping).
    let _ = child.try_wait();
    if let Ok(out) = &result {
        if out.timed_out {
            log_warn!("process: {name} (pid {pid}) killed after {} ms timeout", timeout.as_millis());
        } else {
            log_debug!("process: {name} (pid {pid}) exited with {:?}", out.exit_code);
        }
    }
    result.map(|out| (out, pid))
}

/// Start `exe args...` hidden (stdin = NUL, stdout/stderr piped) while holding [`SPAWN_LOCK`].
/// std creates the child's pipe ends inheritable and closes them before `spawn` returns, i.e.
/// inside the lock. (Not created suspended: std exposes the main thread handle only since Rust
/// 1.100, above this crate's MSRV; the job is assigned right after `spawn` returns.)
fn spawn_piped(exe: &Path, args: &[&str]) -> std::io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.args(args).creation_flags(CREATE_NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let _spawn = spawn_lock();
    cmd.spawn()
}

/// PIDs of running processes whose image name equals `name` (case-insensitive, e.g. `tailscaled.exe`).
pub fn find_processes(name: &str) -> Vec<u32> {
    let wanted = name.trim();
    if wanted.is_empty() {
        return Vec::new();
    }
    // SAFETY: plain snapshot call; the handle is owned below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap == INVALID_HANDLE_VALUE {
        log_warn!("process: {}", WinError::last("CreateToolhelp32Snapshot"));
        return Vec::new();
    }
    let snap = OwnedHandle(snap);
    let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut pids = Vec::new();
    // SAFETY: valid snapshot handle; `entry.dwSize` is initialised as required.
    let mut ok = unsafe { Process32FirstW(snap.raw(), &mut entry) } != 0;
    while ok {
        if image_name_matches(&from_wide(&entry.szExeFile), wanted) {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap.raw(), &mut entry) } != 0;
    }
    pids
}

/// Terminate a process by PID.
pub fn terminate_process(pid: u32) -> Result<(), String> {
    if let Some(reason) = refuse_to_terminate(pid, current_pid()) {
        return Err(reason);
    }
    // Prefer SYNCHRONIZE too so we can wait for the process to really go away.
    // SAFETY: plain OpenProcess calls; handles are owned below.
    let mut raw = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
    let mut can_wait = true;
    if raw.is_null() && last_error() == ERROR_ACCESS_DENIED {
        raw = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        can_wait = false;
    }
    if raw.is_null() {
        return Err(format!("Cannot open process {pid}: {}", WinError::last("OpenProcess")));
    }
    let h = OwnedHandle(raw);
    // SAFETY: valid handle with PROCESS_TERMINATE.
    if unsafe { TerminateProcess(h.raw(), KILLED_EXIT_CODE) } == 0 {
        let e = WinError::last("TerminateProcess");
        // A process that is already exiting reports ACCESS_DENIED; treat "already gone" as success.
        if can_wait && wait_handle(h.raw(), Duration::ZERO) == WaitOutcome::Signaled {
            return Ok(());
        }
        return Err(format!("Cannot terminate process {pid}: {e}"));
    }
    if can_wait && wait_handle(h.raw(), TERMINATE_WAIT) != WaitOutcome::Signaled {
        log_warn!("process: pid {pid} still running {} s after TerminateProcess", TERMINATE_WAIT.as_secs());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Shared building blocks (also used by `session::run_as_session_user` / the lock helper).
// ---------------------------------------------------------------------------------------------

/// A job object that kills every process in it when the handle is closed (dropped).
#[derive(Debug)]
pub(crate) struct Job(OwnedHandle);

impl Job {
    /// Anonymous job with `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION` (no WER dialog can keep
    /// a crashed child alive in session 0).
    pub(crate) fn new() -> Result<Self, WinError> {
        // SAFETY: anonymous job with default security.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return Err(WinError::last("CreateJobObjectW"));
        }
        let job = Job(OwnedHandle(h));
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        // SAFETY: `info` is a properly sized JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
        let ok = unsafe {
            SetInformationJobObject(
                job.0.raw(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(WinError::last("SetInformationJobObject"));
        }
        Ok(job)
    }

    pub(crate) fn assign(&self, process: HANDLE) -> Result<(), WinError> {
        // SAFETY: both handles are valid for the duration of the call.
        if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
            return Err(WinError::last("AssignProcessToJobObject"));
        }
        Ok(())
    }

    /// Kill every process in the job. Returns false if the call failed.
    pub(crate) fn terminate(&self) -> bool {
        // SAFETY: valid job handle.
        unsafe { TerminateJobObject(self.0.raw(), KILLED_EXIT_CODE) != 0 }
    }
}

/// Background readers draining a child's stdout/stderr into capped buffers.
pub(crate) struct OutputReaders {
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
    pending: usize,
}

impl OutputReaders {
    /// Start one reader thread per present stream, keeping at most [`MAX_CAPTURE_BYTES`] each.
    /// With `None` for both this is a no-op set.
    pub(crate) fn start<O, E>(stdout: Option<O>, stderr: Option<E>) -> Result<Self, String>
    where
        O: Read + Send + 'static,
        E: Read + Send + 'static,
    {
        Self::start_capped(stdout, stderr, MAX_CAPTURE_BYTES)
    }

    /// [`OutputReaders::start`] keeping at most `cap` bytes per stream.
    pub(crate) fn start_capped<O, E>(stdout: Option<O>, stderr: Option<E>, cap: usize) -> Result<Self, String>
    where
        O: Read + Send + 'static,
        E: Read + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let mut me = Self {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            done: rx,
            pending: 0,
        };
        if let Some(r) = stdout {
            spawn_reader("proc-stdout", r, me.stdout.clone(), tx.clone(), cap)?;
            me.pending += 1;
        }
        if let Some(r) = stderr {
            spawn_reader("proc-stderr", r, me.stderr.clone(), tx, cap)?;
            me.pending += 1;
        }
        Ok(me)
    }

    /// No streams to read (process started without captured output).
    pub(crate) fn none() -> Self {
        let (_tx, rx) = mpsc::channel();
        Self { stdout: Arc::default(), stderr: Arc::default(), done: rx, pending: 0 }
    }

    /// Wait until every reader reached EOF, at most `timeout`. Returns true when all finished.
    pub(crate) fn wait(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.pending > 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            match self.done.recv_timeout(deadline - now) {
                Ok(()) => self.pending -= 1,
                Err(RecvTimeoutError::Timeout) => return false,
                // Every sender is gone: all reader threads have ended.
                Err(RecvTimeoutError::Disconnected) => self.pending = 0,
            }
        }
        true
    }

    /// Take what has been captured so far (lossy UTF-8).
    pub(crate) fn take(&self) -> (String, String) {
        (take_lossy(&self.stdout), take_lossy(&self.stderr))
    }
}

fn take_lossy(buf: &Mutex<Vec<u8>>) -> String {
    let bytes = std::mem::take(&mut *buf.lock().unwrap_or_else(|e| e.into_inner()));
    String::from_utf8_lossy(&bytes).into_owned()
}

fn spawn_reader<R: Read + Send + 'static>(
    name: &str,
    mut reader: R,
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Sender<()>,
    cap: usize,
) -> Result<(), String> {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(READER_STACK_BYTES)
        .spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drain_capped(&mut reader, &buf, cap)));
            if r.is_err() {
                crate::log_error!("process: output reader thread panicked");
            }
            let _ = done.send(());
        })
        .map(|_| ())
        .map_err(|e| format!("Cannot start an output reader thread: {e}"))
}

/// Read `r` to EOF, appending at most `cap` bytes in total to `buf` (the rest is discarded so the
/// writer never blocks on a full pipe). Read errors (e.g. broken pipe) end the stream.
fn drain_capped<R: Read>(r: &mut R, buf: &Mutex<Vec<u8>>, cap: usize) {
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                let room = cap.saturating_sub(b.len());
                if room > 0 {
                    b.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Signaled,
    TimedOut,
    Failed(u32),
}

/// `WaitForSingleObject` with a `Duration` (saturating, never INFINITE).
pub(crate) fn wait_handle(h: HANDLE, timeout: Duration) -> WaitOutcome {
    // SAFETY: caller passes a valid waitable handle.
    match unsafe { WaitForSingleObject(h, timeout_ms(timeout)) } {
        WAIT_OBJECT_0 => WaitOutcome::Signaled,
        WAIT_TIMEOUT => WaitOutcome::TimedOut,
        WAIT_FAILED => WaitOutcome::Failed(last_error()),
        other => WaitOutcome::Failed(other),
    }
}

/// Milliseconds for a wait call: saturates below `INFINITE`.
fn timeout_ms(d: Duration) -> u32 {
    d.as_millis().min(u128::from(INFINITE - 1)) as u32
}

/// Exit code of an exited process.
pub(crate) fn exit_code_of(process: HANDLE) -> Option<u32> {
    let mut code = 0u32;
    // SAFETY: valid process handle, valid out pointer.
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 { None } else { Some(code) }
}

/// Kill the whole job (preferred) or just the process.
pub(crate) fn kill(process: HANDLE, job: Option<&Job>) {
    if let Some(j) = job
        && j.terminate()
    {
        return;
    }
    // SAFETY: valid process handle with PROCESS_TERMINATE (we created it).
    unsafe {
        TerminateProcess(process, KILLED_EXIT_CODE);
    }
}

/// Wait for `process` up to `timeout`, kill it (and its job) on timeout, then collect output.
pub(crate) fn supervise(
    process: HANDLE,
    job: Option<&Job>,
    mut readers: OutputReaders,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    let (exit_code, timed_out) = match wait_handle(process, timeout) {
        WaitOutcome::Signaled => (exit_code_of(process), false),
        WaitOutcome::TimedOut => {
            kill(process, job);
            let _ = wait_handle(process, KILL_GRACE);
            (None, true)
        }
        WaitOutcome::Failed(code) => {
            kill(process, job);
            let _ = readers.wait(KILL_GRACE);
            return Err(format!("Waiting for the process failed: {}", WinError::new(code, "WaitForSingleObject")));
        }
    };
    if !readers.wait(if timed_out { KILL_GRACE } else { DRAIN_GRACE }) {
        // Something that inherited the pipes (a grandchild) is still alive: kill the rest of the job.
        if let Some(j) = job {
            j.terminate();
        }
        if !readers.wait(KILL_GRACE) {
            log_warn!("process: output pipes still open after the process ended; returning partial output");
        }
    }
    let (stdout, stderr) = readers.take();
    Ok(ProcessOutput { exit_code, stdout, stderr, timed_out })
}

fn current_pid() -> u32 {
    // SAFETY: trivial call.
    unsafe { GetCurrentProcessId() }
}

/// Safety net for `terminate_process`: never kill the idle/system process or ourselves.
fn refuse_to_terminate(pid: u32, own_pid: u32) -> Option<String> {
    match pid {
        0 | 4 => Some(format!("Refusing to terminate system process {pid}.")),
        p if p == own_pid => Some("Refusing to terminate the Vigil service itself.".to_string()),
        _ => None,
    }
}

/// Case-insensitive image name comparison (`Tailscaled.EXE` == `tailscaled.exe`).
fn image_name_matches(image: &str, wanted: &str) -> bool {
    image.eq_ignore_ascii_case(wanted) || (!image.is_ascii() && image.to_lowercase() == wanted.to_lowercase())
}

/// File name of `exe` for messages (`tailscale.exe`), falling back to the full path.
fn display_name(exe: &Path) -> String {
    exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| exe.display().to_string())
}

fn spawn_error_text(name: &str, e: &std::io::Error) -> String {
    match e.kind() {
        ErrorKind::NotFound => format!("Cannot start {name}: the program was not found."),
        ErrorKind::PermissionDenied => format!("Cannot start {name}: access denied."),
        _ => format!("Cannot start {name}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn system32(exe: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        root.join("System32").join(exe)
    }

    /// A long-running hidden child (spawned under the spawn lock like production spawns).
    fn spawn_quiet_ping() -> Child {
        let _spawn = spawn_lock();
        Command::new(system32("PING.EXE"))
            .args(["-n", "30", "127.0.0.1"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn combined_and_success() {
        let o = ProcessOutput { exit_code: Some(0), stdout: " out \n".into(), stderr: "".into(), timed_out: false };
        assert!(o.success());
        assert_eq!(o.combined(), "out");
        let o = ProcessOutput { exit_code: None, stdout: "a".into(), stderr: " b ".into(), timed_out: true };
        assert!(!o.success());
        assert_eq!(o.combined(), "a\nb");
    }

    #[test]
    fn drain_respects_cap_and_reads_to_end() {
        let data = vec![b'x'; 10_000];
        let mut cur = Cursor::new(data);
        let buf = Mutex::new(Vec::new());
        drain_capped(&mut cur, &buf, 5000);
        assert_eq!(buf.lock().unwrap().len(), 5000);
        // The whole input was consumed (writer would never block).
        assert_eq!(cur.position(), 10_000);

        let mut small = Cursor::new(b"hello".to_vec());
        let buf = Mutex::new(Vec::new());
        drain_capped(&mut small, &buf, MAX_CAPTURE_BYTES);
        assert_eq!(&*buf.lock().unwrap(), b"hello");
    }

    #[test]
    fn timeout_conversion() {
        assert_eq!(timeout_ms(Duration::from_millis(1500)), 1500);
        assert_eq!(timeout_ms(Duration::ZERO), 0);
        assert_eq!(timeout_ms(Duration::from_secs(u64::MAX)), INFINITE - 1);
    }

    #[test]
    fn name_matching() {
        assert!(image_name_matches("tailscaled.exe", "TailScaleD.EXE"));
        assert!(image_name_matches("ÄPFEL.exe", "äpfel.EXE"));
        assert!(!image_name_matches("tailscale.exe", "tailscaled.exe"));
    }

    #[test]
    fn refuses_dangerous_pids() {
        assert!(refuse_to_terminate(0, 100).is_some());
        assert!(refuse_to_terminate(4, 100).is_some());
        assert!(refuse_to_terminate(100, 100).is_some());
        assert!(refuse_to_terminate(1234, 100).is_none());
        assert!(terminate_process(current_pid()).is_err());
    }

    #[test]
    fn runs_hostname_and_captures_output() {
        let out = run_with_timeout(&system32("hostname.exe"), &[], Duration::from_secs(10)).unwrap();
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        assert!(out.success());
        let host = out.stdout.trim();
        assert!(!host.is_empty());
        let expected = std::env::var("COMPUTERNAME").unwrap_or_default();
        if !expected.is_empty() {
            assert!(host.eq_ignore_ascii_case(&expected), "{host} vs {expected}");
        }
    }

    #[test]
    fn nonzero_exit_code_and_stderr() {
        // `hostname.exe /?`-style errors: an invalid switch prints to stderr and exits non-zero.
        let out = run_with_timeout(&system32("hostname.exe"), &["-z", "bogus"], Duration::from_secs(10)).unwrap();
        assert!(!out.timed_out);
        assert_ne!(out.exit_code, Some(0));
        assert!(out.exit_code.is_some());
    }

    #[test]
    fn timeout_kills_child_quickly() {
        let ping = system32("PING.EXE");
        let started = Instant::now();
        let (out, pid) =
            run_impl(&ping, &["-n", "30", "127.0.0.1"], Duration::from_secs(1), MAX_CAPTURE_BYTES).unwrap();
        let elapsed = started.elapsed();
        assert!(out.timed_out);
        assert_eq!(out.exit_code, None);
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        // Output produced before the kill is still captured.
        assert!(out.stdout.contains("127.0.0.1"), "{:?}", out.stdout);
        // No leftover ping.exe with our child's pid.
        assert!(!find_processes("ping.exe").contains(&pid), "ping.exe {pid} still running");
    }

    #[test]
    fn capped_capture_keeps_only_the_cap() {
        let out = run_with_timeout_capped(&system32("hostname.exe"), &[], Duration::from_secs(10), 3).unwrap();
        assert!(out.success(), "{out:?}");
        assert_eq!(out.stdout.len(), 3, "{out:?}");
        let full = run_with_timeout(&system32("hostname.exe"), &[], Duration::from_secs(10)).unwrap();
        assert!(full.stdout.starts_with(&out.stdout), "{full:?} vs {out:?}");
    }

    #[test]
    fn run_with_timeout_waits_for_the_spawn_lock() {
        // While another spawn (or an inheritable-handle window in session.rs) holds the lock, no
        // child may be created: it could inherit handles meant for someone else.
        let guard = spawn_lock();
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let r = run_with_timeout(&system32("hostname.exe"), &[], Duration::from_secs(10));
            let _ = tx.send(Instant::now());
            r
        });
        assert!(rx.recv_timeout(Duration::from_millis(400)).is_err(), "child started while the lock was held");
        let released = Instant::now();
        drop(guard);
        let finished = rx.recv_timeout(Duration::from_secs(10)).expect("child never started");
        assert!(finished >= released);
        assert!(worker.join().unwrap().unwrap().success());
    }

    #[test]
    fn missing_exe_is_an_error() {
        let e =
            run_with_timeout(Path::new(r"C:\definitely\not\here\nope.exe"), &[], Duration::from_secs(1)).unwrap_err();
        assert!(e.contains("nope.exe"), "{e}");
        assert!(e.contains("not found"), "{e}");
    }

    #[test]
    fn finds_explorer_and_self() {
        assert!(!find_processes("explorer.exe").is_empty());
        assert!(find_processes("EXPLORER.EXE").len() == find_processes("explorer.exe").len());
        assert!(find_processes("").is_empty());
        assert!(find_processes("no-such-process-1234.exe").is_empty());
        let me = std::env::current_exe().unwrap();
        let my_name = me.file_name().unwrap().to_string_lossy().into_owned();
        assert!(find_processes(&my_name).contains(&current_pid()));
    }

    #[test]
    fn terminate_own_child() {
        let mut child = spawn_quiet_ping();
        terminate_process(child.id()).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(KILLED_EXIT_CODE as i32));
        assert!(terminate_process(0xFFFF_FFF0).is_err());
    }

    #[test]
    fn job_kills_on_close() {
        let mut child = spawn_quiet_ping();
        let job = Job::new().unwrap();
        job.assign(child.as_raw_handle() as HANDLE).unwrap();
        let started = Instant::now();
        drop(job);
        // Kill-on-close terminates the members (Windows reports exit code 0 for them), long
        // before ping's 30 echo requests would have finished.
        child.wait().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }
}
