//! Overlapped named-pipe I/O shared by the IPC server and client. Every operation is bounded by
//! a deadline (WaitForSingleObject + CancelIoEx), so a stuck peer can never block a thread
//! forever. Also implements the client side used by [`crate::ipc::request`].

use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use crate::ipc::{IpcRequest, IpcResponse};
use crate::util::win::{OwnedEvent, OwnedHandle, WinError, error_message, last_error, wide};

/// Largest accepted request line (server side).
pub(crate) const MAX_REQUEST_BYTES: usize = 4096;
/// Largest accepted reply line (client side).
pub(crate) const MAX_REPLY_BYTES: usize = 256 * 1024;

/// Why an overlapped pipe operation did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IoFailure {
    Timeout,
    /// The peer closed its end.
    Closed,
    /// Line longer than the allowed maximum.
    TooLong,
    Win(u32),
}

impl IoFailure {
    pub fn describe(&self, what: &str) -> String {
        match self {
            IoFailure::Timeout => format!("Timed out {what}"),
            IoFailure::Closed => format!("The connection was closed while {what}"),
            IoFailure::TooLong => format!("Message too large while {what}"),
            IoFailure::Win(code) => format!("Error while {what}: {} (error {code})", error_message(*code)),
        }
    }
}

fn map_error(code: u32) -> IoFailure {
    match code {
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA | ERROR_HANDLE_EOF => IoFailure::Closed,
        ERROR_OPERATION_ABORTED => IoFailure::Timeout,
        c => IoFailure::Win(c),
    }
}

/// Milliseconds left until `deadline` (0 when passed).
pub(crate) fn remaining_ms(deadline: Instant) -> u32 {
    deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128 - 1) as u32
}

/// Run one overlapped operation on `h`, waiting for completion until `deadline`. On timeout the
/// I/O is cancelled and its completion awaited before returning, so the OVERLAPPED and the
/// caller's buffer are never used by the kernel after this function returns.
fn overlapped_op(
    h: HANDLE,
    ev: &OwnedEvent,
    deadline: Instant,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> Result<u32, IoFailure> {
    // SAFETY: OVERLAPPED is plain data; zero is its documented initial state.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.raw();
    if start(&mut ov) == 0 {
        let code = last_error();
        if code != ERROR_IO_PENDING {
            return Err(map_error(code));
        }
        // SAFETY: valid event handle owned by `ev`.
        if unsafe { WaitForSingleObject(ev.raw(), remaining_ms(deadline)) } != WAIT_OBJECT_0 {
            let mut n = 0u32;
            // SAFETY: cancel our own pending I/O, then wait (bWait = TRUE) until the kernel is done
            // with `ov` and the buffer.
            unsafe {
                CancelIoEx(h, &ov);
                GetOverlappedResult(h, &ov, &mut n, 1);
            }
            return Err(IoFailure::Timeout);
        }
    }
    let mut n = 0u32;
    // SAFETY: the operation has completed (event signaled or synchronous completion).
    if unsafe { GetOverlappedResult(h, &ov, &mut n, 0) } == 0 {
        return Err(map_error(last_error()));
    }
    Ok(n)
}

/// Write all of `data` before `deadline`.
pub(crate) fn write_all(h: HANDLE, ev: &OwnedEvent, data: &[u8], deadline: Instant) -> Result<(), IoFailure> {
    let mut off = 0usize;
    while off < data.len() {
        let chunk = &data[off..];
        let len = chunk.len().min(64 * 1024) as u32;
        // SAFETY: `chunk` outlives the operation (overlapped_op waits for completion/cancel).
        let n = overlapped_op(h, ev, deadline, |ov| unsafe { WriteFile(h, chunk.as_ptr(), len, null_mut(), ov) })?;
        if n == 0 {
            return Err(IoFailure::Closed);
        }
        off += n as usize;
    }
    Ok(())
}

/// Read bytes until `\n` (excluded) or fail after `max` bytes / at `deadline`.
pub(crate) fn read_line(h: HANDLE, ev: &OwnedEvent, max: usize, deadline: Instant) -> Result<Vec<u8>, IoFailure> {
    let mut out = Vec::with_capacity(256);
    let mut buf = [0u8; 1024];
    loop {
        let ptr = buf.as_mut_ptr();
        let len = buf.len() as u32;
        // SAFETY: `buf` outlives the operation (overlapped_op waits for completion/cancel).
        let n = overlapped_op(h, ev, deadline, |ov| unsafe { ReadFile(h, ptr, len, null_mut(), ov) })? as usize;
        if n == 0 {
            if remaining_ms(deadline) == 0 {
                return Err(IoFailure::Timeout);
            }
            continue;
        }
        let chunk = &buf[..n];
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&chunk[..pos]);
            if out.len() > max {
                return Err(IoFailure::TooLong);
            }
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(out);
        }
        out.extend_from_slice(chunk);
        if out.len() > max {
            return Err(IoFailure::TooLong);
        }
    }
}

/// Wait (bounded) until the peer closes its end, discarding anything it still sends.
pub(crate) fn wait_for_close(h: HANDLE, ev: &OwnedEvent, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 256];
    loop {
        let ptr = buf.as_mut_ptr();
        let len = buf.len() as u32;
        // SAFETY: `buf` outlives the operation.
        match overlapped_op(h, ev, deadline, |ov| unsafe { ReadFile(h, ptr, len, null_mut(), ov) }) {
            Ok(_) if remaining_ms(deadline) > 0 => continue,
            _ => return,
        }
    }
}

/// How the client verifies the pipe server process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerCheck {
    /// Must be the PID the SCM reports for the Predator service.
    PredatorService,
    /// Must be exactly this PID (a caller that just queried the SCM itself; tests). 0 never matches.
    Pid(u32),
}

/// Client: connect to `pipe_name`, verify the server, send one request and read one reply.
pub(crate) fn client_request(
    pipe_name: &str,
    req: &IpcRequest,
    timeout: Duration,
    check: ServerCheck,
) -> Result<IpcResponse, String> {
    let deadline = Instant::now() + timeout.max(Duration::from_millis(200));
    let name = wide(pipe_name);
    let pipe = connect(&name, deadline)?;
    verify_server(&pipe, check)?;
    let ev = OwnedEvent::new_manual().map_err(String::from)?;
    let mut line = serde_json::to_vec(req).map_err(|e| format!("Cannot encode the request: {e}"))?;
    line.push(b'\n');
    write_all(pipe.raw(), &ev, &line, deadline)
        .map_err(|e| e.describe("sending the request to the Predator service"))?;
    let reply = read_line(pipe.raw(), &ev, MAX_REPLY_BYTES, deadline)
        .map_err(|e| e.describe("waiting for the Predator service to answer"))?;
    serde_json::from_slice::<IpcResponse>(&reply).map_err(|e| format!("Invalid reply from the Predator service: {e}"))
}

fn connect(name: &[u16], deadline: Instant) -> Result<OwnedHandle, String> {
    loop {
        // GENERIC_READ | FILE_WRITE_DATA (not GENERIC_WRITE): the pipe DACL deliberately does not
        // grant interactive users FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA, part of
        // GENERIC_WRITE). Identification-level impersonation only: the service can identify the
        // caller but never act as it.
        // SAFETY: `name` is NUL-terminated; the returned handle is owned by OwnedHandle.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | FILE_WRITE_DATA,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE && !h.is_null() {
            return Ok(OwnedHandle(h));
        }
        match last_error() {
            ERROR_PIPE_BUSY => {
                let ms = remaining_ms(deadline).min(2000);
                if ms == 0 {
                    return Err("The Predator service is busy; please try again.".into());
                }
                // SAFETY: NUL-terminated pipe name.
                unsafe { WaitNamedPipeW(name.as_ptr(), ms) };
            }
            ERROR_FILE_NOT_FOUND => {
                return Err("The Predator service is not running (its IPC pipe does not exist).".into());
            }
            ERROR_ACCESS_DENIED => {
                return Err("Access to the Predator service pipe was denied for this account.".into());
            }
            code => {
                return Err(format!("Cannot connect to the Predator service: {}", WinError::new(code, "CreateFileW")));
            }
        }
    }
}

fn verify_server(pipe: &OwnedHandle, check: ServerCheck) -> Result<(), String> {
    let mut server_pid = 0u32;
    // SAFETY: valid pipe handle; out-parameter is valid.
    if unsafe { GetNamedPipeServerProcessId(pipe.raw(), &mut server_pid) } == 0 {
        return Err(format!("Cannot verify the IPC server: {}", WinError::last("GetNamedPipeServerProcessId")));
    }
    let expected = match check {
        ServerCheck::Pid(p) => p,
        ServerCheck::PredatorService => {
            std::panic::catch_unwind(|| crate::sys::scm::query(crate::paths::SERVICE_NAME).1).unwrap_or(0)
        }
    };
    if expected == 0 || expected != server_pid {
        return Err("IPC server is not the Predator service".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_texts() {
        assert!(IoFailure::Timeout.describe("x").starts_with("Timed out"));
        assert_eq!(map_error(ERROR_BROKEN_PIPE), IoFailure::Closed);
        assert_eq!(map_error(ERROR_OPERATION_ABORTED), IoFailure::Timeout);
        assert!(IoFailure::Win(5).describe("y").contains("error 5"));
    }

    #[test]
    fn missing_pipe_is_reported() {
        let r = client_request(
            r"\\.\pipe\PredatorRemoteController-test-missing-0d1f",
            &IpcRequest::Status,
            Duration::from_millis(300),
            ServerCheck::Pid(1),
        );
        assert!(r.unwrap_err().contains("not running"));
    }
}
