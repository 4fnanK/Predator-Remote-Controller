//! Thin Win32 helpers: UTF-16 strings, error formatting, owned handles/events.

use std::fmt;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
};
use windows_sys::Win32::System::Memory::{HeapOptimizeResources, HeapSetInformation, SetProcessWorkingSetSizeEx};
use windows_sys::Win32::System::SystemServices::{
    HEAP_OPTIMIZE_RESOURCES_CURRENT_VERSION, HEAP_OPTIMIZE_RESOURCES_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE, ProcessPowerThrottling, ResetEvent,
    SetEvent, SetProcessInformation, WaitForSingleObject,
};

/// Null-terminated UTF-16 copy of `s`.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Null-terminated UTF-16 copy of an OS path.
pub fn wide_path(p: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Decode a UTF-16 buffer up to the first NUL (or the end).
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Decode a NUL-terminated UTF-16 pointer. Returns an empty string for null.
///
/// # Safety
/// `p` must be null or point to a valid NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// `GetLastError()`.
pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Human readable text for a Win32 error code (system message table), trimmed.
pub fn error_message(code: u32) -> String {
    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let n = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            code,
            0,
            (&mut buf as *mut *mut u16) as *mut u16,
            0,
            std::ptr::null(),
        );
        if n == 0 || buf.is_null() {
            return format!("Windows error {code}");
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(buf, n as usize));
        LocalFree(buf as _);
        s.trim().trim_end_matches('.').to_string()
    }
}

/// A Win32 error with context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinError {
    pub code: u32,
    pub context: String,
}

impl WinError {
    pub fn new(code: u32, context: impl Into<String>) -> Self {
        Self { code, context: context.into() }
    }

    /// Capture `GetLastError()` now.
    pub fn last(context: impl Into<String>) -> Self {
        Self::new(last_error(), context)
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (error {})", self.context, error_message(self.code), self.code)
    }
}

impl std::error::Error for WinError {}

impl From<WinError> for String {
    fn from(e: WinError) -> String {
        e.to_string()
    }
}

/// An owned kernel handle closed on drop. Accepts null/INVALID_HANDLE_VALUE as "empty".
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

// SAFETY: kernel handles are process-global and may be used from any thread.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// An owned Win32 event object.
#[derive(Debug)]
pub struct OwnedEvent(OwnedHandle);

impl OwnedEvent {
    /// Manual-reset, initially non-signaled.
    pub fn new_manual() -> Result<Self, WinError> {
        Self::create(true, false)
    }

    /// Auto-reset, initially non-signaled.
    pub fn new_auto() -> Result<Self, WinError> {
        Self::create(false, false)
    }

    pub fn create(manual_reset: bool, initial: bool) -> Result<Self, WinError> {
        let h = unsafe { CreateEventW(std::ptr::null(), manual_reset as i32, initial as i32, std::ptr::null()) };
        if h.is_null() {
            return Err(WinError::last("CreateEventW"));
        }
        Ok(Self(OwnedHandle(h)))
    }

    pub fn set(&self) {
        unsafe {
            SetEvent(self.0.raw());
        }
    }

    pub fn reset(&self) {
        unsafe {
            ResetEvent(self.0.raw());
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    /// Wait up to `d`; returns true if signaled.
    pub fn wait(&self, d: Duration) -> bool {
        let ms = d.as_millis().min(u32::MAX as u128 - 1) as u32;
        unsafe { WaitForSingleObject(self.0.raw(), ms) == WAIT_OBJECT_0 }
    }
}

// ---------------------------------------------------------------------------------------------
// Process resource helpers (working set, heap caches, power throttling)
// ---------------------------------------------------------------------------------------------

/// Remove as many pages as possible from the current process's working set
/// (`SetProcessWorkingSetSizeEx(-1, -1)`). Nothing is freed: the pages move to the standby /
/// modified lists and come back by soft fault when touched again. Only useful once after start-up
/// and after an on-demand burst — trimming on a short period only causes fault churn. Returns
/// false when Windows refused (harmless).
pub fn trim_working_set() -> bool {
    // SAFETY: pseudo-handle of the current process; (SIZE_T)-1 twice means "trim", no flags.
    unsafe { SetProcessWorkingSetSizeEx(GetCurrentProcess(), usize::MAX, usize::MAX, 0) != 0 }
}

/// Ask every heap of the process to release its cached free blocks and decommit what it can
/// (`HeapSetInformation(NULL, HeapOptimizeResources)`, Windows 8.1+). Best effort: returns false
/// when the call is not supported or failed, which changes nothing.
pub fn release_heap_caches() -> bool {
    let info = HEAP_OPTIMIZE_RESOURCES_INFORMATION { Version: HEAP_OPTIMIZE_RESOURCES_CURRENT_VERSION, Flags: 0 };
    // SAFETY: a NULL heap handle applies the optimisation to every heap of the process; `info`
    // is a valid, correctly sized HEAP_OPTIMIZE_RESOURCES_INFORMATION for the whole call.
    unsafe {
        HeapSetInformation(
            std::ptr::null_mut(),
            HeapOptimizeResources,
            (&info as *const HEAP_OPTIMIZE_RESOURCES_INFORMATION).cast(),
            size_of::<HEAP_OPTIMIZE_RESOURCES_INFORMATION>(),
        ) != 0
    }
}

/// The `PROCESS_POWER_THROTTLING_STATE` that turns EcoQoS ("execution speed" throttling) on or
/// off for a process.
fn eco_qos_state(enabled: bool) -> PROCESS_POWER_THROTTLING_STATE {
    PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: if enabled { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
    }
}

/// Opt the current process in to (or out of) EcoQoS: Windows may then run its threads on
/// efficiency cores / at an efficient clock speed. Meant for a background process whose bursts
/// are short and I/O bound. Returns false when Windows refused (older builds: harmless).
pub fn set_eco_qos(enabled: bool) -> bool {
    let state = eco_qos_state(enabled);
    // SAFETY: pseudo-handle of the current process; `state` is a valid
    // PROCESS_POWER_THROTTLING_STATE of the size passed, alive for the whole call.
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&state as *const PROCESS_POWER_THROTTLING_STATE).cast(),
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        ) != 0
    }
}

/// Wrapper making a raw pointer-sized Win32 handle `Send + Sync` (caller is responsible for
/// thread-safety of the underlying object, e.g. WinHTTP/wevtapi handles which are thread-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendHandle(pub *mut core::ffi::c_void);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_roundtrip() {
        let w = wide("Predator ✓");
        assert_eq!(*w.last().unwrap(), 0);
        assert_eq!(from_wide(&w), "Predator ✓");
        assert_eq!(unsafe { from_wide_ptr(w.as_ptr()) }, "Predator ✓");
        assert_eq!(unsafe { from_wide_ptr(std::ptr::null()) }, "");
    }

    #[test]
    fn error_text() {
        let m = error_message(5);
        assert!(!m.is_empty());
        let e = WinError::new(2, "open file");
        assert!(e.to_string().contains("open file"));
        assert!(e.to_string().contains("error 2"));
    }

    #[test]
    fn eco_qos_state_layout() {
        let on = eco_qos_state(true);
        assert_eq!(on.Version, 1);
        assert_eq!(on.ControlMask, PROCESS_POWER_THROTTLING_EXECUTION_SPEED);
        assert_eq!(on.StateMask, PROCESS_POWER_THROTTLING_EXECUTION_SPEED);
        let off = eco_qos_state(false);
        assert_eq!(off.ControlMask, PROCESS_POWER_THROTTLING_EXECUTION_SPEED, "still controlled: explicit opt-out");
        assert_eq!(off.StateMask, 0);
        // Windows 10 1709+ accepts both; the test process ends opted out (full speed)
        assert!(set_eco_qos(true));
        assert!(set_eco_qos(false));
    }

    #[test]
    fn trim_and_heap_release_work_on_the_current_process() {
        // touch a few MB so there is something to trim
        let mut buf = vec![0u8; 8 * 1024 * 1024];
        for i in (0..buf.len()).step_by(4096) {
            buf[i] = 1;
        }
        let ws = || crate::sys::sysinfo::process_memory().1;
        let before = ws();
        assert!(trim_working_set());
        let after = ws();
        assert!(after < before, "working set {before} -> {after}");
        std::hint::black_box(&buf);
        drop(buf);
        // Windows 8.1+: supported; the result is advisory anyway
        assert!(release_heap_caches());
    }

    #[test]
    fn events() {
        let e = OwnedEvent::new_manual().unwrap();
        assert!(!e.wait(Duration::from_millis(1)));
        e.set();
        assert!(e.wait(Duration::from_millis(1)));
        e.reset();
        assert!(!e.wait(Duration::from_millis(1)));
    }
}
