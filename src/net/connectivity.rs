//! Event-driven internet connectivity: NotifyNetworkConnectivityHintChange (no polling).
//!
//! The OS invokes the registered callback on an NT thread-pool worker (it may run concurrently
//! with itself; serialization is not documented). The callback only maps the level, compares it
//! with the last reported one (atomic swap → duplicates are coalesced) and forwards real changes.
//! Dropping the [`ConnectivityWatcher`] calls `CancelMibChangeNotify2`, which waits for callbacks
//! already running, and only then frees the context.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetNetworkConnectivityHint, NotifyNetworkConnectivityHintChange,
};
use windows_sys::Win32::Networking::WinSock::{
    NL_NETWORK_CONNECTIVITY_HINT, NL_NETWORK_CONNECTIVITY_LEVEL_HINT,
    NetworkConnectivityLevelHintConstrainedInternetAccess, NetworkConnectivityLevelHintInternetAccess,
    NetworkConnectivityLevelHintLocalAccess, NetworkConnectivityLevelHintNone,
};

use crate::sys::InternetStatus;
use crate::util::win::error_message;

/// Map an `NL_NETWORK_CONNECTIVITY_LEVEL_HINT` to our status.
pub fn level_to_status(level: NL_NETWORK_CONNECTIVITY_LEVEL_HINT) -> InternetStatus {
    const INTERNET: NL_NETWORK_CONNECTIVITY_LEVEL_HINT = NetworkConnectivityLevelHintInternetAccess;
    const LOCAL: NL_NETWORK_CONNECTIVITY_LEVEL_HINT = NetworkConnectivityLevelHintLocalAccess;
    const CONSTRAINED: NL_NETWORK_CONNECTIVITY_LEVEL_HINT = NetworkConnectivityLevelHintConstrainedInternetAccess;
    const NONE: NL_NETWORK_CONNECTIVITY_LEVEL_HINT = NetworkConnectivityLevelHintNone;
    match level {
        INTERNET => InternetStatus::Connected,
        LOCAL => InternetStatus::LocalOnly,
        CONSTRAINED => InternetStatus::CaptivePortal,
        NONE => InternetStatus::Disconnected,
        // Unknown (seen briefly at boot), Hidden, and any value added by a future Windows.
        _ => InternetStatus::Unknown,
    }
}

/// Current connectivity level from GetNetworkConnectivityHint.
pub fn current() -> InternetStatus {
    let mut hint = NL_NETWORK_CONNECTIVITY_HINT::default();
    // SAFETY: `hint` is a valid, writable out-parameter.
    let rc = unsafe { GetNetworkConnectivityHint(&mut hint) };
    if rc != NO_ERROR {
        return InternetStatus::Unknown;
    }
    level_to_status(hint.ConnectivityLevel)
}

/// Compact encoding of a status for the atomic "last reported" slot.
fn encode(status: InternetStatus) -> u8 {
    match status {
        InternetStatus::Connected => 0,
        InternetStatus::LocalOnly => 1,
        InternetStatus::CaptivePortal => 2,
        InternetStatus::Disconnected => 3,
        InternetStatus::Unknown => 4,
    }
}

/// The user's change handler.
type OnChange = Arc<dyn Fn(InternetStatus) + Send + Sync>;

/// State shared with the OS callback (heap-allocated, freed only after cancellation).
struct WatchContext {
    on_change: OnChange,
    last: AtomicU8,
}

impl WatchContext {
    fn new(on_change: OnChange, initial: InternetStatus) -> Self {
        Self { on_change, last: AtomicU8::new(encode(initial)) }
    }

    /// Record `status`; `true` when it differs from the previously recorded one.
    fn record(&self, status: InternetStatus) -> bool {
        let code = encode(status);
        self.last.swap(code, Ordering::AcqRel) != code
    }

    /// Handle one OS notification: forward the level only when it actually changed.
    fn handle(&self, level: NL_NETWORK_CONNECTIVITY_LEVEL_HINT) {
        let status = level_to_status(level);
        if self.record(status) {
            (self.on_change)(status);
        }
    }
}

/// `PNETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK` (runs on an OS thread-pool thread).
unsafe extern "system" fn on_hint(context: *const c_void, hint: NL_NETWORK_CONNECTIVITY_HINT) {
    // Never unwind into the OS: that would abort the whole service.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() {
            return;
        }
        // SAFETY: `context` is the `WatchContext` registered in `watch`; it is freed only after
        // CancelMibChangeNotify2 returned, which waits for in-flight callbacks.
        let ctx = unsafe { &*context.cast::<WatchContext>() };
        ctx.handle(hint.ConnectivityLevel);
    }));
}

/// Active registration; dropping it cancels the notification (CancelMibChangeNotify2).
///
/// Must not be dropped from inside the `on_change` callback (CancelMibChangeNotify2 would
/// wait for that very callback and deadlock).
pub struct ConnectivityWatcher {
    handle: HANDLE,
    context: *mut WatchContext,
}

// SAFETY: the notification handle and the context pointer are not tied to the registering thread;
// the context is only read (atomics + an `Arc<dyn Fn + Send + Sync>`) until `Drop` frees it.
unsafe impl Send for ConnectivityWatcher {}
unsafe impl Sync for ConnectivityWatcher {}

impl std::fmt::Debug for ConnectivityWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectivityWatcher { .. }")
    }
}

impl Drop for ConnectivityWatcher {
    fn drop(&mut self) {
        // SAFETY: `handle` comes from a successful registration and is cancelled exactly once.
        let rc = unsafe { CancelMibChangeNotify2(self.handle) };
        if rc == NO_ERROR {
            // SAFETY: the registration is gone and running callbacks have finished, so nothing
            // references the context any more; it was created by Box::into_raw in `watch`.
            drop(unsafe { Box::from_raw(self.context) });
        } else {
            // Callbacks may still fire: leak the (tiny) context rather than risk a use-after-free.
            crate::log_warn!("CancelMibChangeNotify2 failed: {} (error {rc})", error_message(rc));
        }
    }
}

/// Register `on_change(new_status)` to be called (on an OS thread-pool thread) whenever the
/// connectivity level changes. The callback must be fast and must not block.
pub fn watch(on_change: Arc<dyn Fn(InternetStatus) + Send + Sync>) -> Result<ConnectivityWatcher, String> {
    // Seed with the current level and request the initial notification: a change that happens
    // between this read and the registration is still reported, an unchanged level is not.
    let context = Box::into_raw(Box::new(WatchContext::new(on_change, current())));
    let mut handle: HANDLE = null_mut();
    // SAFETY: `on_hint` matches PNETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK; `context` stays valid
    // until the registration is cancelled; `handle` is a valid out-parameter.
    let rc = unsafe {
        NotifyNetworkConnectivityHintChange(Some(on_hint), context.cast_const().cast::<c_void>(), true, &mut handle)
    };
    if rc != NO_ERROR {
        // SAFETY: registration failed, so the OS holds no reference to the context.
        drop(unsafe { Box::from_raw(context) });
        return Err(format!("cannot watch network connectivity changes: {} (error {rc})", error_message(rc)));
    }
    Ok(ConnectivityWatcher { handle, context })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use windows_sys::Win32::Networking::WinSock::{
        NetworkConnectivityLevelHintHidden, NetworkConnectivityLevelHintUnknown,
    };

    fn recorder() -> (Arc<Mutex<Vec<InternetStatus>>>, OnChange) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        (seen, Arc::new(move |s| s2.lock().unwrap().push(s)))
    }

    fn hint(level: NL_NETWORK_CONNECTIVITY_LEVEL_HINT) -> NL_NETWORK_CONNECTIVITY_HINT {
        NL_NETWORK_CONNECTIVITY_HINT { ConnectivityLevel: level, ..Default::default() }
    }

    #[test]
    fn level_mapping() {
        assert_eq!(level_to_status(NetworkConnectivityLevelHintInternetAccess), InternetStatus::Connected);
        assert_eq!(level_to_status(NetworkConnectivityLevelHintLocalAccess), InternetStatus::LocalOnly);
        assert_eq!(
            level_to_status(NetworkConnectivityLevelHintConstrainedInternetAccess),
            InternetStatus::CaptivePortal
        );
        assert_eq!(level_to_status(NetworkConnectivityLevelHintNone), InternetStatus::Disconnected);
        assert_eq!(level_to_status(NetworkConnectivityLevelHintUnknown), InternetStatus::Unknown);
        assert_eq!(level_to_status(NetworkConnectivityLevelHintHidden), InternetStatus::Unknown);
        assert_eq!(level_to_status(42), InternetStatus::Unknown);
        assert_eq!(level_to_status(-1), InternetStatus::Unknown);
    }

    #[test]
    fn encoding_is_distinct() {
        let all = [
            InternetStatus::Connected,
            InternetStatus::LocalOnly,
            InternetStatus::CaptivePortal,
            InternetStatus::Disconnected,
            InternetStatus::Unknown,
        ];
        let mut codes: Vec<u8> = all.iter().map(|s| encode(*s)).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn callback_coalesces_duplicates() {
        let (seen, cb) = recorder();
        let ctx = WatchContext::new(cb, InternetStatus::Connected);
        let p = (&ctx as *const WatchContext).cast::<c_void>();
        // SAFETY: `p` points to a live WatchContext for the duration of the calls.
        unsafe {
            on_hint(p, hint(NetworkConnectivityLevelHintInternetAccess)); // same as initial: ignored
            on_hint(p, hint(NetworkConnectivityLevelHintNone));
            on_hint(p, hint(NetworkConnectivityLevelHintNone)); // duplicate: ignored
            on_hint(p, hint(NetworkConnectivityLevelHintLocalAccess));
            on_hint(p, hint(NetworkConnectivityLevelHintInternetAccess));
            on_hint(p, hint(NetworkConnectivityLevelHintHidden));
            on_hint(p, hint(NetworkConnectivityLevelHintUnknown)); // same mapped status: ignored
        }
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                InternetStatus::Disconnected,
                InternetStatus::LocalOnly,
                InternetStatus::Connected,
                InternetStatus::Unknown
            ]
        );
    }

    #[test]
    fn callback_null_context_and_panics_are_contained() {
        // SAFETY: a null context is explicitly handled.
        unsafe { on_hint(std::ptr::null(), hint(NetworkConnectivityLevelHintNone)) };
        let ctx = WatchContext::new(Arc::new(|_| panic!("boom (expected in this test)")), InternetStatus::Connected);
        let p = (&ctx as *const WatchContext).cast::<c_void>();
        // SAFETY: live context; the panic must be caught inside the callback.
        unsafe { on_hint(p, hint(NetworkConnectivityLevelHintNone)) };
        // The state was still updated, so the same level is not re-forwarded.
        assert!(!ctx.record(InternetStatus::Disconnected));
    }

    #[test]
    fn live_current_and_watch_register_and_cancel() {
        // Read-only OS calls: query the hint, register for changes, cancel on drop.
        let status = current();
        assert!(matches!(
            status,
            InternetStatus::Connected
                | InternetStatus::LocalOnly
                | InternetStatus::CaptivePortal
                | InternetStatus::Disconnected
                | InternetStatus::Unknown
        ));
        let (_seen, cb) = recorder();
        let w = watch(cb).expect("NotifyNetworkConnectivityHintChange");
        assert_eq!(format!("{w:?}"), "ConnectivityWatcher { .. }");
        std::thread::sleep(std::time::Duration::from_millis(50)); // let the initial notification run
        drop(w);
    }
}
