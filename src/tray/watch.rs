//! Event-driven service state for the tray: `NotifyServiceStatusChangeW` watches on the Vigil
//! service (and on the `Tailscale` service while its line is shown) instead of polling the SCM.
//!
//! * Windows delivers a notification as an APC to the thread that armed the watch (the UI
//!   thread), during an alertable wait: the message loop waits with `MWMO_ALERTABLE`. The callback
//!   only copies the result into a thread-local cell and posts [`WM_SVC_NOTIFY`]; the window
//!   procedure does the SCM/IPC work and re-arms (one notification per arm).
//! * A watch holds an SCM handle and a service handle. Both are closed while the tray shows a menu
//!   or a dialog ([`pause`]): APCs are not delivered inside modal loops, and an open handle would
//!   keep a service that is being uninstalled from being deleted. When the watch is re-opened,
//!   Windows reports the current state at once, so nothing that changed meanwhile is missed.
//! * Each target has one `SERVICE_NOTIFY_2W` buffer for the whole process lifetime (allocated on
//!   first use, never freed). It is re-used only when no registration is outstanding: after its
//!   callback ran, or after the handle was closed and the APCs already queued were drained with
//!   `SleepEx(0, TRUE)` (no APC is queued after `CloseServiceHandle` succeeds).
//!
//! The decisions (what a notification means, retry and storm back-off) are in [`super::model`].

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::null_mut;
use std::time::Instant;

use windows_sys::Win32::Foundation::{ERROR_NOT_ENOUGH_MEMORY, ERROR_SUCCESS, HWND};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_NOTIFY_2W, SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_QUERY_STATUS,
};
use windows_sys::Win32::System::Threading::SleepEx;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use super::model::{self, NotifyAction, NotifyEvent, WatchPolicy, WatchTarget};
use crate::paths;
use crate::sys::tailscale;
use crate::util::win::{last_error, wide};

/// Posted to the tray window by the notification callback; `wParam` = [`WatchTarget::index`].
pub(super) const WM_SVC_NOTIFY: u32 = WM_APP + 2;

const TARGETS: usize = WatchTarget::ALL.len();

thread_local! {
    /// Window that receives [`WM_SVC_NOTIFY`] (null = not initialised / shut down).
    static WINDOW: Cell<HWND> = const { Cell::new(null_mut()) };
    /// Result of the last notification per target, until the window procedure takes it.
    static EVENTS: [Cell<Option<NotifyEvent>>; TARGETS] = const { [const { Cell::new(None) }; TARGETS] };
    /// Process-lifetime notification buffers per target (null = not allocated yet).
    static BUFFERS: [Cell<*mut SERVICE_NOTIFY_2W>; TARGETS] = const { [const { Cell::new(null_mut()) }; TARGETS] };
    static SET: RefCell<WatchSet> = RefCell::new(WatchSet::default());
}

/// A service-control handle closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle from OpenSCManagerW/OpenServiceW, closed exactly once. Closing the
            // service handle cancels its outstanding notification.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// An open service (field order = drop order: service handle first, then the manager).
struct Watch {
    svc: ScHandle,
    _mgr: ScHandle,
    /// A registration is outstanding (its callback has not run yet).
    armed: bool,
}

#[derive(Default)]
struct WatchSet {
    watches: [Option<Watch>; TARGETS],
    policies: [WatchPolicy; TARGETS],
    /// Nesting depth of [`pause`]; no watch is open while it is > 0.
    paused: u32,
    /// [`shutdown`] ran: never open a watch again.
    shut_down: bool,
}

fn with_set<R>(f: impl FnOnce(&mut WatchSet) -> R) -> Option<R> {
    SET.try_with(|cell| cell.try_borrow_mut().ok().map(|mut set| f(&mut set))).ok().flatten()
}

fn service_name(target: WatchTarget) -> &'static str {
    match target {
        WatchTarget::Vigil => paths::SERVICE_NAME,
        WatchTarget::Tailscale => tailscale::SERVICE_NAME,
    }
}

/// Remember the window that receives the notifications. Call once, before the first [`sync`].
pub(super) fn init(hwnd: HWND) {
    let _ = WINDOW.try_with(|w| w.set(hwnd));
}

/// Bring the watches in line with `wanted` (indexed by [`WatchTarget::index`]): close unwanted
/// ones, open wanted ones the policy allows, and re-arm watches whose notification was handled.
/// Returns whether the Vigil service is watched, or None while paused / shut down.
pub(super) fn sync(wanted: [bool; TARGETS], now: Instant) -> Option<bool> {
    with_set(|set| {
        if set.paused > 0 || set.shut_down {
            return None;
        }
        for target in WatchTarget::ALL {
            let i = target.index();
            if !wanted[i] {
                close_watch(set, target);
                continue;
            }
            // At most one re-open (after ERROR_SERVICE_NOTIFY_CLIENT_LAGGING) per sync.
            for attempt in 0..2 {
                if set.watches[i].is_none() {
                    if !set.policies[i].may_arm(now) {
                        break;
                    }
                    match Watch::open(target) {
                        Ok(watch) => set.watches[i] = Some(watch),
                        Err(_) => {
                            set.policies[i].failed(now);
                            break;
                        }
                    }
                }
                let Some(watch) = set.watches[i].as_mut() else { break };
                if watch.armed {
                    break;
                }
                match arm(watch, target) {
                    Ok(()) => {
                        watch.armed = true;
                        break;
                    }
                    Err(code) => {
                        close_watch(set, target);
                        if attempt > 0 || model::arm_failure_action(code) != NotifyAction::Reopen {
                            set.policies[i].failed(now);
                            break;
                        }
                    }
                }
            }
        }
        Some(set.watches[WatchTarget::Vigil.index()].is_some())
    })
    .flatten()
}

/// Take the pending notification of `target` (None = nothing pending).
pub(super) fn take_event(target: WatchTarget) -> Option<NotifyEvent> {
    EVENTS.try_with(|events| events[target.index()].take()).ok().flatten()
}

/// A notification of `target` is pending (not taken yet).
pub(super) fn has_event(target: WatchTarget) -> bool {
    EVENTS
        .try_with(|events| {
            let cell = &events[target.index()];
            let ev = cell.take();
            cell.set(ev);
            ev.is_some()
        })
        .unwrap_or(false)
}

/// Book a notification of `target` that was just taken: its registration is complete (the watch
/// is no longer armed). Returns false when there is no watch (nothing to re-arm) or the storm
/// guard closed it; the polling refresh then takes over.
pub(super) fn accept(target: WatchTarget, now: Instant) -> bool {
    with_set(|set| {
        let i = target.index();
        let Some(watch) = set.watches[i].as_mut() else { return false };
        watch.armed = false;
        if set.policies[i].notified(now) {
            true
        } else {
            close_watch(set, target);
            false
        }
    })
    .unwrap_or(false)
}

/// Close the watch of `target`. `retry_from` = now when it may only be re-opened after the
/// policy's retry delay (service being deleted, failure); None = re-open on the next [`sync`].
pub(super) fn close(target: WatchTarget, retry_from: Option<Instant>) {
    with_set(|set| {
        close_watch(set, target);
        if let Some(now) = retry_from {
            set.policies[target.index()].failed(now);
        }
    });
}

/// Close every watch until the matching [`resume`] (nestable).
pub(super) fn pause() {
    with_set(|set| {
        set.paused = set.paused.saturating_add(1);
        for target in WatchTarget::ALL {
            close_watch(set, target);
        }
    });
}

/// End one [`pause`]. True when this ended the last pause: the caller re-syncs the watches.
pub(super) fn resume() -> bool {
    with_set(|set| {
        let was = set.paused;
        set.paused = was.saturating_sub(1);
        was == 1 && !set.shut_down
    })
    .unwrap_or(false)
}

/// Close every watch for good (the tray is exiting).
pub(super) fn shutdown() {
    with_set(|set| {
        set.shut_down = true;
        for target in WatchTarget::ALL {
            close_watch(set, target);
        }
    });
    let _ = WINDOW.try_with(|w| w.set(null_mut()));
}

/// Close the handles (cancels the registration), run the APCs that were already queued, then
/// drop whatever they reported: it belongs to the closed registration.
fn close_watch(set: &mut WatchSet, target: WatchTarget) {
    let Some(watch) = set.watches[target.index()].take() else { return };
    drop(watch);
    // SAFETY: zero-length alertable sleep; runs this thread's queued APCs (our callback only
    // touches the EVENTS/WINDOW cells and posts a message, never SET).
    unsafe { SleepEx(0, 1) };
    let _ = take_event(target);
}

impl Watch {
    fn open(target: WatchTarget) -> Result<Watch, u32> {
        // SAFETY: local machine, default database, connect right only.
        let mgr = ScHandle(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
        if mgr.0.is_null() {
            return Err(last_error());
        }
        let name = wide(service_name(target));
        // SAFETY: valid manager handle and NUL-terminated name; query access only.
        let svc = ScHandle(unsafe { OpenServiceW(mgr.0, name.as_ptr(), SERVICE_QUERY_STATUS) });
        if svc.0.is_null() {
            return Err(last_error());
        }
        Ok(Watch { svc, _mgr: mgr, armed: false })
    }
}

/// The process-lifetime notification buffer of `target`.
fn buffer(target: WatchTarget) -> Option<*mut SERVICE_NOTIFY_2W> {
    BUFFERS
        .try_with(|buffers| {
            let cell = &buffers[target.index()];
            if cell.get().is_null() {
                // Intentionally never freed: a late APC can never touch freed memory.
                cell.set(Box::into_raw(Box::new(SERVICE_NOTIFY_2W::default())));
            }
            cell.get()
        })
        .ok()
}

/// Register for the next state change of `watch`'s service.
fn arm(watch: &Watch, target: WatchTarget) -> Result<(), u32> {
    let buf = buffer(target).ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    let notify = SERVICE_NOTIFY_2W {
        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
        pfnNotifyCallback: Some(notify_callback),
        pContext: std::ptr::without_provenance_mut(target.index()),
        ..Default::default()
    };
    // SAFETY: `buf` is a live, exclusively ours SERVICE_NOTIFY_2W; no registration is outstanding
    // on it (the caller only arms a watch whose callback ran, or a freshly opened one, and closing
    // a watch drains its queued APCs), so the SCM does not use it at this moment.
    unsafe { buf.write(notify) };
    // SAFETY: valid service handle opened with SERVICE_QUERY_STATUS; `buf` stays valid for the
    // rest of the process.
    let rc = unsafe { NotifyServiceStatusChangeW(watch.svc.0, model::WATCH_MASK, buf) };
    if rc == ERROR_SUCCESS { Ok(()) } else { Err(rc) }
}

/// `PFN_SC_NOTIFY_CALLBACK`: runs as an APC on the UI thread. No SCM calls here (documented
/// restriction): copy the result and wake the window procedure.
unsafe extern "system" fn notify_callback(param: *const c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if param.is_null() {
            return;
        }
        // SAFETY: the SCM passes back the buffer registered in `arm` (alive for the process
        // lifetime); only plain integer fields are read. `pszServiceNames` is only set for
        // SERVICE_NOTIFY_CREATED/DELETED on SCM handles, which are never requested.
        let (target, event) = unsafe {
            let n = &*param.cast::<SERVICE_NOTIFY_2W>();
            let event = NotifyEvent {
                status: n.dwNotificationStatus,
                triggered: n.dwNotificationTriggered,
                state: n.ServiceStatus.dwCurrentState,
                pid: n.ServiceStatus.dwProcessId,
            };
            (n.pContext.addr(), event)
        };
        let Some(target) = WatchTarget::from_index(target) else { return };
        let _ = EVENTS.try_with(|events| events[target.index()].set(Some(event)));
        let hwnd = WINDOW.try_with(Cell::get).unwrap_or(null_mut());
        if !hwnd.is_null() {
            // SAFETY: plain post to our own window (a failure only delays the update until the
            // next refresh).
            unsafe { PostMessageW(hwnd, WM_SVC_NOTIFY, target.index(), 0) };
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{WAIT_IO_COMPLETION, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    use windows_sys::Win32::System::Services::SERVICE_RUNNING;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, GetProcessHandleCount, QueueUserAPC,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, PM_NOREMOVE, PM_REMOVE, PeekMessageW, PostThreadMessageW};

    /// Open `name` like `Watch::open` does (the tests watch a system service, read-only).
    fn open_named(name: &str) -> Watch {
        // SAFETY: local machine, default database, connect right only.
        let mgr = ScHandle(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
        assert!(!mgr.0.is_null());
        let name = wide(name);
        // SAFETY: valid manager handle and NUL-terminated name; query access only.
        let svc = ScHandle(unsafe { OpenServiceW(mgr.0, name.as_ptr(), SERVICE_QUERY_STATUS) });
        assert!(!svc.0.is_null());
        Watch { svc, _mgr: mgr, armed: false }
    }

    /// Wait alertably (the APC only runs then) until a notification for `target` arrives.
    fn wait_for_event(target: WatchTarget, ms: u32) -> Option<NotifyEvent> {
        for _ in 0..ms.div_ceil(50) {
            // SAFETY: alertable sleep; runs this thread's queued APCs.
            unsafe { SleepEx(50, 1) };
            if let Some(ev) = take_event(target) {
                return Some(ev);
            }
        }
        None
    }

    /// Live check against a service every Windows has (read-only: only its status is watched):
    /// arming queues the current state at once, the callback copies it, re-arming without a
    /// change queues nothing, and closing drains cleanly. Each test runs on its own thread, so
    /// the thread-locals and the APC queue are private to it.
    #[test]
    fn live_watch_reports_current_state_once() {
        let watch = open_named("EventLog");
        arm(&watch, WatchTarget::Tailscale).expect("arm");
        let ev = wait_for_event(WatchTarget::Tailscale, 5_000).expect("immediate notification of the current state");
        assert_eq!(ev.status, ERROR_SUCCESS);
        assert_eq!(ev.state, SERVICE_RUNNING);
        assert!(ev.pid != 0);
        assert!(ev.triggered & model::WATCH_MASK != 0);
        assert_eq!(model::notify_action(&ev, &crate::sys::ServiceState::Running, Some(ev.pid)), NotifyAction::Rearm);

        // Re-arm on the same handle: EventLog does not change state, so nothing is queued
        // (otherwise every re-arm would loop).
        arm(&watch, WatchTarget::Tailscale).expect("re-arm");
        assert_eq!(wait_for_event(WatchTarget::Tailscale, 500), None);

        // Closing cancels the registration; draining finds nothing.
        drop(watch);
        // SAFETY: zero-length alertable sleep.
        unsafe { SleepEx(0, 1) };
        assert_eq!(take_event(WatchTarget::Tailscale), None);

        // A fresh handle reports the current state again (what resume after a pause relies on).
        let watch = open_named("EventLog");
        arm(&watch, WatchTarget::Tailscale).expect("arm on a new handle");
        assert!(wait_for_event(WatchTarget::Tailscale, 5_000).is_some());
    }

    /// The callback copies the result out of the buffer; with no window registered on this thread
    /// nothing is posted, and unknown contexts or a null buffer are ignored.
    #[test]
    fn callback_copies_the_result_and_ignores_garbage() {
        let mut n = SERVICE_NOTIFY_2W {
            dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
            pContext: std::ptr::without_provenance_mut(WatchTarget::Vigil.index()),
            dwNotificationStatus: 0,
            dwNotificationTriggered: 8,
            ..Default::default()
        };
        n.ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        n.ServiceStatus.dwProcessId = 77;
        // SAFETY: valid SERVICE_NOTIFY_2W on the stack, alive for the call.
        unsafe { notify_callback((&raw const n).cast()) };
        assert!(has_event(WatchTarget::Vigil));
        assert!(has_event(WatchTarget::Vigil)); // peeking does not consume
        assert_eq!(
            take_event(WatchTarget::Vigil),
            Some(NotifyEvent { status: 0, triggered: 8, state: SERVICE_RUNNING, pid: 77 })
        );
        let mut msg = MSG::default();
        // SAFETY: valid out-pointer; thread queue of this test thread.
        assert_eq!(unsafe { PeekMessageW(&mut msg, null_mut(), WM_SVC_NOTIFY, WM_SVC_NOTIFY, PM_REMOVE) }, 0);

        // Unknown context or a null buffer: ignored.
        n.pContext = std::ptr::without_provenance_mut(9);
        // SAFETY: as above; null is handled by the callback.
        unsafe {
            notify_callback((&raw const n).cast());
            notify_callback(std::ptr::null());
        }
        assert_eq!(take_event(WatchTarget::Vigil), None);
        assert_eq!(take_event(WatchTarget::Tailscale), None);
        assert!(!has_event(WatchTarget::Vigil));
    }

    /// pause/resume nest, an unbalanced resume does nothing, and a shut-down set never opens a
    /// watch again.
    #[test]
    fn pause_resume_and_shutdown() {
        let now = Instant::now();
        pause();
        pause();
        assert_eq!(sync([true, false], now), None);
        assert!(!resume());
        assert!(resume());
        assert!(!resume());
        shutdown();
        assert_eq!(sync([true, true], now + Duration::from_secs(1)), None);
        assert!(!resume());
    }

    /// Unwanted targets are never opened; a wanted target that cannot be opened is backed off.
    #[test]
    fn sync_without_wanted_targets_opens_nothing() {
        let now = Instant::now();
        assert_eq!(sync([false, false], now), Some(false));
        assert!(with_set(|set| set.watches.iter().all(Option::is_none)).unwrap_or(false));
    }

    /// The storm guard is wired through `accept`: more than `STORM_LIMIT` notifications within the
    /// window close the watch, and `sync` does not re-open it during the back-off (so no SCM call
    /// is made for the real service name here).
    #[test]
    fn storm_guard_closes_the_watch() {
        let now = Instant::now();
        let target = WatchTarget::Vigil;
        // Stand-in watch on a service every Windows has (read-only; never armed here).
        assert!(with_set(|set| set.watches[target.index()] = Some(open_named("EventLog"))).is_some());
        for i in 0..model::STORM_LIMIT {
            assert!(accept(target, now), "notification {i}");
        }
        assert!(!accept(target, now), "storm: the watch is closed");
        assert!(with_set(|set| set.watches[target.index()].is_none()).unwrap_or(false));
        assert_eq!(sync([true, false], now + Duration::from_secs(1)), Some(false), "backed off");
        assert!(with_set(|set| set.watches[target.index()].is_none()).unwrap_or(false));
        assert!(!accept(target, now), "no watch: nothing to re-arm");
        shutdown();
    }

    /// The message loop's idle wait (`ui::wait_for_input_or_apc`) ends for an APC (that is how a
    /// service notification arrives), for posted input and for input that was already seen but
    /// left queued; and a real notification of an armed watch is delivered during it.
    #[test]
    fn idle_wait_wakes_for_apcs_and_input() {
        use super::super::ui::wait_for_input_or_apc;
        thread_local! {
            static APC_RAN: Cell<usize> = const { Cell::new(0) };
        }
        unsafe extern "system" fn apc(data: usize) {
            APC_RAN.set(data);
        }
        const PROBE: u32 = WM_APP + 77;

        let mut msg = MSG::default();
        // SAFETY: valid out-pointer; creates this test thread's message queue.
        unsafe { PeekMessageW(&mut msg, null_mut(), 0, 0, PM_NOREMOVE) };
        assert_eq!(wait_for_input_or_apc(20), WAIT_TIMEOUT, "nothing pending");

        // SAFETY: pseudo-handle of this thread; `apc` only sets a thread-local cell.
        assert_ne!(unsafe { QueueUserAPC(Some(apc), GetCurrentThread(), 7) }, 0);
        assert_eq!(wait_for_input_or_apc(5_000), WAIT_IO_COMPLETION, "APC ends the wait");
        assert_eq!(APC_RAN.get(), 7);

        // SAFETY: plain thread message to this thread (its queue exists).
        assert_ne!(unsafe { PostThreadMessageW(GetCurrentThreadId(), PROBE, 0, 0) }, 0);
        assert_eq!(wait_for_input_or_apc(5_000), WAIT_OBJECT_0, "posted input ends the wait");
        // SAFETY: valid out-pointer; peek without removing marks the input as seen.
        assert_ne!(unsafe { PeekMessageW(&mut msg, null_mut(), PROBE, PROBE, PM_NOREMOVE) }, 0);
        assert_eq!(wait_for_input_or_apc(0), WAIT_OBJECT_0, "seen but queued input still counts");
        // SAFETY: as above.
        assert_ne!(unsafe { PeekMessageW(&mut msg, null_mut(), PROBE, PROBE, PM_REMOVE) }, 0);
        assert_eq!(wait_for_input_or_apc(20), WAIT_TIMEOUT, "queue drained");

        // A real notification (the current state, queued right after arming) arrives as an APC
        // while the thread sits in the idle wait (or already during the SCM call itself).
        let watch = open_named("EventLog");
        arm(&watch, WatchTarget::Vigil).expect("arm");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ev = take_event(WatchTarget::Vigil);
        while ev.is_none() && Instant::now() < deadline {
            let r = wait_for_input_or_apc(250);
            assert!(r == WAIT_IO_COMPLETION || r == WAIT_TIMEOUT, "unexpected wait result {r:#x}");
            ev = take_event(WatchTarget::Vigil);
        }
        assert_eq!(ev.map(|e| (e.status, e.state)), Some((ERROR_SUCCESS, SERVICE_RUNNING)));
    }

    /// Many open → arm → close → drain cycles (one per menu or dialog, as in `pause`) leave no
    /// handles or memory behind. Process-wide counters, so ignored by default (other tests run in
    /// parallel). Run: `cargo test --lib tray::watch -- --ignored --test-threads=1 --nocapture`.
    #[test]
    #[ignore = "process-wide counters: run alone with --ignored --test-threads=1"]
    fn open_arm_close_cycles_do_not_leak() {
        fn counters() -> (u32, usize) {
            let mut handles = 0u32;
            let mut mem =
                PROCESS_MEMORY_COUNTERS_EX { cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32, ..Default::default() };
            // SAFETY: pseudo-handle of this process; valid out-pointers of the stated size.
            unsafe {
                assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut handles), 0);
                assert_ne!(K32GetProcessMemoryInfo(GetCurrentProcess(), (&raw mut mem).cast(), mem.cb), 0);
            }
            (handles, mem.PrivateUsage)
        }
        let cycle = |i: usize| {
            let watch = open_named("EventLog");
            arm(&watch, WatchTarget::Tailscale).expect("arm");
            if i.is_multiple_of(2) {
                // Half of the cycles take the notification first (the normal path) ...
                let _ = wait_for_event(WatchTarget::Tailscale, 2_000);
            }
            // ... the others close with the registration (and maybe its APC) still outstanding.
            drop(watch);
            // SAFETY: zero-length alertable sleep (the drain of `close_watch`).
            unsafe { SleepEx(0, 1) };
            let _ = take_event(WatchTarget::Tailscale);
        };
        (0..50).for_each(cycle); // warm-up (RPC binding)
        let mut samples = vec![counters()];
        for block in 0..6 {
            (block * 1_000..(block + 1) * 1_000).for_each(cycle);
            samples.push(counters());
        }
        eprintln!("(handles, private bytes) every 1000 cycles: {samples:?}");
        let (first, last) = (samples[0], samples[samples.len() - 1]);
        assert!(last.0 <= first.0 + 8, "handle growth: {first:?} -> {last:?}");
        // Heap growth settles after the first blocks; a leak would keep growing linearly.
        let settled = samples[2];
        assert!(last.1 <= settled.1 + 128 * 1024, "private memory keeps growing: {samples:?}");
    }

    /// A full cycle with the real Vigil service name: whatever its state on this machine
    /// (running, stopped or not installed), sync either watches it or backs off, and pause /
    /// resume close and re-open the watch. Read-only (status queries only).
    #[test]
    fn live_sync_cycle_on_the_predator_service() {
        let now = Instant::now();
        let watched = sync([true, false], now).expect("not paused");
        let installed = crate::sys::scm::query(paths::SERVICE_NAME).0 != crate::sys::ServiceState::NotInstalled;
        if !installed {
            assert!(!watched);
            // Backed off: no new attempt before the retry delay.
            assert!(with_set(|set| !set.policies[0].may_arm(now)).unwrap_or(false));
            return;
        }
        assert!(watched);
        // The first notification reports the current state.
        let ev = wait_for_event(WatchTarget::Vigil, 5_000).expect("current state");
        assert_eq!(ev.status, ERROR_SUCCESS);
        assert!(accept(WatchTarget::Vigil, now));
        assert_eq!(sync([true, false], now), Some(true)); // re-armed
        assert!(with_set(|set| set.watches[0].as_ref().is_some_and(|w| w.armed)).unwrap_or(false));

        pause();
        assert!(with_set(|set| set.watches[0].is_none()).unwrap_or(false));
        assert!(resume());
        assert_eq!(sync([true, false], now), Some(true));
        assert!(wait_for_event(WatchTarget::Vigil, 5_000).is_some());

        close(WatchTarget::Vigil, Some(now));
        assert_eq!(sync([true, false], now), Some(false)); // retry delay
        shutdown();
    }
}
