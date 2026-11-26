//! Win32 half of the tray: single-instance guard, hidden window, notification icon, context
//! menu, dialogs and the message loop. Everything runs on one thread (the UI thread); idle = the
//! thread in an alertable `MsgWaitForMultipleObjectsEx`, woken only by the shell, a service
//! state notification ([`watch`]), the 5-minute safety refresh or a user click. Only while a
//! pairing code created from the tray is active does a one-shot timer ask the service every 5 s
//! whether it was used ("Paired: …" balloon); it stops with the code.
//!
//! Re-entrancy: modal calls (`TrackPopupMenuEx`, `MessageBoxW`, `ShellExecuteW`) and even
//! `Shell_NotifyIconW` / `DestroyWindow` can dispatch messages back into the window procedure.
//! The [`App`] state is therefore only borrowed for short sections that never call such APIs
//! ([`with_app`]), and a busy flag ([`BusyGuard`]) prevents nested menus, dialogs and refreshes.
//! The service watches are closed while a menu or dialog is open ([`WatchPause`]).

use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, HINSTANCE, HWND, LPARAM, LRESULT, POINT, SetLastError,
    WAIT_FAILED, WPARAM,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::SetProcessWorkingSetSizeEx;
use windows_sys::Win32::System::Threading::{CreateMutexW, GetCurrentProcess, INFINITE};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow, GetSystemMetricsForDpi, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NIM_SETVERSION, NOTIFY_ICON_INFOTIP_FLAGS, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
    ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
    DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, GetSystemMetrics, HICON, HMENU,
    IDI_APPLICATION, IMAGE_ICON, KillTimer, LR_DEFAULTCOLOR, LoadIconW, LoadImageW, MB_ICONERROR, MB_ICONINFORMATION,
    MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MENU_ITEM_FLAGS, MESSAGEBOX_STYLE, MF_CHECKED, MF_GRAYED, MF_POPUP,
    MF_SEPARATOR, MF_STRING, MSG, MSGFLT_ALLOW, MWMO_ALERTABLE, MWMO_INPUTAVAILABLE, MessageBoxW,
    MsgWaitForMultipleObjectsEx, PM_REMOVE, PeekMessageW, PostMessageW, PostQuitMessage, QS_ALLINPUT, RegisterClassExW,
    RegisterWindowMessageW, SHOW_WINDOW_CMD, SM_CXSMICON, SM_CYSMICON, SM_MENUDROPALIGNMENT, SW_HIDE, SW_SHOWNORMAL,
    SetCoalescableTimer, SetForegroundWindow, SetTimer, TPM_LEFTALIGN, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTALIGN,
    TPM_RIGHTBUTTON, TrackPopupMenuEx, TranslateMessage, UnregisterClassW, WM_APP, WM_CLOSE, WM_DESTROY, WM_ENDSESSION,
    WM_NULL, WM_QUIT, WM_TIMER, WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_POPUP,
};

use super::model::{
    self, ActionOutcome, BalloonKind, IconKind, MenuAction, MenuEntry, NotifyAction, PairingCheck, PairingStart,
    RefreshPeriod, Snapshot, UsersFetch, WatchTarget,
};
use super::watch::{self, WM_SVC_NOTIFY};
use crate::features::Feature;
use crate::ipc::{self, IpcRequest, IpcResponse};
use crate::paths;
use crate::sys::{ServiceState, scm, tailscale};
use crate::util::win::{OwnedHandle, WinError, error_message, last_error, wide, wide_path};

// The `Win32_UI_Input_Ime` windows-sys feature is not enabled; this is the only IMM function used.
#[link(name = "imm32", kind = "raw-dylib")]
unsafe extern "system" {
    /// `ImmDisableIME(-1)`: no IME / Text Services Framework for any thread of this process.
    fn ImmDisableIME(idthread: u32) -> i32;
}

/// Notification-icon callback message.
const WM_TRAY: u32 = WM_APP + 1;
/// `uID` of our (only) notification icon.
const TRAY_UID: u32 = 1;
const CLASS_NAME: &str = "PredatorRemoteControllerTray";
const STATUS_CAPTION: &str = "Predator Remote Controller — Service Status";
const PAIRING_CAPTION: &str = "Predator Remote Controller — Pair Telegram User";
const USERS_CAPTION: &str = "Predator Remote Controller — Telegram Users";

/// Periodic refresh (SCM queries of the Predator and Tailscale services + IPC Status only):
/// [`RefreshPeriod::Safety`] while the service is watched, [`RefreshPeriod::Poll`] otherwise.
const TIMER_REFRESH: usize = 1;
/// One-shot refresh after "Restart Service" / "Start Service" and after the service (re)started.
const TIMER_FOLLOWUP: usize = 2;
const FOLLOWUP_MS: u32 = 15_000;
/// Delay when the follow-up (or a service notification) arrives while a menu/dialog is open.
const FOLLOWUP_BUSY_RETRY_MS: u32 = 5_000;
/// One-shot retry when the shell refused NIM_ADD (taskbar not ready yet at logon).
const TIMER_ADD_RETRY: usize = 3;
const ADD_RETRY_MS: u32 = 5_000;
const MAX_ADD_RETRIES: u32 = 24;
/// One-shot: handle service notifications that arrived while the tray was busy.
const TIMER_NOTIFY_RETRY: usize = 4;
/// One-shot, re-armed only while a pairing code created from the tray is active
/// ([`model::PAIRING_CHECK`]).
const TIMER_PAIRING: usize = 5;
const PAIRING_CHECK_TOLERANCE_MS: u32 = 1_000;

const STATUS_TIMEOUT: Duration = Duration::from_secs(3);
const ACTION_TIMEOUT: Duration = Duration::from_secs(5);
/// `TailscaleStatus` spawns the Tailscale CLI inside the service (status dialog only).
const TAILSCALE_TIMEOUT: Duration = Duration::from_secs(15);

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    /// A menu, dialog or refresh is in progress (re-entrancy guard).
    static BUSY: Cell<bool> = const { Cell::new(false) };
    /// The tray is shutting down: never (re-)add the icon or show UI again.
    static EXITING: Cell<bool> = const { Cell::new(false) };
    /// Registered "TaskbarCreated" message id (0 = registration failed).
    static TASKBAR_CREATED: Cell<u32> = const { Cell::new(0) };
    /// COM was initialised on this thread by us and must be uninitialised.
    static COM_INITIALIZED: Cell<bool> = const { Cell::new(false) };
    /// Period the refresh timer currently runs with (None = not set yet).
    static TIMER_PERIOD: Cell<Option<RefreshPeriod>> = const { Cell::new(None) };
}

// ---------------------------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------------------------

/// Run the tray until the user exits it (or the service denies access). Returns the exit code.
pub fn run() -> i32 {
    // Before the first window (including a start-up error MessageBox) exists: the tray has no
    // text input, so the IME / Text Services Framework (MSCTF and friends) is never loaded.
    // Measured: about -0.1..-0.2 MB private and -0.8..-1.4 MB working set.
    // SAFETY: plain call; -1 = every thread of this process. Failure leaves the IME enabled.
    unsafe { ImmDisableIME(u32::MAX) };

    let _instance = match acquire_single_instance() {
        Instance::AlreadyRunning => return 0,
        Instance::First(guard) => guard,
    };

    // SAFETY: no pointers; failure (e.g. awareness already set by the manifest) is harmless.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };

    // SAFETY: null = handle of the running executable; never fails for the process image.
    let hinst: HINSTANCE = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class_name = wide(CLASS_NAME);
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        style: 0,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinst,
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
        hIconSm: std::ptr::null_mut(),
    };
    // SAFETY: `wc` and the class name buffer are valid for the call.
    if unsafe { RegisterClassExW(&wc) } == 0 {
        fatal(&WinError::last("Could not register the tray window class (RegisterClassExW)"));
        return 1;
    }

    let title = wide(model::APP_TITLE);
    // A hidden top-level window (not message-only) so the "TaskbarCreated" broadcast reaches us.
    // SAFETY: class registered above; all pointer arguments are valid or null.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        let err = WinError::last("Could not create the tray window (CreateWindowExW)");
        // SAFETY: same class name / instance as registered.
        unsafe { UnregisterClassW(class_name.as_ptr(), hinst) };
        fatal(&err);
        return 1;
    }

    let taskbar_created_name = wide("TaskbarCreated");
    // SAFETY: valid NUL-terminated string.
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar_created_name.as_ptr()) };
    TASKBAR_CREATED.set(taskbar_created);
    // If the tray runs elevated, let the (non-elevated) shell's messages through UIPI.
    allow_message(hwnd, taskbar_created);
    allow_message(hwnd, WM_TRAY);

    let icons = Icons::load(hinst, small_icon_size(hwnd));
    install_app(App {
        hinst,
        icons,
        snapshot: Snapshot::default(),
        bot_username: None,
        icon_added: false,
        shown: None,
        add_retries: 0,
        pending_start: false,
        pending_pairing: None,
        last_menu_close: None,
    });

    watch::init(hwnd);
    // First refresh BEFORE showing anything: a non-owner user must never see the icon. It also
    // opens the service watches and sets the refresh timer.
    let code = if refresh_and_watch(hwnd) {
        if !is_icon_added() {
            schedule_add_retry(hwnd);
        }
        trim_working_set();
        message_loop()
    } else {
        0 // access denied: exit silently
    };

    EXITING.set(true);
    watch::shutdown();
    remove_icon(hwnd);
    // SAFETY: destroying an already destroyed window just fails; WM_DESTROY is idempotent here.
    unsafe { DestroyWindow(hwnd) };
    drop(take_app()); // destroys the icons
    // SAFETY: the window of this class is gone.
    unsafe { UnregisterClassW(class_name.as_ptr(), hinst) };
    com_uninitialize();
    code
}

enum Instance {
    /// Holds the named mutex for the lifetime of the process (null handle = guard unavailable).
    First(OwnedHandle),
    AlreadyRunning,
}

/// One tray per session: `Local\PredatorRemoteControllerTray`.
fn acquire_single_instance() -> Instance {
    let name = wide(paths::TRAY_MUTEX);
    // SAFETY: valid NUL-terminated name, default security, not initially owned.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    let err = last_error();
    if handle.is_null() {
        // ACCESS_DENIED = the object exists but belongs to another security context.
        return if err == ERROR_ACCESS_DENIED {
            Instance::AlreadyRunning
        } else {
            Instance::First(OwnedHandle(std::ptr::null_mut()))
        };
    }
    let guard = OwnedHandle(handle);
    if err == ERROR_ALREADY_EXISTS { Instance::AlreadyRunning } else { Instance::First(guard) }
}

/// Message loop with an alertable wait, so the service-state notifications (APCs queued by
/// `NotifyServiceStatusChangeW`) run while the tray is idle.
fn message_loop() -> i32 {
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid out-pointer; null hwnd = all messages of this thread.
        while unsafe { PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            if msg.message == WM_QUIT {
                return msg.wParam as i32;
            }
            // SAFETY: `msg` was filled by PeekMessageW.
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        // Sleeps until new input arrives or an APC ran (WAIT_IO_COMPLETION); both just loop.
        if wait_for_input_or_apc(INFINITE) == WAIT_FAILED {
            // Never spin: block for one message instead (notifications then wait for the next
            // alertable wait; the refresh timer covers them).
            // SAFETY: as above.
            match unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } {
                0 => return msg.wParam as i32, // WM_QUIT
                -1 => return 1,
                // SAFETY: `msg` was filled by GetMessageW.
                _ => unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                },
            }
        }
    }
}

/// The idle wait of the message loop: returns when input (posted or sent message, timer, shell
/// notification) is available for this thread — including input a `PeekMessageW` already saw but
/// left queued (`MWMO_INPUTAVAILABLE`) —, after queued APCs (service notifications) ran
/// (`WAIT_IO_COMPLETION`), or after `timeout_ms`.
pub(super) fn wait_for_input_or_apc(timeout_ms: u32) -> u32 {
    // SAFETY: no handles; waits only for this thread's message queue and APCs.
    unsafe {
        MsgWaitForMultipleObjectsEx(0, std::ptr::null(), timeout_ms, QS_ALLINPUT, MWMO_ALERTABLE | MWMO_INPUTAVAILABLE)
    }
}

/// Unrecoverable start-up error: tell the user (the tray has no console).
fn fatal(err: &WinError) {
    message_box(std::ptr::null_mut(), &format!("The tray application could not start.\n\n{err}"), MB_ICONERROR);
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

struct App {
    hinst: HINSTANCE,
    icons: Icons,
    snapshot: Snapshot,
    /// Last known bot username (kept while the service is stopped).
    bot_username: Option<String>,
    icon_added: bool,
    /// Icon + tooltip the shell currently displays (None = unknown → next sync modifies).
    shown: Option<(IconKind, String)>,
    add_retries: u32,
    /// "Start Service (admin)…" was launched; check the result on the follow-up refresh.
    pending_start: bool,
    /// Expiry (Unix seconds) of the pairing code the tray created and still watches; it also
    /// identifies the code in `PairingStatus` replies.
    pending_pairing: Option<i64>,
    last_menu_close: Option<Instant>,
}

impl App {
    fn desired(&self) -> (IconKind, String) {
        (model::icon_kind(&self.snapshot), model::tooltip_text(&self.snapshot))
    }
}

fn install_app(app: App) {
    let _ = APP.try_with(|cell| {
        if let Ok(mut slot) = cell.try_borrow_mut() {
            *slot = Some(app);
        }
    });
}

fn take_app() -> Option<App> {
    APP.try_with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.take())).ok().flatten()
}

/// Run `f` with the state borrowed. Returns None when there is no state or it is already borrowed
/// (re-entrant call). `f` must not call anything that dispatches window messages.
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.try_with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.as_mut().map(f))).ok().flatten()
}

fn is_icon_added() -> bool {
    with_app(|a| a.icon_added).unwrap_or(false)
}

/// Re-entrancy guard for menus, dialogs and refreshes.
struct BusyGuard;

impl BusyGuard {
    fn enter() -> Option<BusyGuard> {
        if BUSY.replace(true) { None } else { Some(BusyGuard) }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.set(false);
    }
}

/// Ask the window to close (→ WM_DESTROY removes the icon → WM_QUIT). Used for "Exit" and when
/// the service denies access.
fn request_exit(hwnd: HWND) {
    EXITING.set(true);
    // SAFETY: plain post to our own window.
    unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
}

// ---------------------------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------------------------

/// An icon handle; destroyed on drop unless it is a shared system icon.
struct IconHandle {
    handle: HICON,
    owned: bool,
}

impl IconHandle {
    fn load(hinst: HINSTANCE, kind: IconKind, (cx, cy): (i32, i32)) -> IconHandle {
        for &id in kind.resource_candidates() {
            // SAFETY: MAKEINTRESOURCE(id) is a valid resource name; not LR_SHARED → we own it.
            let h = unsafe { LoadImageW(hinst, id as usize as *const u16, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR) };
            if !h.is_null() {
                return IconHandle { handle: h as HICON, owned: true };
            }
        }
        // Resource missing (e.g. a build without resources): shared stock icon, never destroyed.
        // SAFETY: predefined system icon.
        IconHandle { handle: unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) }, owned: false }
    }
}

impl Drop for IconHandle {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_null() {
            // SAFETY: icon created by LoadImageW without LR_SHARED and not used afterwards
            // (the shell keeps its own copy).
            unsafe { DestroyIcon(self.handle) };
        }
    }
}

struct Icons {
    normal: IconHandle,
    stopped: IconHandle,
    size: (i32, i32),
}

impl Icons {
    fn load(hinst: HINSTANCE, size: (i32, i32)) -> Icons {
        Icons {
            normal: IconHandle::load(hinst, IconKind::Normal, size),
            stopped: IconHandle::load(hinst, IconKind::Stopped, size),
            size,
        }
    }

    fn get(&self, kind: IconKind) -> HICON {
        match kind {
            IconKind::Normal => self.normal.handle,
            IconKind::Stopped => self.stopped.handle,
        }
    }
}

/// Small-icon size for the DPI of the monitor showing our (hidden, primary-monitor) window,
/// falling back to `GetSystemMetrics(SM_CXSMICON/SM_CYSMICON)`.
fn small_icon_size(hwnd: HWND) -> (i32, i32) {
    // SAFETY: plain metric queries on our own window.
    unsafe {
        let dpi = GetDpiForWindow(hwnd);
        if dpi != 0 {
            let (cx, cy) = (GetSystemMetricsForDpi(SM_CXSMICON, dpi), GetSystemMetricsForDpi(SM_CYSMICON, dpi));
            if cx > 0 && cy > 0 {
                return (cx, cy);
            }
        }
        (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON))
    }
}

// ---------------------------------------------------------------------------------------------
// Notification icon
// ---------------------------------------------------------------------------------------------

fn base_icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: TRAY_UID, ..Default::default() }
}

/// Full icon state. NIF_SHOWTIP is repeated on every modify: with NOTIFYICON_VERSION_4 the
/// standard tooltip is otherwise suppressed.
fn icon_data(hwnd: HWND, app: &App, kind: IconKind, tip: &str) -> NOTIFYICONDATAW {
    let mut nid = base_icon_data(hwnd);
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = app.icons.get(kind);
    model::fill_wide(&mut nid.szTip, tip);
    nid
}

/// Add (or re-add) the icon with the current state and switch it to NOTIFYICON_VERSION_4.
/// Returns false when the shell refused (taskbar not ready).
fn add_icon(hwnd: HWND) -> bool {
    if EXITING.get() {
        return false;
    }
    let Some((mut nid, kind, tip)) = with_app(|a| {
        let (kind, tip) = a.desired();
        (icon_data(hwnd, a, kind, &tip), kind, tip)
    }) else {
        return false;
    };
    // NIM_ADD fails if the icon still exists (e.g. TaskbarCreated after a DPI change): modify it.
    // SAFETY: `nid` is fully initialised and lives across the calls.
    let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) != 0 || Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 };
    if ok {
        nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_SETVERSION, &nid) };
        // SAFETY: killing a timer that is not set just fails.
        unsafe { KillTimer(hwnd, TIMER_ADD_RETRY) };
    }
    with_app(|a| {
        a.icon_added = ok;
        a.shown = ok.then_some((kind, tip));
        if ok {
            a.add_retries = 0;
        }
    });
    ok
}

fn schedule_add_retry(hwnd: HWND) {
    if EXITING.get() {
        return;
    }
    let attempt = with_app(|a| {
        a.add_retries += 1;
        a.add_retries
    })
    .unwrap_or(u32::MAX);
    if attempt <= MAX_ADD_RETRIES {
        // SAFETY: our own window.
        unsafe { SetTimer(hwnd, TIMER_ADD_RETRY, ADD_RETRY_MS, None) };
    }
}

fn remove_icon(hwnd: HWND) {
    let added = with_app(|a| std::mem::replace(&mut a.icon_added, false)).unwrap_or(true);
    if added {
        let nid = base_icon_data(hwnd);
        // SAFETY: `nid` identifies our icon; failure (already gone) is harmless.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
    }
}

/// Bring the icon/tooltip in line with the current snapshot (only talks to the shell on change).
fn sync_icon(hwnd: HWND) {
    if EXITING.get() {
        return;
    }
    let Some((nid, kind, tip, added, changed)) = with_app(|a| {
        let (kind, tip) = a.desired();
        let changed = a.shown.as_ref().is_none_or(|(k, t)| *k != kind || *t != tip);
        (icon_data(hwnd, a, kind, &tip), kind, tip, a.icon_added, changed)
    }) else {
        return;
    };
    if !added {
        add_icon(hwnd); // retry timer / TaskbarCreated cover a failure
        return;
    }
    if !changed {
        return;
    }
    // SAFETY: fully initialised icon data.
    if unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) } != 0 {
        with_app(|a| a.shown = Some((kind, tip)));
    } else if !add_icon(hwnd) {
        // The icon vanished (Explorer restarting); TaskbarCreated or the retry timer re-adds it.
        schedule_add_retry(hwnd);
    }
}

/// Show a notification (balloon/toast). Falls back to a message box if the icon is not shown.
fn balloon(hwnd: HWND, title: &str, text: &str, flags: NOTIFY_ICON_INFOTIP_FLAGS) {
    if EXITING.get() {
        return;
    }
    let Some((mut nid, added, kind, tip)) = with_app(|a| {
        let (kind, tip) = a.desired();
        (icon_data(hwnd, a, kind, &tip), a.icon_added, kind, tip)
    }) else {
        return;
    };
    if added {
        nid.uFlags |= NIF_INFO;
        nid.dwInfoFlags = flags;
        model::fill_wide(&mut nid.szInfoTitle, title);
        model::fill_wide(&mut nid.szInfo, text);
        // SAFETY: fully initialised icon data.
        if unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) } != 0 {
            with_app(|a| a.shown = Some((kind, tip)));
            return;
        }
    }
    let style = match flags {
        NIIF_ERROR => MB_ICONERROR,
        NIIF_WARNING => MB_ICONWARNING,
        _ => MB_ICONINFORMATION,
    };
    message_box(hwnd, &format!("{title}\n\n{text}"), style);
}

fn message_box(hwnd: HWND, text: &str, style: MESSAGEBOX_STYLE) {
    message_box_with_caption(hwnd, text, model::APP_TITLE, style);
}

fn message_box_with_caption(hwnd: HWND, text: &str, caption: &str, style: MESSAGEBOX_STYLE) {
    let _pause = WatchPause::new(hwnd);
    let text = wide(text);
    let caption = wide(caption);
    // SAFETY: valid NUL-terminated strings; `hwnd` is our window or null.
    unsafe { MessageBoxW(hwnd, text.as_ptr(), caption.as_ptr(), MB_OK | MB_SETFOREGROUND | style) };
}

fn allow_message(hwnd: HWND, msg: u32) {
    if msg != 0 {
        // SAFETY: our own window; null = no extended result wanted.
        unsafe { ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, std::ptr::null_mut()) };
    }
}

/// Give back the pages touched by the menu/dialog code (the tray is idle almost all the time).
fn trim_working_set() {
    // SAFETY: pseudo-handle of the current process; (SIZE_T)-1 twice = trim.
    unsafe { SetProcessWorkingSetSizeEx(GetCurrentProcess(), usize::MAX, usize::MAX, 0) };
    LAST_TRIM.set(Some(std::time::Instant::now()));
}

/// Minimum spacing of the trims done after periodic refreshes (menus/dialogs always trim).
const PERIODIC_TRIM_MIN_GAP: std::time::Duration = std::time::Duration::from_secs(300);

thread_local! {
    /// Time of the last working-set trim (UI thread only).
    static LAST_TRIM: std::cell::Cell<Option<std::time::Instant>> = const { std::cell::Cell::new(None) };
}

/// After a periodic refresh: trim again if the last trim is at least five minutes old. The
/// refresh itself touches the IPC/SCM/RPC code paths; the safety refresh runs every 5 minutes, so
/// this never adds a wake-up and costs at most a few hundred soft faults per refresh.
fn trim_after_periodic_refresh() {
    let due = LAST_TRIM.get().is_none_or(|t| t.elapsed() >= PERIODIC_TRIM_MIN_GAP);
    if due {
        trim_working_set();
    }
}

// ---------------------------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------------------------

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match catch_unwind(AssertUnwindSafe(|| handle_message(hwnd, msg, wparam, lparam))) {
        Ok(Some(result)) => result,
        // Not handled, or a panic in a handler (state stays consistent: guards reset on unwind).
        _ => {
            // SAFETY: forwarding the original arguments.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

fn handle_message(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> Option<LRESULT> {
    match msg {
        WM_TRAY => {
            on_tray_event(hwnd, wparam, lparam);
            Some(0)
        }
        WM_TIMER => {
            on_timer(hwnd, wparam);
            Some(0)
        }
        WM_SVC_NOTIFY => {
            on_service_notify(hwnd, wparam);
            Some(0)
        }
        WM_ENDSESSION => {
            if wparam != 0 {
                // The session ends and the process will be terminated: just clean up the icon.
                EXITING.set(true);
                remove_icon(hwnd);
            }
            Some(0)
        }
        WM_DESTROY => {
            EXITING.set(true);
            watch::shutdown();
            // SAFETY: our own window/timers; killing an unset timer just fails.
            unsafe {
                KillTimer(hwnd, TIMER_REFRESH);
                KillTimer(hwnd, TIMER_FOLLOWUP);
                KillTimer(hwnd, TIMER_ADD_RETRY);
                KillTimer(hwnd, TIMER_NOTIFY_RETRY);
                KillTimer(hwnd, TIMER_PAIRING);
            }
            remove_icon(hwnd);
            // SAFETY: posts WM_QUIT to this thread.
            unsafe { PostQuitMessage(0) };
            Some(0)
        }
        _ if msg != 0 && msg == TASKBAR_CREATED.get() => {
            on_taskbar_created(hwnd);
            Some(0)
        }
        _ => None,
    }
}

fn on_tray_event(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let (event, id) = model::split_tray_lparam(lparam);
    if EXITING.get() || id != TRAY_UID || !model::opens_menu(event) {
        return;
    }
    show_menu(hwnd, model::anchor_from_wparam(wparam));
}

fn on_timer(hwnd: HWND, id: usize) {
    match id {
        TIMER_REFRESH => {
            // Skipped while a menu/dialog is open: it refreshes on its own.
            if let Some(_busy) = BusyGuard::enter() {
                refresh_and_watch(hwnd);
                trim_after_periodic_refresh();
            }
            // Self-healing: WM_TIMER is only generated once no posted message is queued, so a
            // notification still pending here lost its WM_SVC_NOTIFY (or arrived during this
            // refresh); without a post its watch would never be re-armed.
            repost_pending_notifications(hwnd);
        }
        TIMER_FOLLOWUP => {
            // SAFETY: one-shot: stop the periodic timer.
            unsafe { KillTimer(hwnd, TIMER_FOLLOWUP) };
            match BusyGuard::enter() {
                Some(_busy) => {
                    if refresh_and_watch(hwnd) {
                        check_pending_start(hwnd);
                    }
                }
                None => {
                    // SAFETY: our own window.
                    unsafe { SetTimer(hwnd, TIMER_FOLLOWUP, FOLLOWUP_BUSY_RETRY_MS, None) };
                }
            }
        }
        TIMER_ADD_RETRY => {
            // SAFETY: one-shot.
            unsafe { KillTimer(hwnd, TIMER_ADD_RETRY) };
            if !add_icon(hwnd) {
                schedule_add_retry(hwnd);
            }
        }
        TIMER_NOTIFY_RETRY => {
            // SAFETY: one-shot.
            unsafe { KillTimer(hwnd, TIMER_NOTIFY_RETRY) };
            repost_pending_notifications(hwnd);
        }
        TIMER_PAIRING => {
            // SAFETY: one-shot.
            unsafe { KillTimer(hwnd, TIMER_PAIRING) };
            match BusyGuard::enter() {
                Some(_busy) => check_pairing(hwnd),
                // A menu or dialog is open (e.g. the pairing dialog itself): look again later;
                // closing the pairing dialog checks at once.
                None => arm_pairing_check(hwnd),
            }
        }
        _ => {}
    }
}

/// Post [`WM_SVC_NOTIFY`] again for every service notification not handled yet (a duplicate
/// finds nothing to take and is ignored).
fn repost_pending_notifications(hwnd: HWND) {
    if EXITING.get() {
        return;
    }
    for target in WatchTarget::ALL {
        if watch::has_event(target) {
            // SAFETY: plain post to our own window.
            unsafe { PostMessageW(hwnd, WM_SVC_NOTIFY, target.index(), 0) };
        }
    }
}

/// Explorer (re)started or the DPI changed: reload icons at the new size and re-add the icon.
fn on_taskbar_created(hwnd: HWND) {
    if EXITING.get() {
        return;
    }
    let size = small_icon_size(hwnd);
    with_app(|a| {
        a.icon_added = false;
        a.shown = None;
        a.add_retries = 0;
        if a.icons.size != size {
            a.icons = Icons::load(a.hinst, size);
        }
    });
    if !add_icon(hwnd) {
        schedule_add_retry(hwnd);
    }
}

// ---------------------------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------------------------

/// [`refresh`], then bring the service watches and the refresh timer in line with the new
/// snapshot. Every refresh path uses this. Returns false when the service denied access.
fn refresh_and_watch(hwnd: HWND) -> bool {
    let ok = refresh(hwnd);
    if ok {
        sync_watches(hwnd, true);
    }
    ok
}

/// SCM query (+ IPC Status when running) → snapshot → icon/tooltip. Returns false when the
/// service denied access (exit has been requested).
///
/// The Tailscale state comes from a cheap SCM query of the `Tailscale` service (plus the
/// service's cached connection summary); the refresh never makes anything spawn tailscale.exe.
/// The IPC client checks the pipe server against the PID of this SCM query (no second query).
fn refresh(hwnd: HWND) -> bool {
    let (state, pid) = query_service(paths::SERVICE_NAME);
    let fetch = (state == ServiceState::Running).then(|| model::classify_status(guarded_status(pid)));
    match Snapshot::from_parts(state, pid, fetch) {
        Err(model::AccessDenied) => {
            request_exit(hwnd);
            false
        }
        Ok(snapshot) => {
            let snapshot = if snapshot.tailscale_wanted() {
                let (tailscale, _) = query_service(tailscale::SERVICE_NAME);
                snapshot.with_tailscale_service(tailscale)
            } else {
                snapshot // Tailscale Management disabled: not queried, not shown
            };
            with_app(|a| {
                if let Some(bot) = snapshot.status.as_ref().and_then(|s| s.bot_username.as_deref())
                    && model::dashboard_url(bot).is_some()
                {
                    a.bot_username = Some(bot.to_string());
                }
                a.snapshot = snapshot;
            });
            sync_icon(hwnd);
            true
        }
    }
}

/// `scm::query` (state + PID of a service) shielded against panics in another module.
fn query_service(name: &str) -> (ServiceState, u32) {
    catch_unwind(|| scm::query(name)).unwrap_or((ServiceState::Unknown, 0))
}

/// `ipc::request` shielded against panics in another module. Used for user actions: it queries
/// the SCM for the current service PID itself (the menu may have been open for a while).
fn guarded_request(req: &IpcRequest, timeout: Duration) -> Result<IpcResponse, String> {
    shielded(|| ipc::request(req, timeout))
}

/// IPC `Status` to the service process `pid` that the refresh's own SCM query just reported
/// (`ipc::request_to_pid`; saves the second SCM round trip of `ipc::request`).
fn guarded_status(pid: u32) -> Result<IpcResponse, String> {
    shielded(|| {
        if pid != 0 {
            ipc::request_to_pid(&IpcRequest::Status, STATUS_TIMEOUT, pid)
        } else {
            ipc::request(&IpcRequest::Status, STATUS_TIMEOUT) // running without a PID: let it ask the SCM
        }
    })
}

fn shielded(f: impl FnOnce() -> Result<IpcResponse, String>) -> Result<IpcResponse, String> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err("Internal error while contacting the Predator service.".into()))
}

/// Open/arm/close the service watches for the current snapshot and (re-)set the refresh timer:
/// after a refresh (`refreshed`) the next periodic refresh comes one full period later; otherwise
/// the timer is only touched when the period changes. Does nothing while the watches are paused.
fn sync_watches(hwnd: HWND, refreshed: bool) {
    if EXITING.get() || hwnd.is_null() {
        return;
    }
    let Some(wanted) = with_app(|a| WatchTarget::ALL.map(|t| model::should_watch(t, &a.snapshot))) else { return };
    let Some(watched) = watch::sync(wanted, Instant::now()) else { return }; // paused
    let Some(period) = with_app(|a| model::refresh_period(watched, &a.snapshot)) else { return };
    if !model::reschedule_timer(refreshed, TIMER_PERIOD.get(), period) {
        return;
    }
    // SAFETY: our own window; WM_TIMER (no callback). Replaces (and restarts) the timer with the
    // same id. The tolerance lets Windows batch the wake-up with other timers.
    let mut ok = unsafe { SetCoalescableTimer(hwnd, TIMER_REFRESH, period.interval_ms(), None, period.tolerance_ms()) };
    if ok == 0 {
        // SAFETY: as above, without coalescing.
        ok = unsafe { SetTimer(hwnd, TIMER_REFRESH, period.interval_ms(), None) };
    }
    if ok != 0 {
        TIMER_PERIOD.set(Some(period));
    }
}

/// A service watch reported a state change (posted by the notification callback).
fn on_service_notify(hwnd: HWND, index: WPARAM) {
    let Some(target) = WatchTarget::from_index(index) else { return };
    if EXITING.get() {
        return;
    }
    let Some(_busy) = BusyGuard::enter() else {
        // A menu, dialog or refresh is in progress: the event stays pending; look again shortly.
        // SAFETY: our own window.
        unsafe { SetTimer(hwnd, TIMER_NOTIFY_RETRY, FOLLOWUP_BUSY_RETRY_MS, None) };
        return;
    };
    let Some(event) = watch::take_event(target) else { return }; // already handled / watch closed
    let now = Instant::now();
    if !watch::accept(target, now) {
        sync_watches(hwnd, false); // no watch left (storm guard): switch the timer to polling
        return;
    }
    let Some(((state, pid), before)) =
        with_app(|a| (model::known_state(target, &a.snapshot), (a.snapshot.service.clone(), a.snapshot.pid)))
    else {
        return;
    };
    match model::notify_action(&event, &state, pid) {
        NotifyAction::Rearm => sync_watches(hwnd, false),
        NotifyAction::RefreshAndRearm => {
            if refresh_and_watch(hwnd)
                && with_app(|a| model::settle_refresh_wanted(&before.0, before.1, &a.snapshot)).unwrap_or(false)
            {
                arm_followup(hwnd); // the service just (re)started: show the settled Telegram state
            }
        }
        NotifyAction::Reopen => {
            watch::close(target, None);
            refresh_and_watch(hwnd);
        }
        NotifyAction::Close => {
            watch::close(target, Some(now));
            refresh_and_watch(hwnd);
        }
    }
}

/// Closes the service watches while a menu or dialog is open: notifications (APCs) are not
/// delivered inside modal loops, and an open service handle would keep a service that is being
/// uninstalled from being deleted. The last pause re-opens them; a new watch reports the current
/// state at once, so a change made meanwhile is not missed.
struct WatchPause(HWND);

impl WatchPause {
    fn new(hwnd: HWND) -> WatchPause {
        watch::pause();
        WatchPause(hwnd)
    }
}

impl Drop for WatchPause {
    fn drop(&mut self) {
        // While unwinding only the pause is ended; the next refresh re-opens the watches.
        if watch::resume() && !std::thread::panicking() {
            sync_watches(self.0, true);
        }
    }
}

fn arm_followup(hwnd: HWND) {
    // SAFETY: our own window.
    unsafe { SetTimer(hwnd, TIMER_FOLLOWUP, FOLLOWUP_MS, None) };
}

fn check_pending_start(hwnd: HWND) {
    let Some((pending, state)) = with_app(|a| (std::mem::take(&mut a.pending_start), a.snapshot.service.clone()))
    else {
        return;
    };
    if pending && matches!(state, ServiceState::Stopped | ServiceState::Paused | ServiceState::Unknown) {
        balloon(
            hwnd,
            "Predator service is not running",
            "The service did not start. Run \"predator-service.exe status\" in an elevated command prompt for details.",
            NIIF_WARNING,
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------------------------

/// Owned popup menu (submenus attached to it are destroyed with it).
struct PopupMenu(HMENU);

impl PopupMenu {
    fn build(entries: &[MenuEntry]) -> Result<PopupMenu, WinError> {
        // SAFETY: no preconditions.
        let menu = PopupMenu(unsafe { CreatePopupMenu() });
        if menu.0.is_null() {
            return Err(WinError::last("CreatePopupMenu"));
        }
        for entry in entries {
            match entry {
                MenuEntry::Separator => menu.append(MF_SEPARATOR, 0, None)?,
                MenuEntry::Item { id, label, enabled, checked } => {
                    let mut flags = MF_STRING;
                    if !enabled {
                        flags |= MF_GRAYED;
                    }
                    if *checked {
                        flags |= MF_CHECKED;
                    }
                    menu.append(flags, *id as usize, Some(label))?;
                }
                MenuEntry::Submenu { label, enabled, items } => {
                    let sub = PopupMenu::build(items)?;
                    let flags = if *enabled { MF_STRING | MF_POPUP } else { MF_STRING | MF_POPUP | MF_GRAYED };
                    menu.append(flags, sub.0 as usize, Some(label))?;
                    // Attached: now owned (and destroyed) by the parent menu.
                    std::mem::forget(sub);
                }
            }
        }
        Ok(menu)
    }

    fn append(&self, flags: MENU_ITEM_FLAGS, id: usize, label: Option<&str>) -> Result<(), WinError> {
        let text = label.map(|l| wide(&model::escape_menu_label(l)));
        let ptr = text.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
        // SAFETY: valid menu handle; the text is copied by the menu.
        if unsafe { AppendMenuW(self.0, flags, id, ptr) } == 0 {
            return Err(WinError::last("AppendMenuW"));
        }
        Ok(())
    }
}

impl Drop for PopupMenu {
    fn drop(&mut self) {
        // SAFETY: menu created by CreatePopupMenu and owned by us.
        unsafe { DestroyMenu(self.0) };
    }
}

fn show_menu(hwnd: HWND, anchor: (i32, i32)) {
    let Some(_busy) = BusyGuard::enter() else { return };
    let since_close = with_app(|a| a.last_menu_close.map(|t| t.elapsed())).flatten();
    if !model::menu_allowed(since_close) {
        return; // this click dismissed the previous menu
    }
    {
        let _pause = WatchPause::new(hwnd);
        menu_and_action(hwnd, anchor);
    }
    trim_working_set();
}

/// Refresh, show the menu and run the chosen action (watches paused, busy flag held).
fn menu_and_action(hwnd: HWND, anchor: (i32, i32)) {
    if !refresh_and_watch(hwnd) {
        return; // access denied → exiting
    }
    let Some(entries) = with_app(|a| model::build_menu(&a.snapshot, a.bot_username.as_deref())) else { return };
    let menu = match PopupMenu::build(&entries) {
        Ok(menu) => menu,
        Err(e) => {
            balloon(hwnd, "Could not show the menu", &e.to_string(), NIIF_ERROR);
            return;
        }
    };
    let (x, y) = menu_position(anchor);
    // SAFETY: plain metric query.
    let align = if unsafe { GetSystemMetrics(SM_MENUDROPALIGNMENT) } != 0 { TPM_RIGHTALIGN } else { TPM_LEFTALIGN };
    // SAFETY: valid menu/window of this thread. SetForegroundWindow + WM_NULL is the documented
    // fix so the menu closes when the user clicks elsewhere and the next menu works.
    let cmd = unsafe {
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenuEx(
            menu.0,
            TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY | align,
            x,
            y,
            hwnd,
            std::ptr::null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        cmd
    };
    drop(menu);
    with_app(|a| a.last_menu_close = Some(Instant::now()));

    if let Some(action) = u32::try_from(cmd).ok().and_then(MenuAction::from_id)
        && run_action(hwnd, action)
    {
        refresh_and_watch(hwnd); // refresh after every action
    }
}

/// The shell's anchor point; the cursor position if the shell gave none.
fn menu_position(anchor: (i32, i32)) -> (i32, i32) {
    if anchor != (0, 0) {
        return anchor;
    }
    let mut pt = POINT { x: 0, y: 0 };
    // SAFETY: valid out-pointer.
    if unsafe { GetCursorPos(&mut pt) } != 0 { (pt.x, pt.y) } else { anchor }
}

/// Execute a menu command. Returns false when the tray is exiting (no refresh wanted).
fn run_action(hwnd: HWND, action: MenuAction) -> bool {
    match action {
        MenuAction::OpenDashboard => open_dashboard(hwnd),
        MenuAction::ServiceStatus => show_status(hwnd),
        MenuAction::PairUser => pair_user(hwnd),
        MenuAction::TelegramUsers => show_users(hwnd),
        MenuAction::ToggleFeature(f) => toggle_feature(hwnd, f),
        MenuAction::RestartService => restart_service(hwnd),
        MenuAction::StartService => start_service(hwnd),
        MenuAction::Exit => {
            request_exit(hwnd); // never stops the service
            false
        }
    }
}

fn open_dashboard(hwnd: HWND) -> bool {
    let url = with_app(|a| a.bot_username.as_deref().and_then(model::dashboard_url)).flatten();
    let Some(url) = url else {
        balloon(
            hwnd,
            "Dashboard unavailable",
            "The bot username is not known yet. Make sure the service is running and connected to Telegram.",
            NIIF_WARNING,
        );
        return true;
    };
    if let Err(code) = shell_execute(hwnd, "open", &wide(&url), None, None, SW_SHOWNORMAL) {
        balloon(
            hwnd,
            "Could not open the dashboard",
            &format!("Opening {url} failed: {}", error_text(code)),
            NIIF_ERROR,
        );
    }
    true
}

/// "Service Status" dialog. User-initiated, so it may ask the service for a live Tailscale status
/// (see [`Snapshot::live_tailscale_query`]); otherwise the SCM-based line is shown.
fn show_status(hwnd: HWND) -> bool {
    let live_query = with_app(|a| a.snapshot.live_tailscale_query()).unwrap_or(false);
    let tailscale = if live_query {
        match model::classify_tailscale(guarded_request(&IpcRequest::TailscaleStatus, TAILSCALE_TIMEOUT)) {
            Ok(live) => Some(live),
            Err(model::AccessDenied) => {
                request_exit(hwnd);
                return false;
            }
        }
    } else {
        None
    };
    let Some(text) = with_app(|a| model::status_report(&a.snapshot, tailscale.as_ref(), crate::VERSION)) else {
        return true;
    };
    message_box_with_caption(hwnd, &text, STATUS_CAPTION, MB_ICONINFORMATION);
    true
}

/// "Pair Telegram User…": the service creates a one-time code (User role, 10 minutes) that is
/// shown here only. Afterwards the tray asks every few seconds whether it was used, until it is
/// paired, expires or becomes invalid.
fn pair_user(hwnd: HWND) -> bool {
    let started = match model::classify_pairing_start(guarded_request(&model::start_pairing_request(), ACTION_TIMEOUT))
    {
        PairingStart::Started(p) => p,
        PairingStart::Denied => {
            request_exit(hwnd);
            return false;
        }
        PairingStart::Failed(message) => {
            balloon(hwnd, "Could not start pairing", &message, NIIF_ERROR);
            return true;
        }
    };
    // A new code replaces an earlier one (in the service too): watch this one.
    with_app(|a| a.pending_pairing = Some(started.expires_unix));
    let (bot, first_account) =
        with_app(|a| (a.bot_username.clone(), a.snapshot.no_telegram_user())).unwrap_or((None, false));
    let now = crate::util::time::now_unix();
    let until = crate::util::time::fmt_time(started.expires_unix);
    let text = model::pairing_dialog_text(&started, bot.as_deref(), now, &until, first_account);
    message_box_with_caption(hwnd, &text, PAIRING_CAPTION, MB_ICONINFORMATION);
    // The account may have paired while the dialog was open.
    check_pairing(hwnd);
    true
}

/// (Re-)arm the one-shot pairing check.
fn arm_pairing_check(hwnd: HWND) {
    if EXITING.get() || with_app(|a| a.pending_pairing.is_none()).unwrap_or(true) {
        return;
    }
    let ms = u32::try_from(model::PAIRING_CHECK.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: our own window; replaces the timer with the same id.
    let ok = unsafe { SetCoalescableTimer(hwnd, TIMER_PAIRING, ms, None, PAIRING_CHECK_TOLERANCE_MS) };
    if ok == 0 {
        // SAFETY: as above, without coalescing.
        unsafe { SetTimer(hwnd, TIMER_PAIRING, ms, None) };
    }
}

/// Ask the service whether the tray's pairing code was used: show the result and stop, or keep
/// checking while the code is active. Called with the busy flag held.
fn check_pairing(hwnd: HWND) {
    // SAFETY: killing a timer that is not set just fails.
    unsafe { KillTimer(hwnd, TIMER_PAIRING) };
    if EXITING.get() {
        return;
    }
    let Some(ours) = with_app(|a| a.pending_pairing).flatten() else { return };
    let reply = guarded_request(&IpcRequest::PairingStatus, STATUS_TIMEOUT);
    let check = model::classify_pairing_check(reply, ours, crate::util::time::now_unix());
    match check {
        PairingCheck::KeepWaiting => {
            arm_pairing_check(hwnd);
            return;
        }
        PairingCheck::Denied => {
            with_app(|a| a.pending_pairing = None);
            request_exit(hwnd);
            return;
        }
        _ => {}
    }
    with_app(|a| {
        if a.pending_pairing == Some(ours) {
            a.pending_pairing = None;
        }
    });
    if let Some((title, text, kind)) = model::pairing_balloon(&check) {
        let flags = match kind {
            BalloonKind::Info => NIIF_INFO,
            BalloonKind::Warning => NIIF_WARNING,
        };
        balloon(hwnd, &title, &text, flags);
    }
}

/// "Telegram Users…": the accounts that can use the bot.
fn show_users(hwnd: HWND) -> bool {
    match model::classify_users(guarded_request(&IpcRequest::ListUsers, STATUS_TIMEOUT)) {
        UsersFetch::Users(users) => {
            let text = model::users_report(&users, &crate::util::time::fmt_date);
            message_box_with_caption(hwnd, &text, USERS_CAPTION, MB_ICONINFORMATION);
            true
        }
        UsersFetch::Denied => {
            request_exit(hwnd);
            false
        }
        UsersFetch::Failed(message) => {
            balloon(hwnd, "Could not read the Telegram users", &message, NIIF_ERROR);
            true
        }
    }
}

fn toggle_feature(hwnd: HWND, f: Feature) -> bool {
    let Some(current) = with_app(|a| a.snapshot.feature(f)).flatten() else {
        balloon(
            hwnd,
            &format!("{} not changed", f.label()),
            "The service is not responding, so the current setting is unknown. Try again in a moment.",
            NIIF_WARNING,
        );
        return true;
    };
    match model::classify_action(guarded_request(&model::set_feature_request(f, current), ACTION_TIMEOUT)) {
        ActionOutcome::Done => true,
        ActionOutcome::Denied => {
            request_exit(hwnd);
            false
        }
        ActionOutcome::Failed(message) => {
            let verb = if current { "disable" } else { "enable" };
            balloon(hwnd, &format!("Could not {verb} {}", f.label()), &message, NIIF_ERROR);
            true
        }
    }
}

fn restart_service(hwnd: HWND) -> bool {
    match model::classify_action(guarded_request(&IpcRequest::RestartService, ACTION_TIMEOUT)) {
        ActionOutcome::Done => {
            arm_followup(hwnd);
            true
        }
        ActionOutcome::Denied => {
            request_exit(hwnd);
            false
        }
        ActionOutcome::Failed(message) => {
            balloon(hwnd, "Could not restart the service", &message, NIIF_ERROR);
            true
        }
    }
}

/// `runas <exe dir>\predator-service.exe start` (UAC prompt).
fn start_service(hwnd: HWND) -> bool {
    let dir = paths::exe_dir();
    let exe = dir.join(paths::SERVICE_EXE);
    if !exe.is_file() {
        balloon(
            hwnd,
            "Could not start the service",
            &format!("{} was not found in {}.", paths::SERVICE_EXE, dir.display()),
            NIIF_ERROR,
        );
        return true;
    }
    match shell_execute(hwnd, "runas", &wide_path(&exe), Some("start"), Some(&dir), SW_HIDE) {
        Ok(()) => {
            with_app(|a| a.pending_start = true);
            arm_followup(hwnd);
        }
        Err(ERROR_CANCELLED) => {} // the user declined the UAC prompt
        Err(code) => balloon(hwnd, "Could not start the service", &error_text(code), NIIF_ERROR),
    }
    true
}

/// `ShellExecuteW`; Err = Win32 error code (or the legacy SE_ERR code when none was set).
fn shell_execute(
    hwnd: HWND,
    verb: &str,
    file: &[u16],
    params: Option<&str>,
    dir: Option<&Path>,
    show: SHOW_WINDOW_CMD,
) -> Result<(), u32> {
    ensure_com();
    let verb = wide(verb);
    let params = params.map(wide);
    let dir = dir.map(wide_path);
    // SAFETY: all strings are NUL-terminated and outlive the call; `hwnd` is our window.
    let result = unsafe {
        SetLastError(0);
        ShellExecuteW(
            hwnd,
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
            dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            show,
        )
    } as isize;
    if result > 32 {
        return Ok(());
    }
    match last_error() {
        0 => Err(result.max(0) as u32),
        e => Err(e),
    }
}

fn error_text(code: u32) -> String {
    format!("{} (error {code})", error_message(code))
}

/// ShellExecute may use COM shell extensions: initialise an STA once, on first use.
fn ensure_com() {
    if COM_INITIALIZED.get() {
        return;
    }
    // SAFETY: reserved pointer must be null; this thread pumps messages (STA requirement).
    let hr = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    if hr >= 0 {
        COM_INITIALIZED.set(true);
    }
}

fn com_uninitialize() {
    if COM_INITIALIZED.replace(false) {
        // SAFETY: balances the successful CoInitializeEx on this thread.
        unsafe { CoUninitialize() };
    }
}
