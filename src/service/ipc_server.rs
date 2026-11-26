//! Named-pipe IPC server for the tray (`ipc-server` thread).
//!
//! * The accept loop always owns at least one pipe instance (the first one is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`), so no other process can take over the name while we run.
//! * One request line (≤ 4 KiB) per connection, read on the accept thread with a short timeout.
//!   Quick requests (status, feature switch, settings reload, pairing codes, the Telegram user
//!   list) are answered right there — no thread per request. Only requests that start processes
//!   (Tailscale status, restart) run on a short-lived worker (max 2 at once).
//! * Pairing: `StartPairing` returns the one-time code to the caller only (it is shown on the
//!   PC); it is never logged or sent to Telegram. `RemoveUser` revokes an account at once and
//!   tells every remaining Telegram user. Codes for Admin accounts and `RemoveUser` need
//!   LocalSystem or an elevated administrator: the owner SID alone (which every unelevated
//!   process of the owner's session has, not only the tray) may pair User accounts only.
//! * Every request is authorized by impersonating the client (identification level):
//!   LocalSystem, the configured owner SID, or an elevated member of Administrators. Account
//!   names (an LSA lookup) are resolved only for log lines, and cached.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, INFINITE, OpenThreadToken, WaitForMultipleObjects};

use super::pipe::{IoFailure, MAX_REQUEST_BYTES, read_line, wait_for_close, write_all};
use super::runtime::{Shared, catch};
use super::slot::tailscale_summary;
use super::winsec::SecurityDescriptor;
use crate::config::{MAX_AUTHORIZED_USERS, UserRole};
use crate::context::AppContext;
use crate::features::Feature;
use crate::ipc::{FeatureState, IpcRequest, IpcResponse, ServiceStatusInfo, UserInfo};
use crate::notify::NotificationKind;
use crate::sys::SystemActions;
use crate::util::StopFlag;
use crate::util::win::{OwnedEvent, OwnedHandle, WinError, last_error, wide};
use crate::{log_debug, log_error, log_info, log_warn};

/// Pipe DACL. Network logons are denied first; SYSTEM and Administrators get full access;
/// interactive users get read/write *without* FILE_CREATE_PIPE_INSTANCE (0x12019b =
/// FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA), so they can talk
/// to the service but cannot create competing server instances of our pipe name.
pub(crate) const PIPE_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// Concurrent workers for slow requests.
const MAX_WORKERS: usize = 2;
const MAX_INSTANCES: u32 = 8;
const BUFFER_SIZE: u32 = 4096;
/// The client writes its request right after connecting; a silent client cannot hold the accept
/// thread for longer than this.
const READ_TIMEOUT: Duration = Duration::from_millis(1500);
/// Writing one reply line (normally completes at once: it fits the pipe buffer).
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// After the reply, wait this long for the client to read it and close (inline / worker).
const INLINE_CLOSE_WAIT: Duration = Duration::from_millis(500);
const WORKER_CLOSE_WAIT: Duration = Duration::from_secs(2);
/// Account-name cache (SID → `DOMAIN\name`).
const NAME_CACHE_TTL: Duration = Duration::from_secs(3600);
const NAME_CACHE_MAX: usize = 16;

/// Who is on the other end of a pipe connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientIdentity {
    pub sid: String,
    pub elevated: bool,
    /// Enabled member of BUILTIN\Administrators.
    pub admin: bool,
    pub pid: u32,
}

impl ClientIdentity {
    /// `DOMAIN\name` (cached LSA lookup), or the SID when it cannot be resolved.
    pub fn display(&self) -> String {
        account_display(&self.sid)
    }
}

type NameEntry = (String, Option<String>, Instant);
static NAME_CACHE: Mutex<Vec<NameEntry>> = Mutex::new(Vec::new());

/// Cached `DOMAIN\name` for a string SID (falls back to the SID itself).
pub(crate) fn account_display(sid: &str) -> String {
    cached_name(sid, Instant::now(), super::winsec::account_name_of).unwrap_or_else(|| sid.to_string())
}

/// Look `sid` up in [`NAME_CACHE`] (entries expire after [`NAME_CACHE_TTL`]; at most
/// [`NAME_CACHE_MAX`] are kept, the oldest is evicted). Failed lookups are cached too.
fn cached_name(sid: &str, now: Instant, lookup: impl FnOnce(&str) -> Option<String>) -> Option<String> {
    let mut cache = NAME_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|(_, _, at)| now.saturating_duration_since(*at) < NAME_CACHE_TTL);
    if let Some((_, name, _)) = cache.iter().find(|(s, _, _)| s.eq_ignore_ascii_case(sid)) {
        return name.clone();
    }
    // Resolve outside the lock: LookupAccountSidW can block on a domain controller.
    drop(cache);
    let name = lookup(sid);
    let mut cache = NAME_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if !cache.iter().any(|(s, _, _)| s.eq_ignore_ascii_case(sid)) {
        if cache.len() >= NAME_CACHE_MAX
            && let Some(oldest) = cache.iter().enumerate().min_by_key(|(_, (_, _, at))| *at).map(|(i, _)| i)
        {
            cache.swap_remove(oldest);
        }
        cache.push((sid.to_string(), name.clone(), now));
    }
    name
}

/// Authorization decision for one IPC request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthDecision {
    Allowed(&'static str),
    Denied(String),
}

/// Pure authorization rule: LocalSystem, the configured owner SID, or an elevated administrator.
pub(crate) fn authorize(sid: &str, elevated: bool, admin_member: bool, owner_sid: Option<&str>) -> AuthDecision {
    let sid = sid.trim();
    if sid.eq_ignore_ascii_case("S-1-5-18") {
        return AuthDecision::Allowed("LocalSystem");
    }
    if let Some(owner) = owner_sid.map(str::trim).filter(|o| !o.is_empty())
        && owner.eq_ignore_ascii_case(sid)
    {
        return AuthDecision::Allowed("owner");
    }
    if elevated && admin_member {
        return AuthDecision::Allowed("elevated administrator");
    }
    AuthDecision::Denied(
        "This Windows account is not allowed to control Predator (only the configured owner and elevated \
         administrators are)."
            .into(),
    )
}

/// Requests that start processes or wait on them: served on a worker thread.
pub(crate) fn is_slow_request(req: &IpcRequest) -> bool {
    matches!(req, IpcRequest::TailscaleStatus | IpcRequest::RestartService)
}

/// Handles one parsed request from an identified client.
pub(crate) trait RequestHandler: Send + Sync {
    fn handle(&self, client: &ClientIdentity, req: IpcRequest) -> IpcResponse;

    /// Whether `req` may take long and must be answered on a worker thread instead of the
    /// accept thread.
    fn needs_worker(&self, _client: &ClientIdentity, req: &IpcRequest) -> bool {
        is_slow_request(req)
    }
}

// ---------------------------------------------------------------------------------------------
// Server transport
// ---------------------------------------------------------------------------------------------

struct PipeFactory {
    name: Vec<u16>,
    _sd: SecurityDescriptor,
    sa: SECURITY_ATTRIBUTES,
}

// SAFETY: the SECURITY_ATTRIBUTES only points into the immutable descriptor owned by `_sd`.
unsafe impl Send for PipeFactory {}

impl PipeFactory {
    fn new(pipe_name: &str, sddl: &str) -> Result<Self, String> {
        let sd = SecurityDescriptor::from_sddl(sddl)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr(),
            bInheritHandle: 0,
        };
        Ok(Self { name: wide(pipe_name), _sd: sd, sa })
    }

    fn create(&self, first: bool) -> Result<OwnedHandle, u32> {
        let open_mode =
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: NUL-terminated name; `sa` points to a valid descriptor kept alive by `self`.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                pipe_mode,
                MAX_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                &self.sa,
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() { Err(last_error()) } else { Ok(OwnedHandle(h)) }
    }
}

enum Accept {
    Connected,
    Stopped,
    Failed(u32),
}

/// Overlapped ConnectNamedPipe that also wakes up when `stop` is signalled.
fn accept(pipe: &OwnedHandle, ev: &OwnedEvent, stop: &StopFlag) -> Accept {
    // SAFETY: zeroed OVERLAPPED is the documented initial state.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.raw();
    // SAFETY: valid pipe handle and OVERLAPPED that outlives the operation (we wait below).
    if unsafe { ConnectNamedPipe(pipe.raw(), &mut ov) } != 0 {
        return Accept::Connected;
    }
    match last_error() {
        ERROR_PIPE_CONNECTED => return Accept::Connected,
        ERROR_IO_PENDING => {}
        e => return Accept::Failed(e),
    }
    let handles: [HANDLE; 2] = [ev.raw(), stop.event_handle()];
    // SAFETY: two valid event handles.
    let w = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
    let mut n = 0u32;
    if w == WAIT_OBJECT_0 {
        // SAFETY: the operation completed.
        if unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut n, 0) } == 0 {
            return Accept::Failed(last_error());
        }
        return Accept::Connected;
    }
    // Stop requested (or wait failure): cancel and wait until the kernel releases `ov`.
    // SAFETY: cancelling our own pending I/O on a valid handle.
    unsafe {
        CancelIoEx(pipe.raw(), &ov);
        GetOverlappedResult(pipe.raw(), &ov, &mut n, 1);
    }
    if stop.is_stopped() { Accept::Stopped } else { Accept::Failed(last_error()) }
}

/// Decrements the active-worker counter when dropped.
struct WorkerSlot(Arc<AtomicUsize>);

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve `pipe_name` until `stop`. Returns Err only if the pipe cannot be created at all
/// (e.g. the name is owned by another process).
pub(crate) fn serve(pipe_name: &str, stop: Arc<StopFlag>, handler: Arc<dyn RequestHandler>) -> Result<(), String> {
    serve_with_sddl(pipe_name, PIPE_SDDL, stop, handler)
}

/// [`serve`] with an explicit pipe DACL (tests use one that lets the test user create instances).
fn serve_with_sddl(
    pipe_name: &str,
    sddl: &str,
    stop: Arc<StopFlag>,
    handler: Arc<dyn RequestHandler>,
) -> Result<(), String> {
    let factory = PipeFactory::new(pipe_name, sddl)?;
    let mut listening = factory.create(true).map_err(|e| match e {
        ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY => {
            format!("the IPC pipe {pipe_name} is already in use by another process (is another instance running?)")
        }
        e => format!("cannot create the IPC pipe: {}", WinError::new(e, "CreateNamedPipeW")),
    })?;
    let accept_ev = OwnedEvent::new_manual().map_err(String::from)?;
    // Reused for every inline request (ReadFile/WriteFile reset it when an operation starts).
    let io_ev = OwnedEvent::new_manual().map_err(String::from)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut consecutive_failures = 0u32;
    let mut warned_single_instance = false;
    loop {
        if stop.is_stopped() {
            return Ok(());
        }
        match accept(&listening, &accept_ev, &stop) {
            Accept::Stopped => return Ok(()),
            Accept::Failed(e) => {
                consecutive_failures += 1;
                log_debug!("IPC accept failed: {}", WinError::new(e, "ConnectNamedPipe"));
                // SAFETY: valid pipe handle; resets the instance for the next client.
                unsafe { DisconnectNamedPipe(listening.raw()) };
                if consecutive_failures > 3 && stop.sleep(Duration::from_secs(1)) {
                    return Ok(());
                }
                continue;
            }
            Accept::Connected => consecutive_failures = 0,
        }
        // Create the next listening instance *before* handing this one off, so we never own
        // zero instances of the name.
        let conn = match factory.create(false) {
            Ok(next) => std::mem::replace(&mut listening, next),
            Err(e) => {
                // E.g. a non-elevated console session: the pipe DACL withholds
                // FILE_CREATE_PIPE_INSTANCE from interactive users. Serve on the single instance.
                if !warned_single_instance {
                    log_warn!(
                        "cannot create another IPC pipe instance ({}); serving every request inline",
                        WinError::new(e, "CreateNamedPipeW")
                    );
                    warned_single_instance = true;
                }
                if let Some((client, req)) = serve_inline(listening.raw(), &io_ev, handler.as_ref()) {
                    let response = dispatch(handler.as_ref(), &client, req);
                    send_reply(listening.raw(), &io_ev, &response, WORKER_CLOSE_WAIT);
                }
                // SAFETY: valid pipe handle; resets the instance for the next client.
                unsafe { DisconnectNamedPipe(listening.raw()) };
                continue;
            }
        };
        let Some((client, req)) = serve_inline(conn.raw(), &io_ev, handler.as_ref()) else {
            // SAFETY: valid pipe handle; closed when `conn` drops.
            unsafe { DisconnectNamedPipe(conn.raw()) };
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_WORKERS {
            active.fetch_sub(1, Ordering::SeqCst);
            log_debug!("IPC: too many slow requests at once; refusing one");
            let busy = IpcResponse::Error { message: "The Predator service is busy; please try again.".into() };
            send_reply(conn.raw(), &io_ev, &busy, INLINE_CLOSE_WAIT);
            // SAFETY: valid pipe handle; closed when `conn` drops.
            unsafe { DisconnectNamedPipe(conn.raw()) };
            continue;
        }
        let slot = WorkerSlot(active.clone());
        let h = handler.clone();
        let spawned = std::thread::Builder::new().name("ipc-worker".into()).stack_size(512 * 1024).spawn(move || {
            let _slot = slot;
            let response = dispatch(h.as_ref(), &client, req);
            match OwnedEvent::new_manual() {
                Ok(ev) => send_reply(conn.raw(), &ev, &response, WORKER_CLOSE_WAIT),
                Err(e) => log_warn!("IPC: {e}"),
            }
            // SAFETY: valid pipe handle owned by `conn`, closed right after.
            unsafe { DisconnectNamedPipe(conn.raw()) };
            drop(conn);
        });
        if let Err(e) = spawned {
            // The closure (and with it the connection and the worker slot) was dropped.
            log_warn!("cannot start an IPC worker thread: {e}");
        }
    }
}

/// Read one request on the calling (accept) thread, identify the client and answer quick
/// requests right away. Returns the request when it must be answered on a worker instead.
fn serve_inline(pipe: HANDLE, ev: &OwnedEvent, handler: &dyn RequestHandler) -> Option<(ClientIdentity, IpcRequest)> {
    let response = match read_line(pipe, ev, MAX_REQUEST_BYTES, Instant::now() + READ_TIMEOUT) {
        Ok(line) => match identify_client(pipe) {
            Err(e) => {
                log_warn!("IPC: cannot identify the client: {e}");
                IpcResponse::Denied { reason: "The caller could not be identified.".into() }
            }
            Ok(client) => match serde_json::from_slice::<IpcRequest>(&line) {
                Ok(req) => {
                    if catch(|| handler.needs_worker(&client, &req)).unwrap_or(false) {
                        return Some((client, req));
                    }
                    dispatch(handler, &client, req)
                }
                Err(e) => IpcResponse::Error { message: format!("Invalid request: {e}") },
            },
        },
        Err(IoFailure::TooLong) => IpcResponse::Error { message: "Request too large".into() },
        Err(e) => {
            log_debug!("IPC: connection dropped before a request arrived: {e:?}");
            return None;
        }
    };
    send_reply(pipe, ev, &response, INLINE_CLOSE_WAIT);
    None
}

/// Run the handler, converting a panic into an error reply.
fn dispatch(handler: &dyn RequestHandler, client: &ClientIdentity, req: IpcRequest) -> IpcResponse {
    catch(|| handler.handle(client, req)).unwrap_or_else(|e| {
        log_error!("IPC handler crashed: {e}");
        IpcResponse::Error { message: "Internal error in the Predator service".into() }
    })
}

/// Write one reply line, then wait (bounded) for the client to read it and close.
fn send_reply(pipe: HANDLE, ev: &OwnedEvent, response: &IpcResponse, close_wait: Duration) {
    let mut out = serde_json::to_vec(response)
        .unwrap_or_else(|_| br#"{"type":"error","message":"cannot encode the reply"}"#.to_vec());
    out.push(b'\n');
    if write_all(pipe, ev, &out, Instant::now() + WRITE_TIMEOUT).is_ok() {
        // DisconnectNamedPipe discards unread data: let the client read the reply and close first.
        wait_for_close(pipe, ev, close_wait);
    }
}

/// Identify the client through identification-level impersonation (after data was read).
/// Purely local token queries — no LSA round trip.
fn identify_client(pipe: HANDLE) -> Result<ClientIdentity, String> {
    let mut pid = 0u32;
    // SAFETY: valid pipe handle, valid out-parameter.
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    // SAFETY: valid server pipe handle from which a message has been read.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(WinError::last("ImpersonateNamedPipeClient").to_string());
    }
    let mut token: HANDLE = null_mut();
    // OpenAsSelf = TRUE: an identification-level token cannot be used to open objects itself.
    // SAFETY: pseudo handle of the current thread; `token` receives a handle we own.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0;
    let open_err = last_error();
    // SAFETY: always drop the impersonation before doing anything else.
    if unsafe { RevertToSelf() } == 0 {
        let _ = OwnedHandle(if opened { token } else { null_mut() });
        return Err(WinError::last("RevertToSelf").to_string());
    }
    if !opened {
        return Err(WinError::new(open_err, "OpenThreadToken").to_string());
    }
    let token = OwnedHandle(token);
    let (sid, elevated, admin) = client_token_facts(token.raw())?;
    Ok(ClientIdentity { sid, elevated, admin, pid })
}

/// User SID, elevation and enabled Administrators membership of an impersonation token.
fn client_token_facts(token: HANDLE) -> Result<(String, bool, bool), String> {
    let mut needed = 0u32;
    // SAFETY: size query with a null buffer.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
    if needed < size_of::<TOKEN_USER>() as u32 {
        return Err(WinError::last("GetTokenInformation(TokenUser)").to_string());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let len = (buf.len() * 8) as u32;
    // SAFETY: `buf` is `len` bytes, 8-byte aligned.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut needed) } == 0 {
        return Err(WinError::last("GetTokenInformation(TokenUser)").to_string());
    }
    // SAFETY: the buffer holds a TOKEN_USER whose SID points into the same buffer.
    let user_sid = unsafe { (*(buf.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: valid SID inside `buf`.
    let sid = unsafe { crate::sys::sysinfo::sid_to_string(user_sid) }
        .ok_or_else(|| "Cannot convert the caller's SID".to_string())?;

    let mut elev = TOKEN_ELEVATION::default();
    let mut ret = 0u32;
    // SAFETY: `elev` has exactly the size passed.
    let elevated = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elev as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    } != 0
        && elev.TokenIsElevated != 0;

    Ok((sid, elevated, is_admin_member(token)))
}

/// Enabled member of BUILTIN\Administrators (`token` must be an impersonation token).
fn is_admin_member(token: HANDLE) -> bool {
    let mut admins = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = admins.len() as u32;
    // SAFETY: SECURITY_MAX_SID_SIZE bytes are enough for any well-known SID.
    let created =
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, null_mut(), admins.as_mut_ptr().cast(), &mut size) };
    if created == 0 {
        return false;
    }
    let mut member = 0i32;
    // SAFETY: impersonation token with TOKEN_QUERY and a valid SID buffer.
    let ok = unsafe { CheckTokenMembership(token, admins.as_mut_ptr().cast(), &mut member) };
    ok != 0 && member != 0
}

// ---------------------------------------------------------------------------------------------
// Service request handling
// ---------------------------------------------------------------------------------------------

/// The runtime's IPC thread body: serve the real pipe, retrying while the name is busy.
pub(crate) fn run(sh: &Arc<Shared>) {
    let ctx = &sh.ctx;
    let handler: Arc<dyn RequestHandler> = Arc::new(ServiceIpc { sh: sh.clone() });
    let mut delay = Duration::from_secs(2);
    loop {
        match serve(crate::paths::PIPE_NAME, ctx.stop.clone(), handler.clone()) {
            Ok(()) => return,
            Err(e) if ctx.console_mode => {
                log_warn!("tray IPC disabled in console mode: {e}");
                return;
            }
            Err(e) => {
                log_error!("IPC server: {e}; retrying in {} s", delay.as_secs());
                if ctx.stop.sleep(delay) {
                    return;
                }
                delay = (delay * 2).min(Duration::from_secs(300));
            }
        }
    }
}

struct ServiceIpc {
    sh: Arc<Shared>,
}

fn request_name(req: &IpcRequest) -> &'static str {
    match req {
        IpcRequest::Status => "status",
        IpcRequest::SetFeature { .. } => "set_feature",
        IpcRequest::TailscaleStatus => "tailscale_status",
        IpcRequest::RestartService => "restart_service",
        IpcRequest::ReloadSettings => "reload_settings",
        IpcRequest::StartPairing { .. } => "start_pairing",
        IpcRequest::PairingStatus => "pairing_status",
        IpcRequest::CancelPairing => "cancel_pairing",
        IpcRequest::ListUsers => "list_users",
        IpcRequest::RemoveUser { .. } => "remove_user",
    }
}

impl ServiceIpc {
    fn authorize_client(&self, client: &ClientIdentity) -> AuthDecision {
        let owner_sid = self.sh.ctx.settings.get().owner_windows_sid;
        authorize(&client.sid, client.elevated, client.admin, owner_sid.as_deref())
    }
}

impl RequestHandler for ServiceIpc {
    fn handle(&self, client: &ClientIdentity, req: IpcRequest) -> IpcResponse {
        let name = request_name(&req);
        match self.authorize_client(client) {
            AuthDecision::Denied(reason) => {
                // Anyone signed in interactively can reach the pipe: rate-limited per caller.
                crate::logging::security_untrusted(
                    &format!("ipc:{}", client.sid),
                    &format!(
                        "IPC request '{name}' denied for {} ({}, pid {}, elevated {})",
                        client.display(),
                        client.sid,
                        client.pid,
                        client.elevated
                    ),
                );
                return IpcResponse::Denied { reason };
            }
            AuthDecision::Allowed(why) => {
                log_debug!("IPC '{name}' from {} (pid {}) allowed: {why}", client.sid, client.pid)
            }
        }
        match req {
            IpcRequest::Status => IpcResponse::Status(build_status(&self.sh)),
            IpcRequest::SetFeature { feature, enabled } => set_feature(&self.sh, client, &feature, enabled),
            IpcRequest::TailscaleStatus => {
                if !self.sh.ctx.settings.feature(Feature::TailscaleManagement) {
                    return IpcResponse::Tailscale {
                        summary: "Tailscale Management is disabled".into(),
                        connected: false,
                    };
                }
                let st = self.sh.sys.tailscale_status();
                IpcResponse::Tailscale { summary: tailscale_summary(&st), connected: st.connected }
            }
            IpcRequest::RestartService => restart_service(&self.sh, client),
            IpcRequest::ReloadSettings => reload_settings(&self.sh, client),
            IpcRequest::StartPairing { .. }
            | IpcRequest::PairingStatus
            | IpcRequest::CancelPairing
            | IpcRequest::ListUsers
            | IpcRequest::RemoveUser { .. } => {
                users_request(&self.sh.ctx, &Caller::of(client), req, crate::util::time::now_unix())
            }
        }
    }

    /// Denials are answered inline, so an unauthorized caller can never occupy a worker.
    fn needs_worker(&self, client: &ClientIdentity, req: &IpcRequest) -> bool {
        is_slow_request(req) && matches!(self.authorize_client(client), AuthDecision::Allowed(_))
    }
}

// ---------------------------------------------------------------------------------------------
// Pairing and Telegram users
// ---------------------------------------------------------------------------------------------

/// The IPC client as named in log lines and notices.
pub(crate) struct Caller {
    /// `DOMAIN\name` (or the SID when it cannot be resolved).
    pub name: String,
    pub sid: String,
    /// LocalSystem or an elevated administrator (see [`is_privileged`]).
    pub privileged: bool,
}

impl Caller {
    fn of(client: &ClientIdentity) -> Self {
        Self {
            name: client.display(),
            sid: client.sid.clone(),
            privileged: is_privileged(&client.sid, client.elevated, client.admin),
        }
    }
}

/// LocalSystem or an elevated member of Administrators. The configured owner SID alone is not:
/// every process in the owner's session (not only the tray) runs with it, unelevated.
pub(crate) fn is_privileged(sid: &str, elevated: bool, admin_member: bool) -> bool {
    sid.trim().eq_ignore_ascii_case("S-1-5-18") || (elevated && admin_member)
}

/// Creating an Admin code needs [`Caller::privileged`] (an Admin can remove other accounts).
pub(crate) const ADMIN_CODE_NEEDS_ELEVATION: &str = "Only an elevated administrator can create a pairing code for an \
                                                     Admin account. Run this from an elevated (Administrator) \
                                                     prompt, or pair the account as a User.";
/// Removing an account needs [`Caller::privileged`] (or an Admin account in Telegram).
pub(crate) const REMOVE_NEEDS_ELEVATION: &str = "Removing a Telegram account needs an elevated (Administrator) \
                                                 prompt on this PC, or an Admin account in Telegram (/users).";

/// Refuse a user-management request of a caller that is authorized but not privileged
/// (rate-limited security log; `Error`, not `Denied`, because the caller may use the pipe).
fn refuse_unprivileged(caller: &Caller, what: &str, message: &str) -> IpcResponse {
    crate::logging::security_untrusted(
        &format!("ipc:{}", caller.sid),
        &format!("IPC {what} refused for {} ({}): not elevated", caller.name, caller.sid),
    );
    IpcResponse::Error { message: message.to_string() }
}

/// The pairing and Telegram-user requests of an authorized caller.
pub(crate) fn users_request(ctx: &AppContext, caller: &Caller, req: IpcRequest, now: i64) -> IpcResponse {
    match req {
        IpcRequest::StartPairing { ttl_secs, admin } => start_pairing(ctx, caller, ttl_secs, admin, now),
        IpcRequest::PairingStatus => pairing_state(ctx, now),
        IpcRequest::CancelPairing => cancel_pairing(ctx, caller, now),
        IpcRequest::ListUsers => list_users(ctx),
        IpcRequest::RemoveUser { id } => remove_user(ctx, caller, id),
        other => IpcResponse::Error { message: format!("'{}' is not a pairing request", request_name(&other)) },
    }
}

/// `StartPairing`: create (replace) the one-time code. The code goes back to the caller only —
/// it is neither logged nor sent to Telegram, and nothing is queued. Admin codes need a
/// privileged caller.
pub(crate) fn start_pairing(ctx: &AppContext, caller: &Caller, ttl_secs: u64, admin: bool, now: i64) -> IpcResponse {
    if admin && !caller.privileged {
        return refuse_unprivileged(caller, "start_pairing (Admin code)", ADMIN_CODE_NEEDS_ELEVATION);
    }
    let s = ctx.settings.get();
    if s.authorized_users.len() >= MAX_AUTHORIZED_USERS {
        return IpcResponse::Error {
            message: format!(
                "{MAX_AUTHORIZED_USERS} Telegram accounts are paired already (the maximum). Remove one first \
                 (send /users to the bot from an admin account)."
            ),
        };
    }
    let role = if admin { UserRole::Admin } else { UserRole::User };
    let code = ctx.pairing.start(role, ttl_secs, &caller.name, now);
    let valid = code.expires_unix.saturating_sub(now).max(0);
    // the first account of an empty list always becomes an admin (SettingsStore::add_user)
    let role_text = if s.authorized_users.is_empty() { "Admin (first account)" } else { role.label() };
    // (security() also writes the main log)
    crate::logging::security(&format!(
        "Telegram pairing code created via local IPC (tray or CLI) by {} ({}): role {role_text}, valid {valid} s",
        caller.name, caller.sid
    ));
    IpcResponse::Pairing {
        code: code.code,
        expires_unix: code.expires_unix,
        bot_username: s.bot_username.filter(|b| crate::ipc::bot_username(b).is_some()),
    }
}

/// `PairingStatus` (the code itself is never part of it).
pub(crate) fn pairing_state(ctx: &AppContext, now: i64) -> IpcResponse {
    let st = ctx.pairing.status(now);
    let (paired_name, paired_id, paired_unix) = match st.last_paired {
        Some((u, at)) => (Some(u.label()), Some(u.id), Some(at)),
        None => (None, None, None),
    };
    IpcResponse::PairingState { active: st.active, expires_unix: st.expires_unix, paired_name, paired_id, paired_unix }
}

/// `CancelPairing`: forget the active code (if any).
pub(crate) fn cancel_pairing(ctx: &AppContext, caller: &Caller, now: i64) -> IpcResponse {
    let was_active = ctx.pairing.status(now).active;
    ctx.pairing.cancel();
    if !was_active {
        return IpcResponse::Ok { message: "No pairing code was active".into() };
    }
    crate::logging::security(&format!(
        "Telegram pairing code cancelled via local IPC (tray or CLI) by {} ({})",
        caller.name, caller.sid
    ));
    IpcResponse::Ok { message: "Pairing cancelled".into() }
}

/// `ListUsers`.
pub(crate) fn list_users(ctx: &AppContext) -> IpcResponse {
    IpcResponse::Users { users: ctx.settings.authorized_users().iter().map(UserInfo::from_user).collect() }
}

/// `RemoveUser`: revoke at once (the bot checks the list on every update) and tell every
/// remaining user. The last admin cannot be removed; the caller must be privileged.
pub(crate) fn remove_user(ctx: &AppContext, caller: &Caller, id: i64) -> IpcResponse {
    if !caller.privileged {
        return refuse_unprivileged(caller, &format!("remove_user {id}"), REMOVE_NEEDS_ELEVATION);
    }
    let removed = match ctx.settings.remove_user(id) {
        Ok(u) => u,
        Err(e) => {
            log_info!("removing Telegram user {id} via local IPC refused: {e}");
            return IpcResponse::Error { message: e };
        }
    };
    crate::logging::security(&format!(
        "Telegram user {} ({}) removed via local IPC (tray or CLI) by {} ({})",
        removed.id,
        removed.label(),
        caller.name,
        caller.sid
    ));
    let lines = vec![
        ("Name".to_string(), removed.label()),
        ("User ID".to_string(), removed.id.to_string()),
        ("Role".to_string(), removed.role.label().to_string()),
        ("Removed by".to_string(), format!("tray/CLI on this PC (user {})", caller.name)),
    ];
    if let Err(e) = catch(|| ctx.emit_notice(NotificationKind::Security, "🗑", "TELEGRAM USER REMOVED", &lines, &[]))
        .and_then(|r| r.map_err(|e| e.to_string()))
    {
        log_error!("could not queue the user-removed notification: {e}");
    }
    IpcResponse::Ok { message: format!("Removed {} (id {}).", removed.label(), removed.id) }
}

/// Which settings differ (names only — used for log lines).
pub(crate) fn changed_settings(before: &crate::config::Settings, after: &crate::config::Settings) -> Vec<&'static str> {
    let mut v = Vec::new();
    if before.authorized_users != after.authorized_users {
        v.push("Telegram users");
    }
    if before.owner_windows_sid != after.owner_windows_sid {
        v.push("tray owner SID");
    }
    if before.bot_username != after.bot_username {
        v.push("bot username");
    }
    if before.features != after.features {
        v.push("features");
    }
    if before.dry_run != after.dry_run
        || before.stale_command_secs != after.stale_command_secs
        || before.confirm_timeout_secs != after.confirm_timeout_secs
        || before.lifecycle_notifications != after.lifecycle_notifications
        || before.auto_clean_chat != after.auto_clean_chat
        || before.chat_clean_after_secs != after.chat_clean_after_secs
        || before.version != after.version
    {
        v.push("options");
    }
    v
}

/// `ReloadSettings`: the CLI edited settings.json while the service runs.
fn reload_settings(sh: &Shared, client: &ClientIdentity) -> IpcResponse {
    let before = sh.ctx.settings.get();
    match sh.ctx.settings.reload_from_disk() {
        Ok(true) => {
            let after = sh.ctx.settings.get();
            let changed = changed_settings(&before, &after).join(", ");
            log_info!("settings.json reloaded ({changed} changed)");
            crate::logging::security(&format!(
                "settings.json reloaded at the request of {} ({}): {changed} changed",
                client.display(),
                client.sid
            ));
            if before.dry_run != after.dry_run {
                log_warn!("the dry_run setting changed; it takes effect when the service restarts");
            }
            // A newly configured owner can receive the queued notifications right away.
            sh.kick_sender();
            IpcResponse::Ok { message: "Settings reloaded by the running service".into() }
        }
        Ok(false) => IpcResponse::Ok { message: "Settings unchanged".into() },
        Err(e) => IpcResponse::Error { message: format!("Cannot reload settings.json: {e}") },
    }
}

pub(crate) fn build_status(sh: &Shared) -> ServiceStatusInfo {
    let ctx = &sh.ctx;
    let s = ctx.settings.get();
    let (private_bytes, working_set_bytes) = catch(crate::sys::sysinfo::process_memory).unwrap_or((0, 0));
    ServiceStatusInfo {
        version: crate::VERSION.to_string(),
        pid: std::process::id(),
        uptime_secs: (crate::util::time::now_unix() - ctx.started_unix).max(0) as u64,
        telegram: sh.telegram_label(),
        bot_username: s.bot_username.clone(),
        // at least one Telegram account is paired (the field name predates multi-user support)
        owner_configured: !s.authorized_users.is_empty(),
        features: Feature::ALL
            .iter()
            .map(|f| FeatureState { key: f.key().into(), label: f.label().into(), enabled: s.features.is_enabled(*f) })
            .collect(),
        security_monitor: ctx.status.security().label(),
        ssh_monitor: ctx.status.ssh().label(),
        queued_notifications: ctx.queue.len(),
        private_bytes,
        working_set_bytes,
        tailscale: sh.sys.cached_tailscale(3600).map(|t| tailscale_summary(&t)),
        dry_run: sh.sys.is_dry_run(),
        transport: sh.tg.current().map(|(api, _)| api.transport_name().to_string()),
    }
}

fn set_feature(sh: &Shared, client: &ClientIdentity, key: &str, enabled: bool) -> IpcResponse {
    let Some(feature) = Feature::from_key(key) else {
        let keys: Vec<&str> = Feature::ALL.iter().map(|f| f.key()).collect();
        return IpcResponse::Error { message: format!("Unknown feature '{key}'. Valid keys: {}", keys.join(", ")) };
    };
    let state = if enabled { "Enabled" } else { "Disabled" };
    match sh.ctx.settings.set_feature(feature, enabled) {
        Ok(true) => {
            let who = client.display();
            crate::logging::security(&format!(
                "feature {} {} via local IPC (tray or CLI) by {who} ({})",
                feature.key(),
                state.to_lowercase(),
                client.sid
            ));
            let lines = vec![
                ("Feature".to_string(), feature.label().to_string()),
                ("State".to_string(), state.to_string()),
                ("Changed by".to_string(), format!("tray/CLI on this PC (user {who})")),
            ];
            let now = crate::util::time::now_unix();
            if let Err(e) = catch(|| sh.ctx.emit_system("⚙️", "FEATURE CHANGED", &lines, now, None)) {
                log_error!("cannot render the feature-change notification: {e}");
            }
            IpcResponse::Ok { message: format!("{} {}", feature.label(), state.to_lowercase()) }
        }
        Ok(false) => IpcResponse::Ok { message: format!("{} already {}", feature.label(), state.to_lowercase()) },
        Err(e) => IpcResponse::Error { message: format!("Cannot save settings: {e}") },
    }
}

fn restart_service(sh: &Shared, client: &ClientIdentity) -> IpcResponse {
    if !sh.is_service {
        return IpcResponse::Error {
            message: "Restart is only available when Predator runs as a Windows service".into(),
        };
    }
    match spawn_restart_helper(&sh.ctx.paths.root) {
        Ok(()) => {
            log_info!("service restart requested via the tray by {}", client.display());
            crate::logging::security(&format!(
                "service restart requested via local IPC (tray or CLI) by {} ({})",
                client.display(),
                client.sid
            ));
            IpcResponse::Ok { message: "The Predator service is restarting".into() }
        }
        Err(e) => IpcResponse::Error { message: e },
    }
}

/// Start `predator-service.exe restart-helper` detached (it survives our own stop).
pub(crate) fn spawn_restart_helper(data_root: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS};
    let exe = std::env::current_exe().map_err(|e| format!("Cannot locate predator-service.exe: {e}"))?;
    // No other spawn may run while handles are inheritable (crate-wide spawn lock).
    let _spawn = crate::sys::process::SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::process::Command::new(exe)
        .arg("restart-helper")
        .arg("--data-dir")
        .arg(data_root)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Cannot start the restart helper: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::pipe::{ServerCheck, client_request};

    const OWNER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    #[test]
    fn authorization_rules() {
        assert_eq!(authorize("S-1-5-18", false, false, None), AuthDecision::Allowed("LocalSystem"));
        assert_eq!(authorize(OWNER, false, false, Some(OWNER)), AuthDecision::Allowed("owner"));
        assert_eq!(authorize(&OWNER.to_lowercase(), false, false, Some(OWNER)), AuthDecision::Allowed("owner"));
        assert_eq!(authorize(OWNER, true, true, None), AuthDecision::Allowed("elevated administrator"));
        // filtered (non-elevated) admin token, other user, unset owner
        assert!(matches!(authorize(OWNER, false, true, None), AuthDecision::Denied(_)));
        assert!(matches!(authorize(OWNER, true, false, None), AuthDecision::Denied(_)));
        assert!(matches!(authorize("S-1-5-21-9-9-9-1002", false, false, Some(OWNER)), AuthDecision::Denied(_)));
        assert!(matches!(authorize(OWNER, false, false, Some("")), AuthDecision::Denied(_)));
        assert!(matches!(authorize("S-1-5-19", false, false, Some(OWNER)), AuthDecision::Denied(_)));
    }

    /// Answers with the caller's identity and the authorization decision for "no owner"; other
    /// requests answer with the name of the thread that served them.
    struct Echo;

    impl RequestHandler for Echo {
        fn handle(&self, client: &ClientIdentity, req: IpcRequest) -> IpcResponse {
            match req {
                IpcRequest::Status => IpcResponse::Ok { message: client.sid.clone() },
                IpcRequest::SetFeature { .. } => match authorize(&client.sid, client.elevated, client.admin, None) {
                    AuthDecision::Allowed(w) => IpcResponse::Ok { message: w.into() },
                    AuthDecision::Denied(r) => IpcResponse::Denied { reason: r },
                },
                _ => IpcResponse::Ok { message: std::thread::current().name().unwrap_or("?").to_string() },
            }
        }
    }

    #[test]
    fn slow_requests_only_use_workers() {
        assert!(is_slow_request(&IpcRequest::TailscaleStatus));
        assert!(is_slow_request(&IpcRequest::RestartService));
        assert!(!is_slow_request(&IpcRequest::Status));
        assert!(!is_slow_request(&IpcRequest::ReloadSettings));
        assert!(!is_slow_request(&IpcRequest::SetFeature { feature: "x".into(), enabled: true }));
    }

    #[test]
    fn account_names_are_cached() {
        use std::sync::atomic::AtomicU32;
        let sid = format!("S-1-5-21-9-9-{}-1001", std::process::id());
        let calls = AtomicU32::new(0);
        let lookup = |_: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some("PC\\someone".to_string())
        };
        let t0 = Instant::now();
        assert_eq!(cached_name(&sid, t0, lookup).as_deref(), Some("PC\\someone"));
        for i in 0..10 {
            let again = cached_name(&sid.to_lowercase(), t0 + Duration::from_secs(i), |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            });
            assert_eq!(again.as_deref(), Some("PC\\someone"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one LSA lookup per SID");
        // expired entries are looked up again; failures are cached as well
        let late = t0 + NAME_CACHE_TTL + Duration::from_secs(1);
        assert_eq!(cached_name(&sid, late, |_| None), None);
        assert_eq!(cached_name(&sid, late, |_| Some("x".into())), None);
        // bounded
        for i in 0..(NAME_CACHE_MAX + 5) {
            cached_name(&format!("S-1-5-21-8-8-8-{i}"), late, |_| None);
        }
        assert!(NAME_CACHE.lock().unwrap().len() <= NAME_CACHE_MAX);
    }

    #[test]
    fn changed_settings_names() {
        use crate::config::{AuthorizedUser, Settings};
        let a = Settings::default();
        let mut b = a.clone();
        assert!(changed_settings(&a, &b).is_empty());
        b.authorized_users = vec![AuthorizedUser::new(123456789, "alice", UserRole::Admin, 0)];
        b.owner_windows_sid = Some("S-1-5-21-1-2-3-1001".into());
        b.features.set(Feature::SshMonitoring, false);
        b.confirm_timeout_secs = 30;
        assert_eq!(changed_settings(&a, &b), vec!["Telegram users", "tray owner SID", "features", "options"]);
    }

    const T0: i64 = 1_800_000_000;
    const ALICE: i64 = 123_456_789;
    const BOB: i64 = 987_654_321;

    /// An elevated administrator.
    fn caller() -> Caller {
        Caller { name: r"MY-PC\alice".into(), sid: "S-1-5-21-1-2-3-1001".into(), privileged: true }
    }

    /// The configured owner without elevation (e.g. the tray, or any other process of that session).
    fn owner_unelevated() -> Caller {
        Caller { privileged: false, ..caller() }
    }

    fn started(r: IpcResponse) -> (String, i64, Option<String>) {
        match r {
            IpcResponse::Pairing { code, expires_unix, bot_username } => (code, expires_unix, bot_username),
            other => panic!("unexpected {other:?}"),
        }
    }

    type State = (bool, Option<i64>, Option<String>, Option<i64>, Option<i64>);

    fn state(r: IpcResponse) -> State {
        match r {
            IpcResponse::PairingState { active, expires_unix, paired_name, paired_id, paired_unix } => {
                (active, expires_unix, paired_name, paired_id, paired_unix)
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn pairing_requests_are_quick() {
        for r in [
            IpcRequest::StartPairing { ttl_secs: 600, admin: true },
            IpcRequest::PairingStatus,
            IpcRequest::CancelPairing,
            IpcRequest::ListUsers,
            IpcRequest::RemoveUser { id: 1 },
        ] {
            assert!(!is_slow_request(&r), "{r:?}");
        }
        assert_eq!(request_name(&IpcRequest::StartPairing { ttl_secs: 1, admin: false }), "start_pairing");
        assert_eq!(request_name(&IpcRequest::RemoveUser { id: 1 }), "remove_user");
    }

    #[test]
    fn start_status_and_redeem() {
        let ctx = AppContext::for_tests();
        assert_eq!(state(pairing_state(&ctx, T0)), (false, None, None, None, None));
        let (code, expires, bot) = started(start_pairing(&ctx, &caller(), 600, false, T0));
        assert!(code.len() == 8 && code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        assert_eq!(expires, T0 + 600);
        assert_eq!(bot, None, "no bot username known yet");
        assert_eq!(state(pairing_state(&ctx, T0 + 1)), (true, Some(T0 + 600), None, None, None));
        // the bot redeems the code and records the new account
        assert_eq!(ctx.pairing.redeem(&code, ALICE, T0 + 2), Ok(UserRole::User));
        ctx.pairing.record_paired(crate::config::AuthorizedUser::new(ALICE, "@alice", UserRole::User, T0 + 2));
        assert_eq!(
            state(pairing_state(&ctx, T0 + 3)),
            (false, None, Some("@alice".into()), Some(ALICE), Some(T0 + 2)),
            "single use; the result is reported"
        );
        // a new code clears the result of the previous one
        started(start_pairing(&ctx, &caller(), 600, false, T0 + 4));
        assert_eq!(state(pairing_state(&ctx, T0 + 5)).2, None);
        // expiry
        assert!(!state(pairing_state(&ctx, T0 + 4 + 600)).0);
    }

    #[test]
    fn start_pairing_role_ttl_and_bot() {
        let ctx = AppContext::for_tests();
        let (code, expires, _) = started(start_pairing(&ctx, &caller(), 5, true, T0));
        assert_eq!(expires, T0 + 60, "clamped to the shortest lifetime");
        assert_eq!(ctx.pairing.redeem(&code, ALICE, T0 + 1), Ok(UserRole::Admin));
        let (_, expires, _) = started(start_pairing(&ctx, &caller(), 99_999, false, T0));
        assert_eq!(expires, T0 + 3600, "clamped to the longest lifetime");

        ctx.settings.update(|s| s.bot_username = Some("ExampleBot".into())).unwrap();
        assert_eq!(started(start_pairing(&ctx, &caller(), 600, false, T0)).2.as_deref(), Some("ExampleBot"));
        ctx.settings.update(|s| s.bot_username = Some("not a bot/../x".into())).unwrap();
        assert_eq!(started(start_pairing(&ctx, &caller(), 600, false, T0)).2, None);
    }

    #[test]
    fn privileged_callers() {
        assert!(is_privileged("S-1-5-18", false, false), "LocalSystem");
        assert!(is_privileged(" s-1-5-18 ", false, false));
        assert!(is_privileged(OWNER, true, true), "elevated administrator");
        assert!(!is_privileged(OWNER, false, true), "filtered admin token");
        assert!(!is_privileged(OWNER, true, false), "elevated, not an administrator");
        assert!(!is_privileged(OWNER, false, false), "the owner SID alone");
        let client = ClientIdentity { sid: OWNER.into(), elevated: false, admin: true, pid: 1 };
        assert!(!Caller::of(&client).privileged);
        assert!(Caller::of(&ClientIdentity { elevated: true, ..client }).privileged);
    }

    /// The unelevated owner (the tray, or any process of that session) may pair User accounts,
    /// list them and cancel, but neither create Admin codes nor remove accounts.
    #[test]
    fn unelevated_owner_cannot_grant_or_revoke_admin_power() {
        let ctx = AppContext::for_tests();
        let owner = owner_unelevated();
        match users_request(&ctx, &owner, IpcRequest::StartPairing { ttl_secs: 600, admin: true }, T0) {
            IpcResponse::Error { message } => assert_eq!(message, ADMIN_CODE_NEEDS_ELEVATION),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!state(pairing_state(&ctx, T0)).0, "no code was created");
        let (code, ..) =
            started(users_request(&ctx, &owner, IpcRequest::StartPairing { ttl_secs: 600, admin: false }, T0));
        assert_eq!(ctx.pairing.redeem(&code, BOB, T0 + 1), Ok(UserRole::User));
        let bob = crate::config::AuthorizedUser::new(BOB, "bob", UserRole::User, T0);
        ctx.settings.add_user(bob).unwrap();
        assert!(matches!(users_request(&ctx, &owner, IpcRequest::ListUsers, T0), IpcResponse::Users { .. }));
        match users_request(&ctx, &owner, IpcRequest::RemoveUser { id: BOB }, T0) {
            IpcResponse::Error { message } => assert_eq!(message, REMOVE_NEEDS_ELEVATION),
            other => panic!("unexpected {other:?}"),
        }
        assert!(ctx.settings.is_authorized(BOB), "not removed");
        assert!(ctx.queue.is_empty(), "nobody is told about a refused removal");
        assert!(matches!(
            users_request(&ctx, &caller(), IpcRequest::RemoveUser { id: BOB }, T0),
            IpcResponse::Ok { .. }
        ));
        assert!(!ctx.settings.is_authorized(BOB));
    }

    #[test]
    fn start_pairing_refused_when_the_list_is_full() {
        let ctx = AppContext::for_tests();
        for i in 1..MAX_AUTHORIZED_USERS {
            let u = crate::config::AuthorizedUser::new(ALICE + i as i64, "u", UserRole::User, T0);
            assert_eq!(ctx.settings.add_user(u), Ok(crate::config::AddUserOutcome::Added));
        }
        assert_eq!(ctx.settings.authorized_users().len(), MAX_AUTHORIZED_USERS);
        match start_pairing(&ctx, &caller(), 600, false, T0) {
            IpcResponse::Error { message } => assert!(message.contains("maximum"), "{message}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!state(pairing_state(&ctx, T0)).0, "no code was created");
    }

    #[test]
    fn cancel() {
        let ctx = AppContext::for_tests();
        assert_eq!(
            cancel_pairing(&ctx, &caller(), T0),
            IpcResponse::Ok { message: "No pairing code was active".into() }
        );
        let (code, ..) = started(start_pairing(&ctx, &caller(), 600, false, T0));
        assert_eq!(cancel_pairing(&ctx, &caller(), T0 + 1), IpcResponse::Ok { message: "Pairing cancelled".into() });
        assert!(!state(pairing_state(&ctx, T0 + 1)).0);
        assert_eq!(ctx.pairing.redeem(&code, ALICE, T0 + 2), Err(crate::pairing::RedeemError::NoActiveCode));
        // an expired code is nothing to cancel
        started(start_pairing(&ctx, &caller(), 60, false, T0));
        let inactive = IpcResponse::Ok { message: "No pairing code was active".into() };
        assert_eq!(cancel_pairing(&ctx, &caller(), T0 + 60), inactive);
        assert!(matches!(users_request(&ctx, &caller(), IpcRequest::Status, T0), IpcResponse::Error { .. }));
    }

    /// The pairing and user requests over a real pipe, served by the service's own dispatcher
    /// (`users_request`): both directions of the wire format, end to end.
    struct UsersOnly(Arc<AppContext>);

    impl RequestHandler for UsersOnly {
        fn handle(&self, client: &ClientIdentity, req: IpcRequest) -> IpcResponse {
            let caller = Caller { name: r"MY-PC\alice".into(), sid: client.sid.clone(), privileged: true };
            users_request(&self.0, &caller, req, crate::util::time::now_unix())
        }
    }

    #[test]
    fn pairing_over_a_real_pipe() {
        let name = format!(r"\\.\pipe\PredatorRemoteController-test-{}", crate::util::rand::hex(6));
        let ctx = AppContext::for_tests();
        let stop = Arc::new(StopFlag::new());
        let (n2, s2, c2) = (name.clone(), stop.clone(), ctx.clone());
        let server = std::thread::Builder::new()
            .name("ipc-test-users".into())
            .spawn(move || serve(&n2, s2, Arc::new(UsersOnly(c2))))
            .unwrap();
        let me = std::process::id();
        let ask = |req: &IpcRequest| {
            let mut last = String::new();
            for _ in 0..100 {
                match client_request(&name, req, Duration::from_secs(5), ServerCheck::Pid(me)) {
                    Ok(r) => return r,
                    Err(e) => last = e,
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("no reply: {last}");
        };
        let (code, expires, _) = started(ask(&IpcRequest::StartPairing { ttl_secs: 600, admin: false }));
        assert!(crate::pairing::normalize_code(&code).is_some(), "{code}");
        let (active, exp, ..) = state(ask(&IpcRequest::PairingStatus));
        assert!(active);
        assert_eq!(exp, Some(expires));
        // the bot redeems it (as it would after `/pair CODE`)
        let now = crate::util::time::now_unix();
        assert_eq!(ctx.pairing.redeem(&code, BOB, now), Ok(UserRole::User));
        let bob = crate::config::AuthorizedUser::new(BOB, "bob", UserRole::User, now);
        ctx.settings.add_user(bob.clone()).unwrap();
        ctx.pairing.record_paired(bob);
        let (active, _, paired_name, paired_id, _) = state(ask(&IpcRequest::PairingStatus));
        assert!(!active);
        assert_eq!((paired_name.as_deref(), paired_id), (Some("bob"), Some(BOB)));
        let IpcResponse::Users { users } = ask(&IpcRequest::ListUsers) else { panic!("users") };
        assert_eq!(users.iter().map(|u| u.id).collect::<Vec<_>>(), vec![crate::context::TEST_USER_ID, BOB]);
        assert!(matches!(ask(&IpcRequest::RemoveUser { id: BOB }), IpcResponse::Ok { .. }));
        assert!(!ctx.settings.is_authorized(BOB));
        assert!(matches!(ask(&IpcRequest::CancelPairing), IpcResponse::Ok { .. }));
        stop.stop();
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn list_and_remove_users() {
        use crate::context::TEST_USER_ID;
        let ctx = AppContext::for_tests();
        let IpcResponse::Users { users } = list_users(&ctx) else { panic!("users") };
        assert_eq!(
            users,
            vec![UserInfo { id: TEST_USER_ID, name: "owner".into(), role: "admin".into(), added_unix: 0 }]
        );
        // the last admin stays
        match remove_user(&ctx, &caller(), TEST_USER_ID) {
            IpcResponse::Error { message } => assert_eq!(message, crate::config::LAST_ADMIN_ERROR),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(remove_user(&ctx, &caller(), BOB), IpcResponse::Error { .. }), "unknown id");
        assert!(ctx.queue.is_empty(), "refusals notify nobody");

        let bob = crate::config::AuthorizedUser::new(BOB, "bob", UserRole::User, T0);
        ctx.settings.add_user(bob).unwrap();
        let IpcResponse::Users { users } = list_users(&ctx) else { panic!("users") };
        assert_eq!(users.len(), 2);
        assert_eq!((users[1].id, users[1].role.as_str(), users[1].added_unix), (BOB, "user", T0));

        assert_eq!(remove_user(&ctx, &caller(), BOB), IpcResponse::Ok { message: format!("Removed bob (id {BOB}).") });
        assert!(!ctx.settings.is_authorized(BOB), "revoked at once");
        let n = ctx.queue.front().expect("removal notice queued");
        assert_eq!(n.kind, NotificationKind::Security);
        assert!(n.html.contains("TELEGRAM USER REMOVED") && n.html.contains("bob"), "{}", n.html);
        assert!(n.html.contains(r"MY-PC\alice"), "names the PC account: {}", n.html);
        assert!(n.delivered_to.is_empty(), "every remaining user is told");
    }

    /// Production layout (the service, as LocalSystem, can create further instances): quick
    /// requests inline on the accept thread, slow ones on a bounded worker.
    #[test]
    fn slow_requests_run_on_workers() {
        let facts = crate::service::winsec::current_process_facts().unwrap();
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})", facts.sid);
        let name = format!(r"\\.\pipe\PredatorRemoteController-test-{}", crate::util::rand::hex(6));
        let stop = Arc::new(StopFlag::new());
        let (n2, s2) = (name.clone(), stop.clone());
        let server = std::thread::Builder::new()
            .name("ipc-test-accept".into())
            .spawn(move || serve_with_sddl(&n2, &sddl, s2, Arc::new(Echo)))
            .unwrap();
        let me = std::process::id();
        let on = |req: &IpcRequest| {
            let mut last = String::new();
            for _ in 0..50 {
                match client_request(&name, req, Duration::from_secs(5), ServerCheck::Pid(me)) {
                    Ok(IpcResponse::Ok { message }) => return message,
                    Ok(other) => panic!("unexpected {other:?}"),
                    Err(e) => last = e,
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("no reply: {last}");
        };
        assert_eq!(on(&IpcRequest::ReloadSettings), "ipc-test-accept");
        assert_eq!(on(&IpcRequest::TailscaleStatus), "ipc-worker");
        assert_eq!(on(&IpcRequest::RestartService), "ipc-worker");
        assert_eq!(on(&IpcRequest::Status), facts.sid);
        stop.stop();
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn end_to_end_over_a_real_pipe() {
        let name = format!(r"\\.\pipe\PredatorRemoteController-test-{}", crate::util::rand::hex(6));
        let stop = Arc::new(StopFlag::new());
        let (n2, s2) = (name.clone(), stop.clone());
        let server = std::thread::Builder::new()
            .name("ipc-test-server".into())
            .spawn(move || serve(&n2, s2, Arc::new(Echo)))
            .unwrap();
        let me = std::process::id();
        let mut reply = Err(String::new());
        for _ in 0..50 {
            reply = client_request(&name, &IpcRequest::Status, Duration::from_secs(3), ServerCheck::Pid(me));
            if reply.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let sid = match reply.unwrap() {
            IpcResponse::Ok { message } => message,
            other => panic!("unexpected {other:?}"),
        };
        let facts = crate::service::winsec::current_process_facts().unwrap();
        assert_eq!(sid, facts.sid);

        // several sequential requests on fresh connections
        for _ in 0..5 {
            let r = client_request(
                &name,
                &IpcRequest::SetFeature { feature: "x".into(), enabled: true },
                Duration::from_secs(3),
                ServerCheck::Pid(me),
            )
            .unwrap();
            if facts.elevated && facts.admin {
                assert!(matches!(r, IpcResponse::Ok { .. }));
            } else {
                assert!(matches!(r, IpcResponse::Denied { .. }));
            }
        }

        // Quick requests are answered on the accept thread, slow ones on a worker. A non-elevated
        // test process cannot create a second pipe instance (the DACL gives interactive users no
        // FILE_CREATE_PIPE_INSTANCE), and then everything is served inline on the one instance.
        let multi_instance = facts.sid == "S-1-5-18" || (facts.elevated && facts.admin);
        let slow_thread = if multi_instance { "ipc-worker" } else { "ipc-test-server" };
        let on = |req: IpcRequest| match client_request(&name, &req, Duration::from_secs(5), ServerCheck::Pid(me)) {
            Ok(IpcResponse::Ok { message }) => message,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(on(IpcRequest::ReloadSettings), "ipc-test-server");
        assert_eq!(on(IpcRequest::TailscaleStatus), slow_thread);
        assert_eq!(on(IpcRequest::RestartService), slow_thread);

        // a client that connects and never sends anything does not block the server for long
        let silent = {
            use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_WRITE_DATA, OPEN_EXISTING};
            let w = wide(&name);
            let mut handle = None;
            // the single instance may briefly be between DisconnectNamedPipe and the next accept
            for _ in 0..100 {
                // SAFETY: NUL-terminated name; the handle is owned by OwnedHandle.
                let h = unsafe {
                    CreateFileW(
                        w.as_ptr(),
                        windows_sys::Win32::Foundation::GENERIC_READ | FILE_WRITE_DATA,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        null_mut(),
                    )
                };
                if h != INVALID_HANDLE_VALUE && !h.is_null() {
                    handle = Some(OwnedHandle(h));
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            handle.expect("cannot connect the silent client")
        };
        let t = Instant::now();
        let sid2 = match client_request(&name, &IpcRequest::Status, Duration::from_secs(5), ServerCheck::Pid(me)) {
            Ok(IpcResponse::Ok { message }) => message,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(sid2, facts.sid);
        assert!(t.elapsed() < READ_TIMEOUT + Duration::from_secs(2), "{:?}", t.elapsed());
        drop(silent);

        // wrong expected server pid → refused before sending anything
        let err =
            client_request(&name, &IpcRequest::Status, Duration::from_secs(3), ServerCheck::Pid(me + 1)).unwrap_err();
        assert!(err.contains("not the Predator service"));

        // a second server cannot take over the name
        let dup = serve(&name, Arc::new(StopFlag::new()), Arc::new(Echo));
        assert!(dup.unwrap_err().contains("already in use"));

        stop.stop();
        assert!(server.join().unwrap().is_ok());
    }
}
