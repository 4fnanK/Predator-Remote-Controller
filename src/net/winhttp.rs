//! Synchronous WinHTTP client (OS TLS, system proxy, keep-alive pooling, HTTP/2 when offered).
//!
//! Since the direct transport ([`super::direct`]) exists, WinHTTP is only the proxy fallback of
//! the [`HttpClient`] facade ([`super::http`]): a [`WinHttpClient`] is created the first time a
//! request is routed to it, so `winhttp.dll` (delay-loaded by the service) stays unloaded on the
//! normal path. `HttpClient`, `HttpError` and `HttpResponse` are re-exported here so the
//! `net::winhttp::{HttpClient, HttpError, HttpResponse}` contract keeps working.
//!
//! Design:
//! * One WinHTTP session (`WinHttpOpen`) per [`WinHttpClient`], shared by every thread. WinHTTP pools
//!   TCP/TLS connections at the session level, so a fresh connect + request handle per call still
//!   reuses the pooled connection (and multiplexes concurrent calls when HTTP/2 is negotiated).
//! * SYNCHRONOUS mode only: a call blocks its own thread inside WinHTTP until it completes or a
//!   timeout fires. Handles are never closed from another thread (documented race in WinHTTP).
//! * Every `HINTERNET` is owned by an RAII guard and closed exactly once (children first).
//! * Errors and log lines never contain the host or path: the Telegram path carries the bot token.

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_INVALID_OPTION, ERROR_WINHTTP_TIMEOUT, INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE,
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_DISABLE_COOKIES,
    WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_DISABLE_GLOBAL_POOLING,
    WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, WINHTTP_OPTION_HTTP2_KEEPALIVE, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
    WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_PROTOCOL_FLAG_HTTP2, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

use crate::util::win::{last_error, wide};

pub use super::http::{HttpClient, HttpError, HttpResponse};
use super::http::{MAX_RESPONSE_BYTES, clean_message};

/// WinHTTP proxy access type of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`: the static WinHTTP configuration (`netsh winhttp`),
    /// or no proxy. No WPAD discovery (cheaper; no discovery delay before the first request).
    Default,
    /// `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`: also WPAD, PAC scripts and the Internet Settings.
    Automatic,
}

/// Name resolution limit per request.
const RESOLVE_TIMEOUT_MS: i32 = 10_000;
/// TCP connect limit per request.
const CONNECT_TIMEOUT_MS: i32 = 15_000;
/// Request upload limit per request.
const SEND_TIMEOUT_MS: i32 = 15_000;
/// HTTP/2 PING interval keeping the pooled connection (and NAT mappings) alive.
const HTTP2_KEEPALIVE_MS: u32 = 30_000;
/// Largest chunk read in one `WinHttpReadData` call.
const READ_CHUNK: usize = 64 * 1024;
/// Extra request header (CRLF-terminated, length passed explicitly).
const JSON_HEADER: &str = "Content-Type: application/json\r\n";
/// First and last WinHTTP error codes (their texts live in winhttp.dll's message table).
const WINHTTP_ERROR_FIRST: u32 = 12_000;
const WINHTTP_ERROR_LAST: u32 = 12_999;

/// Owned `HINTERNET`, closed on drop.
struct Internet(*mut c_void);

impl Internet {
    /// Wrap a handle returned by WinHTTP; `None` for NULL (failure).
    fn from_raw(h: *mut c_void) -> Option<Self> {
        (!h.is_null()).then_some(Self(h))
    }

    fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for Internet {
    fn drop(&mut self) {
        // SAFETY: the handle is valid (non-null by construction), owned by this guard and no
        // WinHTTP call using it is in progress (synchronous mode, calls are made through `&self`).
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}

/// One WinHTTP session (thread-safe; share it between the poller and the sender).
pub struct WinHttpClient {
    session: Internet,
}

// SAFETY: a WinHTTP session handle may be used concurrently from several threads (each call
// creates its own connect/request handles, which never leave the calling thread). The session is
// closed only in `Drop`, which cannot run while a `post_json(&self)` borrow is alive.
unsafe impl Send for WinHttpClient {}
unsafe impl Sync for WinHttpClient {}

impl std::fmt::Debug for WinHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WinHttpClient { .. }")
    }
}

impl WinHttpClient {
    /// Open a session with automatic proxy detection (no network I/O).
    pub fn new(user_agent: &str) -> Result<Self, HttpError> {
        Self::with_mode(user_agent, ProxyMode::Automatic)
    }

    /// Open a session with the given proxy mode (no network I/O).
    pub fn with_mode(user_agent: &str, mode: ProxyMode) -> Result<Self, HttpError> {
        let agent = wide(user_agent);
        let session = match mode {
            ProxyMode::Default => open_session(&agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY)?,
            ProxyMode::Automatic => match open_session(&agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY) {
                Ok(s) => s,
                // AUTOMATIC_PROXY needs Windows 8.1+; keep a fallback for unusual stacks.
                Err(first) => open_session(&agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY).map_err(|_| first)?,
            },
        };
        configure_session(&session);
        Ok(Self { session })
    }

    /// HTTPS POST `body` as `application/json` to `https://{host}{path}` and read the full
    /// response. `timeout` bounds the receive phase (long polls pass ~65 s).
    ///
    /// Resolve/connect/send use 10 s / 15 s / 15 s, each additionally capped at `timeout` so a
    /// short request (e.g. during shutdown) cannot hang for longer than asked in any phase.
    pub fn post_json(&self, host: &str, path: &str, body: &[u8], timeout: Duration) -> Result<HttpResponse, HttpError> {
        let body_len = u32::try_from(body.len()).map_err(|_| HttpError::Other("request body is too large".into()))?;
        let host_w = wide(host);
        let path_w = wide(path);

        // SAFETY: session is valid; host_w is NUL-terminated and outlives the call.
        let connect = unsafe { WinHttpConnect(self.session.raw(), host_w.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0) };
        let connect = Internet::from_raw(connect).ok_or_else(last_http_error)?;

        let verb = wide("POST");
        // SAFETY: connect is valid; verb/path are NUL-terminated; NULL version/referrer/accept
        // types select the defaults (HTTP/1.1 request line, HTTP/2 negotiated via ALPN).
        let request = unsafe {
            WinHttpOpenRequest(
                connect.raw(),
                verb.as_ptr(),
                path_w.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE,
            )
        };
        // Declared after `connect`, so it is dropped (closed) first.
        let request = Internet::from_raw(request).ok_or_else(last_http_error)?;

        let t = PhaseTimeouts::for_receive(timeout);
        // SAFETY: request is a valid request handle.
        if unsafe { WinHttpSetTimeouts(request.raw(), t.resolve, t.connect, t.send, t.receive) } == 0 {
            return Err(last_http_error());
        }
        // Header wait limit (default 90 s); the per-receive timeout above remains the hard limit.
        if let Err(code) = set_u32_option(&request, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, t.receive as u32) {
            crate::log_debug!("WinHTTP: cannot set the response timeout (error {code})");
        }
        // No cookie jar, and never follow redirects (the API never redirects; a redirect would be
        // reported as an unexpected status instead of being followed with our request body).
        if let Err(code) = set_u32_option(
            &request,
            WINHTTP_OPTION_DISABLE_FEATURE,
            WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS,
        ) {
            crate::log_debug!("WinHTTP: cannot disable cookies/redirects (error {code})");
        }

        let headers: Vec<u16> = JSON_HEADER.encode_utf16().collect();
        let body_ptr = if body.is_empty() { null() } else { body.as_ptr().cast::<c_void>() };
        // SAFETY: request is valid; headers/body pointers are valid for the given lengths for the
        // whole (synchronous) call.
        let sent = unsafe {
            WinHttpSendRequest(request.raw(), headers.as_ptr(), headers.len() as u32, body_ptr, body_len, body_len, 0)
        };
        if sent == 0 {
            return Err(last_http_error());
        }
        // SAFETY: request is valid; the reserved parameter must be NULL.
        if unsafe { WinHttpReceiveResponse(request.raw(), null_mut()) } == 0 {
            return Err(last_http_error());
        }

        let status = query_status(&request)?;
        let body = read_body(&request)?;
        Ok(HttpResponse { status, body })
    }
}

/// `WinHttpOpen` in synchronous mode with the given proxy access type.
fn open_session(agent: &[u16], access: WINHTTP_ACCESS_TYPE) -> Result<Internet, HttpError> {
    // SAFETY: agent is NUL-terminated; NULL proxy name/bypass = WINHTTP_NO_PROXY_NAME/BYPASS.
    let h = unsafe { WinHttpOpen(agent.as_ptr(), access, null(), null(), 0) };
    Internet::from_raw(h).ok_or_else(last_http_error)
}

/// Session-wide options. All are best-effort: an unsupported option must not prevent requests.
fn configure_session(session: &Internet) {
    let tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if let Err(first) = set_u32_option(session, WINHTTP_OPTION_SECURE_PROTOCOLS, tls) {
        // Stacks without TLS 1.3 reject the combined mask; require at least TLS 1.2 then.
        if let Err(second) =
            set_u32_option(session, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2)
        {
            crate::log_debug!(
                "WinHTTP: TLS protocol selection unavailable (errors {first}, {second}); OS defaults apply"
            );
        }
    }
    // Pool connections only inside this session (recommended; lets a new session drop stale sockets).
    set_optional(session, WINHTTP_OPTION_DISABLE_GLOBAL_POOLING, 1, "session-local pooling");
    set_optional(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, WINHTTP_PROTOCOL_FLAG_HTTP2, "HTTP/2");
    set_optional(session, WINHTTP_OPTION_HTTP2_KEEPALIVE, HTTP2_KEEPALIVE_MS, "HTTP/2 keep-alive");
}

/// Set an optional DWORD option; "invalid option" (older Windows) is silently ignored.
fn set_optional(h: &Internet, option: u32, value: u32, what: &str) {
    if let Err(code) = set_u32_option(h, option, value)
        && code != ERROR_WINHTTP_INVALID_OPTION
    {
        crate::log_debug!("WinHTTP: cannot enable {what} (error {code})");
    }
}

/// `WinHttpSetOption` with a DWORD value. Returns the Win32 error code on failure.
fn set_u32_option(h: &Internet, option: u32, value: u32) -> Result<(), u32> {
    // SAFETY: h is valid; the buffer is a live u32 of the advertised size.
    let ok =
        unsafe { WinHttpSetOption(h.raw(), option, (&value as *const u32).cast::<c_void>(), size_of::<u32>() as u32) };
    if ok != 0 { Ok(()) } else { Err(last_error()) }
}

/// HTTP status code of a received response.
fn query_status(request: &Internet) -> Result<u16, HttpError> {
    let mut status: u32 = 0;
    let mut len = size_of::<u32>() as u32;
    // SAFETY: request is valid and has received a response; the buffer is a live u32.
    // NULL name = WINHTTP_HEADER_NAME_BY_INDEX, NULL index = WINHTTP_NO_HEADER_INDEX.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast::<c_void>(),
            &mut len,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_http_error());
    }
    u16::try_from(status).map_err(|_| HttpError::Other(format!("invalid HTTP status {status}")))
}

/// Read the response body to EOF (so the connection can return to the pool), capped.
fn read_body(request: &Internet) -> Result<Vec<u8>, HttpError> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let mut available: u32 = 0;
        // SAFETY: request is valid; `available` is a live out-parameter.
        if unsafe { WinHttpQueryDataAvailable(request.raw(), &mut available) } == 0 {
            return Err(last_http_error());
        }
        if available == 0 {
            return Ok(body); // end of the response
        }
        let want = next_read_len(body.len(), available as usize)?;
        body.reserve(want);
        let len = body.len();
        let spare = body.spare_capacity_mut();
        let want = want.min(spare.len());
        let mut read: u32 = 0;
        // SAFETY: the destination is `want` bytes of the Vec's spare capacity.
        let ok = unsafe { WinHttpReadData(request.raw(), spare.as_mut_ptr().cast::<c_void>(), want as u32, &mut read) };
        if ok == 0 {
            return Err(last_http_error());
        }
        let read = (read as usize).min(want);
        if read == 0 {
            return Ok(body);
        }
        // SAFETY: WinHttpReadData initialised exactly `read` (<= want <= spare) bytes after `len`.
        unsafe { body.set_len(len + read) };
    }
}

/// How many bytes to read next, or an error when the body would exceed [`MAX_RESPONSE_BYTES`].
fn next_read_len(already: usize, available: usize) -> Result<usize, HttpError> {
    if already.saturating_add(available) > MAX_RESPONSE_BYTES {
        return Err(HttpError::Other(format!(
            "response is larger than {} MiB; aborted",
            MAX_RESPONSE_BYTES / (1024 * 1024)
        )));
    }
    Ok(available.min(READ_CHUNK))
}

/// Per-phase WinHTTP timeouts in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PhaseTimeouts {
    resolve: i32,
    connect: i32,
    send: i32,
    receive: i32,
}

impl PhaseTimeouts {
    /// Receive = `timeout`; the other phases use their defaults, capped at `timeout`.
    /// Never 0 (WinHTTP treats 0 as "infinite").
    fn for_receive(timeout: Duration) -> Self {
        let receive = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        Self {
            resolve: RESOLVE_TIMEOUT_MS.min(receive),
            connect: CONNECT_TIMEOUT_MS.min(receive),
            send: SEND_TIMEOUT_MS.min(receive),
            receive,
        }
    }
}

/// Capture `GetLastError()` (call immediately after the failing WinHTTP call).
fn last_http_error() -> HttpError {
    map_error(last_error())
}

/// Classify a WinHTTP/Win32 error code.
fn map_error(code: u32) -> HttpError {
    if code == ERROR_WINHTTP_TIMEOUT {
        HttpError::Timeout
    } else {
        HttpError::Network { code, message: error_text(code) }
    }
}

/// Human readable text for a WinHTTP (12xxx, from winhttp.dll) or system error code.
fn error_text(code: u32) -> String {
    let module = if (WINHTTP_ERROR_FIRST..=WINHTTP_ERROR_LAST).contains(&code) {
        let name = wide("winhttp.dll");
        // SAFETY: NUL-terminated name; GetModuleHandleW does not add a reference (never freed).
        unsafe { GetModuleHandleW(name.as_ptr()) }
    } else {
        null_mut()
    };
    let mut flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    if !module.is_null() {
        flags |= FORMAT_MESSAGE_FROM_HMODULE; // module table first, then the system table
    }
    let mut buf = [0u16; 512];
    // SAFETY: buf is a writable buffer of the advertised length; no insert arguments are used.
    let n = unsafe { FormatMessageW(flags, module.cast_const(), code, 0, buf.as_mut_ptr(), buf.len() as u32, null()) };
    let text = clean_message(&String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())]));
    if !text.is_empty() {
        text
    } else if (WINHTTP_ERROR_FIRST..=WINHTTP_ERROR_LAST).contains(&code) {
        "WinHTTP request failed".to_string()
    } else {
        "network request failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn client_is_send_sync_and_opens_without_network() {
        assert_send_sync::<WinHttpClient>();
        let c = WinHttpClient::new("PredatorTest/1.0").expect("WinHttpOpen");
        assert_eq!(format!("{c:?}"), "WinHttpClient { .. }");
        let d = WinHttpClient::with_mode("PredatorTest/1.0", ProxyMode::Default).expect("WinHttpOpen");
        assert_eq!(format!("{d:?}"), "WinHttpClient { .. }");
    }

    #[test]
    fn session_options_accepted_by_this_os() {
        // Windows 11 is the target platform: every session option must really apply there.
        let agent = wide("PredatorTest/1.0");
        let s = open_session(&agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY).expect("WinHttpOpen");
        let tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        assert_eq!(set_u32_option(&s, WINHTTP_OPTION_SECURE_PROTOCOLS, tls), Ok(()));
        assert_eq!(set_u32_option(&s, WINHTTP_OPTION_DISABLE_GLOBAL_POOLING, 1), Ok(()));
        assert_eq!(set_u32_option(&s, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, WINHTTP_PROTOCOL_FLAG_HTTP2), Ok(()));
        assert_eq!(set_u32_option(&s, WINHTTP_OPTION_HTTP2_KEEPALIVE, HTTP2_KEEPALIVE_MS), Ok(()));
    }

    #[test]
    fn timeout_maps_to_timeout() {
        assert_eq!(map_error(ERROR_WINHTTP_TIMEOUT), HttpError::Timeout);
        assert_eq!(HttpError::Timeout.to_string(), "request timed out");
    }

    #[test]
    fn winhttp_errors_have_text_from_winhttp_dll() {
        let _session = WinHttpClient::new("PredatorTest/1.0").expect("WinHttpOpen"); // winhttp.dll loaded
        // 12007 = ERROR_WINHTTP_NAME_NOT_RESOLVED, 12029 = ERROR_WINHTTP_CANNOT_CONNECT
        for code in [12007u32, 12029] {
            match map_error(code) {
                HttpError::Network { code: c, message } => {
                    assert_eq!(c, code);
                    assert!(!message.is_empty());
                    assert_ne!(message, "WinHTTP request failed", "no text for {code}");
                    assert!(!message.ends_with('.') && !message.contains('\n'), "{message:?}");
                    let shown = HttpError::Network { code: c, message: message.clone() }.to_string();
                    assert!(shown.contains(&code.to_string()));
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn system_errors_fall_back_to_system_table() {
        // 10054 = WSAECONNRESET, 5 = ERROR_ACCESS_DENIED
        for code in [10054u32, 5] {
            let HttpError::Network { message, .. } = map_error(code) else { panic!("expected Network") };
            assert!(!message.is_empty());
            assert_ne!(message, "network request failed", "no text for {code}");
        }
        // An unknown code still yields a usable message.
        let HttpError::Network { message, .. } = map_error(12_998) else { panic!("expected Network") };
        assert!(!message.is_empty());
    }

    #[test]
    fn message_cleanup() {
        assert_eq!(clean_message("The operation timed out\r\n"), "The operation timed out");
        assert_eq!(clean_message("Line one.\r\nLine two.\r\n"), "Line one. Line two");
        assert_eq!(clean_message("  \r\n"), "");
    }

    #[test]
    fn phase_timeouts() {
        let long = PhaseTimeouts::for_receive(Duration::from_secs(65));
        assert_eq!(long, PhaseTimeouts { resolve: 10_000, connect: 15_000, send: 15_000, receive: 65_000 });
        let short = PhaseTimeouts::for_receive(Duration::from_secs(5));
        assert_eq!(short, PhaseTimeouts { resolve: 5_000, connect: 5_000, send: 5_000, receive: 5_000 });
        let zero = PhaseTimeouts::for_receive(Duration::ZERO);
        assert_eq!(zero, PhaseTimeouts { resolve: 1, connect: 1, send: 1, receive: 1 });
        let huge = PhaseTimeouts::for_receive(Duration::from_secs(u64::MAX));
        assert_eq!(huge.receive, i32::MAX);
        assert_eq!(huge.resolve, 10_000);
    }

    #[test]
    fn body_cap() {
        assert_eq!(next_read_len(0, 100).unwrap(), 100);
        assert_eq!(next_read_len(0, 1_000_000).unwrap(), READ_CHUNK);
        assert_eq!(next_read_len(MAX_RESPONSE_BYTES - 10, 10).unwrap(), 10);
        let err = next_read_len(MAX_RESPONSE_BYTES - 10, 11).unwrap_err();
        assert!(matches!(&err, HttpError::Other(m) if m.contains("4 MiB")), "{err:?}");
        assert!(next_read_len(usize::MAX, 1).is_err());
    }

    #[test]
    fn json_header_is_crlf_terminated() {
        assert!(JSON_HEADER.ends_with("\r\n"));
        assert!(JSON_HEADER.starts_with("Content-Type: application/json"));
    }

    /// Live check of the WinHTTP fallback in both proxy modes (no token):
    /// `cargo test --lib net::winhttp -- --ignored`.
    #[test]
    #[ignore = "needs internet access to api.telegram.org"]
    fn live_both_proxy_modes_reach_telegram() {
        for mode in [ProxyMode::Default, ProxyMode::Automatic] {
            let c = WinHttpClient::with_mode("PredatorTest/1.0", mode).expect("WinHttpOpen");
            let r = c
                .post_json("api.telegram.org", "/botINVALID/getMe", b"{}", Duration::from_secs(30))
                .unwrap_or_else(|e| panic!("{mode:?}: transport failed: {e}"));
            println!("{mode:?}: HTTP {}", r.status);
            assert!(r.status == 401 || r.status == 404, "{mode:?}: status {}", r.status);
        }
    }
}
