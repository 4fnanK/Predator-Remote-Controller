//! Resource-light HTTPS client: `std::net::TcpStream` + SChannel (`schannel` crate) + HTTP/1.1
//! keep-alive. No thread pool and no timers: an idle process has no background wake-ups, and
//! `winhttp.dll` is not loaded (measured: about 1 MB less private memory than WinHTTP).
//!
//! Design:
//! * **TLS**: one SChannel credential (TLS 1.2 + 1.3, `SCH_CREDENTIALS`) acquired on first use and
//!   shared by every connection. The `schannel` crate validates the server certificate chain and
//!   the host name (`tls_stream::Builder::domain`) against the Windows trust store; validation is
//!   never disabled.
//! * **Sockets**: resolved addresses are tried in order with `connect_timeout`; after connecting,
//!   the socket is switched to non-blocking mode with `WSAEventSelect` and every read/write waits
//!   on that event with the request deadline. [`DirectClient::interrupt`] sets a per-connection
//!   cancel flag and signals the same event, so a blocked long poll returns at once
//!   (`shutdown()` does not wake a blocked `recv` on Windows; this was verified).
//! * **What an interrupt stops** ([`Interruptible`]): an `Always` request (idempotent, e.g. the
//!   long poll) at any point; an `UntilSent` request (`sendMessage`) only while it is connecting or
//!   still sending. Once its request has been completely handed to the socket it runs to its
//!   response or its time limit, because reporting it as failed would make the caller send the
//!   message a second time although Telegram may already have delivered it.
//! * **Pool**: at most [`MAX_IDLE`] idle connections, most recently used first; connections idle
//!   for more than [`IDLE_LIMIT`], closed by the server, marked `Connection: close`, or older than
//!   the last interrupt are dropped. One connection per concurrent request (the 50 s long poll and
//!   the sender/bot replies run on different threads).
//! * **Retry**: exactly once, on a fresh connection, and only when a *reused* connection failed
//!   before any response byte arrived (the classic "server closed the idle connection" race).
//! * Errors never contain the host or the path (the Telegram path carries the bot token), and the
//!   plaintext request buffer is wiped after each write.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::windows::io::AsRawSocket;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use schannel::schannel_cred::{Direction, Protocol, SchannelCred};
use schannel::tls_stream::{self, HandshakeError, TlsStream};
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{
    FD_CLOSE, FD_READ, FD_WRITE, SOCKET, WSAEVENT, WSAEnumNetworkEvents, WSAEventSelect, WSAGetLastError,
    WSANETWORKEVENTS,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::http::{HttpError, HttpResponse, Interruptible, MAX_RESPONSE_BYTES, io_error};
use super::http1::{self, Limits, ReadError};
use crate::util::win::OwnedEvent;

/// HTTPS port.
pub const HTTPS_PORT: u16 = 443;
/// Idle connections kept for reuse.
pub const MAX_IDLE: usize = 3;
/// Idle connections older than this are closed instead of reused.
pub const IDLE_LIMIT: Duration = Duration::from_secs(30);
/// TCP connect limit per resolved address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// TCP connect limit over all addresses.
const CONNECT_TOTAL: Duration = Duration::from_secs(30);
/// TLS handshake limit.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Request upload limit.
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
/// At most this many resolved addresses are tried.
const MAX_ADDRESSES: usize = 8;
/// Bodies up to this size are sent in the same TLS write as the head.
const INLINE_BODY_MAX: usize = 16 * 1024;
/// Per-connection buffers that grew beyond this are released after the request.
const SHRINK_ABOVE: usize = 64 * 1024;

/// Per-phase limits of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    /// Per resolved address.
    pub connect: Duration,
    /// All addresses together.
    pub connect_total: Duration,
    pub handshake: Duration,
    pub send: Duration,
    /// From the end of the request to the end of the response.
    pub receive: Duration,
}

impl Timeouts {
    /// `receive` = `timeout`; the other phases use their defaults capped at `timeout` (so a short
    /// request, e.g. during shutdown, cannot hang longer than asked in any phase). Never zero.
    pub(crate) fn for_receive(timeout: Duration) -> Self {
        let receive = timeout.max(Duration::from_millis(1));
        Self {
            connect: CONNECT_TIMEOUT.min(receive),
            connect_total: CONNECT_TOTAL.min(receive),
            handshake: HANDSHAKE_TIMEOUT.min(receive),
            send: SEND_TIMEOUT.min(receive),
            receive,
        }
    }
}

/// Where a request failed (drives the backend fallback in [`super::http::HttpClient`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Invalid input or a local resource problem; nothing was sent.
    Local,
    /// Name resolution.
    Resolve,
    /// TCP connect.
    Connect,
    /// TLS handshake, including certificate validation and credential acquisition.
    Tls,
    /// After the TLS handshake: the server was reached.
    Exchange,
    /// Stopped by [`DirectClient::interrupt`].
    Cancelled,
}

impl Phase {
    /// The server could not be reached at the TCP/TLS level.
    pub(crate) fn is_connect_level(self) -> bool {
        matches!(self, Phase::Resolve | Phase::Connect | Phase::Tls)
    }
}

/// A failed request: the phase plus the caller-facing error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectError {
    pub phase: Phase,
    pub error: HttpError,
}

impl DirectError {
    pub(crate) fn new(phase: Phase, error: HttpError) -> Self {
        Self { phase, error }
    }

    fn cancelled() -> Self {
        Self::new(
            Phase::Cancelled,
            HttpError::Network { code: 995, message: "request cancelled (network change, resume or stop)".into() },
        )
    }

    fn local(message: &str) -> Self {
        Self::new(Phase::Local, HttpError::Other(message.to_owned()))
    }
}

// ---------------------------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------------------------

/// Per-connection cancellation: a flag plus the event the socket is associated with, and the
/// interrupt policy / progress of the request the connection carries right now.
pub(crate) struct CancelCtl {
    cancelled: AtomicBool,
    /// The current request may be stopped even after it was completely sent
    /// ([`Interruptible::Always`]). True while connecting.
    anytime: AtomicBool,
    /// The current request has been completely handed to the socket.
    sent: AtomicBool,
    wake: OwnedEvent,
}

impl CancelCtl {
    fn new() -> io::Result<Arc<Self>> {
        let wake = OwnedEvent::new_manual().map_err(|e| io::Error::from_raw_os_error(e.code as i32))?;
        Ok(Arc::new(Self {
            cancelled: AtomicBool::new(false),
            anytime: AtomicBool::new(true),
            sent: AtomicBool::new(false),
            wake,
        }))
    }

    /// Mark cancelled, then wake a thread waiting for socket readiness.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.wake.set();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// A new request on this connection (called by the thread that carries it, before any I/O).
    fn begin(&self, when: Interruptible) {
        self.sent.store(false, Ordering::SeqCst);
        self.anytime.store(when == Interruptible::Always, Ordering::SeqCst);
    }

    /// The whole request has been handed to the socket (called by the carrying thread).
    fn mark_sent(&self) {
        self.sent.store(true, Ordering::SeqCst);
    }

    /// The current operation must stop: cancelled, unless the request was already sent and may
    /// only be stopped before that. Only the carrying thread changes `sent`, so a cancel that
    /// arrives after the last byte was written can never abort an `UntilSent` request.
    pub(crate) fn should_stop(&self) -> bool {
        self.is_cancelled() && (self.anytime.load(Ordering::SeqCst) || !self.sent.load(Ordering::SeqCst))
    }
}

fn cancelled_io() -> io::Error {
    io::Error::other("request cancelled")
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

/// A connected socket in non-blocking mode whose waits honour a deadline and the cancel flag.
struct Sock {
    tcp: TcpStream,
    ctl: Arc<CancelCtl>,
    deadline: Instant,
}

impl Sock {
    fn new(tcp: TcpStream, ctl: Arc<CancelCtl>, deadline: Instant) -> io::Result<Self> {
        let events = (FD_READ | FD_WRITE | FD_CLOSE) as i32;
        // SAFETY: the socket is owned by `tcp`; the event handle is owned by `ctl`, which this
        // struct keeps alive for as long as the socket exists. WSAEventSelect also makes the
        // socket non-blocking.
        if unsafe { WSAEventSelect(tcp.as_raw_socket() as SOCKET, ctl.wake.raw() as WSAEVENT, events) } != 0 {
            // SAFETY: plain thread-local error query.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        Ok(Self { tcp, ctl, deadline })
    }

    /// Wait until the socket may be ready, the deadline passes or the request is cancelled.
    fn wait(&self) -> io::Result<()> {
        if self.ctl.should_stop() {
            return Err(cancelled_io());
        }
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // Round up so the wait never ends just before the deadline; below INFINITE.
        let ms = u32::try_from(left.as_millis().saturating_add(1)).unwrap_or(u32::MAX).min(u32::MAX - 1);
        // SAFETY: the event handle is valid while `self.ctl` lives.
        match unsafe { WaitForSingleObject(self.ctl.wake.raw(), ms) } {
            WAIT_OBJECT_0 => {
                // SAFETY: zeroed POD out-parameter; valid socket and event. Resets the event (the
                // recorded events are not needed: the retried recv/send tells what happened). A
                // cancel that raced with this reset is still seen through the flag, and a cancel
                // that does not stop this request (sent `UntilSent`) costs one extra wake-up only.
                let mut seen: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    WSAEnumNetworkEvents(self.tcp.as_raw_socket() as SOCKET, self.ctl.wake.raw() as WSAEVENT, &mut seen)
                };
                if rc != 0 {
                    self.ctl.wake.reset(); // never spin on a stuck signalled event
                }
                Ok(())
            }
            WAIT_TIMEOUT => Err(io::ErrorKind::TimedOut.into()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.ctl.should_stop() {
                return Err(cancelled_io());
            }
            match self.tcp.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait()?,
                other => return other,
            }
        }
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            if self.ctl.should_stop() {
                return Err(cancelled_io());
            }
            match self.tcp.write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait()?,
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------------------------

/// One request as seen by a connection.
pub(crate) struct Request<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub user_agent: &'a str,
    pub body: &'a [u8],
}

/// A failed round trip.
#[derive(Debug)]
pub(crate) enum ExchangeError {
    /// Writing the request failed (no response byte can have arrived).
    Send(io::Error),
    /// Reading the response failed.
    Receive(http1::ResponseError),
}

impl ExchangeError {
    /// Safe and useful to repeat on a fresh connection: nothing came back, and it was not a
    /// time-out (the time budget is spent) or a protocol error (would happen again).
    fn retry_on_fresh(&self) -> bool {
        match self {
            ExchangeError::Send(e) => !is_timeout(e),
            ExchangeError::Receive(r) => {
                !r.received_any
                    && match &r.kind {
                        ReadError::Eof => true,
                        ReadError::Io(e) => !is_timeout(e),
                        _ => false,
                    }
            }
        }
    }
}

/// A connection that can carry requests.
pub(crate) trait Exchange {
    /// Cheap check before reusing an idle connection: false when the server closed it or sent
    /// something unexpected.
    fn idle_ok(&mut self) -> bool;
    fn round_trip(&mut self, req: &Request<'_>, t: &Timeouts) -> Result<http1::Response, ExchangeError>;
}

/// Opens connections.
pub(crate) trait Dialer: Send + Sync {
    type Conn: Exchange + Send;
    /// Resolve, connect and handshake. `ctl` is already registered for cancellation.
    fn dial(&self, host: &str, port: u16, ctl: &Arc<CancelCtl>, t: &Timeouts) -> Result<Self::Conn, DirectError>;
}

/// The real dialer: TCP + SChannel.
pub(crate) struct TlsDialer {
    protocols: &'static [Protocol],
    cred: Mutex<Option<SchannelCred>>,
}

impl TlsDialer {
    pub(crate) fn new() -> Self {
        Self::with_protocols(&[Protocol::Tls12, Protocol::Tls13])
    }

    pub(crate) fn with_protocols(protocols: &'static [Protocol]) -> Self {
        Self { protocols, cred: Mutex::new(None) }
    }

    /// The shared credential, acquired on first use (a failure is retried on the next request).
    fn credentials(&self) -> io::Result<SchannelCred> {
        let mut slot = lock(&self.cred);
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        let acquired = SchannelCred::builder().enabled_protocols(self.protocols).acquire(Direction::Outbound);
        let cred = match acquired {
            Ok(c) => c,
            // A system without TLS 1.3 support may refuse the combined mask: require TLS 1.2 then.
            Err(first) if self.protocols.len() > 1 => SchannelCred::builder()
                .enabled_protocols(&[Protocol::Tls12])
                .acquire(Direction::Outbound)
                .map_err(|_| first)?,
            Err(e) => return Err(e),
        };
        *slot = Some(cred.clone());
        Ok(cred)
    }
}

impl Dialer for TlsDialer {
    type Conn = TlsConn;

    fn dial(&self, host: &str, port: u16, ctl: &Arc<CancelCtl>, t: &Timeouts) -> Result<TlsConn, DirectError> {
        let started = Instant::now();
        let addrs = resolve(host, port)?;
        let tcp = connect_any(&addrs, t, ctl)?;
        if let Err(e) = tcp.set_nodelay(true) {
            crate::log_debug!("HTTPS: cannot disable Nagle's algorithm ({e})");
        }
        let sock = Sock::new(tcp, ctl.clone(), Instant::now() + t.handshake)
            .map_err(|e| DirectError::new(Phase::Connect, io_error("cannot prepare the socket", &e)))?;
        let cred = self
            .credentials()
            .map_err(|e| DirectError::new(Phase::Tls, io_error("cannot acquire TLS credentials", &e)))?;
        let mut builder = tls_stream::Builder::new();
        builder.domain(host);
        let tls = match builder.connect(cred, sock) {
            Ok(tls) => tls,
            Err(_) if ctl.is_cancelled() => return Err(DirectError::cancelled()),
            Err(HandshakeError::Failure(e)) => return Err(DirectError::new(Phase::Tls, tls_error(&e))),
            Err(HandshakeError::Interrupted(_)) => {
                return Err(DirectError::new(Phase::Tls, HttpError::Other("TLS handshake did not complete".into())));
            }
        };
        crate::log_debug!("HTTPS: new connection ready in {} ms", started.elapsed().as_millis());
        Ok(TlsConn { tls, out: Vec::new(), scratch: Vec::new() })
    }
}

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, DirectError> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| DirectError::new(Phase::Resolve, io_error("cannot resolve the server name", &e)))?
        .take(MAX_ADDRESSES)
        .collect();
    if addrs.is_empty() {
        return Err(DirectError::new(Phase::Resolve, HttpError::Other("the server name has no address".into())));
    }
    Ok(addrs)
}

/// Try each address with its own time limit; all of them within `t.connect_total`.
fn connect_any(addrs: &[SocketAddr], t: &Timeouts, ctl: &CancelCtl) -> Result<TcpStream, DirectError> {
    let deadline = Instant::now() + t.connect_total;
    let mut last: Option<io::Error> = None;
    for addr in addrs {
        if ctl.is_cancelled() {
            return Err(DirectError::cancelled());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, t.connect.min(left)) {
            Ok(s) if ctl.is_cancelled() => {
                drop(s);
                return Err(DirectError::cancelled());
            }
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    let e = last.unwrap_or_else(|| io::ErrorKind::TimedOut.into());
    Err(DirectError::new(Phase::Connect, io_error("cannot connect to the server", &e)))
}

/// Certificate problems get their own wording; everything else is a handshake failure.
fn tls_error(e: &io::Error) -> HttpError {
    let cert = e.raw_os_error().is_some_and(|c| is_certificate_error(c as u32));
    io_error(if cert { "server certificate rejected" } else { "TLS handshake failed" }, e)
}

/// `CERT_E_*` / `TRUST_E_*` (0x800B....) and the SChannel/CryptoAPI certificate codes.
pub(crate) fn is_certificate_error(code: u32) -> bool {
    (0x800B_0000..=0x800B_FFFF).contains(&code)
        || matches!(
            code,
            0x8009_0322 // SEC_E_WRONG_PRINCIPAL
                | 0x8009_0325 // SEC_E_UNTRUSTED_ROOT
                | 0x8009_0327 // SEC_E_CERT_UNKNOWN
                | 0x8009_0328 // SEC_E_CERT_EXPIRED
                | 0x8009_2010 // CRYPT_E_REVOKED
                | 0x8009_2012 // CRYPT_E_NO_REVOCATION_CHECK
                | 0x8009_2013 // CRYPT_E_REVOCATION_OFFLINE
        )
}

/// A TLS connection with its reusable buffers.
pub(crate) struct TlsConn {
    tls: TlsStream<Sock>,
    /// Request head (+ small body); wiped after every write.
    out: Vec<u8>,
    /// Response head / chunk lines.
    scratch: Vec<u8>,
}

impl Exchange for TlsConn {
    fn idle_ok(&mut self) -> bool {
        if !self.tls.get_buf().is_empty() || self.tls.get_ref().ctl.is_cancelled() {
            return false; // unread decrypted data: the stream is out of step
        }
        let mut probe = [0u8; 1];
        // Non-blocking peek: WouldBlock = open and quiet. Ok(0) = closed by the server; any byte
        // (e.g. a TLS alert) or error = do not reuse.
        matches!(self.tls.get_ref().tcp.peek(&mut probe), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    }

    fn round_trip(&mut self, req: &Request<'_>, t: &Timeouts) -> Result<http1::Response, ExchangeError> {
        self.tls.get_mut().deadline = Instant::now() + t.send;
        self.out.clear();
        http1::write_request_head(&mut self.out, req.host, req.port, req.path, req.user_agent, req.body.len());
        let inline = req.body.len() <= INLINE_BODY_MAX;
        if inline {
            self.out.extend_from_slice(req.body);
        }
        let sent = send_all(&mut self.tls, &self.out, if inline { &[] } else { req.body });
        wipe(&mut self.out);
        sent.map_err(ExchangeError::Send)?;
        // From here on an `UntilSent` request is no longer stopped by an interrupt.
        self.tls.get_ref().ctl.mark_sent();

        self.tls.get_mut().deadline = Instant::now() + t.receive;
        let limits = Limits { head: http1::MAX_HEAD_BYTES, body: MAX_RESPONSE_BYTES };
        let result = http1::read_response(&mut self.tls, &mut self.scratch, limits).map_err(ExchangeError::Receive);
        shrink(&mut self.out);
        shrink(&mut self.scratch);
        result
    }
}

fn send_all<W: Write>(w: &mut W, head: &[u8], body: &[u8]) -> io::Result<()> {
    w.write_all(head)?;
    if !body.is_empty() {
        w.write_all(body)?;
    }
    w.flush()
}

/// Overwrite the plaintext request (it contains the bot token) before the buffer is reused.
fn wipe(buf: &mut Vec<u8>) {
    buf.fill(0);
    std::hint::black_box(&*buf);
    buf.clear();
}

fn shrink(buf: &mut Vec<u8>) {
    if buf.capacity() > SHRINK_ABOVE {
        *buf = Vec::new();
    }
}

// ---------------------------------------------------------------------------------------------
// Pool + request engine (generic over the dialer so the logic is testable with mocks)
// ---------------------------------------------------------------------------------------------

/// An idle connection.
struct Idle<C> {
    conn: C,
    host: Box<str>,
    ctl: Arc<CancelCtl>,
    /// Interrupt generation the connection belongs to.
    epoch: u64,
    since: Instant,
}

/// Idle connections, in-flight cancel handles and the interrupt generation (one lock).
struct PoolState<C> {
    /// Oldest first.
    idle: Vec<Idle<C>>,
    inflight: Vec<Arc<CancelCtl>>,
    epoch: u64,
}

impl<C> PoolState<C> {
    fn new() -> Self {
        Self { idle: Vec::new(), inflight: Vec::new(), epoch: 0 }
    }

    /// Move stale entries (too old, or from before an interrupt) into `dead`.
    fn prune(&mut self, now: Instant, idle_limit: Duration, dead: &mut Vec<Idle<C>>) {
        let epoch = self.epoch;
        let mut i = 0;
        while i < self.idle.len() {
            let e = &self.idle[i];
            if e.epoch != epoch || now.saturating_duration_since(e.since) > idle_limit {
                dead.push(self.idle.remove(i));
            } else {
                i += 1;
            }
        }
    }

    /// The most recently returned fresh connection to `host`.
    fn take(&mut self, host: &str, now: Instant, idle_limit: Duration, dead: &mut Vec<Idle<C>>) -> Option<Idle<C>> {
        self.prune(now, idle_limit, dead);
        let pos = self.idle.iter().rposition(|e| &*e.host == host)?;
        Some(self.idle.remove(pos))
    }

    /// Keep `item` for reuse; the oldest beyond `max_idle` (and stale ones) go to `dead`.
    fn put(&mut self, item: Idle<C>, now: Instant, idle_limit: Duration, max_idle: usize, dead: &mut Vec<Idle<C>>) {
        self.prune(now, idle_limit, dead);
        if item.epoch != self.epoch || max_idle == 0 {
            dead.push(item);
            return;
        }
        self.idle.push(item);
        while self.idle.len() > max_idle {
            dead.push(self.idle.remove(0));
        }
    }

    fn register(&mut self, ctl: &Arc<CancelCtl>) {
        self.inflight.push(Arc::clone(ctl));
    }

    fn unregister(&mut self, ctl: &Arc<CancelCtl>) {
        if let Some(i) = self.inflight.iter().position(|c| Arc::ptr_eq(c, ctl)) {
            self.inflight.swap_remove(i);
        }
    }

    /// New generation: cancel everything in flight, hand back the idle connections to close.
    fn interrupt(&mut self) -> Vec<Idle<C>> {
        self.epoch = self.epoch.wrapping_add(1);
        for ctl in &self.inflight {
            ctl.cancel();
        }
        std::mem::take(&mut self.idle)
    }
}

/// A connection checked out for one request.
struct Lease<C> {
    conn: C,
    ctl: Arc<CancelCtl>,
    epoch: u64,
    reused: bool,
}

/// A failed attempt.
struct Failure {
    error: DirectError,
    retry_on_fresh: bool,
}

pub(crate) struct Engine<D: Dialer> {
    dialer: D,
    user_agent: String,
    port: u16,
    idle_limit: Duration,
    max_idle: usize,
    state: Mutex<PoolState<D::Conn>>,
    dials: AtomicU32,
    reuses: AtomicU32,
}

impl<D: Dialer> Engine<D> {
    pub(crate) fn new(dialer: D, user_agent: &str, port: u16) -> Self {
        Self {
            dialer,
            user_agent: http1::sanitize_header_value(user_agent),
            port,
            idle_limit: IDLE_LIMIT,
            max_idle: MAX_IDLE,
            state: Mutex::new(PoolState::new()),
            dials: AtomicU32::new(0),
            reuses: AtomicU32::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState<D::Conn>> {
        lock(&self.state)
    }

    pub(crate) fn post(
        &self,
        host: &str,
        path: &str,
        body: &[u8],
        timeout: Duration,
        when: Interruptible,
    ) -> Result<HttpResponse, DirectError> {
        if !http1::valid_host(host) || !http1::valid_path(path) {
            return Err(DirectError::local("invalid request target"));
        }
        let t = Timeouts::for_receive(timeout);
        let req = Request { host, port: self.port, path, user_agent: &self.user_agent, body };
        let lease = self.acquire(host, &t)?;
        let reused = lease.reused;
        match self.run(lease, &req, &t, when) {
            Ok(resp) => Ok(resp),
            Err(f) if reused && f.retry_on_fresh => {
                crate::log_debug!(
                    "HTTPS: a kept-alive connection failed before the response ({}); retrying once on a new connection",
                    f.error.error
                );
                let fresh = self.dial_new(host, &t)?;
                self.run(fresh, &req, &t, when).map_err(|f| f.error)
            }
            Err(f) => Err(f.error),
        }
    }

    /// A live idle connection to `host`, or a new one.
    fn acquire(&self, host: &str, t: &Timeouts) -> Result<Lease<D::Conn>, DirectError> {
        loop {
            let mut dead = Vec::new();
            let candidate = self.lock().take(host, Instant::now(), self.idle_limit, &mut dead);
            drop(dead); // close outside the lock
            let Some(mut idle) = candidate else { return self.dial_new(host, t) };
            let alive = catch_unwind(AssertUnwindSafe(|| idle.conn.idle_ok())).unwrap_or(false);
            if !alive {
                continue; // `idle` is closed here; try the next one
            }
            let mut st = self.lock();
            if idle.epoch != st.epoch {
                drop(st);
                continue; // interrupted while we looked at it
            }
            st.register(&idle.ctl);
            drop(st);
            self.reuses.fetch_add(1, Ordering::Relaxed);
            return Ok(Lease { conn: idle.conn, ctl: idle.ctl, epoch: idle.epoch, reused: true });
        }
    }

    fn dial_new(&self, host: &str, t: &Timeouts) -> Result<Lease<D::Conn>, DirectError> {
        let ctl =
            CancelCtl::new().map_err(|e| DirectError::new(Phase::Local, io_error("cannot create a wait event", &e)))?;
        let epoch = {
            let mut st = self.lock();
            st.register(&ctl);
            st.epoch
        };
        let dialed =
            catch_unwind(AssertUnwindSafe(|| self.dialer.dial(host, self.port, &ctl, t))).unwrap_or_else(|_| {
                Err(DirectError::new(Phase::Tls, HttpError::Other("internal error while connecting".into())))
            });
        match dialed {
            Ok(conn) => {
                self.dials.fetch_add(1, Ordering::Relaxed);
                Ok(Lease { conn, ctl, epoch, reused: false })
            }
            Err(e) => {
                self.lock().unregister(&ctl);
                Err(if ctl.is_cancelled() { DirectError::cancelled() } else { e })
            }
        }
    }

    /// One round trip on `lease`; the connection goes back to the pool when it may be reused.
    fn run(
        &self,
        lease: Lease<D::Conn>,
        req: &Request<'_>,
        t: &Timeouts,
        when: Interruptible,
    ) -> Result<HttpResponse, Failure> {
        let Lease { mut conn, ctl, epoch, reused } = lease;
        ctl.begin(when);
        let outcome = catch_unwind(AssertUnwindSafe(|| conn.round_trip(req, t)));
        // Any interrupt retires the connection; only one that stopped this request makes its
        // failure a "cancelled" one (a sent `UntilSent` request keeps its real outcome).
        let cancelled = ctl.should_stop();
        let reusable = !ctl.is_cancelled() && matches!(&outcome, Ok(Ok(r)) if r.reusable);
        let mut dead = Vec::new();
        let leftover = {
            let mut st = self.lock();
            st.unregister(&ctl);
            if reusable {
                let item = Idle { conn, host: req.host.into(), ctl, epoch, since: Instant::now() };
                st.put(item, Instant::now(), self.idle_limit, self.max_idle, &mut dead);
                None
            } else {
                Some(conn)
            }
        };
        drop(leftover); // close outside the lock
        drop(dead);
        match outcome {
            // A complete response is valid even if an interrupt arrived just after it.
            Ok(Ok(r)) => Ok(HttpResponse { status: r.status, body: r.body }),
            Ok(Err(_)) if cancelled => Err(Failure { error: DirectError::cancelled(), retry_on_fresh: false }),
            Ok(Err(e)) => Err(Failure { retry_on_fresh: reused && e.retry_on_fresh(), error: exchange_error(e) }),
            Err(_) => Err(Failure {
                error: DirectError::new(Phase::Exchange, HttpError::Other("internal error in the HTTPS client".into())),
                retry_on_fresh: false,
            }),
        }
    }

    pub(crate) fn interrupt(&self) {
        let dead = self.lock().interrupt();
        drop(dead);
    }

    /// Close the idle connections (in-flight requests are not affected).
    pub(crate) fn close_idle(&self) {
        let dead = std::mem::take(&mut self.lock().idle);
        drop(dead);
    }
}

fn exchange_error(e: ExchangeError) -> DirectError {
    let error = match e {
        ExchangeError::Send(io) if is_timeout(&io) => HttpError::Timeout,
        ExchangeError::Send(io) => io_error("sending the request failed", &io),
        ExchangeError::Receive(r) => match r.kind {
            ReadError::Io(io) if is_timeout(&io) => HttpError::Timeout,
            ReadError::Io(io) => io_error("receiving the response failed", &io),
            ReadError::Eof => HttpError::Other("the server closed the connection without a response".into()),
            ReadError::Truncated => HttpError::Other("the connection closed before the response was complete".into()),
            ReadError::Malformed(what) => HttpError::Other(format!("invalid HTTP response ({what})")),
            ReadError::HeadTooLarge => HttpError::Other(format!(
                "response header is larger than {} KiB; aborted",
                http1::MAX_HEAD_BYTES / 1024
            )),
            ReadError::BodyTooLarge => {
                HttpError::Other(format!("response is larger than {} MiB; aborted", MAX_RESPONSE_BYTES / (1024 * 1024)))
            }
        },
    };
    DirectError::new(Phase::Exchange, error)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Public client
// ---------------------------------------------------------------------------------------------

/// Direct HTTPS client (thread-safe; share it between the poller and the sender).
pub struct DirectClient {
    engine: Engine<TlsDialer>,
}

impl std::fmt::Debug for DirectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectClient { .. }")
    }
}

impl DirectClient {
    /// No network I/O and no system calls; the TLS credential is acquired by the first request.
    pub fn new(user_agent: &str) -> Self {
        Self::with_port(user_agent, HTTPS_PORT)
    }

    pub(crate) fn with_port(user_agent: &str, port: u16) -> Self {
        Self { engine: Engine::new(TlsDialer::new(), user_agent, port) }
    }

    /// HTTPS POST `body` as `application/json` to `https://{host}{path}`; `timeout` bounds the
    /// wait for the response (connect/handshake/send use 15 s each, capped at `timeout`).
    /// [`DirectClient::interrupt`] may stop it at any point ([`Interruptible::Always`]).
    pub fn post_json(&self, host: &str, path: &str, body: &[u8], timeout: Duration) -> Result<HttpResponse, HttpError> {
        self.post_classified(host, path, body, timeout, Interruptible::Always).map_err(|e| e.error)
    }

    pub(crate) fn post_classified(
        &self,
        host: &str,
        path: &str,
        body: &[u8],
        timeout: Duration,
        when: Interruptible,
    ) -> Result<HttpResponse, DirectError> {
        self.engine.post(host, path, body, timeout, when)
    }

    /// Stop the requests in flight at once (they fail with a "cancelled" error) and close the
    /// idle connections: every `Always` request, and every `UntilSent` request that has not been
    /// completely sent yet (a sent one finishes normally). Requests started afterwards are not
    /// affected.
    pub fn interrupt(&self) {
        self.engine.interrupt();
    }

    /// Close the idle connections only.
    pub fn close_idle(&self) {
        self.engine.close_idle();
    }

    /// Connections opened so far (diagnostics).
    pub fn connections_opened(&self) -> u32 {
        self.engine.dials.load(Ordering::Relaxed)
    }

    /// Requests that reused an idle connection (diagnostics).
    pub fn connections_reused(&self) -> u32 {
        self.engine.reuses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::TcpListener;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn types_are_thread_safe() {
        assert_send_sync::<DirectClient>();
        assert_send_sync::<Engine<MockDialer>>();
        assert_send_sync::<TlsConn>();
    }

    #[test]
    fn timeouts() {
        let long = Timeouts::for_receive(Duration::from_secs(65));
        assert_eq!(long.connect, Duration::from_secs(15));
        assert_eq!(long.connect_total, Duration::from_secs(30));
        assert_eq!(
            (long.handshake, long.send, long.receive),
            (HANDSHAKE_TIMEOUT, SEND_TIMEOUT, Duration::from_secs(65))
        );
        let short = Timeouts::for_receive(Duration::from_secs(3));
        assert!(
            [short.connect, short.connect_total, short.handshake, short.send, short.receive]
                .iter()
                .all(|d| *d == Duration::from_secs(3))
        );
        assert_eq!(Timeouts::for_receive(Duration::ZERO).receive, Duration::from_millis(1));
    }

    #[test]
    fn certificate_codes() {
        for c in [0x800B_0101u32, 0x800B_010F, 0x800B_0109, 0x8009_0325, 0x8009_0328, 0x8009_0322] {
            assert!(is_certificate_error(c), "{c:#x}");
        }
        for c in [0x8009_0308u32, 0x8009_0331, 10054, 0] {
            assert!(!is_certificate_error(c), "{c:#x}");
        }
    }

    #[test]
    fn exchange_errors_never_mention_the_target() {
        let r = |kind, received_any| ExchangeError::Receive(http1::ResponseError { kind, received_any });
        let cases = vec![
            ExchangeError::Send(io::Error::from_raw_os_error(10054)),
            ExchangeError::Send(io::ErrorKind::TimedOut.into()),
            r(ReadError::Io(io::Error::from_raw_os_error(10053)), false),
            r(ReadError::Io(io::ErrorKind::TimedOut.into()), true),
            r(ReadError::Eof, false),
            r(ReadError::Truncated, true),
            r(ReadError::Malformed("invalid header name"), true),
            r(ReadError::HeadTooLarge, true),
            r(ReadError::BodyTooLarge, true),
        ];
        for e in cases {
            let d = exchange_error(e);
            assert_eq!(d.phase, Phase::Exchange);
            let s = d.error.to_string();
            assert!(!s.is_empty() && !s.contains("/bot") && !s.contains("api.telegram.org"), "{s}");
        }
        assert_eq!(exchange_error(ExchangeError::Send(io::ErrorKind::TimedOut.into())).error, HttpError::Timeout);
    }

    #[test]
    fn retry_rule() {
        let r = |kind, received_any| ExchangeError::Receive(http1::ResponseError { kind, received_any });
        assert!(r(ReadError::Eof, false).retry_on_fresh());
        assert!(r(ReadError::Io(io::Error::from_raw_os_error(10054)), false).retry_on_fresh());
        assert!(ExchangeError::Send(io::Error::from_raw_os_error(10053)).retry_on_fresh());
        assert!(!r(ReadError::Io(io::Error::from_raw_os_error(10054)), true).retry_on_fresh());
        assert!(!r(ReadError::Io(io::ErrorKind::TimedOut.into()), false).retry_on_fresh());
        assert!(!ExchangeError::Send(io::ErrorKind::TimedOut.into()).retry_on_fresh());
        assert!(!r(ReadError::Truncated, true).retry_on_fresh());
        assert!(!r(ReadError::Malformed("x"), false).retry_on_fresh());
    }

    // ---- pool state ----------------------------------------------------------------------

    fn idle(host: &str, id: u32, epoch: u64, since: Instant) -> Idle<u32> {
        Idle { conn: id, host: host.into(), ctl: CancelCtl::new().unwrap(), epoch, since }
    }

    #[test]
    fn pool_lifo_per_host_and_staleness() {
        let t0 = Instant::now();
        let limit = Duration::from_secs(30);
        let mut st: PoolState<u32> = PoolState::new();
        let mut dead = Vec::new();
        st.put(idle("a", 1, 0, t0), t0, limit, 3, &mut dead);
        st.put(idle("b", 2, 0, t0), t0, limit, 3, &mut dead);
        st.put(idle("a", 3, 0, t0 + Duration::from_secs(1)), t0, limit, 3, &mut dead);
        assert!(dead.is_empty());
        // most recently returned connection to the host first
        assert_eq!(st.take("a", t0 + Duration::from_secs(2), limit, &mut dead).map(|e| e.conn), Some(3));
        assert_eq!(st.take("c", t0, limit, &mut dead).map(|e| e.conn), None);
        // 31 s later everything idle is stale
        assert!(st.take("a", t0 + Duration::from_secs(31), limit, &mut dead).is_none());
        assert_eq!(dead.iter().map(|e| e.conn).collect::<Vec<_>>(), vec![1, 2]);
        assert!(st.idle.is_empty());
        // exactly at the limit is still fresh
        st.put(idle("a", 4, 0, t0), t0, limit, 3, &mut dead);
        assert_eq!(st.take("a", t0 + limit, limit, &mut dead).map(|e| e.conn), Some(4));
    }

    #[test]
    fn pool_caps_idle_connections() {
        let t0 = Instant::now();
        let limit = Duration::from_secs(30);
        let mut st: PoolState<u32> = PoolState::new();
        let mut dead = Vec::new();
        for id in 1..=5 {
            st.put(idle("a", id, 0, t0), t0, limit, MAX_IDLE, &mut dead);
        }
        assert_eq!(st.idle.iter().map(|e| e.conn).collect::<Vec<_>>(), vec![3, 4, 5]);
        assert_eq!(dead.iter().map(|e| e.conn).collect::<Vec<_>>(), vec![1, 2], "oldest are closed");
        let mut dead = Vec::new();
        st.put(idle("a", 9, 0, t0), t0, limit, 0, &mut dead);
        assert_eq!(dead.len(), 1, "max_idle 0 keeps nothing");
    }

    #[test]
    fn pool_interrupt_generation() {
        let t0 = Instant::now();
        let limit = Duration::from_secs(30);
        let mut st: PoolState<u32> = PoolState::new();
        let mut dead = Vec::new();
        st.put(idle("a", 1, 0, t0), t0, limit, 3, &mut dead);
        let flying = CancelCtl::new().unwrap();
        st.register(&flying);
        let drained = st.interrupt();
        assert_eq!(drained.len(), 1);
        assert!(flying.is_cancelled(), "in-flight request cancelled");
        assert!(flying.wake.wait(Duration::ZERO), "and its wait event signalled");
        // a connection leased before the interrupt is not taken back
        st.put(idle("a", 2, 0, t0), t0, limit, 3, &mut dead);
        assert_eq!(dead.iter().map(|e| e.conn).collect::<Vec<_>>(), vec![2]);
        st.put(idle("a", 3, 1, t0), t0, limit, 3, &mut dead);
        assert_eq!(st.idle.len(), 1);
        st.unregister(&flying);
        assert!(st.inflight.is_empty());
        st.unregister(&flying); // idempotent
    }

    // ---- engine with mock connections ------------------------------------------------------

    #[derive(Debug, Clone, Copy)]
    enum Reply {
        Ok {
            reusable: bool,
        },
        /// Fails before any response byte (server closed the idle connection).
        NoBytes,
        /// Fails after part of the response.
        AfterBytes,
        Timeout,
        /// Stalls while sending until stopped (or 5 s); nothing reaches the server.
        StallSending,
        /// Sends the whole request, then waits `ms` for the response (which arrives unless the
        /// request is stopped first).
        SentThenSlow {
            ms: u64,
        },
        Panic,
    }

    /// Wait until `ctl` says stop (true) or `limit` passes (false). Like `Sock::wait`, a wake-up
    /// that does not stop the request resets the event and keeps waiting.
    fn wait_until_stopped(ctl: &CancelCtl, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if ctl.should_stop() {
                return true;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            if ctl.wake.wait(left) {
                ctl.wake.reset();
            }
        }
    }

    struct MockConn {
        id: u32,
        alive: bool,
        replies: VecDeque<Reply>,
        ctl: Arc<CancelCtl>,
        log: Arc<Mutex<Vec<(u32, String)>>>,
    }

    impl Exchange for MockConn {
        fn idle_ok(&mut self) -> bool {
            self.alive
        }

        fn round_trip(&mut self, req: &Request<'_>, _t: &Timeouts) -> Result<http1::Response, ExchangeError> {
            assert!(req.path.starts_with('/'));
            let reply = self.replies.pop_front().unwrap_or(Reply::NoBytes);
            let fail = |kind, received_any| Err(ExchangeError::Receive(http1::ResponseError { kind, received_any }));
            self.log.lock().unwrap().push((self.id, req.path.to_owned()));
            let ok = |id: u32, reusable| Ok(http1::Response { status: 200, body: vec![id as u8], reusable });
            match reply {
                Reply::Ok { reusable } => {
                    self.ctl.mark_sent();
                    ok(self.id, reusable)
                }
                Reply::NoBytes => {
                    self.ctl.mark_sent();
                    fail(ReadError::Eof, false)
                }
                Reply::AfterBytes => {
                    self.ctl.mark_sent();
                    fail(ReadError::Truncated, true)
                }
                Reply::Timeout => {
                    self.ctl.mark_sent();
                    fail(ReadError::Io(io::ErrorKind::TimedOut.into()), false)
                }
                Reply::StallSending => {
                    let stopped = wait_until_stopped(&self.ctl, Duration::from_secs(5));
                    Err(ExchangeError::Send(if stopped { cancelled_io() } else { io::ErrorKind::TimedOut.into() }))
                }
                Reply::SentThenSlow { ms } => {
                    self.ctl.mark_sent();
                    if wait_until_stopped(&self.ctl, Duration::from_millis(ms)) {
                        fail(ReadError::Io(cancelled_io()), false)
                    } else {
                        ok(self.id, true)
                    }
                }
                Reply::Panic => panic!("mock connection panicked (expected in this test)"),
            }
        }
    }

    /// One scripted dial: `Ok((alive when idle, replies))` or a failure in the given phase.
    type Scripted = Result<(bool, Vec<Reply>), Phase>;

    struct MockDialer {
        script: Mutex<VecDeque<Scripted>>,
        next_id: AtomicU32,
        log: Arc<Mutex<Vec<(u32, String)>>>,
    }

    impl MockDialer {
        fn new(script: Vec<Scripted>) -> Self {
            Self { script: Mutex::new(script.into()), next_id: AtomicU32::new(1), log: Arc::default() }
        }
    }

    impl Dialer for MockDialer {
        type Conn = MockConn;

        fn dial(&self, _host: &str, _port: u16, ctl: &Arc<CancelCtl>, _t: &Timeouts) -> Result<MockConn, DirectError> {
            let next = self.script.lock().unwrap().pop_front().unwrap_or(Err(Phase::Connect));
            match next {
                Ok((alive, replies)) => Ok(MockConn {
                    id: self.next_id.fetch_add(1, Ordering::Relaxed),
                    alive,
                    replies: replies.into(),
                    ctl: ctl.clone(),
                    log: self.log.clone(),
                }),
                Err(phase) => Err(DirectError::new(phase, HttpError::Other("mock dial failure".into()))),
            }
        }
    }

    fn engine(script: Vec<Scripted>) -> Engine<MockDialer> {
        Engine::new(MockDialer::new(script), "Test/1.0", 443)
    }

    fn post(e: &Engine<MockDialer>) -> Result<HttpResponse, DirectError> {
        post_with(e, Interruptible::Always)
    }

    fn post_with(e: &Engine<MockDialer>, when: Interruptible) -> Result<HttpResponse, DirectError> {
        e.post("api.telegram.org", "/botX/getMe", b"{}", Duration::from_secs(5), when)
    }

    fn served_by(e: &Engine<MockDialer>) -> Vec<u32> {
        e.dialer.log.lock().unwrap().iter().map(|(id, _)| *id).collect()
    }

    const OK: Reply = Reply::Ok { reusable: true };

    #[test]
    fn sequential_requests_reuse_one_connection() {
        let e = engine(vec![Ok((true, vec![OK, OK, OK]))]);
        for _ in 0..3 {
            assert_eq!(post(&e).unwrap().body, vec![1]);
        }
        assert_eq!(e.dials.load(Ordering::Relaxed), 1);
        assert_eq!(e.reuses.load(Ordering::Relaxed), 2);
        assert_eq!(e.lock().idle.len(), 1);
        assert!(e.lock().inflight.is_empty());
    }

    #[test]
    fn connection_close_is_not_pooled() {
        let e = engine(vec![Ok((true, vec![Reply::Ok { reusable: false }])), Ok((true, vec![OK]))]);
        assert_eq!(post(&e).unwrap().body, vec![1]);
        assert!(e.lock().idle.is_empty());
        assert_eq!(post(&e).unwrap().body, vec![2]);
        assert_eq!(e.dials.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn dead_idle_connection_is_replaced_without_a_request() {
        let e = engine(vec![Ok((false, vec![OK, OK])), Ok((true, vec![OK]))]);
        assert_eq!(post(&e).unwrap().body, vec![1]);
        assert_eq!(post(&e).unwrap().body, vec![2]);
        assert_eq!(served_by(&e), vec![1, 2], "the closed connection carried no request");
        assert_eq!(e.reuses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stale_idle_connection_is_not_reused() {
        let mut e = engine(vec![Ok((true, vec![OK, OK])), Ok((true, vec![OK]))]);
        e.idle_limit = Duration::ZERO;
        assert_eq!(post(&e).unwrap().body, vec![1]);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(post(&e).unwrap().body, vec![2]);
        assert_eq!(e.dials.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn reused_connection_failing_before_any_byte_is_retried_once_on_a_fresh_one() {
        let e = engine(vec![Ok((true, vec![OK, Reply::NoBytes])), Ok((true, vec![OK, OK]))]);
        assert_eq!(post(&e).unwrap().body, vec![1]);
        assert_eq!(post(&e).unwrap().body, vec![2]);
        assert_eq!(served_by(&e), vec![1, 1, 2]);
        // the fresh connection went back to the pool
        assert_eq!(post(&e).unwrap().body, vec![2]);
    }

    #[test]
    fn retry_happens_at_most_once() {
        let e = engine(vec![Ok((true, vec![OK, Reply::NoBytes])), Ok((true, vec![Reply::NoBytes]))]);
        post(&e).unwrap();
        let err = post(&e).unwrap_err();
        assert_eq!(err.phase, Phase::Exchange);
        assert_eq!(served_by(&e), vec![1, 1, 2]);
        assert_eq!(e.dials.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn no_retry_after_response_bytes_timeouts_or_on_fresh_connections() {
        for (second, expect_timeout) in [(Reply::AfterBytes, false), (Reply::Timeout, true)] {
            let e = engine(vec![Ok((true, vec![OK, second])), Ok((true, vec![OK]))]);
            post(&e).unwrap();
            let err = post(&e).unwrap_err();
            assert_eq!(err.phase, Phase::Exchange);
            assert_eq!(err.error == HttpError::Timeout, expect_timeout, "{err:?}");
            assert_eq!(e.dials.load(Ordering::Relaxed), 1, "{second:?} must not be retried");
        }
        // the first request on a fresh connection is never retried
        let e = engine(vec![Ok((true, vec![Reply::NoBytes])), Ok((true, vec![OK]))]);
        assert_eq!(post(&e).unwrap_err().phase, Phase::Exchange);
        assert_eq!(e.dials.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dial_failures_keep_their_phase() {
        for phase in [Phase::Resolve, Phase::Connect, Phase::Tls] {
            let e = engine(vec![Err(phase)]);
            assert_eq!(post(&e).unwrap_err().phase, phase);
            assert!(e.lock().inflight.is_empty());
        }
    }

    #[test]
    fn invalid_targets_are_refused_locally() {
        let e = engine(vec![Ok((true, vec![OK]))]);
        for (host, path) in [("api.telegram.org", "/a b"), ("api.telegram.org", "x"), ("bad host", "/x"), ("", "/x")] {
            let err = e.post(host, path, b"", Duration::from_secs(1), Interruptible::Always).unwrap_err();
            assert_eq!(err.phase, Phase::Local);
            assert_eq!(err.error.to_string(), "invalid request target");
        }
        assert_eq!(e.dials.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn panics_are_contained_and_the_engine_keeps_working() {
        let e = engine(vec![Ok((true, vec![Reply::Panic])), Ok((true, vec![OK]))]);
        let err = post(&e).unwrap_err();
        assert!(err.error.to_string().contains("internal error"), "{err:?}");
        assert!(e.lock().inflight.is_empty() && e.lock().idle.is_empty());
        assert_eq!(post(&e).unwrap().body, vec![2]);
    }

    /// Run one request with `when` on its own (fresh) connection in another thread, interrupt it
    /// once it is in flight, and return its result and duration.
    fn interrupt_during(
        e: &Arc<Engine<MockDialer>>,
        when: Interruptible,
    ) -> (Result<HttpResponse, DirectError>, Duration) {
        let e1 = e.clone();
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            (post_with(&e1, when), started.elapsed())
        });
        let t0 = Instant::now();
        while e.lock().inflight.is_empty() && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        e.interrupt();
        worker.join().unwrap()
    }

    #[test]
    fn interrupt_cancels_in_flight_requests_and_drops_idle_connections() {
        let slow = Reply::SentThenSlow { ms: 5000 };
        let e = Arc::new(engine(vec![Ok((true, vec![OK])), Ok((true, vec![slow])), Ok((true, vec![OK]))]));
        // conn 1 idle in the pool; take it out so that the blocking request dials conn 2
        post(&e).unwrap();
        e.close_idle();
        let (result, took) = interrupt_during(&e, Interruptible::Always);
        let err = result.unwrap_err();
        assert_eq!(err.phase, Phase::Cancelled, "{err:?}");
        assert!(took < Duration::from_secs(2), "interrupt took {took:?}");
        assert!(e.lock().idle.is_empty() && e.lock().inflight.is_empty());
        // later requests work normally on a new connection
        assert_eq!(post(&e).unwrap().body, vec![3]);
    }

    #[test]
    fn interrupt_does_not_fail_an_until_sent_request_that_was_already_sent() {
        // The request is on the wire when the interrupt arrives: it must finish with its real
        // response (a "cancelled" error would make the caller send the message twice).
        let e = Arc::new(engine(vec![Ok((true, vec![Reply::SentThenSlow { ms: 600 }])), Ok((true, vec![OK]))]));
        let (result, took) = interrupt_during(&e, Interruptible::UntilSent);
        assert_eq!(result.unwrap().body, vec![1]);
        assert!(took >= Duration::from_millis(550), "finished normally after {took:?}");
        // the interrupted generation's connection is retired, nothing is left in flight
        assert!(e.lock().idle.is_empty() && e.lock().inflight.is_empty());
        assert_eq!(post(&e).unwrap().body, vec![2]);
    }

    #[test]
    fn interrupt_stops_an_until_sent_request_that_is_still_sending() {
        let e = Arc::new(engine(vec![Ok((true, vec![Reply::StallSending])), Ok((true, vec![OK]))]));
        let (result, took) = interrupt_during(&e, Interruptible::UntilSent);
        let err = result.unwrap_err();
        assert_eq!(err.phase, Phase::Cancelled, "{err:?}");
        assert!(took < Duration::from_secs(2), "interrupt took {took:?}");
        assert!(e.lock().idle.is_empty() && e.lock().inflight.is_empty());
        assert_eq!(post(&e).unwrap().body, vec![2]);
    }

    #[test]
    fn a_reused_connection_starts_each_request_unsent() {
        // `sent` from the previous request must not leak into the next one: an interrupt that
        // arrives before the second request has sent anything stops it.
        let ctl = CancelCtl::new().unwrap();
        ctl.begin(Interruptible::UntilSent);
        ctl.mark_sent();
        ctl.begin(Interruptible::UntilSent);
        ctl.cancel();
        assert!(ctl.should_stop());
        // ... while after `mark_sent` the same cancel is ignored by `UntilSent` only
        ctl.mark_sent();
        assert!(!ctl.should_stop());
        ctl.begin(Interruptible::Always);
        ctl.mark_sent();
        assert!(ctl.should_stop());
        // a new connection (dial phase) can always be stopped
        let fresh = CancelCtl::new().unwrap();
        fresh.cancel();
        assert!(fresh.should_stop());
    }

    // ---- real sockets, local only -----------------------------------------------------------

    /// A local listener that accepts and then stays silent (a dead server / dead path).
    fn silent_server() -> (u16, std::thread::JoinHandle<()>, Arc<AtomicBool>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let d2 = done.clone();
        let h = std::thread::spawn(move || {
            let _held = l.accept();
            while !d2.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        (port, h, done)
    }

    #[test]
    fn interrupt_unblocks_a_waiting_tls_handshake() {
        let (port, server, done) = silent_server();
        let client = Arc::new(DirectClient::with_port("Test/1.0", port));
        let c2 = client.clone();
        let h = std::thread::spawn(move || {
            let t = Instant::now();
            // `UntilSent`: even a send-protected request is stopped while it is still connecting
            (
                c2.post_classified("127.0.0.1", "/x", b"{}", Duration::from_secs(30), Interruptible::UntilSent),
                t.elapsed(),
            )
        });
        std::thread::sleep(Duration::from_millis(400));
        client.interrupt();
        let (r, took) = h.join().unwrap();
        done.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert_eq!(r.unwrap_err().phase, Phase::Cancelled);
        assert!(took < Duration::from_secs(3), "took {took:?}");
    }

    #[test]
    fn handshake_deadline_is_honoured() {
        let (port, server, done) = silent_server();
        let client = DirectClient::with_port("Test/1.0", port);
        let t = Instant::now();
        let r = client.post_classified("127.0.0.1", "/x", b"{}", Duration::from_millis(400), Interruptible::Always);
        let took = t.elapsed();
        done.store(true, Ordering::Relaxed);
        server.join().unwrap();
        let err = r.unwrap_err();
        assert_eq!(err.phase, Phase::Tls, "{err:?}");
        assert!(err.error.to_string().contains("timed out"), "{err:?}");
        assert!(took >= Duration::from_millis(350) && took < Duration::from_secs(3), "took {took:?}");
    }

    #[test]
    fn refused_and_closed_connections_are_connect_level() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        }; // listener dropped: connection refused
        let client = DirectClient::with_port("Test/1.0", port);
        let err = client
            .post_classified("127.0.0.1", "/x", b"{}", Duration::from_secs(5), Interruptible::Always)
            .unwrap_err();
        assert_eq!(err.phase, Phase::Connect, "{err:?}");
        assert!(err.phase.is_connect_level());
        assert!(!err.error.to_string().contains("127.0.0.1") && !err.error.to_string().contains("/x"));

        // accepted and closed at once: the handshake fails
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || drop(l.accept()));
        let client = DirectClient::with_port("Test/1.0", port);
        let err = client
            .post_classified("127.0.0.1", "/x", b"{}", Duration::from_secs(5), Interruptible::Always)
            .unwrap_err();
        h.join().unwrap();
        assert_eq!(err.phase, Phase::Tls, "{err:?}");
        assert_eq!(client.connections_opened(), 0);
    }

    #[test]
    fn sock_waits_honour_data_deadline_and_cancel() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        client.write_all(b"warm-up").unwrap();
        let ctl = CancelCtl::new().unwrap();
        let mut sock = Sock::new(server, ctl.clone(), Instant::now() + Duration::from_secs(5)).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(sock.read(&mut buf).unwrap(), 7);
        // deadline
        sock.deadline = Instant::now() + Duration::from_millis(200);
        let t = Instant::now();
        let e = sock.read(&mut buf).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() >= Duration::from_millis(190) && t.elapsed() < Duration::from_secs(2));
        // data arriving while waiting
        sock.deadline = Instant::now() + Duration::from_secs(5);
        let mut c2 = client.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.write_all(b"abc").unwrap();
        });
        assert_eq!(sock.read(&mut buf).unwrap(), 3);
        writer.join().unwrap();
        // cancel while blocked
        let ctl2 = ctl.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            ctl2.cancel();
        });
        let t = Instant::now();
        assert!(sock.read(&mut buf).is_err());
        assert!(t.elapsed() < Duration::from_secs(2), "cancel took {:?}", t.elapsed());
        canceller.join().unwrap();
        // writes fail once cancelled
        assert!(sock.write(b"x").is_err());
        // a new association on the same socket: writes work in non-blocking mode, peer close → EOF
        let mut sock2 =
            Sock::new(sock.tcp, CancelCtl::new().unwrap(), Instant::now() + Duration::from_secs(5)).unwrap();
        sock2.write_all(b"pong").unwrap();
        let mut got = [0u8; 4];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pong");
        drop(client);
        assert_eq!(sock2.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn sock_keeps_waiting_for_the_response_of_a_sent_until_sent_request() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let ctl = CancelCtl::new().unwrap();
        let mut sock = Sock::new(server, ctl.clone(), Instant::now() + Duration::from_secs(5)).unwrap();
        ctl.begin(Interruptible::UntilSent);
        ctl.mark_sent();
        let ctl2 = ctl.clone();
        let other = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            ctl2.cancel(); // the interrupt: must not end this read
            std::thread::sleep(Duration::from_millis(200));
            peer.write_all(b"reply").unwrap();
            peer
        });
        let t = Instant::now();
        let mut buf = [0u8; 16];
        let n = sock.read(&mut buf).unwrap();
        let took = t.elapsed();
        let _peer = other.join().unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert!(took >= Duration::from_millis(250) && took < Duration::from_secs(3), "took {took:?}");
        // the deadline still applies after such a cancel
        sock.deadline = Instant::now() + Duration::from_millis(150);
        assert_eq!(sock.read(&mut buf).unwrap_err().kind(), io::ErrorKind::TimedOut);
        // a new request on the same connection is stopped by the (still set) cancel flag
        ctl.begin(Interruptible::UntilSent);
        assert!(sock.write(b"x").is_err());
    }

    // ---- live checks (no token; run with `cargo test --lib net::direct -- --ignored`) --------

    /// (a) Two requests on one pooled connection to the real Bot API.
    #[test]
    #[ignore = "needs internet access to api.telegram.org"]
    fn live_invalid_token_twice_on_one_connection() {
        let c = DirectClient::new("PredatorTest/1.0");
        for round in 1..=2 {
            let t = Instant::now();
            let r = c
                .post_json("api.telegram.org", "/botINVALID/getMe", b"{}", Duration::from_secs(20))
                .unwrap_or_else(|e| panic!("round {round}: {e}"));
            println!("round {round}: HTTP {} in {:?}: {}", r.status, t.elapsed(), String::from_utf8_lossy(&r.body));
            assert!(r.status == 401 || r.status == 404, "status {}", r.status);
            assert!(r.body.starts_with(b"{\"ok\":false"), "JSON error body");
        }
        assert_eq!(c.connections_opened(), 1, "second request must reuse the connection");
        assert_eq!(c.connections_reused(), 1);
    }

    /// (b) Certificate validation stays on: bad certificates are rejected at the TLS phase.
    #[test]
    #[ignore = "needs internet access to badssl.com"]
    fn live_bad_certificates_are_rejected() {
        let c = DirectClient::new("PredatorTest/1.0");
        // Control: a valid certificate on the same infrastructure works (any HTTP status).
        let ok = c.post_classified("badssl.com", "/", b"{}", Duration::from_secs(20), Interruptible::Always);
        println!("badssl.com: {:?}", ok.as_ref().map(|r| r.status));
        assert!(ok.is_ok(), "control request failed: {ok:?}");
        for host in
            ["wrong.host.badssl.com", "expired.badssl.com", "self-signed.badssl.com", "untrusted-root.badssl.com"]
        {
            let err = c.post_classified(host, "/", b"{}", Duration::from_secs(20), Interruptible::Always).unwrap_err();
            println!("{host}: {err:?} -> {}", err.error);
            assert_eq!(err.phase, Phase::Tls, "{host}: {err:?}");
            assert!(err.error.to_string().contains("certificate"), "{host}: {}", err.error);
            assert!(!err.error.to_string().contains("badssl"), "the host must not appear in errors");
        }
    }

    /// Interrupt policies over real TLS: a response that takes 3 s is interrupted after 1 s. An
    /// `Always` request fails at once as cancelled; a sent `UntilSent` request (`sendMessage`)
    /// still gets its response.
    #[test]
    #[ignore = "needs internet access to httpbin.org"]
    fn live_interrupt_policies_on_a_slow_response() {
        for (when, expect_ok) in [(Interruptible::Always, false), (Interruptible::UntilSent, true)] {
            let c = Arc::new(DirectClient::new("PredatorTest/1.0"));
            let c2 = c.clone();
            let h = std::thread::spawn(move || {
                let t = Instant::now();
                (c2.post_classified("httpbin.org", "/delay/3", b"{}", Duration::from_secs(20), when), t.elapsed())
            });
            std::thread::sleep(Duration::from_millis(1500)); // connected and sent by now
            c.interrupt();
            let (r, took) = h.join().unwrap();
            println!("{when:?}: {:?} after {took:?}", r.as_ref().map(|r| r.status).map_err(|e| e.phase));
            if expect_ok {
                assert_eq!(r.unwrap().status, 200, "{when:?}");
                assert!(took >= Duration::from_millis(2900), "{when:?} finished early: {took:?}");
            } else {
                assert_eq!(r.unwrap_err().phase, Phase::Cancelled, "{when:?}");
                assert!(took < Duration::from_millis(2500), "{when:?} not interrupted: {took:?}");
            }
        }
    }

    /// (c) TLS 1.3 is negotiated: a TLS-1.3-only credential completes the handshake with the Bot
    /// API (and a TLS-1.2-only one does too, so both are usable).
    #[test]
    #[ignore = "needs internet access to api.telegram.org"]
    fn live_tls13_is_negotiated() {
        for (name, protocols) in [("TLS 1.3 only", &[Protocol::Tls13][..]), ("TLS 1.2 only", &[Protocol::Tls12][..])] {
            let e = Engine::new(TlsDialer::with_protocols(protocols), "PredatorTest/1.0", HTTPS_PORT);
            let r =
                e.post("api.telegram.org", "/botINVALID/getMe", b"{}", Duration::from_secs(20), Interruptible::Always);
            println!("{name}: {:?}", r.as_ref().map(|r| r.status).map_err(|e| e.error.to_string()));
            assert!(r.is_ok(), "{name}: {r:?}");
        }
    }
}
