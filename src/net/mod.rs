//! Networking: the HTTPS client (direct SChannel transport with a WinHTTP proxy fallback) and
//! connectivity-change notifications.
//!
//! * [`http`] — `HttpClient` facade (backend selection and fallback), `HttpError`, `HttpResponse`.
//! * [`direct`] — TcpStream + SChannel HTTP/1.1 keep-alive client (the normal path).
//! * [`winhttp`] — WinHTTP client, used only for proxies; re-exports the facade types for the
//!   `net::winhttp::{HttpClient, HttpError, HttpResponse}` contract.
//! * [`connectivity`] — `NotifyNetworkConnectivityHintChange` watcher.

pub mod connectivity;
pub mod direct;
pub mod http;
mod http1;
mod proxy;
pub mod winhttp;
