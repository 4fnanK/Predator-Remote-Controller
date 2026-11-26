//! Predator Remote Controller — shared library used by both binaries.
//!
//! * `predator-service.exe` — the LocalSystem Windows service (login monitor + Telegram bot)
//!   and its command-line management interface (install / uninstall / set-token / pair / ...).
//! * `predator-tray.exe` — the per-user notification-area (system tray) companion. It never
//!   monitors anything or talks to Telegram itself; it only talks to the service over a
//!   secured local named pipe.
//!
//! Design goals: near-zero idle CPU, a few MB of RAM, event-driven everything, no async runtime,
//! native Win32 APIs (WinHTTP, wevtapi, WTS, SCM) instead of large frameworks.

#![cfg(windows)]

pub mod config;
pub mod context;
pub mod features;
pub mod ipc;
pub mod logging;
pub mod monitor;
pub mod net;
pub mod notify;
pub mod pairing;
pub mod paths;
pub mod secrets;
pub mod service;
pub mod sys;
pub mod telegram;
pub mod tray;
pub mod util;

/// Product version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Human readable product name.
pub const PRODUCT_NAME: &str = "Predator Remote Controller";
