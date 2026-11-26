//! Which HTTPS backend to start with: the `PREDATOR_HTTP_TRANSPORT` override and the machine's
//! proxy configuration, read from the registry (no WinHTTP call, so `winhttp.dll` stays unloaded).
//!
//! Sources, all read once when an [`super::http::HttpClient`] is created:
//! * `HKLM\...\Internet Settings\Connections\WinHttpSettings` — the static WinHTTP proxy
//!   (`netsh winhttp set proxy`). A proxy there → WinHTTP with `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`.
//! * The Internet Settings of the account (`HKCU`, i.e. LocalSystem's own hive for the service)
//!   and, when the `ProxySettingsPerUser = 0` policy makes them machine-wide, of `HKLM`: a manual
//!   proxy or a PAC (auto-config) URL → WinHTTP with `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`, which
//!   is what honours those settings. "Automatically detect settings" (WPAD) alone does not count:
//!   it is on by default almost everywhere, and the runtime fallback covers networks that need it.

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};

use super::winhttp::ProxyMode;
use crate::util::win::wide;

/// Environment variable that overrides the backend choice: `direct` or `winhttp`.
pub const TRANSPORT_ENV: &str = "PREDATOR_HTTP_TRANSPORT";

const CONNECTIONS_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const INTERNET_SETTINGS_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
const POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
/// Registry blobs larger than this are ignored (real ones are well under 1 KiB).
const MAX_BLOB: usize = 64 * 1024;

/// `PROXY_TYPE_*` flags of a connection-settings blob.
const FLAG_PROXY: u32 = 0x02;
const FLAG_AUTO_PROXY_URL: u32 = 0x04;
const FLAG_AUTO_DETECT: u32 = 0x08;

/// The `PREDATOR_HTTP_TRANSPORT` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Override {
    /// Not set (or `auto`): decide from the proxy configuration, fall back at run time.
    Auto,
    /// `direct`: always the direct client, no automatic fallback (diagnostics).
    Direct,
    /// `winhttp`: always WinHTTP.
    WinHttp,
}

/// Parse the override; the second value is true when a non-empty value was not recognised.
pub(crate) fn parse_override(value: Option<&str>) -> (Override, bool) {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else { return (Override::Auto, false) };
    if v.eq_ignore_ascii_case("direct") {
        (Override::Direct, false)
    } else if v.eq_ignore_ascii_case("winhttp") {
        (Override::WinHttp, false)
    } else if v.eq_ignore_ascii_case("auto") {
        (Override::Auto, false)
    } else {
        (Override::Auto, true)
    }
}

/// Proxy-relevant content of a connection-settings blob (`WinHttpSettings` or
/// `DefaultConnectionSettings`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProxyFlags {
    /// A manual proxy is enabled and its server list is not empty.
    pub manual_proxy: bool,
    /// An auto-config (PAC) URL is enabled and not empty.
    pub auto_config_url: bool,
    /// "Automatically detect settings" (WPAD).
    pub auto_detect: bool,
}

/// Parse a connection-settings blob:
/// `u32 version, u32 counter, u32 flags, u32 len + proxy, u32 len + bypass[, u32 len + PAC URL ...]`
/// (little endian). `WinHttpSettings` ends after the bypass list. `None` when the blob is too short
/// for the flags; lengths running past the end are treated as absent.
pub(crate) fn parse_connection_settings(blob: &[u8]) -> Option<ProxyFlags> {
    let flags = u32_at(blob, 8)?;
    let mut pos = 12;
    let proxy_len = take_string(blob, &mut pos);
    let _bypass_len = take_string(blob, &mut pos);
    let url_len = take_string(blob, &mut pos);
    Some(ProxyFlags {
        manual_proxy: flags & FLAG_PROXY != 0 && proxy_len.is_some_and(|n| n > 0),
        auto_config_url: flags & FLAG_AUTO_PROXY_URL != 0 && url_len.is_some_and(|n| n > 0),
        auto_detect: flags & FLAG_AUTO_DETECT != 0,
    })
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let bytes = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read `u32 len` + `len` bytes at `pos`; returns the length when both fit.
fn take_string(b: &[u8], pos: &mut usize) -> Option<usize> {
    let len = u32_at(b, *pos)? as usize;
    let end = pos.checked_add(4)?.checked_add(len)?;
    if end > b.len() {
        *pos = b.len();
        return None;
    }
    *pos = end;
    Some(len)
}

/// Proxy configuration found on this machine.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SystemProxy {
    /// A static WinHTTP proxy (`netsh winhttp set proxy`).
    pub winhttp_static: bool,
    /// A manual proxy or PAC URL in the Internet Settings that apply to this process.
    pub internet_settings: bool,
}

/// Backend chosen at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Start {
    Direct,
    WinHttp(ProxyMode),
}

/// The start decision plus why (for one log line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Initial {
    pub start: Start,
    /// Chosen by `PREDATOR_HTTP_TRANSPORT`: no automatic switching between direct and WinHTTP.
    pub forced: bool,
    pub reason: &'static str,
}

/// Decide the starting backend (pure).
pub(crate) fn initial_choice(over: Override, sys: SystemProxy) -> Initial {
    let winhttp_mode =
        if sys.winhttp_static || !sys.internet_settings { ProxyMode::Default } else { ProxyMode::Automatic };
    match over {
        Override::Direct => Initial { start: Start::Direct, forced: true, reason: "PREDATOR_HTTP_TRANSPORT=direct" },
        Override::WinHttp => {
            Initial { start: Start::WinHttp(winhttp_mode), forced: true, reason: "PREDATOR_HTTP_TRANSPORT=winhttp" }
        }
        Override::Auto if sys.winhttp_static => Initial {
            start: Start::WinHttp(ProxyMode::Default),
            forced: false,
            reason: "a WinHTTP proxy is configured (netsh winhttp)",
        },
        Override::Auto if sys.internet_settings => Initial {
            start: Start::WinHttp(ProxyMode::Automatic),
            forced: false,
            reason: "a proxy or PAC script is configured in the Internet Settings",
        },
        Override::Auto => Initial { start: Start::Direct, forced: false, reason: "no proxy is configured" },
    }
}

/// Read the proxy configuration from the registry (a few local reads, no network).
pub(crate) fn detect() -> SystemProxy {
    let winhttp_static = read_binary(HKEY_LOCAL_MACHINE, CONNECTIONS_KEY, "WinHttpSettings")
        .as_deref()
        .and_then(parse_connection_settings)
        .is_some_and(|f| f.manual_proxy);
    let machine_wide = read_dword(HKEY_LOCAL_MACHINE, POLICY_KEY, "ProxySettingsPerUser") == Some(0);
    let root = if machine_wide { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
    SystemProxy { winhttp_static, internet_settings: internet_settings_proxy(root) }
}

/// Manual proxy or PAC URL in the Internet Settings under `root`: the binary connection settings,
/// or the plain values that group policy writes (`ProxyEnable` + `ProxyServer`, `AutoConfigURL`).
fn internet_settings_proxy(root: HKEY) -> bool {
    let blob = read_binary(root, CONNECTIONS_KEY, "DefaultConnectionSettings")
        .as_deref()
        .and_then(parse_connection_settings)
        .is_some_and(|f| f.manual_proxy || f.auto_config_url);
    let manual = read_dword(root, INTERNET_SETTINGS_KEY, "ProxyEnable") == Some(1)
        && read_string(root, INTERNET_SETTINGS_KEY, "ProxyServer").is_some_and(|s| !s.trim().is_empty());
    let pac = read_string(root, INTERNET_SETTINGS_KEY, "AutoConfigURL").is_some_and(|s| !s.trim().is_empty());
    blob || manual || pac
}

/// `RegGetValueW` into a byte buffer of the value's size (bounded by [`MAX_BLOB`]).
fn read_raw(root: HKEY, subkey: &str, value: &str, flags: u32) -> Option<Vec<u8>> {
    let key = wide(subkey);
    let name = wide(value);
    let mut size: u32 = 0;
    // SAFETY: NUL-terminated strings; NULL data pointer queries the size only.
    let rc = unsafe { RegGetValueW(root, key.as_ptr(), name.as_ptr(), flags, null_mut(), null_mut(), &mut size) };
    if rc != ERROR_SUCCESS || size as usize > MAX_BLOB {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let mut got = size;
    // SAFETY: `buf` is writable for `got` bytes.
    let rc = unsafe {
        RegGetValueW(root, key.as_ptr(), name.as_ptr(), flags, null_mut(), buf.as_mut_ptr().cast(), &mut got)
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

fn read_binary(root: HKEY, subkey: &str, value: &str) -> Option<Vec<u8>> {
    read_raw(root, subkey, value, RRF_RT_REG_BINARY)
}

fn read_dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    read_raw(root, subkey, value, RRF_RT_REG_DWORD).and_then(|b| u32_at(&b, 0))
}

fn read_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let raw = read_raw(root, subkey, value, RRF_RT_REG_SZ)?;
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Some(String::from_utf16_lossy(&units[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(flags: u32, proxy: &str, bypass: &str, pac: Option<&str>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x46u32.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        for s in [Some(proxy), Some(bypass), pac].into_iter().flatten() {
            b.extend_from_slice(&(s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        b
    }

    #[test]
    fn winhttp_settings_reset_means_direct() {
        // `netsh winhttp reset proxy` (the value found on the development PC).
        let reset = [0x18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_connection_settings(&reset), Some(ProxyFlags::default()));
    }

    #[test]
    fn winhttp_settings_with_proxy() {
        // `netsh winhttp set proxy proxy-server="proxy.corp:8080" bypass-list="<local>"`
        let b = blob(3, "proxy.corp:8080", "<local>", None);
        let f = parse_connection_settings(&b).unwrap();
        assert!(f.manual_proxy && !f.auto_config_url && !f.auto_detect);
        // flag set but empty server list → no proxy
        assert!(!parse_connection_settings(&blob(3, "", "", None)).unwrap().manual_proxy);
        // server listed but flag clear (proxy disabled) → no proxy
        assert!(!parse_connection_settings(&blob(1, "p:1", "", None)).unwrap().manual_proxy);
    }

    #[test]
    fn internet_settings_blobs() {
        // LocalSystem default on the development PC: direct + auto-detect, nothing else.
        let ls = hex("4600000002000000090000000000000000000000000000000000000000000000");
        let f = parse_connection_settings(&ls).unwrap();
        assert_eq!(f, ProxyFlags { manual_proxy: false, auto_config_url: false, auto_detect: true });
        let pac = blob(0x05, "", "", Some("http://wpad.corp/proxy.pac"));
        assert!(parse_connection_settings(&pac).unwrap().auto_config_url);
        // PAC flag without URL, URL without flag
        assert!(!parse_connection_settings(&blob(0x05, "", "", Some(""))).unwrap().auto_config_url);
        assert!(!parse_connection_settings(&blob(0x01, "", "", Some("http://x/p.pac"))).unwrap().auto_config_url);
    }

    #[test]
    fn truncated_or_bogus_blobs() {
        assert_eq!(parse_connection_settings(&[]), None);
        assert_eq!(parse_connection_settings(&[0; 11]), None);
        // flags only: no strings → nothing usable, but no panic
        assert_eq!(parse_connection_settings(&[0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]), Some(ProxyFlags::default()));
        // a length running past the end
        let mut b = blob(3, "proxy:1", "", None);
        b.truncate(18);
        assert!(!parse_connection_settings(&b).unwrap().manual_proxy);
        let mut huge = vec![0u8; 16];
        huge[8] = 3;
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!parse_connection_settings(&huge).unwrap().manual_proxy);
    }

    #[test]
    fn override_parsing() {
        assert_eq!(parse_override(None), (Override::Auto, false));
        assert_eq!(parse_override(Some("  ")), (Override::Auto, false));
        assert_eq!(parse_override(Some("direct")), (Override::Direct, false));
        assert_eq!(parse_override(Some(" WinHTTP ")), (Override::WinHttp, false));
        assert_eq!(parse_override(Some("AUTO")), (Override::Auto, false));
        assert_eq!(parse_override(Some("curl")), (Override::Auto, true));
    }

    #[test]
    fn start_decision() {
        let none = SystemProxy::default();
        let stat = SystemProxy { winhttp_static: true, internet_settings: false };
        let ie = SystemProxy { winhttp_static: false, internet_settings: true };
        let both = SystemProxy { winhttp_static: true, internet_settings: true };
        let d = initial_choice(Override::Auto, none);
        assert_eq!((d.start, d.forced), (Start::Direct, false));
        assert_eq!(initial_choice(Override::Auto, stat).start, Start::WinHttp(ProxyMode::Default));
        assert_eq!(initial_choice(Override::Auto, ie).start, Start::WinHttp(ProxyMode::Automatic));
        assert_eq!(initial_choice(Override::Auto, both).start, Start::WinHttp(ProxyMode::Default));
        // overrides win and disable automatic switching
        for sys in [none, stat, ie, both] {
            let d = initial_choice(Override::Direct, sys);
            assert_eq!((d.start, d.forced), (Start::Direct, true));
            let w = initial_choice(Override::WinHttp, sys);
            assert!(w.forced && matches!(w.start, Start::WinHttp(_)));
        }
        assert_eq!(initial_choice(Override::WinHttp, ie).start, Start::WinHttp(ProxyMode::Automatic));
        assert_eq!(initial_choice(Override::WinHttp, none).start, Start::WinHttp(ProxyMode::Default));
    }

    #[test]
    fn live_registry_read_does_not_fail() {
        // Read-only registry access; whatever the machine has, the call must return.
        let sys = detect();
        println!("detected: {sys:?}");
        assert!(
            read_dword(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentMajorVersionNumber"
            )
            .is_some()
        );
        assert!(
            read_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
                .is_some_and(|s| s.contains("Windows"))
        );
        assert_eq!(read_binary(HKEY_LOCAL_MACHINE, r"SOFTWARE\Predator\does-not-exist", "x"), None);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
