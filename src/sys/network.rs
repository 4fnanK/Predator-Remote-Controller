//! `/network`: connection type, Wi-Fi SSID, local IPv4, internet status (on demand only).
//!
//! * Primary interface = the route Windows would use towards Telegram (GetBestRoute2; no packet
//!   is sent). Classified with GetIfEntry2 (`Type`, `PhysicalMediumType`, HardwareInterface bit).
//! * When that route goes through a tunnel/VPN (Tailscale exit node, full-tunnel VPN), the VPN is
//!   reported separately and the physical uplink (Up, has a gateway, hardware, lowest metric) is
//!   shown as the connection.
//! * SSID (Wi-Fi only): WLAN API → WinRT `GetConnectedSsid` → NLM `INetwork::GetDescription`.
//!   Since Windows 11 24H2 the WLAN API needs location consent (also for SYSTEM); the WinRT and
//!   NLM fallbacks do not. Nothing else is ever collected (no BSSID, scans, profiles or keys).
//! * The SSID lookup never runs inside the service: the WinRT/COM/WLAN stack it loads keeps
//!   ~1 MB private memory and several threads alive for the life of the process (measured). It
//!   runs in a short-lived child, `<exe dir>\predator-service.exe ssid-helper` (fixed argument,
//!   no input), started through [`process::run_with_timeout`] (hidden, kill-on-close job, 8 s
//!   timeout). The helper ([`ssid_helper_main`]) re-resolves the Wi-Fi interface itself and
//!   prints one JSON line `{"ssid":string|null,"note":string|null}`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr::null;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NO_DATA, ERROR_NOT_FOUND,
    ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetBestRoute2, GetIfEntry2, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PROP_VIRTUAL,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IF_TYPE_WWANPP, IF_TYPE_WWANPP2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, NdisPhysicalMedium802_3, NdisPhysicalMediumNative802_11, NdisPhysicalMediumWirelessWan,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_INET};

use super::process;
use super::{ConnectionType, NetworkInfo};
use crate::util::win::{error_message, from_wide, from_wide_ptr};

/// api.telegram.org (149.154.167.220) — only used for the route lookup, nothing is sent.
const PROBE_V4: [u8; 4] = [149, 154, 167, 220];
/// Telegram's IPv6 range (2001:67c:4e8:f004::9) for IPv6-only networks.
const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x067c, 0x04e8, 0xf004, 0, 0, 0, 0x9);

/// `MIB_IF_ROW2.InterfaceAndOperStatusFlags` bits.
const IF_FLAG_HARDWARE: u8 = 0x01;

/// Hidden subcommand of predator-service.exe that runs [`ssid_helper_main`].
pub const SSID_HELPER_ARG: &str = "ssid-helper";
/// Upper bound for the helper (normally 50–300 ms including process start; a one-off 33 s stall
/// of the first WLAN/WinRT call was observed on this machine, so never wait unbounded).
const SSID_HELPER_TIMEOUT: Duration = Duration::from_secs(8);
/// Longest SSID / note accepted from the helper (SSIDs are ≤ 32 bytes; NLM names can be longer).
const MAX_SSID_CHARS: usize = 64;
const MAX_NOTE_CHARS: usize = 200;

/// Collect the network summary for the primary (default-route) interface.
pub fn network_info() -> Result<NetworkInfo, String> {
    let mut info = collect()?;
    info.internet = crate::net::connectivity::current();
    Ok(info)
}

/// Everything except the internet status (which comes from the connectivity hint). The SSID
/// comes from the `ssid-helper` child process (see the module docs).
pub fn collect() -> Result<NetworkInfo, String> {
    let (mut info, wifi_guid) = collect_interfaces()?;
    if wifi_guid.is_some() {
        let (ssid, note) = ssid_via_helper(&crate::paths::service_exe_path());
        info.ssid = ssid;
        info.ssid_note = note;
    }
    Ok(info)
}

/// Entry point of `predator-service.exe ssid-helper`: resolve the SSID of the Wi-Fi interface
/// that carries the primary connection, in this (short-lived) process — WLAN API → WinRT → NLM —
/// and print exactly one JSON line `{"ssid":string|null,"note":string|null}` to stdout. Always
/// returns exit code 0; failures are reported through `note`. Needs no logging or data directory.
pub fn ssid_helper_main() -> i32 {
    use std::io::Write;
    let (ssid, note) = std::panic::catch_unwind(helper_lookup)
        .unwrap_or_else(|_| (None, Some("SSID unavailable — internal error in the Wi-Fi helper".into())));
    let line = helper_reply_line(ssid, note);
    let mut out = std::io::stdout().lock();
    // Nothing useful can be done if the parent closed the pipe.
    let _ = out.write_all(line.as_bytes()).and_then(|()| out.write_all(b"\n")).and_then(|()| out.flush());
    0
}

/// The helper's lookup: find the Wi-Fi interface like [`collect`] does, then ask Windows.
fn helper_lookup() -> (Option<String>, Option<String>) {
    match collect_interfaces() {
        Ok((_, Some(guid))) => wifi::lookup(guid),
        Ok((_, None)) => (None, Some("SSID unavailable — no Wi-Fi connection found".into())),
        Err(e) => (None, Some(format!("SSID unavailable — {e}"))),
    }
}

/// One line of the helper protocol.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct HelperReply {
    ssid: Option<String>,
    note: Option<String>,
}

fn helper_reply_line(ssid: Option<String>, note: Option<String>) -> String {
    let reply = HelperReply { note: if ssid.is_some() { None } else { note }, ssid };
    serde_json::to_string(&reply).unwrap_or_else(|_| r#"{"ssid":null,"note":"SSID unavailable"}"#.into())
}

/// Parse the helper's stdout: the last line that is a valid reply wins. Values are cleaned and
/// length-limited again (defence in depth). `None` when no valid line was printed.
fn parse_helper_output(stdout: &str) -> Option<(Option<String>, Option<String>)> {
    let reply: HelperReply = stdout
        .lines()
        .rev()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .find_map(|l| serde_json::from_str(l).ok())?;
    let ssid = reply.ssid.as_deref().and_then(clean_text).map(|s| crate::util::truncate_chars(&s, MAX_SSID_CHARS));
    if ssid.is_some() {
        return Some((ssid, None));
    }
    let note = reply
        .note
        .as_deref()
        .and_then(clean_text)
        .map(|n| crate::util::truncate_chars(&n, MAX_NOTE_CHARS))
        .unwrap_or_else(|| "SSID unavailable".into());
    Some((None, Some(note)))
}

/// Run `<helper_exe> ssid-helper` and translate its answer (never fails: errors become notes).
fn ssid_via_helper(helper_exe: &Path) -> (Option<String>, Option<String>) {
    match process::run_with_timeout(helper_exe, &[SSID_HELPER_ARG], SSID_HELPER_TIMEOUT) {
        Ok(out) => helper_result(&out),
        Err(e) => {
            crate::log_warn!("network: cannot run the Wi-Fi helper: {e}");
            (None, Some("SSID unavailable — the Wi-Fi helper could not be started".into()))
        }
    }
}

fn helper_result(out: &process::ProcessOutput) -> (Option<String>, Option<String>) {
    if out.timed_out {
        return (None, Some("SSID unavailable — Windows did not answer in time".into()));
    }
    match parse_helper_output(&out.stdout) {
        Some(r) => r,
        None => {
            crate::log_warn!(
                "network: the Wi-Fi helper gave no answer (exit {:?}): {}",
                out.exit_code,
                crate::util::truncate_chars(&out.combined(), 200)
            );
            (None, Some("SSID unavailable — the Wi-Fi helper failed".into()))
        }
    }
}

/// Route/interface classification without the SSID: the summary plus the interface GUID of the
/// Wi-Fi adapter carrying the connection (if the connection is Wi-Fi).
fn collect_interfaces() -> Result<(NetworkInfo, Option<u128>), String> {
    let route = match best_route() {
        Ok(Some(r)) => r,
        Ok(None) => return Ok((NetworkInfo { connection: ConnectionType::None, ..Default::default() }, None)),
        Err(code) => {
            return Err(format!(
                "Could not determine the primary network interface: {} (error {code})",
                error_message(code)
            ));
        }
    };
    let adapters = adapters();
    let primary_adapter = adapters.iter().find(|a| a.luid == route.luid);
    let primary_if = if_entry(route.luid);
    let alias = primary_adapter
        .map(|a| a.friendly_name.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| primary_if.as_ref().map(|f| f.alias.clone()).filter(|s| !s.is_empty()));
    let description = primary_if
        .as_ref()
        .map(|f| f.description.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| primary_adapter.map(|a| a.description.clone()))
        .unwrap_or_default();
    let medium = primary_if.as_ref().map_or(Medium::Other, |f| classify(f.if_type, f.medium, f.flags));
    let primary_ipv4 = route.src.or_else(|| primary_adapter.and_then(|a| a.ipv4));

    let mut info = NetworkInfo::default();
    let mut wifi_guid = None;

    if medium.is_virtual() && !is_hyperv_vswitch(&description) {
        // Default route through a tunnel/VPN: report it and look for the physical uplink.
        let candidates: Vec<UplinkCandidate> = adapters
            .iter()
            .map(|a| {
                let cheap_ok = a.luid != route.luid && a.up && a.has_gateway && is_uplink_type(a.if_type);
                let facts = if cheap_ok { if_entry(a.luid) } else { None };
                UplinkCandidate {
                    if_type: a.if_type,
                    up: a.up && a.luid != route.luid,
                    has_gateway: a.has_gateway,
                    hardware: facts.as_ref().is_some_and(|f| f.flags & IF_FLAG_HARDWARE != 0),
                    metric: a.metric,
                    medium: facts.as_ref().map_or(Medium::Other, |f| classify(f.if_type, f.medium, f.flags)),
                    guid: facts.as_ref().map_or(0, |f| f.guid),
                }
            })
            .collect();
        match pick_uplink(&candidates) {
            Some(i) => {
                let up = &adapters[i];
                let c = &candidates[i];
                info.vpn = Some(vpn_label(alias.as_deref().unwrap_or(""), &description));
                info.connection = connection_for(c.medium, &up.description);
                info.adapter = Some(up.friendly_name.clone()).filter(|s| !s.is_empty());
                info.ipv4 = up.ipv4.map(|ip| ip.to_string());
                if c.medium == Medium::WiFi {
                    wifi_guid = Some(c.guid);
                }
            }
            None => {
                if medium == Medium::VirtualEthernet {
                    info.connection = ConnectionType::Other("Ethernet (virtual switch)".into());
                } else {
                    info.connection = ConnectionType::Other("VPN tunnel".into());
                    info.vpn = Some(vpn_label(alias.as_deref().unwrap_or(""), &description));
                }
                info.adapter = alias;
                info.ipv4 = primary_ipv4.map(|ip| ip.to_string());
            }
        }
    } else {
        info.connection = if medium == Medium::VirtualEthernet {
            ConnectionType::Other("Ethernet (virtual switch)".into())
        } else {
            connection_for(medium, &description)
        };
        info.adapter = alias;
        info.ipv4 = primary_ipv4.map(|ip| ip.to_string());
        if medium == Medium::WiFi {
            wifi_guid = primary_if.as_ref().map(|f| f.guid);
        }
    }

    Ok((info, wifi_guid))
}

// ---------------------------------------------------------------------------------------------
// Pure helpers.
// ---------------------------------------------------------------------------------------------

/// Physical medium of an interface, as far as `/network` cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Medium {
    WiFi,
    Ethernet,
    Cellular,
    /// IfType 6 without the hardware bit: Hyper-V vEthernet, VMware/VirtualBox, VPN miniports.
    VirtualEthernet,
    /// Tunnel/VPN (Tailscale/Wintun, TAP, OpenVPN DCO, PPP/RAS ...).
    Tunnel,
    Loopback,
    Other,
}

impl Medium {
    fn is_virtual(self) -> bool {
        matches!(self, Medium::VirtualEthernet | Medium::Tunnel)
    }
}

/// Classify from `MIB_IF_ROW2` `Type`, `PhysicalMediumType` and `InterfaceAndOperStatusFlags`.
fn classify(if_type: u32, physical_medium: i32, flags: u8) -> Medium {
    let hardware = flags & IF_FLAG_HARDWARE != 0;
    match if_type {
        IF_TYPE_SOFTWARE_LOOPBACK => Medium::Loopback,
        IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL => Medium::Tunnel,
        IF_TYPE_IEEE80211 => Medium::WiFi,
        _ if physical_medium == NdisPhysicalMediumNative802_11 => Medium::WiFi,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => Medium::Cellular,
        _ if physical_medium == NdisPhysicalMediumWirelessWan => Medium::Cellular,
        IF_TYPE_ETHERNET_CSMACD if hardware => Medium::Ethernet,
        IF_TYPE_ETHERNET_CSMACD => Medium::VirtualEthernet,
        _ if hardware && physical_medium == NdisPhysicalMedium802_3 => Medium::Ethernet,
        _ if hardware => Medium::Other,
        // PPP (RAS VPN) and every other software interface.
        _ => Medium::Tunnel,
    }
}

fn connection_for(m: Medium, description: &str) -> ConnectionType {
    match m {
        Medium::WiFi => ConnectionType::WiFi,
        Medium::Ethernet => ConnectionType::Ethernet,
        Medium::Cellular => ConnectionType::Cellular,
        Medium::VirtualEthernet => ConnectionType::Other("Ethernet (virtual switch)".into()),
        Medium::Tunnel => ConnectionType::Other("VPN tunnel".into()),
        Medium::Loopback => ConnectionType::Other("Loopback".into()),
        Medium::Other => {
            let d = description.trim();
            ConnectionType::Other(if d.is_empty() { "Network adapter".into() } else { d.to_string() })
        }
    }
}

/// Last-resort name filter: a Hyper-V external switch carries the host IP on vEthernet.
fn is_hyperv_vswitch(description: &str) -> bool {
    description.to_ascii_lowercase().contains("hyper-v virtual ethernet")
}

fn is_uplink_type(if_type: u32) -> bool {
    matches!(if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_WWANPP | IF_TYPE_WWANPP2)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UplinkCandidate {
    if_type: u32,
    up: bool,
    has_gateway: bool,
    hardware: bool,
    metric: u32,
    medium: Medium,
    guid: u128,
}

/// Index of the physical uplink: Up, has a gateway, Ethernet/Wi-Fi/WWAN, hardware, lowest metric.
fn pick_uplink(c: &[UplinkCandidate]) -> Option<usize> {
    c.iter()
        .enumerate()
        .filter(|(_, c)| c.up && c.has_gateway && c.hardware && is_uplink_type(c.if_type))
        .min_by_key(|(i, c)| (c.metric, *i))
        .map(|(i, _)| i)
}

/// `Tailscale` + `Tailscale Tunnel` → `Tailscale Tunnel`; `Ethernet 3` + `TAP-Windows Adapter V9`
/// → `Ethernet 3 (TAP-Windows Adapter V9)`.
fn vpn_label(alias: &str, description: &str) -> String {
    let (a, d) = (alias.trim(), description.trim());
    let (al, dl) = (a.to_lowercase(), d.to_lowercase());
    match (a.is_empty(), d.is_empty()) {
        (true, true) => "VPN".into(),
        (true, false) => d.into(),
        (false, true) => a.into(),
        _ if dl.contains(&al) => d.into(),
        _ if al.contains(&dl) => a.into(),
        _ => format!("{a} ({d})"),
    }
}

/// `IN_ADDR.S_un.S_addr` is in network byte order: its in-memory bytes are the octets.
fn ipv4_from_s_addr(s_addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(s_addr.to_ne_bytes())
}

/// Control characters removed, trimmed; `None` when nothing is left.
fn clean_text(s: &str) -> Option<String> {
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_link_local() && !ip.is_loopback()
}

fn guid_u128(g: &windows_sys::core::GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | u64::from_be_bytes(g.data4) as u128
}

// ---------------------------------------------------------------------------------------------
// IP Helper calls.
// ---------------------------------------------------------------------------------------------

struct Route {
    luid: u64,
    src: Option<Ipv4Addr>,
}

/// Best route towards Telegram (IPv4, then IPv6). `Ok(None)` = no route at all.
fn best_route() -> Result<Option<Route>, u32> {
    let mut dest = SOCKADDR_INET::default();
    dest.Ipv4 = SOCKADDR_IN { sin_family: AF_INET, ..Default::default() };
    dest.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(PROBE_V4);
    match route_to(&dest) {
        Ok(r) => return Ok(Some(r)),
        Err(ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE | ERROR_NOT_FOUND) => {}
        Err(code) => return Err(code),
    }
    let mut dest6 = SOCKADDR_INET::default();
    dest6.Ipv6.sin6_family = AF_INET6;
    dest6.Ipv6.sin6_addr.u.Byte = PROBE_V6.octets();
    Ok(route_to(&dest6).ok())
}

fn route_to(dest: &SOCKADDR_INET) -> Result<Route, u32> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut src = SOCKADDR_INET::default();
    // SAFETY: valid in/out structures; a null LUID and index 0 let the stack choose the interface.
    let rc = unsafe { GetBestRoute2(null(), 0, null(), dest, 0, &mut row, &mut src) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    // SAFETY: unions of plain data; the family field tells which variant is valid.
    let (luid, src) = unsafe {
        let ip = (src.si_family == AF_INET)
            .then(|| ipv4_from_s_addr(src.Ipv4.sin_addr.S_un.S_addr))
            .filter(|ip| usable_ipv4(*ip));
        (row.InterfaceLuid.Value, ip)
    };
    Ok(Route { luid, src })
}

/// Interface facts from GetIfEntry2.
#[derive(Clone, Debug, Default)]
struct IfFacts {
    guid: u128,
    if_type: u32,
    medium: i32,
    flags: u8,
    alias: String,
    description: String,
}

fn if_entry(luid: u64) -> Option<IfFacts> {
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid.Value = luid;
    // SAFETY: `row` is a valid MIB_IF_ROW2 with its LUID set.
    if unsafe { GetIfEntry2(&mut row) } != ERROR_SUCCESS {
        return None;
    }
    Some(IfFacts {
        guid: guid_u128(&row.InterfaceGuid),
        if_type: row.Type,
        medium: row.PhysicalMediumType,
        flags: row.InterfaceAndOperStatusFlags._bitfield,
        alias: from_wide(&row.Alias),
        description: from_wide(&row.Description),
    })
}

/// One IPv4-enabled adapter from GetAdaptersAddresses.
#[derive(Clone, Debug, Default)]
struct Adapter {
    luid: u64,
    if_type: u32,
    up: bool,
    has_gateway: bool,
    metric: u32,
    friendly_name: String,
    description: String,
    ipv4: Option<Ipv4Addr>,
}

fn adapters() -> Vec<Adapter> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
    // 15 KB initial buffer (Microsoft's recommendation), u64 for alignment.
    let mut buf: Vec<u64> = vec![0; 15 * 1024 / 8];
    for _ in 0..4 {
        let mut size = (buf.len() * 8) as u32;
        // SAFETY: `buf` is `size` bytes long and 8-byte aligned.
        let rc = unsafe { GetAdaptersAddresses(AF_INET as u32, flags, null(), buf.as_mut_ptr().cast(), &mut size) };
        match rc {
            ERROR_SUCCESS => {
                // SAFETY: on success the buffer holds a linked list of IP_ADAPTER_ADDRESSES_LH
                // whose pointers all point into `buf`, which outlives the walk.
                return unsafe { walk_adapters(buf.as_ptr().cast()) };
            }
            ERROR_BUFFER_OVERFLOW => buf = vec![0; (size as usize).div_ceil(8) + 64],
            ERROR_NO_DATA => return Vec::new(),
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

/// # Safety
/// `first` must be null or the head of a valid adapter list.
unsafe fn walk_adapters(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Adapter> {
    let mut out = Vec::new();
    let mut p = first;
    // SAFETY: caller guarantees the list is valid; every pointer is checked for null.
    unsafe {
        while !p.is_null() && out.len() < 256 {
            let a = &*p;
            let mut ipv4 = None;
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let ua = &*u;
                let sa = ua.Address.lpSockaddr;
                if !sa.is_null() && (*sa).sa_family == AF_INET {
                    let ip = ipv4_from_s_addr((*sa.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr);
                    if usable_ipv4(ip) {
                        ipv4 = Some(ip);
                        break;
                    }
                }
                u = ua.Next;
            }
            out.push(Adapter {
                luid: a.Luid.Value,
                if_type: a.IfType,
                up: a.OperStatus == IfOperStatusUp,
                has_gateway: !a.FirstGatewayAddress.is_null(),
                metric: a.Ipv4Metric,
                friendly_name: from_wide_ptr(a.FriendlyName),
                description: from_wide_ptr(a.Description),
                ipv4,
            });
            p = a.Next;
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Wi-Fi SSID.
// ---------------------------------------------------------------------------------------------

mod wifi {
    use std::ptr::{addr_of, null, null_mut};
    use std::sync::OnceLock;

    use windows::Networking::Connectivity::{ConnectionProfile, NetworkInformation};
    use windows::Win32::Networking::NetworkListManager::{INetworkConnection, INetworkListManager, NetworkListManager};
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoIncrementMTAUsage, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::NetworkManagement::WiFi::{
        WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces,
        WlanFreeMemory, WlanOpenHandle, WlanQueryInterface, wlan_interface_state_connected,
        wlan_intf_opcode_current_connection,
    };

    use super::guid_u128;

    /// Result of the (location-gated) WLAN API query.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum WlanOutcome {
        Ssid(String),
        /// ERROR_ACCESS_DENIED: no location consent (Windows 11 24H2+).
        Denied,
        /// WLAN AutoConfig (wlansvc) is not running.
        ServiceOff,
        NotConnected,
        Failed(u32),
    }

    /// The lookup for interface `target` (interface GUID): WLAN API → WinRT → NLM. Returns
    /// (ssid, note when unavailable). Runs only in the `ssid-helper` process (see the module
    /// docs), on its main thread; the parent enforces the timeout and kills the helper if needed.
    pub(super) fn lookup(target: u128) -> (Option<String>, Option<String>) {
        let wlan = wlan_ssid(target);
        if let WlanOutcome::Ssid(s) = wlan {
            return (Some(s), None);
        }
        let _com = ComApartment::enter();
        if let Ok(Some(s)) = winrt_ssid(target) {
            return (Some(s), None);
        }
        if let Ok(Some(s)) = nlm_ssid(target) {
            return (Some(s), None);
        }
        (None, Some(unavailable_note(&wlan)))
    }

    pub(super) fn unavailable_note(wlan: &WlanOutcome) -> String {
        match wlan {
            WlanOutcome::Denied => "SSID unavailable — Windows location services are off".into(),
            WlanOutcome::ServiceOff => "SSID unavailable — the WLAN AutoConfig service is not running".into(),
            WlanOutcome::NotConnected => "SSID unavailable — the Wi-Fi adapter reports no connection".into(),
            WlanOutcome::Failed(code) => format!("SSID unavailable — the Wi-Fi query failed (error {code})"),
            WlanOutcome::Ssid(_) => "SSID unavailable".into(),
        }
    }

    /// Raw SSID bytes → display string (lossy UTF-8, control characters removed).
    pub(super) fn ssid_from_bytes(bytes: &[u8]) -> Option<String> {
        clean_ssid(&String::from_utf8_lossy(bytes))
    }

    pub(super) fn clean_ssid(s: &str) -> Option<String> {
        super::clean_text(s)
    }

    struct WlanHandle(HANDLE);
    impl Drop for WlanHandle {
        fn drop(&mut self) {
            // SAFETY: handle from WlanOpenHandle, closed once.
            unsafe {
                WlanCloseHandle(self.0, null());
            }
        }
    }

    /// Memory returned by the WLAN API.
    struct WlanMem(*mut core::ffi::c_void);
    impl Drop for WlanMem {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: pointer allocated by the WLAN API, freed once.
                unsafe { WlanFreeMemory(self.0) };
            }
        }
    }

    fn wlan_ssid(target: u128) -> WlanOutcome {
        let mut negotiated = 0u32;
        let mut h: HANDLE = null_mut();
        // SAFETY: valid out-pointers; client version 2 (Vista+).
        let rc = unsafe { WlanOpenHandle(2, null(), &mut negotiated, &mut h) };
        if rc != ERROR_SUCCESS {
            return if rc == ERROR_SERVICE_NOT_ACTIVE { WlanOutcome::ServiceOff } else { WlanOutcome::Failed(rc) };
        }
        let h = WlanHandle(h);
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = null_mut();
        // SAFETY: valid client handle and out-pointer.
        let rc = unsafe { WlanEnumInterfaces(h.0, null(), &mut list) };
        if rc != ERROR_SUCCESS || list.is_null() {
            return WlanOutcome::Failed(rc);
        }
        let _list_mem = WlanMem(list.cast());
        // SAFETY: `list` points to a WLAN_INTERFACE_INFO_LIST followed by `dwNumberOfItems` entries.
        let infos: &[WLAN_INTERFACE_INFO] = unsafe {
            let n = ((*list).dwNumberOfItems as usize).min(64);
            std::slice::from_raw_parts(addr_of!((*list).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>(), n)
        };
        let iface = infos
            .iter()
            .find(|i| guid_u128(&i.InterfaceGuid) == target)
            .or_else(|| infos.iter().find(|i| i.isState == wlan_interface_state_connected));
        let Some(iface) = iface else {
            return WlanOutcome::NotConnected;
        };
        if iface.isState != wlan_interface_state_connected {
            return WlanOutcome::NotConnected;
        }
        let mut size = 0u32;
        let mut data: *mut core::ffi::c_void = null_mut();
        // SAFETY: valid handle and interface GUID; `data` receives WLAN-allocated memory freed below.
        let rc = unsafe {
            WlanQueryInterface(
                h.0,
                &iface.InterfaceGuid,
                wlan_intf_opcode_current_connection,
                null(),
                &mut size,
                &mut data,
                null_mut(),
            )
        };
        if rc == ERROR_ACCESS_DENIED {
            return WlanOutcome::Denied;
        }
        if rc != ERROR_SUCCESS || data.is_null() {
            return WlanOutcome::Failed(rc);
        }
        let _data_mem = WlanMem(data);
        if (size as usize) < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
            return WlanOutcome::Failed(rc);
        }
        // SAFETY: `data` holds a WLAN_CONNECTION_ATTRIBUTES of at least its size. Only the SSID is read.
        let ssid = unsafe {
            let attrs = &*(data.cast::<WLAN_CONNECTION_ATTRIBUTES>());
            let s = &attrs.wlanAssociationAttributes.dot11Ssid;
            let n = (s.uSSIDLength as usize).min(s.ucSSID.len());
            ssid_from_bytes(&s.ucSSID[..n])
        };
        match ssid {
            Some(s) => WlanOutcome::Ssid(s),
            None => WlanOutcome::NotConnected,
        }
    }

    /// COM/WinRT initialization for the calling thread (MTA). Uninitializes only what it
    /// initialized. The process-wide MTA is pinned once (CoIncrementMTAUsage, never released)
    /// because the `windows` crate caches agile activation factories for the process lifetime:
    /// COM must never be fully torn down underneath that cache.
    struct ComApartment {
        uninit: bool,
    }

    impl ComApartment {
        fn enter() -> Self {
            static MTA_PIN: OnceLock<bool> = OnceLock::new();
            MTA_PIN.get_or_init(|| {
                // SAFETY: plain COM call; the cookie is intentionally kept for the process lifetime.
                unsafe { CoIncrementMTAUsage() }.is_ok()
            });
            // SAFETY: plain COM call; S_OK/S_FALSE must be balanced with CoUninitialize, while
            // RPC_E_CHANGED_MODE (thread already STA) must not be.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            Self { uninit: hr.is_ok() }
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.uninit {
                // SAFETY: balances the successful CoInitializeEx on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn profile_ssid(p: &ConnectionProfile, target: u128) -> Option<String> {
        if !p.IsWlanConnectionProfile().ok()? {
            return None;
        }
        let id = p.NetworkAdapter().ok()?.NetworkAdapterId().ok()?;
        if id.to_u128() != target {
            return None;
        }
        let ssid = p.WlanConnectionProfileDetails().ok()?.GetConnectedSsid().ok()?;
        clean_ssid(&ssid.to_string_lossy())
    }

    /// WinRT `WlanConnectionProfileDetails.GetConnectedSsid` (no location consent needed).
    fn winrt_ssid(target: u128) -> windows::core::Result<Option<String>> {
        // Cheap first try: the internet profile is usually the Wi-Fi one.
        if let Ok(p) = NetworkInformation::GetInternetConnectionProfile()
            && let Some(s) = profile_ssid(&p, target)
        {
            return Ok(Some(s));
        }
        // Lists every saved profile; only the connected one has a non-empty SSID.
        let profiles = NetworkInformation::GetConnectionProfiles()?;
        let n = profiles.Size()?.min(1024);
        for i in 0..n {
            if let Ok(p) = profiles.GetAt(i)
                && let Some(s) = profile_ssid(&p, target)
            {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    /// NLM: the connection on adapter `target` → its network's description (the SSID by default).
    fn nlm_ssid(target: u128) -> windows::core::Result<Option<String>> {
        // SAFETY: standard COM activation and calls on interfaces we own.
        unsafe {
            let nlm: INetworkListManager =
                CoCreateInstance(&NetworkListManager, None::<&windows::core::IUnknown>, CLSCTX_ALL)?;
            let conns = nlm.GetNetworkConnections()?;
            for _ in 0..256 {
                let mut item: [Option<INetworkConnection>; 1] = [None];
                let mut fetched = 0u32;
                conns.Next(&mut item, Some(&mut fetched))?;
                if fetched == 0 {
                    break;
                }
                let Some(conn) = item[0].take() else {
                    break;
                };
                if !conn.GetAdapterId().is_ok_and(|g| g.to_u128() == target) {
                    continue;
                }
                let desc = conn.GetNetwork()?.GetDescription()?;
                if let Some(s) = clean_ssid(&desc.to_string()) {
                    return Ok(Some(s));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::wifi::{WlanOutcome, clean_ssid, ssid_from_bytes, unavailable_note};
    use super::*;
    use std::path::PathBuf;

    const NO_FLAGS: u8 = 0;
    const HW: u8 = 0x05; // HardwareInterface | ConnectorPresent (measured on real Wi-Fi and Ethernet adapters)

    #[test]
    fn classification() {
        // Measured on this machine (research notes).
        assert_eq!(classify(71, 9, HW), Medium::WiFi); // a Wi-Fi 6 adapter
        assert_eq!(classify(6, 14, 0x15), Medium::Ethernet); // a gigabit Ethernet adapter
        assert_eq!(classify(53, 0, 0x00), Medium::Tunnel); // Tailscale Tunnel
        assert_eq!(classify(6, 0, 0x00), Medium::VirtualEthernet); // Hyper-V vEthernet
        assert_eq!(classify(6, 14, 0x80), Medium::VirtualEthernet); // VMware / VirtualBox host-only
        assert_eq!(classify(71, 9, 0x10), Medium::WiFi); // Wi-Fi Direct virtual (never a default route)
        // Others.
        assert_eq!(classify(243, 8, HW), Medium::Cellular);
        assert_eq!(classify(244, 0, HW), Medium::Cellular);
        assert_eq!(classify(6, 8, HW), Medium::Cellular);
        assert_eq!(classify(131, 0, NO_FLAGS), Medium::Tunnel);
        assert_eq!(classify(23, 0, NO_FLAGS), Medium::Tunnel); // PPP / RAS VPN
        assert_eq!(classify(24, 0, NO_FLAGS), Medium::Loopback);
        assert_eq!(classify(1, 0, HW), Medium::Other);
        assert_eq!(classify(1, 14, HW), Medium::Ethernet);
        assert!(Medium::Tunnel.is_virtual() && Medium::VirtualEthernet.is_virtual());
        assert!(!Medium::WiFi.is_virtual() && !Medium::Ethernet.is_virtual());
    }

    #[test]
    fn connection_mapping() {
        assert_eq!(connection_for(Medium::WiFi, "x"), ConnectionType::WiFi);
        assert_eq!(connection_for(Medium::Ethernet, "x"), ConnectionType::Ethernet);
        assert_eq!(connection_for(Medium::Cellular, "x"), ConnectionType::Cellular);
        assert_eq!(connection_for(Medium::Other, " USB modem "), ConnectionType::Other("USB modem".into()));
        assert_eq!(connection_for(Medium::Other, ""), ConnectionType::Other("Network adapter".into()));
        assert_eq!(connection_for(Medium::Tunnel, ""), ConnectionType::Other("VPN tunnel".into()));
        assert!(is_hyperv_vswitch("Hyper-V Virtual Ethernet Adapter #2"));
        assert!(!is_hyperv_vswitch("Tailscale Tunnel"));
    }

    fn cand(if_type: u32, up: bool, gw: bool, hw: bool, metric: u32) -> UplinkCandidate {
        UplinkCandidate { if_type, up, has_gateway: gw, hardware: hw, metric, medium: Medium::Other, guid: 0 }
    }

    #[test]
    fn uplink_selection() {
        let c = [
            cand(53, true, true, false, 5),   // Tailscale tunnel
            cand(6, true, true, false, 10),   // Hyper-V vEthernet (not hardware)
            cand(71, true, true, true, 35),   // Wi-Fi
            cand(6, true, true, true, 25),    // Ethernet, lower metric
            cand(6, false, true, true, 1),    // Ethernet down
            cand(6, true, false, true, 1),    // Ethernet without gateway
            cand(243, true, true, true, 100), // WWAN
        ];
        assert_eq!(pick_uplink(&c), Some(3));
        assert_eq!(pick_uplink(&c[..3]), Some(2));
        assert_eq!(pick_uplink(&c[..2]), None);
        assert_eq!(pick_uplink(&[]), None);
        // Tie on metric → first one wins.
        assert_eq!(pick_uplink(&[cand(71, true, true, true, 25), cand(6, true, true, true, 25)]), Some(0));
    }

    #[test]
    fn vpn_labels() {
        assert_eq!(vpn_label("Tailscale", "Tailscale Tunnel"), "Tailscale Tunnel");
        assert_eq!(vpn_label("Ethernet 3", "TAP-Windows Adapter V9"), "Ethernet 3 (TAP-Windows Adapter V9)");
        assert_eq!(vpn_label("ProtonVPN WireGuard", "WireGuard"), "ProtonVPN WireGuard");
        assert_eq!(vpn_label("ProtonVPN", ""), "ProtonVPN");
        assert_eq!(vpn_label("", "Wintun Userspace Tunnel"), "Wintun Userspace Tunnel");
        assert_eq!(vpn_label(" ", ""), "VPN");
    }

    #[test]
    fn ipv4_byte_order() {
        assert_eq!(ipv4_from_s_addr(u32::from_ne_bytes([192, 168, 1, 105])), Ipv4Addr::new(192, 168, 1, 105));
        #[cfg(target_endian = "little")]
        assert_eq!(ipv4_from_s_addr(0x6901_A8C0), Ipv4Addr::new(192, 168, 1, 105));
        assert_eq!(ipv4_from_s_addr(u32::from_ne_bytes(PROBE_V4)), Ipv4Addr::new(149, 154, 167, 220));
        assert!(usable_ipv4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(!usable_ipv4(Ipv4Addr::new(169, 254, 3, 4)));
        assert!(!usable_ipv4(Ipv4Addr::UNSPECIFIED));
        assert!(!usable_ipv4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn guid_conversion_matches_windows_crate() {
        let g = windows_sys::core::GUID {
            data1: 0x3F25_04E0,
            data2: 0x4F89,
            data3: 0x41D3,
            data4: [0x9A, 0x0C, 0x03, 0x05, 0xE8, 0x2C, 0x33, 0x01],
        };
        let expected = 0x3F2504E0_4F89_41D3_9A0C_0305E82C3301_u128;
        assert_eq!(guid_u128(&g), expected);
        assert_eq!(windows::core::GUID::from_u128(expected).to_u128(), expected);
    }

    #[test]
    fn ssid_helpers() {
        assert_eq!(ssid_from_bytes(b"Example-WiFi_5G").as_deref(), Some("Example-WiFi_5G"));
        assert_eq!(ssid_from_bytes(b"").as_deref(), None);
        assert_eq!(ssid_from_bytes(b"Caf\xc3\xa9 \x07").as_deref(), Some("Café"));
        assert_eq!(ssid_from_bytes(&[0xff, b'A']).as_deref(), Some("\u{fffd}A"));
        assert_eq!(clean_ssid("  "), None);
        assert_eq!(unavailable_note(&WlanOutcome::Denied), "SSID unavailable — Windows location services are off");
        assert!(unavailable_note(&WlanOutcome::ServiceOff).contains("WLAN AutoConfig"));
        assert!(unavailable_note(&WlanOutcome::Failed(87)).contains("87"));
    }

    #[test]
    fn helper_reply_lines() {
        assert_eq!(helper_reply_line(Some("Café \"5G\"".into()), None), r#"{"ssid":"Café \"5G\"","note":null}"#);
        assert_eq!(
            helper_reply_line(None, Some("SSID unavailable — Windows location services are off".into())),
            r#"{"ssid":null,"note":"SSID unavailable — Windows location services are off"}"#
        );
        // A found SSID never carries a note.
        assert_eq!(helper_reply_line(Some("x".into()), Some("n".into())), r#"{"ssid":"x","note":null}"#);
        assert_eq!(helper_reply_line(None, None), r#"{"ssid":null,"note":null}"#);
        // Round trip through the parent's parser.
        let line = helper_reply_line(Some("Example-WiFi_5G".into()), None);
        assert_eq!(parse_helper_output(&line), Some((Some("Example-WiFi_5G".into()), None)));
        let line = helper_reply_line(Some("Caf\u{e9}\u{7}".into()), None);
        assert_eq!(parse_helper_output(&line), Some((Some("Café".into()), None)));
    }

    #[test]
    fn helper_output_parsing() {
        assert_eq!(parse_helper_output("{\"ssid\":\"Home\",\"note\":null}\r\n"), Some((Some("Home".into()), None)));
        assert_eq!(
            parse_helper_output(r#"{"ssid":null,"note":"SSID unavailable — no Wi-Fi connection found"}"#),
            Some((None, Some("SSID unavailable — no Wi-Fi connection found".into())))
        );
        // Noise around the reply; the last valid line wins.
        let noisy = "warning: x\n{\"ssid\":\"Old\",\"note\":null}\n{\"ssid\":\"New\",\"note\":null}\ntrailer\n";
        assert_eq!(parse_helper_output(noisy), Some((Some("New".into()), None)));
        // Unknown fields are tolerated (newer helper, older parent).
        assert_eq!(parse_helper_output(r#"{"ssid":"A","note":null,"extra":1}"#), Some((Some("A".into()), None)));
        // Cleaned and bounded again on the parent side.
        assert_eq!(
            parse_helper_output(r#"{"ssid":"  Lab\u0007Net  ","note":null}"#),
            Some((Some("LabNet".into()), None))
        );
        let long = "x".repeat(500);
        let (ssid, _) = parse_helper_output(&format!(r#"{{"ssid":"{long}","note":null}}"#)).unwrap();
        assert_eq!(ssid.unwrap().chars().count(), MAX_SSID_CHARS);
        let (_, note) = parse_helper_output(&format!(r#"{{"ssid":null,"note":"{long}"}}"#)).unwrap();
        assert_eq!(note.unwrap().chars().count(), MAX_NOTE_CHARS);
        // Blank SSID and no note → generic note.
        assert_eq!(parse_helper_output(r#"{"ssid":" ","note":null}"#), Some((None, Some("SSID unavailable".into()))));
        // Nothing usable.
        assert_eq!(parse_helper_output(""), None);
        assert_eq!(parse_helper_output("error: boom"), None);
        assert_eq!(parse_helper_output(r#"{"ssid":5}"#), None);
    }

    #[test]
    fn helper_results() {
        let out = |stdout: &str, exit: Option<u32>, timed_out: bool| process::ProcessOutput {
            exit_code: exit,
            stdout: stdout.into(),
            stderr: String::new(),
            timed_out,
        };
        assert_eq!(helper_result(&out(r#"{"ssid":"Home","note":null}"#, Some(0), false)), (Some("Home".into()), None));
        let (s, n) = helper_result(&out("", None, true));
        assert_eq!(s, None);
        assert!(n.unwrap().contains("did not answer in time"));
        let (s, n) = helper_result(&out("usage: predator-service ...", Some(2), false));
        assert_eq!(s, None);
        assert!(n.unwrap().contains("helper failed"));
    }

    #[test]
    fn helper_spawn_failures_become_notes() {
        let (s, n) = ssid_via_helper(Path::new(r"C:\definitely\not\here\predator-service.exe"));
        assert_eq!(s, None);
        assert!(n.unwrap().contains("could not be started"));
        // A program that does not speak the protocol (whoami.exe rejects the argument).
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let (s, n) = ssid_via_helper(&root.join("System32").join("whoami.exe"));
        assert_eq!(s, None);
        assert!(n.unwrap().contains("helper failed"));
    }

    #[test]
    fn clean_text_strips_controls() {
        assert_eq!(clean_text("  a\tb\u{1b}c \n").as_deref(), Some("abc"));
        assert_eq!(clean_text("\u{7}\u{0}"), None);
        assert_eq!(clean_text("Café ✓").as_deref(), Some("Café ✓"));
    }

    /// Live probe of the service side (`collect()` spawns `predator-service.exe ssid-helper` next
    /// to the test executable, so its SSID note says "could not be started" unless one was copied
    /// there) and of the helper-side lookup, which runs WLAN/WinRT/NLM in THIS test process.
    /// Run with `cargo test --lib sys::network -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_network_info_print() {
        let (p0, w0) = crate::sys::sysinfo::process_memory();
        let t0 = std::time::Instant::now();
        let first = collect();
        let d1 = t0.elapsed();
        let (p1, w1) = crate::sys::sysinfo::process_memory();
        println!("collect() = {first:?} ({d1:?})");
        println!(
            "service side: private {} -> {} KiB ({:+} KiB); working set {} -> {} KiB",
            p0 / 1024,
            p1 / 1024,
            (p1 as i64 - p0 as i64) / 1024,
            w0 / 1024,
            w1 / 1024
        );
        let t1 = std::time::Instant::now();
        let (ssid, note) = helper_lookup();
        println!("helper_lookup() = ({ssid:?}, {note:?}) in {:?}", t1.elapsed());
        println!("helper line: {}", helper_reply_line(ssid, note));
        let (p2, w2) = crate::sys::sysinfo::process_memory();
        println!(
            "in-process lookup (what the helper pays): private {:+} KiB, working set {:+} KiB",
            (p2 as i64 - p1 as i64) / 1024,
            (w2 as i64 - w1 as i64) / 1024
        );
        assert!(first.is_ok());
    }
}
