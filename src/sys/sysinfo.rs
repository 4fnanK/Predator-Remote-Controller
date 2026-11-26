//! Cheap system facts: computer name, OS version, boot time, own memory/CPU usage, SIDs.
//!

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS, FILETIME, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW, GetTickCount64};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes, OpenProcessToken};

use crate::util::win::{OwnedHandle, from_wide, from_wide_ptr, last_error, wide};

const CURRENT_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// Predefined registry root for [`reg_get_string`] / [`reg_get_dword`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegRoot {
    /// `HKEY_LOCAL_MACHINE`
    LocalMachine,
}

impl RegRoot {
    fn hkey(self) -> HKEY {
        match self {
            RegRoot::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }
}

/// NetBIOS computer name (e.g. `DESKTOP-01`).
pub fn computer_name() -> String {
    let mut buf = vec![0u16; 64];
    for _ in 0..3 {
        let mut len = buf.len() as u32;
        // SAFETY: `buf` is valid for `len` UTF-16 units; `len` receives the needed/written size.
        let ok = unsafe { GetComputerNameExW(ComputerNameNetBIOS, buf.as_mut_ptr(), &mut len) };
        if ok != 0 {
            let name = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
            if !name.is_empty() {
                return name;
            }
            break;
        }
        if last_error() != ERROR_MORE_DATA {
            break;
        }
        buf.resize((len as usize).max(buf.len() * 2) + 1, 0);
    }
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "PC".to_string())
}

/// e.g. `Windows 11 Pro 25H2 (build 26200.7171)`.
pub fn os_version() -> String {
    let product = reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("ProductName"));
    let display = reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("DisplayVersion"))
        .or_else(|| reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("ReleaseId")));
    let build = reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("CurrentBuild"))
        .or_else(|| reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("CurrentBuildNumber")));
    let ubr = reg_get_dword(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("UBR"));
    format_os_version(product.as_deref(), display.as_deref(), build.as_deref(), ubr)
}

/// Pure formatting of the registry values that make up the OS version string.
///
/// `ProductName` still says "Windows 10" on Windows 11 (a well-known Microsoft quirk), so it is
/// corrected when the build number is 22000 or newer.
pub fn format_os_version(
    product: Option<&str>,
    display: Option<&str>,
    build: Option<&str>,
    ubr: Option<u32>,
) -> String {
    let build = build.map(str::trim).filter(|b| !b.is_empty());
    let build_num = build.and_then(|b| b.parse::<u32>().ok());
    let mut name = product.map(str::trim).filter(|p| !p.is_empty()).unwrap_or("Windows").to_string();
    if build_num.is_some_and(|b| b >= 22_000) && name.contains("Windows 10") {
        name = name.replacen("Windows 10", "Windows 11", 1);
    }
    if let Some(d) = display.map(str::trim).filter(|d| !d.is_empty()) {
        name.push(' ');
        name.push_str(d);
    }
    match (build, ubr) {
        (Some(b), Some(u)) => format!("{name} (build {b}.{u})"),
        (Some(b), None) => format!("{name} (build {b})"),
        _ => name,
    }
}

/// Unix time of the last boot (now - GetTickCount64).
pub fn boot_unix() -> i64 {
    // SAFETY: no arguments, cannot fail.
    let up_ms = unsafe { GetTickCount64() };
    boot_unix_from(crate::util::time::now_unix(), up_ms)
}

/// Pure helper: boot time from the current Unix time and the uptime in milliseconds.
fn boot_unix_from(now_unix: i64, uptime_ms: u64) -> i64 {
    now_unix - (uptime_ms / 1000).min(i64::MAX as u64) as i64
}

/// (private bytes, working set bytes) of the current process.
pub fn process_memory() -> (u64, u64) {
    let mut c = PROCESS_MEMORY_COUNTERS_EX {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: the pseudo handle needs no closing; `c` is a PROCESS_MEMORY_COUNTERS_EX whose size is passed in `cb`.
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut c as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            c.cb,
        )
    };
    if ok == 0 {
        return (0, 0);
    }
    (c.PrivateUsage as u64, c.WorkingSetSize as u64)
}

/// Total (kernel + user) CPU time of the current process in milliseconds.
pub fn process_cpu_ms() -> u64 {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all out-pointers are valid FILETIME structs.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut creation, &mut exit, &mut kernel, &mut user) };
    if ok == 0 {
        return 0;
    }
    (filetime_u64(&kernel) + filetime_u64(&user)) / 10_000
}

fn filetime_u64(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// String SID of the current process token user (e.g. `S-1-5-18` for LocalSystem).
pub fn current_user_sid() -> Option<String> {
    let token = open_own_token()?;
    token_user_sid(token.raw())
}

/// Resolve an account name (`alex`, `DESKTOP-01\alex`) to a string SID.
pub fn lookup_account_sid(account: &str) -> Option<String> {
    let account = account.trim();
    if account.is_empty() || account.contains('\0') {
        return None;
    }
    let name = wide(account);
    let mut sid_len = 0u32;
    let mut dom_len = 0u32;
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: size query — null buffers with zero lengths; the call fills in the needed sizes.
    let ok = unsafe {
        LookupAccountNameW(null(), name.as_ptr(), null_mut(), &mut sid_len, null_mut(), &mut dom_len, &mut use_)
    };
    if ok != 0 || last_error() != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
        return None;
    }
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut domain = vec![0u16; dom_len.max(1) as usize];
    // SAFETY: buffers are at least as large as the sizes reported by the first call.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut dom_len,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: `sid` now holds a valid SID.
    unsafe { sid_to_string(sid.as_mut_ptr().cast()) }
}

/// True when the current process runs as LocalSystem.
pub fn is_local_system() -> bool {
    current_user_sid().as_deref() == Some("S-1-5-18")
}

/// True when the current process token is elevated (admin).
pub fn is_elevated() -> bool {
    let Some(token) = open_own_token() else {
        return false;
    };
    let mut elev = TOKEN_ELEVATION::default();
    let mut ret = 0u32;
    // SAFETY: `elev` is a TOKEN_ELEVATION and its exact size is passed.
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            (&mut elev as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    };
    ok != 0 && elev.TokenIsElevated != 0
}

/// String SID of the user of an access token (opened with at least `TOKEN_QUERY`).
pub fn token_user_sid(token: HANDLE) -> Option<String> {
    let buf = token_information(token, TokenUser)?;
    if buf.len() * 8 < std::mem::size_of::<TOKEN_USER>() {
        return None;
    }
    // SAFETY: the buffer is 8-byte aligned and holds a TOKEN_USER written by GetTokenInformation;
    // the SID it points to lives inside the same buffer.
    unsafe {
        let tu = &*(buf.as_ptr().cast::<TOKEN_USER>());
        sid_to_string(tu.User.Sid)
    }
}

/// Convert a binary SID to its string form (`S-1-5-...`).
///
/// # Safety
/// `sid` must be null or point to a valid SID.
pub unsafe fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut out: *mut u16 = null_mut();
    // SAFETY: caller guarantees a valid SID; `out` receives a LocalAlloc'ed string that we free.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
            return None;
        }
        let s = from_wide_ptr(out);
        LocalFree(out as HLOCAL);
        (!s.is_empty()).then_some(s)
    }
}

fn open_own_token() -> Option<OwnedHandle> {
    let mut h: HANDLE = null_mut();
    // SAFETY: pseudo process handle; `h` receives a token handle that OwnedHandle closes.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) };
    (ok != 0 && !h.is_null()).then(|| OwnedHandle(h))
}

/// Two-call GetTokenInformation into an 8-byte aligned buffer.
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: size query with a null buffer.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let len = (buf.len() * 8) as u32;
    // SAFETY: `buf` is `len` bytes long.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut needed) };
    (ok != 0).then_some(buf)
}

/// Read a `REG_SZ` value (`None` = the key's default value) from the 64-bit registry view.
/// Returns `None` when the key/value is missing, has another type or is empty.
pub fn reg_get_string(root: RegRoot, subkey: &str, value: Option<&str>) -> Option<String> {
    let root = root.hkey();
    let subkey_w = wide(subkey);
    let value_w = value.map(wide);
    let value_ptr = value_w.as_ref().map_or(null(), |v| v.as_ptr());
    let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
    let mut size = 0u32;
    // SAFETY: size query with a null data buffer.
    let rc = unsafe { RegGetValueW(root, subkey_w.as_ptr(), value_ptr, flags, null_mut(), null_mut(), &mut size) };
    if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
        return None;
    }
    // The value may grow between the calls: retry a few times.
    for _ in 0..3 {
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `buf` is `bytes` bytes long.
        let rc = unsafe {
            RegGetValueW(root, subkey_w.as_ptr(), value_ptr, flags, null_mut(), buf.as_mut_ptr().cast(), &mut bytes)
        };
        match rc {
            ERROR_SUCCESS => {
                let n = (bytes as usize / 2).min(buf.len());
                let s = from_wide(&buf[..n]);
                return (!s.is_empty()).then_some(s);
            }
            ERROR_MORE_DATA => size = bytes,
            _ => return None,
        }
    }
    None
}

/// Read a `REG_DWORD` value from the 64-bit registry view.
pub fn reg_get_dword(root: RegRoot, subkey: &str, value: Option<&str>) -> Option<u32> {
    let root = root.hkey();
    let subkey_w = wide(subkey);
    let value_w = value.map(wide);
    let value_ptr = value_w.as_ref().map_or(null(), |v| v.as_ptr());
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `data` is a 4-byte buffer and `size` says so.
    let rc = unsafe {
        RegGetValueW(
            root,
            subkey_w.as_ptr(),
            value_ptr,
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_formatting() {
        assert_eq!(
            format_os_version(Some("Windows 10 Pro"), Some("25H2"), Some("26200"), Some(7171)),
            "Windows 11 Pro 25H2 (build 26200.7171)"
        );
        assert_eq!(
            format_os_version(Some("Windows 10 Pro"), Some("22H2"), Some("19045"), Some(5737)),
            "Windows 10 Pro 22H2 (build 19045.5737)"
        );
        assert_eq!(
            format_os_version(Some("Windows 11 Home"), None, Some("22000"), None),
            "Windows 11 Home (build 22000)"
        );
        assert_eq!(
            format_os_version(Some("Windows Server 2022 Standard"), Some("21H2"), Some("20348"), Some(1)),
            "Windows Server 2022 Standard 21H2 (build 20348.1)"
        );
        assert_eq!(format_os_version(None, None, None, None), "Windows");
        assert_eq!(format_os_version(Some("  "), Some(""), Some(""), Some(3)), "Windows");
    }

    #[test]
    fn boot_time_math() {
        assert_eq!(boot_unix_from(1_000_000, 3_600_000), 996_400);
        assert_eq!(boot_unix_from(1_000_000, 999), 1_000_000);
    }

    #[test]
    fn live_computer_name_and_os() {
        let n = computer_name();
        assert!(!n.is_empty() && n.len() <= 15, "{n}");
        let v = os_version();
        assert!(v.starts_with("Windows"), "{v}");
        assert!(v.contains("(build "), "{v}");
        println!("computer={n} os={v}");
    }

    #[test]
    fn live_boot_time_sane() {
        let b = boot_unix();
        let now = crate::util::time::now_unix();
        assert!(b <= now && b > now - 400 * 86_400, "boot={b} now={now}");
    }

    #[test]
    fn live_process_counters() {
        let (private, ws) = process_memory();
        assert!(private > 64 * 1024 && private < 4 << 30, "private={private}");
        assert!(ws > 64 * 1024 && ws < 4 << 30, "ws={ws}");
        // Burn a little CPU so the counter is non-zero.
        let mut x = 0u64;
        for i in 0..5_000_000u64 {
            x = x.wrapping_mul(31).wrapping_add(i);
        }
        std::hint::black_box(x);
        let cpu = process_cpu_ms();
        assert!(cpu < 24 * 3_600_000, "cpu={cpu}");
    }

    #[test]
    fn live_sids() {
        let sid = current_user_sid().expect("current user SID");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        // Well-known account names resolve to well-known SIDs.
        assert_eq!(lookup_account_sid("NT AUTHORITY\\SYSTEM").as_deref(), Some("S-1-5-18"));
        assert_eq!(lookup_account_sid("SYSTEM").as_deref(), Some("S-1-5-18"));
        assert_eq!(lookup_account_sid(""), None);
        assert_eq!(lookup_account_sid("no-such-user-zz-1234567"), None);
        // The current user's own name resolves to the token SID.
        if let Ok(user) = std::env::var("USERNAME")
            && !is_local_system()
        {
            assert_eq!(lookup_account_sid(&user).as_deref(), Some(sid.as_str()));
        }
        // Not elevated in the dev shell; the call must simply not fail.
        let _ = is_elevated();
    }

    #[test]
    fn live_registry_helpers() {
        assert!(reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("ProductName")).is_some());
        assert!(reg_get_dword(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("UBR")).is_some());
        assert_eq!(reg_get_string(RegRoot::LocalMachine, r"SOFTWARE\NoSuchKeyPredator123", None), None);
        // Wrong type → None (UBR is a DWORD).
        assert_eq!(reg_get_string(RegRoot::LocalMachine, CURRENT_VERSION_KEY, Some("UBR")), None);
    }
}
