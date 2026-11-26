//! Win32 security helpers used by the service: in-memory secrets, SIDs and account names,
//! security descriptors (SDDL), the data-directory ACL and its trust check, token facts, the
//! HKLM Run value and a hidden console prompt.
//!
//! Trust model of the data directory (`%ProgramData%\Predator`): every standard user may create
//! folders in `%ProgramData%`, so a pre-existing `Vigil` folder may have been planted with a
//! forged `token.dat` (any account can create a machine-scope DPAPI blob), an attacker's owner id
//! or a poisoned `audit-backup.json`. A folder is trusted only when its owner is SYSTEM or
//! Administrators and its DACL is protected and grants nobody else access ([`assess_data_dir`]).
//! The installer moves an untrusted folder aside ([`move_aside`]) and never reads from it.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_OWNER, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, HANDLE,
    HLOCAL, LUID, LocalFree, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CheckTokenMembership, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupAccountSidW,
    LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_PRIVILEGE_ENABLED, SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::util::time::LocalTime;
use crate::util::win::{OwnedHandle, WinError, from_wide, from_wide_ptr, last_error, wide, wide_path};

/// Owner Administrators; protected DACL: SYSTEM + Administrators full control, inherited by
/// every file and sub-directory. Nobody else can read the token or change the settings.
pub(crate) use crate::paths::DATA_DIR_SDDL;

const SID_SYSTEM: &str = "S-1-5-18";
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
const SID_OWNER_RIGHTS: &str = "S-1-3-4";
/// NT SERVICE\TrustedInstaller (owner of Program Files).
const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// `NT SERVICE\*` per-service SIDs: only the SCM can put them into a token, so an object owned
/// by one was created by a service (e.g. ours, running as LocalSystem).
const SERVICE_SID_PREFIX: &str = "S-1-5-80-";
/// Limits for walking the data directory (it normally holds about 15 entries, 2 levels deep).
const MAX_TREE_ENTRIES: usize = 10_000;
const MAX_TREE_DEPTH: u32 = 8;

/// HKLM Run key used for the tray autostart.
pub(crate) const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

// ---------------------------------------------------------------------------------------------
// Secrets in memory
// ---------------------------------------------------------------------------------------------

/// A string wiped from memory when dropped (bot token). Never printed by `Debug`.
pub(crate) struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(s)
    }

    /// Trimmed copy; the original buffer is wiped.
    pub fn trimmed(mut s: String) -> Self {
        let t = s.trim().to_string();
        // SAFETY: writing zero bytes keeps the buffer valid UTF-8.
        crate::secrets::zeroize(unsafe { s.as_mut_vec() });
        Secret(t)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: writing zero bytes keeps the buffer valid UTF-8.
        crate::secrets::zeroize(unsafe { self.0.as_mut_vec() });
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// ---------------------------------------------------------------------------------------------
// LocalAlloc'ed memory
// ---------------------------------------------------------------------------------------------

/// Memory returned by Win32 APIs that must be released with `LocalFree`.
pub(crate) struct LocalMem(pub *mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by the OS with LocalAlloc and is freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SIDs and account names
// ---------------------------------------------------------------------------------------------

/// Cheap syntactic check of a string SID (`S-1-5-21-...`).
pub(crate) fn looks_like_sid(s: &str) -> bool {
    let s = s.trim();
    let Some(rest) = s.strip_prefix("S-1-").or_else(|| s.strip_prefix("s-1-")) else { return false };
    !rest.is_empty()
        && rest.len() <= 180
        && rest.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate a string SID with the OS and return its canonical form.
pub(crate) fn canonical_sid(s: &str) -> Option<String> {
    if !looks_like_sid(s) {
        return None;
    }
    let w = wide(s.trim());
    let mut psid: PSID = null_mut();
    // SAFETY: `w` is NUL-terminated; `psid` receives a LocalAlloc'ed SID freed by LocalMem.
    let ok = unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut psid) };
    if ok == 0 || psid.is_null() {
        return None;
    }
    let _guard = LocalMem(psid);
    // SAFETY: `psid` is a valid SID.
    unsafe { crate::sys::sysinfo::sid_to_string(psid) }
}

/// `DOMAIN\name` for a binary SID (None when it cannot be resolved).
///
/// # Safety
/// `sid` must point to a valid SID.
pub(crate) unsafe fn account_name(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: buffers and their lengths match; the caller guarantees a valid SID.
    let ok = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    let n = from_wide(&name);
    let d = from_wide(&domain);
    if n.is_empty() {
        None
    } else if d.is_empty() {
        Some(n)
    } else {
        Some(format!("{d}\\{n}"))
    }
}

/// `DOMAIN\name` for a string SID.
pub(crate) fn account_name_of(sid: &str) -> Option<String> {
    if !looks_like_sid(sid) {
        return None;
    }
    let w = wide(sid.trim());
    let mut psid: PSID = null_mut();
    // SAFETY: `w` is NUL-terminated; the SID is freed by LocalMem.
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut psid) } == 0 || psid.is_null() {
        return None;
    }
    let _guard = LocalMem(psid);
    // SAFETY: valid SID.
    unsafe { account_name(psid) }
}

/// Facts about an access token used for IPC authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenFacts {
    pub sid: String,
    pub account: Option<String>,
    pub elevated: bool,
    /// Member of BUILTIN\Administrators with the group enabled (i.e. not a filtered UAC token).
    pub admin: bool,
}

/// Query user SID, account name, elevation and admin membership of `token` (TOKEN_QUERY).
/// `CheckTokenMembership` requires an impersonation token; for a primary token pass
/// `impersonation = false` and the membership is derived from elevation alone.
pub(crate) fn token_facts(token: HANDLE, impersonation: bool) -> Result<TokenFacts, String> {
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
    // SAFETY: valid SID inside `buf`.
    let account = unsafe { account_name(user_sid) };

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

    let admin = if impersonation { is_admin_member(token).unwrap_or(false) } else { elevated };
    Ok(TokenFacts { sid, account, elevated, admin })
}

fn is_admin_member(token: HANDLE) -> Result<bool, String> {
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = sid.len() as u32;
    // SAFETY: `sid` has SECURITY_MAX_SID_SIZE bytes, enough for any well-known SID.
    if unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(WinError::last("CreateWellKnownSid").to_string());
    }
    let mut member = 0i32;
    // SAFETY: impersonation token with TOKEN_QUERY, valid SID buffer.
    if unsafe { CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut member) } == 0 {
        return Err(WinError::last("CheckTokenMembership").to_string());
    }
    Ok(member != 0)
}

/// Token facts of the current process (CLI / selftest).
pub(crate) fn current_process_facts() -> Option<TokenFacts> {
    let mut h: HANDLE = null_mut();
    // SAFETY: pseudo handle of the current process; the token handle is closed by OwnedHandle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) } == 0 {
        return None;
    }
    let token = OwnedHandle(h);
    token_facts(token.raw(), false).ok()
}

// ---------------------------------------------------------------------------------------------
// Security descriptors
// ---------------------------------------------------------------------------------------------

/// A self-relative security descriptor built from SDDL (freed with LocalFree).
pub(crate) struct SecurityDescriptor(LocalMem);

// SAFETY: the descriptor is immutable after creation and only read by the OS.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> Result<Self, String> {
        let w = wide(sddl);
        let mut psd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `w` is NUL-terminated; `psd` receives a LocalAlloc'ed descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut psd, null_mut())
        };
        if ok == 0 || psd.is_null() {
            return Err(WinError::last("ConvertStringSecurityDescriptorToSecurityDescriptorW").to_string());
        }
        Ok(Self(LocalMem(psd)))
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.0
    }

    fn dacl(&self) -> Result<*mut ACL, String> {
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: valid descriptor; out-parameters are valid.
        if unsafe { GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(WinError::last("GetSecurityDescriptorDacl").to_string());
        }
        Ok(dacl)
    }

    fn owner(&self) -> Result<PSID, String> {
        let mut owner: PSID = null_mut();
        let mut defaulted = 0i32;
        // SAFETY: valid descriptor; out-parameters are valid.
        if unsafe { GetSecurityDescriptorOwner(self.as_ptr(), &mut owner, &mut defaulted) } == 0 {
            return Err(WinError::last("GetSecurityDescriptorOwner").to_string());
        }
        Ok(owner)
    }
}

/// Owner + DACL of a file or directory as SDDL (e.g. `O:BAD:PAI(A;OICI;FA;;;SY)...`).
pub(crate) fn path_sddl(path: &Path) -> Result<String, String> {
    let w = wide_path(path);
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: `w` is NUL-terminated; `psd` receives a LocalAlloc'ed descriptor.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            info,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut psd,
        )
    };
    if rc != 0 {
        return Err(WinError::new(rc, "GetNamedSecurityInfoW").to_string());
    }
    let _sd = LocalMem(psd);
    let mut s: *mut u16 = null_mut();
    // SAFETY: valid descriptor; `s` receives a LocalAlloc'ed string.
    if unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, info, &mut s, null_mut()) }
        == 0
    {
        return Err(WinError::last("ConvertSecurityDescriptorToStringSecurityDescriptorW").to_string());
    }
    let _str = LocalMem(s.cast());
    // SAFETY: NUL-terminated string from the OS.
    Ok(unsafe { from_wide_ptr(s) })
}

// ---------------------------------------------------------------------------------------------
// SDDL inspection (pure, unit-tested)
// ---------------------------------------------------------------------------------------------

/// One access control entry of an SDDL string: `(type;flags;rights;object;inherit object;trustee)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SddlAce {
    /// `A` allow, `D` deny, `OA`, `XA`, … (upper case).
    pub kind: String,
    /// Two-letter inheritance flags such as `OICIID` (upper case).
    pub flags: String,
    /// Rights: `FA`, `0x1200a9`, `CCDCLC…` (upper case).
    pub rights: String,
    /// Alias (`SY`, `BA`, `WD`) or string SID.
    pub trustee: String,
}

/// Owner and DACL of an SDDL string.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SddlInfo {
    pub owner: Option<String>,
    /// DACL control flags (`P`, `AI`, `AR`, `NO_ACCESS_CONTROL`); `None` without a `D:` part.
    pub dacl_flags: Option<String>,
    pub aces: Vec<SddlAce>,
}

impl SddlInfo {
    /// A missing or NULL DACL grants everyone full access.
    fn dacl_is_null(&self) -> bool {
        self.dacl_flags.as_deref().is_none_or(|f| f.contains("NO_ACCESS_CONTROL"))
    }

    fn dacl_protected(&self) -> bool {
        !self.dacl_is_null() && self.dacl_flags.as_deref().is_some_and(|f| f.contains('P'))
    }
}

impl SddlAce {
    fn is_allow(&self) -> bool {
        matches!(self.kind.as_str(), "A" | "OA" | "XA" | "ZA")
    }

    fn has_flag(&self, flag: &str) -> bool {
        self.flags.as_bytes().chunks(2).any(|c| c == flag.as_bytes())
    }
}

/// Split an SDDL string into its `O:`, `G:`, `D:` and `S:` sections (markers inside ACE
/// parentheses are ignored).
fn sddl_sections(sddl: &str) -> Vec<(u8, &str)> {
    let b = sddl.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current: Option<(u8, usize)> = None;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            c @ (b'O' | b'G' | b'D' | b'S') if depth == 0 && b.get(i + 1) == Some(&b':') => {
                if let Some((k, start)) = current.take() {
                    out.push((k, &sddl[start..i]));
                }
                current = Some((c, i + 2));
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some((k, start)) = current {
        out.push((k, &sddl[start..]));
    }
    out
}

/// Parse the owner and DACL of an SDDL string (as produced by
/// `ConvertSecurityDescriptorToStringSecurityDescriptorW`).
pub(crate) fn parse_sddl(sddl: &str) -> SddlInfo {
    let mut info = SddlInfo::default();
    for (kind, value) in sddl_sections(sddl.trim()) {
        match kind {
            b'O' => info.owner = Some(value.trim().to_string()),
            b'D' => {
                let first = value.find('(').unwrap_or(value.len());
                info.dacl_flags = Some(value[..first].trim().to_ascii_uppercase());
                let mut depth = 0i32;
                let mut start = 0usize;
                for (i, c) in value.char_indices() {
                    match c {
                        '(' => {
                            if depth == 0 {
                                start = i + 1;
                            }
                            depth += 1;
                        }
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                let parts: Vec<&str> = value[start..i].split(';').collect();
                                let field = |n: usize| parts.get(n).map(|s| s.trim()).unwrap_or("");
                                info.aces.push(SddlAce {
                                    kind: field(0).to_ascii_uppercase(),
                                    flags: field(1).to_ascii_uppercase(),
                                    rights: field(2).to_ascii_uppercase(),
                                    trustee: field(5).to_string(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    info
}

fn trustee_is(t: &str, alias: &str, sid: &str) -> bool {
    let t = t.trim();
    t.eq_ignore_ascii_case(alias) || t.eq_ignore_ascii_case(sid)
}

/// SYSTEM or BUILTIN\Administrators.
fn is_system_or_admins(t: &str) -> bool {
    trustee_is(t, "SY", SID_SYSTEM) || trustee_is(t, "BA", SID_ADMINISTRATORS)
}

/// OWNER RIGHTS only ever applies to the (separately validated) owner.
fn is_owner_rights(t: &str) -> bool {
    trustee_is(t, "OW", SID_OWNER_RIGHTS)
}

fn is_trusted_installer(t: &str) -> bool {
    t.trim().eq_ignore_ascii_case(SID_TRUSTED_INSTALLER)
}

fn is_service_sid(t: &str) -> bool {
    t.trim().to_ascii_uppercase().starts_with(SERVICE_SID_PREFIX)
}

fn is_extra(t: &str, extra: Option<&str>) -> bool {
    extra.is_some_and(|e| !e.trim().is_empty() && e.trim().eq_ignore_ascii_case(t.trim()))
}

/// Readable name of an SDDL trustee: `PC\eve (S-1-5-21-…)`, `Everyone (WD)`.
pub(crate) fn describe_trustee(t: &str) -> String {
    let t = t.trim();
    let alias = match t.to_ascii_uppercase().as_str() {
        "WD" => Some("Everyone"),
        "AU" => Some("Authenticated Users"),
        "BU" => Some("BUILTIN\\Users"),
        "IU" => Some("INTERACTIVE"),
        "CO" => Some("CREATOR OWNER"),
        "OW" => Some("OWNER RIGHTS"),
        "SY" => Some("NT AUTHORITY\\SYSTEM"),
        "BA" => Some("BUILTIN\\Administrators"),
        "AN" => Some("ANONYMOUS LOGON"),
        "NU" => Some("NETWORK"),
        "LS" => Some("LOCAL SERVICE"),
        "NS" => Some("NETWORK SERVICE"),
        _ => None,
    };
    match alias {
        Some(name) => format!("{name} ({t})"),
        None if looks_like_sid(t) => match account_name_of(t) {
            Some(name) => format!("{name} ({t})"),
            None => t.to_string(),
        },
        None => t.to_string(),
    }
}

/// Access mask of an SDDL rights field (`FA`, `0x1301bf`, `CCDCLCSWRPWP…`). Unknown codes count
/// as every right (conservative).
pub(crate) fn rights_mask(rights: &str) -> u32 {
    let r = rights.trim();
    if let Some(hex) = r.strip_prefix("0x").or_else(|| r.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).unwrap_or(u32::MAX);
    }
    if r.is_empty() || !r.len().is_multiple_of(2) {
        return if r.is_empty() { 0 } else { u32::MAX };
    }
    let mut mask = 0u32;
    for code in r.as_bytes().chunks(2) {
        mask |= match code.to_ascii_uppercase().as_slice() {
            b"FA" => 0x001F_01FF,
            b"FR" => 0x0012_0089,
            b"FW" => 0x0012_0116,
            b"FX" => 0x0012_00A0,
            b"GA" => 0x1000_0000,
            b"GR" => 0x8000_0000,
            b"GW" => 0x4000_0000,
            b"GX" => 0x2000_0000,
            b"SD" => 0x0001_0000,
            b"RC" => 0x0002_0000,
            b"WD" => 0x0004_0000,
            b"WO" => 0x0008_0000,
            b"CC" => 0x0001,
            b"DC" => 0x0002,
            b"LC" => 0x0004,
            b"SW" => 0x0008,
            b"RP" => 0x0010,
            b"WP" => 0x0020,
            b"DT" => 0x0040,
            b"LO" => 0x0080,
            b"CR" => 0x0100,
            _ => u32::MAX,
        };
    }
    mask
}

/// Rights that let a principal change a file or folder (data, attributes, children, deletion,
/// permissions, owner) — everything except reading and executing.
const WRITE_RIGHTS: u32 = 0x0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0010 // FILE_WRITE_EA
    | 0x0040 // FILE_DELETE_CHILD
    | 0x0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0200_0000 // MAXIMUM_ALLOWED
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// The protected data-directory ACL exactly as `install` sets it: owner Administrators (or
/// SYSTEM), protected DACL with only the full-control, inheritable allow entries of SYSTEM and
/// Administrators (any order). Used to skip re-securing when nothing needs to change.
pub(crate) fn is_secure_data_dir_sddl(sddl: &str) -> bool {
    let info = parse_sddl(sddl);
    if !info.owner.as_deref().is_some_and(is_system_or_admins) || !info.dacl_protected() || info.aces.len() != 2 {
        return false;
    }
    let full_inheritable = |a: &SddlAce, alias: &str, sid: &str| {
        a.kind == "A"
            && trustee_is(&a.trustee, alias, sid)
            && rights_mask(&a.rights) == 0x001F_01FF
            && a.has_flag("OI")
            && a.has_flag("CI")
            && !a.has_flag("IO")
            && a.flags.len() == 4
    };
    let has = |alias: &str, sid: &str| info.aces.iter().any(|a| full_inheritable(a, alias, sid));
    has("SY", SID_SYSTEM) && has("BA", SID_ADMINISTRATORS)
}

/// Why a data-directory root with this SDDL must not be trusted (`None` = trusted): its owner
/// must be SYSTEM or Administrators and its DACL protected (not inherited from `%ProgramData%`)
/// and must grant nobody but SYSTEM, Administrators (and OWNER RIGHTS) any access.
pub(crate) fn root_distrust_reason(sddl: &str) -> Option<String> {
    let info = parse_sddl(sddl);
    match info.owner.as_deref() {
        Some(o) if is_system_or_admins(o) => {}
        Some(o) => return Some(format!("it is owned by {}, not by SYSTEM or Administrators", describe_trustee(o))),
        None => return Some("its owner cannot be determined".into()),
    }
    if info.dacl_is_null() {
        return Some("it has no access control list (everyone has full access)".into());
    }
    if !info.dacl_protected() {
        return Some("its permissions are inherited from the parent folder (other users can add files)".into());
    }
    foreign_allow(&info).map(|t| format!("its permissions grant access to {}", describe_trustee(t)))
}

/// First allow entry for somebody other than SYSTEM, Administrators or OWNER RIGHTS.
fn foreign_allow(info: &SddlInfo) -> Option<&str> {
    info.aces
        .iter()
        .find(|a| a.is_allow() && !is_system_or_admins(&a.trustee) && !is_owner_rights(&a.trustee))
        .map(|a| a.trustee.as_str())
}

/// Why a file or folder inside a trusted data directory must not be trusted (`None` = trusted).
/// Acceptable owners: SYSTEM, Administrators, a service SID (the service itself) and
/// `extra_owner` (the administrator running the installer). Nobody else may be granted access.
pub(crate) fn child_distrust_reason(sddl: &str, extra_owner: Option<&str>) -> Option<String> {
    let info = parse_sddl(sddl);
    match info.owner.as_deref() {
        Some(o) if is_system_or_admins(o) || is_service_sid(o) || is_extra(o, extra_owner) => {}
        Some(o) => return Some(format!("is owned by {}", describe_trustee(o))),
        None => return Some("has no readable owner".into()),
    }
    if info.dacl_is_null() {
        return Some("has no access control list (everyone has full access)".into());
    }
    foreign_allow(&info).map(|t| format!("grants access to {}", describe_trustee(t)))
}

/// Why non-administrators could modify a program file or folder with this SDDL (`None` =
/// only SYSTEM, Administrators, TrustedInstaller and `extra_owner` can change it). Read and
/// execute grants (Users, application packages) are fine; inherit-only templates are ignored.
pub(crate) fn nonadmin_write_reason(sddl: &str, extra_owner: Option<&str>) -> Option<String> {
    let info = parse_sddl(sddl);
    match info.owner.as_deref() {
        Some(o) if is_system_or_admins(o) || is_trusted_installer(o) || is_extra(o, extra_owner) => {}
        Some(o) => return Some(format!("is owned by {}", describe_trustee(o))),
        None => return Some("has no readable owner".into()),
    }
    if info.dacl_is_null() {
        return Some("has no access control list (everyone has full access)".into());
    }
    info.aces
        .iter()
        .find(|a| {
            a.is_allow()
                && !a.has_flag("IO")
                && !is_system_or_admins(&a.trustee)
                && !is_trusted_installer(&a.trustee)
                && !is_owner_rights(&a.trustee)
                && rights_mask(&a.rights) & WRITE_RIGHTS != 0
        })
        .map(|a| format!("can be modified by {}", describe_trustee(&a.trustee)))
}

// ---------------------------------------------------------------------------------------------
// Data directory: trust check, move-aside, ACL
// ---------------------------------------------------------------------------------------------

fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Remove a junction or symbolic link itself (never its target).
fn remove_link(path: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::windows::fs::FileTypeExt;
    let ft = meta.file_type();
    if ft.is_symlink_dir() || meta.is_dir() { std::fs::remove_dir(path) } else { std::fs::remove_file(path) }
}

/// Whether an existing data directory may be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirTrust {
    /// Nothing exists at the path.
    Missing,
    /// Owned by SYSTEM/Administrators with a protected SYSTEM + Administrators ACL.
    Trusted,
    /// Must not be used; the text says why (`it is owned by …`, `…\token.dat is owned by …`).
    Untrusted(String),
}

/// Decide whether the data directory at `root` can be trusted. With `check_children` every file
/// and folder below it is inspected too (owner, ACL, no junctions); the installer does that
/// before it reuses a stored token, owner or audit-policy backup.
pub(crate) fn assess_data_dir(root: &Path, check_children: bool) -> DirTrust {
    let meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DirTrust::Missing,
        Err(e) => return DirTrust::Untrusted(format!("it cannot be inspected ({e})")),
    };
    if is_reparse_point(&meta) {
        return DirTrust::Untrusted("it is a junction or symbolic link".into());
    }
    if !meta.is_dir() {
        return DirTrust::Untrusted("it is not a folder".into());
    }
    let sddl = match path_sddl(root) {
        Ok(s) => s,
        Err(e) => return DirTrust::Untrusted(format!("its permissions cannot be read ({e})")),
    };
    if let Some(why) = root_distrust_reason(&sddl) {
        return DirTrust::Untrusted(why);
    }
    if check_children {
        let me = current_process_facts().map(|f| f.sid);
        let mut budget = MAX_TREE_ENTRIES;
        if let Err(why) = inspect_children(root, me.as_deref(), 0, &mut budget) {
            return DirTrust::Untrusted(why);
        }
    }
    DirTrust::Trusted
}

fn inspect_children(dir: &Path, extra_owner: Option<&str>, depth: u32, budget: &mut usize) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{} cannot be listed ({e})", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{} cannot be listed ({e})", dir.display()))?;
        if *budget == 0 {
            return Err("it contains an unexpectedly large number of files".into());
        }
        *budget -= 1;
        let path = entry.path();
        let meta =
            std::fs::symlink_metadata(&path).map_err(|e| format!("{} cannot be inspected ({e})", path.display()))?;
        if is_reparse_point(&meta) {
            return Err(format!("{} is a junction or symbolic link", path.display()));
        }
        let sddl =
            path_sddl(&path).map_err(|e| format!("the permissions of {} cannot be read ({e})", path.display()))?;
        if let Some(why) = child_distrust_reason(&sddl, extra_owner) {
            return Err(format!("{} {why}", path.display()));
        }
        if meta.is_dir() {
            if depth + 1 >= MAX_TREE_DEPTH {
                return Err(format!("{} is nested unexpectedly deep", path.display()));
            }
            inspect_children(&path, extra_owner, depth + 1, budget)?;
        }
    }
    Ok(())
}

/// `<root>.untrusted-YYYYMMDD-HHMMSS` (plus `-N` for `attempt > 0`) next to `root`.
pub(crate) fn untrusted_sibling(root: &Path, t: LocalTime, attempt: u32) -> PathBuf {
    let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "Predator".into());
    let mut s =
        format!("{name}.untrusted-{:04}{:02}{:02}-{:02}{:02}{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second);
    if attempt > 0 {
        s.push_str(&format!("-{}", attempt + 1));
    }
    root.with_file_name(s)
}

/// Rename an untrusted data directory out of the way (nothing inside it is read or changed) so
/// a fresh, protected one can be created. Returns the new location.
pub(crate) fn move_aside(root: &Path) -> Result<PathBuf, String> {
    let now = crate::util::time::to_local(crate::util::time::now_unix());
    for attempt in 0..50 {
        let target = untrusted_sibling(root, now, attempt);
        if std::fs::symlink_metadata(&target).is_ok() {
            continue;
        }
        return std::fs::rename(root, &target)
            .map(|()| target.clone())
            .map_err(|e| format!("it could not be moved to {}: {e}", target.display()));
    }
    Err(format!("no free name to move {} aside", root.display()))
}

/// Make `root` (and everything below it) owned by Administrators and accessible only to SYSTEM
/// and Administrators. Children lose any explicit ACL and inherit from `root`. Reparse points
/// (junctions/symlinks planted to redirect our writes) are refused at the root and removed below
/// it. With `only_if_needed` nothing is changed when the root already has the expected ACL.
///
/// Every failure is reported: `Err` lists the entries whose owner/ACL could not be reset (the
/// installer treats that as fatal; the service logs it). Returns `Ok(true)` when changed.
pub(crate) fn secure_data_dir(root: &Path, only_if_needed: bool) -> Result<bool, String> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| format!("Cannot access {}: {e}", root.display()))?;
    if is_reparse_point(&meta) || !meta.is_dir() {
        return Err(format!(
            "{} is a junction, symbolic link or file — refusing to use it as the data directory. Delete it and run install again.",
            root.display()
        ));
    }
    if only_if_needed && path_sddl(root).map(|s| is_secure_data_dir_sddl(&s)).unwrap_or(false) {
        return Ok(false);
    }
    let sd = SecurityDescriptor::from_sddl(DATA_DIR_SDDL)?;
    let dacl = sd.dacl()?;
    let owner = sd.owner()?;
    let mut failures = Vec::new();
    let w = wide_path(root);
    let full = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: valid path and SD components; the OS copies what it needs.
    let mut rc = unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, full, owner, null_mut(), dacl, null()) };
    if rc == ERROR_INVALID_OWNER {
        failures.push(format!("cannot make Administrators the owner of {}", root.display()));
        let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: as above.
        rc = unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, info, null_mut(), null_mut(), dacl, null()) };
    }
    if rc != 0 {
        return Err(format!("Cannot secure {}: {}", root.display(), WinError::new(rc, "SetNamedSecurityInfoW")));
    }
    // Children: owner Administrators, explicit ACEs removed so only the inherited ones remain.
    let empty = SecurityDescriptor::from_sddl("D:")?;
    let mut reset = TreeReset::new(owner, empty.dacl()?);
    reset.run(root, 0);
    failures.append(&mut reset.failures);
    if failures.is_empty() { Ok(true) } else { Err(summarize_failures(root, &failures)) }
}

fn summarize_failures(root: &Path, failures: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut text =
        format!("Cannot fully secure {}: {}", root.display(), failures[..failures.len().min(SHOWN)].join("; "));
    if failures.len() > SHOWN {
        text.push_str(&format!(" (and {} more)", failures.len() - SHOWN));
    }
    text
}

/// Resets owner + explicit ACL of everything below a directory, collecting every failure.
struct TreeReset {
    owner: PSID,
    empty_dacl: *mut ACL,
    failures: Vec<String>,
    budget: usize,
    /// Take-ownership privileges, enabled on the first access-denied entry (`None` = not yet).
    privileges: Option<Vec<PrivilegeGuard>>,
}

impl TreeReset {
    fn new(owner: PSID, empty_dacl: *mut ACL) -> Self {
        Self { owner, empty_dacl, failures: Vec::new(), budget: MAX_TREE_ENTRIES, privileges: None }
    }

    fn run(&mut self, dir: &Path, depth: u32) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                self.failures.push(format!("cannot list {}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    self.failures.push(format!("cannot list {}: {e}", dir.display()));
                    continue;
                }
            };
            if self.budget == 0 {
                self.failures.push(format!("{} contains too many files", dir.display()));
                return;
            }
            self.budget -= 1;
            let path = entry.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    self.failures.push(format!("cannot inspect {}: {e}", path.display()));
                    continue;
                }
            };
            if is_reparse_point(&meta) {
                match remove_link(&path, &meta) {
                    Ok(()) => {
                        crate::log_warn!("removed unexpected reparse point {} from the data directory", path.display())
                    }
                    Err(e) => self.failures.push(format!("cannot remove the junction/link {}: {e}", path.display())),
                }
                continue;
            }
            if let Err(e) = self.reset_one(&path) {
                self.failures.push(format!("cannot reset the permissions of {}: {e}", path.display()));
            }
            if meta.is_dir() {
                if depth + 1 >= MAX_TREE_DEPTH {
                    self.failures.push(format!("{} is nested too deeply", path.display()));
                } else {
                    self.run(&path, depth + 1);
                }
            }
        }
    }

    /// Owner Administrators + empty explicit DACL (only inherited entries remain). When the
    /// entry's DACL denies us, take ownership first (SeTakeOwnership/SeRestore privileges); the
    /// new owner may then replace the DACL.
    fn reset_one(&mut self, path: &Path) -> Result<(), WinError> {
        let w = wide_path(path);
        let full = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: valid path, owner SID and (empty) DACL.
        let rc = unsafe {
            SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, full, self.owner, null_mut(), self.empty_dacl, null())
        };
        if rc == 0 {
            return Ok(());
        }
        if rc != ERROR_ACCESS_DENIED {
            return Err(WinError::new(rc, "SetNamedSecurityInfoW"));
        }
        if self.privileges.is_none() {
            self.privileges = Some(
                ["SeTakeOwnershipPrivilege", "SeRestorePrivilege"]
                    .iter()
                    .filter_map(|p| PrivilegeGuard::enable(p))
                    .collect(),
            );
        }
        // SAFETY: as above; owner only.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                self.owner,
                null_mut(),
                null_mut(),
                null(),
            )
        };
        if rc != 0 {
            return Err(WinError::new(rc, "SetNamedSecurityInfoW(owner)"));
        }
        let info = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: as above; DACL only.
        let rc = unsafe {
            SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, info, null_mut(), null_mut(), self.empty_dacl, null())
        };
        if rc != 0 {
            return Err(WinError::new(rc, "SetNamedSecurityInfoW(DACL)"));
        }
        Ok(())
    }
}

/// Enables a privilege that the process token holds (disabled) for the guard's lifetime and
/// disables it again on drop when it was off before.
struct PrivilegeGuard {
    token: OwnedHandle,
    luid: LUID,
    restore: bool,
}

impl PrivilegeGuard {
    fn enable(name: &str) -> Option<Self> {
        let wname = wide(name);
        let mut luid = LUID::default();
        // SAFETY: NUL-terminated name; valid out pointer.
        if unsafe { LookupPrivilegeValueW(null(), wname.as_ptr(), &mut luid) } == 0 {
            return None;
        }
        let mut raw: HANDLE = null_mut();
        // SAFETY: pseudo handle of the current process; the token handle is closed by OwnedHandle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut raw) } == 0 {
            return None;
        }
        let token = OwnedHandle(raw);
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let mut prev = TOKEN_PRIVILEGES::default();
        let mut len = 0u32;
        // SAFETY: valid token with TOKEN_ADJUST_PRIVILEGES; `prev` has the size passed.
        let ok = unsafe {
            SetLastError(ERROR_SUCCESS);
            AdjustTokenPrivileges(token.raw(), 0, &tp, size_of::<TOKEN_PRIVILEGES>() as u32, &mut prev, &mut len)
        };
        if ok == 0 || last_error() == ERROR_NOT_ALL_ASSIGNED {
            return None;
        }
        // PreviousState lists the privilege only when its state actually changed.
        Some(Self { token, luid, restore: prev.PrivilegeCount > 0 })
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        if self.restore {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: self.luid, Attributes: 0 }],
            };
            // SAFETY: same token handle; disables the privilege we enabled.
            unsafe { AdjustTokenPrivileges(self.token.raw(), 0, &tp, 0, null_mut(), null_mut()) };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Registry: HKLM Run value for the tray
// ---------------------------------------------------------------------------------------------

pub(crate) fn set_run_value(name: &str, command: &str) -> Result<(), String> {
    let key = wide(RUN_KEY);
    let value = wide(name);
    let data = wide(command);
    // SAFETY: NUL-terminated strings; `data` length in bytes includes the terminator.
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    if rc != 0 {
        return Err(format!("Cannot write HKLM\\{RUN_KEY}\\{name}: {}", WinError::new(rc, "RegSetKeyValueW")));
    }
    Ok(())
}

/// Returns `Ok(false)` when the value did not exist.
pub(crate) fn delete_run_value(name: &str) -> Result<bool, String> {
    let key = wide(RUN_KEY);
    let value = wide(name);
    // SAFETY: NUL-terminated strings.
    let rc = unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr()) };
    match rc {
        0 => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        _ => Err(format!("Cannot delete HKLM\\{RUN_KEY}\\{name}: {}", WinError::new(rc, "RegDeleteKeyValueW"))),
    }
}

pub(crate) fn get_run_value(name: &str) -> Option<String> {
    let key = wide(RUN_KEY);
    let value = wide(name);
    let mut buf = [0u16; 1024];
    let mut cb = (buf.len() * 2) as u32;
    // SAFETY: `buf` has `cb` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut cb,
        )
    };
    (rc == 0).then(|| from_wide(&buf))
}

// ---------------------------------------------------------------------------------------------
// Console: hidden input
// ---------------------------------------------------------------------------------------------

/// Restores the console input mode on drop.
struct ConsoleModeGuard(HANDLE, u32);

impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the mode captured from the same console handle.
        unsafe { SetConsoleMode(self.0, self.1) };
    }
}

/// Prompt on stderr and read one line from the console with echo disabled.
pub(crate) fn read_hidden_line(prompt: &str) -> Result<Secret, String> {
    use std::io::Write;
    // SAFETY: standard handle query / console mode calls on our own console.
    let (h, mode) = unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
            return Err("Standard input is not a console, so the token cannot be typed in hidden. \
                        Use 'set-token --file PATH' or pipe it with 'set-token --stdin'."
                .into());
        }
        (h, mode)
    };
    let _restore = ConsoleModeGuard(h, mode);
    // SAFETY: same console handle.
    unsafe { SetConsoleMode(h, (mode & !ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT) };
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let res = std::io::stdin().read_line(&mut line);
    eprintln!();
    let secret = Secret::trimmed(line);
    res.map_err(|e| format!("Cannot read from the console: {e}"))?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_syntax() {
        assert!(looks_like_sid("S-1-5-18"));
        assert!(looks_like_sid("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(!looks_like_sid("S-1-"));
        assert!(!looks_like_sid("S-1-5--18"));
        assert!(!looks_like_sid("alex"));
        assert!(!looks_like_sid("S-1-5-18; rm"));
        assert_eq!(canonical_sid("s-1-5-18").as_deref(), Some("S-1-5-18"));
        assert_eq!(canonical_sid("S-1-x"), None);
    }

    #[test]
    fn well_known_names() {
        let n = account_name_of("S-1-5-18").unwrap_or_default();
        assert!(n.to_ascii_uppercase().contains("SYSTEM"), "{n}");
        let me = current_process_facts().unwrap();
        assert!(looks_like_sid(&me.sid));
    }

    #[test]
    fn sddl_parse_and_compare() {
        let sd = SecurityDescriptor::from_sddl(DATA_DIR_SDDL).unwrap();
        assert!(!sd.dacl().unwrap().is_null());
        assert!(!sd.owner().unwrap().is_null());
        assert!(SecurityDescriptor::from_sddl("D:garbage(").is_err());
        assert!(is_secure_data_dir_sddl("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"));
        assert!(is_secure_data_dir_sddl("O:SYG:SYD:PAI(A;CIOI;FA;;;BA)(A;OICI;0x1f01ff;;;SY)"));
        assert!(!is_secure_data_dir_sddl("O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;BU)"));
        assert!(!is_secure_data_dir_sddl("O:BAD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), "not protected");
        assert!(!is_secure_data_dir_sddl("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)"));
        assert!(!is_secure_data_dir_sddl("O:BAD:PAI(A;OICIIO;FA;;;SY)(A;OICI;FA;;;BA)"), "inherit-only");
        assert!(!is_secure_data_dir_sddl("O:BAD:NO_ACCESS_CONTROL"));
        let tmp = std::env::temp_dir();
        assert!(path_sddl(&tmp).unwrap().contains("D:"));
    }

    #[test]
    fn sddl_parser() {
        let i = parse_sddl("O:S-1-5-21-1-2-3-1001G:SYD:PAI(A;OICIID;0x1301bf;;;AU)(D;;FA;;;WD)S:AI(AU;SA;FA;;;WD)");
        assert_eq!(i.owner.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(i.dacl_flags.as_deref(), Some("PAI"));
        assert_eq!(i.aces.len(), 2, "SACL entries are not DACL entries: {i:?}");
        assert_eq!(i.aces[0].kind, "A");
        assert_eq!(i.aces[0].flags, "OICIID");
        assert_eq!(i.aces[0].rights, "0X1301BF");
        assert_eq!(i.aces[0].trustee, "AU");
        assert_eq!(i.aces[1].kind, "D");
        assert!(i.aces[0].has_flag("ID") && !i.aces[0].has_flag("IO"));
        let none = parse_sddl("O:BA");
        assert!(none.dacl_is_null());
        assert!(parse_sddl("O:BAD:NO_ACCESS_CONTROL").dacl_is_null());
        assert!(parse_sddl("").owner.is_none());
        assert_eq!(rights_mask("FA"), 0x1F_01FF);
        assert_eq!(rights_mask("0x1200a9"), 0x12_00A9);
        assert_eq!(rights_mask("CCDC"), 0x3);
        assert_eq!(rights_mask("zz"), u32::MAX);
        assert_eq!(rights_mask("FR") & WRITE_RIGHTS, 0);
        assert_eq!(rights_mask("0x1200a9") & WRITE_RIGHTS, 0, "read & execute");
        assert_ne!(rights_mask("0x1301bf") & WRITE_RIGHTS, 0, "modify");
        assert_eq!(describe_trustee("WD"), "Everyone (WD)");
    }

    #[test]
    fn data_dir_root_trust() {
        assert_eq!(root_distrust_reason(DATA_DIR_SDDL), None);
        // Legacy installer ACL with an OWNER RIGHTS entry is still administrators-only.
        assert_eq!(root_distrust_reason("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)"), None);
        assert_eq!(root_distrust_reason("O:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"), None);
        // Pre-created by a standard user: their owner, ACL inherited from ProgramData.
        let planted =
            "O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;CIID;DCLCRPCR;;;BU)";
        assert!(root_distrust_reason(planted).unwrap().contains("owned by"));
        let inherited = "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;CIID;DCLCRPCR;;;BU)";
        assert!(root_distrust_reason(inherited).unwrap().contains("inherited"));
        let extra = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)";
        assert!(root_distrust_reason(extra).unwrap().contains("grant access"));
        assert!(root_distrust_reason("O:BAD:NO_ACCESS_CONTROL").unwrap().contains("no access control"));
        assert!(root_distrust_reason("D:PAI(A;OICI;FA;;;SY)").unwrap().contains("owner"));
        // A deny entry for someone else grants nothing.
        assert_eq!(root_distrust_reason("O:BAD:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), None);
    }

    #[test]
    fn data_dir_child_trust() {
        let me = "S-1-5-21-1-2-3-500";
        let inherited = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)";
        assert_eq!(child_distrust_reason(&format!("O:BA{inherited}"), None), None);
        assert_eq!(child_distrust_reason(&format!("O:SY{inherited}"), None), None);
        assert_eq!(child_distrust_reason(&format!("O:S-1-5-80-1-2-3-4-5{inherited}"), None), None);
        assert_eq!(child_distrust_reason(&format!("O:{me}{inherited}"), Some(me)), None);
        assert!(child_distrust_reason(&format!("O:{me}{inherited}"), None).unwrap().contains("owned by"));
        assert!(child_distrust_reason(&format!("O:S-1-5-21-9-9-9-1001{inherited}"), Some(me)).is_some());
        let shared = "O:BAD:AI(A;;FA;;;WD)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)";
        assert!(child_distrust_reason(shared, None).unwrap().contains("Everyone"));
        assert!(child_distrust_reason("O:BAD:NO_ACCESS_CONTROL", None).is_some());
        assert!(child_distrust_reason("D:AI(A;;FA;;;SY)", None).is_some());
    }

    #[test]
    fn program_file_write_access() {
        // Program Files style: TrustedInstaller/SYSTEM/Administrators full, Users read+execute,
        // application packages read+execute, CREATOR OWNER inherit-only.
        let pf = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;RC;;;OW)\
                  (A;CIIO;GA;;;CO)(A;OICI;0x1200a9;;;AC)(A;CI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)";
        assert_eq!(nonadmin_write_reason(pf, None), None);
        let ti_owned = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;SY)";
        assert_eq!(nonadmin_write_reason(ti_owned, None), None);
        // A repository folder: Authenticated Users may modify.
        let repo = "O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1301bf;;;AU)";
        assert!(nonadmin_write_reason(repo, Some("S-1-5-21-1-2-3-1001")).unwrap().contains("Authenticated Users"));
        assert!(nonadmin_write_reason(repo, None).unwrap().contains("owned by"));
        // Planted exe kept by Copy-Item -Force: Everyone full control.
        assert!(nonadmin_write_reason("O:BAD:P(A;;FA;;;WD)", None).is_some());
        // Users may only add files: still a DLL-planting hole.
        assert!(nonadmin_write_reason("O:BAD:P(A;;FA;;;BA)(A;;0x100002;;;BU)", None).is_some());
    }

    #[test]
    fn untrusted_names() {
        let t = LocalTime { year: 2026, month: 11, day: 5, hour: 7, minute: 8, second: 9 };
        let root = Path::new(r"C:\ProgramData\Predator");
        assert_eq!(untrusted_sibling(root, t, 0), PathBuf::from(r"C:\ProgramData\Predator.untrusted-20261105-070809"));
        assert_eq!(
            untrusted_sibling(root, t, 1),
            PathBuf::from(r"C:\ProgramData\Predator.untrusted-20261105-070809-2")
        );
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("predator-winsec-{tag}-{}", crate::util::rand::hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn assess_and_move_aside() {
        let base = temp_dir("assess");
        let root = base.join("Predator");
        assert_eq!(assess_data_dir(&root, true), DirTrust::Missing);
        // A folder created the ordinary way inherits the parent's ACL: never trusted.
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("token.dat"), b"PDT1Mforged").unwrap();
        match assess_data_dir(&root, true) {
            DirTrust::Untrusted(why) => assert!(why.contains("owned by") || why.contains("inherited"), "{why}"),
            other => panic!("unexpected {other:?}"),
        }
        let moved = move_aside(&root).unwrap();
        assert!(!root.exists());
        assert!(moved.file_name().unwrap().to_string_lossy().starts_with("Predator.untrusted-"));
        assert!(moved.join("token.dat").exists(), "contents are moved, not read or deleted");
        // A file where the folder should be.
        std::fs::write(&root, b"x").unwrap();
        assert_eq!(assess_data_dir(&root, false), DirTrust::Untrusted("it is not a folder".into()));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn atomic_creation_applies_the_descriptor() {
        let me = current_process_facts().unwrap().sid;
        let base = temp_dir("create");
        let dir = base.join("secured");
        // Grant ourselves access too so the test can clean up without elevation.
        let sddl = format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})");
        assert!(crate::paths::create_dir_with_sddl(&dir, &sddl).unwrap());
        assert!(!crate::paths::create_dir_with_sddl(&dir, &sddl).unwrap(), "already exists");
        let info = parse_sddl(&path_sddl(&dir).unwrap());
        assert!(info.dacl_protected(), "{info:?}");
        assert_eq!(info.aces.len(), 3, "{info:?}");
        assert!(info.aces.iter().all(|a| !a.has_flag("ID")), "nothing inherited from the temp folder: {info:?}");
        // Children inherit exactly these entries.
        std::fs::write(dir.join("child.txt"), b"x").unwrap();
        let child = parse_sddl(&path_sddl(&dir.join("child.txt")).unwrap());
        assert!(child.aces.iter().all(|a| a.has_flag("ID")), "{child:?}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn tree_reset_reports_every_failure() {
        let base = temp_dir("reset");
        std::fs::create_dir_all(base.join("logs")).unwrap();
        std::fs::write(base.join("settings.json"), b"{}").unwrap();
        std::fs::write(base.join("logs").join("predator.log"), b"x").unwrap();
        let sd = SecurityDescriptor::from_sddl(DATA_DIR_SDDL).unwrap();
        let empty = SecurityDescriptor::from_sddl("D:").unwrap();
        let mut reset = TreeReset::new(sd.owner().unwrap(), empty.dacl().unwrap());
        reset.run(&base, 0);
        if super::super::commands::is_elevated() {
            assert!(reset.failures.is_empty(), "{:?}", reset.failures);
        } else {
            // A standard user cannot make Administrators the owner: each entry is reported.
            assert_eq!(reset.failures.len(), 3, "{:?}", reset.failures);
            let all = summarize_failures(&base, &reset.failures);
            assert!(all.contains("settings.json") && all.contains("predator.log"), "{all}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn secret_redacts() {
        let s = Secret::trimmed("  abc \n".to_string());
        assert_eq!(s.expose(), "abc");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }
}
