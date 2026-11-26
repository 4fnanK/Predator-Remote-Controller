//! Bot token storage protected with Windows DPAPI (CryptProtectData), never plain text.
//!
//! File format: 4-byte magic `PDT1` + 1 byte scope (`M` = LocalMachine, `U` = CurrentUser) +
//! DPAPI blob (with fixed application entropy).
//!
//! # Scope decision: machine scope, protected by the file ACL
//! `set-token` (an elevated administrator) writes a **machine-scope** blob into the
//! SYSTEM/Administrators-only data directory, and it stays that way: the service reads it
//! directly. A machine-scope blob can be decrypted by any process on this PC that can *read*
//! the file, so the real protection is `token.dat`'s ACL (inherited from the data directory:
//! SYSTEM + Administrators only). Earlier versions re-protected the token with LocalSystem's user
//! scope on the first service start. That added no real protection — an administrator can always
//! run code as SYSTEM — but it locked elevated administrators out of `pair` and `selftest`, so
//! the service no longer does it. [`migrate_to_user_scope`] is kept for API compatibility only;
//! [`migrate_to_machine_scope`] converts a blob written by such an older version back (it must
//! run as the account that protected it, i.e. the service). [`load_token`] accepts both scopes.
//!
//! # Trust
//! Any local account can create a machine-scope blob with the (public) entropy, so a
//! `token.dat` means something only inside a trusted data directory (owner SYSTEM/Administrators,
//! protected ACL). The installer moves an untrusted directory aside instead of reusing its token.
//!

use std::path::Path;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use crate::util::win::{WinError, wide};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// CRYPTPROTECT_LOCAL_MACHINE — any process on this machine that can read the file.
    Machine,
    /// Current user only (LocalSystem when called from the service).
    CurrentUser,
}

impl Scope {
    fn byte(self) -> u8 {
        match self {
            Scope::Machine => SCOPE_MACHINE,
            Scope::CurrentUser => SCOPE_USER,
        }
    }

    fn from_byte(b: u8) -> Option<Scope> {
        match b {
            SCOPE_MACHINE => Some(Scope::Machine),
            SCOPE_USER => Some(Scope::CurrentUser),
            _ => None,
        }
    }

    /// Human readable description (selftest / CLI output).
    pub fn describe(self) -> &'static str {
        match self {
            Scope::Machine => "machine scope (readable by the service and administrators on this PC)",
            Scope::CurrentUser => "user scope (readable only by the account that stored it)",
        }
    }
}

const MAGIC: &[u8; 4] = b"PDT1";
const SCOPE_MACHINE: u8 = b'M';
const SCOPE_USER: u8 = b'U';
/// Fixed application entropy: a blob from another DPAPI user cannot be decrypted by us by
/// accident, and a casual `CryptUnprotectData` without the entropy fails.
const ENTROPY: &[u8] = b"PredatorRemoteController/v1";
/// token.dat is tiny (≈ 300 bytes); refuse anything absurd.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Overwrite a buffer with zeros in a way the optimizer cannot remove.
pub(crate) fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, exclusive reference to one byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Encrypt and atomically store `token`.
pub fn save_token(path: &Path, token: &str, scope: Scope) -> Result<(), String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("Refusing to store an empty bot token".into());
    }
    let blob = protect(token.as_bytes(), scope)?;
    let data = encode_file(scope, &blob);
    crate::paths::atomic_write(path, &data).map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

/// Load and decrypt the token (either scope).
pub fn load_token(path: &Path) -> Result<String, String> {
    let data = read_token_file(path)?;
    let (scope, blob) = parse_file(&data)?;
    let mut plain = unprotect(blob, scope)?;
    let result = match std::str::from_utf8(&plain) {
        Ok(s) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        Ok(_) => Err(format!("{} contains an empty token", path.display())),
        Err(_) => Err(format!("{} does not contain a valid token (not UTF-8)", path.display())),
    };
    zeroize(&mut plain);
    result
}

/// If the stored blob is machine-scope, re-protect it with current-user scope. Returns true when
/// migrated.
///
/// Kept for API compatibility only: the service no longer calls it (see the module docs — user
/// scope locks elevated administrators out of `pair`/`selftest` without adding protection).
pub fn migrate_to_user_scope(path: &Path) -> Result<bool, String> {
    reprotect(path, Scope::CurrentUser)
}

/// If the stored blob is user-scope (written for LocalSystem by an older version), re-protect it
/// with machine scope so elevated administrators can use it again. Must run as the account that
/// protected it (the service). Returns true when migrated; a machine-scope file is left as is.
pub fn migrate_to_machine_scope(path: &Path) -> Result<bool, String> {
    reprotect(path, Scope::Machine)
}

/// Rewrite the token file with `target` scope (no-op when it already has it).
fn reprotect(path: &Path, target: Scope) -> Result<bool, String> {
    let data = read_token_file(path)?;
    let (scope, blob) = parse_file(&data)?;
    if scope == target {
        return Ok(false);
    }
    let mut plain = unprotect(blob, scope)?;
    let protected = protect(&plain, target);
    zeroize(&mut plain);
    let data = encode_file(target, &protected?);
    crate::paths::atomic_write(path, &data).map_err(|e| format!("Cannot rewrite {}: {e}", path.display()))?;
    Ok(true)
}

/// Scope of the stored token without decrypting it. `Ok(None)` when no token file exists.
pub fn stored_scope(path: &Path) -> Result<Option<Scope>, String> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let data = read_token_file(path)?;
    parse_file(&data).map(|(scope, _)| Some(scope))
}

fn read_token_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            format!("No bot token is stored ({} not found). Run 'predator-service set-token'.", path.display())
        }
        std::io::ErrorKind::PermissionDenied => {
            format!("Access to {} was denied (administrator rights are required).", path.display())
        }
        _ => format!("Cannot read {}: {e}", path.display()),
    })?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("{} is too large to be a token file", path.display()));
    }
    std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("Access to {} was denied (administrator rights are required).", path.display())
        }
        _ => format!("Cannot read {}: {e}", path.display()),
    })
}

fn encode_file(scope: Scope, blob: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(MAGIC.len() + 1 + blob.len());
    data.extend_from_slice(MAGIC);
    data.push(scope.byte());
    data.extend_from_slice(blob);
    data
}

/// Split a token file into (scope, DPAPI blob).
fn parse_file(data: &[u8]) -> Result<(Scope, &[u8]), String> {
    if data.len() < MAGIC.len() + 2 || &data[..MAGIC.len()] != MAGIC {
        return Err(
            "token.dat is not a Predator token file (bad header); store the token again with 'set-token'".into()
        );
    }
    let scope = Scope::from_byte(data[MAGIC.len()]).ok_or_else(|| {
        "token.dat has an unknown protection scope; store the token again with 'set-token'".to_string()
    })?;
    Ok((scope, &data[MAGIC.len() + 1..]))
}

fn blob_of(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

fn protect(plain: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
    let input = blob_of(plain);
    let entropy = blob_of(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    let flags = CRYPTPROTECT_UI_FORBIDDEN | if scope == Scope::Machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 };
    let description = wide("Predator bot token");
    // SAFETY: all blobs point to live buffers for the duration of the call; `out` receives a
    // LocalAlloc'ed buffer which is copied and freed below.
    let ok = unsafe {
        CryptProtectData(&input, description.as_ptr(), &entropy, std::ptr::null(), std::ptr::null(), flags, &mut out)
    };
    if ok == 0 || out.pbData.is_null() {
        return Err(format!("Cannot encrypt the token: {}", WinError::last("CryptProtectData")));
    }
    // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`.
    let blob = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: the buffer was allocated by DPAPI with LocalAlloc.
    unsafe { LocalFree(out.pbData as HLOCAL) };
    Ok(blob)
}

fn unprotect(blob: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
    let input = blob_of(blob);
    let entropy = blob_of(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input/entropy point to live buffers; `out` receives a LocalAlloc'ed buffer which
    // is copied, wiped and freed below.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 || out.pbData.is_null() {
        let err = WinError::last("CryptUnprotectData");
        return Err(match scope {
            Scope::CurrentUser => format!(
                "Cannot decrypt token.dat: it is protected for another Windows account (normally the service's \
                 LocalSystem account) — {err}"
            ),
            Scope::Machine => format!("Cannot decrypt token.dat — {err}"),
        });
    }
    // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`; we own the buffer until LocalFree.
    let plain = unsafe {
        let s = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let copy = s.to_vec();
        zeroize(s);
        LocalFree(out.pbData as HLOCAL);
        copy
    };
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456789:AAFakeTokenForTestsOnly_0123456789a";

    fn temp_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("predator-secrets-{}", crate::util::rand::hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip_both_scopes() {
        let dir = temp_dir();
        for scope in [Scope::Machine, Scope::CurrentUser] {
            let p = dir.join(format!("token-{scope:?}.dat"));
            save_token(&p, &format!("  {TOKEN}\n"), scope).unwrap();
            let raw = std::fs::read(&p).unwrap();
            assert_eq!(&raw[..4], b"PDT1");
            assert_eq!(raw[4], scope.byte());
            // never stored in plain text
            assert!(!raw.windows(10).any(|w| w == &TOKEN.as_bytes()[..10]));
            assert_eq!(load_token(&p).unwrap(), TOKEN);
            assert_eq!(stored_scope(&p).unwrap(), Some(scope));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrate_machine_to_user() {
        let dir = temp_dir();
        let p = dir.join("token.dat");
        save_token(&p, TOKEN, Scope::Machine).unwrap();
        assert!(migrate_to_user_scope(&p).unwrap());
        assert_eq!(stored_scope(&p).unwrap(), Some(Scope::CurrentUser));
        assert_eq!(load_token(&p).unwrap(), TOKEN);
        assert!(!migrate_to_user_scope(&p).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrate_user_back_to_machine() {
        let dir = temp_dir();
        let p = dir.join("token.dat");
        // What an older service left behind: a user-scope blob of the service account.
        save_token(&p, TOKEN, Scope::CurrentUser).unwrap();
        assert!(migrate_to_machine_scope(&p).unwrap());
        assert_eq!(stored_scope(&p).unwrap(), Some(Scope::Machine));
        assert_eq!(load_token(&p).unwrap(), TOKEN);
        assert!(!migrate_to_machine_scope(&p).unwrap(), "machine scope is left as is");
        assert!(migrate_to_machine_scope(&dir.join("missing.dat")).unwrap_err().contains("set-token"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_bad_files() {
        let dir = temp_dir();
        let p = dir.join("token.dat");
        assert!(load_token(&p).unwrap_err().contains("set-token"));
        assert_eq!(stored_scope(&p).unwrap(), None);
        std::fs::write(&p, b"hello world").unwrap();
        assert!(load_token(&p).unwrap_err().contains("bad header"));
        std::fs::write(&p, b"PDT1Xabc").unwrap();
        assert!(load_token(&p).unwrap_err().contains("scope"));
        // corrupt blob
        std::fs::write(&p, b"PDT1Mgarbage-garbage").unwrap();
        assert!(load_token(&p).unwrap_err().contains("decrypt"));
        assert!(save_token(&p, "   ", Scope::Machine).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_header() {
        assert!(parse_file(b"PDT1M").is_err());
        let (s, b) = parse_file(b"PDT1Uxy").unwrap();
        assert_eq!(s, Scope::CurrentUser);
        assert_eq!(b, b"xy");
        let mut v = vec![1u8, 2, 3];
        zeroize(&mut v);
        assert_eq!(v, [0, 0, 0]);
    }
}
