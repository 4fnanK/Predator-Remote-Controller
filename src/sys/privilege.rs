//! Token privilege helpers.
//!
//! LocalSystem holds `SeShutdownPrivilege`, but it is *disabled* in the token, so it must be
//! enabled before `InitiateShutdownW` / `SetSuspendState`. `AdjustTokenPrivileges` returns TRUE
//! even when it could not enable the privilege (the account does not hold it); that case is only
//! visible through `GetLastError() == ERROR_NOT_ALL_ASSIGNED` and is treated as a failure here.

use windows_sys::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, HANDLE, LUID, SetLastError};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::util::win::{OwnedHandle, WinError, last_error, wide};

/// Enable a privilege (e.g. `SeShutdownPrivilege`) in the current process token.
pub fn enable_privilege(name: &str) -> Result<(), WinError> {
    if name.is_empty() || name.contains('\0') {
        return Err(WinError::new(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER, "Invalid privilege name"));
    }
    let wname = wide(name);

    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    // SAFETY: `wname` is NUL-terminated and outlives the call; `luid` is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), wname.as_ptr(), &mut luid) } == 0 {
        return Err(WinError::last(format!("Unknown privilege {name}")));
    }

    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle; `raw` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut raw) } == 0 {
        return Err(WinError::last("OpenProcessToken"));
    }
    let token = OwnedHandle(raw);

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    // SAFETY: valid token handle with TOKEN_ADJUST_PRIVILEGES; `tp` lives across the call; the
    // previous-state output is not requested (null + 0 length).
    let ok = unsafe {
        SetLastError(ERROR_SUCCESS);
        AdjustTokenPrivileges(token.raw(), 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    let err = last_error();
    adjust_outcome(ok != 0, err).map_err(|code| {
        if code == ERROR_NOT_ALL_ASSIGNED {
            WinError::new(code, format!("{name} is not held by this account"))
        } else {
            WinError::new(code, format!("AdjustTokenPrivileges({name})"))
        }
    })
}

/// Interpret the result of `AdjustTokenPrivileges` (`ok` = return value != 0, `last_error` =
/// `GetLastError()` right after the call). Returns the failing error code.
fn adjust_outcome(ok: bool, last_error: u32) -> Result<(), u32> {
    if !ok {
        // A failed call always sets an error; guard against a bogus 0.
        return Err(if last_error == 0 { windows_sys::Win32::Foundation::ERROR_GEN_FAILURE } else { last_error });
    }
    if last_error == ERROR_NOT_ALL_ASSIGNED {
        return Err(ERROR_NOT_ALL_ASSIGNED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_mapping() {
        assert_eq!(adjust_outcome(true, 0), Ok(()));
        assert_eq!(adjust_outcome(true, ERROR_NOT_ALL_ASSIGNED), Err(1300));
        assert_eq!(adjust_outcome(false, 5), Err(5));
        assert!(adjust_outcome(false, 0).is_err());
    }

    #[test]
    fn enables_held_privilege() {
        // Every interactive account (standard users included) holds SeShutdownPrivilege
        // (disabled). Enabling it only affects this test process's token.
        enable_privilege("SeShutdownPrivilege").expect("SeShutdownPrivilege should be enableable");
        // Idempotent.
        enable_privilege("SeShutdownPrivilege").unwrap();
    }

    #[test]
    fn rejects_unknown_privilege() {
        let e = enable_privilege("SeDefinitelyNotAPrivilege").unwrap_err();
        assert_ne!(e.code, 0);
        assert!(e.to_string().contains("SeDefinitelyNotAPrivilege"));
        assert!(enable_privilege("").is_err());
    }

    #[test]
    fn not_held_privilege_is_an_error() {
        // SeTcbPrivilege is only held by LocalSystem; a normal (even elevated) user does not hold it.
        if crate_is_local_system() {
            return;
        }
        let e = enable_privilege("SeTcbPrivilege").unwrap_err();
        assert_eq!(e.code, ERROR_NOT_ALL_ASSIGNED);
        assert!(e.to_string().contains("not held"), "{e}");
    }

    fn crate_is_local_system() -> bool {
        std::env::var("USERNAME").map(|u| u.ends_with('$') || u.eq_ignore_ascii_case("SYSTEM")).unwrap_or(false)
    }
}
