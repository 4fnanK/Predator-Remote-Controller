//! Audit policy for logon events (AuditQuerySystemPolicy / AuditSetSystemPolicy).
//!
//! Only three subcategories are ever read or written: Logon `{0CCE9215-…}` (4624/4625),
//! Logoff `{0CCE9216-…}` (4634/4647) and Other Logon/Logoff Events `{0CCE921C-…}` (4778/4779).
//! The service itself never changes the policy — only the installer/uninstaller CLI does.
//! Values: 0 none, 1 success, 2 failure, 3 both. When *setting*, 0 means "unchanged", so a saved
//! 0 is restored as `POLICY_AUDIT_EVENT_NONE` (4).

use std::path::Path;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD};
use windows_sys::Win32::Security::Authentication::Identity::{
    AUDIT_POLICY_INFORMATION, Audit_Logon_Logoff, Audit_Logon_Logon, Audit_Logon_Others, AuditFree,
    AuditQuerySystemPolicy, AuditSetSystemPolicy, POLICY_AUDIT_EVENT_FAILURE, POLICY_AUDIT_EVENT_NONE,
    POLICY_AUDIT_EVENT_SUCCESS,
};
use windows_sys::core::GUID;

use crate::util::win::{WinError, last_error};

const SUCCESS: u32 = POLICY_AUDIT_EVENT_SUCCESS as u32;
const FAILURE: u32 = POLICY_AUDIT_EVENT_FAILURE as u32;
const NONE: u32 = POLICY_AUDIT_EVENT_NONE as u32;

struct Subcategory {
    name: &'static str,
    guid: GUID,
    /// Bits that must be set for monitoring to be complete.
    sufficient: u32,
    /// Bits the installer enables.
    enable: u32,
}

const SUBCATEGORIES: [Subcategory; 3] = [
    Subcategory { name: "Logon", guid: Audit_Logon_Logon, sufficient: SUCCESS | FAILURE, enable: SUCCESS | FAILURE },
    Subcategory { name: "Logoff", guid: Audit_Logon_Logoff, sufficient: SUCCESS, enable: SUCCESS },
    Subcategory {
        name: "Other Logon/Logoff",
        guid: Audit_Logon_Others,
        sufficient: SUCCESS,
        enable: SUCCESS | FAILURE,
    },
];

/// Current values of Logon, Logoff, Other Logon/Logoff (bit 0 success, bit 1 failure).
pub type AuditValues = [u32; 3];

fn guid_u128(g: &GUID) -> u128 {
    (u128::from(g.data1) << 96)
        | (u128::from(g.data2) << 80)
        | (u128::from(g.data3) << 64)
        | u128::from(u64::from_be_bytes(g.data4))
}

/// `{0CCE9215-69AE-11D9-BED3-505054503030}`.
fn guid_string(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

fn label(v: u32) -> &'static str {
    match v & (SUCCESS | FAILURE) {
        0 => "No auditing",
        SUCCESS => "Success",
        FAILURE => "Failure",
        _ => "Success+Failure",
    }
}

/// Text and sufficiency for a set of values, e.g.
/// `("Logon: Success+Failure · Logoff: Success · Other Logon/Logoff: Success+Failure", true)`.
pub fn describe_values(v: &AuditValues) -> (String, bool) {
    let text =
        SUBCATEGORIES.iter().zip(v.iter()).map(|(s, val)| format!("{}: {}", s.name, label(*val))).collect::<Vec<_>>();
    let sufficient = SUBCATEGORIES.iter().zip(v.iter()).all(|(s, val)| val & s.sufficient == s.sufficient);
    (text.join(" · "), sufficient)
}

/// Successful logons are audited (without this, no 4624 is ever written).
pub fn logon_success_enabled(v: &AuditValues) -> bool {
    v[0] & SUCCESS != 0
}

/// Values the installer sets: current bits plus the required ones (never removes auditing).
fn enabled_values(current: &AuditValues) -> AuditValues {
    let mut out = *current;
    for (o, s) in out.iter_mut().zip(SUBCATEGORIES.iter()) {
        *o = (*o & (SUCCESS | FAILURE)) | s.enable;
    }
    out
}

/// Value to pass to AuditSetSystemPolicy to restore a saved value (0 would mean "unchanged").
fn restore_value(saved: u32) -> u32 {
    match saved & (SUCCESS | FAILURE) {
        0 => NONE,
        v => v,
    }
}

fn audit_error(op: &str, code: u32) -> String {
    match code {
        ERROR_PRIVILEGE_NOT_HELD | ERROR_ACCESS_DENIED => {
            format!("cannot {op} the audit policy: administrator rights are required (SeSecurityPrivilege)")
        }
        _ => format!("cannot {op} the audit policy: {}", WinError::new(code, "Audit policy API")),
    }
}

/// Enable SeSecurityPrivilege in the process token. Failure is not fatal (the API may still be
/// allowed through AUDIT_QUERY/SET_SYSTEM_POLICY access); the error text is returned for context.
fn enable_security_privilege() -> Option<String> {
    let r = std::panic::catch_unwind(|| crate::sys::privilege::enable_privilege("SeSecurityPrivilege"));
    match r {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("privilege helper failed".to_string()),
    }
}

/// Read the three subcategories (requires SeSecurityPrivilege, i.e. admin or LocalSystem).
pub fn query_values() -> Result<AuditValues, String> {
    let priv_err = enable_security_privilege();
    let guids: [GUID; 3] = [SUBCATEGORIES[0].guid, SUBCATEGORIES[1].guid, SUBCATEGORIES[2].guid];
    let mut p: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
    // SAFETY: `guids` holds 3 GUIDs; on success the system allocates `p` (freed below).
    let ok = unsafe { AuditQuerySystemPolicy(guids.as_ptr(), guids.len() as u32, &mut p) };
    if !ok || p.is_null() {
        let code = last_error();
        if let Some(pe) = priv_err {
            crate::log_debug!("SeSecurityPrivilege could not be enabled: {pe}");
        }
        return Err(audit_error("read", code));
    }
    let mut out: AuditValues = [0; 3];
    let mut seen = [false; 3];
    for i in 0..guids.len() {
        // SAFETY: on success `p` points to an array of `guids.len()` entries.
        let entry = unsafe { &*p.add(i) };
        let g = guid_u128(&entry.AuditSubCategoryGuid);
        if let Some(idx) = SUBCATEGORIES.iter().position(|s| guid_u128(&s.guid) == g) {
            out[idx] = entry.AuditingInformation & (SUCCESS | FAILURE);
            seen[idx] = true;
        }
    }
    // SAFETY: `p` was allocated by AuditQuerySystemPolicy and is freed exactly once.
    unsafe { AuditFree(p.cast()) };
    if seen.iter().all(|s| *s) { Ok(out) } else { Err("unexpected audit policy data returned by Windows".to_string()) }
}

fn set_policy(changes: &[(GUID, u32)]) -> Result<(), String> {
    let infos: Vec<AUDIT_POLICY_INFORMATION> = changes
        .iter()
        .map(|(g, v)| AUDIT_POLICY_INFORMATION {
            AuditSubCategoryGuid: *g,
            AuditingInformation: *v,
            AuditCategoryGuid: GUID::from_u128(0),
        })
        .collect();
    // SAFETY: `infos` is a valid array of `infos.len()` entries for the duration of the call.
    let ok = unsafe { AuditSetSystemPolicy(infos.as_ptr(), infos.len() as u32) };
    if ok { Ok(()) } else { Err(audit_error("change", last_error())) }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BackupEntry {
    name: String,
    guid: String,
    value: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditBackup {
    version: u32,
    saved_unix: i64,
    subcategories: Vec<BackupEntry>,
}

fn make_backup(v: &AuditValues, now: i64) -> AuditBackup {
    AuditBackup {
        version: 1,
        saved_unix: now,
        subcategories: SUBCATEGORIES
            .iter()
            .zip(v.iter())
            .map(|(s, val)| BackupEntry { name: s.name.to_string(), guid: guid_string(&s.guid), value: *val })
            .collect(),
    }
}

/// Saved bits per known subcategory (index into [`SUBCATEGORIES`], success/failure bits) of
/// `backup`; unknown GUIDs are ignored.
fn restore_plan(backup: &AuditBackup) -> Vec<(usize, u32)> {
    SUBCATEGORIES
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let id = guid_string(&s.guid);
            backup
                .subcategories
                .iter()
                .find(|e| e.guid.trim().eq_ignore_ascii_case(&id))
                .map(|e| (i, e.value & (SUCCESS | FAILURE)))
        })
        .collect()
}

/// Changes (GUID, value to set) that restore `backup`; unknown GUIDs are ignored.
fn restore_changes(backup: &AuditBackup) -> Vec<(GUID, u32)> {
    restore_plan(backup).into_iter().map(|(i, v)| (SUBCATEGORIES[i].guid, restore_value(v))).collect()
}

/// A subcategory whose current value differs from the expected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mismatch {
    /// Index into [`SUBCATEGORIES`].
    idx: usize,
    have: u32,
    want: u32,
}

/// Subcategories of `expected` (index, success/failure bits) whose value in `actual` differs.
fn mismatches(expected: &[(usize, u32)], actual: &AuditValues) -> Vec<Mismatch> {
    expected
        .iter()
        .filter_map(|&(idx, want)| {
            let have = actual.get(idx).copied()? & (SUCCESS | FAILURE);
            let want = want & (SUCCESS | FAILURE);
            (have != want).then_some(Mismatch { idx, have, want })
        })
        .collect()
}

/// `"Logon is Success+Failure, expected Success; Logoff is ..."`.
fn describe_mismatches(m: &[Mismatch]) -> String {
    m.iter()
        .map(|m| format!("{} is {}, expected {}", SUBCATEGORIES[m.idx].name, label(m.have), label(m.want)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Re-read the policy and compare it with `expected`.
fn verify(expected: &[(usize, u32)]) -> Result<Vec<Mismatch>, String> {
    query_values().map(|v| mismatches(expected, &v))
}

/// Human readable current state of the Logon, Logoff and Other Logon/Logoff subcategories, plus
/// whether they are sufficient (`Logon` success+failure, `Logoff` success, `Other` success).
pub fn describe() -> Result<(String, bool), String> {
    query_values().map(|v| describe_values(&v))
}

/// Installer: save the original values to `backup` (only if no backup exists yet) and enable the
/// required subcategories. Requires admin (SeSecurityPrivilege). Returns a summary.
pub fn ensure_enabled(backup: &Path) -> Result<String, String> {
    let current = query_values()?;
    let mut note = String::new();
    if !backup.exists() {
        let json = serde_json::to_vec_pretty(&make_backup(&current, crate::util::time::now_unix()))
            .map_err(|e| format!("cannot serialize the audit-policy backup: {e}"))?;
        crate::paths::atomic_write(backup, &json)
            .map_err(|e| format!("cannot save the audit-policy backup to {}: {e}", backup.display()))?;
        note = format!(" Original values saved to {}.", backup.display());
    }
    let wanted = enabled_values(&current);
    let plan: Vec<(usize, u32)> =
        (0..SUBCATEGORIES.len()).filter(|&i| current[i] != wanted[i]).map(|i| (i, wanted[i])).collect();
    if plan.is_empty() {
        return Ok(format!("Audit policy already enabled: {}.{note}", describe_values(&current).0));
    }
    let changes: Vec<(GUID, u32)> = plan.iter().map(|&(i, v)| (SUBCATEGORIES[i].guid, v)).collect();
    set_policy(&changes)?;
    let after = query_values()?;
    let (text, sufficient) = describe_values(&after);
    let wrong = mismatches(&plan, &after);
    if !wrong.is_empty() || !sufficient {
        let detail = if wrong.is_empty() { String::new() } else { format!(" ({})", describe_mismatches(&wrong)) };
        return Err(format!(
            "the audit policy did not change as requested{detail}; now: {text}. A Group Policy or MDM setting may be \
             overriding it"
        ));
    }
    Ok(format!("Audit policy enabled: {text}.{note}"))
}

/// Uninstaller: restore exactly the saved subcategory values from `backup` (no-op if missing).
///
/// The result is verified by re-reading the policy. When a value did not come back exactly (for
/// example the API merged bits instead of replacing them), the subcategory is cleared with
/// `POLICY_AUDIT_EVENT_NONE` and set again; if it still differs, an error is returned and the
/// backup is KEPT so the restore can be retried.
pub fn restore(backup: &Path) -> Result<String, String> {
    let bytes = match std::fs::read(backup) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok("No audit-policy backup found; nothing to restore.".to_string());
        }
        Err(e) => return Err(format!("cannot read the audit-policy backup {}: {e}", backup.display())),
    };
    let saved: AuditBackup = serde_json::from_slice(&bytes)
        .map_err(|e| format!("the audit-policy backup {} is corrupt: {e}", backup.display()))?;
    let plan = restore_plan(&saved);
    let changes = restore_changes(&saved);
    if changes.is_empty() {
        return Err(format!("the audit-policy backup {} contains no known subcategories", backup.display()));
    }
    if let Some(pe) = enable_security_privilege() {
        crate::log_debug!("SeSecurityPrivilege not enabled: {pe}");
    }
    set_policy(&changes)?;
    let kept = |why: String| format!("{why}; the backup {} was kept so the restore can be retried", backup.display());
    let mut wrong = verify(&plan).map_err(|e| kept(format!("cannot verify the restored audit policy: {e}")))?;
    if !wrong.is_empty() {
        crate::log_warn!(
            "audit policy restore did not apply exactly ({}); clearing and re-applying",
            describe_mismatches(&wrong)
        );
        let (clear, set) = retry_plan(&wrong);
        for step in [&clear, &set] {
            if !step.is_empty() {
                set_policy(step).map_err(&kept)?;
            }
        }
        wrong = verify(&plan).map_err(|e| kept(format!("cannot verify the restored audit policy: {e}")))?;
        if !wrong.is_empty() {
            return Err(kept(format!(
                "the audit policy could not be restored exactly ({})",
                describe_mismatches(&wrong)
            )));
        }
    }
    let text = query_values().map(|v| describe_values(&v).0).unwrap_or_else(|e| format!("(could not re-read: {e})"));
    if let Err(e) = std::fs::remove_file(backup) {
        crate::log_warn!("audit policy restored but the backup {} could not be removed: {e}", backup.display());
    }
    Ok(format!("Audit policy restored: {text}."))
}

/// (subcategory GUID, value) pairs for one `AuditSetSystemPolicy` call.
type PolicyChanges = Vec<(GUID, u32)>;

/// Second attempt for mismatched subcategories: first clear them (NONE), then set the saved
/// bits of those whose saved value is not "no auditing" (the clear already achieved that).
fn retry_plan(wrong: &[Mismatch]) -> (PolicyChanges, PolicyChanges) {
    let clear = wrong.iter().map(|m| (SUBCATEGORIES[m.idx].guid, NONE)).collect();
    let set = wrong.iter().filter(|m| m.want != 0).map(|m| (SUBCATEGORIES[m.idx].guid, m.want)).collect();
    (clear, set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_match_auditpol() {
        assert_eq!(guid_string(&SUBCATEGORIES[0].guid), "{0CCE9215-69AE-11D9-BED3-505054503030}");
        assert_eq!(guid_string(&SUBCATEGORIES[1].guid), "{0CCE9216-69AE-11D9-BED3-505054503030}");
        assert_eq!(guid_string(&SUBCATEGORIES[2].guid), "{0CCE921C-69AE-11D9-BED3-505054503030}");
        assert_eq!(guid_u128(&SUBCATEGORIES[0].guid), 0x0cce9215_69ae_11d9_bed3_505054503030);
    }

    #[test]
    fn describe_and_sufficiency() {
        let (t, ok) = describe_values(&[3, 1, 3]);
        assert_eq!(t, "Logon: Success+Failure · Logoff: Success · Other Logon/Logoff: Success+Failure");
        assert!(ok);
        assert!(describe_values(&[3, 1, 1]).1);
        // Windows 11 default: Other Logon/Logoff not audited
        let (t, ok) = describe_values(&[3, 1, 0]);
        assert!(!ok);
        assert!(t.ends_with("Other Logon/Logoff: No auditing"));
        assert!(!describe_values(&[1, 1, 1]).1);
        assert_eq!(
            describe_values(&[2, 0, 0]).0,
            "Logon: Failure · Logoff: No auditing · Other Logon/Logoff: No auditing"
        );
        assert!(logon_success_enabled(&[1, 0, 0]));
        assert!(!logon_success_enabled(&[2, 1, 1]));
    }

    #[test]
    fn enabling_only_adds_bits() {
        assert_eq!(enabled_values(&[0, 0, 0]), [3, 1, 3]);
        assert_eq!(enabled_values(&[1, 3, 2]), [3, 3, 3]);
        assert_eq!(enabled_values(&[3, 1, 3]), [3, 1, 3]);
    }

    #[test]
    fn backup_roundtrip_and_restore_mapping() {
        let b = make_backup(&[1, 0, 2], 1234);
        let json = serde_json::to_string(&b).unwrap();
        let back: AuditBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
        let ch = restore_changes(&back);
        assert_eq!(ch.len(), 3);
        let vals: Vec<u32> = ch.iter().map(|(_, v)| *v).collect();
        assert_eq!(vals, vec![1, NONE, 2], "saved 0 must be restored as NONE (4), not UNCHANGED (0)");
        assert_eq!(restore_value(3), 3);
        assert_eq!(restore_value(4), NONE);
        // unknown GUIDs and case differences
        let custom = AuditBackup {
            version: 1,
            saved_unix: 0,
            subcategories: vec![
                BackupEntry { name: "x".into(), guid: "{0cce9216-69ae-11d9-bed3-505054503030}".into(), value: 1 },
                BackupEntry { name: "evil".into(), guid: "{0CCE9217-69AE-11D9-BED3-505054503030}".into(), value: 0 },
            ],
        };
        let ch = restore_changes(&custom);
        assert_eq!(ch.len(), 1);
        assert_eq!(guid_string(&ch[0].0), "{0CCE9216-69AE-11D9-BED3-505054503030}");
    }

    #[test]
    fn verification_detects_merged_bits() {
        let b = make_backup(&[1, 0, 2], 1234);
        let plan = restore_plan(&b);
        assert_eq!(plan, vec![(0, 1), (1, 0), (2, 2)]);
        assert!(mismatches(&plan, &[1, 0, 2]).is_empty(), "exact restore");
        // the API OR-ed the saved Success into the enabled Success+Failure
        let wrong = mismatches(&plan, &[3, 0, 3]);
        assert_eq!(wrong, vec![Mismatch { idx: 0, have: 3, want: 1 }, Mismatch { idx: 2, have: 3, want: 2 }]);
        assert_eq!(
            describe_mismatches(&wrong),
            "Logon is Success+Failure, expected Success; Other Logon/Logoff is Success+Failure, expected Failure"
        );
        let (clear, set) = retry_plan(&wrong);
        assert_eq!(
            clear.iter().map(|(g, v)| (guid_string(g), *v)).collect::<Vec<_>>(),
            vec![
                ("{0CCE9215-69AE-11D9-BED3-505054503030}".to_string(), NONE),
                ("{0CCE921C-69AE-11D9-BED3-505054503030}".to_string(), NONE),
            ]
        );
        assert_eq!(set.iter().map(|(_, v)| *v).collect::<Vec<_>>(), vec![1, 2]);
        // a saved "no auditing" is fully handled by the clear
        let none = mismatches(&[(1, 0)], &[3, 1, 3]);
        assert_eq!(none, vec![Mismatch { idx: 1, have: 1, want: 0 }]);
        let (clear, set) = retry_plan(&none);
        assert_eq!(clear.len(), 1);
        assert!(set.is_empty());
        // installer check: every changed subcategory must read back as requested
        assert!(mismatches(&[(2, 3)], &enabled_values(&[3, 1, 0])).is_empty());
        assert_eq!(mismatches(&[(2, 3)], &[3, 1, 1]).len(), 1);
    }

    #[test]
    fn restore_without_backup_is_noop() {
        let p = std::env::temp_dir().join(format!("predator-audit-{}.json", crate::util::rand::hex(4)));
        assert!(restore(&p).unwrap().contains("nothing to restore"));
        std::fs::write(&p, b"{not json").unwrap();
        assert!(restore(&p).unwrap_err().contains("corrupt"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn error_texts() {
        assert!(audit_error("read", 1314).contains("administrator"));
        assert!(audit_error("change", 5).contains("administrator"));
        assert!(audit_error("read", 87).contains("error 87"));
    }
}
