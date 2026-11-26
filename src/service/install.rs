//! `install` / `uninstall`: SCM registration and configuration, data directory trust + ACL, logon
//! audit policy and the tray autostart value. Only our own service is ever opened.
//!
//! Both commands act on the registered service, which always uses the protected default data
//! directory, so they refuse `--data-dir`. The setup wizard (`setup/`) copies the program into
//! its protected folder first and then uses [`register`] for the same steps.

use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
    SERVICE_PRESHUTDOWN_INFO, SERVICE_QUERY_STATUS, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_STOP,
    SERVICE_WIN32_OWN_PROCESS,
};

use super::commands::{DataCtx, reject_custom_data_dir, require_admin, service_state};
use super::winsec::{self, DirTrust};
use crate::paths::{
    DataPaths, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_EXE, SERVICE_NAME, TRAY_EXE, TRAY_RUN_VALUE,
};
use crate::sys::ServiceState;
use crate::util::win::{WinError, last_error, wide};

/// SCM handle closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle returned by OpenSCManagerW/OpenServiceW/CreateServiceW, closed once.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn open_scm(access: u32) -> Result<ScHandle, String> {
    // SAFETY: local machine, default database.
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h.is_null() {
        return Err(format!("Cannot open the Service Control Manager: {}", WinError::last("OpenSCManagerW")));
    }
    Ok(ScHandle(h))
}

/// `"<dir>\predator-service.exe"` — always quoted (paths with spaces).
pub(crate) fn service_command_line(exe_dir: &Path) -> String {
    format!("\"{}\"", exe_dir.join(SERVICE_EXE).display())
}

/// `"<dir>\predator-tray.exe"` for the HKLM Run value.
pub(crate) fn tray_command_line(exe_dir: &Path) -> String {
    format!("\"{}\"", exe_dir.join(TRAY_EXE).display())
}

/// Files next to the executables that a process loads automatically (DLL planting).
pub(crate) fn is_loadable_module(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".dll", ".ocx", ".cpl", ".local", ".manifest"].iter().any(|ext| n.ends_with(ext))
}

/// Refuse to register a LocalSystem service whose program folder or executables other accounts
/// can modify (they could replace the exe or plant a DLL it loads) — wherever the folder is.
/// Read-only; also used by setup before it updates the installed files.
pub(crate) fn check_program_files(exe_dir: &Path) -> Result<(), String> {
    let me = winsec::current_process_facts().map(|f| f.sid);
    let hint = format!(
        "A LocalSystem service must not run from a location other accounts can change. Start \
         PredatorRemoteController.exe without arguments (setup copies and protects the files in {}), or copy \
         both executables to a folder only administrators can modify and run 'install' from there.",
        crate::paths::DEFAULT_INSTALL_DIR
    );
    for path in [exe_dir.to_path_buf(), exe_dir.join(SERVICE_EXE), exe_dir.join(TRAY_EXE)] {
        if !path.exists() {
            continue;
        }
        let sddl =
            winsec::path_sddl(&path).map_err(|e| format!("Cannot read the permissions of {}: {e}", path.display()))?;
        if let Some(why) = winsec::nonadmin_write_reason(&sddl, me.as_deref()) {
            return Err(format!("{} {why}. {hint}", path.display()));
        }
    }
    let entries = std::fs::read_dir(exe_dir).map_err(|e| format!("Cannot list {}: {e}", exe_dir.display()))?;
    let modules: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_loadable_module(n))
        .collect();
    if !modules.is_empty() {
        return Err(format!(
            "{} contains files that Windows would load into the service ({}). Predator ships no such files; \
             delete them (setup removes them) and run install again.",
            exe_dir.display(),
            modules.join(", ")
        ));
    }
    Ok(())
}

/// Make the default data directory trustworthy before anything in it is used: a folder that
/// another account created or changed (foreign owner, inherited/extra permissions, junctions,
/// foreign files inside) is moved aside — its token, owner ids, settings, queue and audit-policy
/// backup are never reused — and a fresh one is created atomically with the protected ACL.
/// Every ACL failure is fatal.
pub(crate) fn prepare_data_dir(paths: &DataPaths) -> Result<(), String> {
    let root = &paths.root;
    match winsec::assess_data_dir(root, true) {
        DirTrust::Missing | DirTrust::Trusted => {}
        DirTrust::Untrusted(why) => {
            let moved = winsec::move_aside(root).map_err(|e| {
                format!(
                    "{} cannot be trusted ({why}) and {e}. Close programs that use files in it (or delete it) and \
                     run install again.",
                    root.display()
                )
            })?;
            println!("WARNING: {} cannot be trusted ({why}).", root.display());
            println!(
                "         It was moved to {} and NOTHING from it is used (bot token, owner, settings, queue, \
                 audit-policy backup). Store the token and pair again; delete that folder when you no longer need it.",
                moved.display()
            );
        }
    }
    paths.ensure_dirs_secure().map_err(|e| super::commands::io_error(root, &e))?;
    winsec::secure_data_dir(root, false)?;
    match winsec::assess_data_dir(root, true) {
        DirTrust::Trusted => Ok(()),
        DirTrust::Missing => Err(format!("{} disappeared while it was being secured", root.display())),
        DirTrust::Untrusted(why) => Err(format!("{} is still not protected after securing it ({why})", root.display())),
    }
}

/// Delete the data directory. With `keep`, every entry except the file named `keep` (compared
/// case-insensitively) is deleted and the directory itself stays. Junctions and symbolic links
/// are removed, never followed.
pub(crate) fn purge_data_dir(root: &Path, keep: Option<&str>) -> Result<(), String> {
    let Some(keep) = keep else {
        return std::fs::remove_dir_all(root).map_err(|e| format!("Cannot delete {}: {e}", root.display()));
    };
    let entries = std::fs::read_dir(root).map_err(|e| format!("Cannot list {}: {e}", root.display()))?;
    let mut failures = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                failures.push(e.to_string());
                continue;
            }
        };
        if entry.file_name().to_string_lossy().eq_ignore_ascii_case(keep) {
            continue;
        }
        let path = entry.path();
        let removed = std::fs::symlink_metadata(&path).and_then(|m| {
            use std::os::windows::fs::FileTypeExt;
            let ft = m.file_type();
            if ft.is_symlink_dir() {
                std::fs::remove_dir(&path)
            } else if ft.is_symlink() || !m.is_dir() {
                std::fs::remove_file(&path)
            } else {
                std::fs::remove_dir_all(&path)
            }
        });
        if let Err(e) = removed {
            failures.push(format!("{}: {e}", path.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("Cannot delete everything in {}: {}", root.display(), failures.join("; ")))
    }
}

/// A directory we may delete with `--purge-data`: it must look like our data directory.
pub(crate) fn looks_like_data_dir(root: &Path) -> bool {
    if root.parent().is_none() || root.components().count() < 3 {
        return false; // drive root or top-level folder
    }
    let named = root.file_name().map(|n| n.to_string_lossy().eq_ignore_ascii_case("Predator")).unwrap_or(false);
    let has_ours =
        ["settings.json", "token.dat", "queue.json", "telegram-state.json"].iter().any(|f| root.join(f).exists());
    named || has_ours
}

fn configure_service(svc: &ScHandle) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut desc = wide(SERVICE_DESCRIPTION);
    let d = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
    let mut actions = [
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 10_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 30_000 },
    ];
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    let flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 1 };
    let pre = SERVICE_PRESHUTDOWN_INFO { dwPreshutdownTimeout: 15_000 };
    let sid = SERVICE_SID_INFO { dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED };
    let items: [(u32, *const std::ffi::c_void, &str); 5] = [
        (SERVICE_CONFIG_DESCRIPTION, (&d as *const SERVICE_DESCRIPTIONW).cast(), "description"),
        (SERVICE_CONFIG_FAILURE_ACTIONS, (&fa as *const SERVICE_FAILURE_ACTIONSW).cast(), "failure actions"),
        (
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
            "failure actions flag",
        ),
        (SERVICE_CONFIG_PRESHUTDOWN_INFO, (&pre as *const SERVICE_PRESHUTDOWN_INFO).cast(), "preshutdown timeout"),
        (SERVICE_CONFIG_SERVICE_SID_INFO, (&sid as *const SERVICE_SID_INFO).cast(), "service SID type"),
    ];
    for (level, info, what) in items {
        // SAFETY: service handle with SERVICE_ALL_ACCESS; `info` points to the matching struct,
        // alive for the duration of the call.
        if unsafe { ChangeServiceConfig2W(svc.0, level, info) } == 0 {
            warnings.push(format!("could not set the {what}: {}", WinError::last("ChangeServiceConfig2W")));
        }
    }
    warnings
}

pub(crate) fn install(data: &DataCtx, start: bool) -> Result<(), String> {
    reject_custom_data_dir(data, "install")?;
    require_admin("install")?;
    let exe_dir = crate::paths::exe_dir();
    register(data, &exe_dir, None)?;

    // Start / next steps.
    let store = data.settings()?;
    let token_present = data.paths.token().exists();
    let paired = store.primary_user_id().is_some();
    if start {
        if service_state().0 == ServiceState::Running {
            println!("The service is already running; restart it to use the new configuration.");
        } else {
            crate::sys::scm::start_and_wait(SERVICE_NAME, Duration::from_secs(40))?;
            println!("Service started.");
        }
    }
    if !token_present || !paired {
        println!("\nNext steps:");
        if !token_present {
            println!("  predator-service set-token     (bot token from @BotFather)");
            if start {
                println!("  predator-service stop && predator-service start   (use the new token)");
            }
        }
        if !paired {
            println!("  predator-service pair --admin  (link your Telegram account;");
            println!("                                  or: predator-service set-owner --telegram-id ID)");
        }
        if !start {
            println!("  predator-service start");
        }
    } else if !start {
        println!("Start it with: predator-service start");
    }
    Ok(())
}

/// Register (or update) the service for `<exe_dir>\predator-service.exe` and everything around
/// it: trusted data directory, tray owner, failure actions, logon audit policy, tray Run value.
/// `owner_sid` (setup: the account that started it) becomes the tray owner; without it the
/// installing account is used when no owner is configured yet. Does not start the service.
pub(crate) fn register(data: &DataCtx, exe_dir: &Path, owner_sid: Option<&str>) -> Result<(), String> {
    reject_custom_data_dir(data, "install")?;
    require_admin("install")?;
    let service_exe = exe_dir.join(SERVICE_EXE);
    if !service_exe.exists() {
        return Err(format!(
            "{} not found — run install from the installed predator-service.exe",
            service_exe.display()
        ));
    }
    check_program_files(exe_dir)?;

    // 1. Data directory (trusted or moved aside, protected ACL), settings with the tray owner =
    //    the given account, else the installing user unless one is configured already.
    prepare_data_dir(&data.paths)?;
    let store = data.settings()?;
    let owner = match owner_sid.and_then(winsec::canonical_sid).filter(|s| s != "S-1-5-18") {
        Some(sid) => Some(sid),
        None if store.get().owner_windows_sid.is_none() => {
            winsec::current_process_facts().map(|f| f.sid).filter(|s| s != "S-1-5-18")
        }
        None => None,
    };
    if let Some(sid) = owner {
        if store.get().owner_windows_sid.as_deref() != Some(sid.as_str()) {
            let s2 = sid.clone();
            store
                .update(move |s| s.owner_windows_sid = Some(s2))
                .map_err(|e| super::commands::io_error(&data.paths.settings(), &e))?;
        }
        let name = winsec::account_name_of(&sid).unwrap_or_else(|| "unknown account".into());
        println!("Tray owner: {name} ({sid})");
    }
    store.save().map_err(|e| super::commands::io_error(&data.paths.settings(), &e))?;
    println!("Data directory: {} (SYSTEM + Administrators only)", data.paths.root.display());

    // 2. Service registration (create or update).
    let scm = open_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(SERVICE_NAME);
    let display = wide(SERVICE_DISPLAY_NAME);
    let bin = wide(&service_command_line(exe_dir));
    let mut deps = wide("EventLog");
    deps.push(0); // double-NUL-terminated list
    // SAFETY: valid SCM handle and NUL-terminated name.
    let existing = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    let svc = if !existing.is_null() {
        let svc = ScHandle(existing);
        let account = wide("LocalSystem");
        let empty = wide("");
        // SAFETY: all strings NUL-terminated; deps double-NUL-terminated.
        let ok = unsafe {
            ChangeServiceConfigW(
                svc.0,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin.as_ptr(),
                null(),
                null_mut(),
                deps.as_ptr(),
                account.as_ptr(),
                empty.as_ptr(),
                display.as_ptr(),
            )
        };
        if ok == 0 {
            return Err(format!("Cannot update the service: {}", WinError::last("ChangeServiceConfigW")));
        }
        println!("Service '{SERVICE_NAME}' updated.");
        svc
    } else {
        match last_error() {
            ERROR_SERVICE_DOES_NOT_EXIST => {}
            ERROR_SERVICE_MARKED_FOR_DELETE => {
                return Err(
                    "The service is marked for deletion. Close services.msc / Event Viewer and try again.".into()
                );
            }
            code => return Err(format!("Cannot open the service: {}", WinError::new(code, "OpenServiceW"))),
        }
        // SAFETY: valid SCM handle; null start name = LocalSystem; strings NUL-terminated.
        let h = unsafe {
            CreateServiceW(
                scm.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin.as_ptr(),
                null(),
                null_mut(),
                deps.as_ptr(),
                null(),
                null(),
            )
        };
        if h.is_null() {
            return Err(format!("Cannot create the service: {}", WinError::last("CreateServiceW")));
        }
        println!("Service '{SERVICE_NAME}' created (automatic start, LocalSystem).");
        ScHandle(h)
    };
    for w in configure_service(&svc) {
        println!("WARNING: {w}");
    }
    drop(svc);
    drop(scm);

    // 3. Logon audit policy (needed for the Security-log monitor).
    let backup = data.paths.audit_backup();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::monitor::audit::ensure_enabled(&backup))) {
        Ok(Ok(summary)) => println!("Audit policy: {summary}"),
        Ok(Err(e)) => println!("WARNING: could not enable logon auditing: {e}"),
        Err(_) => println!("WARNING: could not enable logon auditing (internal error)"),
    }
    // Files written above (settings, audit backup) belong to Administrators like the rest.
    if let Err(e) = winsec::secure_data_dir(&data.paths.root, false) {
        println!("WARNING: {e}");
    }

    // 4. Tray autostart for every user.
    let tray = exe_dir.join(TRAY_EXE);
    if tray.exists() {
        match winsec::set_run_value(TRAY_RUN_VALUE, &tray_command_line(exe_dir)) {
            Ok(()) => println!("Tray autostart registered (HKLM Run\\{TRAY_RUN_VALUE})."),
            Err(e) => println!("WARNING: {e}"),
        }
    } else {
        println!("WARNING: {} not found; tray autostart not registered.", tray.display());
    }
    Ok(())
}

pub(crate) fn uninstall(data: &DataCtx, keep_audit_policy: bool, purge_data: bool) -> Result<(), String> {
    uninstall_steps(data, keep_audit_policy, purge_data).result
}

/// Result of [`uninstall_steps`].
pub(crate) struct UninstallOutcome {
    /// The service registration is gone (deleted, marked for deletion, or it did not exist).
    /// `false` = nothing was removed; the program files must then stay where they are.
    pub service_removed: bool,
    pub result: Result<(), String>,
}

/// [`uninstall`], also telling whether the service itself was removed (a later step, such as
/// restoring the audit policy, may still have failed).
pub(crate) fn uninstall_steps(data: &DataCtx, keep_audit_policy: bool, purge_data: bool) -> UninstallOutcome {
    let mut service_removed = false;
    let result = uninstall_inner(data, keep_audit_policy, purge_data, &mut service_removed);
    UninstallOutcome { service_removed, result }
}

fn uninstall_inner(
    data: &DataCtx,
    keep_audit_policy: bool,
    purge_data: bool,
    service_removed: &mut bool,
) -> Result<(), String> {
    reject_custom_data_dir(data, "uninstall")?;
    require_admin("uninstall")?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: valid SCM handle, NUL-terminated name of OUR service only.
    let h = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE) };
    if h.is_null() {
        match last_error() {
            ERROR_SERVICE_DOES_NOT_EXIST => println!("Service '{SERVICE_NAME}' is not installed."),
            code => return Err(format!("Cannot open the service: {}", WinError::new(code, "OpenServiceW"))),
        }
        *service_removed = true;
    } else {
        let svc = ScHandle(h);
        if !matches!(service_state().0, ServiceState::Stopped | ServiceState::NotInstalled) {
            println!("Stopping the service…");
            if let Err(e) = crate::sys::scm::stop_and_wait(SERVICE_NAME, Duration::from_secs(40)) {
                println!("WARNING: {e}");
            }
        }
        // SAFETY: handle opened with DELETE access.
        if unsafe { DeleteService(svc.0) } == 0 {
            let code = last_error();
            if code != ERROR_SERVICE_MARKED_FOR_DELETE {
                return Err(format!("Cannot delete the service: {}", WinError::new(code, "DeleteService")));
            }
        }
        println!("Service '{SERVICE_NAME}' removed.");
        *service_removed = true;
    }
    drop(scm);

    match winsec::delete_run_value(TRAY_RUN_VALUE) {
        Ok(true) => println!("Tray autostart removed."),
        Ok(false) => {}
        Err(e) => println!("WARNING: {e}"),
    }

    // Audit policy. `audit::restore` deletes the backup itself after a successful restore (and
    // treats a missing backup as "nothing to restore"); on failure the backup must survive.
    let backup = data.paths.audit_backup();
    let audit_failure = if keep_audit_policy { None } else { restore_audit_policy(&data.paths) };

    let root = &data.paths.root;
    if purge_data {
        if !root.exists() {
            println!("Data directory {} does not exist.", root.display());
        } else if !looks_like_data_dir(root) {
            return Err(format!(
                "Refusing to delete {}: it does not look like a Predator data directory.",
                root.display()
            ));
        } else if audit_failure.is_some() && backup.exists() {
            let keep = backup.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            purge_data_dir(root, Some(&keep))?;
            println!(
                "Data directory {} emptied except {} (original audit policy, not restored).",
                root.display(),
                backup.display()
            );
        } else {
            purge_data_dir(root, None)?;
            println!("Data directory {} deleted.", root.display());
        }
    } else {
        println!("Data kept in {} (bot token, Telegram users, settings; --purge-data deletes it).", root.display());
    }

    if let Some(e) = audit_failure {
        let kept = if backup.exists() {
            format!("The original values are kept in {}; restore them later", backup.display())
        } else {
            "Restore the original values".to_string()
        };
        return Err(format!(
            "the service was removed, but the original logon audit policy was NOT restored ({e}). {kept} with \
             'predator-service audit restore' (elevated), or see docs\\TROUBLESHOOTING.md (\"Uninstall leftovers\")."
        ));
    }
    Ok(())
}

/// Restore the saved audit policy. Returns the failure (None = restored or nothing to restore).
/// A backup inside a data directory that cannot be trusted is not applied.
fn restore_audit_policy(paths: &DataPaths) -> Option<String> {
    let backup = paths.audit_backup();
    if backup.exists() {
        let distrust = match winsec::assess_data_dir(&paths.root, false) {
            DirTrust::Untrusted(why) => Some(why),
            _ => {
                let me = winsec::current_process_facts().map(|f| f.sid);
                winsec::path_sddl(&backup)
                    .map(|s| winsec::child_distrust_reason(&s, me.as_deref()))
                    .unwrap_or_else(|e| Some(format!("its permissions cannot be read ({e})")))
            }
        };
        if let Some(why) = distrust {
            let e = format!("the saved values in {} cannot be trusted: {why}", backup.display());
            println!("WARNING: audit policy not restored: {e}");
            return Some(e);
        }
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::monitor::audit::restore(&backup))) {
        Ok(Ok(summary)) => {
            println!("Audit policy: {summary}");
            None
        }
        Ok(Err(e)) => {
            println!("WARNING: could not restore the audit policy: {e}");
            Some(e)
        }
        Err(_) => {
            println!("WARNING: could not restore the audit policy (internal error)");
            Some("internal error".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_are_quoted() {
        let d = Path::new(r"C:\Program Files\Predator");
        assert_eq!(service_command_line(d), r#""C:\Program Files\Predator\predator-service.exe""#);
        assert_eq!(tray_command_line(d), r#""C:\Program Files\Predator\predator-tray.exe""#);
    }

    #[test]
    fn planted_modules() {
        assert!(is_loadable_module("version.dll"));
        assert!(is_loadable_module("VERSION.DLL"));
        assert!(is_loadable_module("predator-service.exe.local"));
        assert!(is_loadable_module("predator-service.exe.manifest"));
        assert!(!is_loadable_module("predator-service.exe"));
        assert!(!is_loadable_module("install-manifest.txt"));
        assert!(!is_loadable_module("README.md"));
    }

    #[test]
    fn user_writable_program_folder_is_refused() {
        // A folder created by this (test) user under %TEMP% is writable by its non-SYSTEM owner
        // (or, when the tests run elevated, inherits a user-writable ACL from the profile).
        let dir = std::env::temp_dir().join(format!("predator-prog-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SERVICE_EXE), b"MZ").unwrap();
        let e = check_program_files(&dir).unwrap_err();
        assert!(e.contains("LocalSystem service must not run"), "{e}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn purge_keeps_only_the_audit_backup() {
        let tmp = std::env::temp_dir().join(format!("predator-purge-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(tmp.join("logs")).unwrap();
        std::fs::write(tmp.join("settings.json"), b"{}").unwrap();
        std::fs::write(tmp.join("token.dat"), b"PDT1M").unwrap();
        std::fs::write(tmp.join("audit-backup.json"), b"{}").unwrap();
        std::fs::write(tmp.join("logs").join("predator.log"), b"x").unwrap();
        purge_data_dir(&tmp, Some("AUDIT-BACKUP.json")).unwrap();
        let left: Vec<String> =
            std::fs::read_dir(&tmp).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, vec!["audit-backup.json".to_string()]);
        purge_data_dir(&tmp, None).unwrap();
        assert!(!tmp.exists());
        assert!(purge_data_dir(&tmp, Some("audit-backup.json")).is_err(), "missing directory is reported");
    }

    #[test]
    fn purge_guard() {
        assert!(!looks_like_data_dir(Path::new(r"C:\")));
        assert!(!looks_like_data_dir(Path::new(r"C:\Windows")));
        assert!(looks_like_data_dir(Path::new(r"C:\ProgramData\Predator")));
        let tmp = std::env::temp_dir().join(format!("predator-purge-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(!looks_like_data_dir(&tmp));
        std::fs::write(tmp.join("settings.json"), b"{}").unwrap();
        assert!(looks_like_data_dir(&tmp));
        std::fs::remove_dir_all(&tmp).ok();
    }
}
