//! Program files: the protected install folder, writing the two executables with SHA-256
//! verification, replacing them atomically (update) and removing them (uninstall).
//!
//! Every write goes to a new, uniquely named `<name>.new-<hex>` file inside the protected folder
//! (so it gets the folder's ACL), is read back and hashed, and only then renamed into place. The
//! file it replaces is renamed to `<name>.old-<hex>` first (a running program can be renamed,
//! not overwritten) and deleted after success — or at the next restart when it is still in use.

use std::borrow::Cow;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};

use super::super::winsec::{self, SecurityDescriptor};
use super::{desktop, embedded, sha256};
use crate::paths::{DEFAULT_INSTALL_DIR, SERVICE_EXE, TRAY_EXE};
use crate::util::win::{WinError, wide_path};

/// Install folder ACL: owner Administrators, protected DACL; SYSTEM + Administrators full
/// control, Users read/execute (the tray runs in every user's session), OWNER RIGHTS only
/// READ_CONTROL (an owner cannot re-open the ACL from a non-elevated process).
pub(crate) const INSTALL_DIR_SDDL: &str =
    "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;RC;;;OW)";

/// The old PowerShell installer's list of the files it installed.
const OLD_MANIFEST: &str = "install-manifest.txt";

/// Files of the old PowerShell installer that no longer apply (the program uninstalls itself).
const LEGACY_FILES: [&str; 2] = ["uninstall.ps1", OLD_MANIFEST];

/// Top-level files the old installer put next to the executables (removed on uninstall from a
/// dedicated program folder only).
const OLD_INSTALLER_TOP: [&str; 3] = ["README.md", "uninstall.ps1", OLD_MANIFEST];

/// Sub-folders of the old installer (`assets\predator*.ico`, `docs\*.md`).
const OLD_INSTALLER_SUBDIRS: [&str; 2] = ["assets", "docs"];

/// `<Program Files>\Predator`. The Program Files location comes from HKLM (only administrators can
/// change it), not from environment variables.
pub(crate) fn default_install_dir() -> PathBuf {
    crate::sys::sysinfo::reg_get_string(
        crate::sys::sysinfo::RegRoot::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        Some("ProgramFilesDir"),
    )
    .map(|p| PathBuf::from(p.trim()))
    .filter(|p| p.is_absolute())
    .map(|p| p.join("Predator"))
    .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR))
}

/// Folder of the registered service executable (`None` when not installed or the binary is not
/// a `predator-service.exe`).
pub(crate) fn installed_dir() -> Option<PathBuf> {
    let bin = std::panic::catch_unwind(|| crate::sys::scm::binary_path(crate::paths::SERVICE_NAME)).ok().flatten()?;
    let is_ours = bin.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(SERVICE_EXE));
    if !is_ours {
        return None;
    }
    bin.parent().map(Path::to_path_buf)
}

/// Why `dir` must never be used (or deleted) as the install folder: not absolute, a drive root
/// or top-level folder, or one of the `forbidden` system folders. `None` = acceptable.
pub(crate) fn unsafe_dir_reason(dir: &Path, forbidden: &[PathBuf]) -> Option<String> {
    if !dir.is_absolute() {
        return Some(format!("{} is not a full path", dir.display()));
    }
    let normal = dir.components().filter(|c| matches!(c, std::path::Component::Normal(_))).count();
    if normal < 2 {
        return Some(format!("{} is a drive root or top-level folder", dir.display()));
    }
    if forbidden.iter().any(|f| desktop::same_path(f, dir)) {
        return Some(format!("{} is a system folder", dir.display()));
    }
    None
}

/// System folders that are never an install folder.
fn forbidden_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for var in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE"] {
        if let Some(p) = std::env::var_os(var) {
            let p = PathBuf::from(p);
            if var == "SystemRoot" {
                v.push(p.join("System32"));
            }
            if var == "USERPROFILE"
                && let Some(parent) = p.parent()
            {
                v.push(parent.to_path_buf());
            }
            v.push(p);
        }
    }
    if let Some(pf) = default_install_dir().parent() {
        v.push(pf.to_path_buf());
    }
    v
}

fn check_dir(dir: &Path) -> Result<(), String> {
    match unsafe_dir_reason(dir, &forbidden_dirs()) {
        Some(why) => Err(format!("Refusing to use {} as the program folder: {why}.", dir.display())),
        None => Ok(()),
    }
}

fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Set owner + protected DACL of `path` from an SDDL string.
fn apply_sddl(path: &Path, sddl: &str) -> Result<(), String> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut dacl: *mut ACL = null_mut();
    let mut owner: PSID = null_mut();
    let (mut present, mut defaulted) = (0i32, 0i32);
    // SAFETY: valid self-relative descriptor; out pointers are valid and point into `sd`.
    let ok = unsafe {
        GetSecurityDescriptorDacl(sd.as_ptr(), &mut present, &mut dacl, &mut defaulted) != 0
            && GetSecurityDescriptorOwner(sd.as_ptr(), &mut owner, &mut defaulted) != 0
    };
    if !ok || dacl.is_null() || owner.is_null() {
        return Err(format!("Cannot prepare the permissions for {}", path.display()));
    }
    let w = wide_path(path);
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: NUL-terminated path; owner and DACL point into `sd`, alive for the call.
    let rc = unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, info, owner, null_mut(), dacl, null()) };
    if rc != 0 {
        return Err(format!("Cannot protect {}: {}", path.display(), WinError::new(rc, "SetNamedSecurityInfoW")));
    }
    Ok(())
}

/// Create the install folder with its final ACL (no moment with inherited permissions), or take
/// an existing one over (owner Administrators + the same ACL). Then check that nobody but
/// SYSTEM and administrators can change it.
pub(crate) fn prepare_install_dir(dir: &Path) -> Result<(), String> {
    check_dir(dir)?;
    let created = match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent()
                && !parent.is_dir()
            {
                return Err(format!("{} does not exist", parent.display()));
            }
            crate::paths::create_dir_with_sddl(dir, INSTALL_DIR_SDDL)
                .map_err(|e| format!("Cannot create {}: {e}", dir.display()))?
        }
        Err(e) => return Err(format!("Cannot inspect {}: {e}", dir.display())),
        Ok(meta) if is_reparse_point(&meta) => {
            return Err(format!("{} is a junction or symbolic link. Delete it and run setup again.", dir.display()));
        }
        Ok(meta) if !meta.is_dir() => return Err(format!("{} exists and is not a folder", dir.display())),
        Ok(_) => {
            // Never take over (new ACL, planted modules deleted) a folder of another program.
            let names = entry_names(dir).map_err(|e| format!("Cannot list {}: {e}", dir.display()))?;
            let foreign = foreign_contents(&names);
            if !foreign.is_empty() {
                return Err(format!(
                    "{} already exists and contains files that are not part of Vigil ({}). Move them \
                     elsewhere (or delete the folder) and run setup again.",
                    dir.display(),
                    preview(&foreign)
                ));
            }
            false
        }
    };
    if !created {
        apply_sddl(dir, INSTALL_DIR_SDDL)?;
    }
    let sddl = winsec::path_sddl(dir).map_err(|e| format!("Cannot read the permissions of {}: {e}", dir.display()))?;
    let me = winsec::current_process_facts().map(|f| f.sid);
    if let Some(why) = winsec::nonadmin_write_reason(&sddl, me.as_deref()) {
        return Err(format!("{} could not be protected: it {why}", dir.display()));
    }
    let protected = winsec::parse_sddl(&sddl)
        .dacl_flags
        .as_deref()
        .is_some_and(|f| f.contains('P') && !f.contains("NO_ACCESS_CONTROL"));
    if !protected {
        return Err(format!("{} still inherits permissions from its parent folder", dir.display()));
    }
    Ok(())
}

/// SHA-256 (hex) of a file.
pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = sha256::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(sha256::to_hex(&h.finish()))
}

/// The two program images to install: this executable itself and the tray (embedded in the
/// release build; a development build uses the `predator-tray.exe` next to it).
pub(crate) struct Images {
    pub service: Vec<u8>,
    pub tray: Cow<'static, [u8]>,
}

impl Images {
    pub(crate) fn load() -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("Cannot find this program's path: {e}"))?;
        let service = std::fs::read(&exe).map_err(|e| format!("Cannot read {}: {e}", exe.display()))?;
        if service.len() < 2 || &service[..2] != b"MZ" {
            return Err(format!("{} is not a Windows executable", exe.display()));
        }
        let tray = match embedded::tray() {
            Some(e) => Cow::Borrowed(embedded::verify(&e)?),
            None => {
                let sibling = exe.with_file_name(TRAY_EXE);
                if !sibling.is_file() {
                    return Err(format!(
                        "This build does not contain the tray program and {} was not found. Use the release file \
                         Vigil.exe (or build it with scripts\\build.ps1).",
                        sibling.display()
                    ));
                }
                let bytes = std::fs::read(&sibling).map_err(|e| format!("Cannot read {}: {e}", sibling.display()))?;
                Cow::Owned(bytes)
            }
        };
        Ok(Self { service, tray })
    }
}

/// A file prepared next to its final location.
#[derive(Debug)]
pub(crate) enum Staged {
    /// The installed file already has exactly these bytes.
    Unchanged(PathBuf),
    /// Verified copy at `new`, to be renamed to `target`.
    New { target: PathBuf, new: PathBuf },
}

impl Staged {
    pub(crate) fn is_unchanged(&self) -> bool {
        matches!(self, Staged::Unchanged(_))
    }
}

/// `<name>.<kind>-<8 hex>` next to `target`.
fn sibling(target: &Path, kind: &str) -> PathBuf {
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    target.with_file_name(format!("{name}.{kind}-{}", crate::util::rand::hex(4)))
}

/// A leftover of an interrupted update/install (`predator-*.exe.new-*` / `.old-*`).
pub(crate) fn is_leftover(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [SERVICE_EXE, TRAY_EXE].iter().any(|exe| {
        n.strip_prefix(exe).is_some_and(|rest| {
            rest.strip_prefix(".new-")
                .or_else(|| rest.strip_prefix(".old-"))
                .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        })
    })
}

/// Names of the entries of `dir`.
fn entry_names(dir: &Path) -> std::io::Result<Vec<String>> {
    Ok(std::fs::read_dir(dir)?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
}

/// Up to three names (`a, b, c, ...`) for a message.
fn preview(names: &[String]) -> String {
    let mut s = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > 3 {
        s.push_str(", ...");
    }
    s
}

/// A file that only Vigil puts into its program folder.
fn is_predator_marker(name: &str) -> bool {
    [SERVICE_EXE, TRAY_EXE, OLD_MANIFEST].iter().any(|m| m.eq_ignore_ascii_case(name)) || is_leftover(name)
}

/// The entries that keep an existing folder from being used as the program folder: none when it
/// is empty or holds a Vigil executable / leftover / old-installer manifest, otherwise all of
/// them (the folder belongs to something else).
pub(crate) fn foreign_contents(names: &[String]) -> Vec<String> {
    if names.iter().any(|n| is_predator_marker(n)) { Vec::new() } else { names.to_vec() }
}

/// Whether uninstall deletes the file `name` (in the sub-folder `sub` of the program folder):
/// the two executables and leftovers of interrupted updates always; in a `dedicated` folder
/// (named `Vigil`, or written by the old installer) also the old installer's README, scripts,
/// manifest, icons and docs. Everything else is left alone.
pub(crate) fn is_removable(sub: Option<&str>, name: &str, dedicated: bool) -> bool {
    let n = name.to_ascii_lowercase();
    match sub.map(str::to_ascii_lowercase).as_deref() {
        None if n == SERVICE_EXE || n == TRAY_EXE || is_leftover(name) => true,
        None => dedicated && OLD_INSTALLER_TOP.iter().any(|f| f.eq_ignore_ascii_case(name)),
        Some("assets") => dedicated && (n == "predator.ico" || n == "predator-off.ico"),
        Some("docs") => dedicated && n.ends_with(".md"),
        Some(_) => false,
    }
}

/// Write `bytes` as a verified new copy of `dir\name` (or report that it is already installed).
pub(crate) fn stage(dir: &Path, name: &str, bytes: &[u8]) -> Result<Staged, String> {
    let target = dir.join(name);
    let expected = sha256::hex_digest(bytes);
    if target.is_file() && sha256_file(&target).is_ok_and(|h| h == expected) {
        return Ok(Staged::Unchanged(target));
    }
    let new = sibling(&target, "new");
    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&new)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&new);
        return Err(format!("Cannot write {}: {e}", new.display()));
    }
    match sha256_file(&new) {
        Ok(h) if h == expected => Ok(Staged::New { target, new }),
        Ok(h) => {
            let _ = std::fs::remove_file(&new);
            Err(format!("The copy {} is damaged (SHA-256 {h}, expected {expected}).", new.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&new);
            Err(format!("Cannot verify {}: {e}", new.display()))
        }
    }
}

/// Delete a staged copy that will not be used.
pub(crate) fn discard(s: &Staged) {
    if let Staged::New { new, .. } = s {
        let _ = std::fs::remove_file(new);
    }
}

/// A file renamed into place; `old` is the previous file (kept until [`finish`] or [`rollback`]).
#[derive(Debug)]
pub(crate) struct Committed {
    pub target: PathBuf,
    pub old: Option<PathBuf>,
    pub changed: bool,
}

/// `std::fs::rename`, retried briefly: an antivirus scanner may hold a fresh file for a moment.
fn rename_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(300));
        }
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

/// Move a staged file into place: the current file (if any) is renamed to `.old-*` first, then
/// the new copy takes its name. On failure the previous state is restored.
pub(crate) fn commit(s: Staged) -> Result<Committed, String> {
    let (target, new) = match s {
        Staged::Unchanged(target) => return Ok(Committed { target, old: None, changed: false }),
        Staged::New { target, new } => (target, new),
    };
    let old = if target.exists() {
        let old = sibling(&target, "old");
        if let Err(e) = rename_retry(&target, &old) {
            let _ = std::fs::remove_file(&new);
            return Err(format!("Cannot move {} aside: {e}", target.display()));
        }
        Some(old)
    } else {
        None
    };
    if let Err(e) = rename_retry(&new, &target) {
        if let Some(old) = &old {
            let _ = rename_retry(old, &target);
        }
        let _ = std::fs::remove_file(&new);
        return Err(format!("Cannot put {} in place: {e}", target.display()));
    }
    Ok(Committed { target, old, changed: true })
}

/// Undo [`commit`]: the new file is removed and the previous one gets its name back.
pub(crate) fn rollback(c: &Committed) -> Result<(), String> {
    if !c.changed {
        return Ok(());
    }
    match &c.old {
        Some(old) => {
            let failed = sibling(&c.target, "old");
            rename_retry(&c.target, &failed)
                .and_then(|()| rename_retry(old, &c.target))
                .map_err(|e| format!("Cannot restore {}: {e}", c.target.display()))?;
            let _ = remove_or_schedule(&failed);
            Ok(())
        }
        None => match remove_or_schedule(&c.target) {
            Removal::Failed(e) => Err(e),
            _ => Ok(()),
        },
    }
}

/// Delete the previous file after a successful replacement. Returns a note when it is still in
/// use and will be deleted at the next restart.
pub(crate) fn finish(c: &Committed) -> Option<String> {
    let old = c.old.as_ref()?;
    match remove_or_schedule(old) {
        Removal::Removed => None,
        Removal::AtReboot => {
            Some(format!("{} is still in use; Windows deletes it at the next restart.", old.display()))
        }
        Removal::Failed(e) => Some(format!("WARNING: {e}")),
    }
}

/// Result of [`remove_or_schedule`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed,
    /// In use: deleted by Windows at the next restart.
    AtReboot,
    Failed(String),
}

/// Delete a file (a missing file counts as removed); a file in use is scheduled for deletion at
/// the next restart (`MoveFileExW(.., MOVEFILE_DELAY_UNTIL_REBOOT)`, administrators only).
pub(crate) fn remove_or_schedule(path: &Path) -> Removal {
    remove_or_schedule_with(path, &schedule_delete)
}

/// [`remove_or_schedule`] with the reboot scheduling passed in (tests). A file in use is first
/// renamed to a unique `<name>.old-<hex>` (a running program can be renamed, not deleted), and
/// that name is scheduled: the deletion at the restart must not hit a file that a reinstall puts
/// at the original path meanwhile.
fn remove_or_schedule_with(path: &Path, schedule: &dyn Fn(&Path) -> Result<Removal, String>) -> Removal {
    match std::fs::remove_file(path) {
        Ok(()) => Removal::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Removal::Removed,
        Err(e) => {
            let already_aside = path.file_name().is_some_and(|n| is_leftover(&n.to_string_lossy()));
            let aside = sibling(path, "old");
            let target =
                if !already_aside && std::fs::rename(path, &aside).is_ok() { aside } else { path.to_path_buf() };
            schedule(&target).unwrap_or_else(|why| Removal::Failed(format!("{}: {e}; {why}", path.display())))
        }
    }
}

fn schedule_delete(path: &Path) -> Result<Removal, String> {
    let w = wide_path(path);
    // SAFETY: NUL-terminated path; a null new name means "delete at reboot".
    if unsafe { MoveFileExW(w.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(format!("cannot schedule it for deletion: {}", WinError::last("MoveFileExW")));
    }
    Ok(Removal::AtReboot)
}

/// Remove leftovers of interrupted runs, the old installer's files and loadable modules
/// (`.dll`, `.manifest`, …) that Windows would load into the service. Returns notes.
pub(crate) fn clean_dir(dir: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return notes };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let planted = super::super::install::is_loadable_module(&name);
        let legacy = LEGACY_FILES.iter().any(|l| l.eq_ignore_ascii_case(&name));
        if !(planted || legacy || is_leftover(&name)) {
            continue;
        }
        let path = entry.path();
        let is_file = std::fs::symlink_metadata(&path).map(|m| !m.is_dir() || is_reparse_point(&m)).unwrap_or(false);
        if !is_file {
            continue;
        }
        let removal = remove_or_schedule(&path);
        if planted {
            notes.push(format!("WARNING: removed {} (Vigil ships no such files).", path.display()));
        }
        if let Removal::Failed(e) = removal {
            notes.push(format!("WARNING: {e}"));
        }
    }
    notes
}

/// Install (or repair) both executables in `dir`. Returns notes for the user.
pub(crate) fn install_program(dir: &Path, images: &Images) -> Result<Vec<String>, String> {
    prepare_install_dir(dir)?;
    let mut notes = clean_dir(dir);
    let svc = stage(dir, SERVICE_EXE, &images.service)?;
    let tray = match stage(dir, TRAY_EXE, &images.tray) {
        Ok(t) => t,
        Err(e) => {
            discard(&svc);
            return Err(e);
        }
    };
    let svc = match commit(svc) {
        Ok(c) => c,
        Err(e) => {
            discard(&tray);
            return Err(e);
        }
    };
    let tray = match commit(tray) {
        Ok(c) => c,
        Err(e) => {
            if let Err(r) = rollback(&svc) {
                notes.push(format!("WARNING: {r}"));
            }
            return Err(e);
        }
    };
    notes.extend([finish(&svc), finish(&tray)].into_iter().flatten());
    Ok(notes)
}

/// What [`sweep`] did.
#[derive(Default)]
struct Sweep {
    /// In use: deleted at the next restart.
    scheduled: Vec<PathBuf>,
    failed: Vec<String>,
    /// Entries that are not Vigil's (left alone), relative to the program folder.
    kept: Vec<String>,
}

/// Delete Vigil's files in `dir` (`sub` = its name below the program folder). Never follows
/// or deletes junctions / symbolic links and never descends into folders it does not know.
fn sweep(dir: &Path, sub: Option<&str>, dedicated: bool, s: &mut Sweep) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        s.failed.push(format!("cannot list {}", dir.display()));
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let shown = match sub {
            Some(d) => format!("{d}\\{name}"),
            None => name.clone(),
        };
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            s.kept.push(shown);
            continue;
        };
        if is_reparse_point(&meta) {
            s.kept.push(shown);
        } else if meta.is_dir() {
            let ours =
                sub.is_none() && dedicated && OLD_INSTALLER_SUBDIRS.iter().any(|d| d.eq_ignore_ascii_case(&name));
            if !ours {
                s.kept.push(shown);
                continue;
            }
            let (kept, scheduled) = (s.kept.len(), s.scheduled.len());
            sweep(&path, Some(&name), dedicated, s);
            if std::fs::remove_dir(&path).is_err() && s.kept.len() == kept && s.scheduled.len() > scheduled {
                // Empty once the files in use are gone at the restart.
                let _ = schedule_delete(&path);
            }
        } else if is_removable(sub, &name, dedicated) {
            match remove_or_schedule(&path) {
                Removal::Removed => {}
                Removal::AtReboot => s.scheduled.push(path),
                Removal::Failed(e) => s.failed.push(e),
            }
        } else {
            s.kept.push(shown);
        }
    }
}

/// Remove Vigil's files from its program folder (see [`is_removable`]) and then the folder
/// itself when nothing else is in it — files of other programs are never deleted. Files in use
/// are deleted at the next restart. A junction or symbolic link is never followed. Returns notes.
pub(crate) fn remove_install_dir(dir: &Path) -> Result<Vec<String>, String> {
    check_dir(dir)?;
    let meta = match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect {}: {e}", dir.display())),
        Ok(m) => m,
    };
    if is_reparse_point(&meta) || !meta.is_dir() {
        return Err(format!(
            "{} is not a plain folder (junction, symbolic link or file); nothing in it was deleted.",
            dir.display()
        ));
    }
    let dedicated = dir.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("Predator"))
        || dir.join(OLD_MANIFEST).is_file();
    if !dedicated && !dir.join(SERVICE_EXE).exists() {
        return Err(format!("Refusing to delete {}: it does not look like a Vigil program folder.", dir.display()));
    }
    let mut s = Sweep::default();
    sweep(dir, None, dedicated, &mut s);
    let mut notes = Vec::new();
    if let Err(e) = std::fs::remove_dir(dir) {
        if !s.kept.is_empty() {
            notes.push(format!(
                "{} was kept: it also contains {} (not part of Vigil).",
                dir.display(),
                preview(&s.kept)
            ));
        } else if !s.scheduled.is_empty() {
            if let Err(why) = schedule_delete(dir) {
                s.failed.push(format!("{}: {why}", dir.display()));
            }
        } else {
            s.failed.push(format!("{}: {e}", dir.display()));
        }
    }
    if !s.scheduled.is_empty() {
        notes.push(format!(
            "In use, deleted at the next restart: {}",
            s.scheduled.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        ));
    }
    if !s.failed.is_empty() {
        return Err(format!("Could not delete everything in {}: {}", dir.display(), s.failed.join("; ")));
    }
    Ok(notes)
}

/// Stop every `predator-tray.exe` started from exactly `tray` (any session). Other programs
/// with the same name are never touched. Returns `(stopped, failures)`.
pub(crate) fn stop_installed_trays(tray: &Path) -> (usize, Vec<String>) {
    let mut stopped = 0;
    let mut failures = Vec::new();
    for pid in crate::sys::process::find_processes(TRAY_EXE) {
        match desktop::stop_if_image(pid, tray) {
            Ok(true) => stopped += 1,
            Ok(false) => {}
            Err(e) => failures.push(e),
        }
    }
    (stopped, failures)
}

/// Diagnostic `extract-tray <path>`: write the embedded tray to a new file and verify it.
/// Returns the SHA-256 and size.
pub(crate) fn extract_tray(path: &Path) -> Result<(String, usize), String> {
    let e = embedded::tray().ok_or(
        "This build does not contain an embedded tray program (built without the \
                                     embed-tray feature).",
    )?;
    let bytes = embedded::verify(&e)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("Cannot create {} (it must not exist yet): {err}", path.display()))?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|err| format!("Cannot write {}: {err}", path.display()))?;
    drop(f);
    let h = sha256_file(path).map_err(|err| format!("Cannot verify {}: {err}", path.display()))?;
    if !h.eq_ignore_ascii_case(e.sha256) {
        return Err(format!("The written file {} does not match (SHA-256 {h}).", path.display()));
    }
    Ok((h, bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("predator-setup-{tag}-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn dangerous_folders_are_refused() {
        let forbidden = vec![PathBuf::from(r"C:\Windows"), PathBuf::from(r"C:\Program Files")];
        assert!(unsafe_dir_reason(Path::new(r"C:\"), &forbidden).is_some());
        assert!(unsafe_dir_reason(Path::new(r"C:\Predator"), &forbidden).is_some(), "top-level folder");
        assert!(unsafe_dir_reason(Path::new(r"relative\dir"), &forbidden).is_some());
        assert!(unsafe_dir_reason(Path::new(r"C:\program files\"), &forbidden).is_some());
        assert!(unsafe_dir_reason(Path::new(r"C:\Program Files\Predator"), &forbidden).is_none());
        assert!(unsafe_dir_reason(Path::new(r"D:\Apps\Predator"), &forbidden).is_none());
        let fb = forbidden_dirs();
        assert!(unsafe_dir_reason(&default_install_dir(), &fb).is_none(), "{}", default_install_dir().display());
        assert!(default_install_dir().ends_with("Predator"));
    }

    #[test]
    fn leftover_names() {
        assert!(is_leftover("predator-service.exe.new-0a1b2c3d"));
        assert!(is_leftover("PREDATOR-TRAY.EXE.old-ff00"));
        assert!(!is_leftover("predator-service.exe"));
        assert!(!is_leftover("predator-service.exe.old-"));
        assert!(!is_leftover("predator-service.exe.old-xyz"));
        assert!(!is_leftover("other.exe.old-00"));
    }

    #[test]
    fn stage_commit_finish_and_rollback() {
        let d = tmp("files");
        // Fresh file.
        let s = stage(&d, "a.exe", b"MZ one").unwrap();
        assert!(!s.is_unchanged());
        let c = commit(s).unwrap();
        assert!(c.old.is_none() && c.changed);
        assert_eq!(std::fs::read(d.join("a.exe")).unwrap(), b"MZ one");
        assert_eq!(finish(&c), None);
        // Same bytes: nothing written.
        let s = stage(&d, "a.exe", b"MZ one").unwrap();
        assert!(s.is_unchanged());
        assert!(!commit(s).unwrap().changed);
        // Replacement keeps the old file until finish/rollback.
        let c = commit(stage(&d, "a.exe", b"MZ two").unwrap()).unwrap();
        let old = c.old.clone().unwrap();
        assert_eq!(std::fs::read(&old).unwrap(), b"MZ one");
        assert_eq!(std::fs::read(d.join("a.exe")).unwrap(), b"MZ two");
        rollback(&c).unwrap();
        assert_eq!(std::fs::read(d.join("a.exe")).unwrap(), b"MZ one", "previous version restored");
        let c = commit(stage(&d, "a.exe", b"MZ three").unwrap()).unwrap();
        assert_eq!(finish(&c), None);
        assert!(!c.old.unwrap().exists());
        // Discarded stage leaves nothing behind.
        let s = stage(&d, "b.exe", b"MZ b").unwrap();
        discard(&s);
        let names: Vec<String> =
            std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["a.exe".to_string()], "no .new/.old leftovers: {names:?}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn removal_and_cleaning() {
        let d = tmp("clean");
        std::fs::write(d.join("version.dll"), b"x").unwrap();
        std::fs::write(d.join("uninstall.ps1"), b"x").unwrap();
        std::fs::write(d.join("predator-tray.exe.old-12ab"), b"x").unwrap();
        std::fs::write(d.join("README.md"), b"x").unwrap();
        let notes = clean_dir(&d);
        assert!(notes.iter().any(|n| n.contains("version.dll")), "{notes:?}");
        let mut names: Vec<String> =
            std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["README.md".to_string()]);
        assert_eq!(remove_or_schedule(&d.join("missing.txt")), Removal::Removed);
        // A folder that is not ours is never deleted.
        assert!(remove_install_dir(&d).unwrap_err().contains("does not look like"));
        std::fs::remove_dir_all(&d).ok();
    }

    fn names_in(d: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn uninstall_deletes_only_predator_files() {
        // The service was registered from a shared folder (e.g. with 'install'): only Vigil's
        // executables and leftovers go; everything else, and the folder, stays.
        let d = tmp("shared");
        for f in [SERVICE_EXE, TRAY_EXE, "predator-service.exe.old-0a0b", "README.md", "other.txt", "tool.dll"] {
            std::fs::write(d.join(f), b"MZ").unwrap();
        }
        std::fs::create_dir_all(d.join("docs")).unwrap();
        std::fs::write(d.join("docs").join("x.md"), b"x").unwrap();
        let notes = remove_install_dir(&d).unwrap();
        assert!(notes.iter().any(|n| n.contains("was kept") && n.contains("README.md")), "{notes:?}");
        assert_eq!(names_in(&d), vec!["README.md", "docs", "other.txt", "tool.dll"]);
        assert_eq!(names_in(&d.join("docs")), vec!["x.md"]);
        std::fs::remove_dir_all(&d).ok();

        // A dedicated folder (named Vigil): the old installer's files go too, other files stay.
        let root = tmp("dedicated");
        let p = root.join("Predator");
        std::fs::create_dir_all(p.join("assets")).unwrap();
        std::fs::create_dir_all(p.join("docs")).unwrap();
        std::fs::create_dir_all(p.join("data")).unwrap();
        for f in [SERVICE_EXE, TRAY_EXE, "README.md", "uninstall.ps1", "install-manifest.txt"] {
            std::fs::write(p.join(f), b"x").unwrap();
        }
        for f in ["predator.ico", "predator-off.ico", "custom.png"] {
            std::fs::write(p.join("assets").join(f), b"x").unwrap();
        }
        std::fs::write(p.join("docs").join("ARCHITECTURE.md"), b"x").unwrap();
        std::fs::write(p.join("data").join("keep.txt"), b"x").unwrap();
        let notes = remove_install_dir(&p).unwrap();
        assert!(notes.iter().any(|n| n.contains("was kept")), "{notes:?}");
        assert_eq!(names_in(&p), vec!["assets", "data"]);
        assert_eq!(names_in(&p.join("assets")), vec!["custom.png"]);
        assert_eq!(names_in(&p.join("data")), vec!["keep.txt"], "unknown folders are never entered");
        // Without foreign files the folder itself is removed.
        std::fs::remove_dir_all(p.join("data")).unwrap();
        std::fs::remove_file(p.join("assets").join("custom.png")).unwrap();
        std::fs::write(p.join(SERVICE_EXE), b"x").unwrap();
        assert!(remove_install_dir(&p).unwrap().is_empty());
        assert!(!p.exists());
        // Missing folder: nothing to do.
        assert!(remove_install_dir(&p).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn removable_files() {
        for dedicated in [false, true] {
            assert!(is_removable(None, "PREDATOR-SERVICE.EXE", dedicated));
            assert!(is_removable(None, TRAY_EXE, dedicated));
            assert!(is_removable(None, "predator-tray.exe.new-1f2e", dedicated));
            assert!(!is_removable(None, "other.exe", dedicated));
            assert!(!is_removable(None, "version.dll", dedicated));
            assert!(!is_removable(Some("data"), "x.md", dedicated));
        }
        assert!(is_removable(None, "readme.md", true) && !is_removable(None, "README.md", false));
        assert!(is_removable(None, "install-manifest.txt", true) && !is_removable(None, "uninstall.ps1", false));
        assert!(is_removable(Some("assets"), "predator.ico", true) && !is_removable(Some("assets"), "x.ico", true));
        assert!(is_removable(Some("Docs"), "TROUBLESHOOTING.md", true) && !is_removable(Some("docs"), "x.txt", true));
        assert!(!is_removable(Some("docs"), "x.md", false));
    }

    #[test]
    fn a_foreign_folder_is_never_taken_over() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(foreign_contents(&[]).is_empty(), "an empty folder may be used");
        assert!(foreign_contents(&s(&["README.md", "PREDATOR-SERVICE.EXE", "version.dll"])).is_empty());
        assert!(foreign_contents(&s(&["install-manifest.txt", "docs"])).is_empty(), "old installer");
        assert!(foreign_contents(&s(&["predator-tray.exe.old-00ff"])).is_empty(), "interrupted update");
        assert_eq!(foreign_contents(&s(&["app.exe", "app.dll"])), s(&["app.exe", "app.dll"]));
        assert_eq!(preview(&s(&["a", "b", "c", "d"])), "a, b, c, ...");
        // Refused before anything (ACL, module cleanup) is changed.
        let d = tmp("foreign");
        std::fs::write(d.join("app.dll"), b"x").unwrap();
        let e = prepare_install_dir(&d).unwrap_err();
        assert!(e.contains("not part of Vigil") && e.contains("app.dll"), "{e}");
        assert_eq!(names_in(&d), vec!["app.dll"]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_file_in_use_is_moved_aside_before_its_reboot_deletion() {
        use std::cell::RefCell;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_AS_IMAGE_RESOURCE, LoadLibraryExW};

        let d = tmp("inuse");
        let f = d.join(TRAY_EXE);
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        std::fs::copy(system.join("System32").join("version.dll"), &f).unwrap();
        // Mapped as an image (like a running program): it can be renamed, not deleted.
        let w = wide_path(&f);
        // SAFETY: NUL-terminated path; the module is freed below.
        let module = unsafe { LoadLibraryExW(w.as_ptr(), null_mut(), LOAD_LIBRARY_AS_IMAGE_RESOURCE) };
        assert!(!module.is_null(), "{}", WinError::last("LoadLibraryExW"));
        let scheduled = RefCell::new(Vec::new());
        let r = remove_or_schedule_with(&f, &|p: &Path| {
            scheduled.borrow_mut().push(p.to_path_buf());
            Ok(Removal::AtReboot)
        });
        // SAFETY: module loaded above.
        unsafe { FreeLibrary(module) };
        assert_eq!(r, Removal::AtReboot);
        let scheduled = scheduled.into_inner();
        assert_eq!(scheduled.len(), 1);
        let name = scheduled[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(is_leftover(&name), "{name}");
        assert!(!f.exists(), "the original path is free for a reinstall");
        assert!(scheduled[0].exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn images_and_extraction() {
        // Tests run from target\...\deps without a sibling tray (and without the feature).
        if embedded::tray().is_none() {
            let e = extract_tray(&std::env::temp_dir().join("never-written.exe")).unwrap_err();
            assert!(e.contains("embed-tray"), "{e}");
        }
        let d = tmp("hash");
        std::fs::write(d.join("f"), b"abc").unwrap();
        assert_eq!(
            sha256_file(&d.join("f")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
