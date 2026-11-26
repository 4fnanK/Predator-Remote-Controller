//! Well-known names and on-disk locations.
//!
//! All persistent state lives under `%ProgramData%\Predator` (ACL: SYSTEM + Administrators only,
//! set by the installer). The console/test mode can point the data root anywhere with
//! `--data-dir`.
//!
//! `%ProgramData%` lets every standard user create sub-folders, so the protected root is created
//! atomically with its final security descriptor ([`DataPaths::ensure_dirs_secure`]) — there is
//! never a moment in which it carries the inherited, user-writable ACL. Whether an *existing*
//! root can be trusted is decided by the service's installer logic, not here.

use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT};

/// Security descriptor of the protected data directory: owner Administrators; protected DACL
/// (no inheritance from `%ProgramData%`) granting SYSTEM and Administrators full control,
/// inherited by every file and sub-directory. Nobody else can read the token or change settings.
pub const DATA_DIR_SDDL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Windows service (SCM) name.
pub const SERVICE_NAME: &str = "PredatorRemoteController";
/// Service display name.
pub const SERVICE_DISPLAY_NAME: &str = "Vigil";
/// Service description shown in services.msc.
pub const SERVICE_DESCRIPTION: &str =
    "Monitors Windows/SSH logins and provides secure remote control of this PC through a private Telegram bot.";
/// Local IPC named pipe used by the tray application.
pub const PIPE_NAME: &str = r"\\.\pipe\PredatorRemoteController";
/// File names of the two executables (installed side by side).
pub const SERVICE_EXE: &str = "predator-service.exe";
pub const TRAY_EXE: &str = "predator-tray.exe";
/// HKLM Run value name for the tray autostart.
pub const TRAY_RUN_VALUE: &str = "PredatorTray";
/// Named mutex ensuring one tray instance per session.
pub const TRAY_MUTEX: &str = r"Local\PredatorRemoteControllerTray";
/// Default install directory.
pub const DEFAULT_INSTALL_DIR: &str = r"C:\Program Files\Predator";

/// Paths of every persistent file, relative to a data root.
#[derive(Debug, Clone)]
pub struct DataPaths {
    pub root: PathBuf,
}

impl DataPaths {
    /// `%ProgramData%\Predator` (falls back to `C:\ProgramData\Predator`).
    pub fn default_root() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Predator")
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default_paths() -> Self {
        Self::new(Self::default_root())
    }

    /// Feature switches, owner ids, options (JSON).
    pub fn settings(&self) -> PathBuf {
        self.root.join("settings.json")
    }
    /// DPAPI-protected bot token.
    pub fn token(&self) -> PathBuf {
        self.root.join("token.dat")
    }
    /// Persistent outgoing notification queue (JSON).
    pub fn queue(&self) -> PathBuf {
        self.root.join("queue.json")
    }
    /// Login history ring buffer (JSON).
    pub fn history(&self) -> PathBuf {
        self.root.join("history.json")
    }
    /// Telegram polling state (last processed update id).
    pub fn telegram_state(&self) -> PathBuf {
        self.root.join("telegram-state.json")
    }
    /// Short-lived chat messages waiting for automatic deletion (JSON).
    pub fn chat_cleanup(&self) -> PathBuf {
        self.root.join("chat-cleanup.json")
    }
    /// Original audit-policy values saved by the installer (restored on uninstall).
    pub fn audit_backup(&self) -> PathBuf {
        self.root.join("audit-backup.json")
    }
    pub fn bookmarks_dir(&self) -> PathBuf {
        self.root.join("bookmarks")
    }
    /// Event-log bookmark XML for a channel key such as `security` or `openssh`.
    pub fn bookmark(&self, key: &str) -> PathBuf {
        self.bookmarks_dir().join(format!("{key}.xml"))
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn log_file(&self) -> PathBuf {
        self.logs_dir().join("predator.log")
    }
    /// Unauthorized-access / security audit log.
    pub fn security_log(&self) -> PathBuf {
        self.logs_dir().join("security.log")
    }
    /// Marker file: when present, power actions are simulated (dry-run).
    pub fn dry_run_marker(&self) -> PathBuf {
        self.root.join("DRY_RUN")
    }

    /// Create the root, bookmarks and logs directories with plain, inherited permissions. Only
    /// for custom locations (`--data-dir`, console mode, tests); the protected default location
    /// uses [`DataPaths::ensure_dirs_secure`].
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.bookmarks_dir())?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(())
    }

    /// Like [`DataPaths::ensure_dirs`], but a missing root is created atomically with
    /// [`DATA_DIR_SDDL`] (owner Administrators, SYSTEM + Administrators only), so no other user
    /// can ever add files to it. The sub-directories inherit that ACL. Needs an elevated
    /// administrator or LocalSystem (assigning the Administrators owner fails otherwise).
    ///
    /// Returns `true` when the root was created by this call. An existing root is neither
    /// changed nor validated here — callers must decide whether it can be trusted (owner and
    /// ACL) before using anything inside it. A root that is a junction/symbolic link or not a
    /// directory is an error.
    pub fn ensure_dirs_secure(&self) -> std::io::Result<bool> {
        if let Some(parent) = self.root.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let created = create_dir_with_sddl(&self.root, DATA_DIR_SDDL)?;
        let meta = std::fs::symlink_metadata(&self.root)?;
        if is_reparse_point(&meta) || !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a plain directory (junction, symbolic link or file)", self.root.display()),
            ));
        }
        std::fs::create_dir_all(self.bookmarks_dir())?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(created)
    }
}

fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct SddlDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SddlDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the OS with LocalAlloc; freed exactly once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// Create the single directory `dir` (its parent must exist) with the security descriptor
/// `sddl` applied by the file system at creation time — no window with inherited permissions.
/// Returns `Ok(true)` when created and `Ok(false)` when something already exists at `dir`
/// (left untouched; the caller must inspect it).
pub fn create_dir_with_sddl(dir: &Path, sddl: &str) -> std::io::Result<bool> {
    let text = crate::util::win::wide(sddl);
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `text` is NUL-terminated; `psd` receives a LocalAlloc'ed descriptor freed by the guard.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut psd, null_mut())
    };
    if ok == 0 || psd.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let sd = SddlDescriptor(psd);
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let path = crate::util::win::wide_path(dir);
    // SAFETY: NUL-terminated path; `sa` and the descriptor it points to outlive the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } != 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) { Ok(false) } else { Err(err) }
}

/// Directory containing the running executable.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR))
}

/// Full path of the tray executable next to the running executable.
pub fn tray_exe_path() -> PathBuf {
    exe_dir().join(TRAY_EXE)
}

/// Full path of the service executable next to the running executable.
pub fn service_exe_path() -> PathBuf {
    exe_dir().join(SERVICE_EXE)
}

/// Write `data` to `path` atomically: write a sibling temp file, flush to disk, then rename over
/// the destination (MoveFileExW with REPLACE_EXISTING under the hood).
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", path.extension().and_then(|e| e.to_str()).unwrap_or("dat")));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let p = DataPaths::new(r"C:\x");
        assert_eq!(p.settings(), PathBuf::from(r"C:\x\settings.json"));
        assert_eq!(p.bookmark("security"), PathBuf::from(r"C:\x\bookmarks\security.xml"));
        assert_eq!(p.chat_cleanup(), PathBuf::from(r"C:\x\chat-cleanup.json"));
        assert!(DataPaths::default_root().ends_with("Predator"));
    }

    #[test]
    fn secure_dirs() {
        let base = std::env::temp_dir().join(format!("predator-paths-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&base).unwrap();
        // Grant the current user access as well so the test can clean up without elevation.
        let me = crate::sys::sysinfo::current_user_sid().unwrap();
        let sddl = format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})");
        let one = base.join("one");
        assert!(create_dir_with_sddl(&one, &sddl).unwrap());
        assert!(!create_dir_with_sddl(&one, &sddl).unwrap());
        assert!(create_dir_with_sddl(&base.join("missing").join("x"), &sddl).is_err(), "parent must exist");
        assert!(create_dir_with_sddl(&base.join("bad"), "D:garbage(").is_err());

        // Something that is not a directory at the root is refused.
        let file_root = base.join("file");
        std::fs::write(&file_root, b"x").unwrap();
        assert!(DataPaths::new(&file_root).ensure_dirs_secure().is_err());

        // The real descriptor makes Administrators the owner: only an elevated admin (or
        // LocalSystem) may do that; a standard user gets ERROR_INVALID_OWNER and nothing is created.
        let root = base.join("Predator");
        let p = DataPaths::new(&root);
        match p.ensure_dirs_secure() {
            Ok(created) => {
                assert!(created);
                assert!(p.logs_dir().is_dir() && p.bookmarks_dir().is_dir());
                assert!(!p.ensure_dirs_secure().unwrap(), "second call finds the existing root");
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(1307), "{e}");
                assert!(!root.exists());
            }
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn atomic_write_works() {
        let dir = std::env::temp_dir().join(format!("predator-test-{}", crate::util::rand::hex(4)));
        let f = dir.join("a.json");
        atomic_write(&f, b"one").unwrap();
        atomic_write(&f, b"two").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        std::fs::remove_dir_all(&dir).ok();
    }
}
