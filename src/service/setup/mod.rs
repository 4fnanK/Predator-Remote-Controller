//! Interactive setup of the single-file release: what runs when `Vigil.exe`
//! is started without arguments outside the Service Control Manager (double-click), or with
//! `setup`.
//!
//! * Not elevated → relaunch elevated (UAC, `runas`) with `setup --invoking-sid <SID>`, wait,
//!   pass the exit code on.
//! * Elevated, service not installed → the wizard (`wizard.rs`): bot token (hidden prompt,
//!   getMe), protected data folder, pairing of the first Telegram account as Admin, program files
//!   (own image + embedded tray, SHA-256 verified), service registration, start, tray, Tailscale.
//! * Elevated, installed → the management menu (`menu.rs`).
//! * `--yes` (+ `--token-file`, `--telegram-id`) → the same without any question.
//!
//! The dialogs only talk to [`io::Io`] and the `WizardEnv` / `MenuEnv` traits; `actions.rs`
//! implements those against the real machine.

mod actions;
mod desktop;
mod elevate;
mod embedded;
mod files;
mod io;
mod menu;
/// SHA-256 (also compiled into build.rs, so it stays self-contained).
mod sha256;
mod tailscale;
mod wizard;

use std::path::Path;

pub(crate) use super::cli::SetupOptions;
use super::commands::{self, DataCtx, reject_custom_data_dir, service_state};
use super::winsec;
use crate::sys::ServiceState;
use io::Io;

/// Lifetime of a pairing code shown by setup (and the tray).
pub(crate) const PAIR_TTL_SECS: u64 = 600;

/// Entry point for `setup` and for a start without arguments outside the SCM. Returns the
/// process exit code. The window waits for Enter at the end when it belongs to this process
/// only (it would close at once otherwise) — never with `--yes`.
pub(crate) fn run(data: &DataCtx, opts: &SetupOptions) -> i32 {
    let mut con = io::ConsoleIo;
    let console_ours = elevate::console_is_ours();
    let (code, wants_pause) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_inner(&mut con, data, opts))) {
            Ok(r) => r,
            Err(_) => {
                con.say("ERROR: setup stopped because of an internal error.");
                (1, true)
            }
        };
    if wants_pause && console_ours && !opts.yes {
        io::pause(&mut con);
    }
    code
}

/// `(exit code, whether the last screen should wait for Enter)`.
fn run_inner(io: &mut dyn Io, data: &DataCtx, opts: &SetupOptions) -> (i32, bool) {
    if let Err(e) = reject_custom_data_dir(data, "setup") {
        io.say(&format!("ERROR: {e}"));
        return (2, true);
    }
    if !commands::is_elevated() {
        return relaunch(io, opts);
    }
    let my_sid = winsec::current_process_facts().map(|f| f.sid);
    let invoking_sid = match resolve_invoking_sid(opts.invoking_sid.as_deref(), my_sid.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            io.say(&format!("ERROR: {e}"));
            return (2, true);
        }
    };
    let token = match &opts.token_file {
        Some(f) => match super::runtime::read_plain_token(f) {
            Ok(t) => Some(t),
            Err(e) => {
                io.say(&format!("ERROR: {e}"));
                return (1, true);
            }
        },
        None => None,
    };

    let installed = !matches!(service_state().0, ServiceState::NotInstalled);
    if installed {
        let dir = files::installed_dir().unwrap_or_else(files::default_install_dir);
        let mut machine = actions::Machine::new(data, dir, invoking_sid, my_sid);
        if opts.yes {
            return match menu::run_unattended(io, &mut machine, token, opts.telegram_id) {
                Ok(()) => (0, false),
                Err(e) => {
                    io.say(&format!("ERROR: {e}"));
                    (1, false)
                }
            };
        }
        if token.is_some() || opts.telegram_id.is_some() {
            io.say("Note: --token-file and --telegram-id are applied only with --yes; use the menu below.");
        }
        return match menu::run_menu(io, &mut machine) {
            menu::MenuExit::Exit => (0, false),
            menu::MenuExit::Uninstalled => (0, true),
        };
    }

    let mut machine = actions::Machine::new(data, files::default_install_dir(), invoking_sid, my_sid);
    let wopts = wizard::WizardOptions { token, telegram_id: opts.telegram_id, yes: opts.yes };
    match wizard::run_wizard(io, &mut machine, wopts) {
        Ok(wizard::WizardEnd::Done { ok }) => (if ok { 0 } else { 1 }, true),
        Ok(wizard::WizardEnd::Cancelled) => {
            io.say("\nSetup was cancelled. Run this program again to continue.");
            (1, true)
        }
        Err(e) => {
            io.say(&format!("\nERROR: {e}"));
            io.say("Nothing was rolled back: fix the problem and run this program again to continue.");
            (1, true)
        }
    }
}

/// The tray owner: the SID given by the non-elevated parent (validated), else this process's
/// account. LocalSystem is never an owner.
fn resolve_invoking_sid(given: Option<&str>, mine: Option<&str>) -> Result<Option<String>, String> {
    match given {
        Some(s) => match winsec::canonical_sid(s) {
            Some(c) if c != "S-1-5-18" => Ok(Some(c)),
            _ => Err(format!("--invoking-sid '{s}' is not a valid user SID")),
        },
        None => Ok(mine.filter(|s| *s != "S-1-5-18").map(str::to_string)),
    }
}

/// Not elevated: ask Windows for administrator rights by starting the elevated copy.
fn relaunch(io: &mut dyn Io, opts: &SetupOptions) -> (i32, bool) {
    io.say(&format!("{} {} - setup", crate::PRODUCT_NAME, crate::VERSION));
    io.say("Setup needs administrator rights. Please confirm the Windows prompt (User Account Control);");
    io.say("setup then continues in a new window.");
    let sid = winsec::current_process_facts().map(|f| f.sid);
    let cwd = std::env::current_dir().unwrap_or_default();
    let args = elevate::elevated_args(opts, sid.as_deref(), &cwd);
    match elevate::relaunch_elevated(&args) {
        Ok(elevate::Relaunch::Exited(code)) => {
            if code != 0 {
                io.say(&format!("Setup ended with exit code {code}."));
            }
            (code as i32, false)
        }
        Ok(elevate::Relaunch::Declined) => {
            io.say("Administrator rights were not granted, so nothing was changed.");
            io.say("Run the program again and choose Yes in the Windows prompt.");
            (1, true)
        }
        Err(e) => {
            io.say(&format!("ERROR: {e}"));
            (1, true)
        }
    }
}

/// Hidden diagnostic `extract-tray <path>`: write the embedded tray to a new file, verify it and
/// print its size and SHA-256 (used by scripts/build.ps1 to check the release file).
pub(crate) fn extract_tray(path: &Path) -> Result<(), String> {
    let (hash, size) = files::extract_tray(path)?;
    println!("Extracted the embedded tray to {} ({size} bytes, SHA-256 {hash}).", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoking_sid() {
        assert_eq!(
            resolve_invoking_sid(Some("s-1-5-21-1-2-3-1001"), Some("S-1-5-21-9-9-9-500")).unwrap().as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert!(resolve_invoking_sid(Some("S-1-5-18"), None).is_err());
        assert!(resolve_invoking_sid(Some("garbage"), None).is_err());
        assert_eq!(
            resolve_invoking_sid(None, Some("S-1-5-21-1-2-3-1001")).unwrap().as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(resolve_invoking_sid(None, Some("S-1-5-18")).unwrap(), None);
        assert_eq!(resolve_invoking_sid(None, None).unwrap(), None);
    }

    #[test]
    fn setup_refuses_a_custom_data_dir() {
        let dir = std::env::temp_dir().join(format!("predator-setup-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        let mut con = io::ScriptedIo::new(&[]);
        let (code, pause) = run_inner(&mut con, &data, &SetupOptions::default());
        assert_eq!((code, pause), (2, true));
        assert!(con.text().contains("--data-dir"));
        assert!(!dir.exists());
    }
}
