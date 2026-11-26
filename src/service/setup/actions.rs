//! The real wizard and menu environment: what setup actually does on this PC. The dialogs that
//! drive it are in `wizard.rs` and `menu.rs`.

use std::path::PathBuf;
use std::time::Duration;

use super::super::commands::{self, DataCtx, describe_token_error, service_state};
use super::super::install;
use super::super::runtime::{TokenLoad, TokenSource, load_token_from};
use super::super::winsec::{self, DirTrust, Secret};
use super::PAIR_TTL_SECS;
use super::desktop;
use super::files::{self, Images};
use super::menu::{MenuEnv, MenuState};
use super::wizard::{BotInfo, WizardEnv};
use crate::config::{AddUserOutcome, AuthorizedUser, UserRole};
use crate::paths::{SERVICE_EXE, SERVICE_NAME, TRAY_EXE};
use crate::sys::{ServiceState, TailscaleStatus};
use crate::telegram::api::TelegramApi;

/// How long service start/stop may take.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(40);

/// This PC, as seen by setup.
pub(crate) struct Machine<'a> {
    data: &'a DataCtx,
    install_dir: PathBuf,
    /// Windows account that started setup (becomes the tray owner). Differs from `my_sid` when
    /// another administrator's credentials were entered in the UAC prompt.
    invoking_sid: Option<String>,
    /// Account this elevated process runs as (needed for the non-elevated shell launch).
    my_sid: Option<String>,
    images: Option<Images>,
    update_available: Option<bool>,
}

impl<'a> Machine<'a> {
    pub(crate) fn new(
        data: &'a DataCtx,
        install_dir: PathBuf,
        invoking_sid: Option<String>,
        my_sid: Option<String>,
    ) -> Self {
        Self { data, install_dir, invoking_sid, my_sid, images: None, update_available: None }
    }

    fn images(&mut self) -> Result<&Images, String> {
        if self.images.is_none() {
            self.images = Some(Images::load()?);
        }
        self.images.as_ref().ok_or_else(|| "internal error: program images missing".to_string())
    }

    fn trusted_data(&self) -> bool {
        winsec::assess_data_dir(&self.data.paths.root, true) == DirTrust::Trusted
    }

    fn tray_path(&self) -> PathBuf {
        self.install_dir.join(TRAY_EXE)
    }

    fn start_tray_line(&self) -> String {
        desktop::start_tray(&self.tray_path(), self.my_sid.as_deref()).describe()
    }

    /// The running program is not the installed one and has different bytes.
    fn compute_update_available(&self) -> bool {
        let installed = self.install_dir.join(SERVICE_EXE);
        let Ok(running) = std::env::current_exe() else { return false };
        if desktop::same_path(&running, &installed) {
            return false;
        }
        // One program file missing (deleted or quarantined) while the other is there: the update
        // repairs the installation. Neither file there: nothing is installed in this folder.
        let tray_present = self.install_dir.join(crate::paths::TRAY_EXE).is_file();
        match (installed.is_file(), tray_present) {
            (false, false) => return false,
            (false, true) | (true, false) => return true,
            (true, true) => {}
        }
        match (files::sha256_file(&running), files::sha256_file(&installed)) {
            (Ok(a), Ok(b)) => a != b,
            // An unreadable installed file is worth replacing.
            (Ok(_), Err(_)) => true,
            _ => false,
        }
    }

    fn add_admin_user(&self, telegram_id: i64) -> Result<(), String> {
        self.data.ensure()?;
        let store = self.data.settings()?;
        let user = AuthorizedUser::new(telegram_id, "", UserRole::Admin, crate::util::time::now_unix());
        match store.add_user(user)? {
            AddUserOutcome::Added => {}
            AddUserOutcome::AlreadyAuthorized => {
                store
                    .update(|s| {
                        if let Some(u) = s.authorized_users.iter_mut().find(|u| u.id == telegram_id) {
                            u.role = UserRole::Admin;
                        }
                    })
                    .map_err(|e| commands::io_error(&self.data.paths.settings(), &e))?;
            }
            AddUserOutcome::LimitReached => {
                return Err(format!(
                    "{} Telegram accounts are already authorized; remove one first.",
                    crate::config::MAX_AUTHORIZED_USERS
                ));
            }
        }
        commands::tell_service_settings_changed(self.data);
        Ok(())
    }

    fn store_token_in_data(&self, token: &Secret, bot: &BotInfo) -> Result<(), String> {
        self.data.ensure()?;
        crate::secrets::save_token(&self.data.paths.token(), token.expose(), crate::secrets::Scope::Machine)?;
        let username = bot.username.clone();
        self.data
            .settings()?
            .update(move |s| s.bot_username = username)
            .map_err(|e| commands::io_error(&self.data.paths.settings(), &e))?;
        // A running service must re-read settings.json, or it writes its old copy back later.
        commands::tell_service_settings_changed(self.data);
        Ok(())
    }

    /// Replace the installed executables with this program (and its tray): stage verified
    /// copies, stop the service and the installed tray, swap the files, refresh the service
    /// configuration, start it again. A version that does not start is rolled back.
    fn update_installation(&mut self) -> Result<(), String> {
        let dir = self.install_dir.clone();
        // Never write a LocalSystem program into a folder other accounts can change (they could
        // swap the verified copy before it is renamed into place).
        install::check_program_files(&dir).map_err(|e| {
            format!(
                "The installed program folder is not protected, so it is not updated ({e}). Uninstall (7) and \
                 run setup again."
            )
        })?;
        let images = self.images()?;
        let svc = files::stage(&dir, SERVICE_EXE, &images.service)?;
        let tray = match files::stage(&dir, TRAY_EXE, &images.tray) {
            Ok(t) => t,
            Err(e) => {
                files::discard(&svc);
                return Err(e);
            }
        };
        if svc.is_unchanged() && tray.is_unchanged() {
            println!("  The installed program is already this version.");
            self.update_available = Some(false);
            return Ok(());
        }
        let was_running = matches!(service_state().0, ServiceState::Running | ServiceState::StartPending);
        println!("  Stopping the service...");
        if let Err(e) = crate::sys::scm::stop_and_wait(SERVICE_NAME, SERVICE_TIMEOUT) {
            files::discard(&svc);
            files::discard(&tray);
            return Err(format!("Cannot stop the service for the update: {e}"));
        }
        let (stopped, failures) = files::stop_installed_trays(&self.tray_path());
        if stopped > 0 {
            println!("  Stopped {stopped} tray icon process(es).");
        }
        for f in failures {
            println!("  WARNING: {f} (the file is replaced anyway; that tray restarts at its next sign-in)");
        }
        let restart_old = |what: &str| {
            if was_running && let Err(e) = crate::sys::scm::start_and_wait(SERVICE_NAME, SERVICE_TIMEOUT) {
                println!("  WARNING: the {what} service did not start again: {e}");
            }
        };
        let svc = match files::commit(svc) {
            Ok(c) => c,
            Err(e) => {
                files::discard(&tray);
                restart_old("previous");
                return Err(e);
            }
        };
        let tray = match files::commit(tray) {
            Ok(c) => c,
            Err(e) => {
                if let Err(r) = files::rollback(&svc) {
                    println!("  WARNING: {r}");
                }
                restart_old("previous");
                return Err(e);
            }
        };
        // The configuration of THIS version (failure actions, audit policy, tray autostart).
        if let Err(e) = install::register(self.data, &dir, None) {
            println!("  WARNING: {e}");
        }
        println!("  Starting the new version...");
        if let Err(e) = crate::sys::scm::start_and_wait(SERVICE_NAME, SERVICE_TIMEOUT) {
            if !was_running {
                // The previous version was not running either: nothing proves it worked better,
                // so the update stays (the cause is likely the configuration, see Status).
                for note in [files::finish(&svc), files::finish(&tray)].into_iter().flatten() {
                    println!("  {note}");
                }
                self.update_available = Some(false);
                println!("  WARNING: the program was updated, but the service did not start: {e}");
                println!("  (It was not running before the update either; see Status.)");
                println!("  Tray icon: {}", self.start_tray_line());
                return Ok(());
            }
            println!("  The new version did not start ({e}); restoring the previous version...");
            // A start that timed out may still be pending: stop it before the files are swapped back.
            let _ = crate::sys::scm::stop_and_wait(SERVICE_NAME, SERVICE_TIMEOUT);
            for c in [&tray, &svc] {
                if let Err(r) = files::rollback(c) {
                    println!("  WARNING: {r}");
                }
            }
            restart_old("restored");
            return Err(format!(
                "Update failed: the new version did not start ({e}). The previous version was restored."
            ));
        }
        for note in [files::finish(&svc), files::finish(&tray)].into_iter().flatten() {
            println!("  {note}");
        }
        self.update_available = Some(false);
        println!("  Tray icon: {}", self.start_tray_line());
        Ok(())
    }
}

/// getMe with a fresh client; errors never contain the token.
fn verify(token: &str) -> Result<BotInfo, String> {
    let api = TelegramApi::new(token).map_err(|e| describe_token_error(&e))?;
    let me = api.get_me().map_err(|e| describe_token_error(&e))?;
    if !me.is_bot {
        return Err("getMe did not return a bot account.".into());
    }
    Ok(BotInfo { username: me.username.filter(|u| !u.is_empty()), name: me.first_name })
}

fn tailscale_status() -> TailscaleStatus {
    std::panic::catch_unwind(crate::sys::tailscale::status).unwrap_or_default()
}

impl WizardEnv for Machine<'_> {
    fn install_dir(&self) -> PathBuf {
        self.install_dir.clone()
    }

    fn data_dir(&self) -> PathBuf {
        self.data.paths.root.clone()
    }

    fn stored_token(&mut self) -> Option<Option<String>> {
        if !self.trusted_data() {
            return None;
        }
        match load_token_from(&TokenSource::DataDir(self.data.paths.token())) {
            TokenLoad::Loaded(_) => Some(self.data.settings().ok().and_then(|s| s.get().bot_username)),
            _ => None,
        }
    }

    fn verify_token(&mut self, token: &str) -> Result<BotInfo, String> {
        verify(token)
    }

    fn prepare_data(&mut self) -> Result<(), String> {
        install::prepare_data_dir(&self.data.paths)
    }

    fn store_token(&mut self, token: &Secret, bot: &BotInfo) -> Result<(), String> {
        self.store_token_in_data(token, bot)
    }

    fn users(&mut self) -> Vec<AuthorizedUser> {
        if !self.trusted_data() {
            return Vec::new();
        }
        self.data.settings().map(|s| s.authorized_users()).unwrap_or_default()
    }

    fn pair_admin(&mut self) -> Result<(), String> {
        commands::pair_interactive(self.data, true, PAIR_TTL_SECS)
    }

    fn add_admin(&mut self, telegram_id: i64) -> Result<(), String> {
        self.add_admin_user(telegram_id)
    }

    fn install_files(&mut self) -> Result<(), String> {
        let dir = self.install_dir.clone();
        let images = self.images()?;
        for note in files::install_program(&dir, images)? {
            println!("  {note}");
        }
        Ok(())
    }

    fn register_service(&mut self) -> Result<(), String> {
        install::register(self.data, &self.install_dir, self.invoking_sid.as_deref())
    }

    fn start_service(&mut self) -> Result<(), String> {
        crate::sys::scm::start_and_wait(SERVICE_NAME, SERVICE_TIMEOUT)
    }

    fn start_tray(&mut self) -> String {
        self.start_tray_line()
    }

    fn tailscale(&mut self) -> TailscaleStatus {
        println!("  Checking Tailscale...");
        tailscale_status()
    }
}

impl MenuEnv for Machine<'_> {
    fn state(&mut self) -> MenuState {
        if self.update_available.is_none() {
            self.update_available = Some(self.compute_update_available());
        }
        let settings = self.data.settings().ok();
        let installed = self.install_dir.join(SERVICE_EXE);
        MenuState {
            service: service_state().0.label().to_string(),
            bot: settings.as_ref().and_then(|s| s.get().bot_username),
            users: settings.as_ref().map(|s| s.authorized_users().len()).unwrap_or(0),
            installed_version: std::panic::catch_unwind(|| crate::sys::tailscale::file_version(&installed))
                .ok()
                .flatten(),
            install_dir: self.install_dir.clone(),
            update_available: self.update_available.unwrap_or(false),
        }
    }

    fn status(&mut self) -> Result<(), String> {
        commands::status()?;
        println!("  Program folder:  {}", self.install_dir.display());
        println!("  Data folder:     {}", self.data.paths.root.display());
        let ts = tailscale_status();
        println!("  Tailscale:       {}", super::tailscale::summary(&ts));
        for line in super::tailscale::advice(&ts) {
            println!("    {}", line.replace('\n', "\n    "));
        }
        Ok(())
    }

    fn pair(&mut self, admin: bool) -> Result<(), String> {
        commands::pair_interactive(self.data, admin, PAIR_TTL_SECS)
    }

    fn list_users(&mut self) -> Result<(), String> {
        commands::users_list(self.data)
    }

    fn remove_user(&mut self, id: i64) -> Result<(), String> {
        commands::users_remove(self.data, id)
    }

    fn add_admin(&mut self, id: i64) -> Result<(), String> {
        self.add_admin_user(id)
    }

    fn verify_token(&mut self, token: &str) -> Result<BotInfo, String> {
        verify(token)
    }

    fn store_token(&mut self, token: &Secret, bot: &BotInfo) -> Result<(), String> {
        self.store_token_in_data(token, bot)
    }

    fn service_running(&mut self) -> bool {
        matches!(service_state().0, ServiceState::Running | ServiceState::StartPending)
    }

    fn restart_service(&mut self) -> Result<(), String> {
        crate::sys::scm::stop_and_wait(SERVICE_NAME, SERVICE_TIMEOUT)?;
        crate::sys::scm::start_and_wait(SERVICE_NAME, SERVICE_TIMEOUT)
    }

    fn update(&mut self) -> Result<(), String> {
        self.update_installation()
    }

    fn open_bot(&mut self) -> Result<String, String> {
        let username = self.data.settings().ok().and_then(|s| s.get().bot_username);
        let link = username
            .as_deref()
            .and_then(desktop::bot_link)
            .ok_or("The bot's username is not known yet. Choose 4 (Change bot token) to look it up.")?;
        desktop::open_link(&link, self.my_sid.as_deref()).map_err(|why| format!("{why}. Open {link} yourself."))?;
        Ok(link)
    }

    fn uninstall(&mut self, purge_data: bool) -> Result<Option<String>, String> {
        let outcome = install::uninstall_steps(self.data, false, purge_data);
        if !outcome.service_removed {
            // The service is still registered: its program files must stay.
            return Err(outcome.result.err().unwrap_or_else(|| "the service could not be removed".into()));
        }
        let (stopped, failures) = files::stop_installed_trays(&self.tray_path());
        if stopped > 0 {
            println!("Stopped {stopped} tray icon process(es).");
        }
        for f in failures {
            println!("WARNING: {f}");
        }
        let removed = files::remove_install_dir(&self.install_dir);
        match &removed {
            Ok(notes) => {
                println!("Program folder {} removed.", self.install_dir.display());
                for n in notes {
                    println!("{n}");
                }
            }
            Err(e) => println!("WARNING: {e}"),
        }
        let problems: Vec<String> = [outcome.result.err(), removed.err()].into_iter().flatten().collect();
        Ok((!problems.is_empty()).then(|| problems.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_detection_in_a_scratch_install() {
        let dir = std::env::temp_dir().join(format!("predator-upd-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let data = DataCtx::new(Some(&dir.join("data")));
        let m = Machine::new(&data, dir.clone(), None, None);
        assert!(!m.compute_update_available(), "nothing installed");
        std::fs::write(dir.join(crate::paths::TRAY_EXE), b"MZ tray").unwrap();
        assert!(m.compute_update_available(), "service exe missing (e.g. quarantined): repair");
        std::fs::write(dir.join(SERVICE_EXE), b"MZ other build").unwrap();
        assert!(m.compute_update_available(), "different bytes");
        std::fs::copy(std::env::current_exe().unwrap(), dir.join(SERVICE_EXE)).unwrap();
        assert!(!m.compute_update_available(), "same bytes");
        std::fs::remove_file(dir.join(crate::paths::TRAY_EXE)).unwrap();
        assert!(m.compute_update_available(), "tray missing: repair");
        std::fs::remove_dir_all(&dir).ok();
    }
}
