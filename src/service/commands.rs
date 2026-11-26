//! Implementations of the management commands (set-token, set-owner, features, audit, start,
//! stop, status, restart-helper). Output goes to stdout; errors are returned as user-facing text.
//! Pairing and the Telegram user list (`pair_interactive`, `users_list`, `users_remove`) live in
//! `pairing.rs` and are re-exported here.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use super::cli::{AuditCmd, FeatureCmd, OwnerSid, TokenInput};
use super::text::fmt_mb;
use super::winsec::{self, Secret};
use crate::config::SettingsStore;
use crate::features::Feature;
use crate::ipc::{IpcRequest, IpcResponse};
use crate::paths::{DataPaths, SERVICE_NAME};
use crate::sys::ServiceState;
use crate::telegram::TgError;
use crate::telegram::api::{TelegramApi, is_valid_token_format};

pub(crate) use super::pairing::{pair_interactive, users_list, users_remove};

/// Resolved data location for a command.
pub(crate) struct DataCtx {
    pub paths: DataPaths,
    /// True when `--data-dir` was not given (the protected `%ProgramData%\Predator`).
    pub is_default: bool,
}

impl DataCtx {
    pub fn new(data_dir: Option<&Path>) -> Self {
        match data_dir {
            Some(d) => Self { paths: DataPaths::new(d), is_default: false },
            None => Self { paths: DataPaths::default_paths(), is_default: true },
        }
    }

    /// Commands touching the protected default data directory need an elevated prompt.
    pub fn require_admin(&self, what: &str) -> Result<(), String> {
        if self.is_default { require_admin(what) } else { Ok(()) }
    }

    pub fn settings(&self) -> Result<SettingsStore, String> {
        SettingsStore::load(&self.paths.settings()).map_err(|e| io_error(&self.paths.settings(), &e))
    }

    /// Create the directories before writing into them. A custom `--data-dir` gets plain
    /// directories. The protected default location must be trusted (owner SYSTEM/Administrators,
    /// protected ACL — a folder another user pre-created is refused), is created atomically with
    /// its final ACL when missing, and gets that ACL re-applied when it drifted.
    pub fn ensure(&self) -> Result<(), String> {
        if !self.is_default {
            return self.paths.ensure_dirs().map_err(|e| io_error(&self.paths.root, &e));
        }
        require_admin("Writing to the protected data directory")?;
        if let winsec::DirTrust::Untrusted(why) = winsec::assess_data_dir(&self.paths.root, false) {
            return Err(untrusted_data_dir_message(&self.paths.root, &why));
        }
        self.paths.ensure_dirs_secure().map_err(|e| io_error(&self.paths.root, &e))?;
        winsec::secure_data_dir(&self.paths.root, true)?;
        Ok(())
    }
}

/// Error text for a default data directory that cannot be trusted (see `winsec::assess_data_dir`).
pub(crate) fn untrusted_data_dir_message(root: &Path, why: &str) -> String {
    format!(
        "{} was not created by the Vigil installer and cannot be trusted ({why}). Nothing in it is used. \
         Run 'predator-service install' from an elevated prompt (stop the service first): it moves the folder aside \
         and creates a new protected one.",
        root.display()
    )
}

/// The Windows service always uses the protected default data directory, so the commands that
/// manage the service (`install`, `uninstall`, `start`, `stop`) refuse `--data-dir` instead of
/// silently acting on a different directory than the service.
pub(crate) fn reject_custom_data_dir(data: &DataCtx, what: &str) -> Result<(), String> {
    if data.is_default {
        return Ok(());
    }
    Err(format!(
        "'{what}' does not accept --data-dir: the Windows service always uses the protected data directory {}. \
         --data-dir is only for 'console' and for testing the setup commands. Run '{what}' again without it.",
        DataPaths::default_root().display()
    ))
}

pub(crate) fn io_error(path: &Path, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("Access to {} was denied. Run this command from an elevated (Administrator) prompt.", path.display())
    } else {
        format!("{}: {e}", path.display())
    }
}

pub(crate) fn is_elevated() -> bool {
    std::panic::catch_unwind(crate::sys::sysinfo::is_elevated).unwrap_or(false)
}

pub(crate) fn require_admin(what: &str) -> Result<(), String> {
    if is_elevated() {
        Ok(())
    } else {
        Err(format!(
            "'{what}' needs administrator rights. Open Windows Terminal or Command Prompt with \
             'Run as administrator' and try again."
        ))
    }
}

pub(crate) fn service_state() -> (ServiceState, u32) {
    std::panic::catch_unwind(|| crate::sys::scm::query(SERVICE_NAME)).unwrap_or((ServiceState::Unknown, 0))
}

fn service_running() -> bool {
    matches!(service_state().0, ServiceState::Running | ServiceState::StartPending)
}

const RESTART_HINT: &str = "Restart the service to apply the change: predator-service stop && predator-service start";

/// After settings.json was changed on disk while the service runs, ask it to re-read the file
/// (IPC `ReloadSettings`) — otherwise it would keep, and later write back, its old copy.
/// Prints what happened; never fails the command.
pub(crate) fn tell_service_settings_changed(data: &DataCtx) {
    if !data.is_default || !service_running() {
        return;
    }
    match crate::ipc::request(&IpcRequest::ReloadSettings, Duration::from_secs(5)) {
        Ok(IpcResponse::Ok { .. }) => println!("The running service reloaded its settings."),
        Ok(IpcResponse::Denied { reason }) => {
            println!("The service refused to reload its settings ({reason}). {RESTART_HINT}")
        }
        Ok(IpcResponse::Error { message }) => {
            println!("The service could not reload its settings ({message}). {RESTART_HINT}")
        }
        Ok(other) => println!("Unexpected reply from the service ({other:?}). {RESTART_HINT}"),
        Err(e) => println!("The running service was not reachable ({e}). {RESTART_HINT}"),
    }
}

// ---------------------------------------------------------------------------------------------
// set-token
// ---------------------------------------------------------------------------------------------

fn read_token(input: &TokenInput) -> Result<Secret, String> {
    match input {
        TokenInput::File(p) => super::runtime::read_plain_token(p),
        TokenInput::Stdin => {
            let mut raw = Vec::new();
            std::io::stdin()
                .take(64 * 1024)
                .read_to_end(&mut raw)
                .map_err(|e| format!("Cannot read the token from standard input: {e}"))?;
            let text = String::from_utf8(raw).map_err(|_| "Standard input is not UTF-8 text".to_string())?;
            let text = Secret::new(text);
            Ok(Secret::new(text.expose().lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string()))
        }
        TokenInput::Prompt => winsec::read_hidden_line("Paste the bot token from @BotFather (input is hidden): "),
    }
}

/// Map a getMe failure to an actionable message (never containing the token).
pub(crate) fn describe_token_error(e: &TgError) -> String {
    match e {
        TgError::Unauthorized => {
            "Telegram rejected this token (401 Unauthorized). Copy it again from @BotFather (/mybots → API Token)."
                .into()
        }
        TgError::Network(m) => {
            format!("Could not reach Telegram to verify the token ({m}). Check the internet connection and try again.")
        }
        other => format!("Telegram did not accept the token check: {other}"),
    }
}

pub(crate) fn set_token(data: &DataCtx, input: &TokenInput, verify: bool) -> Result<(), String> {
    data.require_admin("set-token")?;
    let token = read_token(input)?;
    if token.expose().is_empty() {
        return Err("No token was entered.".into());
    }
    if !is_valid_token_format(token.expose()) {
        return Err("This does not look like a Telegram bot token (expected something like 123456789:AA…, \
                    as shown by @BotFather)."
            .into());
    }
    let mut username: Option<String> = None;
    if verify {
        let api = TelegramApi::new(token.expose()).map_err(|e| describe_token_error(&e))?;
        let me = api.get_me().map_err(|e| match e {
            TgError::Network(_) => {
                format!("{} Or store it without checking using --no-verify.", describe_token_error(&e))
            }
            _ => describe_token_error(&e),
        })?;
        if !me.is_bot {
            return Err("getMe did not return a bot account.".into());
        }
        username = me.username.filter(|u| !u.is_empty());
    }
    data.ensure()?;
    // Always machine scope: token.dat's ACL (SYSTEM + Administrators) is the protection, and
    // elevated administrators must stay able to use it for 'pair' and 'selftest' (see secrets.rs).
    crate::secrets::save_token(&data.paths.token(), token.expose(), crate::secrets::Scope::Machine)?;
    let mut settings_changed = false;
    if let Some(u) = &username {
        let store = data.settings()?;
        let u2 = u.clone();
        settings_changed = store.get().bot_username.as_deref() != Some(u.as_str());
        store.update(move |s| s.bot_username = Some(u2)).map_err(|e| io_error(&data.paths.settings(), &e))?;
    }
    match &username {
        Some(u) => println!("Token stored (DPAPI) for @{u}"),
        None => println!("Token stored (DPAPI); not verified with Telegram (--no-verify)"),
    }
    let paired = data.settings().ok().and_then(|s| s.primary_user_id());
    if paired.is_none() {
        println!("Next: link your Telegram account with 'predator-service pair'.");
    }
    if data.is_default && service_running() {
        if settings_changed {
            tell_service_settings_changed(data);
        }
        println!("The running service keeps using the previous token until it restarts. {RESTART_HINT}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// set-owner / set-owner-sid
// ---------------------------------------------------------------------------------------------

pub(crate) fn set_owner(data: &DataCtx, telegram_id: i64) -> Result<(), String> {
    data.require_admin("set-owner")?;
    data.ensure()?;
    let store = data.settings()?;
    // The deprecated single-owner field keeps its meaning (see `Settings::owner_telegram_id`):
    // this account becomes the only authorized one, as an Admin. Used to revoke everyone else.
    store.update(|s| s.owner_telegram_id = Some(telegram_id)).map_err(|e| io_error(&data.paths.settings(), &e))?;
    store.save().map_err(|e| io_error(&data.paths.settings(), &e))?;
    println!(
        "Telegram user id {telegram_id} is now the only authorized account (Admin); any other paired account was \
         removed. Add more accounts with 'predator-service pair'."
    );
    println!("Make sure that account has pressed Start in the bot chat, otherwise Telegram cannot deliver alerts.");
    tell_service_settings_changed(data);
    Ok(())
}

pub(crate) fn set_owner_sid(data: &DataCtx, who: &OwnerSid) -> Result<(), String> {
    data.require_admin("set-owner-sid")?;
    let sid = match who {
        OwnerSid::User(name) => std::panic::catch_unwind(|| crate::sys::sysinfo::lookup_account_sid(name))
            .ok()
            .flatten()
            .ok_or_else(|| format!("Windows account '{name}' was not found."))?,
        OwnerSid::Sid(s) => {
            winsec::canonical_sid(s).ok_or_else(|| format!("'{s}' is not a valid SID (expected S-1-5-21-…)."))?
        }
    };
    if sid == "S-1-5-18" {
        return Err("LocalSystem is always allowed; choose the interactive user's account.".into());
    }
    data.ensure()?;
    let store = data.settings()?;
    let s2 = sid.clone();
    store.update(move |s| s.owner_windows_sid = Some(s2)).map_err(|e| io_error(&data.paths.settings(), &e))?;
    let name = winsec::account_name_of(&sid).unwrap_or_else(|| "unknown account".into());
    println!("Tray owner set to {name} ({sid}).");
    tell_service_settings_changed(data);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// features
// ---------------------------------------------------------------------------------------------

fn print_features(states: &[(String, String, bool)]) {
    for (key, label, on) in states {
        println!("  [{}] {key:<28} {label}", if *on { "on " } else { "off" });
    }
}

pub(crate) fn features(data: &DataCtx, cmd: &FeatureCmd) -> Result<(), String> {
    let via_service = data.is_default && service_running();
    match cmd {
        FeatureCmd::List => {
            if via_service {
                match crate::ipc::request(&IpcRequest::Status, Duration::from_secs(5)) {
                    Ok(IpcResponse::Status(st)) => {
                        println!("Features (from the running service):");
                        let v: Vec<_> = st.features.into_iter().map(|f| (f.key, f.label, f.enabled)).collect();
                        print_features(&v);
                        return Ok(());
                    }
                    Ok(IpcResponse::Denied { reason }) => println!("(service: {reason} — showing settings.json)"),
                    Ok(other) => println!("(unexpected reply {other:?} — showing settings.json)"),
                    Err(e) => println!("(service not reachable: {e} — showing settings.json)"),
                }
            }
            let s = data.settings()?.get();
            println!("Features ({}):", data.paths.settings().display());
            let v: Vec<_> = Feature::ALL
                .iter()
                .map(|f| (f.key().to_string(), f.label().to_string(), s.features.is_enabled(*f)))
                .collect();
            print_features(&v);
            Ok(())
        }
        FeatureCmd::Enable(key) | FeatureCmd::Disable(key) => {
            let enabled = matches!(cmd, FeatureCmd::Enable(_));
            let feature = Feature::from_key(key).ok_or_else(|| {
                let keys: Vec<&str> = Feature::ALL.iter().map(|f| f.key()).collect();
                format!("Unknown feature '{key}'. Valid keys: {}", keys.join(", "))
            })?;
            if via_service {
                let req = IpcRequest::SetFeature { feature: feature.key().into(), enabled };
                match crate::ipc::request(&req, Duration::from_secs(5)) {
                    Ok(IpcResponse::Ok { message }) => {
                        println!("{message} (applied by the running service)");
                        return Ok(());
                    }
                    Ok(IpcResponse::Denied { reason }) => return Err(format!("The service refused: {reason}")),
                    Ok(IpcResponse::Error { message }) => return Err(message),
                    Ok(other) => return Err(format!("Unexpected reply from the service: {other:?}")),
                    // Not reachable: edit settings.json directly and ask the service to reload it.
                    Err(e) => println!("(service not reachable: {e} — editing settings.json)"),
                }
            }
            data.require_admin("features")?;
            data.ensure()?;
            let store = data.settings()?;
            let changed = store.set_feature(feature, enabled).map_err(|e| io_error(&data.paths.settings(), &e))?;
            let state = if enabled { "enabled" } else { "disabled" };
            if changed {
                println!("{} {state}.", feature.label());
                tell_service_settings_changed(data);
            } else {
                println!("{} was already {state}.", feature.label());
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------------------------

pub(crate) fn audit(data: &DataCtx, cmd: AuditCmd) -> Result<(), String> {
    let run = |f: &dyn Fn() -> Result<String, String>| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| Err("internal error".into()))
    };
    match cmd {
        AuditCmd::Status => {
            let (text, ok) = std::panic::catch_unwind(crate::monitor::audit::describe)
                .unwrap_or_else(|_| Err("internal error".into()))
                .map_err(|e| {
                    if is_elevated() {
                        e
                    } else {
                        format!("{e}\nReading the audit policy needs an elevated (Administrator) prompt.")
                    }
                })?;
            println!("Logon audit policy: {text}");
            if ok {
                println!("Sufficient for login alerts.");
            } else {
                println!("NOT sufficient for login alerts — run 'predator-service audit enable' as Administrator.");
            }
            Ok(())
        }
        AuditCmd::Enable => {
            require_admin("audit enable")?;
            data.ensure()?;
            let backup = data.paths.audit_backup();
            println!("{}", run(&|| crate::monitor::audit::ensure_enabled(&backup))?);
            Ok(())
        }
        AuditCmd::Restore => {
            require_admin("audit restore")?;
            let backup = data.paths.audit_backup();
            println!("{}", run(&|| crate::monitor::audit::restore(&backup))?);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// start / stop / status / restart-helper
// ---------------------------------------------------------------------------------------------

pub(crate) fn start() -> Result<(), String> {
    require_admin("start")?;
    match service_state().0 {
        ServiceState::NotInstalled => {
            return Err("The service is not installed. Run 'predator-service install'.".into());
        }
        ServiceState::Running => {
            println!("The service is already running.");
            return Ok(());
        }
        _ => {}
    }
    crate::sys::scm::start_and_wait(SERVICE_NAME, Duration::from_secs(40))?;
    println!("Service started (PID {}).", service_state().1);
    Ok(())
}

pub(crate) fn stop() -> Result<(), String> {
    require_admin("stop")?;
    match service_state().0 {
        ServiceState::NotInstalled => return Err("The service is not installed.".into()),
        ServiceState::Stopped => {
            println!("The service is already stopped.");
            return Ok(());
        }
        _ => {}
    }
    crate::sys::scm::stop_and_wait(SERVICE_NAME, Duration::from_secs(40))?;
    println!("Service stopped.");
    Ok(())
}

pub(crate) fn status() -> Result<(), String> {
    let (state, pid) = service_state();
    match &state {
        ServiceState::NotInstalled => {
            println!("{}: not installed.", crate::PRODUCT_NAME);
            return Ok(());
        }
        ServiceState::Running => println!("{}: Running (PID {pid})", crate::PRODUCT_NAME),
        other => println!("{}: {}", crate::PRODUCT_NAME, other.label()),
    }
    if let Some(bin) = std::panic::catch_unwind(|| crate::sys::scm::binary_path(SERVICE_NAME)).ok().flatten() {
        println!("  Binary:          {}", bin.display());
    }
    if state != ServiceState::Running {
        return Ok(());
    }
    match crate::ipc::request(&IpcRequest::Status, Duration::from_secs(5)) {
        Ok(IpcResponse::Status(st)) => {
            let bot = st.bot_username.as_deref().map(|b| format!(" (@{b})")).unwrap_or_default();
            println!("  Version:         {}", st.version);
            println!("  Uptime:          {}", crate::util::time::fmt_duration(st.uptime_secs));
            println!("  Telegram:        {}{bot}", st.telegram);
            if let Some(t) = &st.transport {
                println!("  HTTPS transport: {t}");
            }
            println!("  Telegram users:  {}", if st.owner_configured { "paired" } else { "none yet (run 'pair')" });
            println!("  Login monitor:   {}", st.security_monitor);
            println!("  SSH monitor:     {}", st.ssh_monitor);
            println!("  Queued alerts:   {}", st.queued_notifications);
            println!(
                "  Memory:          {} private, {} working set",
                fmt_mb(st.private_bytes),
                fmt_mb(st.working_set_bytes)
            );
            if let Some(ts) = st.tailscale {
                println!("  Tailscale:       {ts}");
            }
            if st.dry_run {
                println!("  DRY-RUN:         power, lock, logout and Tailscale up/down are simulated");
            }
            let on: Vec<String> = st.features.iter().filter(|f| f.enabled).map(|f| f.key.clone()).collect();
            let off: Vec<String> = st.features.iter().filter(|f| !f.enabled).map(|f| f.key.clone()).collect();
            println!("  Features on:     {}", if on.is_empty() { "-".into() } else { on.join(", ") });
            println!("  Features off:    {}", if off.is_empty() { "-".into() } else { off.join(", ") });
        }
        Ok(IpcResponse::Denied { reason }) => println!("  (details unavailable: {reason} Use an elevated prompt.)"),
        Ok(other) => println!("  (unexpected reply: {other:?})"),
        Err(e) => println!("  (details unavailable: {e})"),
    }
    Ok(())
}

/// Internal: started detached by the service (IPC RestartService). Stops and restarts our own
/// service through the SCM.
pub(crate) fn restart_helper(data: &DataCtx) -> Result<(), String> {
    crate::logging::init(&data.paths.logs_dir(), false, false);
    crate::log_info!("restart-helper: restarting {SERVICE_NAME}");
    // Give the service a moment to deliver the IPC reply.
    std::thread::sleep(Duration::from_millis(1500));
    let result = crate::sys::scm::stop_and_wait(SERVICE_NAME, Duration::from_secs(45))
        .and_then(|()| crate::sys::scm::start_and_wait(SERVICE_NAME, Duration::from_secs(45)));
    match &result {
        Ok(()) => crate::log_info!("restart-helper: service restarted"),
        Err(e) => crate::log_error!("restart-helper: {e}"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_errors_are_actionable() {
        assert!(describe_token_error(&TgError::Unauthorized).contains("BotFather"));
        let net = describe_token_error(&TgError::Network("dns".into()));
        assert!(net.contains("internet connection") && !net.contains("--no-verify"), "{net}");
    }

    #[test]
    fn custom_data_dir_needs_no_admin_and_edits_settings() {
        let dir = std::env::temp_dir().join(format!("predator-cmd-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        assert!(!data.is_default);
        data.require_admin("x").unwrap();
        set_owner(&data, 4242).unwrap();
        assert_eq!(data.settings().unwrap().owner_id(), Some(4242));
        features(&data, &FeatureCmd::Disable("ssh-monitoring".into())).unwrap();
        assert!(!data.settings().unwrap().feature(Feature::SshMonitoring));
        assert!(features(&data, &FeatureCmd::Enable("nope".into())).unwrap_err().contains("Valid keys"));
        set_owner_sid(&data, &OwnerSid::Sid("s-1-5-32-545".into())).unwrap();
        assert_eq!(data.settings().unwrap().get().owner_windows_sid.as_deref(), Some("S-1-5-32-545"));
        assert!(set_owner_sid(&data, &OwnerSid::Sid("S-1-5-18".into())).is_err());
        assert!(set_owner_sid(&data, &OwnerSid::Sid("garbage".into())).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn service_commands_reject_a_custom_data_dir() {
        let dir = std::env::temp_dir().join(format!("predator-cmd-{}", crate::util::rand::hex(4)));
        let custom = DataCtx::new(Some(&dir));
        for what in ["install", "uninstall", "start", "stop"] {
            let e = reject_custom_data_dir(&custom, what).unwrap_err();
            assert!(e.contains("--data-dir") && e.contains(what), "{e}");
        }
        assert!(reject_custom_data_dir(&DataCtx::new(None), "install").is_ok());
        // install/uninstall check this before anything else (no admin rights needed to see it).
        assert!(super::super::install::install(&custom, false).unwrap_err().contains("--data-dir"));
        assert!(super::super::install::uninstall(&custom, false, true).unwrap_err().contains("--data-dir"));
        assert!(!dir.exists(), "nothing was created");
        let m = untrusted_data_dir_message(Path::new(r"C:\ProgramData\Predator"), "it is owned by X");
        assert!(m.contains("owned by X") && m.contains("moves the folder aside"), "{m}");
    }

    #[test]
    fn set_token_stores_machine_scope() {
        let dir = std::env::temp_dir().join(format!("predator-cmd-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        let token_file = std::env::temp_dir().join(format!("predator-tok-{}.txt", crate::util::rand::hex(4)));
        std::fs::write(&token_file, "123456789:AAExampleExampleExampleExampleExam\n").unwrap();
        set_token(&data, &TokenInput::File(token_file.clone()), false).unwrap();
        assert_eq!(crate::secrets::stored_scope(&data.paths.token()).unwrap(), Some(crate::secrets::Scope::Machine));
        assert!(data.paths.logs_dir().is_dir());
        std::fs::remove_file(&token_file).ok();
        std::fs::remove_dir_all(&dir).ok();
    }
}
