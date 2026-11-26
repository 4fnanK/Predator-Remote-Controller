//! The first-run wizard (service not installed yet). The dialog is written against [`Io`] and
//! [`WizardEnv`] so every path — cancel, bad token, failed pairing, unattended mode — is tested
//! with scripted input and a fake environment; the real environment is in `actions.rs`.

use std::path::PathBuf;

use super::super::winsec::Secret;
use super::io::{Io, ask_yes_no};
use crate::config::AuthorizedUser;
use crate::sys::TailscaleStatus;
use crate::telegram::api::is_valid_token_format;

/// The bot behind a token (from getMe).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BotInfo {
    pub username: Option<String>,
    pub name: String,
}

impl BotInfo {
    /// `@ExampleBot`, or the display name when the bot has no username.
    pub(crate) fn label(&self) -> String {
        match &self.username {
            Some(u) if !u.is_empty() => format!("@{u}"),
            _ => self.name.clone(),
        }
    }
}

/// How to get a token, shown before the prompt.
pub(crate) const BOTFATHER_GUIDE: &str = "\
You need your own Telegram bot (free, takes a minute). If you do not have one yet:
  1. In Telegram, open a chat with @BotFather (the official bot with the blue check mark).
  2. Send /newbot, choose a display name, then a username that ends in \"bot\".
  3. BotFather answers with a token that looks like 123456789:AAH...  Copy it.
Paste the token below. It is not shown while you type and is stored encrypted (DPAPI).
Keep it secret: anyone who has it can read and send messages as your bot.";

/// How many tokens are tried before setup gives up.
pub(crate) const MAX_TOKEN_ATTEMPTS: usize = 5;

/// Whitespace removed (a pasted token often carries a trailing newline or spaces).
pub(crate) fn clean_token(raw: &Secret) -> Secret {
    Secret::new(raw.expose().chars().filter(|c| !c.is_whitespace()).collect())
}

/// Ask for the bot token until Telegram accepts one (format check first, then `verify` = getMe).
/// `Ok(None)` = the user entered nothing (cancel).
pub(crate) fn ask_token(
    io: &mut dyn Io,
    verify: &mut dyn FnMut(&str) -> Result<BotInfo, String>,
) -> Result<Option<(Secret, BotInfo)>, String> {
    io.say(BOTFATHER_GUIDE);
    for _ in 0..MAX_TOKEN_ATTEMPTS {
        let token = clean_token(&io.ask_secret("\nBot token (hidden; press Enter alone to cancel): ")?);
        if token.expose().is_empty() {
            return Ok(None);
        }
        if !is_valid_token_format(token.expose()) {
            io.say("  That does not look like a bot token (expected 123456789:AAH... as sent by @BotFather).");
            continue;
        }
        io.say("  Checking the token with Telegram...");
        match verify(token.expose()) {
            Ok(bot) => {
                io.say(&format!("  OK - this is the token of {} ({}).", bot.label(), bot.name));
                return Ok(Some((token, bot)));
            }
            Err(e) => io.say(&format!("  {e}")),
        }
    }
    Err(format!("No working bot token after {MAX_TOKEN_ATTEMPTS} attempts."))
}

/// Everything the wizard does to the machine.
pub(crate) trait WizardEnv {
    fn install_dir(&self) -> PathBuf;
    fn data_dir(&self) -> PathBuf;
    /// A token already stored in a TRUSTED data folder: `Some(bot username if known)`.
    fn stored_token(&mut self) -> Option<Option<String>>;
    fn verify_token(&mut self, token: &str) -> Result<BotInfo, String>;
    /// Trust check of the data folder (an untrusted one is moved aside) + protected ACL.
    fn prepare_data(&mut self) -> Result<(), String>;
    fn store_token(&mut self, token: &Secret, bot: &BotInfo) -> Result<(), String>;
    /// Authorized Telegram users in a trusted data folder.
    fn users(&mut self) -> Vec<AuthorizedUser>;
    /// Interactive pairing of a Telegram account as Admin (direct polling, service not running).
    fn pair_admin(&mut self) -> Result<(), String>;
    /// `--telegram-id N`: authorize N as Admin without pairing.
    fn add_admin(&mut self, telegram_id: i64) -> Result<(), String>;
    fn install_files(&mut self) -> Result<(), String>;
    /// Service registration, failure actions, audit policy, tray Run value, tray owner SID.
    fn register_service(&mut self) -> Result<(), String>;
    fn start_service(&mut self) -> Result<(), String>;
    /// Start the tray in this session (not elevated); returns a status text.
    fn start_tray(&mut self) -> String;
    fn tailscale(&mut self) -> TailscaleStatus;
}

/// Options of an unattended (`--yes`) or partly scripted run.
#[derive(Default)]
pub(crate) struct WizardOptions {
    /// Token read from `--token-file`.
    pub token: Option<Secret>,
    pub telegram_id: Option<i64>,
    pub yes: bool,
}

/// How the wizard ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WizardEnd {
    /// Installed; `false` when something needs attention (e.g. the service did not start).
    Done {
        ok: bool,
    },
    Cancelled,
}

/// `--yes` cannot ask anything: it needs a token and a Telegram id up front (or what a kept data
/// folder already has).
pub(crate) fn unattended_problem(opts: &WizardOptions, have_token: bool, have_users: bool) -> Option<String> {
    if !opts.yes {
        return None;
    }
    if opts.token.is_none() && !have_token {
        return Some("--yes needs --token-file FILE (a text file with the bot token).".into());
    }
    if opts.telegram_id.is_none() && !have_users {
        return Some("--yes needs --telegram-id ID (your numeric Telegram user id).".into());
    }
    None
}

fn step(io: &mut dyn Io, n: u32, title: &str) {
    io.say(&format!("\n[{n}/6] {title}"));
    io.say(&"-".repeat(title.len() + 6));
}

fn users_line(users: &[AuthorizedUser]) -> String {
    if users.is_empty() {
        return "none".into();
    }
    users.iter().map(|u| format!("{} ({}, {})", u.label(), u.id, u.role.label())).collect::<Vec<_>>().join(", ")
}

/// Ask `question` (unattended: take `unattended`). `None` = end of input.
fn confirm(io: &mut dyn Io, yes: bool, question: &str, default: bool, unattended: bool) -> Option<bool> {
    if yes { Some(unattended) } else { ask_yes_no(io, question, default) }
}

/// Run the wizard. `Err` = a step failed (already explained); nothing is rolled back, running
/// setup again continues where it stopped.
pub(crate) fn run_wizard(io: &mut dyn Io, env: &mut dyn WizardEnv, opts: WizardOptions) -> Result<WizardEnd, String> {
    let stored = env.stored_token();
    let known_users = env.users();
    if let Some(problem) = unattended_problem(&opts, stored.is_some(), !known_users.is_empty()) {
        return Err(problem);
    }

    io.say(&format!("{} {} - Setup", crate::PRODUCT_NAME, crate::VERSION));
    io.say(&"=".repeat(crate::PRODUCT_NAME.len() + crate::VERSION.len() + 10));
    io.say("This installs Predator Remote Controller on this PC:");
    io.say("  * a Windows service that starts with Windows (before anyone signs in), sends sign-in");
    io.say("    alerts to your private Telegram bot and lets you control the PC from Telegram;");
    io.say("  * a small tray icon for the signed-in user.");
    io.say(&format!("Program files: {}", env.install_dir().display()));
    io.say(&format!("Settings:      {} (only SYSTEM and administrators can read it)", env.data_dir().display()));
    if confirm(io, opts.yes, "\nInstall now?", true, true) != Some(true) {
        return Ok(WizardEnd::Cancelled);
    }

    // 1. Token.
    step(io, 1, "Telegram bot token");
    let mut new_token: Option<(Secret, BotInfo)> = None;
    let bot_label: Option<String>;
    if let Some(token) = opts.token {
        let token = clean_token(&token);
        if !is_valid_token_format(token.expose()) {
            return Err("The token file does not contain a valid bot token (123456789:AAH...).".into());
        }
        io.say("  Checking the token from the token file with Telegram...");
        let bot = env.verify_token(token.expose())?;
        io.say(&format!("  OK - token of {}.", bot.label()));
        bot_label = Some(bot.label());
        new_token = Some((token, bot));
    } else {
        let keep = match &stored {
            Some(user) => {
                let who = user.as_deref().map(|u| format!(" for @{u}")).unwrap_or_default();
                io.say(&format!("A bot token{who} is already stored on this PC."));
                match confirm(io, opts.yes, "Keep using it?", true, true) {
                    Some(k) => k,
                    None => return Ok(WizardEnd::Cancelled),
                }
            }
            None => false,
        };
        if keep {
            bot_label = stored.flatten().map(|u| format!("@{u}"));
        } else {
            let mut verify = |t: &str| env.verify_token(t);
            match ask_token(io, &mut verify)? {
                Some((token, bot)) => {
                    bot_label = Some(bot.label());
                    new_token = Some((token, bot));
                }
                None => return Ok(WizardEnd::Cancelled),
            }
        }
    }

    // 2. Data folder + token.
    step(io, 2, "Protected data folder");
    env.prepare_data()?;
    io.say(&format!("  {} is protected (SYSTEM + Administrators only).", env.data_dir().display()));
    if let Some((token, bot)) = &new_token {
        env.store_token(token, bot)?;
        io.say("  Bot token stored, encrypted with DPAPI.");
    }
    drop(new_token);

    // 3. Telegram account.
    step(io, 3, "Link your Telegram account");
    let users = env.users();
    if let Some(id) = opts.telegram_id {
        env.add_admin(id)?;
        io.say(&format!("  Telegram user {id} is authorized (Admin)."));
    } else if !users.is_empty() {
        io.say(&format!("  Already authorized: {}", users_line(&users)));
        if confirm(io, opts.yes, "  Pair another Telegram account (as Admin) now?", false, false) == Some(true) {
            pair_with_retry(io, env, opts.yes)?;
        }
    } else {
        io.say("  Now link the Telegram account that will control this PC. It becomes the first Admin");
        io.say("  (admins can also remove other users). Only accounts you pair can use the bot.");
        if !pair_with_retry(io, env, opts.yes)? {
            return Ok(WizardEnd::Cancelled);
        }
    }

    // 4. Program files.
    step(io, 4, "Program files");
    env.install_files()?;
    io.say(&format!("  Installed and verified (SHA-256) in {}.", env.install_dir().display()));

    // 5. Service.
    step(io, 5, "Windows service");
    env.register_service()?;
    let started = env.start_service();
    match &started {
        Ok(()) => io.say("  Service started."),
        Err(e) => io.say(&format!("  The service did not start: {e}")),
    }

    // 6. Tray + Tailscale.
    step(io, 6, "Tray icon and Tailscale");
    let tray = env.start_tray();
    io.say(&format!("  Tray icon: {tray}"));
    io.say("");
    io.say(super::tailscale::WHY);
    io.say("");
    let ts = env.tailscale();
    for line in super::tailscale::advice(&ts) {
        io.say(&format!("  {line}"));
    }

    // Summary.
    let users = env.users();
    io.say("\n==================== Summary ====================");
    io.say(&format!("Program folder : {}", env.install_dir().display()));
    io.say(&format!("Data folder    : {} (SYSTEM + Administrators only)", env.data_dir().display()));
    io.say(&format!(
        "Service        : {}",
        if started.is_ok() { "running (starts automatically with Windows)" } else { "installed, NOT running" }
    ));
    io.say(&format!("Telegram bot   : {}", bot_label.as_deref().unwrap_or("stored token")));
    io.say(&format!("Telegram users : {}", users_line(&users)));
    io.say(&format!("Tray icon      : {tray}"));
    io.say(&format!("Tailscale      : {}", super::tailscale::summary(&ts)));
    io.say("");
    io.say("Next: open your bot in Telegram and send /menu.");
    io.say("Run this program again at any time to pair more people, list or remove users, change the");
    io.say("bot token, update to a newer version or uninstall.");
    if users.is_empty() {
        io.say("NOTE: no Telegram account is paired yet - run this program again and choose 'Pair'.");
    }
    if let Err(e) = started {
        io.say(&format!("\nThe service is installed but not running ({e}). See docs\\TROUBLESHOOTING.md."));
        return Ok(WizardEnd::Done { ok: false });
    }
    Ok(WizardEnd::Done { ok: true })
}

/// Pair; on failure offer another try or to continue without a paired account.
/// `Ok(false)` = cancelled by the user.
fn pair_with_retry(io: &mut dyn Io, env: &mut dyn WizardEnv, yes: bool) -> Result<bool, String> {
    loop {
        match env.pair_admin() {
            Ok(()) => return Ok(true),
            Err(e) => {
                io.say(&format!("  Pairing did not complete: {e}"));
                if yes {
                    return Err(e);
                }
                match ask_yes_no(io, "  Try again?", true) {
                    Some(true) => continue,
                    Some(false) => {}
                    None => return Ok(false),
                }
                return match ask_yes_no(
                    io,
                    "  Continue without a paired account? (Pair later: run this program again.)",
                    false,
                ) {
                    Some(true) => Ok(true),
                    _ => Ok(false),
                };
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::io::ScriptedIo;
    use super::*;
    use crate::config::UserRole;

    pub(crate) const TOKEN: &str = "123456789:AAFakeTokenForTestsOnly_0123456789a";

    pub(crate) fn bot() -> BotInfo {
        BotInfo { username: Some("ExampleBot".into()), name: "Example Bot".into() }
    }

    #[derive(Default)]
    struct FakeEnv {
        calls: Vec<String>,
        stored: Option<Option<String>>,
        users: Vec<AuthorizedUser>,
        pair_failures: u32,
        start_fails: bool,
        verify_fails: u32,
    }

    impl WizardEnv for FakeEnv {
        fn install_dir(&self) -> PathBuf {
            PathBuf::from(r"C:\Program Files\Predator")
        }
        fn data_dir(&self) -> PathBuf {
            PathBuf::from(r"C:\ProgramData\Predator")
        }
        fn stored_token(&mut self) -> Option<Option<String>> {
            self.stored.clone()
        }
        fn verify_token(&mut self, token: &str) -> Result<BotInfo, String> {
            self.calls.push("verify".into());
            assert_eq!(token, TOKEN, "whitespace is removed before the check");
            if self.verify_fails > 0 {
                self.verify_fails -= 1;
                return Err("Telegram rejected this token (401 Unauthorized).".into());
            }
            Ok(bot())
        }
        fn prepare_data(&mut self) -> Result<(), String> {
            self.calls.push("prepare".into());
            Ok(())
        }
        fn store_token(&mut self, token: &Secret, bot: &BotInfo) -> Result<(), String> {
            assert_eq!(token.expose(), TOKEN);
            self.calls.push(format!("store:{}", bot.label()));
            Ok(())
        }
        fn users(&mut self) -> Vec<AuthorizedUser> {
            self.users.clone()
        }
        fn pair_admin(&mut self) -> Result<(), String> {
            self.calls.push("pair".into());
            if self.pair_failures > 0 {
                self.pair_failures -= 1;
                return Err("no valid code arrived".into());
            }
            self.users.push(AuthorizedUser::new(123456789, "alice", UserRole::Admin, 1));
            Ok(())
        }
        fn add_admin(&mut self, telegram_id: i64) -> Result<(), String> {
            self.calls.push(format!("add:{telegram_id}"));
            self.users.push(AuthorizedUser::new(telegram_id, "", UserRole::Admin, 1));
            Ok(())
        }
        fn install_files(&mut self) -> Result<(), String> {
            self.calls.push("files".into());
            Ok(())
        }
        fn register_service(&mut self) -> Result<(), String> {
            self.calls.push("register".into());
            Ok(())
        }
        fn start_service(&mut self) -> Result<(), String> {
            self.calls.push("start".into());
            if self.start_fails { Err("error 1053".into()) } else { Ok(()) }
        }
        fn start_tray(&mut self) -> String {
            self.calls.push("tray".into());
            "started (not elevated)".into()
        }
        fn tailscale(&mut self) -> TailscaleStatus {
            TailscaleStatus::default()
        }
    }

    fn calls(env: &FakeEnv) -> String {
        env.calls.join(",")
    }

    #[test]
    fn full_interactive_install() {
        // install? token (with a pasted space) -> pairing succeeds.
        let mut io = ScriptedIo::new(&["", &format!(" {TOKEN} \n")]);
        let mut env = FakeEnv::default();
        let end = run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap();
        assert_eq!(end, WizardEnd::Done { ok: true });
        assert_eq!(calls(&env), "verify,prepare,store:@ExampleBot,pair,files,register,start,tray");
        let t = io.text();
        assert!(t.contains("@BotFather") && t.contains("/newbot"), "BotFather guidance");
        assert!(t.contains("Why Tailscale?") && t.contains("Run unattended"));
        assert!(t.contains("Telegram users : alice (123456789, Admin)"), "{t}");
        assert!(!t.contains("AAHYebz"), "the token never appears in the output");
    }

    #[test]
    fn cancel_paths() {
        let mut env = FakeEnv::default();
        let mut io = ScriptedIo::new(&["n"]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Cancelled);
        assert!(env.calls.is_empty(), "nothing done before the confirmation");
        // Empty token = cancel.
        let mut io = ScriptedIo::new(&["y", ""]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Cancelled);
        assert!(env.calls.is_empty());
        // End of input at the first question.
        let mut io = ScriptedIo::new(&[]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Cancelled);
    }

    #[test]
    fn bad_tokens_are_asked_again() {
        let mut env = FakeEnv { verify_fails: 1, ..Default::default() };
        let mut io = ScriptedIo::new(&["y", "not-a-token", TOKEN, TOKEN]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Done { ok: true });
        let t = io.text();
        assert!(t.contains("does not look like a bot token"));
        assert!(t.contains("401 Unauthorized"));
        // Too many attempts.
        let mut io = ScriptedIo::new(&["x", "x", "x", "x", "x"]);
        let mut verify = |_: &str| -> Result<BotInfo, String> { unreachable!() };
        assert!(ask_token(&mut io, &mut verify).unwrap_err().contains("5 attempts"));
    }

    #[test]
    fn stored_token_and_users_are_kept() {
        let mut env = FakeEnv {
            stored: Some(Some("ExampleBot".into())),
            users: vec![AuthorizedUser::new(123456789, "alice", UserRole::Admin, 1)],
            ..Default::default()
        };
        // install? keep token? pair another? -> no.
        let mut io = ScriptedIo::new(&["", "", ""]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Done { ok: true });
        assert_eq!(calls(&env), "prepare,files,register,start,tray");
        assert!(io.text().contains("Telegram bot   : @ExampleBot"));
    }

    #[test]
    fn failed_pairing_offers_retry_and_continue() {
        let mut env = FakeEnv { pair_failures: 2, ..Default::default() };
        // install, token, pair fails -> retry (fails again) -> no retry -> continue? yes
        let mut io = ScriptedIo::new(&["", TOKEN, "y", "n", "y"]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Done { ok: true });
        assert_eq!(env.calls.iter().filter(|c| *c == "pair").count(), 2);
        assert!(io.text().contains("no Telegram account is paired yet"));
        // ... or stop there.
        let mut env = FakeEnv { pair_failures: 1, ..Default::default() };
        let mut io = ScriptedIo::new(&["", TOKEN, "n", "n"]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Cancelled);
        assert!(!env.calls.contains(&"files".to_string()));
    }

    #[test]
    fn service_start_failure_is_reported() {
        let mut env = FakeEnv { start_fails: true, ..Default::default() };
        let mut io = ScriptedIo::new(&["", TOKEN]);
        assert_eq!(run_wizard(&mut io, &mut env, WizardOptions::default()).unwrap(), WizardEnd::Done { ok: false });
        assert!(io.text().contains("installed, NOT running"));
    }

    #[test]
    fn unattended_install() {
        let opts = || WizardOptions { token: Some(Secret::new(TOKEN.into())), telegram_id: Some(42), yes: true };
        let mut env = FakeEnv::default();
        let mut io = ScriptedIo::new(&[]);
        assert_eq!(run_wizard(&mut io, &mut env, opts()).unwrap(), WizardEnd::Done { ok: true });
        assert_eq!(calls(&env), "verify,prepare,store:@ExampleBot,add:42,files,register,start,tray");
        // Missing pieces are refused before anything happens.
        let mut env = FakeEnv::default();
        let no_id = WizardOptions { telegram_id: None, ..opts() };
        assert!(run_wizard(&mut io, &mut env, no_id).unwrap_err().contains("--telegram-id"));
        let no_token = WizardOptions { token: None, ..opts() };
        assert!(run_wizard(&mut io, &mut env, no_token).unwrap_err().contains("--token-file"));
        assert!(env.calls.is_empty());
        assert_eq!(unattended_problem(&WizardOptions { yes: true, ..Default::default() }, true, true), None);
        assert_eq!(unattended_problem(&WizardOptions::default(), false, false), None);
        // A broken token file is refused.
        let bad = WizardOptions { token: Some(Secret::new("garbage".into())), ..opts() };
        assert!(run_wizard(&mut io, &mut env, bad).unwrap_err().contains("token file"));
    }

    #[test]
    fn labels() {
        assert_eq!(bot().label(), "@ExampleBot");
        assert_eq!(BotInfo { username: None, name: "X".into() }.label(), "X");
        assert_eq!(clean_token(&Secret::new(" 1:a b\r\n".into())).expose(), "1:ab");
        assert_eq!(users_line(&[]), "none");
    }
}
