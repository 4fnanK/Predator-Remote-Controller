//! The management menu (service installed), written against [`Io`] and [`MenuEnv`] like the
//! wizard so every choice is tested with scripted input.

use std::path::PathBuf;

use super::super::winsec::Secret;
use super::io::{Io, ask_yes_no};
use super::wizard::{BotInfo, ask_token, clean_token};
use crate::telegram::api::is_valid_token_format;

/// What the menu header shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MenuState {
    /// `Running`, `Stopped`, ...
    pub service: String,
    pub bot: Option<String>,
    pub users: usize,
    pub install_dir: PathBuf,
    pub installed_version: Option<String>,
    /// The running program differs from the installed one (option 5 is offered).
    pub update_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MenuChoice {
    Status,
    Pair,
    Users,
    Token,
    Update,
    OpenBot,
    Uninstall,
    Exit,
}

/// Parse the typed choice. `5` exists only while an update is available.
pub(crate) fn parse_choice(input: &str, update_available: bool) -> Option<MenuChoice> {
    Some(match input.trim() {
        "1" => MenuChoice::Status,
        "2" => MenuChoice::Pair,
        "3" => MenuChoice::Users,
        "4" => MenuChoice::Token,
        "5" if update_available => MenuChoice::Update,
        "6" => MenuChoice::OpenBot,
        "7" => MenuChoice::Uninstall,
        "0" | "q" | "Q" | "exit" => MenuChoice::Exit,
        _ => return None,
    })
}

/// Header and options.
pub(crate) fn menu_text(st: &MenuState) -> String {
    let mut s = format!("\n{} {} - installed\n", crate::PRODUCT_NAME, crate::VERSION);
    let bot = st.bot.as_deref().map(|b| format!("@{b}")).unwrap_or_else(|| "unknown".into());
    s.push_str(&format!("  Service: {} | Bot: {bot} | Telegram users: {}\n", st.service, st.users));
    let version = st.installed_version.as_deref().map(|v| format!(" (version {v})")).unwrap_or_default();
    s.push_str(&format!("  Installed in {}{version}\n\n", st.install_dir.display()));
    s.push_str("  1  Status\n");
    s.push_str("  2  Pair a Telegram user\n");
    s.push_str("  3  Telegram users (list / remove)\n");
    s.push_str("  4  Change bot token\n");
    if st.update_available {
        s.push_str(&format!("  5  Update installed program to this version ({})\n", crate::VERSION));
    }
    s.push_str("  6  Open the bot in Telegram\n");
    s.push_str("  7  Uninstall\n");
    s.push_str("  0  Exit");
    s
}

/// A numeric Telegram user id (positive).
pub(crate) fn parse_user_id(input: &str) -> Option<i64> {
    input.trim().parse::<i64>().ok().filter(|id| *id > 0)
}

/// Everything the menu does to the machine.
pub(crate) trait MenuEnv {
    fn state(&mut self) -> MenuState;
    fn status(&mut self) -> Result<(), String>;
    fn pair(&mut self, admin: bool) -> Result<(), String>;
    fn list_users(&mut self) -> Result<(), String>;
    fn remove_user(&mut self, id: i64) -> Result<(), String>;
    fn add_admin(&mut self, id: i64) -> Result<(), String>;
    fn verify_token(&mut self, token: &str) -> Result<BotInfo, String>;
    fn store_token(&mut self, token: &Secret, bot: &BotInfo) -> Result<(), String>;
    fn service_running(&mut self) -> bool;
    fn restart_service(&mut self) -> Result<(), String>;
    fn update(&mut self) -> Result<(), String>;
    /// Open the bot chat in the user's browser; returns the link.
    fn open_bot(&mut self) -> Result<String, String>;
    /// `Ok(None)` = removed; `Ok(Some(problem))` = the service is gone but a later step failed
    /// (e.g. the audit policy was not restored); `Err` = the service is still installed.
    fn uninstall(&mut self, purge_data: bool) -> Result<Option<String>, String>;
}

/// How the menu was left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MenuExit {
    /// 0 / Exit, or end of input.
    Exit,
    /// The program was uninstalled (the window should stay open so the result can be read).
    Uninstalled,
}

/// Show the menu until Exit, end of input or a completed uninstall.
pub(crate) fn run_menu(io: &mut dyn Io, env: &mut dyn MenuEnv) -> MenuExit {
    loop {
        let st = env.state();
        io.say(&menu_text(&st));
        let Some(answer) = io.ask("\nChoose an option: ") else { return MenuExit::Exit };
        let Some(choice) = parse_choice(&answer, st.update_available) else {
            io.say("  Please type one of the numbers shown.");
            continue;
        };
        let result = match choice {
            MenuChoice::Exit => return MenuExit::Exit,
            MenuChoice::Status => env.status(),
            MenuChoice::Pair => pair(io, env),
            MenuChoice::Users => users(io, env),
            MenuChoice::Token => change_token(io, env),
            MenuChoice::Update => update(io, env),
            MenuChoice::OpenBot => env.open_bot().map(|link| io.say(&format!("  Opened {link}"))),
            MenuChoice::Uninstall => match uninstall(io, env) {
                Ok(true) => return MenuExit::Uninstalled,
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            },
        };
        if let Err(e) = result {
            io.say(&format!("  ERROR: {e}"));
        }
    }
}

fn pair(io: &mut dyn Io, env: &mut dyn MenuEnv) -> Result<(), String> {
    io.say("  A one-time code is shown. The person sends /pair CODE to the bot in a private chat (or opens");
    io.say("  the link), and gets access. The code expires after 10 minutes and works only once.");
    let Some(admin) = ask_yes_no(io, "  Make this account an Admin (can also remove users)?", false) else {
        return Ok(());
    };
    env.pair(admin)
}

fn users(io: &mut dyn Io, env: &mut dyn MenuEnv) -> Result<(), String> {
    env.list_users()?;
    let Some(answer) = io.ask("\n  Type a user id to remove that account, or press Enter to go back: ") else {
        return Ok(());
    };
    if answer.trim().is_empty() {
        return Ok(());
    }
    let id = parse_user_id(&answer).ok_or_else(|| format!("'{}' is not a numeric Telegram user id", answer.trim()))?;
    if ask_yes_no(io, &format!("  Remove Telegram user {id}? It loses access immediately."), false) != Some(true) {
        return Ok(());
    }
    env.remove_user(id)
}

fn change_token(io: &mut dyn Io, env: &mut dyn MenuEnv) -> Result<(), String> {
    io.say("  Paired users stay authorized. With a token of a DIFFERENT bot, everyone must open the new");
    io.say("  bot and press Start once, otherwise Telegram cannot deliver its messages.");
    let mut verify = |t: &str| env.verify_token(t);
    let Some((token, bot)) = ask_token(io, &mut verify)? else { return Ok(()) };
    env.store_token(&token, &bot)?;
    drop(token);
    io.say(&format!("  Token stored for {}.", bot.label()));
    if env.service_running() {
        if ask_yes_no(io, "  Restart the service now so it uses the new token?", true) == Some(true) {
            env.restart_service()?;
            io.say("  Service restarted.");
        } else {
            io.say("  The service keeps the previous token until it restarts.");
        }
    }
    Ok(())
}

fn update(io: &mut dyn Io, env: &mut dyn MenuEnv) -> Result<(), String> {
    io.say(&format!("  The service and the tray icon stop for a few seconds, then version {} starts.", crate::VERSION));
    if ask_yes_no(io, "  Update now?", true) != Some(true) {
        return Ok(());
    }
    env.update()?;
    io.say("  Update complete.");
    Ok(())
}

/// `Ok(true)` = uninstalled (the menu ends).
fn uninstall(io: &mut dyn Io, env: &mut dyn MenuEnv) -> Result<bool, String> {
    io.say("  This removes the service, the tray icon and its autostart and the program files, and");
    io.say("  restores the original logon audit policy.");
    if ask_yes_no(io, "  Uninstall Predator Remote Controller?", false) != Some(true) {
        return Ok(false);
    }
    let Some(purge) = ask_yes_no(
        io,
        "  Also delete the data folder (bot token, Telegram users, settings, logs)? Keep it to reinstall later.",
        false,
    ) else {
        return Ok(false);
    };
    match env.uninstall(purge)? {
        None => io.say("  Predator Remote Controller was removed."),
        // The service is gone, so the menu (which manages it) ends either way.
        Some(problem) => {
            io.say(&format!("  WARNING: {problem}"));
            io.say("  Predator Remote Controller was removed, but see the warning above.");
        }
    }
    Ok(true)
}

/// `--yes` on an installed PC: update when this program is newer/different, then apply
/// `--token-file` and `--telegram-id`, then show the status. Never asks anything.
pub(crate) fn run_unattended(
    io: &mut dyn Io,
    env: &mut dyn MenuEnv,
    token: Option<Secret>,
    telegram_id: Option<i64>,
) -> Result<(), String> {
    let st = env.state();
    if st.update_available {
        io.say(&format!("Updating the installed program to version {}...", crate::VERSION));
        env.update()?;
    }
    if let Some(token) = token {
        let token = clean_token(&token);
        if !is_valid_token_format(token.expose()) {
            return Err("The token file does not contain a valid bot token (123456789:AAH...).".into());
        }
        let bot = env.verify_token(token.expose())?;
        env.store_token(&token, &bot)?;
        io.say(&format!("Token stored for {}.", bot.label()));
        if env.service_running() {
            env.restart_service()?;
            io.say("Service restarted.");
        }
    }
    if let Some(id) = telegram_id {
        env.add_admin(id)?;
        io.say(&format!("Telegram user {id} is authorized (Admin)."));
    }
    env.status()
}

#[cfg(test)]
mod tests {
    use super::super::io::ScriptedIo;
    use super::super::wizard::tests::{TOKEN, bot};
    use super::*;

    #[derive(Default)]
    struct FakeMenu {
        calls: Vec<String>,
        update_available: bool,
        running: bool,
        fail_remove: bool,
        /// `Some(Ok(problem))` = removed with a problem; `Some(Err(e))` = not removed.
        uninstall_result: Option<Result<String, String>>,
    }

    impl MenuEnv for FakeMenu {
        fn state(&mut self) -> MenuState {
            MenuState {
                service: "Running".into(),
                bot: Some("ExampleBot".into()),
                users: 1,
                install_dir: PathBuf::from(r"C:\Program Files\Predator"),
                installed_version: Some("1.0.0".into()),
                update_available: self.update_available,
            }
        }
        fn status(&mut self) -> Result<(), String> {
            self.calls.push("status".into());
            Ok(())
        }
        fn pair(&mut self, admin: bool) -> Result<(), String> {
            self.calls.push(format!("pair:{admin}"));
            Ok(())
        }
        fn list_users(&mut self) -> Result<(), String> {
            self.calls.push("list".into());
            Ok(())
        }
        fn remove_user(&mut self, id: i64) -> Result<(), String> {
            self.calls.push(format!("remove:{id}"));
            if self.fail_remove { Err(crate::config::LAST_ADMIN_ERROR.into()) } else { Ok(()) }
        }
        fn add_admin(&mut self, id: i64) -> Result<(), String> {
            self.calls.push(format!("add:{id}"));
            Ok(())
        }
        fn verify_token(&mut self, _token: &str) -> Result<BotInfo, String> {
            self.calls.push("verify".into());
            Ok(bot())
        }
        fn store_token(&mut self, token: &Secret, _bot: &BotInfo) -> Result<(), String> {
            assert_eq!(token.expose(), TOKEN);
            self.calls.push("store".into());
            Ok(())
        }
        fn service_running(&mut self) -> bool {
            self.running
        }
        fn restart_service(&mut self) -> Result<(), String> {
            self.calls.push("restart".into());
            Ok(())
        }
        fn update(&mut self) -> Result<(), String> {
            self.calls.push("update".into());
            Ok(())
        }
        fn open_bot(&mut self) -> Result<String, String> {
            self.calls.push("open".into());
            Ok("https://t.me/ExampleBot".into())
        }
        fn uninstall(&mut self, purge_data: bool) -> Result<Option<String>, String> {
            self.calls.push(format!("uninstall:{purge_data}"));
            match self.uninstall_result.clone() {
                None => Ok(None),
                Some(Ok(problem)) => Ok(Some(problem)),
                Some(Err(e)) => Err(e),
            }
        }
    }

    #[test]
    fn choices() {
        assert_eq!(parse_choice(" 1 ", false), Some(MenuChoice::Status));
        assert_eq!(parse_choice("5", false), None, "no update offered");
        assert_eq!(parse_choice("5", true), Some(MenuChoice::Update));
        assert_eq!(parse_choice("0", false), Some(MenuChoice::Exit));
        assert_eq!(parse_choice("9", true), None);
        assert_eq!(parse_choice("", true), None);
        assert_eq!(parse_user_id(" 123456789 "), Some(123456789));
        assert_eq!(parse_user_id("-5"), None);
        assert_eq!(parse_user_id("abc"), None);
        let st = MenuState { update_available: false, ..Default::default() };
        assert!(!menu_text(&st).contains("  5  "));
        let st = MenuState { update_available: true, ..Default::default() };
        let t = menu_text(&st);
        for item in ["1  Status", "2  Pair", "3  Telegram users", "4  Change bot token", "5  Update", "6  Open the bot"]
        {
            assert!(t.contains(item), "{item}");
        }
        assert!(t.contains("7  Uninstall") && t.contains("0  Exit"));
    }

    #[test]
    fn menu_actions() {
        let mut env = FakeMenu { running: true, ..Default::default() };
        let mut io = ScriptedIo::new(&[
            "1", // status
            "2",
            "y", // pair as admin
            "3",
            "123456789",
            "y", // remove a user
            "3",
            "", // list only
            "4",
            TOKEN,
            "",  // token + restart
            "6", // open bot
            "5", // not offered -> retry message
            "x",
            "0",
        ]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Exit);
        assert_eq!(env.calls.join(","), "status,pair:true,list,remove:123456789,list,verify,store,restart,open");
        assert!(io.text().contains("Please type one of the numbers shown."));
        assert!(!io.text().contains("AAHYebz"));
    }

    #[test]
    fn errors_are_shown_and_the_menu_continues() {
        let mut env = FakeMenu { fail_remove: true, ..Default::default() };
        let mut io = ScriptedIo::new(&["3", "123456789", "y", "3", "abc", "0"]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Exit);
        let t = io.text();
        assert!(t.contains("ERROR: The last admin cannot be removed"), "{t}");
        assert!(t.contains("is not a numeric Telegram user id"));
    }

    #[test]
    fn update_and_uninstall() {
        let mut env = FakeMenu { update_available: true, ..Default::default() };
        let mut io = ScriptedIo::new(&["5", "", "7", "n", "7", "y", "y"]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Uninstalled);
        assert_eq!(env.calls.join(","), "update,uninstall:true");
        assert!(io.text().contains("was removed"));
        // End of input leaves the menu.
        let mut io = ScriptedIo::new(&[]);
        assert_eq!(run_menu(&mut io, &mut FakeMenu::default()), MenuExit::Exit);
    }

    #[test]
    fn uninstall_with_problems_or_failure() {
        // Removed, but the audit policy was not restored: the menu ends and says so.
        let mut env = FakeMenu { uninstall_result: Some(Ok("audit policy NOT restored".into())), ..Default::default() };
        let mut io = ScriptedIo::new(&["7", "y", "n"]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Uninstalled);
        let t = io.text();
        assert!(t.contains("WARNING: audit policy NOT restored") && t.contains("see the warning above"), "{t}");
        // The service could not be removed: an error, and the menu stays.
        let mut env =
            FakeMenu { uninstall_result: Some(Err("Cannot delete the service".into())), ..Default::default() };
        let mut io = ScriptedIo::new(&["7", "y", "n", "0"]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Exit);
        let t = io.text();
        assert!(t.contains("ERROR: Cannot delete the service") && !t.contains("was removed"), "{t}");
        // Declined, or no answer to the data question: nothing happens.
        let mut env = FakeMenu::default();
        let mut io = ScriptedIo::new(&["7", "n", "7", "y"]);
        assert_eq!(run_menu(&mut io, &mut env), MenuExit::Exit);
        assert!(env.calls.is_empty(), "{:?}", env.calls);
    }

    #[test]
    fn unattended_management() {
        let mut env = FakeMenu { update_available: true, running: true, ..Default::default() };
        let mut io = ScriptedIo::new(&[]);
        run_unattended(&mut io, &mut env, Some(Secret::new(format!("{TOKEN}\n"))), Some(42)).unwrap();
        assert_eq!(env.calls.join(","), "update,verify,store,restart,add:42,status");
        let mut env = FakeMenu::default();
        run_unattended(&mut io, &mut env, None, None).unwrap();
        assert_eq!(env.calls.join(","), "status");
        assert!(run_unattended(&mut io, &mut env, Some(Secret::new("bad".into())), None).is_err());
    }
}
