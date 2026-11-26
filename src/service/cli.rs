//! Command-line parsing (pure, unit-tested) and usage text.

use std::path::PathBuf;

/// Where `set-token` reads the token from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TokenInput {
    File(PathBuf),
    Stdin,
    Prompt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnerSid {
    User(String),
    Sid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FeatureCmd {
    List,
    Enable(String),
    Disable(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditCmd {
    Status,
    Enable,
    Restore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UsersCmd {
    List,
    Remove(i64),
}

/// Options of `setup` (also used for a start without arguments).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SetupOptions {
    /// Text file with the bot token (instead of the hidden prompt).
    pub token_file: Option<PathBuf>,
    /// Authorize this Telegram user id as Admin (instead of interactive pairing).
    pub telegram_id: Option<i64>,
    /// Never ask: take the defaults (needs `--token-file` and `--telegram-id` on a new install).
    pub yes: bool,
    /// Internal: SID of the account that started setup before the elevation (the tray owner).
    pub invoking_sid: Option<String>,
    /// `--verbose` (passed on to the elevated copy).
    pub verbose: bool,
}

/// Default lifetime of a pairing code (seconds).
pub(crate) const PAIR_TTL_DEFAULT: u64 = 600;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct ConsoleOptions {
    pub token_file: Option<PathBuf>,
    pub stdin_commands: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// No arguments: run under the SCM; when started outside it (double-click), interactive
    /// setup.
    Default,
    /// `service`: run under the SCM (prints the usage when started outside it).
    RunService,
    /// Setup wizard (not installed) or management menu (installed); elevates itself.
    Setup(SetupOptions),
    Help,
    Version,
    Install {
        start: bool,
    },
    Uninstall {
        keep_audit_policy: bool,
        purge_data: bool,
    },
    Start,
    Stop,
    Status,
    SetToken {
        input: TokenInput,
        verify: bool,
    },
    Pair {
        admin: bool,
        ttl_secs: u64,
    },
    Users(UsersCmd),
    SetOwner {
        telegram_id: i64,
    },
    SetOwnerSid(OwnerSid),
    Features(FeatureCmd),
    Audit(AuditCmd),
    Selftest {
        tailscale: bool,
    },
    Console(ConsoleOptions),
    RestartHelper,
    /// Internal (not in the usage text): resolve the Wi-Fi SSID in a short-lived child process
    /// and print one JSON line (keeps COM/WinRT out of the service process).
    SsidHelper,
    /// Internal diagnostic (not in the usage text): write the embedded tray program to a new
    /// file and verify it (used by scripts/build.ps1).
    ExtractTray(PathBuf),
}

/// A parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub command: Command,
    pub data_dir: Option<PathBuf>,
    pub verbose: bool,
}

/// Simple option scanner: `--name value`, `--name=value`, flags and positionals.
struct Args {
    items: Vec<String>,
    pos: usize,
    command: String,
}

impl Args {
    fn next(&mut self) -> Option<String> {
        let v = self.items.get(self.pos).cloned();
        if v.is_some() {
            self.pos += 1;
        }
        v
    }

    fn value(&mut self, flag: &str, inline: Option<String>) -> Result<String, String> {
        if let Some(v) = inline {
            return if v.is_empty() { Err(format!("'{flag}' needs a value")) } else { Ok(v) };
        }
        match self.next() {
            Some(v) if !v.starts_with("--") => Ok(v),
            _ => Err(format!("'{flag}' needs a value (see 'predator-service help')")),
        }
    }

    fn unknown(&self, arg: &str) -> String {
        if arg.starts_with('-') {
            format!("unknown option '{arg}' for '{}' (see 'predator-service help')", self.command)
        } else {
            format!("unexpected argument '{arg}' for '{}' (see 'predator-service help')", self.command)
        }
    }
}

fn split_flag(arg: &str) -> (String, Option<String>) {
    match arg.split_once('=') {
        Some((k, v)) if arg.starts_with("--") => (k.to_ascii_lowercase(), Some(v.to_string())),
        _ => (arg.to_ascii_lowercase(), None),
    }
}

/// Parse the process arguments (without the program name).
pub(crate) fn parse(argv: &[String]) -> Result<Invocation, String> {
    let Some(first) = argv.first() else {
        return Ok(Invocation { command: Command::Default, data_dir: None, verbose: false });
    };
    let cmd = first.trim().to_ascii_lowercase();
    let cmd = match cmd.as_str() {
        "-h" | "--help" | "/?" | "-?" | "/h" => "help".to_string(),
        "-v" | "--version" => "version".to_string(),
        _ => cmd,
    };
    let mut a = Args { items: argv[1..].to_vec(), pos: 0, command: cmd.clone() };
    let mut data_dir: Option<PathBuf> = None;
    let mut verbose = false;

    // command-specific state
    let mut start = false;
    let mut keep_audit = false;
    let mut purge = false;
    let mut token_file: Option<PathBuf> = None;
    let mut token_stdin = false;
    let mut verify = true;
    let mut ttl_secs: u64 = PAIR_TTL_DEFAULT;
    let mut admin = false;
    let mut yes = false;
    let mut invoking_sid: Option<String> = None;
    let mut telegram_id: Option<i64> = None;
    let mut user: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut tailscale = false;
    let mut stdin_commands = false;
    let mut positionals: Vec<String> = Vec::new();

    while let Some(raw) = a.next() {
        let (flag, inline) = split_flag(&raw);
        match flag.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(a.value("--data-dir", inline)?)),
            "--verbose" | "-v" => verbose = true,
            "--start" if cmd == "install" => start = true,
            "--keep-audit-policy" if cmd == "uninstall" => keep_audit = true,
            "--purge-data" if cmd == "uninstall" => purge = true,
            "--file" if cmd == "set-token" => token_file = Some(PathBuf::from(a.value("--file", inline)?)),
            "--stdin" if cmd == "set-token" => token_stdin = true,
            "--no-verify" if cmd == "set-token" => verify = false,
            "--ttl" if cmd == "pair" => {
                let v = a.value("--ttl", inline)?;
                ttl_secs = v
                    .parse::<u64>()
                    .ok()
                    .filter(|t| (60..=3600).contains(t))
                    .ok_or_else(|| format!("--ttl must be a number of seconds between 60 and 3600 (got '{v}')"))?;
            }
            // Older name of --ttl (it accepted 30..=3600; codes live at least 60 s now).
            "--timeout" if cmd == "pair" => {
                let v = a.value("--timeout", inline)?;
                ttl_secs =
                    v.parse::<u64>().ok().filter(|t| (30..=3600).contains(t)).map(|t| t.max(60)).ok_or_else(|| {
                        format!("--timeout must be a number of seconds between 30 and 3600 (got '{v}')")
                    })?;
            }
            "--admin" if cmd == "pair" => admin = true,
            // Accepted for older scripts: pairing goes through the running service now.
            "--force" if cmd == "pair" => {}
            "--yes" | "-y" if cmd == "setup" => yes = true,
            "--invoking-sid" if cmd == "setup" => invoking_sid = Some(a.value("--invoking-sid", inline)?),
            "--telegram-id" if cmd == "set-owner" || cmd == "setup" => {
                let v = a.value("--telegram-id", inline)?;
                telegram_id =
                    Some(v.trim().parse::<i64>().ok().filter(|id| *id > 0).ok_or_else(|| {
                        format!("--telegram-id must be a positive numeric Telegram user id (got '{v}')")
                    })?);
            }
            "--user" if cmd == "set-owner-sid" => user = Some(a.value("--user", inline)?),
            "--sid" if cmd == "set-owner-sid" => sid = Some(a.value("--sid", inline)?),
            "--tailscale" if cmd == "selftest" => tailscale = true,
            "--token-file" if cmd == "console" || cmd == "setup" => {
                token_file = Some(PathBuf::from(a.value("--token-file", inline)?))
            }
            // console mode is always dry-run; the flag is accepted for clarity
            "--dry-run" if cmd == "console" => {}
            "--stdin-commands" if cmd == "console" => stdin_commands = true,
            _ if !raw.starts_with('-') && matches!(cmd.as_str(), "features" | "audit" | "users" | "extract-tray") => {
                positionals.push(raw)
            }
            _ => return Err(a.unknown(&raw)),
        }
    }

    let command = match cmd.as_str() {
        "service" => Command::RunService,
        "setup" => Command::Setup(SetupOptions { token_file, telegram_id, yes, invoking_sid, verbose }),
        "help" => Command::Help,
        "version" => Command::Version,
        "install" => Command::Install { start },
        "uninstall" => Command::Uninstall { keep_audit_policy: keep_audit, purge_data: purge },
        "start" => Command::Start,
        "stop" => Command::Stop,
        "status" => Command::Status,
        "set-token" => {
            let input = match (token_file, token_stdin) {
                (Some(_), true) => return Err("use either --file or --stdin, not both".into()),
                (Some(f), false) => TokenInput::File(f),
                (None, true) => TokenInput::Stdin,
                (None, false) => TokenInput::Prompt,
            };
            Command::SetToken { input, verify }
        }
        "pair" => Command::Pair { admin, ttl_secs },
        "users" => {
            let p: Vec<&str> = positionals.iter().map(String::as_str).collect();
            Command::Users(match p.as_slice() {
                [] | ["list"] => UsersCmd::List,
                ["remove", id] => {
                    UsersCmd::Remove(id.trim().parse::<i64>().ok().filter(|i| *i > 0).ok_or_else(|| {
                        format!("users remove needs a positive numeric Telegram user id (got '{id}')")
                    })?)
                }
                ["remove"] => return Err("users remove needs the numeric Telegram user id (see 'users list')".into()),
                _ => return Err("usage: users [list | remove ID]".into()),
            })
        }
        "set-owner" => Command::SetOwner {
            telegram_id: telegram_id.ok_or("set-owner needs --telegram-id ID (your numeric Telegram user id)")?,
        },
        "set-owner-sid" => match (user, sid) {
            (Some(u), None) => Command::SetOwnerSid(OwnerSid::User(u)),
            (None, Some(s)) => Command::SetOwnerSid(OwnerSid::Sid(s)),
            _ => return Err("set-owner-sid needs exactly one of --user NAME or --sid SID".into()),
        },
        "features" => {
            let p: Vec<&str> = positionals.iter().map(String::as_str).collect();
            Command::Features(match p.as_slice() {
                [] | ["list"] => FeatureCmd::List,
                ["enable", key] => FeatureCmd::Enable(key.to_string()),
                ["disable", key] => FeatureCmd::Disable(key.to_string()),
                ["enable" | "disable"] => return Err("features enable/disable needs a feature KEY".into()),
                _ => return Err("usage: features [list | enable KEY | disable KEY]".into()),
            })
        }
        "audit" => {
            let p: Vec<String> = positionals.iter().map(|s| s.to_ascii_lowercase()).collect();
            Command::Audit(match p.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [] | ["status"] => AuditCmd::Status,
                ["enable"] => AuditCmd::Enable,
                ["restore"] => AuditCmd::Restore,
                _ => return Err("usage: audit (status | enable | restore)".into()),
            })
        }
        "selftest" => Command::Selftest { tailscale },
        "console" => Command::Console(ConsoleOptions { token_file, stdin_commands }),
        "restart-helper" => Command::RestartHelper,
        "ssid-helper" => Command::SsidHelper,
        "extract-tray" => match positionals.as_slice() {
            [path] => Command::ExtractTray(PathBuf::from(path)),
            _ => return Err("usage: extract-tray PATH".into()),
        },
        other => return Err(format!("unknown command '{other}' (see 'predator-service help')")),
    };
    Ok(Invocation { command, data_dir, verbose })
}

/// Full usage text.
pub(crate) fn usage() -> String {
    let keys: Vec<&str> = crate::features::Feature::ALL.iter().map(|f| f.key()).collect();
    format!(
        "{product} {version} — Windows service and management tool

USAGE
  PredatorRemoteController.exe                (no arguments: setup wizard / management menu)
  predator-service.exe <command> [options]    (the installed copy of the same program)

GETTING STARTED
  Start the program without arguments (double-click it). It asks for administrator rights and
  then installs everything step by step: bot token, pairing of your Telegram account, program
  files, service, tray icon, Tailscale check. Once installed, the same start opens the menu:
  status, pair a Telegram user, list/remove users, change the token, update, uninstall.
  setup [--token-file F] [--telegram-id ID] [--yes]
                              The same from a prompt. --yes never asks (scripted installs; a new
                              install then needs --token-file and --telegram-id; an installed
                              one is updated to this version and gets the given token/user)

TELEGRAM USERS (while the service runs, the tray owner may pair User accounts and list them;
                everything else needs Administrator)
  pair [--admin] [--ttl SECS] One-time 8-digit code (valid SECS = 60..3600, default {ttl} s).
                              The person sends /pair CODE to the bot (or opens the link shown)
                              and may then use it; --admin also lets them remove users
  users [list | remove ID]    Authorized Telegram accounts; remove revokes access at once
  set-owner --telegram-id ID  Replace ALL authorized accounts by this one (Admin)

SERVICE (Administrator)
  install [--start]           Register or update the service from the folder of this exe, secure
                              the data directory, enable logon auditing and the tray autostart
  uninstall [--keep-audit-policy] [--purge-data]
                              Stop and remove the service and the tray autostart; restores the
                              original audit policy unless --keep-audit-policy (the menu's
                              Uninstall also deletes the program files)
  start | stop                Start / stop the service
  status                      Service state and runtime details

SETTINGS (Administrator)
  set-token [--file PATH | --stdin] [--no-verify]
                              Store the Telegram bot token, encrypted with DPAPI. Without options
                              it is typed into a hidden prompt. The token is checked with getMe
  set-owner-sid (--user NAME | --sid SID)
                              Windows account allowed to use the tray controls
  features [list | enable KEY | disable KEY]
  audit (status | enable | restore)
                              Windows logon audit policy needed for login alerts

DIAGNOSTICS
  selftest [--tailscale]      Read-only health report (--tailscale also queries Tailscale)
  console [--token-file F] [--stdin-commands] [--dry-run]
                              Run the service in the foreground (Ctrl+C or end of input stops).
                              Console mode ALWAYS simulates power/lock/logout/Tailscale up+down.
                              --stdin-commands: each input line is sent to the bot as a message
                              from the first authorized user (e.g. /status) or a button press
                              (cb:nav:feat)
  version | help

COMMON OPTIONS
  --data-dir DIR              Use DIR instead of %ProgramData%\\Predator (not for setup, install,
                              uninstall, start, stop)
  --verbose, -v               Debug output

FEATURE KEYS
  {keys}
",
        product = crate::PRODUCT_NAME,
        version = crate::VERSION,
        ttl = PAIR_TTL_DEFAULT,
        keys = keys.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Invocation, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn cmd(args: &[&str]) -> Command {
        p(args).unwrap().command
    }

    #[test]
    fn basics() {
        assert_eq!(cmd(&[]), Command::Default);
        assert_eq!(cmd(&["service"]), Command::RunService);
        assert_eq!(cmd(&["--help"]), Command::Help);
        assert_eq!(cmd(&["/?"]), Command::Help);
        assert_eq!(cmd(&["HELP"]), Command::Help);
        assert_eq!(cmd(&["--version"]), Command::Version);
        assert_eq!(cmd(&["install"]), Command::Install { start: false });
        assert_eq!(cmd(&["install", "--start"]), Command::Install { start: true });
        assert_eq!(
            cmd(&["uninstall", "--purge-data"]),
            Command::Uninstall { keep_audit_policy: false, purge_data: true }
        );
        assert_eq!(cmd(&["restart-helper", "--data-dir", "C:\\x"]), Command::RestartHelper);
        assert_eq!(cmd(&["ssid-helper"]), Command::SsidHelper);
        assert!(p(&["ssid-helper", "extra"]).is_err());
        assert!(!usage().contains("ssid-helper"), "internal command stays out of the usage text");
        assert!(!usage().contains("extract-tray"), "internal command stays out of the usage text");
        assert!(!usage().contains("invoking-sid"), "internal option stays out of the usage text");
        assert!(p(&["frobnicate"]).unwrap_err().contains("unknown command"));
        assert!(p(&["install", "--purge-data"]).unwrap_err().contains("unknown option"));
        assert!(p(&["start", "extra"]).unwrap_err().contains("unexpected argument"));
    }

    #[test]
    fn global_options() {
        let i = p(&["selftest", "--data-dir", r"D:\tmp\p", "-v", "--tailscale"]).unwrap();
        assert_eq!(i.data_dir, Some(PathBuf::from(r"D:\tmp\p")));
        assert!(i.verbose);
        assert_eq!(i.command, Command::Selftest { tailscale: true });
        let i = p(&["status", "--data-dir=E:\\d"]).unwrap();
        assert_eq!(i.data_dir, Some(PathBuf::from("E:\\d")));
        assert!(p(&["status", "--data-dir"]).is_err());
        assert!(p(&["status", "--data-dir", "--verbose"]).is_err());
    }

    #[test]
    fn set_token_and_owner() {
        assert_eq!(cmd(&["set-token"]), Command::SetToken { input: TokenInput::Prompt, verify: true });
        assert_eq!(
            cmd(&["set-token", "--stdin", "--no-verify"]),
            Command::SetToken { input: TokenInput::Stdin, verify: false }
        );
        assert_eq!(
            cmd(&["set-token", "--file", "t.txt"]),
            Command::SetToken { input: TokenInput::File("t.txt".into()), verify: true }
        );
        assert!(p(&["set-token", "--file", "a", "--stdin"]).is_err());
        assert_eq!(cmd(&["set-owner", "--telegram-id", "123456789"]), Command::SetOwner { telegram_id: 123456789 });
        assert!(p(&["set-owner"]).is_err());
        assert!(p(&["set-owner", "--telegram-id", "-5"]).is_err());
        assert!(p(&["set-owner", "--telegram-id", "abc"]).is_err());
        assert_eq!(cmd(&["set-owner-sid", "--user", "alice"]), Command::SetOwnerSid(OwnerSid::User("alice".into())));
        assert_eq!(
            cmd(&["set-owner-sid", "--sid=S-1-5-21-1-2-3-1001"]),
            Command::SetOwnerSid(OwnerSid::Sid("S-1-5-21-1-2-3-1001".into()))
        );
        assert!(p(&["set-owner-sid"]).is_err());
        assert!(p(&["set-owner-sid", "--user", "a", "--sid", "S-1-5-18"]).is_err());
    }

    #[test]
    fn pair_features_audit_console() {
        assert_eq!(cmd(&["pair"]), Command::Pair { admin: false, ttl_secs: 600 });
        assert_eq!(cmd(&["pair", "--admin", "--ttl", "120"]), Command::Pair { admin: true, ttl_secs: 120 });
        assert_eq!(cmd(&["pair", "--ttl=3600"]), Command::Pair { admin: false, ttl_secs: 3600 });
        assert!(p(&["pair", "--ttl", "59"]).is_err());
        assert!(p(&["pair", "--ttl", "3601"]).is_err());
        // Older options keep working: --timeout (at least 60 s now), --force (ignored).
        assert_eq!(cmd(&["pair", "--timeout", "30", "--force"]), Command::Pair { admin: false, ttl_secs: 60 });
        assert_eq!(cmd(&["pair", "--timeout", "120"]), Command::Pair { admin: false, ttl_secs: 120 });
        assert!(p(&["pair", "--timeout", "5"]).is_err());
        assert!(p(&["pair", "--yes"]).is_err());
        assert_eq!(cmd(&["users"]), Command::Users(UsersCmd::List));
        assert_eq!(cmd(&["users", "list"]), Command::Users(UsersCmd::List));
        assert_eq!(cmd(&["users", "remove", "123456789"]), Command::Users(UsersCmd::Remove(123456789)));
        assert!(p(&["users", "remove"]).is_err());
        assert!(p(&["users", "remove", "-1"]).is_err());
        assert!(p(&["users", "remove", "bob"]).is_err());
        assert!(p(&["users", "add", "1"]).is_err());
        assert_eq!(cmd(&["features"]), Command::Features(FeatureCmd::List));
        assert_eq!(cmd(&["features", "list"]), Command::Features(FeatureCmd::List));
        assert_eq!(
            cmd(&["features", "disable", "ssh_monitoring"]),
            Command::Features(FeatureCmd::Disable("ssh_monitoring".into()))
        );
        assert_eq!(
            cmd(&["features", "enable", "battery_info"]),
            Command::Features(FeatureCmd::Enable("battery_info".into()))
        );
        assert!(p(&["features", "enable"]).is_err());
        assert!(p(&["features", "toggle", "x"]).is_err());
        assert_eq!(cmd(&["audit"]), Command::Audit(AuditCmd::Status));
        assert_eq!(cmd(&["audit", "ENABLE"]), Command::Audit(AuditCmd::Enable));
        assert_eq!(cmd(&["audit", "restore"]), Command::Audit(AuditCmd::Restore));
        assert!(p(&["audit", "wipe"]).is_err());
        assert_eq!(
            cmd(&["console", "--dry-run", "--stdin-commands", "--token-file", "tok.txt"]),
            Command::Console(ConsoleOptions { token_file: Some("tok.txt".into()), stdin_commands: true })
        );
        assert!(usage().contains("set-owner-sid"));
        assert!(usage().contains("ssh_monitoring"));
        for item in ["setup [--token-file F]", "pair [--admin] [--ttl SECS]", "users [list | remove ID]"] {
            assert!(usage().contains(item), "{item}");
        }
        assert!(usage().contains(r"%ProgramData%\Predator"));
    }

    #[test]
    fn setup_and_diagnostics() {
        assert_eq!(cmd(&["setup"]), Command::Setup(SetupOptions::default()));
        let i = p(&[
            "setup",
            "--token-file",
            r"C:\t.txt",
            "--telegram-id=123456789",
            "--yes",
            "--invoking-sid",
            "S-1-5-21-1-2-3-1001",
            "-v",
        ])
        .unwrap();
        assert_eq!(
            i.command,
            Command::Setup(SetupOptions {
                token_file: Some(r"C:\t.txt".into()),
                telegram_id: Some(123456789),
                yes: true,
                invoking_sid: Some("S-1-5-21-1-2-3-1001".into()),
                verbose: true,
            })
        );
        assert_eq!(cmd(&["SETUP", "-y"]), Command::Setup(SetupOptions { yes: true, ..Default::default() }));
        assert!(p(&["setup", "--telegram-id", "0"]).is_err());
        assert!(p(&["setup", "--start"]).unwrap_err().contains("unknown option"));
        assert!(p(&["setup", "extra"]).unwrap_err().contains("unexpected argument"));
        assert_eq!(cmd(&["extract-tray", r"C:\x\t.exe"]), Command::ExtractTray(r"C:\x\t.exe".into()));
        assert!(p(&["extract-tray"]).is_err());
        assert!(p(&["extract-tray", "a", "b"]).is_err());
        // Options stay specific to their command.
        assert!(p(&["install", "--yes"]).is_err());
        assert!(p(&["console", "--telegram-id", "1"]).is_err());
    }
}
