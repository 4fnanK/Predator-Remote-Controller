//! The Windows service, its runtime threads (Telegram poller, notification sender, monitors,
//! IPC server, connectivity watcher), the command-line management interface and the interactive
//! setup (wizard / management menu) of the single-file release.

mod cli;
mod commands;
mod console;
mod install;
mod ipc_server;
mod pairing;
pub(crate) mod pipe;
mod poller;
mod runtime;
mod scm;
mod selftest;
mod sender;
mod setup;
mod slot;
mod text;
mod winsec;

use cli::Command;
use commands::DataCtx;

/// Entry point of `predator-service.exe` (released as `PredatorRemoteController.exe`). With no
/// arguments it runs under the SCM, or — when started outside it (double-click) — the
/// interactive setup; `service` runs under the SCM only; anything else is a CLI subcommand.
/// Returns the process exit code.
pub fn main_entry() -> i32 {
    restrict_dll_search();
    // args_os: never panic on non-UTF-16-clean arguments.
    let argv: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let inv = match cli::parse(&argv) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    if inv.command == Command::SsidHelper {
        // Child process of the service (network info): no logging, no data directory.
        return crate::sys::network::ssid_helper_main();
    }
    if inv.verbose && !matches!(inv.command, Command::Console(_) | Command::RunService) {
        crate::logging::init_stderr_only(true);
    }
    let data = DataCtx::new(inv.data_dir.as_deref());
    let result = match &inv.command {
        Command::Default => {
            return match scm::run_dispatcher(None) {
                Ok(()) => 0,
                // Not started by the SCM: someone opened the program. Install / manage it.
                Err(windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
                    setup::run(&data, &cli::SetupOptions::default())
                }
                Err(code) => {
                    eprintln!("error: cannot start the service dispatcher: {}", crate::util::win::error_message(code));
                    1
                }
            };
        }
        Command::Setup(opts) => return setup::run(&data, opts),
        Command::RunService => {
            return match scm::run_dispatcher(inv.data_dir.clone()) {
                Ok(()) => 0,
                Err(windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
                    println!("{}", cli::usage());
                    println!("(This program runs as a Windows service. Use one of the commands above.)");
                    1
                }
                Err(code) => {
                    eprintln!("error: cannot start the service dispatcher: {}", crate::util::win::error_message(code));
                    1
                }
            };
        }
        Command::Help => {
            println!("{}", cli::usage());
            Ok(())
        }
        Command::Version => {
            println!("{} {}", crate::PRODUCT_NAME, crate::VERSION);
            Ok(())
        }
        Command::Install { start } => install::install(&data, *start),
        Command::Uninstall { keep_audit_policy, purge_data } => {
            install::uninstall(&data, *keep_audit_policy, *purge_data)
        }
        Command::Start => commands::reject_custom_data_dir(&data, "start").and_then(|()| commands::start()),
        Command::Stop => commands::reject_custom_data_dir(&data, "stop").and_then(|()| commands::stop()),
        Command::Status => commands::status(),
        Command::SetToken { input, verify } => commands::set_token(&data, input, *verify),
        Command::Pair { admin, ttl_secs } => commands::pair_interactive(&data, *admin, *ttl_secs),
        Command::Users(cli::UsersCmd::List) => commands::users_list(&data),
        Command::Users(cli::UsersCmd::Remove(id)) => commands::users_remove(&data, *id),
        Command::SetOwner { telegram_id } => commands::set_owner(&data, *telegram_id),
        Command::SetOwnerSid(who) => commands::set_owner_sid(&data, who),
        Command::Features(cmd) => commands::features(&data, cmd),
        Command::Audit(cmd) => commands::audit(&data, *cmd),
        Command::Selftest { tailscale } => return selftest::run(&data, *tailscale),
        Command::Console(opts) => console::run(&data, opts, inv.verbose),
        Command::RestartHelper => commands::restart_helper(&data),
        Command::SsidHelper => return crate::sys::network::ssid_helper_main(),
        Command::ExtractTray(path) => setup::extract_tray(path),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// DLLs loaded later by name (the delay-loaded `version.dll`, `wtsapi32.dll`, `userenv.dll`, …,
/// and whatever system DLLs load on demand) come from System32 only, never from the folder of
/// the executable: the release file is typically started — and elevated — from the Downloads
/// folder, where a planted `version.dll` would otherwise run as administrator. The static
/// imports get the same rule from the image (`/DEPENDENTLOADFLAG:0x800`, see build.rs). Predator
/// ships no DLLs of its own.
fn restrict_dll_search() {
    use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
    // SAFETY: plain process-wide setting, called before anything is loaded on demand. A failure
    // (not expected on Windows 10/11) only keeps the default search order.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
}
