//! `console`: the full service runtime in the foreground (always dry-run).
//!
//! Stops on Ctrl+C / Ctrl+Break / console close or at the end of standard input. With
//! `--stdin-commands` every input line is injected into the dispatcher as a message from the
//! primary authorized Telegram user (`/status`) or a button press (`cb:nav:feat`), so the bot can
//! be tested end-to-end.

use std::io::BufRead;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
};

use super::cli::ConsoleOptions;
use super::commands::{DataCtx, service_state};
use super::runtime::{Runtime, RuntimeOptions, Shared, StopReason, catch};
use crate::sys::ServiceState;
use crate::telegram::types::{CallbackQuery, Chat, Message, Update, User};
use crate::util::StopFlag;
use crate::util::win::OwnedEvent;
use crate::{log_error, log_info};

static CONSOLE_STOP: OnceLock<Arc<StopFlag>> = OnceLock::new();
static CONSOLE_DONE: OnceLock<OwnedEvent> = OnceLock::new();

unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    std::panic::catch_unwind(|| match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            if let Some(stop) = CONSOLE_STOP.get() {
                stop.stop();
            }
            if ctrl_type >= CTRL_CLOSE_EVENT {
                // The process is terminated when this handler returns: let the shutdown finish.
                if let Some(done) = CONSOLE_DONE.get() {
                    done.wait(Duration::from_secs(8));
                }
            }
            1
        }
        _ => 0,
    })
    .unwrap_or(1)
}

/// Builds synthetic updates "from a Telegram user" for `--stdin-commands`.
pub(crate) struct Injector {
    user: i64,
    next_update: AtomicI64,
    next_message: AtomicI64,
}

impl Injector {
    /// Updates sent as Telegram user `user` in their private chat.
    pub fn new(user: i64) -> Self {
        Self { user, next_update: AtomicI64::new(900_000_000), next_message: AtomicI64::new(500_000) }
    }

    /// `None` for blank lines; `cb:<data>` → callback query, anything else → text message.
    pub fn build(&self, line: &str, now: i64) -> Option<Update> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let user = User {
            id: self.user,
            is_bot: false,
            first_name: "Console".into(),
            last_name: None,
            username: Some("console".into()),
        };
        let chat = Chat { id: self.user, kind: "private".into(), title: None, username: None };
        let message_id = self.next_message.fetch_add(1, Ordering::Relaxed);
        let update_id = self.next_update.fetch_add(1, Ordering::Relaxed);
        let mut u =
            Update { update_id, message: None, edited_message: None, callback_query: None, my_chat_member: None };
        if let Some(data) = line.strip_prefix("cb:") {
            u.callback_query = Some(CallbackQuery {
                id: format!("console-{update_id}"),
                from: user,
                message: Some(Message { message_id, date: now, chat, from: None, text: Some("menu".into()) }),
                data: Some(data.trim().to_string()),
            });
        } else {
            u.message = Some(Message { message_id, date: now, chat, from: Some(user), text: Some(line.to_string()) });
        }
        Some(u)
    }
}

fn stdin_loop(sh: Arc<Shared>, inject: bool) {
    let user = sh.ctx.settings.primary_user_id();
    let injector = Injector::new(user.unwrap_or(0));
    if inject {
        match user {
            Some(id) => {
                println!("stdin commands: lines are sent to the bot as Telegram user {id} (e.g. /status, cb:nav:feat).")
            }
            None => println!(
                "stdin commands: no Telegram user is paired, so the bot will reject them (add one with \
                 'set-owner --telegram-id N --data-dir DIR')."
            ),
        }
    }
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if sh.ctx.stop.is_stopped() {
            return;
        }
        let t = line.trim();
        if t.eq_ignore_ascii_case("quit") || t.eq_ignore_ascii_case("exit") {
            break;
        }
        if !inject {
            continue;
        }
        if let Some(u) = injector.build(&line, crate::util::time::now_unix())
            && let Err(e) = catch(|| sh.bot.handle_update(&u))
        {
            log_error!("dispatcher crashed: {e}");
        }
    }
    log_info!("end of input: stopping");
    sh.ctx.stop.stop();
}

pub(crate) fn run(data: &DataCtx, opts: &ConsoleOptions, verbose: bool) -> Result<(), String> {
    if data.is_default && matches!(service_state().0, ServiceState::Running | ServiceState::StartPending) {
        return Err("The Predator service is running and uses the default data directory. Stop it first, or run \
                    the console with --data-dir DIR (a separate test directory)."
            .into());
    }
    println!(
        "{} {} — console mode (DRY-RUN: power, lock, logout and Tailscale up/down are simulated)",
        crate::PRODUCT_NAME,
        crate::VERSION
    );
    println!("Data directory: {}", data.paths.root.display());
    println!("Press Ctrl+C (or end the input) to stop.\n");

    let runtime = Runtime::start(
        RuntimeOptions { paths: data.paths.clone(), console: true, token_file: opts.token_file.clone(), verbose },
        &|| {},
    )?;
    let sh = runtime.shared.clone();
    let _ = CONSOLE_STOP.set(sh.ctx.stop.clone());
    if let Ok(ev) = OwnedEvent::new_manual() {
        let _ = CONSOLE_DONE.set(ev);
    }
    // SAFETY: registers a handler that only touches thread-safe statics.
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };

    let sh2 = sh.clone();
    let inject = opts.stdin_commands;
    if let Err(e) = std::thread::Builder::new()
        .name("console-stdin".into())
        .stack_size(512 * 1024)
        .spawn(move || stdin_loop(sh2, inject))
    {
        log_error!("cannot read standard input: {e}");
    }

    while !sh.ctx.stop.sleep(Duration::from_secs(3600)) {}
    runtime.shutdown(StopReason::Console, &|| {});
    if let Some(done) = CONSOLE_DONE.get() {
        done.set();
    }
    println!("Stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_updates() {
        let inj = Injector::new(77);
        assert!(inj.build("   ", 1).is_none());
        let m = inj.build("/network", 1000).unwrap();
        let msg = m.message.unwrap();
        assert_eq!(msg.text.as_deref(), Some("/network"));
        assert_eq!(msg.chat.id, 77);
        assert!(msg.chat.is_private());
        assert_eq!(msg.from.unwrap().id, 77);
        assert_eq!(msg.date, 1000);
        let c = inj.build("cb:nav:feat", 1000).unwrap();
        assert!(c.update_id > m.update_id);
        let cb = c.callback_query.unwrap();
        assert_eq!(cb.data.as_deref(), Some("nav:feat"));
        assert_eq!(cb.from.id, 77);
        let cm = cb.message.unwrap();
        assert_eq!(cm.chat.id, 77);
        assert_ne!(cm.message_id, msg.message_id);
    }
}
