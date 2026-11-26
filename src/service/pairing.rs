//! Pairing Telegram accounts and managing the list of authorized accounts from the command line.
//!
//! * [`pair_interactive`] — while the service runs, the service itself creates the one-time
//!   8-digit code (IPC `StartPairing`) and redeems it when the new account sends it; this command
//!   only shows the code and the deep link `https://t.me/<bot>?start=pair-<code>` and asks for
//!   `PairingStatus` every 2 s until the account is paired, the code expires or Ctrl+C cancels
//!   it (`CancelPairing`, only while the active code is still ours). While the service certainly
//!   does not run (first setup, service stopped), the command polls getUpdates itself
//!   ([`direct_pairing`]): both at once is impossible, Telegram answers 409 Conflict to the
//!   second consumer. While the service starts, stops or its state is unknown, nothing is done
//!   ([`route`]). The direct path skips messages that were pending before the code existed,
//!   accepts `/pair CODE` and the deep link (`/start pair-CODE`) from a private chat whose id
//!   equals the sender's id, uses the same one-time code rules as the bot
//!   ([`crate::pairing::PairingSlot`]: single use, expires, invalidated after 5 wrong guesses)
//!   and never answers a failed attempt.
//! * [`users_list`] / [`users_remove`] — through the running service (IPC `ListUsers` /
//!   `RemoveUser`; removing needs an elevated prompt), otherwise on `settings.json` directly.
//!
//! Accounts are identified by their numeric Telegram user id only. The first account of an empty
//! list always becomes an Admin. The code is shown on this console only — never logged.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler};

use super::commands::{DataCtx, describe_token_error, service_state, tell_service_settings_changed};
use super::poller::PollState;
use super::runtime::{TokenLoad, TokenSource, load_token_from};
use crate::config::{AddUserOutcome, AuthorizedUser, MAX_AUTHORIZED_USERS, SettingsStore, UserRole};
use crate::ipc::{IpcRequest, IpcResponse, PairingProgress, UserInfo};
use crate::notify::NotificationKind;
use crate::pairing::{PairingSlot, RedeemError};
use crate::sys::ServiceState;
use crate::telegram::TgError;
use crate::telegram::api::TelegramApi;
use crate::telegram::types::Update;
use crate::util::win::OwnedEvent;

/// `PairingStatus` is asked this often while the service waits for the new account.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive failed status requests before the console says so (the loop keeps trying until
/// the code expires).
const WARN_AFTER_FAILURES: u32 = 3;

/// `token.dat` holds a user-scope blob written for LocalSystem by an older version.
const TOKEN_FOR_SERVICE_ONLY: &str = "The stored bot token is protected for the service account only, so it cannot \
                                      be read from this prompt. Enter it again with \
                                      'predator-service set-token' (the token from @BotFather), then pair again — \
                                      or set the account directly with 'predator-service set-owner --telegram-id ID'.";

const SERVICE_STARTING: &str = "The Predator service is starting. Wait a few seconds until it runs, then try again.";
const SERVICE_STOPPING: &str =
    "The Predator service is stopping. Wait until it has stopped (or start it again), then try again.";
const SERVICE_STATE_UNCLEAR: &str = "The state of the Predator service is unclear (paused, or the Service Control \
                                     Manager could not be asked). Start it ('predator-service start') or stop it \
                                     ('predator-service stop'), then try again.";
const SERVICE_STARTED_MEANWHILE: &str = "The Predator service was started meanwhile and now receives the bot's \
                                         messages. Start the pairing again: it then goes through the service.";

/// How `pair` and `users remove` reach the list of Telegram accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// Through the running service (IPC): it owns settings.json and the bot's updates.
    Service,
    /// On settings.json / getUpdates directly: nothing else uses them.
    Direct,
    /// Neither is safe right now (the text says why).
    Refuse(&'static str),
}

/// The route for the default data directory's service in `state` (a custom `--data-dir` is never
/// used by the service: always direct). Direct access needs a service that is certainly not
/// running: one that starts has read settings.json already (a removal would not reach it) and
/// polls the bot (two consumers of getUpdates steal each other's messages).
pub(crate) fn route(is_default: bool, state: &ServiceState) -> Route {
    if !is_default {
        return Route::Direct;
    }
    match state {
        ServiceState::Running => Route::Service,
        ServiceState::Stopped | ServiceState::NotInstalled => Route::Direct,
        ServiceState::StartPending => Route::Refuse(SERVICE_STARTING),
        ServiceState::StopPending => Route::Refuse(SERVICE_STOPPING),
        ServiceState::Paused | ServiceState::Unknown => Route::Refuse(SERVICE_STATE_UNCLEAR),
    }
}

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------------------------

/// The code part of a pairing attempt: `/pair CODE` (`/pair@Bot CODE`; the code may be empty or
/// malformed — the pairing slot decides) or the deep-link start `/start pair-CODE` /
/// `/start pair_CODE`. `None` for every other message.
pub(crate) fn pairing_input(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix('/')?;
    let (token, args) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim()),
        None => (rest, ""),
    };
    let name = token.split('@').next().unwrap_or_default().to_ascii_lowercase();
    match name.as_str() {
        "pair" => Some(args.to_string()),
        "start" => {
            let first = args.split_whitespace().next()?;
            let lower = first.to_ascii_lowercase();
            (lower.starts_with("pair-") || lower.starts_with("pair_")).then(|| first.to_string())
        }
        _ => None,
    }
}

/// A pairing attempt found in an update (direct path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub user_id: i64,
    pub chat_id: i64,
    /// Display name (`@username` or the first name, sanitized).
    pub name: String,
    pub input: String,
}

/// A private `/pair …` or `/start pair-…` message sent by a person in their own chat (chat id ==
/// sender id). Groups, channels, bots and everything else are ignored.
pub(crate) fn attempt_of(u: &Update) -> Option<Attempt> {
    let msg = u.message.as_ref()?;
    let from = msg.from.as_ref()?;
    if !msg.chat.is_private() || msg.chat.id != from.id || from.is_bot || from.id <= 0 {
        return None;
    }
    let input = pairing_input(msg.text.as_deref()?)?;
    Some(Attempt {
        user_id: from.id,
        chat_id: msg.chat.id,
        name: AuthorizedUser::display_name(from.username.as_deref(), &from.first_name),
        input,
    })
}

/// The role a new account gets: an Admin code always gives Admin; otherwise User, except for the
/// first account of an empty list (always an Admin). `list_empty` = None when unknown.
pub(crate) fn role_text(admin: bool, list_empty: Option<bool>) -> &'static str {
    match (admin, list_empty) {
        (true, _) => "Admin",
        (false, Some(true)) => "Admin (the first account always is)",
        (false, Some(false)) => "User",
        (false, None) => "User (Admin if it is the first account)",
    }
}

/// `45 s`, `10 min`, `1 h`, `1 h 30 min`.
pub(crate) fn fmt_validity(secs: i64) -> String {
    let secs = secs.max(0);
    match (secs / 3600, (secs % 3600) / 60) {
        (0, 0) => format!("{secs} s"),
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// What the console shows after a code was created. `until` is the local expiry time.
pub(crate) fn instructions(code: &str, bot: Option<&str>, valid_secs: i64, until: &str, role: &str) -> String {
    let bot = bot.and_then(crate::ipc::bot_username);
    let digits = crate::pairing::normalize_code(code).unwrap_or_else(|| code.to_string());
    let mut out = String::new();
    out.push_str(&format!("Pairing code:  {}\n", crate::ipc::spaced_code(&digits)));
    out.push_str(&format!("Valid for:     {} (until {until}), single use\n", fmt_validity(valid_secs)));
    out.push_str(&format!("Role:          {role}\n\n"));
    out.push_str("On the phone with the Telegram account to add:\n");
    match bot.and_then(|b| crate::ipc::pairing_deep_link(b, &digits).map(|link| (b, link))) {
        Some((b, link)) => {
            out.push_str(&format!("  - open this link and press Start:   {link}\n"));
            out.push_str(&format!("  - or send this message to @{b}:   /pair {digits}\n"));
        }
        None => out.push_str(&format!("  - send this message to the bot:   /pair {digits}\n")),
    }
    out
}

/// Error text for a pairing that ended without a new account.
pub(crate) fn ended_message(o: &PairingProgress) -> &'static str {
    match o {
        PairingProgress::Expired => "The pairing code expired without being used. Start the pairing again.",
        PairingProgress::Replaced => {
            "A new pairing code was created elsewhere (tray or another console); this one is no longer valid."
        }
        _ => {
            "The pairing code is no longer valid: it was cancelled, invalidated after too many wrong attempts, or \
             the service restarted. Start the pairing again."
        }
    }
}

/// The user table of `users list` (`date` formats `added_unix` > 0).
pub(crate) fn format_users(users: &[UserInfo], source: &str, date: &dyn Fn(i64) -> String) -> String {
    if users.is_empty() {
        return format!(
            "No Telegram account is paired yet ({source}). Pair one with 'predator-service pair' (the first \
             account becomes an Admin)."
        );
    }
    let mut out = format!("Telegram users ({} of {MAX_AUTHORIZED_USERS}, {source}):\n", users.len());
    out.push_str(&format!("  {:<14} {:<6} {:<12} {}\n", "USER ID", "ROLE", "ADDED", "NAME"));
    for u in users {
        let added = if u.added_unix > 0 { date(u.added_unix) } else { "-".to_string() };
        out.push_str(&format!("  {:<14} {:<6} {:<12} {}\n", u.id, u.role_label(), added, u.display_name()));
    }
    out.push_str("\nAccess is decided by the numeric user id only; names are for display.");
    out
}

// ---------------------------------------------------------------------------------------------
// pair
// ---------------------------------------------------------------------------------------------

fn service_up() -> ServiceState {
    service_state().0
}

/// Pair a Telegram account: through the running service when there is one, otherwise by polling
/// Telegram directly. `admin` = the new account becomes an Admin (the first account always does).
/// `ttl_secs` = lifetime of the code (60 … 3600 s).
pub(crate) fn pair_interactive(data: &DataCtx, admin: bool, ttl_secs: u64) -> Result<(), String> {
    let ttl_secs = ttl_secs.clamp(crate::pairing::MIN_TTL_SECS, crate::pairing::MAX_TTL_SECS);
    let state = if data.is_default { service_up() } else { ServiceState::NotInstalled };
    match route(data.is_default, &state) {
        Route::Service => pair_via_service(admin, ttl_secs),
        Route::Direct => pair_direct(data, admin, ttl_secs),
        Route::Refuse(why) => Err(why.into()),
    }
}

/// Set by the console control handler while a service-side pairing is waiting (`None` = the
/// event could not be created: Ctrl+C then ends the process as usual).
static PAIR_CANCEL: OnceLock<Option<OwnedEvent>> = OnceLock::new();
/// `expires_unix` of the service-side code this console waits for (0 = none): identifies it for
/// the close handler without the code itself.
static PAIR_OURS: AtomicI64 = AtomicI64::new(0);
/// Each of the (at most two) requests of the close handler; Windows ends the process about 5 s
/// after CTRL_CLOSE_EVENT.
const CLOSE_IPC_TIMEOUT: Duration = Duration::from_millis(1500);

fn cancel_event() -> Option<&'static OwnedEvent> {
    PAIR_CANCEL.get_or_init(|| OwnedEvent::new_manual().ok()).as_ref()
}

/// Whether `CancelPairing` may be sent for the code expiring at `ours`, given the reply to a
/// `PairingStatus` asked right before: not when that reply shows the code is used, gone or was
/// replaced (by the tray or another console — their code must not be cancelled). Without a
/// usable reply it is sent (the service then forgets whatever is active, as before).
pub(crate) fn may_cancel(status: &Result<IpcResponse, String>, ours: i64, now: i64) -> bool {
    match status.as_ref().ok().and_then(|r| crate::ipc::progress_of(r, ours, now)) {
        None | Some(PairingProgress::Waiting) => true,
        Some(_) => false,
    }
}

/// Cancel the service's code expiring at `ours`, unless it is no longer the active one.
fn cancel_own_code(ours: i64, request: &dyn Fn(&IpcRequest) -> Result<IpcResponse, String>) {
    let status = request(&IpcRequest::PairingStatus);
    if may_cancel(&status, ours, crate::util::time::now_unix()) {
        let _ = request(&IpcRequest::CancelPairing);
    }
}

unsafe extern "system" fn pair_ctrl_handler(ctrl_type: u32) -> i32 {
    std::panic::catch_unwind(|| match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => match PAIR_CANCEL.get().and_then(Option::as_ref) {
            Some(ev) => {
                ev.set();
                1
            }
            None => 0,
        },
        CTRL_CLOSE_EVENT => {
            // The window is closing and the process ends when this returns: forget the code now.
            let ours = PAIR_OURS.load(Ordering::SeqCst);
            if ours != 0 {
                cancel_own_code(ours, &|req| crate::ipc::request(req, CLOSE_IPC_TIMEOUT));
            }
            0
        }
        _ => 0,
    })
    .unwrap_or(0)
}

/// Ctrl+C / Ctrl+Break cancel the pairing (instead of ending the process) while this lives;
/// closing the console window cancels it as well.
struct CancelOnCtrlC {
    event: Option<&'static OwnedEvent>,
}

impl CancelOnCtrlC {
    /// `ours` = `expires_unix` of the code to cancel.
    fn install(ours: i64) -> Self {
        let Some(ev) = cancel_event() else { return Self { event: None } };
        ev.reset();
        PAIR_OURS.store(ours, Ordering::SeqCst);
        // SAFETY: the handler only touches the statics above and makes at most two IPC requests.
        let installed = unsafe { SetConsoleCtrlHandler(Some(pair_ctrl_handler), 1) } != 0;
        if !installed {
            PAIR_OURS.store(0, Ordering::SeqCst);
        }
        Self { event: installed.then_some(ev) }
    }

    /// Wait up to `d`; true when Ctrl+C was pressed.
    fn wait(&self, d: Duration) -> bool {
        match self.event {
            Some(ev) => ev.wait(d),
            None => {
                std::thread::sleep(d);
                false
            }
        }
    }
}

impl Drop for CancelOnCtrlC {
    fn drop(&mut self) {
        if self.event.is_some() {
            // SAFETY: removes the handler registered in `install`.
            unsafe { SetConsoleCtrlHandler(Some(pair_ctrl_handler), 0) };
            PAIR_OURS.store(0, Ordering::SeqCst);
        }
    }
}

fn ipc(req: &IpcRequest) -> Result<IpcResponse, String> {
    std::panic::catch_unwind(|| crate::ipc::request(req, IPC_TIMEOUT))
        .unwrap_or_else(|_| Err("internal error while contacting the service".into()))
}

/// The service creates and redeems the code; this console shows it and waits.
fn pair_via_service(admin: bool, ttl_secs: u64) -> Result<(), String> {
    // A service without a usable token cannot receive the code: say so instead of waiting.
    if let Ok(IpcResponse::Status(st)) = ipc(&IpcRequest::Status) {
        let telegram = st.telegram.trim().to_ascii_lowercase();
        if telegram == "not configured" || telegram == "invalid token" {
            return Err(format!(
                "The service cannot reach the bot ({}). Store a valid bot token first: predator-service set-token",
                st.telegram.trim()
            ));
        }
        if telegram == "offline" {
            println!("Note: the service is not connected to Telegram right now; the code works once it is.\n");
        }
    }
    let list_empty = match ipc(&IpcRequest::ListUsers) {
        Ok(IpcResponse::Users { users }) => Some(users.is_empty()),
        _ => None,
    };
    let (code, expires_unix, bot) = match ipc(&IpcRequest::StartPairing { ttl_secs, admin }) {
        Ok(IpcResponse::Pairing { code, expires_unix, bot_username }) => (code, expires_unix, bot_username),
        Ok(IpcResponse::Denied { reason }) => {
            return Err(format!("The service refused: {reason} Run this from an elevated (Administrator) prompt."));
        }
        Ok(IpcResponse::Error { message }) => return Err(message),
        Ok(other) => return Err(format!("Unexpected reply from the service: {other:?}")),
        Err(e) => return Err(format!("The running service was not reachable: {e}")),
    };
    let now = crate::util::time::now_unix();
    let until = crate::util::time::fmt_time(expires_unix);
    println!("{}", instructions(&code, bot.as_deref(), expires_unix - now, &until, role_text(admin, list_empty)));
    println!("Waiting for the new account… (Ctrl+C cancels the code)");

    let cancel = CancelOnCtrlC::install(expires_unix);
    let mut failures = 0u32;
    loop {
        if cancel.wait(POLL_INTERVAL) {
            cancel_own_code(expires_unix, &ipc);
            return Err("Pairing cancelled; the code can no longer be used.".into());
        }
        let now = crate::util::time::now_unix();
        let reply = ipc(&IpcRequest::PairingStatus);
        match reply.as_ref().ok().and_then(|r| crate::ipc::progress_of(r, expires_unix, now)) {
            Some(PairingProgress::Waiting) => {
                failures = 0;
                continue;
            }
            Some(PairingProgress::Paired { name, id }) => {
                let role = match ipc(&IpcRequest::ListUsers) {
                    Ok(IpcResponse::Users { users }) => {
                        users.iter().find(|u| u.id == id).map(|u| format!(" as {}", u.role_label()))
                    }
                    _ => None,
                };
                println!(
                    "\nPaired: {} (Telegram user id {id}){}. The account can use the bot now.",
                    crate::config::clean_user_name(&name),
                    role.unwrap_or_default()
                );
                return Ok(());
            }
            Some(ended) => return Err(ended_message(&ended).into()),
            None => {}
        }
        match reply {
            Ok(IpcResponse::Denied { reason }) => return Err(format!("The service refused: {reason}")),
            other => {
                failures += 1;
                if failures == WARN_AFTER_FAILURES {
                    let why = match other {
                        Err(e) => e,
                        Ok(r) => format!("unexpected reply {r:?}"),
                    };
                    println!("(the service does not answer: {why}; still trying)");
                }
                if service_up() != ServiceState::Running {
                    return Err("The service stopped, so the pairing code is no longer valid.".into());
                }
                if now >= expires_unix {
                    return Err(ended_message(&PairingProgress::Expired).into());
                }
            }
        }
    }
}

/// Without a running service: poll Telegram here and add the account to settings.json.
fn pair_direct(data: &DataCtx, admin: bool, ttl_secs: u64) -> Result<(), String> {
    data.require_admin("pair")?;
    // Never pair from (or write the account into) a data directory that is not trusted.
    data.ensure()?;
    let token = match load_token_from(&TokenSource::DataDir(data.paths.token())) {
        TokenLoad::Loaded(t) => t,
        TokenLoad::Missing(_) => return Err("No bot token stored yet. Run 'predator-service set-token' first.".into()),
        TokenLoad::Invalid(e) => {
            if matches!(crate::secrets::stored_scope(&data.paths.token()), Ok(Some(crate::secrets::Scope::CurrentUser)))
            {
                return Err(TOKEN_FOR_SERVICE_ONLY.into());
            }
            return Err(e);
        }
    };
    let api = TelegramApi::new(token.expose()).map_err(|e| describe_token_error(&e))?;
    drop(token);
    let me = api.get_me().map_err(|e| describe_token_error(&e))?;
    let store = data.settings()?;
    if store.authorized_users().len() >= MAX_AUTHORIZED_USERS {
        return Err(format!(
            "{MAX_AUTHORIZED_USERS} Telegram accounts are paired already (the maximum). Remove one first."
        ));
    }
    let role = if admin { UserRole::Admin } else { UserRole::User };
    let list_empty = store.authorized_users().is_empty();
    let bot = me.username.clone().filter(|u| !u.is_empty());

    let accept = &mut |candidate: AuthorizedUser| add_paired_user(&store, candidate);
    let is_authorized = |id: i64| store.is_authorized(id);
    let service_started =
        || data.is_default && matches!(service_up(), ServiceState::Running | ServiceState::StartPending);
    let role_label = role_text(admin, Some(list_empty));
    let announce = |code: &str, expires: i64| {
        let valid = expires - crate::util::time::now_unix();
        let until = crate::util::time::fmt_time(expires);
        println!("{}", instructions(code, bot.as_deref(), valid, &until, role_label));
        println!("Waiting for the new account… (Ctrl+C aborts)");
    };
    let opts = DirectPairing {
        role,
        ttl_secs,
        is_authorized: &is_authorized,
        service_started: &service_started,
        announce: &announce,
        computer: computer_name(),
    };
    let (user, last_seen) = direct_pairing(&api, &opts, accept)?;

    // Let the service start after the updates consumed here, bound to this bot.
    let st = PollState { last_update_id: last_seen, updated_unix: crate::util::time::now_unix() };
    let state_path = data.paths.telegram_state();
    if let Err(e) = st.save_for_bot(&state_path, Some(me.id)) {
        println!("WARNING: cannot save {}: {e}", state_path.display());
    }
    println!("\nPaired: {} (Telegram user id {}) as {}.", user.label(), user.id, user.role.label());
    let others: Vec<i64> = store.authorized_users().iter().map(|u| u.id).filter(|id| *id != user.id).collect();
    let running = data.is_default && matches!(service_up(), ServiceState::Running | ServiceState::StartPending);
    if !others.is_empty() && !running {
        let lines = vec![
            ("Name".to_string(), user.label()),
            ("User ID".to_string(), user.id.to_string()),
            ("Role".to_string(), user.role.label().to_string()),
            ("Computer".to_string(), computer_name()),
        ];
        queue_offline_notice(data, "👤", "NEW TELEGRAM USER PAIRED", &lines, &[user.id]);
    }
    if running {
        // The service was started meanwhile: it must re-read settings.json (new account).
        tell_service_settings_changed(data);
    } else if data.is_default && service_up() != ServiceState::NotInstalled {
        println!("Start the service with: predator-service start");
    }
    Ok(())
}

fn computer_name() -> String {
    std::panic::catch_unwind(crate::sys::sysinfo::computer_name).unwrap_or_default()
}

/// Store the account that redeemed the code; returns it as stored (the first account of an
/// empty list is promoted to Admin by the store).
pub(crate) fn add_paired_user(store: &SettingsStore, candidate: AuthorizedUser) -> Result<AuthorizedUser, String> {
    let id = candidate.id;
    match store.add_user(candidate.clone())? {
        AddUserOutcome::Added | AddUserOutcome::AlreadyAuthorized => Ok(store.user(id).unwrap_or(candidate)),
        AddUserOutcome::LimitReached => {
            Err(format!("{MAX_AUTHORIZED_USERS} Telegram accounts are paired already (the maximum). Remove one first."))
        }
    }
}

/// The polling position after skipping the backlog: getUpdates with offset -1 returned
/// `newest` (Telegram then forgets every older pending update). `(offset, last_seen)`.
pub(crate) fn after_backlog(newest: &[Update]) -> (i64, i64) {
    match newest.iter().map(|u| u.update_id).max() {
        Some(id) => (id.saturating_add(1), id),
        None => (0, 0),
    }
}

/// The Bot API calls of the direct path (the real [`TelegramApi`], or a script in tests).
pub(crate) trait PairingTransport {
    fn delete_webhook(&self) -> Result<(), TgError>;
    fn get_updates(&self, offset: i64, timeout_secs: u32) -> Result<Vec<Update>, TgError>;
    fn send(&self, chat_id: i64, screen: &crate::telegram::ui::Screen) -> Result<(), TgError>;
}

impl PairingTransport for TelegramApi {
    fn delete_webhook(&self) -> Result<(), TgError> {
        TelegramApi::delete_webhook(self)
    }

    fn get_updates(&self, offset: i64, timeout_secs: u32) -> Result<Vec<Update>, TgError> {
        TelegramApi::get_updates(self, offset, timeout_secs)
    }

    fn send(&self, chat_id: i64, screen: &crate::telegram::ui::Screen) -> Result<(), TgError> {
        let (text, kb) = screen;
        self.send_message_with_timeout(chat_id, text, kb.as_ref(), Duration::from_secs(10)).map(|_| ())
    }
}

/// What [`direct_pairing`] needs besides the bot and the store.
pub(crate) struct DirectPairing<'a> {
    pub role: UserRole,
    pub ttl_secs: u64,
    pub is_authorized: &'a dyn Fn(i64) -> bool,
    /// The service polls the bot now (asked when Telegram reports a second consumer).
    pub service_started: &'a dyn Fn() -> bool,
    /// Show the instructions for the new code (`code`, `expires_unix`) on this console.
    pub announce: &'a dyn Fn(&str, i64),
    /// Named in the "paired" reply.
    pub computer: String,
}

/// Poll getUpdates until a valid code arrives (or the code expires / is invalidated). Announces
/// the code first. `accept` stores the new account and returns it as stored (e.g. promoted to
/// Admin as the first account); only then is the account told it is paired. Accounts for which
/// `is_authorized` holds get "already paired" and leave the code untouched. Failed attempts are
/// never answered (an outsider cannot learn whether a code exists). Returns the account and the
/// last update id consumed (the caller records it in `telegram-state.json`).
///
/// Messages that were pending before the code existed are skipped unread: none can contain it,
/// and wrong `/pair` guesses queued in advance would otherwise use up the new code at once.
///
/// Nothing else may poll this bot meanwhile (the service must be stopped or not installed yet).
/// When Telegram reports a second consumer and `service_started` holds, the pairing ends.
pub(crate) fn direct_pairing(
    api: &dyn PairingTransport,
    opts: &DirectPairing<'_>,
    accept: &mut dyn FnMut(AuthorizedUser) -> Result<AuthorizedUser, String>,
) -> Result<(AuthorizedUser, i64), String> {
    if let Err(e) = api.delete_webhook()
        && e == TgError::Unauthorized
    {
        return Err(describe_token_error(&e));
    }
    // Before the code exists: forget the backlog (a failure here only means it is read below).
    let (mut offset, mut last_seen) = match api.get_updates(-1, 0) {
        Ok(newest) => after_backlog(&newest),
        Err(TgError::Unauthorized) => return Err(describe_token_error(&TgError::Unauthorized)),
        Err(_) => (0, 0),
    };
    let slot = PairingSlot::new();
    let code = slot.start(opts.role, opts.ttl_secs, "command line", crate::util::time::now_unix());
    let expires = code.expires_unix;
    (opts.announce)(&code.code, expires);
    drop(code);
    let is_authorized = opts.is_authorized;
    let service_started = opts.service_started;

    let mut warned = false;
    // false once the service polls the bot: it confirms (and handles) the updates from then on
    let mut confirm = true;
    let outcome: Result<AuthorizedUser, String> = 'poll: loop {
        let now = crate::util::time::now_unix();
        if now >= expires {
            break Err(ended_message(&PairingProgress::Expired).into());
        }
        let left = u32::try_from((expires - now).clamp(1, 25)).unwrap_or(25);
        let updates = match api.get_updates(offset, left) {
            Ok(u) => u,
            Err(TgError::Unauthorized) => break Err(describe_token_error(&TgError::Unauthorized)),
            Err(TgError::Conflict(_)) if service_started() => {
                confirm = false;
                break Err(SERVICE_STARTED_MEANWHILE.into());
            }
            Err(e) => {
                if !warned {
                    match e {
                        TgError::Conflict(_) => {
                            println!("Telegram reports another program polling this bot (the service?). Retrying…")
                        }
                        other => println!("Telegram request failed ({other}); retrying…"),
                    }
                    warned = true;
                }
                std::thread::sleep(Duration::from_secs(3));
                continue;
            }
        };
        for u in &updates {
            offset = offset.max(u.update_id + 1);
            last_seen = last_seen.max(u.update_id);
            let Some(att) = attempt_of(u) else { continue };
            if is_authorized(att.user_id) {
                // Already has access: nothing to hide from them, and the code stays valid.
                let _ = api.send(att.chat_id, &crate::telegram::ui::already_paired_screen());
                println!("Telegram user {} is paired already; the code is still valid.", att.user_id);
                continue;
            }
            match slot.redeem(&att.input, att.user_id, crate::util::time::now_unix()) {
                Ok(role) => {
                    let candidate = AuthorizedUser::new(att.user_id, &att.name, role, crate::util::time::now_unix());
                    let user = match accept(candidate) {
                        Ok(u) => u,
                        Err(e) => break 'poll Err(e),
                    };
                    if let Err(e) = api.send(att.chat_id, &crate::telegram::ui::paired_screen(&opts.computer)) {
                        println!("WARNING: paired, but the confirmation message failed: {e}");
                    }
                    break 'poll Ok(user);
                }
                Err(RedeemError::Wrong) => {
                    println!(
                        "Ignored a pairing attempt with a wrong or incomplete code (Telegram user {}).",
                        att.user_id
                    )
                }
                Err(RedeemError::Exhausted) => {
                    break 'poll Err(
                        "Too many wrong pairing codes: the code was invalidated. Start the pairing again.".into(),
                    );
                }
                Err(RedeemError::Expired | RedeemError::NoActiveCode) => {
                    break 'poll Err(ended_message(&PairingProgress::Expired).into());
                }
            }
        }
    };
    // Confirm the consumed updates (the service must not handle them again). Not while the
    // service polls: that request would cut its long poll short.
    if confirm && offset > 0 {
        let _ = api.get_updates(offset, 0);
    }
    outcome.map(|u| (u, last_seen))
}

/// Queue a notice for the other Telegram users in `queue.json`; the service delivers it when it
/// starts. Only while the service does not run (it owns the file then).
fn queue_offline_notice(data: &DataCtx, emoji: &str, title: &str, lines: &[(String, String)], exclude: &[i64]) {
    let now = crate::util::time::now_unix();
    let html = crate::notify::format::render_system(emoji, title, lines, now);
    let queued = crate::notify::queue::NotificationQueue::open(&data.paths.queue())
        .and_then(|q| q.push_excluding(NotificationKind::Security, now, html, None, exclude));
    match queued {
        Ok(_) => println!("The other Telegram users will be told as soon as the service runs."),
        Err(e) => println!("WARNING: could not queue the notice for the other Telegram users: {e}"),
    }
}

// ---------------------------------------------------------------------------------------------
// users list / users remove
// ---------------------------------------------------------------------------------------------

fn via_service(data: &DataCtx) -> bool {
    data.is_default && service_up() == ServiceState::Running
}

fn users_from(store: &SettingsStore) -> Vec<UserInfo> {
    store.authorized_users().iter().map(UserInfo::from_user).collect()
}

/// Print the authorized Telegram accounts (from the running service, else from settings.json).
pub(crate) fn users_list(data: &DataCtx) -> Result<(), String> {
    if via_service(data) {
        match ipc(&IpcRequest::ListUsers) {
            Ok(IpcResponse::Users { users }) => {
                println!("{}", format_users(&users, "from the running service", &crate::util::time::fmt_date));
                return Ok(());
            }
            Ok(IpcResponse::Denied { reason }) => println!("(service: {reason} — showing settings.json)"),
            Ok(IpcResponse::Error { message }) => println!("(service: {message} — showing settings.json)"),
            Ok(other) => println!("(unexpected reply {other:?} — showing settings.json)"),
            Err(e) => println!("(service not reachable: {e} — showing settings.json)"),
        }
    }
    let users = users_from(&data.settings()?);
    let source = format!("from {}", data.paths.settings().display());
    println!("{}", format_users(&users, &source, &crate::util::time::fmt_date));
    Ok(())
}

/// Revoke a Telegram account by its numeric id (through the running service, else in
/// settings.json). The last admin cannot be removed.
pub(crate) fn users_remove(data: &DataCtx, id: i64) -> Result<(), String> {
    if id <= 0 {
        return Err(format!("{id} is not a valid Telegram user id."));
    }
    let state = if data.is_default { service_up() } else { ServiceState::NotInstalled };
    let running = match route(data.is_default, &state) {
        Route::Service => true,
        Route::Direct => false,
        // e.g. a starting service has read settings.json already: the removal would not reach it
        Route::Refuse(why) => return Err(why.into()),
    };
    if running {
        match ipc(&IpcRequest::RemoveUser { id }) {
            Ok(IpcResponse::Ok { message }) => {
                println!("{message} Access was revoked at once; the remaining Telegram users were told.");
                return Ok(());
            }
            Ok(IpcResponse::Denied { reason }) => return Err(format!("The service refused: {reason}")),
            Ok(IpcResponse::Error { message }) => return Err(message),
            Ok(other) => return Err(format!("Unexpected reply from the service: {other:?}")),
            // Not reachable: editing settings.json behind the running service's back would leave the
            // account authorized in its memory (and a later save could even restore it), so refuse.
            Err(e) => {
                return Err(format!(
                    "The running service did not answer ({e}), so the account was NOT removed. Restart the \
                     service ('predator-service stop', then 'start') and try again, or stop it first to edit \
                     the settings directly."
                ));
            }
        }
    }
    data.require_admin("removing a Telegram user")?;
    data.ensure()?;
    let store = data.settings()?;
    let removed = store.remove_user(id)?;
    println!("Removed {} (Telegram user id {}, {}).", removed.label(), removed.id, removed.role.label());
    // only reached while the service is stopped: it sends the notice when it starts
    if !store.authorized_users().is_empty() {
        let lines = vec![
            ("Name".to_string(), removed.label()),
            ("User ID".to_string(), removed.id.to_string()),
            ("Role".to_string(), removed.role.label().to_string()),
            ("Removed by".to_string(), "an administrator on this PC (command line)".to_string()),
        ];
        queue_offline_notice(data, "🗑", "TELEGRAM USER REMOVED", &lines, &[]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::types::{Chat, Message, User};

    const ALICE: i64 = 123_456_789;
    const BOB: i64 = 987_654_321;

    fn update(chat_id: i64, kind: &str, from: i64, text: &str) -> Update {
        Update {
            update_id: 1,
            message: Some(Message {
                message_id: 1,
                date: 0,
                chat: Chat { id: chat_id, kind: kind.into(), title: None, username: None },
                from: Some(User {
                    id: from,
                    is_bot: false,
                    first_name: "Alice".into(),
                    last_name: None,
                    username: Some("alice".into()),
                }),
                text: Some(text.into()),
            }),
            edited_message: None,
            callback_query: None,
            my_chat_member: None,
        }
    }

    #[test]
    fn pairing_messages() {
        assert_eq!(pairing_input("/pair 12345678").as_deref(), Some("12345678"));
        assert_eq!(pairing_input("  /PAIR@ExampleBot   1234 5678 ").as_deref(), Some("1234 5678"));
        assert_eq!(pairing_input("/pair").as_deref(), Some(""));
        assert_eq!(pairing_input("/start pair-12345678").as_deref(), Some("pair-12345678"));
        assert_eq!(pairing_input("/start@ExampleBot PAIR_12345678 x").as_deref(), Some("PAIR_12345678"));
        for other in ["/start", "/start hello", "/status", "pair 12345678", "", "/pairing 1", "hello"] {
            assert_eq!(pairing_input(other), None, "{other:?}");
        }
    }

    #[test]
    fn only_private_chats_of_the_sender() {
        let a = attempt_of(&update(ALICE, "private", ALICE, "/pair 12345678")).unwrap();
        assert_eq!(a, Attempt { user_id: ALICE, chat_id: ALICE, name: "@alice".into(), input: "12345678".into() });
        let deep = attempt_of(&update(ALICE, "private", ALICE, "/start pair-12345678")).unwrap();
        assert_eq!(deep.input, "pair-12345678");
        assert_eq!(attempt_of(&update(-100, "group", ALICE, "/pair 12345678")), None);
        assert_eq!(attempt_of(&update(BOB, "private", ALICE, "/pair 12345678")), None);
        assert_eq!(attempt_of(&update(ALICE, "private", ALICE, "/menu")), None);
        let mut bot = update(ALICE, "private", ALICE, "/pair 12345678");
        if let Some(f) = bot.message.as_mut().and_then(|m| m.from.as_mut()) {
            f.is_bot = true;
        }
        assert_eq!(attempt_of(&bot), None);
        let mut no_text = update(ALICE, "private", ALICE, "x");
        if let Some(m) = no_text.message.as_mut() {
            m.text = None;
        }
        assert_eq!(attempt_of(&no_text), None);
    }

    /// The direct path redeems with the same slot rules as the bot: every accepted form works
    /// once, and a wrong guess is no success.
    #[test]
    fn direct_attempts_redeem_like_the_bot() {
        let slot = PairingSlot::new();
        let now = 1_800_000_000;
        let c = slot.start(UserRole::User, 600, "command line", now);
        let wrong = if c.code == "00000000" { "11111111" } else { "00000000" };
        let bad = attempt_of(&update(BOB, "private", BOB, &format!("/pair {wrong}"))).unwrap();
        assert_eq!(slot.redeem(&bad.input, bad.user_id, now + 1), Err(RedeemError::Wrong));
        let deep = attempt_of(&update(ALICE, "private", ALICE, &format!("/start pair-{}", c.code))).unwrap();
        assert_eq!(slot.redeem(&deep.input, deep.user_id, now + 2), Ok(UserRole::User));
        assert_eq!(slot.redeem(&c.code, ALICE, now + 3), Err(RedeemError::NoActiveCode), "single use");
    }

    #[test]
    fn routes_by_service_state() {
        use ServiceState::*;
        assert_eq!(route(true, &Running), Route::Service);
        assert_eq!(route(true, &Stopped), Route::Direct);
        assert_eq!(route(true, &NotInstalled), Route::Direct);
        assert_eq!(route(true, &StartPending), Route::Refuse(SERVICE_STARTING));
        assert_eq!(route(true, &StopPending), Route::Refuse(SERVICE_STOPPING));
        // a paused service or one the SCM cannot report on may still poll the bot
        assert_eq!(route(true, &Paused), Route::Refuse(SERVICE_STATE_UNCLEAR));
        assert_eq!(route(true, &Unknown), Route::Refuse(SERVICE_STATE_UNCLEAR));
        for s in [Running, StartPending, StopPending, Paused, Unknown, Stopped] {
            assert_eq!(route(false, &s), Route::Direct, "a custom --data-dir is never the service's: {s:?}");
        }
    }

    #[test]
    fn cancels_only_its_own_code() {
        let ours = 1_800_000_600;
        let now = ours - 100;
        let st = |active: bool, expires: Option<i64>, paired: Option<i64>| -> Result<IpcResponse, String> {
            Ok(IpcResponse::PairingState {
                active,
                expires_unix: expires,
                paired_name: paired.map(|_| "@alice".to_string()),
                paired_id: paired,
                paired_unix: paired.map(|_| now),
            })
        };
        assert!(may_cancel(&st(true, Some(ours), None), ours, now), "still ours");
        assert!(!may_cancel(&st(true, Some(ours + 30), None), ours, now), "replaced by the tray or another console");
        assert!(!may_cancel(&st(false, None, Some(ALICE)), ours, now), "used meanwhile");
        assert!(!may_cancel(&st(false, None, None), ours, now), "gone already");
        assert!(!may_cancel(&st(false, None, None), ours, ours + 1), "expired");
        // no usable answer: cancel (whatever is active) as before
        assert!(may_cancel(&Err("timeout".into()), ours, now));
        assert!(may_cancel(&Ok(IpcResponse::Ok { message: String::new() }), ours, now));
    }

    type Step = Box<dyn Fn(&str) -> Result<Vec<Update>, TgError>>;

    /// A scripted bot: the backlog reply (offset -1), then one reply per further getUpdates
    /// (each built from the announced code); afterwards 401, which ends the loop.
    struct Script {
        backlog: Result<Vec<Update>, TgError>,
        steps: std::cell::RefCell<std::collections::VecDeque<Step>>,
        code: std::cell::RefCell<String>,
        offsets: std::cell::RefCell<Vec<i64>>,
        sent: std::cell::RefCell<Vec<(i64, String)>>,
    }

    impl Script {
        fn new(backlog: Result<Vec<Update>, TgError>, steps: Vec<Step>) -> Self {
            Self {
                backlog,
                steps: std::cell::RefCell::new(steps.into()),
                code: Default::default(),
                offsets: Default::default(),
                sent: Default::default(),
            }
        }

        fn run(
            &self,
            authorized: &[i64],
            service_started: bool,
            accept: &mut dyn FnMut(AuthorizedUser) -> Result<AuthorizedUser, String>,
        ) -> Result<(AuthorizedUser, i64), String> {
            let is_authorized = |id: i64| authorized.contains(&id);
            let started = || service_started;
            let announce = |code: &str, _expires: i64| *self.code.borrow_mut() = code.to_string();
            let opts = DirectPairing {
                role: UserRole::User,
                ttl_secs: 600,
                is_authorized: &is_authorized,
                service_started: &started,
                announce: &announce,
                computer: "MY-PC".into(),
            };
            direct_pairing(self, &opts, accept)
        }
    }

    impl PairingTransport for Script {
        fn delete_webhook(&self) -> Result<(), TgError> {
            Ok(())
        }

        fn get_updates(&self, offset: i64, _timeout_secs: u32) -> Result<Vec<Update>, TgError> {
            self.offsets.borrow_mut().push(offset);
            if offset == -1 {
                return self.backlog.clone();
            }
            let step = self.steps.borrow_mut().pop_front();
            match step {
                Some(step) => step(&self.code.borrow()),
                None => Err(TgError::Unauthorized),
            }
        }

        fn send(&self, chat_id: i64, screen: &crate::telegram::ui::Screen) -> Result<(), TgError> {
            self.sent.borrow_mut().push((chat_id, screen.0.clone()));
            Ok(())
        }
    }

    fn private(update_id: i64, from: i64, text: &str) -> Update {
        Update { update_id, ..update(from, "private", from, text) }
    }

    fn wrong_for(code: &str) -> &'static str {
        if code == "00000000" { "/pair 11111111" } else { "/pair 00000000" }
    }

    fn keep(u: AuthorizedUser) -> Result<AuthorizedUser, String> {
        Ok(u)
    }

    /// Wrong guesses queued before the code existed are skipped unread (they cannot burn it);
    /// the deep link redeems it; the consumed updates are confirmed.
    #[test]
    fn direct_pairing_skips_the_backlog_and_redeems_the_deep_link() {
        let backlog = Ok(vec![private(10, BOB, "/pair 00000000")]);
        let s =
            Script::new(backlog, vec![Box::new(|code| Ok(vec![private(11, ALICE, &format!("/start pair-{code}"))]))]);
        let (user, last_seen) = s.run(&[], false, &mut keep).unwrap();
        assert_eq!((user.id, user.role, last_seen), (ALICE, UserRole::User, 11));
        assert_eq!(*s.offsets.borrow(), vec![-1, 11, 12], "backlog forgotten, then polled after it, then confirmed");
        let sent = s.sent.borrow();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, ALICE);
        assert!(sent[0].1.contains("Paired with MY-PC"), "{}", sent[0].1);
    }

    /// An already paired sender is told so and leaves the code valid; a wrong guess gets no
    /// reply at all; the right code from another account pairs it.
    #[test]
    fn direct_pairing_answers_only_paired_and_successful_senders() {
        let s = Script::new(
            Ok(vec![]),
            vec![
                Box::new(|code| Ok(vec![private(20, ALICE, &format!("/pair {code}"))])),
                Box::new(|code| Ok(vec![private(21, 555, wrong_for(code)), private(22, 556, "/pair")])),
                Box::new(|code| Ok(vec![private(23, BOB, &format!("/pair {} {}", &code[..4], &code[4..]))])),
            ],
        );
        let (user, last_seen) = s.run(&[ALICE], false, &mut keep).unwrap();
        assert_eq!((user.id, last_seen), (BOB, 23));
        assert_eq!(*s.offsets.borrow(), vec![-1, 0, 21, 23, 24]);
        let sent = s.sent.borrow();
        let chats: Vec<i64> = sent.iter().map(|(c, _)| *c).collect();
        assert_eq!(chats, vec![ALICE, BOB], "nothing is sent to the senders of failed attempts");
        assert_eq!(sent[0].1, crate::telegram::ui::already_paired_screen().0);
    }

    #[test]
    fn direct_pairing_ends_after_too_many_wrong_codes() {
        let s = Script::new(
            Ok(vec![]),
            vec![Box::new(|code| Ok((0..5).map(|i| private(30 + i, 600 + i, wrong_for(code))).collect()))],
        );
        let e = s.run(&[], false, &mut keep).unwrap_err();
        assert!(e.contains("invalidated"), "{e}");
        assert!(s.sent.borrow().is_empty());
        assert_eq!(s.offsets.borrow().last(), Some(&35), "the consumed attempts are confirmed");
    }

    /// The service started meanwhile (Telegram reports a second consumer): stop, and do not
    /// confirm anything (that request would cut the service's long poll short).
    #[test]
    fn direct_pairing_gives_way_to_a_started_service() {
        let conflict = || -> Step { Box::new(|_| Err(TgError::Conflict("terminated by other getUpdates".into()))) };
        let s = Script::new(Ok(vec![private(40, BOB, "/menu")]), vec![conflict()]);
        assert_eq!(s.run(&[], true, &mut keep).unwrap_err(), SERVICE_STARTED_MEANWHILE);
        assert_eq!(*s.offsets.borrow(), vec![-1, 41], "no final confirmation");
    }

    #[test]
    fn direct_pairing_token_and_store_failures() {
        let s = Script::new(Err(TgError::Unauthorized), vec![]);
        assert!(s.run(&[], false, &mut keep).unwrap_err().contains("BotFather"));
        assert!(s.code.borrow().is_empty(), "no code is created for a rejected token");
        // the store refuses (e.g. full): the account is not told it is paired
        let s = Script::new(Ok(vec![]), vec![Box::new(|code| Ok(vec![private(50, ALICE, &format!("/pair {code}"))]))]);
        let e = s.run(&[], false, &mut |_| Err("full".to_string())).unwrap_err();
        assert_eq!(e, "full");
        assert!(s.sent.borrow().is_empty());
    }

    #[test]
    fn paired_accounts_are_stored() {
        let store = SettingsStore::in_memory(crate::config::Settings::default());
        let first = add_paired_user(&store, AuthorizedUser::new(ALICE, "@alice", UserRole::User, 1)).unwrap();
        assert_eq!(first.role, UserRole::Admin, "the first account always becomes an Admin");
        let second = add_paired_user(&store, AuthorizedUser::new(BOB, "bob", UserRole::User, 2)).unwrap();
        assert_eq!(second.role, UserRole::User);
        for i in 0..(MAX_AUTHORIZED_USERS as i64 - 2) {
            add_paired_user(&store, AuthorizedUser::new(1000 + i, "u", UserRole::User, 3)).unwrap();
        }
        let e = add_paired_user(&store, AuthorizedUser::new(9999, "late", UserRole::User, 4)).unwrap_err();
        assert!(e.contains("maximum"), "{e}");
        assert!(!store.is_authorized(9999));
    }

    #[test]
    fn backlog_is_skipped() {
        let u = |update_id| Update {
            update_id,
            message: None,
            edited_message: None,
            callback_query: None,
            my_chat_member: None,
        };
        assert_eq!(after_backlog(&[]), (0, 0), "nothing pending: poll from the start");
        assert_eq!(after_backlog(&[u(500)]), (501, 500));
        assert_eq!(after_backlog(&[u(7), u(9), u(8)]), (10, 9));
        assert_eq!(after_backlog(&[u(i64::MAX)]), (i64::MAX, i64::MAX), "no overflow");
    }

    #[test]
    fn roles_and_validity() {
        assert_eq!(role_text(true, Some(false)), "Admin");
        assert_eq!(role_text(true, None), "Admin");
        assert!(role_text(false, Some(true)).starts_with("Admin"));
        assert_eq!(role_text(false, Some(false)), "User");
        assert!(role_text(false, None).starts_with("User"));
        assert_eq!(fmt_validity(45), "45 s");
        assert_eq!(fmt_validity(600), "10 min");
        assert_eq!(fmt_validity(3600), "1 h");
        assert_eq!(fmt_validity(5400), "1 h 30 min");
        assert_eq!(fmt_validity(-5), "0 s");
    }

    #[test]
    fn instruction_text() {
        let t = instructions("12345678", Some("ExampleBot"), 600, "14:35", "User");
        for needle in [
            "Pairing code:  1234 5678\n",
            "Valid for:     10 min (until 14:35), single use\n",
            "Role:          User\n",
            "https://t.me/ExampleBot?start=pair-12345678",
            "send this message to @ExampleBot:   /pair 12345678",
        ] {
            assert!(t.contains(needle), "missing {needle:?} in:\n{t}");
        }
        // unknown or invalid bot username: no link, the message still works
        for bot in [None, Some("bad name/x")] {
            let t = instructions("12345678", bot, 60, "14:35", "Admin");
            assert!(!t.contains("https://"), "{t}");
            assert!(t.contains("send this message to the bot:   /pair 12345678"), "{t}");
            assert!(t.contains("Valid for:     1 min"), "{t}");
        }
    }

    #[test]
    fn ended_messages() {
        let all = [PairingProgress::Expired, PairingProgress::Replaced, PairingProgress::Invalidated];
        let texts: Vec<&str> = all.iter().map(ended_message).collect();
        assert!(texts.iter().all(|t| !t.is_empty()));
        assert!(texts[0].contains("expired") && texts[1].contains("new pairing code"), "{texts:?}");
        assert!(texts[2].contains("too many wrong attempts"), "{texts:?}");
    }

    #[test]
    fn user_table() {
        let users = vec![
            UserInfo { id: ALICE, name: "@alice".into(), role: "admin".into(), added_unix: 1_800_000_000 },
            UserInfo { id: BOB, name: "bob\nInjected".into(), role: "user".into(), added_unix: 0 },
        ];
        let t = format_users(&users, "from the running service", &|_| "25 Nov 2026".to_string());
        assert!(t.starts_with("Telegram users (2 of 20, from the running service):\n"), "{t}");
        assert!(t.contains(&format!("  {ALICE:<14} Admin  25 Nov 2026  @alice\n")), "{t}");
        assert!(t.contains(&format!("  {BOB:<14} User   -            bob Injected\n")), "{t}");
        assert!(t.contains("numeric user id only"));
        let empty = format_users(&[], "from settings.json", &|_| String::new());
        assert!(empty.contains("No Telegram account is paired yet") && empty.contains("pair"), "{empty}");
    }

    #[test]
    fn direct_pairing_needs_a_token() {
        let dir = std::env::temp_dir().join(format!("predator-pair-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        let e = pair_interactive(&data, false, 30).unwrap_err();
        assert!(e.contains("set-token"), "{e}");
        assert!(data.paths.logs_dir().is_dir(), "the data directory is prepared before use");
        assert!(TOKEN_FOR_SERVICE_ONLY.contains("set-token") && TOKEN_FOR_SERVICE_ONLY.contains("set-owner"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn users_in_a_custom_data_dir() {
        let dir = std::env::temp_dir().join(format!("predator-users-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        users_list(&data).unwrap(); // empty list, nothing created
        data.ensure().unwrap();
        let store = data.settings().unwrap();
        store.add_user(AuthorizedUser::new(ALICE, "@alice", UserRole::User, 1_800_000_000)).unwrap();
        store.add_user(AuthorizedUser::new(BOB, "bob", UserRole::User, 1_800_000_100)).unwrap();
        users_list(&data).unwrap();
        assert!(users_remove(&data, 0).is_err());
        assert!(users_remove(&data, 555).unwrap_err().contains("not authorized"));
        // the first account was promoted to admin and is the last one: it stays
        assert_eq!(users_remove(&data, ALICE).unwrap_err(), crate::config::LAST_ADMIN_ERROR);
        assert!(!data.paths.queue().exists(), "refusals queue nothing");
        users_remove(&data, BOB).unwrap();
        let after = data.settings().unwrap();
        assert!(!after.is_authorized(BOB) && after.is_authorized(ALICE));
        // the service is not running: the remaining account is told when it starts
        let q = crate::notify::queue::NotificationQueue::open(&data.paths.queue()).unwrap();
        let n = q.front().expect("removal notice queued");
        assert!(n.html.contains("TELEGRAM USER REMOVED") && n.html.contains("bob"), "{}", n.html);
        assert!(n.delivered_to.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_notices_are_queued_for_the_service() {
        let dir = std::env::temp_dir().join(format!("predator-notice-{}", crate::util::rand::hex(4)));
        let data = DataCtx::new(Some(&dir));
        data.ensure().unwrap();
        let lines = vec![("Name".to_string(), "@alice".to_string())];
        queue_offline_notice(&data, "👤", "NEW TELEGRAM USER PAIRED", &lines, &[ALICE]);
        let q = crate::notify::queue::NotificationQueue::open(&data.paths.queue()).unwrap();
        let n = q.front().expect("queued");
        assert_eq!(n.kind, NotificationKind::Security);
        assert!(n.html.contains("NEW TELEGRAM USER PAIRED"));
        assert_eq!(n.delivered_to, vec![ALICE], "not sent to the new account itself");
        std::fs::remove_dir_all(&dir).ok();
    }
}
