//! Command / callback dispatcher: authorization, feature gating, confirmations, menus.
//!
//! Security model (see docs/ARCHITECTURE.md §6):
//! * Only private chats of authorized users are served: `settings.authorized_users`, checked by
//!   numeric user id (never the username), with chat id == user id. Groups/channels are left
//!   immediately; other users get one "access denied" reply per hour and every authorized user
//!   is alerted (rate limited, bounded memory).
//! * Pairing: `/pair CODE` or the deep link `/start pair-CODE` from ANY private chat is checked
//!   against the single active code ([`crate::pairing`]) before the unauthorized rejection. A
//!   valid code adds the sender (and tells everyone else); every failure gets exactly the reply
//!   of any other unauthorized message, so nobody can learn whether a code is active. Codes are
//!   never logged (pairing attempts are logged with the code hidden).
//! * `/users` lists the accounts; admins can remove other users (immediately, no confirmation).
//!   A removed user loses access with the next update.
//! * State-changing commands older than `stale_command_secs` are not executed.
//! * A button press carries no timestamp, so state-changing presses (lock, logout, Tailscale
//!   up/down, feature toggles, power requests and confirmations, removing a user) are not
//!   executed when the poller marks them as backlog — delivered in the first batch after a start
//!   or an outage ([`Bot::handle_update_with`]). Read-only navigation still works.
//! * Only shutdown/restart/sleep/hibernate need a confirmation. Every user has at most one
//!   pending confirmation (per chat): only that user can confirm or cancel it. It is *taken*
//!   atomically when confirmed, so it can execute at most once, and it expires after
//!   `confirm_timeout_secs`.
//! * Tailscale up/down run on a short-lived worker thread (one at a time) so polling continues.
//!
//! Chat cleanup (see [`super::janitor`]), per chat: every reply the bot sends and every message
//! a user sends is short-lived. When the user sends something new, the earlier ones in that chat
//! are deleted (after the new reply went out), except the message holding their pending power
//! confirmation; `/clear` deletes everything in that chat at once. Button presses edit in place
//! and keep their menu alive.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::janitor::{self, TrackedMessage};
use super::types::{CallbackQuery, Chat, ChatMemberUpdated, Message, Update, User};
use super::ui::{self, CallbackAction, Nav, Screen};
use super::{Telegram, TgError};
use crate::config::{AddUserOutcome, AuthorizedUser, MAX_AUTHORIZED_USERS};
use crate::context::AppContext;
use crate::features::Feature;
use crate::notify::NotificationKind;
use crate::sys::{PowerAction, SystemActions};
use crate::util::time::now_unix;
use crate::util::truncate_chars;

/// One "access denied" reply + user alert per unauthorized user per this many seconds.
const DENIED_NOTICE_INTERVAL_SECS: i64 = 3600;
/// Upper bound of the unauthorized-user rate-limit table.
const MAX_DENIED_TRACKED: usize = 256;
/// Characters of foreign message text that may be logged / forwarded to the users.
const LOG_TEXT_CHARS: usize = 64;
/// Upper bound of pending power confirmations (one per authorized user).
const MAX_PENDING: usize = MAX_AUTHORIZED_USERS;
/// Entries shown on the login history screen.
const HISTORY_ITEMS: usize = 10;
/// Telegram limit for callback answer texts.
const MAX_CALLBACK_ANSWER: usize = 200;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ───────────────────────────── pure helpers ─────────────────────────────

/// A parsed slash command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    /// Read-only screen (`/start`, `/menu`, `/status`, `/tailscale status`, ...).
    Show(Nav),
    Power(PowerAction),
    Lock,
    Logout,
    Cancel,
    /// `/clear`: delete the short-lived chat messages now.
    Clear,
    TailscaleUp,
    TailscaleDown,
    /// `/tailscale <something unknown>`.
    TailscaleUsage,
    /// `/users`: the authorized Telegram accounts.
    Users,
    /// `/pair` from an account that is already paired (strangers' pairing attempts are handled
    /// before authorization, see [`pairing_payload`]).
    Pair,
    Unknown,
}

impl Command {
    /// The display form (e.g. `/lock`) of commands that change state; `None` for read-only ones.
    fn state_changing_label(self) -> Option<String> {
        match self {
            Command::Power(a) => Some(format!("/{}", a.key())),
            Command::Lock => Some("/lock".into()),
            Command::Logout => Some("/logout".into()),
            Command::TailscaleUp => Some("/tailscale up".into()),
            Command::TailscaleDown => Some("/tailscale down".into()),
            Command::Show(_)
            | Command::Cancel
            | Command::Clear
            | Command::TailscaleUsage
            | Command::Users
            | Command::Pair
            | Command::Unknown => None,
        }
    }
}

/// Split `/name@botname args` into the lower-cased command name (without slash and bot
/// suffix) and the trimmed argument string. `None` when the text is not a command.
fn split_command(text: &str) -> Option<(String, &str)> {
    let rest = text.trim().strip_prefix('/')?;
    let (token, args) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim()),
        None => (rest, ""),
    };
    let name = token.split('@').next().unwrap_or_default();
    Some((name.to_ascii_lowercase(), args))
}

fn classify(name: &str, args: &str) -> Command {
    match name {
        "start" | "menu" => Command::Show(Nav::Main),
        "help" => Command::Show(Nav::Help),
        "status" => Command::Show(Nav::Status),
        "network" => Command::Show(Nav::Network),
        "battery" => Command::Show(Nav::Battery),
        "history" => Command::Show(Nav::History),
        "features" => Command::Show(Nav::Features),
        "lock" => Command::Lock,
        "logout" => Command::Logout,
        "cancel" => Command::Cancel,
        "clear" => Command::Clear,
        "users" => Command::Users,
        "pair" => Command::Pair,
        "tailscale" => {
            let sub = args.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
            match sub.as_str() {
                "" | "status" => Command::Show(Nav::Tailscale),
                "up" => Command::TailscaleUp,
                "down" => Command::TailscaleDown,
                _ => Command::TailscaleUsage,
            }
        }
        other => PowerAction::from_key(other).map(Command::Power).unwrap_or(Command::Unknown),
    }
}

/// Whether `m` is the `/clear` command (handled before the usual dispatch, because it deletes
/// the message itself together with everything else).
fn is_clear_command(m: &Message) -> bool {
    split_command(m.text.as_deref().unwrap_or_default())
        .is_some_and(|(name, args)| classify(&name, args) == Command::Clear)
}

/// True when a state-changing command must not run because it is too old. A missing date
/// (≤ 0) cannot be verified and therefore counts as stale (fail-safe).
fn is_stale(message_date: i64, now: i64, stale_secs: u64) -> bool {
    if message_date <= 0 {
        return true;
    }
    let limit = i64::try_from(stale_secs).unwrap_or(i64::MAX);
    now.saturating_sub(message_date) > limit
}

/// The private chat of an authorized user, sent by that user (`authorized` = the sender's
/// numeric id is in the user list). Usernames are never consulted.
fn is_user_chat(authorized: bool, from_id: i64, chat: &Chat) -> bool {
    authorized && from_id > 0 && chat.is_private() && chat.id == from_id
}

/// The code part of a pairing attempt: `/pair CODE` (the code may be empty) or the deep-link
/// start `/start pair-CODE` / `/start pair_CODE`. `None` for every other message.
fn pairing_payload(text: &str) -> Option<String> {
    let (name, args) = split_command(text)?;
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

/// Message text for log lines and alerts: sanitized and truncated, with any pairing code hidden
/// (even a wrong guess may be close to the active code).
fn log_text(text: &str) -> String {
    match split_command(text) {
        Some((name, _)) if pairing_payload(text).is_some() => format!("/{} (pairing code hidden)", sanitize(&name, 16)),
        _ => sanitize(text, LOG_TEXT_CHARS),
    }
}

/// Replace control characters and quotes, then truncate — safe for one log line.
fn sanitize(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_control() {
                ' '
            } else if c == '"' {
                '\''
            } else {
                c
            }
        })
        .collect();
    truncate_chars(cleaned.trim(), max)
}

fn full_name(u: &User) -> String {
    match u.last_name.as_deref().filter(|l| !l.is_empty()) {
        Some(last) => format!("{} {}", u.first_name, last),
        None => u.first_name.clone(),
    }
}

fn describe_user(u: Option<&User>) -> String {
    match u {
        None => "unknown sender".into(),
        Some(u) => {
            let uname = u.username.as_deref().map(|n| format!(" @{}", sanitize(n, 64))).unwrap_or_default();
            format!("user_id={}{} name=\"{}\"", u.id, uname, sanitize(&full_name(u), 64))
        }
    }
}

/// Per-user "last notified" table with bounded size.
#[derive(Default)]
struct DeniedLimiter {
    last: HashMap<i64, i64>,
}

impl DeniedLimiter {
    /// Whether `user_id` may get a reply / user alert now (records it when allowed).
    fn allow(&mut self, user_id: i64, now: i64) -> bool {
        let fresh = |t: i64| now >= t && now - t < DENIED_NOTICE_INTERVAL_SECS;
        if let Some(&t) = self.last.get(&user_id) {
            if fresh(t) {
                return false;
            }
        } else if self.last.len() >= MAX_DENIED_TRACKED {
            self.last.retain(|_, t| fresh(*t));
            if self.last.len() >= MAX_DENIED_TRACKED
                && let Some(oldest) = self.last.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k)
            {
                self.last.remove(&oldest);
            }
        }
        self.last.insert(user_id, now);
        true
    }
}

/// An outstanding power confirmation (at most one per chat, i.e. per user).
struct Pending {
    action: PowerAction,
    nonce: String,
    created: Instant,
    /// Wall-clock creation time: a dialog older than its user's pairing (removed and paired
    /// again meanwhile) can never be confirmed.
    created_unix: i64,
    chat_id: i64,
    message_id: i64,
}

/// How a callback query is answered once handled.
enum Ack {
    Silent,
    Toast(String),
    Alert(String),
    /// Already answered by the handler.
    Done,
}

/// Clears the Tailscale busy flag when dropped (also during unwinding).
struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// ───────────────────────────── the bot ─────────────────────────────

struct Inner {
    ctx: Arc<AppContext>,
    tg: Arc<dyn Telegram>,
    sys: Arc<dyn SystemActions>,
    /// Pending power confirmations by chat id (bounded by [`MAX_PENDING`]).
    pending: Mutex<HashMap<i64, Pending>>,
    denied: Mutex<DeniedLimiter>,
    ts_busy: AtomicBool,
    /// Worker threads started in tests, so they can be joined deterministically.
    #[cfg(test)]
    workers: Mutex<Vec<JoinHandle<()>>>,
}

/// The Telegram command dispatcher. Cheap to clone (shared state behind `Arc`).
#[derive(Clone)]
pub struct Bot {
    inner: Arc<Inner>,
}

impl Bot {
    pub fn new(ctx: Arc<AppContext>, tg: Arc<dyn Telegram>, sys: Arc<dyn SystemActions>) -> Self {
        Self {
            inner: Arc::new(Inner {
                ctx,
                tg,
                sys,
                pending: Mutex::new(HashMap::new()),
                denied: Mutex::new(DeniedLimiter::default()),
                ts_busy: AtomicBool::new(false),
                #[cfg(test)]
                workers: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Process one update. Never panics outward; every failure is logged and, where possible,
    /// reported to the user. Slow operations (Tailscale up/down) run on a short-lived worker
    /// thread so polling continues. Same as `handle_update_with(update, false)`.
    pub fn handle_update(&self, update: &Update) {
        self.handle_update_with(update, false);
    }

    /// Process one update. `from_backlog` marks an update that Telegram had queued while
    /// PREDATOR was not polling (the first `getUpdates` batch after a start or an outage): its
    /// state-changing button presses (`act:*`, `ts:*`, `ft:*`, `pw:*`, `cf:*`) are then NOT
    /// executed — a callback has no press time, so it could otherwise run hours late — and the
    /// user is told to press again. Read-only buttons and `cx:*` work as usual; messages keep
    /// their own `message.date` staleness rule either way.
    pub fn handle_update_with(&self, update: &Update, from_backlog: bool) {
        if catch_unwind(AssertUnwindSafe(|| self.dispatch(update, from_backlog))).is_err() {
            crate::log_error!("telegram: internal error (panic) while handling update {}", update.update_id);
        }
    }

    /// Commands registered with `setMyCommands` (command without slash, description).
    pub fn command_list() -> Vec<(&'static str, &'static str)> {
        vec![
            ("menu", "Open the control panel"),
            ("status", "System status"),
            ("network", "Network information"),
            ("battery", "Battery status"),
            ("history", "Recent logins"),
            ("features", "Switch features on or off"),
            ("tailscale", "Tailscale status and Up/Down"),
            ("lock", "Lock the PC (immediate)"),
            ("logout", "Log off the active user (immediate)"),
            ("shutdown", "Shut down (asks for confirmation)"),
            ("restart", "Restart (asks for confirmation)"),
            ("sleep", "Sleep (asks for confirmation)"),
            ("hibernate", "Hibernate (asks for confirmation)"),
            ("cancel", "Cancel a pending confirmation"),
            ("clear", "Delete menus and replies from this chat"),
            ("users", "Paired Telegram accounts (admins can remove them)"),
            ("pair", "Pair this Telegram account with a code from the PC"),
            ("help", "All commands and the security policy"),
        ]
    }

    // ───────────── Telegram I/O helpers ─────────────

    /// Send a reply to a user. Every reply is short-lived: it is tracked for the automatic
    /// chat cleanup (when enabled).
    fn send(&self, chat: i64, sc: &Screen) -> Option<i64> {
        match self.inner.tg.send_message(chat, &sc.0, sc.1.as_ref()) {
            Ok(id) => {
                self.inner.ctx.track_chat_message(chat, id, now_unix());
                Some(id)
            }
            Err(e) => {
                crate::log_warn!("telegram: sendMessage failed: {e}");
                None
            }
        }
    }

    /// Edit without fallback. Returns whether Telegram accepted the edit.
    fn edit_only(&self, chat: i64, message_id: i64, sc: &Screen) -> bool {
        match self.inner.tg.edit_message(chat, message_id, &sc.0, sc.1.as_ref()) {
            Ok(()) => true,
            Err(e) => {
                crate::log_debug!("telegram: editMessageText({message_id}) failed: {e}");
                false
            }
        }
    }

    /// Edit `message_id` in place; when Telegram refuses (message deleted, too old ...) send the
    /// screen as a new message. Returns the id of the message now showing it.
    fn edit_or_send(&self, chat: i64, message_id: i64, sc: &Screen) -> Option<i64> {
        match self.inner.tg.edit_message(chat, message_id, &sc.0, sc.1.as_ref()) {
            Ok(()) => Some(message_id),
            Err(TgError::BadRequest(e)) => {
                crate::log_debug!("telegram: edit of {message_id} refused ({e}); sending a new message");
                self.send(chat, sc)
            }
            Err(e) => {
                crate::log_warn!("telegram: editMessageText failed: {e}");
                None
            }
        }
    }

    /// Edit `existing` (button press) or send a new message (slash command).
    fn show(&self, chat: i64, existing: Option<i64>, sc: &Screen) -> Option<i64> {
        match existing {
            Some(id) => self.edit_or_send(chat, id, sc),
            None => self.send(chat, sc),
        }
    }

    fn answer(&self, callback_id: &str, text: Option<&str>, alert: bool) {
        let text = text.map(|t| truncate_chars(t, MAX_CALLBACK_ANSWER));
        if let Err(e) = self.inner.tg.answer_callback(callback_id, text.as_deref(), alert) {
            crate::log_debug!("telegram: answerCallbackQuery failed: {e}");
        }
    }

    fn leave_chat(&self, chat: &Chat, from: Option<&User>, what: &str) {
        crate::logging::security_untrusted(
            &format!("tg-chat:{}", chat.id),
            &format!(
                "Telegram {what} in non-private chat id={} type={} title=\"{}\" from {}; leaving the chat",
                chat.id,
                sanitize(&chat.kind, 16),
                sanitize(chat.title.as_deref().unwrap_or_default(), 64),
                describe_user(from)
            ),
        );
        if let Err(e) = self.inner.tg.leave_chat(chat.id) {
            crate::log_warn!("telegram: leaveChat({}) failed: {e}", chat.id);
        }
    }

    // ───────────── dispatch ─────────────

    fn dispatch(&self, u: &Update, from_backlog: bool) {
        if let Some(m) = &u.my_chat_member {
            self.on_chat_member(m);
        }
        if let Some(m) = &u.message {
            // messages carry their own date: the stale-command rule covers them
            self.on_message(m);
        }
        if let Some(m) = &u.edited_message {
            self.on_edited_message(m);
        }
        if let Some(cq) = &u.callback_query {
            self.on_callback(cq, from_backlog);
        }
    }

    fn on_chat_member(&self, m: &ChatMemberUpdated) {
        if m.chat.is_private() {
            crate::log_debug!("telegram: private chat membership changed (bot blocked/unblocked)");
            return;
        }
        self.leave_chat(&m.chat, Some(&m.from), "membership change");
    }

    fn on_edited_message(&self, m: &Message) {
        if !m.chat.is_private() {
            self.leave_chat(&m.chat, m.from.as_ref(), "edited message");
            return;
        }
        // Edited messages are never executed (an edit must not re-trigger or alter a command).
        crate::log_debug!("telegram: ignoring edited message {}", m.message_id);
    }

    fn on_message(&self, m: &Message) {
        if !m.chat.is_private() {
            self.leave_chat(&m.chat, m.from.as_ref(), "message");
            return;
        }
        let Some(from) = m.from.as_ref() else {
            crate::logging::security_untrusted(
                &format!("tg-chat:{}", m.chat.id),
                &format!("Telegram message without sender in private chat {}; ignored", m.chat.id),
            );
            return;
        };
        if !self.is_user_chat(from.id, &m.chat) {
            // A pairing code is the only thing an unauthorized sender can use.
            match pairing_payload(m.text.as_deref().unwrap_or_default()) {
                Some(code) => self.try_pair(m, from, &code),
                None => self.deny_message(m, from, None),
            }
            return;
        }
        if is_clear_command(m) {
            self.clear_chat(m);
            return;
        }
        // The user moved on: the earlier short-lived messages of this chat go — deleted only
        // after the new reply was sent, so the answer shows up without delay. They stay in the
        // janitor's list until then, so a failure while handling the command cannot make them
        // permanent.
        let previous = self.note_previous(m);
        self.on_user_message(m);
        self.delete_previous(m.chat.id, &previous);
    }

    /// Whether `from_id` is an authorized user writing in their own private chat.
    fn is_user_chat(&self, from_id: i64, chat: &Chat) -> bool {
        is_user_chat(self.inner.ctx.settings.is_authorized(from_id), from_id, chat)
    }

    /// An authorized message from a user in their private chat (not `/clear`).
    fn on_user_message(&self, m: &Message) {
        let chat = m.chat.id;
        let text = m.text.as_deref().unwrap_or_default();
        if pairing_payload(text).is_some() {
            // the code is not checked (and not used up): this account is paired already
            crate::log_info!("telegram: user {chat} sent a pairing code but is already paired");
            self.send(chat, &ui::already_paired_screen());
            return;
        }
        let Some((name, args)) = split_command(text) else {
            self.send(chat, &ui::plain_text_hint());
            return;
        };
        let cmd = classify(&name, args);
        crate::log_info!("telegram: command /{} from user {chat}", sanitize(&name, 32));
        if let Some(label) = cmd.state_changing_label() {
            let stale_secs = self.inner.ctx.settings.get().stale_command_secs;
            let now = now_unix();
            if is_stale(m.date, now, stale_secs) {
                crate::log_warn!(
                    "telegram: ignored stale command {label} (sent at {}, now {now}, limit {stale_secs}s)",
                    m.date
                );
                self.send(chat, &(ui::stale_text(&label, m.date, now, stale_secs), None));
                return;
            }
        }
        self.run_command(cmd, chat);
    }

    /// A pairing attempt (`/pair CODE`, `/start pair-CODE`) from a sender who is not an
    /// authorized user in their own private chat. Success adds the account and tells every other
    /// user; any failure is answered exactly like every other unauthorized message.
    fn try_pair(&self, m: &Message, from: &User, input: &str) {
        let ctx = &self.inner.ctx;
        if from.is_bot || from.id <= 0 || m.chat.id != from.id {
            self.deny_message(m, from, Some("pairing refused: not the sender's own private chat"));
            return;
        }
        if ctx.settings.is_authorized(from.id) {
            // authorized, but not in their own private chat: an ordinary denial
            self.deny_message(m, from, None);
            return;
        }
        let now = now_unix();
        let role = match ctx.pairing.redeem(input, from.id, now) {
            Ok(role) => role,
            Err(e) => {
                self.deny_message(m, from, Some(&format!("pairing failed: {}", e.describe())));
                return;
            }
        };
        let name = AuthorizedUser::display_name(from.username.as_deref(), &from.first_name);
        let candidate = AuthorizedUser::new(from.id, &name, role, now);
        match ctx.settings.add_user(candidate.clone()) {
            Ok(AddUserOutcome::Added) => {}
            Ok(AddUserOutcome::AlreadyAuthorized) => {
                self.send(m.chat.id, &ui::already_paired_screen());
                return;
            }
            Ok(AddUserOutcome::LimitReached) => {
                crate::log_warn!(
                    "telegram: pairing code redeemed by user {}, but {MAX_AUTHORIZED_USERS} users are paired already",
                    from.id
                );
                self.deny_message(m, from, Some("pairing refused: the user limit is reached"));
                return;
            }
            Err(e) => {
                crate::log_error!("telegram: cannot add the paired user {}: {e}", from.id);
                self.deny_message(m, from, Some("pairing failed: settings.json could not be saved"));
                return;
            }
        }
        // the first user of an empty list is promoted to admin by the store
        let user = ctx.settings.user(from.id).unwrap_or(candidate);
        ctx.pairing.record_paired(user.clone());
        crate::logging::security(&format!(
            "Telegram {} paired with a pairing code as {}",
            describe_user(Some(from)),
            user.role.label()
        ));
        // the pairing message and the reply are short-lived, like any other command in the chat
        ctx.track_chat_message(m.chat.id, m.message_id, m.date);
        self.send(m.chat.id, &ui::paired_screen(&ctx.computer_name));
        let lines = vec![
            ("Name".to_string(), user.label()),
            ("User ID".to_string(), user.id.to_string()),
            ("Role".to_string(), user.role.label().to_string()),
            ("Computer".to_string(), ctx.computer_name.clone()),
        ];
        if let Err(e) =
            ctx.emit_notice(NotificationKind::Security, "👤", "NEW TELEGRAM USER PAIRED", &lines, &[user.id])
        {
            crate::log_error!("could not queue the new-user notification: {e}");
        }
    }

    /// The reply to every unauthorized private message (also every failed pairing attempt): a
    /// security log line (with `why`, local only) and — at most once per user per hour — the
    /// access-denied reply plus an alert to every authorized user.
    fn deny_message(&self, m: &Message, from: &User, why: Option<&str>) {
        let text = m.text.as_deref().map(log_text).unwrap_or_else(|| "(non-text message)".to_string());
        let why = why.map(|w| format!(" — {w}")).unwrap_or_default();
        crate::logging::security_untrusted(
            &format!("tg:{}", from.id),
            &format!(
                "unauthorized Telegram message from {} chat_id={}: \"{text}\"{why}",
                describe_user(Some(from)),
                m.chat.id
            ),
        );
        if !lock(&self.inner.denied).allow(from.id, now_unix()) {
            return;
        }
        if let Err(e) = self.inner.tg.send_message(m.chat.id, ui::ACCESS_DENIED, None) {
            crate::log_warn!("telegram: could not send the access-denied reply: {e}");
        }
        let lines = vec![
            ("User ID".to_string(), from.id.to_string()),
            (
                "Username".to_string(),
                from.username.as_deref().map(|u| format!("@{u}")).unwrap_or_else(|| "(none)".into()),
            ),
            ("Name".to_string(), truncate_chars(&full_name(from), 64)),
            ("Message".to_string(), text),
        ];
        if let Err(e) = self.inner.ctx.emit_security("UNAUTHORIZED ACCESS ATTEMPT", &lines) {
            crate::log_error!("could not queue the unauthorized-access alert: {e}");
        }
    }

    fn run_command(&self, cmd: Command, chat: i64) {
        match cmd {
            Command::Show(nav) => {
                let sc = self.nav_screen(nav);
                self.send(chat, &sc);
            }
            Command::Power(action) => self.request_power(action, chat, None),
            Command::Lock => {
                let sc = self.lock_screen();
                self.send(chat, &sc);
            }
            Command::Logout => {
                let sc = self.logout_screen();
                self.send(chat, &sc);
            }
            Command::Cancel => self.cancel_command(chat),
            // handled before dispatch (it needs the /clear message itself); nothing to delete here
            Command::Clear => {}
            Command::TailscaleUp | Command::TailscaleDown => {
                if let Some(sc) = self.gate(Feature::TailscaleManagement) {
                    self.send(chat, &sc);
                } else if !self.start_tailscale(cmd == Command::TailscaleUp, chat, None) {
                    self.send(chat, &(ui::TAILSCALE_BUSY.to_string(), None));
                }
            }
            Command::TailscaleUsage => {
                self.send(chat, &ui::tailscale_usage());
            }
            Command::Users => {
                let sc = self.users_screen(chat);
                self.send(chat, &sc);
            }
            Command::Pair => {
                self.send(chat, &ui::already_paired_screen());
            }
            Command::Unknown => {
                self.send(chat, &ui::unknown_command());
            }
        }
    }

    fn on_callback(&self, cq: &CallbackQuery, from_backlog: bool) {
        let data = cq.data.as_deref().unwrap_or_default();
        let Some(msg) = cq.message.as_ref() else {
            crate::logging::security_untrusted(
                &format!("tg:{}", cq.from.id),
                &format!(
                    "Telegram button press without message from {} data=\"{}\"; rejected",
                    describe_user(Some(&cq.from)),
                    sanitize(data, LOG_TEXT_CHARS)
                ),
            );
            self.answer(&cq.id, Some(ui::NOT_AUTHORIZED), true);
            return;
        };
        if !msg.chat.is_private() {
            self.answer(&cq.id, Some(ui::NOT_AUTHORIZED), true);
            self.leave_chat(&msg.chat, Some(&cq.from), "button press");
            return;
        }
        if !self.is_user_chat(cq.from.id, &msg.chat) {
            crate::logging::security_untrusted(
                &format!("tg:{}", cq.from.id),
                &format!(
                    "unauthorized Telegram button press from {} chat_id={} data=\"{}\"",
                    describe_user(Some(&cq.from)),
                    msg.chat.id,
                    sanitize(data, LOG_TEXT_CHARS)
                ),
            );
            self.answer(&cq.id, Some(ui::NOT_AUTHORIZED), true);
            return;
        }
        self.keep_alive(msg);
        let ack = match CallbackAction::parse(data) {
            Some(action) if from_backlog && action.changes_state() => {
                self.ignore_backlogged(&action, msg.chat.id, msg.message_id)
            }
            Some(action) => self.run_callback(action, &cq.id, msg.chat.id, msg.message_id),
            None => {
                crate::log_warn!("telegram: unknown callback data \"{}\"", sanitize(data, LOG_TEXT_CHARS));
                Ack::Toast(ui::UNKNOWN_BUTTON.to_string())
            }
        };
        match ack {
            Ack::Silent => self.answer(&cq.id, None, false),
            Ack::Toast(t) => self.answer(&cq.id, Some(&t), false),
            Ack::Alert(t) => self.answer(&cq.id, Some(&t), true),
            Ack::Done => {}
        }
    }

    /// A state-changing button press delivered from Telegram's backlog: do nothing, tell the
    /// user, offer the button again. A late confirmation also discards its pending dialog, so
    /// that power action can never run from it.
    fn ignore_backlogged(&self, action: &CallbackAction, chat: i64, message_id: i64) -> Ack {
        crate::log_warn!(
            "telegram: ignored button press {} — queued while PREDATOR was offline",
            sanitize(&action.log_label(), LOG_TEXT_CHARS)
        );
        if let CallbackAction::Confirm(nonce) = action
            && let Some(p) = self.take_pending(chat, nonce)
        {
            crate::log_info!("telegram: {} confirmation discarded (pressed while offline)", p.action.key());
            if p.message_id != message_id {
                self.edit_only(p.chat_id, p.message_id, &ui::power_expired(p.action));
            }
        }
        let sc = ui::backlog_ignored_screen(action, &self.inner.ctx.settings.get().features);
        self.edit_or_send(chat, message_id, &sc);
        Ack::Silent
    }

    fn run_callback(&self, action: CallbackAction, callback_id: &str, chat: i64, message_id: i64) -> Ack {
        match action {
            CallbackAction::Nav(nav) => {
                // Answer first: some screens (Tailscale, network) take a moment to build.
                self.answer(callback_id, None, false);
                let sc = self.nav_screen(nav);
                self.edit_or_send(chat, message_id, &sc);
                Ack::Done
            }
            CallbackAction::ToggleFeature(f) => match self.inner.ctx.settings.toggle_feature(f) {
                Ok(on) => {
                    crate::logging::security(&format!(
                        "feature {} {} via Telegram",
                        f.key(),
                        if on { "enabled" } else { "disabled" }
                    ));
                    let sc = ui::features_screen(&self.inner.ctx.settings.get().features);
                    self.edit_or_send(chat, message_id, &sc);
                    Ack::Toast(ui::feature_toggled_text(f, on))
                }
                Err(e) => {
                    crate::log_error!("could not save feature {}: {e}", f.key());
                    Ack::Alert(format!("❌ Could not save the setting: {e}"))
                }
            },
            CallbackAction::Power(a) => {
                self.request_power(a, chat, Some(message_id));
                Ack::Silent
            }
            CallbackAction::Lock => {
                let sc = self.lock_screen();
                self.edit_or_send(chat, message_id, &sc);
                Ack::Silent
            }
            CallbackAction::Logout => {
                let sc = self.logout_screen();
                self.edit_or_send(chat, message_id, &sc);
                Ack::Silent
            }
            CallbackAction::TailscaleUp | CallbackAction::TailscaleDown => {
                if let Some(sc) = self.gate(Feature::TailscaleManagement) {
                    self.edit_or_send(chat, message_id, &sc);
                    Ack::Silent
                } else if self.start_tailscale(action == CallbackAction::TailscaleUp, chat, Some(message_id)) {
                    Ack::Silent
                } else {
                    Ack::Alert(ui::TAILSCALE_BUSY.to_string())
                }
            }
            CallbackAction::Confirm(nonce) => self.confirm(callback_id, chat, &nonce),
            CallbackAction::Cancel(nonce) => self.cancel_callback(chat, &nonce),
            CallbackAction::UsersRefresh => {
                self.answer(callback_id, None, false);
                let sc = self.users_screen(chat);
                self.edit_or_send(chat, message_id, &sc);
                Ack::Done
            }
            CallbackAction::RemoveUser(target) => self.remove_user(chat, target, message_id),
        }
    }

    // ───────────── users ─────────────

    /// The user list as `viewer` sees it (remove buttons for admins).
    fn users_screen(&self, viewer: i64) -> Screen {
        ui::users_screen(&self.inner.ctx.settings.authorized_users(), viewer)
    }

    /// `um:rm:<target>` pressed by `viewer` on `message_id` (the user list in the viewer's chat).
    /// Admins only, immediate (no confirmation, see the confirmation policy). The removed user
    /// loses access with the next update; every remaining user is told.
    fn remove_user(&self, viewer: i64, target: i64, message_id: i64) -> Ack {
        let ctx = &self.inner.ctx;
        let Some(me) = ctx.settings.user(viewer) else { return Ack::Alert(ui::NOT_AUTHORIZED.to_string()) };
        if !me.role.is_admin() {
            crate::logging::security(&format!(
                "Telegram user {viewer} tried to remove Telegram user {target} but is not an admin; refused"
            ));
            return Ack::Alert(ui::ONLY_ADMINS.to_string());
        }
        if target == viewer {
            return Ack::Alert(ui::CANNOT_REMOVE_SELF.to_string());
        }
        let ack = match ctx.settings.remove_user(target) {
            Ok(removed) => {
                crate::logging::security(&format!(
                    "Telegram user {} ({}) removed via Telegram by {} ({})",
                    removed.id,
                    sanitize(&removed.label(), 64),
                    me.id,
                    sanitize(&me.label(), 64)
                ));
                self.discard_pending(removed.id);
                let lines = vec![
                    ("Name".to_string(), removed.label()),
                    ("User ID".to_string(), removed.id.to_string()),
                    ("Role".to_string(), removed.role.label().to_string()),
                    ("Removed by".to_string(), format!("{} ({})", me.label(), me.id)),
                ];
                if let Err(e) = ctx.emit_notice(NotificationKind::Security, "🗑", "TELEGRAM USER REMOVED", &lines, &[])
                {
                    crate::log_error!("could not queue the user-removed notification: {e}");
                }
                Ack::Toast(format!("Removed {}", removed.label()))
            }
            Err(e) => {
                crate::log_info!("telegram: removing user {target} refused: {e}");
                Ack::Alert(e)
            }
        };
        let sc = self.users_screen(viewer);
        self.edit_or_send(viewer, message_id, &sc);
        ack
    }

    // ───────────── chat cleanup ─────────────

    /// Before handling a new user message: note (read-only) every earlier short-lived message of
    /// the chat except a confirmation that can still be confirmed, and track the new message
    /// itself. Nothing happens when automatic cleaning is off.
    fn note_previous(&self, m: &Message) -> Vec<i64> {
        if self.inner.ctx.auto_clean_after().is_none() {
            return Vec::new();
        }
        // an expired confirmation no longer needs its dialog: clean it with the rest
        self.release_expired_confirmation();
        let janitor = &self.inner.ctx.janitor;
        let now = now_unix();
        let previous = janitor.deletable_ids(m.chat.id, &[m.message_id], now);
        janitor.track(m.chat.id, m.message_id, m.date, now);
        previous
    }

    /// After the reply: delete the messages noted by [`Bot::note_previous`] (those still tracked
    /// and not protected meanwhile).
    fn delete_previous(&self, chat: i64, ids: &[i64]) {
        if ids.is_empty() {
            return;
        }
        let taken = self.inner.ctx.janitor.take_ids(chat, ids, now_unix());
        self.purge(&taken);
    }

    /// Chat cleanup: a confirmation dialog is protected from deletion only while it can still be
    /// confirmed. Once it has expired it is an ordinary short-lived message again — deleted with
    /// the next command or by the time-based sweep — while the pending entry stays, so a late
    /// press still answers "Confirmation expired". Called before every cleanup: by the next user
    /// message and by the poller's sweep (for every chat). Returns whether a dialog was released.
    pub fn release_expired_confirmation(&self) -> bool {
        if lock(&self.inner.pending).is_empty() {
            return false; // the common case: no settings snapshot, no scan
        }
        let timeout = Duration::from_secs(self.inner.ctx.settings.get().confirm_timeout_secs);
        let expired: Vec<(i64, i64, PowerAction)> = lock(&self.inner.pending)
            .values()
            .filter(|p| p.created.elapsed() >= timeout)
            .map(|p| (p.chat_id, p.message_id, p.action))
            .collect();
        let janitor = &self.inner.ctx.janitor;
        let mut released = false;
        for (chat, message_id, action) in expired {
            if janitor.is_protected(chat, message_id) {
                janitor.unprotect(chat, message_id);
                crate::log_debug!("telegram: expired {} confirmation released for the chat cleanup", action.key());
                released = true;
            }
        }
        released
    }

    /// A button was pressed on `msg`: the menu is in use, so its inactivity timeout restarts (a
    /// menu sent before a restart is tracked from now on). Telegram reports messages it can no
    /// longer serve with date 0 — those are left alone.
    fn keep_alive(&self, msg: &Message) {
        if msg.date > 0 && self.inner.ctx.auto_clean_after().is_some() {
            self.inner.ctx.janitor.touch(msg.chat.id, msg.message_id, msg.date, now_unix());
        }
    }

    /// Delete `entries` now (failures with a retryable error are retried by the next sweep).
    fn purge(&self, entries: &[TrackedMessage]) -> usize {
        if entries.is_empty() {
            return 0;
        }
        janitor::purge(&*self.inner.tg, &self.inner.ctx.janitor, entries, now_unix())
    }

    /// `/clear`: delete every tracked short-lived message of the chat at once, including the
    /// `/clear` message itself and the user's pending confirmation dialog (that confirmation is
    /// discarded — it can no longer be pressed). No reply, no confirmation. Other chats are not
    /// touched.
    fn clear_chat(&self, m: &Message) {
        let chat = m.chat.id;
        crate::log_info!("telegram: command /clear from user {chat}");
        if self.inner.ctx.auto_clean_after().is_none() {
            self.send(chat, &ui::clear_disabled());
            return;
        }
        let pending = lock(&self.inner.pending).remove(&chat);
        if let Some(p) = pending {
            self.release(&p);
            crate::log_info!("telegram: {} confirmation discarded by /clear", p.action.key());
        }
        let janitor = &self.inner.ctx.janitor;
        let now = now_unix();
        janitor.track(chat, m.message_id, m.date, now);
        let all = janitor.take_all_except(chat, &[], now);
        let deleted = self.purge(&all);
        crate::log_info!("telegram: /clear deleted {deleted} of {} message(s)", all.len());
    }

    /// The pending confirmation `p` was taken: its message may be cleaned again.
    fn release(&self, p: &Pending) {
        self.inner.ctx.janitor.unprotect(p.chat_id, p.message_id);
    }

    /// Drop the pending confirmation of `chat` (its user was removed): it can never be confirmed.
    fn discard_pending(&self, chat: i64) {
        let taken = lock(&self.inner.pending).remove(&chat);
        if let Some(p) = taken {
            self.release(&p);
            crate::log_info!("telegram: {} confirmation of removed user {chat} discarded", p.action.key());
        }
    }

    // ───────────── screens ─────────────

    /// `Some(rejection)` when `f` is disabled.
    fn gate(&self, f: Feature) -> Option<Screen> {
        (!self.inner.ctx.settings.feature(f)).then(|| ui::disabled_screen(f))
    }

    fn nav_screen(&self, nav: Nav) -> Screen {
        let ctx = &self.inner.ctx;
        let sys = &self.inner.sys;
        match nav {
            Nav::Main => self.main_menu(),
            Nav::Status => self.status_screen(),
            Nav::Network => self.gate(Feature::NetworkInfo).unwrap_or_else(|| ui::network_screen(&sys.network())),
            Nav::Battery => self.gate(Feature::BatteryInfo).unwrap_or_else(|| ui::battery_screen(&sys.battery())),
            Nav::History => ui::history_screen(&ctx.history.recent(HISTORY_ITEMS)),
            Nav::Features => ui::features_screen(&ctx.settings.get().features),
            Nav::Tailscale => {
                self.gate(Feature::TailscaleManagement).unwrap_or_else(|| ui::tailscale_screen(&sys.tailscale_status()))
            }
            Nav::Help => {
                let s = ctx.settings.get();
                ui::help_screen_with(s.confirm_timeout_secs, s.stale_command_secs, ctx.auto_clean_after())
            }
        }
    }

    fn main_menu(&self) -> Screen {
        let ctx = &self.inner.ctx;
        let st = self.inner.sys.system_status();
        let computer = if ctx.computer_name.is_empty() { st.computer } else { ctx.computer_name.clone() };
        let service_start_unix = if st.service_start_unix > 0 { st.service_start_unix } else { ctx.started_unix };
        ui::main_menu(&ui::MenuView {
            computer,
            boot_unix: st.boot_unix,
            service_start_unix,
            now_unix: now_unix(),
            security: ctx.status.security(),
            ssh: ctx.status.ssh(),
            queued: ctx.queue.len(),
            dry_run: self.inner.sys.is_dry_run(),
        })
    }

    fn status_screen(&self) -> Screen {
        let ctx = &self.inner.ctx;
        let mut st = self.inner.sys.system_status();
        if st.service_start_unix <= 0 {
            st.service_start_unix = ctx.started_unix;
        }
        if st.computer.is_empty() {
            st.computer = ctx.computer_name.clone();
        }
        ui::status_screen(&ui::StatusView {
            sys: st,
            telegram: ctx.status.telegram_label().to_string(),
            security: ctx.status.security(),
            ssh: ctx.status.ssh(),
            audit_policy: lock(&ctx.status.audit_policy).clone(),
            queued: ctx.queue.len(),
            delivered: ctx.status.delivered.load(Ordering::Relaxed),
            dry_run: self.inner.sys.is_dry_run(),
            now_unix: now_unix(),
            version: crate::VERSION.to_string(),
        })
    }

    fn lock_screen(&self) -> Screen {
        if let Some(sc) = self.gate(Feature::PowerManagement) {
            return sc;
        }
        let r = self.inner.sys.lock();
        crate::logging::security(&format!("lock requested via Telegram: {}", outcome(&r)));
        ui::lock_result(&r)
    }

    fn logout_screen(&self) -> Screen {
        if let Some(sc) = self.gate(Feature::PowerManagement) {
            return sc;
        }
        let r = self.inner.sys.logout();
        crate::logging::security(&format!("logout requested via Telegram: {}", outcome(&r)));
        ui::logout_result(&r)
    }

    // ───────────── power confirmation ─────────────

    fn request_power(&self, action: PowerAction, chat: i64, existing: Option<i64>) {
        if let Some(sc) = self.gate(Feature::PowerManagement) {
            self.show(chat, existing, &sc);
            return;
        }
        if let Err(e) = self.inner.sys.check_power(action) {
            crate::log_warn!("telegram: {} not available: {e}", action.key());
            self.show(chat, existing, &ui::power_unavailable(action, &e));
            return;
        }
        let timeout = self.inner.ctx.settings.get().confirm_timeout_secs;
        let nonce = crate::util::rand::hex(16);
        let sc = ui::confirm_screen(action, &self.inner.ctx.computer_name, timeout, &nonce);
        let Some(message_id) = self.show(chat, existing, &sc) else {
            crate::log_warn!("telegram: could not show the {} confirmation", action.key());
            return;
        };
        // the dialog must survive the chat cleanup until it is confirmed, cancelled or replaced
        self.inner.ctx.janitor.protect(chat, message_id);
        let pending =
            Pending { action, nonce, created: Instant::now(), created_unix: now_unix(), chat_id: chat, message_id };
        let (previous, evicted) = {
            let mut g = lock(&self.inner.pending);
            // bounded: one per authorized user; should a removed user's entry linger, the
            // oldest entry of another chat gives way
            let evicted = if !g.contains_key(&chat) && g.len() >= MAX_PENDING {
                g.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| *k).and_then(|k| g.remove(&k))
            } else {
                None
            };
            (g.insert(chat, pending), evicted)
        };
        crate::log_info!("telegram: {} requested by user {chat}, waiting for confirmation", action.key());
        if let Some(old) = evicted {
            self.release(&old);
        }
        // the same user's earlier request is replaced (other users' requests are independent)
        if let Some(old) = previous
            && old.message_id != message_id
        {
            self.release(&old);
            self.edit_only(old.chat_id, old.message_id, &ui::superseded(old.action));
        }
    }

    /// Atomically remove the pending confirmation of `chat` if it matches `nonce` — a user can
    /// only ever take their own. Its message is no longer protected from the chat cleanup.
    fn take_pending(&self, chat: i64, nonce: &str) -> Option<Pending> {
        let taken = {
            let mut g = lock(&self.inner.pending);
            if g.get(&chat).is_some_and(|p| crate::pairing::ct_eq(p.nonce.as_bytes(), nonce.as_bytes())) {
                g.remove(&chat)
            } else {
                None
            }
        };
        if let Some(p) = &taken {
            self.release(p);
        }
        taken
    }

    fn is_expired(&self, p: &Pending) -> bool {
        let timeout = self.inner.ctx.settings.get().confirm_timeout_secs;
        p.created.elapsed() >= Duration::from_secs(timeout)
    }

    fn confirm(&self, callback_id: &str, chat: i64, nonce: &str) -> Ack {
        let Some(p) = self.take_pending(chat, nonce) else {
            return Ack::Alert(ui::CONFIRMATION_INVALID.to_string());
        };
        let action = p.action;
        if self.inner.ctx.settings.user(chat).is_none_or(|u| u.added_unix > p.created_unix) {
            crate::log_info!("telegram: {} confirmation predates the user's pairing", action.key());
            self.edit_or_send(p.chat_id, p.message_id, &ui::power_expired(action));
            return Ack::Alert(ui::CONFIRMATION_INVALID.to_string());
        }
        if self.is_expired(&p) {
            crate::log_info!("telegram: {} confirmation expired", action.key());
            self.edit_or_send(p.chat_id, p.message_id, &ui::power_expired(action));
            return Ack::Toast("⌛ Confirmation expired.".to_string());
        }
        if let Some(sc) = self.gate(Feature::PowerManagement) {
            self.edit_or_send(p.chat_id, p.message_id, &sc);
            return Ack::Toast(format!("{} is disabled", Feature::PowerManagement.label()));
        }
        self.answer(callback_id, Some(&format!("{} {}…", action.emoji(), action.label())), false);
        let shown = self.edit_or_send(p.chat_id, p.message_id, &ui::power_progress(action));
        crate::logging::security(&format!("power action {} confirmed via Telegram", action.key()));
        let r = self.inner.sys.execute_power(action);
        match &r {
            Ok(m) => crate::log_info!("power action {} accepted: {m}", action.key()),
            Err(e) => crate::log_error!("power action {} failed: {e}", action.key()),
        }
        let sc = ui::power_result(
            action,
            &self.inner.ctx.computer_name,
            crate::sys::SHUTDOWN_GRACE_SECS,
            &r,
            self.inner.sys.is_dry_run(),
        );
        self.edit_or_send(p.chat_id, shown.unwrap_or(p.message_id), &sc);
        Ack::Done
    }

    fn cancel_callback(&self, chat: i64, nonce: &str) -> Ack {
        match self.take_pending(chat, nonce) {
            Some(p) => {
                crate::log_info!("telegram: {} cancelled", p.action.key());
                self.edit_or_send(p.chat_id, p.message_id, &ui::power_cancelled(p.action));
                Ack::Toast("Cancelled".to_string())
            }
            None => Ack::Alert(ui::CONFIRMATION_INVALID.to_string()),
        }
    }

    /// `/cancel`: clears the caller's pending confirmation (it never aborts an initiated action,
    /// and never touches another user's confirmation).
    fn cancel_command(&self, chat: i64) {
        let taken = lock(&self.inner.pending).remove(&chat);
        if let Some(p) = &taken {
            self.release(p);
        }
        match taken {
            Some(p) if !self.is_expired(&p) => {
                crate::log_info!("telegram: {} cancelled with /cancel", p.action.key());
                let sc = ui::power_cancelled(p.action);
                self.edit_only(p.chat_id, p.message_id, &(sc.0.clone(), None));
                self.send(chat, &sc);
            }
            Some(p) => {
                self.edit_only(p.chat_id, p.message_id, &ui::power_expired(p.action));
                self.send(chat, &ui::nothing_to_cancel());
            }
            None => {
                self.send(chat, &ui::nothing_to_cancel());
            }
        }
    }

    // ───────────── tailscale worker ─────────────

    /// Start Tailscale up/down on a worker thread. Returns `false` when another operation is
    /// still running (nothing was started).
    fn start_tailscale(&self, up: bool, chat: i64, existing: Option<i64>) -> bool {
        if self.inner.ts_busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }
        let op = if up { "up" } else { "down" };
        crate::logging::security(&format!("tailscale {op} requested via Telegram"));
        let target = self.show(chat, existing, &ui::tailscale_progress(up));
        let bot = self.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("tailscale-{op}"))
            .spawn(move || bot.tailscale_worker(up, chat, target));
        match spawned {
            Ok(handle) => self.track_worker(handle),
            Err(e) => {
                self.inner.ts_busy.store(false, Ordering::Release);
                crate::log_error!("could not start the tailscale {op} worker: {e}");
                self.show(chat, target, &ui::tailscale_failed(up, &format!("could not start a worker thread: {e}")));
            }
        }
        true
    }

    fn tailscale_worker(&self, up: bool, chat: i64, target: Option<i64>) {
        let outcome = {
            let _busy = BusyGuard(&self.inner.ts_busy);
            catch_unwind(AssertUnwindSafe(|| {
                if up { self.inner.sys.tailscale_up() } else { self.inner.sys.tailscale_down() }
            }))
        };
        let op = if up { "up" } else { "down" };
        let sc = match outcome {
            Ok(r) => {
                crate::log_info!(
                    "tailscale {op} finished: success={} error={}",
                    r.success,
                    r.error.as_deref().unwrap_or("none")
                );
                ui::tailscale_result(up, &r)
            }
            Err(_) => {
                crate::log_error!("tailscale {op} worker panicked");
                ui::tailscale_failed(up, "internal error — see the service log")
            }
        };
        if catch_unwind(AssertUnwindSafe(|| self.show(chat, target, &sc))).is_err() {
            crate::log_error!("tailscale {op} worker: panic while reporting the result");
        }
    }

    #[cfg(not(test))]
    fn track_worker(&self, handle: JoinHandle<()>) {
        drop(handle); // detached: the worker reports its own result and exits
    }

    #[cfg(test)]
    fn track_worker(&self, handle: JoinHandle<()>) {
        lock(&self.inner.workers).push(handle);
    }

    /// Test hook: wait for every worker thread started so far.
    #[cfg(test)]
    pub(crate) fn join_workers(&self) {
        let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *lock(&self.inner.workers));
        for h in handles {
            h.join().expect("worker thread panicked");
        }
    }

    /// Test hook: make every pending confirmation look `by` older.
    #[cfg(test)]
    pub(crate) fn age_pending(&self, by: Duration) {
        for p in lock(&self.inner.pending).values_mut() {
            p.created = p.created.checked_sub(by).expect("instant underflow");
            p.created_unix -= by.as_secs() as i64;
        }
    }

    /// Test hook: nonce of the pending confirmation of the test context's user.
    #[cfg(test)]
    pub(crate) fn pending_nonce(&self) -> Option<String> {
        self.pending_nonce_for(crate::context::TEST_USER_ID)
    }

    /// Test hook: nonce of the pending confirmation in `chat`.
    #[cfg(test)]
    pub(crate) fn pending_nonce_for(&self, chat: i64) -> Option<String> {
        lock(&self.inner.pending).get(&chat).map(|p| p.nonce.clone())
    }
}

fn outcome(r: &Result<String, String>) -> String {
    match r {
        Ok(m) => format!("ok ({})", sanitize(m, 120)),
        Err(e) => format!("failed ({})", sanitize(e, 120)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{
        AcStatus, BatteryInfo, ConnectionType, InternetStatus, NetworkInfo, ServiceState, SessionInfo, SystemStatus,
        TailscaleOpResult, TailscaleStatus,
    };
    use crate::telegram::types::InlineKeyboardMarkup;
    use std::sync::atomic::AtomicI64;
    use std::sync::mpsc;

    use crate::config::UserRole;

    /// The admin of `AppContext::for_tests`.
    const OWNER: i64 = crate::context::TEST_USER_ID;
    const STRANGER: i64 = 2000;
    /// A second authorized user (role User) after [`H::add_second`].
    const SECOND: i64 = 5000;
    const MENU_MSG: i64 = 77;

    // ───────────── mocks ─────────────

    #[derive(Clone, Debug, PartialEq)]
    enum Call {
        Send { chat: i64, id: i64, html: String, kb: Option<InlineKeyboardMarkup> },
        Edit { chat: i64, msg: i64, html: String, kb: Option<InlineKeyboardMarkup> },
        Answer { text: Option<String>, alert: bool },
        Leave { chat: i64 },
    }

    #[derive(Default)]
    struct MockTg {
        calls: Mutex<Vec<Call>>,
        /// `delete_messages` calls (kept apart from `calls`, which many tests compare exactly).
        deletes: Mutex<Vec<(i64, Vec<i64>)>>,
        next_id: AtomicI64,
        fail_edits: AtomicBool,
    }

    impl Telegram for MockTg {
        fn send_message(
            &self,
            chat_id: i64,
            html: &str,
            keyboard: Option<&InlineKeyboardMarkup>,
        ) -> Result<i64, TgError> {
            let id = 500 + self.next_id.fetch_add(1, Ordering::SeqCst);
            lock(&self.calls).push(Call::Send { chat: chat_id, id, html: html.into(), kb: keyboard.cloned() });
            Ok(id)
        }
        fn edit_message(
            &self,
            chat_id: i64,
            message_id: i64,
            html: &str,
            keyboard: Option<&InlineKeyboardMarkup>,
        ) -> Result<(), TgError> {
            lock(&self.calls).push(Call::Edit {
                chat: chat_id,
                msg: message_id,
                html: html.into(),
                kb: keyboard.cloned(),
            });
            if self.fail_edits.load(Ordering::SeqCst) {
                Err(TgError::BadRequest("message to edit not found".into()))
            } else {
                Ok(())
            }
        }
        fn answer_callback(&self, _callback_id: &str, text: Option<&str>, show_alert: bool) -> Result<(), TgError> {
            lock(&self.calls).push(Call::Answer { text: text.map(str::to_string), alert: show_alert });
            Ok(())
        }
        fn leave_chat(&self, chat_id: i64) -> Result<(), TgError> {
            lock(&self.calls).push(Call::Leave { chat: chat_id });
            Ok(())
        }
        fn delete_messages(&self, chat_id: i64, message_ids: &[i64]) -> Result<(), TgError> {
            lock(&self.deletes).push((chat_id, message_ids.to_vec()));
            Ok(())
        }
    }

    impl MockTg {
        /// Every message id deleted so far (in order).
        fn deleted(&self) -> Vec<i64> {
            lock(&self.deletes).iter().flat_map(|(_, ids)| ids.clone()).collect()
        }
        /// Id of the most recent message sent.
        fn last_sent_id(&self) -> i64 {
            self.calls()
                .into_iter()
                .rev()
                .find_map(|c| match c {
                    Call::Send { id, .. } => Some(id),
                    _ => None,
                })
                .expect("nothing was sent")
        }
        /// Ids of every message sent.
        fn sent_ids(&self) -> Vec<i64> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Send { id, .. } => Some(id),
                    _ => None,
                })
                .collect()
        }
        fn calls(&self) -> Vec<Call> {
            lock(&self.calls).clone()
        }
        fn clear(&self) {
            lock(&self.calls).clear();
        }
        /// Every HTML text sent or edited, in order.
        fn texts(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Send { html, .. } | Call::Edit { html, .. } => Some(html),
                    _ => None,
                })
                .collect()
        }
        fn all_text(&self) -> String {
            let mut s = self.texts().join("\n---\n");
            for (t, _) in self.answers() {
                s.push_str("\n---\n");
                s.push_str(&t.unwrap_or_default());
            }
            s
        }
        fn last_text(&self) -> String {
            self.texts().pop().unwrap_or_default()
        }
        fn sends(&self) -> Vec<(i64, String)> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Send { chat, html, .. } => Some((chat, html)),
                    _ => None,
                })
                .collect()
        }
        fn edits(&self) -> Vec<(i64, String)> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Edit { msg, html, .. } => Some((msg, html)),
                    _ => None,
                })
                .collect()
        }
        fn answers(&self) -> Vec<(Option<String>, bool)> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Answer { text, alert } => Some((text, alert)),
                    _ => None,
                })
                .collect()
        }
        fn leaves(&self) -> Vec<i64> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Leave { chat } => Some(chat),
                    _ => None,
                })
                .collect()
        }
        fn keyboards(&self) -> Vec<InlineKeyboardMarkup> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Send { kb, .. } | Call::Edit { kb, .. } => kb,
                    _ => None,
                })
                .collect()
        }
        /// (nonce, message id) of the most recent confirmation dialog in `chat_id`.
        fn last_confirmation_in(&self, chat_id: i64) -> (String, i64) {
            self.calls()
                .into_iter()
                .rev()
                .find_map(|c| match c {
                    Call::Send { kb, id, chat, .. } | Call::Edit { kb, msg: id, chat, .. } if chat == chat_id => {
                        kb.as_ref().and_then(confirm_nonce).map(|n| (n, id))
                    }
                    _ => None,
                })
                .expect("no confirmation dialog was shown in this chat")
        }
        /// Keyboard of the most recent message sent or edited in `chat_id`.
        fn last_keyboard_in(&self, chat_id: i64) -> Option<InlineKeyboardMarkup> {
            self.calls().into_iter().rev().find_map(|c| match c {
                Call::Send { kb, chat, .. } | Call::Edit { kb, chat, .. } if chat == chat_id => Some(kb),
                _ => None,
            })?
        }
        /// (nonce, message id) of the most recent confirmation dialog.
        fn last_confirmation(&self) -> (String, i64) {
            self.calls()
                .into_iter()
                .rev()
                .find_map(|c| match c {
                    Call::Send { kb, id, .. } | Call::Edit { kb, msg: id, .. } => {
                        kb.as_ref().and_then(confirm_nonce).map(|n| (n, id))
                    }
                    _ => None,
                })
                .expect("no confirmation dialog was shown")
        }
    }

    fn confirm_nonce(kb: &InlineKeyboardMarkup) -> Option<String> {
        kb.callback_datas().into_iter().find_map(|d| d.strip_prefix("cf:").map(str::to_string))
    }

    #[derive(Default)]
    struct MockSys {
        calls: Mutex<Vec<String>>,
        check_err: Mutex<Option<String>>,
        gate: Mutex<Option<mpsc::Receiver<()>>>,
        dry_run: bool,
    }

    impl MockSys {
        fn record(&self, s: String) {
            lock(&self.calls).push(s);
        }
        fn count(&self, name: &str) -> usize {
            lock(&self.calls).iter().filter(|c| c.as_str() == name).count()
        }
        /// Number of calls that change system state.
        fn executed(&self) -> usize {
            lock(&self.calls)
                .iter()
                .filter(|c| {
                    c.starts_with("execute_power:")
                        || matches!(c.as_str(), "lock" | "logout" | "tailscale_up" | "tailscale_down")
                })
                .count()
        }
        fn wait_gate(&self) {
            let rx = lock(&self.gate).take();
            if let Some(rx) = rx {
                let _ = rx.recv_timeout(Duration::from_secs(10));
            }
        }
        fn ts_status() -> TailscaleStatus {
            TailscaleStatus {
                installed: true,
                version: Some("1.104.6".into()),
                service: ServiceState::Running,
                backend_state: Some("Running".into()),
                connected: true,
                ipv4: Some("100.64.0.5".into()),
                hostname: Some("testpc".into()),
                ..Default::default()
            }
        }
    }

    impl SystemActions for MockSys {
        fn check_power(&self, action: PowerAction) -> Result<(), String> {
            self.record(format!("check_power:{}", action.key()));
            match lock(&self.check_err).clone() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn execute_power(&self, action: PowerAction) -> Result<String, String> {
            self.record(format!("execute_power:{}", action.key()));
            if self.dry_run {
                Ok(format!("DRY-RUN: {} was simulated (nothing happened).", action.label()))
            } else {
                Ok(format!("{} accepted", action.label()))
            }
        }
        fn lock(&self) -> Result<String, String> {
            self.record("lock".into());
            Ok("Locked 1 session.".into())
        }
        fn logout(&self) -> Result<String, String> {
            self.record("logout".into());
            Ok("Logged off alice (session 1).".into())
        }
        fn network(&self) -> Result<NetworkInfo, String> {
            self.record("network".into());
            Ok(NetworkInfo {
                connection: ConnectionType::WiFi,
                ssid: Some("HomeNet".into()),
                ipv4: Some("192.168.1.5".into()),
                internet: InternetStatus::Connected,
                ..Default::default()
            })
        }
        fn battery(&self) -> Result<BatteryInfo, String> {
            self.record("battery".into());
            Ok(BatteryInfo {
                present: true,
                percent: Some(80),
                charging: true,
                ac: AcStatus::Connected,
                ..Default::default()
            })
        }
        fn tailscale_status(&self) -> TailscaleStatus {
            self.record("tailscale_status".into());
            Self::ts_status()
        }
        fn tailscale_up(&self) -> TailscaleOpResult {
            self.record("tailscale_up".into());
            self.wait_gate();
            TailscaleOpResult {
                success: true,
                steps: vec!["✅ tailscale up: Success.".into()],
                status: Self::ts_status(),
                error: None,
            }
        }
        fn tailscale_down(&self) -> TailscaleOpResult {
            self.record("tailscale_down".into());
            self.wait_gate();
            // what sys::tailscale::down() reports after success: the service is stopped
            TailscaleOpResult {
                success: true,
                steps: vec!["✅ tailscale down".into(), "✅ Service stopped".into()],
                status: TailscaleStatus {
                    service: ServiceState::Stopped,
                    connected: false,
                    backend_state: Some("Service stopped".into()),
                    ipv4: None,
                    hostname: None,
                    ..Self::ts_status()
                },
                error: None,
            }
        }
        fn system_status(&self) -> SystemStatus {
            self.record("system_status".into());
            let now = now_unix();
            SystemStatus {
                computer: "TESTPC".into(),
                os_version: "Windows 11 Pro".into(),
                boot_unix: now - 3600,
                service_start_unix: now - 60,
                service_private_bytes: 3 << 20,
                service_working_set_bytes: 6 << 20,
                service_cpu_ms: 1500,
                sessions: vec![SessionInfo {
                    id: 1,
                    user: "alice".into(),
                    state: "Active".into(),
                    station: "Console".into(),
                    ..Default::default()
                }],
            }
        }
        fn is_dry_run(&self) -> bool {
            self.dry_run
        }
    }

    // ───────────── harness ─────────────

    struct H {
        bot: Bot,
        tg: Arc<MockTg>,
        sys: Arc<MockSys>,
        ctx: Arc<AppContext>,
    }

    fn harness_with(sys: MockSys) -> H {
        let ctx = AppContext::for_tests();
        let tg = Arc::new(MockTg::default());
        let sys = Arc::new(sys);
        let bot = Bot::new(ctx.clone(), tg.clone(), sys.clone());
        H { bot, tg, sys, ctx }
    }

    fn harness() -> H {
        harness_with(MockSys::default())
    }

    fn user(id: i64, username: &str) -> User {
        User { id, is_bot: false, first_name: "Test".into(), last_name: None, username: Some(username.into()) }
    }

    fn chat(id: i64, kind: &str) -> Chat {
        Chat { id, kind: kind.into(), title: None, username: None }
    }

    fn message(from: User, chat: Chat, text: &str, date: i64) -> Message {
        Message { message_id: 10, date, chat, from: Some(from), text: Some(text.into()) }
    }

    fn msg_update(m: Message) -> Update {
        Update { update_id: 1, message: Some(m), edited_message: None, callback_query: None, my_chat_member: None }
    }

    fn cb_update(from: User, chat: Chat, data: &str, message_id: i64) -> Update {
        Update {
            update_id: 2,
            message: None,
            edited_message: None,
            callback_query: Some(CallbackQuery {
                id: "cb1".into(),
                from,
                message: Some(Message { message_id, date: 1, chat, from: None, text: None }),
                data: Some(data.into()),
            }),
            my_chat_member: None,
        }
    }

    impl H {
        /// Owner sends `text` now.
        fn cmd(&self, text: &str) {
            self.cmd_at(text, now_unix());
        }
        fn cmd_at(&self, text: &str, date: i64) {
            self.bot.handle_update(&msg_update(message(user(OWNER, "owner"), chat(OWNER, "private"), text, date)));
            self.bot.join_workers();
        }
        /// Owner presses a button on the menu message.
        fn press(&self, data: &str) {
            self.press_on(data, MENU_MSG);
        }
        fn press_on(&self, data: &str, message_id: i64) {
            self.bot.handle_update(&cb_update(user(OWNER, "owner"), chat(OWNER, "private"), data, message_id));
            self.bot.join_workers();
        }
        /// Owner's button press delivered from Telegram's backlog (pressed while offline).
        fn press_backlog(&self, data: &str) {
            self.press_backlog_on(data, MENU_MSG);
        }
        fn press_backlog_on(&self, data: &str, message_id: i64) {
            let u = cb_update(user(OWNER, "owner"), chat(OWNER, "private"), data, message_id);
            self.bot.handle_update_with(&u, true);
            self.bot.join_workers();
        }
        /// Owner's message delivered from the backlog.
        fn cmd_backlog_at(&self, text: &str, date: i64) {
            let u = msg_update(message(user(OWNER, "owner"), chat(OWNER, "private"), text, date));
            self.bot.handle_update_with(&u, true);
            self.bot.join_workers();
        }
        fn disable(&self, f: Feature) {
            self.ctx.settings.set_feature(f, false).unwrap();
        }
        /// Owner sends `text` now as message `message_id` (unique ids, like real Telegram).
        fn say(&self, text: &str, message_id: i64) {
            let mut m = message(user(OWNER, "owner"), chat(OWNER, "private"), text, now_unix());
            m.message_id = message_id;
            self.bot.handle_update(&msg_update(m));
            self.bot.join_workers();
        }
        /// Owner presses a button on message `message_id`, which was sent `age` seconds ago.
        fn press_live(&self, data: &str, message_id: i64, age: i64) {
            let mut u = cb_update(user(OWNER, "owner"), chat(OWNER, "private"), data, message_id);
            if let Some(m) = u.callback_query.as_mut().and_then(|c| c.message.as_mut()) {
                m.date = now_unix() - age;
            }
            self.bot.handle_update(&u);
            self.bot.join_workers();
        }
        fn tracked(&self, message_id: i64) -> bool {
            self.ctx.janitor.contains(OWNER, message_id)
        }
        /// Authorize [`SECOND`] ("bob", role User).
        fn add_second(&self) {
            let bob = AuthorizedUser::new(SECOND, "bob", UserRole::User, now_unix());
            assert_eq!(self.ctx.settings.add_user(bob).unwrap(), AddUserOutcome::Added);
        }
        /// Telegram user `from` sends `text` now in their private chat as message `message_id`.
        fn say_as(&self, from: i64, text: &str, message_id: i64) {
            let mut m = message(user(from, "u"), chat(from, "private"), text, now_unix());
            m.message_id = message_id;
            self.bot.handle_update(&msg_update(m));
            self.bot.join_workers();
        }
        /// Telegram user `from` presses `data` on message `message_id` in their private chat.
        fn press_as(&self, from: i64, data: &str, message_id: i64) {
            self.bot.handle_update(&cb_update(user(from, "u"), chat(from, "private"), data, message_id));
            self.bot.join_workers();
        }
        /// The text of the last message sent to `chat_id`.
        fn last_sent_to(&self, chat_id: i64) -> String {
            self.tg.sends().into_iter().rev().find(|(c, _)| *c == chat_id).map(|(_, t)| t).unwrap_or_default()
        }
    }

    /// A valid code of the same length that is not `code`.
    fn other_code(code: &str) -> String {
        let first = if code.starts_with('0') { '1' } else { '0' };
        format!("{first}{}", &code[1..])
    }

    fn assert_no_confirmation(tg: &MockTg) {
        for kb in tg.keyboards() {
            for d in kb.callback_datas() {
                assert!(!d.starts_with("cf:") && !d.starts_with("cx:"), "unexpected confirmation button {d}");
            }
        }
        assert!(!tg.all_text().contains("CONFIRM"), "unexpected confirmation dialog");
    }

    // ───────────── pure helpers ─────────────

    #[test]
    fn bot_is_clone_send_sync() {
        fn check<T: Clone + Send + Sync + 'static>() {}
        check::<Bot>();
    }

    #[test]
    fn command_parsing() {
        assert_eq!(split_command("/status"), Some(("status".into(), "")));
        assert_eq!(split_command("  /Status@ExampleBot  "), Some(("status".into(), "")));
        assert_eq!(split_command("/tailscale@Bot   UP now"), Some(("tailscale".into(), "UP now")));
        assert_eq!(split_command("/"), Some(("".into(), "")));
        assert_eq!(split_command("hello /status"), None);
        assert_eq!(split_command(""), None);
        assert_eq!(classify("start", "payload"), Command::Show(Nav::Main));
        assert_eq!(classify("menu", ""), Command::Show(Nav::Main));
        assert_eq!(classify("shutdown", ""), Command::Power(PowerAction::Shutdown));
        assert_eq!(classify("hibernate", ""), Command::Power(PowerAction::Hibernate));
        assert_eq!(classify("tailscale", ""), Command::Show(Nav::Tailscale));
        assert_eq!(classify("tailscale", "Status"), Command::Show(Nav::Tailscale));
        assert_eq!(classify("tailscale", "up"), Command::TailscaleUp);
        assert_eq!(classify("tailscale", "DOWN"), Command::TailscaleDown);
        assert_eq!(classify("tailscale", "logout"), Command::TailscaleUsage);
        assert_eq!(classify("rm", "-rf"), Command::Unknown);
        assert_eq!(classify("", ""), Command::Unknown);
        assert_eq!(Command::Lock.state_changing_label().as_deref(), Some("/lock"));
        assert_eq!(Command::Show(Nav::Status).state_changing_label(), None);
        assert_eq!(Command::Cancel.state_changing_label(), None);
    }

    #[test]
    fn staleness() {
        assert!(!is_stale(1000, 1000, 300));
        assert!(!is_stale(1000, 1300, 300));
        assert!(is_stale(1000, 1301, 300));
        assert!(!is_stale(2000, 1000, 300)); // sender clock ahead
        assert!(is_stale(0, 1000, 300)); // unknown date
        assert!(!is_stale(1, 1000, u64::MAX));
    }

    #[test]
    fn user_chat_check() {
        assert!(is_user_chat(true, OWNER, &chat(OWNER, "private")));
        assert!(!is_user_chat(false, OWNER, &chat(OWNER, "private")));
        assert!(!is_user_chat(true, OWNER, &chat(STRANGER, "private")), "someone else's chat");
        assert!(!is_user_chat(true, OWNER, &chat(OWNER, "group")));
        assert!(!is_user_chat(true, 0, &chat(0, "private")));
        assert!(!is_user_chat(true, -7, &chat(-7, "private")));
    }

    #[test]
    fn pairing_payloads_and_log_redaction() {
        assert_eq!(pairing_payload("/pair 1234 5678").as_deref(), Some("1234 5678"));
        assert_eq!(pairing_payload("/pair@ExampleBot 12345678").as_deref(), Some("12345678"));
        assert_eq!(pairing_payload("/PAIR").as_deref(), Some(""));
        assert_eq!(pairing_payload("/start pair-12345678").as_deref(), Some("pair-12345678"));
        assert_eq!(pairing_payload("/start PAIR_12345678 x").as_deref(), Some("PAIR_12345678"));
        for other in ["/start", "/start hello", "/status", "pair 12345678", "", "/pairing 1"] {
            assert_eq!(pairing_payload(other), None, "{other:?}");
        }
        assert_eq!(log_text("/pair 1234 5678"), "/pair (pairing code hidden)");
        assert_eq!(log_text("/start pair-12345678"), "/start (pairing code hidden)");
        assert_eq!(log_text("/status"), "/status");
        assert!(!log_text("/pair@Bot 99887766").contains("9988"));
    }

    #[test]
    fn denied_limiter_rate_and_bound() {
        let mut l = DeniedLimiter::default();
        assert!(l.allow(5, 1000));
        assert!(!l.allow(5, 1001));
        assert!(!l.allow(5, 1000 + DENIED_NOTICE_INTERVAL_SECS - 1));
        assert!(l.allow(5, 1000 + DENIED_NOTICE_INTERVAL_SECS));
        assert!(l.allow(6, 1001));
        for id in 0..10_000 {
            l.allow(100 + id, 5000);
        }
        assert!(l.last.len() <= MAX_DENIED_TRACKED);
    }

    #[test]
    fn sanitize_for_logs() {
        assert_eq!(sanitize("a\r\nb\"c", 64), "a  b'c");
        assert_eq!(sanitize(&"x".repeat(100), 64).chars().count(), 64);
    }

    #[test]
    fn command_list_is_valid() {
        let list = Bot::command_list();
        assert!(list.len() >= 14);
        for (c, d) in &list {
            assert!(!c.is_empty() && c.len() <= 32);
            assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
            assert!((3..=256).contains(&d.chars().count()));
            assert_ne!(classify(c, ""), Command::Unknown, "/{c} is listed but not handled");
        }
    }

    // ───────────── authorization ─────────────

    #[test]
    fn wrong_user_rejected_and_rate_limited() {
        let h = harness();
        let m = message(user(STRANGER, "owner"), chat(STRANGER, "private"), "/lock", now_unix());
        h.bot.handle_update(&msg_update(m.clone()));
        assert_eq!(h.tg.sends(), vec![(STRANGER, ui::ACCESS_DENIED.to_string())]);
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.ctx.queue.len(), 1);
        let alert = h.ctx.queue.front().unwrap().html;
        assert!(alert.contains("UNAUTHORIZED ACCESS ATTEMPT"));
        assert!(alert.contains(&STRANGER.to_string()));
        // second attempt within the hour: logged only
        h.bot.handle_update(&msg_update(m));
        assert_eq!(h.tg.sends().len(), 1);
        assert_eq!(h.ctx.queue.len(), 1);
        // a different stranger gets their own notice
        h.bot.handle_update(&msg_update(message(user(3000, "x"), chat(3000, "private"), "hi", now_unix())));
        assert_eq!(h.tg.sends().len(), 2);
        assert_eq!(h.ctx.queue.len(), 2);
    }

    #[test]
    fn same_username_different_id_rejected() {
        let h = harness();
        // the owner's username is "owner" in these tests; usernames must never authorize
        for text in ["/status", "/shutdown", "/menu"] {
            h.bot.handle_update(&msg_update(message(
                user(STRANGER, "owner"),
                chat(STRANGER, "private"),
                text,
                now_unix(),
            )));
        }
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.sys.count("system_status"), 0);
        assert!(h.tg.texts().iter().all(|t| t == ui::ACCESS_DENIED));
        assert!(h.bot.pending_nonce().is_none());
    }

    #[test]
    fn owner_id_in_foreign_chat_rejected() {
        let h = harness();
        h.bot.handle_update(&msg_update(message(user(OWNER, "owner"), chat(4242, "private"), "/lock", now_unix())));
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.tg.texts(), vec![ui::ACCESS_DENIED.to_string()]);
    }

    #[test]
    fn no_user_configured_rejects_everything() {
        let h = harness();
        h.ctx.settings.update(|s| s.authorized_users.clear()).unwrap();
        h.cmd("/lock");
        h.press("act:lock");
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.all_text().contains(ui::ACCESS_DENIED));
        assert!(h.tg.answers().contains(&(Some(ui::NOT_AUTHORIZED.to_string()), true)));
    }

    #[test]
    fn group_chats_are_left_and_nothing_executes() {
        for kind in ["group", "supergroup", "channel"] {
            let h = harness();
            h.bot.handle_update(&msg_update(message(user(OWNER, "owner"), chat(-100, kind), "/lock", now_unix())));
            assert_eq!(h.tg.leaves(), vec![-100], "{kind}");
            assert!(h.tg.sends().is_empty());
            assert_eq!(h.sys.executed(), 0);

            // bot added to a group
            let h = harness();
            h.bot.handle_update(&Update {
                update_id: 3,
                message: None,
                edited_message: None,
                callback_query: None,
                my_chat_member: Some(ChatMemberUpdated { chat: chat(-200, kind), from: user(OWNER, "owner"), date: 1 }),
            });
            assert_eq!(h.tg.leaves(), vec![-200]);
            assert!(h.tg.sends().is_empty());
        }
        // a button press inside a group is refused too
        let h = harness();
        h.bot.handle_update(&cb_update(user(OWNER, "owner"), chat(-300, "group"), "act:lock", 5));
        assert_eq!(h.tg.leaves(), vec![-300]);
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn private_my_chat_member_is_ignored() {
        let h = harness();
        h.bot.handle_update(&Update {
            update_id: 3,
            message: None,
            edited_message: None,
            callback_query: None,
            my_chat_member: Some(ChatMemberUpdated { chat: chat(OWNER, "private"), from: user(OWNER, "o"), date: 1 }),
        });
        assert!(h.tg.calls().is_empty());
    }

    #[test]
    fn callback_from_wrong_user_rejected() {
        let h = harness();
        for data in ["act:lock", "pw:shutdown", "ft:0", "nav:status", "ts:up"] {
            h.bot.handle_update(&cb_update(user(STRANGER, "owner"), chat(OWNER, "private"), data, MENU_MSG));
            h.bot.handle_update(&cb_update(user(STRANGER, "owner"), chat(STRANGER, "private"), data, MENU_MSG));
        }
        h.bot.join_workers();
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.sys.count("system_status"), 0);
        assert!(h.tg.edits().is_empty() && h.tg.sends().is_empty());
        assert!(h.tg.answers().iter().all(|a| a == &(Some(ui::NOT_AUTHORIZED.to_string()), true)));
        assert_eq!(h.tg.answers().len(), 10);
        assert!(h.ctx.settings.feature(Feature::LoginMonitoring));
    }

    #[test]
    fn edited_messages_never_execute() {
        let h = harness();
        h.bot.handle_update(&Update {
            update_id: 4,
            message: None,
            edited_message: Some(message(user(OWNER, "owner"), chat(OWNER, "private"), "/lock", now_unix())),
            callback_query: None,
            my_chat_member: None,
        });
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.calls().is_empty());
    }

    #[test]
    fn html_escaping_of_hostile_username() {
        let h = harness();
        let evil = User {
            id: STRANGER,
            is_bot: false,
            first_name: "<b>evil&".into(),
            last_name: Some("<i>".into()),
            username: Some("<b>evil&".into()),
        };
        h.bot.handle_update(&msg_update(message(evil, chat(STRANGER, "private"), "<script>x</script>", now_unix())));
        let html = h.ctx.queue.front().unwrap().html;
        assert!(html.contains("&lt;b&gt;evil&amp;"), "{html}");
        assert!(!html.contains("<b>evil"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<i>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    // ───────────── stale commands ─────────────

    #[test]
    fn stale_lock_ignored_but_stale_status_answered() {
        let h = harness();
        let old = now_unix() - 1000;
        h.cmd_at("/lock", old);
        assert_eq!(h.sys.executed(), 0);
        let t = h.tg.last_text();
        assert!(t.starts_with("⌛ Ignored /lock sent at "), "{t}");
        assert!(t.contains("older than 5 minutes"));

        for cmd in ["/logout", "/shutdown", "/tailscale up", "/tailscale down"] {
            h.cmd_at(cmd, old);
            assert!(h.tg.last_text().contains(&format!("Ignored {cmd}")), "{cmd}");
        }
        assert_eq!(h.sys.executed(), 0);
        assert!(h.bot.pending_nonce().is_none());

        h.cmd_at("/status", old);
        assert!(h.tg.last_text().contains("SYSTEM STATUS"));
        h.cmd_at("/network", old);
        assert!(h.tg.last_text().contains("NETWORK STATUS"));
    }

    // ───────────── backlogged button presses ─────────────

    #[test]
    fn backlog_state_changing_buttons_are_not_executed() {
        let buttons = [
            "act:lock",
            "act:logout",
            "ts:up",
            "ts:down",
            "ft:0",
            "ft:1",
            "ft:5",
            "pw:shutdown",
            "pw:restart",
            "pw:sleep",
            "pw:hibernate",
            "cf:0123456789abcdef0123456789abcdef",
        ];
        for b in buttons {
            let h = harness();
            let before = h.ctx.settings.get().features;
            h.press_backlog(b);
            assert_eq!(h.sys.executed(), 0, "{b} executed from the backlog");
            // not even a power pre-check or a Tailscale/system query ran
            assert!(lock(&h.sys.calls).is_empty(), "{b}: {:?}", lock(&h.sys.calls));
            assert_eq!(h.ctx.settings.get().features, before, "{b} changed a feature");
            assert!(h.bot.pending_nonce().is_none(), "{b} opened a confirmation");
            // answered exactly once, and the pressed message now explains why nothing happened
            assert_eq!(h.tg.answers(), vec![(None, false)], "{b}");
            assert_eq!(h.tg.edits(), vec![(MENU_MSG, ui::BACKLOG_IGNORED.to_string())], "{b}");
            assert!(h.tg.sends().is_empty(), "{b}");
            assert_no_confirmation(&h.tg);
        }
    }

    #[test]
    fn backlog_ignored_message_is_sent_when_the_edit_fails() {
        let h = harness();
        h.tg.fail_edits.store(true, Ordering::SeqCst);
        h.press_backlog("act:logout");
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.tg.sends().last().map(|s| s.1.clone()), Some(ui::BACKLOG_IGNORED.to_string()));
        // the screen offers the button again
        let kb = h.tg.keyboards().pop().unwrap();
        assert!(kb.callback_datas().contains(&"act:logout".to_string()));
    }

    #[test]
    fn backlog_confirmation_is_discarded_never_executed() {
        let h = harness();
        h.cmd("/shutdown");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_backlog_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
        assert!(h.bot.pending_nonce().is_none(), "the late confirmation must not stay usable");
        assert_eq!(h.tg.last_text(), ui::BACKLOG_IGNORED);
        // pressing the same Confirm again later does nothing either
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.answers().contains(&(Some(ui::CONFIRMATION_INVALID.to_string()), true)));
        // a fresh request + live confirmation still works
        h.press("pw:shutdown");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.count("execute_power:shutdown"), 1);
    }

    #[test]
    fn backlog_read_only_buttons_still_work() {
        let h = harness();
        let expected = [
            (Nav::Main, "PREDATOR REMOTE CONTROL"),
            (Nav::Status, "SYSTEM STATUS"),
            (Nav::Network, "NETWORK STATUS"),
            (Nav::Battery, "BATTERY STATUS"),
            (Nav::History, "LOGIN HISTORY"),
            (Nav::Features, "PREDATOR FEATURES"),
            (Nav::Tailscale, "TAILSCALE"),
            (Nav::Help, "HELP"),
        ];
        assert_eq!(expected.len(), Nav::ALL.len());
        for (nav, needle) in expected {
            h.tg.clear();
            h.press_backlog(nav.data());
            let t = h.tg.last_text();
            assert!(t.contains(needle), "{}: {t}", nav.data());
            assert_ne!(t, ui::BACKLOG_IGNORED);
            assert_eq!(h.tg.answers().len(), 1, "{}", nav.data());
        }
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.sys.count("network"), 1);
        assert_eq!(h.sys.count("tailscale_status"), 1);

        // cancelling is harmless and still works from the backlog
        h.cmd("/sleep");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_backlog_on(&format!("cx:{nonce}"), msg);
        assert!(h.bot.pending_nonce().is_none());
        assert_eq!(h.tg.last_text(), "❌ Sleep cancelled.");
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn backlog_flag_does_not_change_message_commands_or_live_presses() {
        let h = harness();
        // messages keep the message.date rule: a fresh one runs even inside a backlog batch ...
        h.cmd_backlog_at("/lock", now_unix());
        assert_eq!(h.sys.count("lock"), 1);
        // ... an old one is refused with the usual stale text
        h.cmd_backlog_at("/logout", now_unix() - 1000);
        assert_eq!(h.sys.count("logout"), 0);
        assert!(h.tg.last_text().starts_with("⌛ Ignored /logout sent at "));
        h.cmd_backlog_at("/status", now_unix() - 1000);
        assert!(h.tg.last_text().contains("SYSTEM STATUS"));

        // the same presses outside the backlog execute immediately (handle_update == from_backlog false)
        h.press("act:lock");
        h.press("act:logout");
        h.press("ft:1");
        h.press("ts:down");
        assert_eq!(h.sys.count("lock"), 2);
        assert_eq!(h.sys.count("logout"), 1);
        assert_eq!(h.sys.count("tailscale_down"), 1);
        assert!(!h.ctx.settings.feature(Feature::SshMonitoring));
        assert!(!h.tg.all_text().contains(ui::BACKLOG_IGNORED));
    }

    #[test]
    fn backlog_presses_from_strangers_are_still_rejected() {
        let h = harness();
        h.bot.handle_update_with(
            &cb_update(user(STRANGER, "owner"), chat(OWNER, "private"), "act:lock", MENU_MSG),
            true,
        );
        h.bot.handle_update_with(&cb_update(user(OWNER, "owner"), chat(-5, "group"), "act:lock", MENU_MSG), true);
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.answers().iter().all(|a| a == &(Some(ui::NOT_AUTHORIZED.to_string()), true)));
        assert_eq!(h.tg.leaves(), vec![-5]);
        assert!(!h.tg.all_text().contains(ui::BACKLOG_IGNORED));
        // unknown data from the backlog is answered as unknown, not executed
        h.tg.clear();
        h.press_backlog("rm:-rf");
        assert_eq!(h.tg.answers(), vec![(Some(ui::UNKNOWN_BUTTON.to_string()), false)]);
    }

    // ───────────── immediate actions ─────────────

    #[test]
    fn lock_and_logout_execute_immediately() {
        let h = harness();
        h.cmd("/lock");
        assert_eq!(h.sys.count("lock"), 1);
        assert!(h.tg.last_text().contains("Locked 1 session."));
        h.cmd("/logout");
        assert_eq!(h.sys.count("logout"), 1);
        assert!(h.tg.last_text().contains("Logged off alice"));
        h.press("act:lock");
        h.press("act:logout");
        assert_eq!(h.sys.count("lock"), 2);
        assert_eq!(h.sys.count("logout"), 2);
        // button presses edit the menu message in place
        assert_eq!(h.tg.edits().len(), 2);
        assert!(h.tg.edits().iter().all(|(m, _)| *m == MENU_MSG));
        assert_no_confirmation(&h.tg);
    }

    #[test]
    fn info_and_tailscale_commands_execute_immediately() {
        let h = harness();
        h.cmd("/network");
        assert_eq!(h.sys.count("network"), 1);
        assert!(h.tg.last_text().contains("SSID: HomeNet"));
        h.cmd("/battery");
        assert_eq!(h.sys.count("battery"), 1);
        assert!(h.tg.last_text().contains("Battery: 80%"));
        h.cmd("/tailscale");
        h.cmd("/tailscale status");
        assert_eq!(h.sys.count("tailscale_status"), 2);
        assert!(h.tg.last_text().contains("Tailscale IP: <code>100.64.0.5</code>"));
        h.cmd("/tailscale up");
        assert_eq!(h.sys.count("tailscale_up"), 1);
        let texts = h.tg.texts();
        assert!(texts.iter().any(|t| t == "⏳ Bringing Tailscale up…"));
        assert!(h.tg.last_text().contains("Tailscale up completed"));
        h.cmd("/tailscale down");
        assert_eq!(h.sys.count("tailscale_down"), 1);
        let t = h.tg.last_text();
        assert!(t.contains("Tailscale down completed"), "{t}");
        // a stopped service after a successful down is "disconnected", not a warning
        assert!(t.contains("Connection: 🔴 Disconnected (Tailscale service stopped)"), "{t}");
        assert!(!t.contains('🟡'), "{t}");
        h.cmd("/features");
        assert!(h.tg.last_text().contains("PREDATOR FEATURES"));
        h.cmd("/history");
        assert!(h.tg.last_text().contains("LOGIN HISTORY"));
        h.cmd("/help");
        assert!(h.tg.last_text().contains("Confirmation policy"));
        h.cmd("/menu");
        assert!(h.tg.last_text().contains("PREDATOR REMOTE CONTROL"));
        h.cmd("/start");
        assert!(h.tg.last_text().contains("PREDATOR REMOTE CONTROL"));
        h.cmd("/tailscale reboot");
        assert!(h.tg.last_text().contains("Usage"));
        assert_no_confirmation(&h.tg);
    }

    #[test]
    fn tailscale_buttons_edit_in_place() {
        let h = harness();
        h.press("ts:up");
        assert_eq!(h.sys.count("tailscale_up"), 1);
        let edits = h.tg.edits();
        assert_eq!(edits.first().map(|e| e.1.as_str()), Some("⏳ Bringing Tailscale up…"));
        assert!(edits.iter().all(|(m, _)| *m == MENU_MSG));
        assert!(edits.last().unwrap().1.contains("Tailscale up completed"));
        h.press("ts:down");
        assert_eq!(h.sys.count("tailscale_down"), 1);
        assert_no_confirmation(&h.tg);
    }

    #[test]
    fn tailscale_busy_guard() {
        let (tx, rx) = mpsc::channel();
        let sys = MockSys::default();
        *lock(&sys.gate) = Some(rx);
        let h = harness_with(sys);
        // start "up" without joining: the worker blocks inside tailscale_up
        h.bot.handle_update(&msg_update(message(
            user(OWNER, "owner"),
            chat(OWNER, "private"),
            "/tailscale up",
            now_unix(),
        )));
        h.bot.handle_update(&msg_update(message(
            user(OWNER, "owner"),
            chat(OWNER, "private"),
            "/tailscale down",
            now_unix(),
        )));
        assert!(h.tg.texts().iter().any(|t| t == ui::TAILSCALE_BUSY));
        h.bot.handle_update(&cb_update(user(OWNER, "owner"), chat(OWNER, "private"), "ts:down", MENU_MSG));
        assert!(h.tg.answers().contains(&(Some(ui::TAILSCALE_BUSY.to_string()), true)));
        tx.send(()).unwrap();
        h.bot.join_workers();
        assert_eq!(h.sys.count("tailscale_up"), 1);
        assert_eq!(h.sys.count("tailscale_down"), 0);
        // the guard was released: the next operation runs
        h.cmd("/tailscale down");
        assert_eq!(h.sys.count("tailscale_down"), 1);
    }

    #[test]
    fn feature_toggle_is_immediate() {
        let h = harness();
        h.press("ft:1");
        assert!(!h.ctx.settings.feature(Feature::SshMonitoring));
        assert!(h.tg.answers().contains(&(Some("SSH Monitoring disabled".to_string()), false)));
        let (msg, html) = h.tg.edits().pop().unwrap();
        assert_eq!(msg, MENU_MSG);
        assert!(html.contains("🔴 SSH Monitoring"));
        h.press("ft:1");
        assert!(h.ctx.settings.feature(Feature::SshMonitoring));
        assert!(h.tg.answers().contains(&(Some("SSH Monitoring enabled".to_string()), false)));
        assert_no_confirmation(&h.tg);
    }

    // ───────────── confirmations ─────────────

    #[test]
    fn power_commands_require_confirmation_and_execute_once() {
        for action in PowerAction::ALL {
            let h = harness();
            h.cmd(&format!("/{}", action.key()));
            assert_eq!(h.sys.executed(), 0, "{action:?} executed without confirmation");
            assert!(h.tg.last_text().contains(&format!("CONFIRM {}", action.label().to_uppercase())));
            let (nonce, msg) = h.tg.last_confirmation();
            assert_eq!(nonce.len(), 32);
            assert_eq!(h.bot.pending_nonce().as_deref(), Some(nonce.as_str()));

            h.press_on(&format!("cf:{nonce}"), msg);
            assert_eq!(h.sys.count(&format!("execute_power:{}", action.key())), 1);
            assert_eq!(h.sys.executed(), 1);
            let texts = h.tg.texts();
            assert!(texts.contains(&ui::power_progress(action).0));
            assert!(h.tg.last_text().contains("TESTPC"));
            assert!(h.bot.pending_nonce().is_none());

            // replaying the same confirmation does nothing
            h.tg.clear();
            h.press_on(&format!("cf:{nonce}"), msg);
            assert_eq!(h.sys.executed(), 1);
            assert_eq!(h.tg.answers(), vec![(Some(ui::CONFIRMATION_INVALID.to_string()), true)]);
            assert!(h.tg.edits().is_empty());
        }
    }

    #[test]
    fn power_buttons_confirm_in_place() {
        let h = harness();
        h.press("pw:shutdown");
        assert_eq!(h.sys.executed(), 0);
        let (nonce, msg) = h.tg.last_confirmation();
        assert_eq!(msg, MENU_MSG);
        h.press(&format!("cf:{nonce}"));
        assert_eq!(h.sys.count("execute_power:shutdown"), 1);
        assert_eq!(h.tg.last_text(), "✅ Shutdown initiated — TESTPC will power off in 5 seconds.");
    }

    #[test]
    fn dry_run_result_shows_simulation_text() {
        let h = harness_with(MockSys { dry_run: true, ..Default::default() });
        h.cmd("/restart");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_on(&format!("cf:{nonce}"), msg);
        assert!(h.tg.last_text().contains("DRY-RUN: Restart was simulated"));
    }

    #[test]
    fn check_power_failure_creates_no_confirmation() {
        let sys = MockSys::default();
        *lock(&sys.check_err) = Some("Hibernation is disabled (powercfg /h on)".into());
        let h = harness_with(sys);
        h.cmd("/hibernate");
        assert!(h.tg.last_text().starts_with("❌ Hibernate is not available: Hibernation is disabled"));
        assert!(h.bot.pending_nonce().is_none());
        assert_no_confirmation(&h.tg);
    }

    #[test]
    fn expired_confirmation_rejected() {
        let h = harness();
        h.cmd("/restart");
        let (nonce, msg) = h.tg.last_confirmation();
        h.bot.age_pending(Duration::from_secs(61));
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.last_text().contains("Confirmation expired. Send /restart again."));
        assert!(h.bot.pending_nonce().is_none());
        // with a zero timeout every confirmation is already expired
        h.ctx.settings.update(|s| s.confirm_timeout_secs = 0).unwrap();
        h.cmd("/sleep");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn cancel_button_and_command_clear_pending() {
        let h = harness();
        h.cmd("/shutdown");
        let (nonce, msg) = h.tg.last_confirmation();
        h.press_on(&format!("cx:{nonce}"), msg);
        assert!(h.bot.pending_nonce().is_none());
        assert!(h.tg.edits().iter().any(|(m, t)| *m == msg && t == "❌ Shutdown cancelled."));
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);

        h.cmd("/sleep");
        let (_, msg) = h.tg.last_confirmation();
        h.tg.clear();
        h.cmd("/cancel");
        assert!(h.bot.pending_nonce().is_none());
        assert!(h.tg.edits().iter().any(|(m, t)| *m == msg && t == "❌ Sleep cancelled."));
        assert_eq!(h.tg.sends().last().unwrap().1, "❌ Sleep cancelled.");
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn cancel_with_nothing_pending() {
        let h = harness();
        h.cmd("/cancel");
        assert_eq!(h.tg.texts(), vec!["ℹ️ Nothing to cancel.".to_string()]);
        // an unknown cancel nonce is answered, never "unknown"
        h.press("cx:0123456789abcdef0123456789abcdef");
        assert_eq!(h.tg.answers(), vec![(Some(ui::CONFIRMATION_INVALID.to_string()), true)]);
    }

    #[test]
    fn newer_request_supersedes_older() {
        let h = harness();
        h.cmd("/shutdown");
        let (old_nonce, old_msg) = h.tg.last_confirmation();
        h.cmd("/sleep");
        let (new_nonce, new_msg) = h.tg.last_confirmation();
        assert_ne!(old_nonce, new_nonce);
        assert!(h.tg.edits().iter().any(|(m, t)| *m == old_msg && t.contains("Superseded")));
        h.press_on(&format!("cf:{old_nonce}"), old_msg);
        assert_eq!(h.sys.executed(), 0);
        h.press_on(&format!("cf:{new_nonce}"), new_msg);
        assert_eq!(h.sys.count("execute_power:sleep"), 1);
        assert_eq!(h.sys.count("execute_power:shutdown"), 0);
    }

    #[test]
    fn confirmation_rejected_when_power_disabled_meanwhile() {
        let h = harness();
        h.cmd("/shutdown");
        let (nonce, msg) = h.tg.last_confirmation();
        h.disable(Feature::PowerManagement);
        h.press_on(&format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
        assert!(h.tg.last_text().contains("Power Management is disabled"));
    }

    // ───────────── feature gating ─────────────

    #[test]
    fn disabled_features_reject_commands_and_buttons() {
        let cases: Vec<(Feature, Vec<&str>, Vec<&str>)> = vec![
            (Feature::NetworkInfo, vec!["/network"], vec!["nav:net"]),
            (Feature::BatteryInfo, vec!["/battery"], vec!["nav:bat"]),
            (
                Feature::TailscaleManagement,
                vec!["/tailscale", "/tailscale status", "/tailscale up", "/tailscale down"],
                vec!["nav:ts", "ts:up", "ts:down"],
            ),
            (
                Feature::PowerManagement,
                vec!["/shutdown", "/restart", "/sleep", "/hibernate", "/lock", "/logout"],
                vec!["pw:shutdown", "pw:restart", "pw:sleep", "pw:hibernate", "act:lock", "act:logout"],
            ),
        ];
        for (feature, commands, buttons) in cases {
            let expected = format!("🚫 <b>{} is disabled.</b>\nEnable it in /features.", feature.label());
            for c in commands {
                let h = harness();
                h.disable(feature);
                h.cmd(c);
                assert_eq!(h.tg.last_text(), expected, "{c}");
                assert_eq!(h.sys.executed(), 0, "{c}");
                assert_eq!(lock(&h.sys.calls).iter().filter(|x| !x.starts_with("system_status")).count(), 0, "{c}");
                assert!(h.bot.pending_nonce().is_none());
            }
            for b in buttons {
                let h = harness();
                h.disable(feature);
                h.press(b);
                assert_eq!(h.tg.last_text(), expected, "{b}");
                assert_eq!(h.sys.executed(), 0, "{b}");
                assert!(h.bot.pending_nonce().is_none());
            }
        }
    }

    #[test]
    fn features_screen_works_with_everything_disabled() {
        let h = harness();
        h.ctx
            .settings
            .update(|s| {
                for f in Feature::ALL {
                    s.features.set(f, false);
                }
            })
            .unwrap();
        h.cmd("/features");
        let t = h.tg.last_text();
        assert!(t.contains("PREDATOR FEATURES"));
        assert!(t.contains("🔴 Windows Login Monitoring"));
        assert!(!t.contains("🟢"));
        h.press("nav:feat");
        assert!(h.tg.last_text().contains("PREDATOR FEATURES"));
        h.press("ft:7");
        assert!(h.ctx.settings.feature(Feature::BatteryInfo));
        assert!(h.tg.last_text().contains("🟢 Battery Information"));
        // the read-only screens that are not feature gated still work
        h.cmd("/status");
        assert!(h.tg.last_text().contains("SYSTEM STATUS"));
        h.cmd("/help");
        h.cmd("/history");
        h.cmd("/menu");
        assert!(h.tg.last_text().contains("PREDATOR REMOTE CONTROL"));
    }

    // ───────────── navigation / misc ─────────────

    #[test]
    fn every_keyboard_button_is_handled() {
        use crate::features::FeatureSet;
        // keyboards of every builder ...
        let mut kbs: Vec<InlineKeyboardMarkup> = vec![
            ui::main_keyboard(),
            ui::features_keyboard(&FeatureSet::default()),
            ui::tailscale_keyboard(&MockSys::ts_status()),
            ui::menu_keyboard(),
        ];
        let listed = [
            AuthorizedUser::new(OWNER, "owner", UserRole::Admin, 0),
            AuthorizedUser::new(SECOND, "bob", UserRole::User, 0),
        ];
        let screens = [
            ui::status_screen(&ui::StatusView::default()),
            ui::network_screen(&Err("x".into())),
            ui::battery_screen(&Err("x".into())),
            ui::history_screen(&[]),
            ui::help_screen(60, 300),
            ui::confirm_screen(PowerAction::Shutdown, "PC", 60, "0123456789abcdef0123456789abcdef"),
            ui::disabled_screen(Feature::BatteryInfo),
            ui::plain_text_hint(),
            ui::tailscale_screen(&TailscaleStatus::default()),
            ui::tailscale_failed(true, "x"),
            ui::power_expired(PowerAction::Sleep),
            ui::lock_result(&Err("x".into())),
            ui::backlog_ignored_screen(&CallbackAction::TailscaleUp, &FeatureSet::default()),
            ui::backlog_ignored_screen(&CallbackAction::ToggleFeature(Feature::BatteryInfo), &FeatureSet::default()),
            ui::backlog_ignored_screen(&CallbackAction::Lock, &FeatureSet::default()),
            ui::backlog_ignored_screen(&CallbackAction::RemoveUser(SECOND), &FeatureSet::default()),
            ui::users_screen(&listed, OWNER),
            ui::paired_screen("MY-PC"),
            ui::already_paired_screen(),
        ];
        kbs.extend(screens.into_iter().filter_map(|s| s.1));
        // ... plus every keyboard the bot itself produced while navigating everywhere
        let h = harness();
        for nav in Nav::ALL {
            h.press(nav.data());
        }
        for cmd in ["/menu", "/shutdown", "/lock", "/tailscale up", "/cancel", "hello", "/users", "/pair"] {
            h.cmd(cmd);
        }
        kbs.extend(h.tg.keyboards());

        let mut datas: Vec<String> = kbs.iter().flat_map(InlineKeyboardMarkup::callback_datas).collect();
        datas.sort();
        datas.dedup();
        // 8 nav + 9 ft + 4 pw + 2 act + 2 ts + two cf/cx pairs + um:ls + um:rm
        assert!(datas.len() >= 31, "only {} distinct buttons", datas.len());
        for d in datas {
            assert!(d.len() <= ui::MAX_CALLBACK_DATA, "{d} too long");
            let h = harness();
            h.press(&d);
            let answers = h.tg.answers();
            assert_eq!(answers.len(), 1, "{d}: every callback must be answered exactly once");
            assert!(answers.iter().all(|(t, _)| t.as_deref() != Some(ui::UNKNOWN_BUTTON)), "{d} was not recognised");
            assert!(!h.tg.all_text().contains("Unknown button"), "{d}");
        }
    }

    #[test]
    fn unknown_callback_data_is_answered() {
        let h = harness();
        h.press("rm:-rf");
        assert_eq!(h.tg.answers(), vec![(Some(ui::UNKNOWN_BUTTON.to_string()), false)]);
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn navigation_edits_in_place_with_fallback() {
        let h = harness();
        h.press("nav:status");
        let edits = h.tg.edits();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].0, MENU_MSG);
        assert!(edits[0].1.contains("SYSTEM STATUS"));
        assert!(h.tg.sends().is_empty());
        // message gone: the screen is sent as a new message instead
        h.tg.fail_edits.store(true, Ordering::SeqCst);
        h.press("nav:main");
        assert!(h.tg.sends().last().unwrap().1.contains("PREDATOR REMOTE CONTROL"));
    }

    #[test]
    fn botname_suffix_is_stripped() {
        let h = harness();
        h.cmd("/status@ExampleBot");
        assert!(h.tg.last_text().contains("SYSTEM STATUS"));
        h.cmd("/LOCK@ExampleBot");
        assert_eq!(h.sys.count("lock"), 1);
        h.cmd("/tailscale@ExampleBot status");
        assert!(h.tg.last_text().contains("TAILSCALE"));
    }

    #[test]
    fn unknown_command_and_plain_text() {
        let h = harness();
        h.cmd("/foo");
        assert_eq!(h.tg.last_text(), ui::UNKNOWN_COMMAND);
        h.cmd("/");
        assert_eq!(h.tg.last_text(), ui::UNKNOWN_COMMAND);
        h.cmd("hello there");
        let calls = h.tg.calls();
        match calls.last() {
            Some(Call::Send { html, kb: Some(kb), .. }) => {
                assert!(html.contains("/menu"));
                assert_eq!(kb.callback_datas(), vec!["nav:main"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn history_screen_lists_recent_events_escaped() {
        let h = harness();
        h.ctx.history.record(crate::notify::EventDetails {
            user: "<b>evil&".into(),
            method: "Interactive".into(),
            event_unix: now_unix(),
            ..Default::default()
        });
        h.cmd("/history");
        let t = h.tg.last_text();
        assert!(t.contains("&lt;b&gt;evil&amp; · Interactive"), "{t}");
        assert!(!t.contains("<b>evil"));
    }

    #[test]
    fn missing_sender_or_message_is_rejected() {
        let h = harness();
        let mut m = message(user(OWNER, "owner"), chat(OWNER, "private"), "/lock", now_unix());
        m.from = None;
        h.bot.handle_update(&msg_update(m));
        let mut u = cb_update(user(OWNER, "owner"), chat(OWNER, "private"), "act:lock", 1);
        if let Some(cq) = u.callback_query.as_mut() {
            cq.message = None;
        }
        h.bot.handle_update(&u);
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.tg.answers(), vec![(Some(ui::NOT_AUTHORIZED.to_string()), true)]);
    }

    // ───────────── chat cleanup ─────────────

    fn ids_of(entries: &[TrackedMessage]) -> Vec<i64> {
        entries.iter().map(|e| e.message_id).collect()
    }

    /// A new command deletes the earlier commands, replies and system notices — never login /
    /// logout / security alerts (those are never tracked).
    #[test]
    fn new_command_deletes_previous_ephemeral_messages_but_never_alerts() {
        let h = harness();
        let now = now_unix();
        // what the sender does after delivering notifications: only System notices are tracked
        for (kind, id) in [
            (crate::notify::NotificationKind::Login, 900),
            (crate::notify::NotificationKind::Logout, 901),
            (crate::notify::NotificationKind::SshLogin, 902),
            (crate::notify::NotificationKind::FailedLogin, 903),
            (crate::notify::NotificationKind::Security, 904),
            (crate::notify::NotificationKind::System, 905),
        ] {
            if janitor::is_ephemeral_kind(kind) {
                h.ctx.track_chat_message(OWNER, id, now);
            }
        }
        h.say("/status", 20);
        let status_reply = h.tg.last_sent_id();
        assert!(h.tracked(20) && h.tracked(status_reply));
        // the system notice went with the first command, after the reply
        assert_eq!(h.tg.deleted(), vec![905]);
        assert!(h.tg.last_text().contains("SYSTEM STATUS"));

        h.say("/network", 21);
        assert_eq!(h.tg.deleted(), vec![905, 20, status_reply]);
        assert!(h.tracked(21) && h.tracked(h.tg.last_sent_id()));
        // plain text and unknown commands clean up as well
        h.say("hello", 22);
        h.say("/foo", 23);
        assert!(h.tg.deleted().contains(&21) && h.tg.deleted().contains(&22));
        for kept in 900..=904 {
            assert!(!h.tg.deleted().contains(&kept), "alert {kept} was deleted");
            assert!(!h.tracked(kept));
        }
        // every delete happened after the corresponding reply (the reply is never deleted with it)
        let sent = h.tg.sent_ids();
        assert!(!h.tg.deleted().contains(sent.last().unwrap()));
    }

    #[test]
    fn pending_confirmation_survives_new_commands_until_resolved() {
        let h = harness();
        h.say("/shutdown", 30);
        let (nonce, dialog) = h.tg.last_confirmation();
        assert!(h.ctx.janitor.is_protected(OWNER, dialog));
        h.say("/status", 31);
        h.say("/network", 32);
        assert!(h.tg.deleted().contains(&30) && h.tg.deleted().contains(&31));
        assert!(!h.tg.deleted().contains(&dialog), "the pending dialog must stay");
        assert!(h.bot.pending_nonce().is_some());
        // cancelled: the dialog is an ordinary short-lived message again
        h.press_live(&format!("cx:{nonce}"), dialog, 5);
        assert!(!h.ctx.janitor.is_protected(OWNER, dialog));
        h.say("/menu", 33);
        assert!(h.tg.deleted().contains(&dialog));

        // confirmed: the result replaces the dialog and is cleaned with the next command
        h.say("/restart", 34);
        let (nonce, dialog) = h.tg.last_confirmation();
        h.say("/battery", 35);
        assert!(!h.tg.deleted().contains(&dialog));
        h.press_live(&format!("cf:{nonce}"), dialog, 5);
        assert_eq!(h.sys.count("execute_power:restart"), 1);
        assert!(!h.ctx.janitor.is_protected(OWNER, dialog));
        h.say("/status", 36);
        assert!(h.tg.deleted().contains(&dialog));

        // superseded: the old dialog is released, the new one protected
        h.say("/sleep", 37);
        let (_, first) = h.tg.last_confirmation();
        h.say("/hibernate", 38);
        let (_, second) = h.tg.last_confirmation();
        assert!(!h.ctx.janitor.is_protected(OWNER, first));
        assert!(h.ctx.janitor.is_protected(OWNER, second));
        // expired: the next command deletes its dialog; the pending entry itself stays, so a late
        // press is still answered with "expired" and never executes
        let (nonce, _) = h.tg.last_confirmation();
        h.bot.age_pending(Duration::from_secs(61));
        h.say("/status", 39);
        assert!(h.tg.deleted().contains(&second));
        assert!(!h.ctx.janitor.is_protected(OWNER, second));
        assert_eq!(h.bot.pending_nonce().as_deref(), Some(nonce.as_str()));
        h.press_live(&format!("cf:{nonce}"), second, 70);
        assert!(h.tg.all_text().contains("Confirmation expired"));
        assert_eq!(h.sys.executed(), 1);
    }

    /// The owner sends nothing after asking for a power action: once the confirmation expired,
    /// its dialog is released, so the poller's time-based sweep deletes it like any other reply.
    #[test]
    fn expired_confirmation_is_swept_without_a_new_command() {
        let h = harness();
        h.say("/shutdown", 80);
        let (_, dialog) = h.tg.last_confirmation();
        assert!(!h.bot.release_expired_confirmation(), "still valid: stays protected");
        assert!(h.ctx.janitor.is_protected(OWNER, dialog));
        let later = now_unix() + 3600;
        assert_eq!(ids_of(&h.ctx.janitor.take_expired(later, 600)), vec![80], "only the command goes");
        h.bot.age_pending(Duration::from_secs(61));
        assert!(h.bot.release_expired_confirmation());
        assert!(!h.bot.release_expired_confirmation(), "released once");
        assert_eq!(ids_of(&h.ctx.janitor.take_expired(later, 600)), vec![dialog]);
        assert!(h.bot.pending_nonce().is_some(), "a late press still gets the expired answer");
        // nothing pending: nothing to do
        h.say("/cancel", 81);
        assert!(!h.bot.release_expired_confirmation());
    }

    /// The earlier messages leave the janitor's list only after the reply went out: if handling
    /// the command panics, they stay tracked and are cleaned with the next command.
    #[test]
    fn previous_messages_survive_a_failing_command() {
        struct PanicPower(MockSys);
        impl SystemActions for PanicPower {
            fn check_power(&self, _: PowerAction) -> Result<(), String> {
                panic!("boom")
            }
            fn execute_power(&self, a: PowerAction) -> Result<String, String> {
                self.0.execute_power(a)
            }
            fn lock(&self) -> Result<String, String> {
                self.0.lock()
            }
            fn logout(&self) -> Result<String, String> {
                self.0.logout()
            }
            fn network(&self) -> Result<NetworkInfo, String> {
                self.0.network()
            }
            fn battery(&self) -> Result<BatteryInfo, String> {
                self.0.battery()
            }
            fn tailscale_status(&self) -> TailscaleStatus {
                self.0.tailscale_status()
            }
            fn tailscale_up(&self) -> TailscaleOpResult {
                self.0.tailscale_up()
            }
            fn tailscale_down(&self) -> TailscaleOpResult {
                self.0.tailscale_down()
            }
            fn system_status(&self) -> SystemStatus {
                self.0.system_status()
            }
            fn is_dry_run(&self) -> bool {
                true
            }
        }
        let ctx = AppContext::for_tests();
        let tg = Arc::new(MockTg::default());
        let bot = Bot::new(ctx.clone(), tg.clone(), Arc::new(PanicPower(MockSys::default())));
        let say = |text: &str, id: i64| {
            let mut m = message(user(OWNER, "owner"), chat(OWNER, "private"), text, now_unix());
            m.message_id = id;
            bot.handle_update(&msg_update(m));
        };
        say("/status", 90);
        let reply = tg.last_sent_id();
        tg.deletes.lock().unwrap().clear();
        say("/shutdown", 91); // panics inside check_power (caught by the dispatcher)
        assert!(tg.deleted().is_empty());
        for id in [90, reply, 91] {
            assert!(ctx.janitor.contains(OWNER, id), "{id} must stay tracked");
        }
        say("/menu", 92);
        let deleted = tg.deleted();
        for id in [90, reply, 91] {
            assert!(deleted.contains(&id), "{id} not deleted: {deleted:?}");
        }
    }

    #[test]
    fn cancel_command_releases_the_dialog() {
        let h = harness();
        h.say("/hibernate", 40);
        let (_, dialog) = h.tg.last_confirmation();
        h.say("/cancel", 41);
        assert!(h.bot.pending_nonce().is_none());
        assert!(!h.ctx.janitor.is_protected(OWNER, dialog));
        assert!(h.tracked(dialog));
        h.say("/menu", 42);
        assert!(h.tg.deleted().contains(&dialog) && h.tg.deleted().contains(&41));
    }

    #[test]
    fn clear_deletes_everything_including_itself() {
        let h = harness();
        h.ctx.track_chat_message(OWNER, 905, now_unix()); // a system notice
        h.say("/status", 50);
        let reply = h.tg.last_sent_id();
        h.say("/shutdown", 51);
        let (_, dialog) = h.tg.last_confirmation();
        let sends_before = h.tg.sends().len();
        h.tg.deletes.lock().unwrap().clear();
        h.say("/clear", 52);
        let deleted = h.tg.deleted();
        for id in [51, dialog, 52] {
            assert!(deleted.contains(&id), "{id} not deleted: {deleted:?}");
        }
        assert!(!deleted.contains(&reply) && !deleted.contains(&905), "already deleted by /shutdown");
        assert_eq!(lock(&h.tg.deletes).len(), 1, "one request");
        assert!(h.ctx.janitor.is_empty());
        // no reply, no confirmation, and the dialog's confirmation is gone
        assert_eq!(h.tg.sends().len(), sends_before);
        assert!(h.bot.pending_nonce().is_none());
        assert!(!h.ctx.janitor.is_protected(OWNER, dialog));
        // /clear@botname works too; with nothing tracked only the command itself goes
        h.tg.deletes.lock().unwrap().clear();
        h.say("/clear@ExampleBot", 53);
        assert_eq!(h.tg.deleted(), vec![53]);
        assert_eq!(h.sys.executed(), 0);
    }

    #[test]
    fn disabled_cleanup_tracks_and_deletes_nothing() {
        let h = harness();
        h.ctx.settings.update(|s| s.auto_clean_chat = false).unwrap();
        h.say("/status", 60);
        h.say("/shutdown", 61);
        h.say("hello", 62);
        h.press_live("nav:main", MENU_MSG, 10);
        h.say("/clear", 63);
        assert!(h.tg.deleted().is_empty());
        assert!(lock(&h.tg.deletes).is_empty());
        assert!(h.ctx.janitor.is_empty());
        assert!(h.tg.last_text().contains("Automatic chat cleaning is switched off"));
        // the help says so
        h.say("/help", 64);
        assert!(h.tg.last_text().contains("Automatic chat cleaning is switched off"));
        assert!(h.bot.pending_nonce().is_some(), "/clear does not touch the confirmation when off");
    }

    #[test]
    fn button_presses_keep_their_menu_alive_and_track_fallback_messages() {
        let h = harness();
        h.ctx.settings.update(|s| s.chat_clean_after_secs = 600).unwrap();
        // a menu sent 10 minutes ago (e.g. before a restart) is tracked when used
        h.press_live("nav:status", MENU_MSG, 590);
        assert!(h.tracked(MENU_MSG));
        let e = h.ctx.janitor.entries();
        assert!(e[0].active_unix >= now_unix() - 1, "{e:?}");
        assert!(h.tg.sends().is_empty(), "edited in place");
        assert!(h.tg.deleted().is_empty(), "a button press deletes nothing");
        // the edit fails: the screen is sent as a new message, which is tracked
        h.tg.fail_edits.store(true, Ordering::SeqCst);
        h.press_live("nav:main", MENU_MSG, 590);
        assert!(h.tracked(h.tg.last_sent_id()));
        // Telegram reports messages it cannot serve any more with date 0: not tracked
        h.press_live("nav:main", 4321, now_unix());
        assert!(!h.tracked(4321));
        // the help mentions /clear and the configured time
        h.say("/help", 70);
        let t = h.tg.texts().into_iter().rev().find(|t| t.contains("HELP")).unwrap();
        assert!(t.contains("/clear") && t.contains("after 10 minutes without use"), "{t}");
    }

    #[test]
    fn strangers_and_groups_never_feed_the_janitor() {
        let h = harness();
        h.bot.handle_update(&msg_update(message(user(STRANGER, "x"), chat(STRANGER, "private"), "/clear", now_unix())));
        h.bot.handle_update(&msg_update(message(user(OWNER, "owner"), chat(-100, "group"), "/clear", now_unix())));
        assert!(h.ctx.janitor.is_empty());
        assert!(lock(&h.tg.deletes).is_empty());
        // the access-denied reply in the stranger's chat is not tracked either
        assert_eq!(h.tg.sends().len(), 1);
    }

    #[test]
    fn panicking_system_call_does_not_escape() {
        struct PanicSys;
        impl SystemActions for PanicSys {
            fn check_power(&self, _: PowerAction) -> Result<(), String> {
                panic!("boom")
            }
            fn execute_power(&self, _: PowerAction) -> Result<String, String> {
                panic!("boom")
            }
            fn lock(&self) -> Result<String, String> {
                panic!("boom")
            }
            fn logout(&self) -> Result<String, String> {
                panic!("boom")
            }
            fn network(&self) -> Result<NetworkInfo, String> {
                panic!("boom")
            }
            fn battery(&self) -> Result<BatteryInfo, String> {
                panic!("boom")
            }
            fn tailscale_status(&self) -> TailscaleStatus {
                panic!("boom")
            }
            fn tailscale_up(&self) -> TailscaleOpResult {
                panic!("boom")
            }
            fn tailscale_down(&self) -> TailscaleOpResult {
                panic!("boom")
            }
            fn system_status(&self) -> SystemStatus {
                panic!("boom")
            }
            fn is_dry_run(&self) -> bool {
                false
            }
        }
        let ctx = AppContext::for_tests();
        let tg = Arc::new(MockTg::default());
        let bot = Bot::new(ctx, tg.clone(), Arc::new(PanicSys));
        let send = |text: &str| {
            bot.handle_update(&msg_update(message(user(OWNER, "o"), chat(OWNER, "private"), text, now_unix())))
        };
        send("/lock");
        send("/status");
        send("/tailscale up");
        bot.join_workers();
        // the worker caught the panic, reported it and released the busy flag
        assert!(tg.last_text().contains("Tailscale up failed"));
        send("/tailscale down");
        bot.join_workers();
        assert!(tg.last_text().contains("Tailscale down failed"));
    }

    // ───────────── multiple users / pairing ─────────────

    /// An unauthorized user with a valid code is added (role of the code), gets the paired
    /// reply, everyone else is told, and the code is used up.
    #[test]
    fn valid_code_pairs_the_sender_and_tells_the_others() {
        for (role, deep_link) in [(UserRole::User, false), (UserRole::Admin, true)] {
            let h = harness();
            let code = h.ctx.pairing.start(role, 600, "MY-PC\\alice", now_unix());
            let text = if deep_link {
                format!("/start {}", code.deep_link_payload())
            } else {
                format!("/pair {}", code.display())
            };
            h.say_as(STRANGER, &text, 40);
            let added = h.ctx.settings.user(STRANGER).expect("paired");
            assert_eq!(added.role, role);
            assert_eq!(added.name, "@u", "display name from the @username");
            assert!(added.added_unix > 0);
            assert_eq!(h.tg.sends(), vec![(STRANGER, "✅ Paired with TESTPC. Send /menu to start.".to_string())]);
            // the notice goes to every OTHER user (the new one is pre-excluded)
            assert_eq!(h.ctx.queue.len(), 1);
            let n = h.ctx.queue.front().unwrap();
            assert_eq!(n.kind, NotificationKind::Security);
            assert!(n.html.contains("NEW TELEGRAM USER PAIRED"), "{}", n.html);
            assert!(n.html.contains(&STRANGER.to_string()) && n.html.contains(role.label()), "{}", n.html);
            assert!(n.html.contains("@u"), "{}", n.html);
            assert_eq!(n.delivered_to, vec![STRANGER]);
            assert!(!n.html.contains(&code.code), "the code never leaves the PC");
            // single use; the tray / CLI can see who paired
            let st = h.ctx.pairing.status(now_unix());
            assert!(!st.active);
            assert_eq!(st.last_paired.map(|(u, _)| u.id), Some(STRANGER));
            // the new user can use the bot right away, and the pairing message is short-lived
            h.say_as(STRANGER, "/status", 41);
            assert!(h.last_sent_to(STRANGER).contains("SYSTEM STATUS"));
            assert!(h.tg.deleted().contains(&40));
            assert_eq!(h.sys.executed(), 0);
        }
    }

    /// The first account paired into an empty list becomes an admin whatever the code says.
    #[test]
    fn first_paired_user_is_admin() {
        let h = harness();
        h.ctx.settings.update(|s| s.authorized_users.clear()).unwrap();
        let code = h.ctx.pairing.start(UserRole::User, 600, "x", now_unix());
        h.say_as(STRANGER, &format!("/pair {}", code.code), 40);
        assert_eq!(h.ctx.settings.user(STRANGER).map(|u| u.role), Some(UserRole::Admin));
        // nobody else to tell: the notice is complete at once
        assert_eq!(h.ctx.queue.front().unwrap().delivered_to, vec![STRANGER]);
    }

    /// Wrong, expired, missing, malformed and exhausted codes all get exactly the reply any other
    /// unauthorized message gets — nobody can tell whether a code is active. Guesses are never
    /// logged or forwarded.
    #[test]
    fn failed_pairing_gets_exactly_the_generic_denial() {
        for case in ["wrong", "expired", "none", "garbage", "deep link", "empty", "exhausted"] {
            let h = harness();
            let now = now_unix();
            let text = match case {
                "wrong" => {
                    let c = h.ctx.pairing.start(UserRole::Admin, 600, "x", now);
                    format!("/pair {}", other_code(&c.code))
                }
                "expired" => {
                    let c = h.ctx.pairing.start(UserRole::Admin, 60, "x", now - 120);
                    format!("/pair {}", c.code)
                }
                "none" => "/pair 12345678".to_string(),
                "garbage" => {
                    h.ctx.pairing.start(UserRole::Admin, 600, "x", now);
                    "/pair let me in".to_string()
                }
                "deep link" => {
                    let c = h.ctx.pairing.start(UserRole::Admin, 600, "x", now);
                    format!("/start pair-{}", other_code(&c.code))
                }
                "empty" => {
                    h.ctx.pairing.start(UserRole::Admin, 600, "x", now);
                    "/pair".to_string()
                }
                _ => {
                    let c = h.ctx.pairing.start(UserRole::Admin, 600, "x", now);
                    for i in 0..crate::pairing::MAX_WRONG_PER_CODE {
                        let _ = h.ctx.pairing.redeem(&other_code(&c.code), 777 + i64::from(i), now);
                    }
                    format!("/pair {}", c.code)
                }
            };
            h.say_as(STRANGER, &text, 40);
            // reference: an ordinary unauthorized message from someone else
            h.say_as(3000, "hello", 41);
            assert!(!h.ctx.settings.is_authorized(STRANGER), "{case}");
            assert_eq!(
                h.tg.calls()
                    .into_iter()
                    .filter_map(|c| match c {
                        Call::Send { chat, html, kb, .. } => Some((chat, html, kb)),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                vec![(STRANGER, ui::ACCESS_DENIED.to_string(), None), (3000, ui::ACCESS_DENIED.to_string(), None)],
                "{case}"
            );
            // both alerts look alike; the guess itself is hidden
            assert_eq!(h.ctx.queue.len(), 2, "{case}");
            let alert = h.ctx.queue.front().unwrap().html;
            assert!(alert.contains("UNAUTHORIZED ACCESS ATTEMPT"), "{case}: {alert}");
            if text.contains("12345678") || text.chars().filter(char::is_ascii_digit).count() >= 8 {
                assert!(alert.contains("pairing code hidden"), "{case}: {alert}");
                let digits: String = text.chars().filter(char::is_ascii_digit).collect();
                assert!(!alert.contains(&digits[..6]), "{case}: {alert}");
            }
            // a second attempt within the hour: logged only, like any other message
            h.say_as(STRANGER, "/pair 00000000", 42);
            assert_eq!(h.tg.sends().len(), 2, "{case}");
            assert!(h.ctx.janitor.is_empty(), "{case}: strangers never feed the janitor");
            assert_eq!(h.sys.executed(), 0);
        }
    }

    /// A paired user sending a code (or the deep link) is told so; the code is not used up.
    #[test]
    fn already_authorized_redeem_keeps_the_code() {
        let h = harness();
        let code = h.ctx.pairing.start(UserRole::User, 600, "x", now_unix());
        for text in [format!("/pair {}", code.code), format!("/start pair-{}", code.code), "/pair".to_string()] {
            h.cmd(&text);
            assert!(h.tg.last_text().starts_with(ui::ALREADY_PAIRED), "{text}: {}", h.tg.last_text());
        }
        assert!(h.ctx.pairing.status(now_unix()).active, "not used up");
        assert!(h.ctx.queue.is_empty(), "no notices");
        assert_eq!(h.ctx.settings.authorized_users().len(), 1);
        // the code still works for the account it was meant for
        h.say_as(STRANGER, &format!("/pair {}", code.code), 50);
        assert!(h.ctx.settings.is_authorized(STRANGER));
    }

    /// Tapping /pair in Telegram's command menu sends a bare `/pair`: it gets the generic denial
    /// but does not use up the code, so the account can still pair with `/pair CODE`.
    #[test]
    fn bare_pair_from_the_command_menu_does_not_burn_the_code() {
        let h = harness();
        let code = h.ctx.pairing.start(UserRole::User, 600, "x", now_unix());
        for (i, text) in ["/pair", "/pair code please", "/pair 1234"].iter().cycle().take(12).enumerate() {
            h.say_as(STRANGER, text, 40 + i as i64);
        }
        assert_eq!(h.tg.sends(), vec![(STRANGER, ui::ACCESS_DENIED.to_string())], "one generic denial per hour");
        assert!(h.ctx.pairing.status(now_unix()).active, "malformed input is no guess");
        h.say_as(STRANGER, &format!("/pair {}", code.display()), 60);
        assert!(h.ctx.settings.is_authorized(STRANGER));
        assert_eq!(h.last_sent_to(STRANGER), "✅ Paired with TESTPC. Send /menu to start.");
    }

    /// A valid code redeemed while every slot is taken: the generic denial, nobody is added and
    /// nobody is told about a new user (the code is used up; the PC sees it as no longer active).
    #[test]
    fn pairing_refused_when_the_user_limit_is_reached() {
        let h = harness();
        for i in 1..MAX_AUTHORIZED_USERS as i64 {
            let u = AuthorizedUser::new(10_000 + i, "u", UserRole::User, 0);
            assert_eq!(h.ctx.settings.add_user(u).unwrap(), AddUserOutcome::Added);
        }
        assert_eq!(h.ctx.settings.authorized_users().len(), MAX_AUTHORIZED_USERS);
        let code = h.ctx.pairing.start(UserRole::Admin, 600, "x", now_unix());
        h.say_as(STRANGER, &format!("/pair {}", code.code), 40);
        assert!(!h.ctx.settings.is_authorized(STRANGER));
        assert_eq!(h.tg.sends(), vec![(STRANGER, ui::ACCESS_DENIED.to_string())]);
        let st = h.ctx.pairing.status(now_unix());
        assert!(!st.active && st.last_paired.is_none(), "{st:?}");
        assert_eq!(h.ctx.queue.len(), 1);
        let alert = h.ctx.queue.front().unwrap().html;
        assert!(alert.contains("UNAUTHORIZED ACCESS ATTEMPT") && !alert.contains("NEW TELEGRAM USER"), "{alert}");
        assert!(!alert.contains(&code.code[..6]), "{alert}");
    }

    /// A pairing code is only accepted in the sender's own private chat, never from bots.
    #[test]
    fn pairing_needs_the_senders_own_private_chat() {
        let h = harness();
        let code = h.ctx.pairing.start(UserRole::Admin, 600, "x", now_unix());
        let text = format!("/pair {}", code.code);
        h.bot.handle_update(&msg_update(message(user(STRANGER, "u"), chat(4242, "private"), &text, now_unix())));
        let mut bot_user = user(3000, "bot");
        bot_user.is_bot = true;
        h.bot.handle_update(&msg_update(message(bot_user, chat(3000, "private"), &text, now_unix())));
        h.bot.handle_update(&msg_update(message(user(3001, "u"), chat(-100, "group"), &text, now_unix())));
        assert_eq!(h.ctx.settings.authorized_users().len(), 1);
        assert_eq!(h.tg.leaves(), vec![-100]);
        assert!(h.tg.sends().iter().all(|(_, t)| t == ui::ACCESS_DENIED));
        assert!(h.ctx.pairing.status(now_unix()).active, "refused before the code was checked");
    }

    #[test]
    fn second_user_can_use_every_command() {
        let h = harness();
        h.add_second();
        for (cmd, needle) in [
            ("/menu", "PREDATOR REMOTE CONTROL"),
            ("/status", "SYSTEM STATUS"),
            ("/network", "NETWORK STATUS"),
            ("/battery", "BATTERY STATUS"),
            ("/history", "LOGIN HISTORY"),
            ("/features", "PREDATOR FEATURES"),
            ("/tailscale", "TAILSCALE"),
            ("/help", "HELP"),
            ("/users", "TELEGRAM USERS"),
            ("/cancel", "Nothing to cancel"),
        ] {
            h.say_as(SECOND, cmd, 60);
            assert!(h.last_sent_to(SECOND).contains(needle), "{cmd}: {}", h.last_sent_to(SECOND));
        }
        h.say_as(SECOND, "/lock", 61);
        h.say_as(SECOND, "/logout", 62);
        h.say_as(SECOND, "/tailscale up", 63);
        assert_eq!((h.sys.count("lock"), h.sys.count("logout"), h.sys.count("tailscale_up")), (1, 1, 1));
        h.say_as(SECOND, "/shutdown", 64);
        let (nonce, msg) = h.tg.last_confirmation_in(SECOND);
        assert_eq!(h.bot.pending_nonce_for(SECOND).as_deref(), Some(nonce.as_str()));
        h.press_as(SECOND, &format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.count("execute_power:shutdown"), 1);
        // buttons
        h.press_as(SECOND, "ft:1", MENU_MSG);
        assert!(!h.ctx.settings.feature(Feature::SshMonitoring));
        h.press_as(SECOND, "act:lock", MENU_MSG);
        h.press_as(SECOND, "nav:status", MENU_MSG);
        assert_eq!(h.sys.count("lock"), 2);
        // everything happened in the second user's chat
        let chats: Vec<i64> =
            h.tg.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Send { chat, .. } | Call::Edit { chat, .. } => Some(chat),
                    _ => None,
                })
                .collect();
        assert!(chats.iter().all(|c| *c == SECOND), "{chats:?}");
    }

    /// Confirmations are per user: A can neither confirm nor cancel B's pending shutdown, and
    /// both can have one at the same time.
    #[test]
    fn users_cannot_touch_each_others_confirmations() {
        let h = harness();
        h.add_second();
        h.say_as(SECOND, "/shutdown", 60);
        let (nonce_b, msg_b) = h.tg.last_confirmation_in(SECOND);
        // the owner presses B's buttons (they can only press them in their own chat)
        h.tg.clear();
        h.press_as(OWNER, &format!("cf:{nonce_b}"), msg_b);
        h.press_as(OWNER, &format!("cx:{nonce_b}"), msg_b);
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.tg.answers(), vec![(Some(ui::CONFIRMATION_INVALID.to_string()), true); 2]);
        assert!(h.tg.edits().is_empty());
        assert_eq!(h.bot.pending_nonce_for(SECOND).as_deref(), Some(nonce_b.as_str()));
        assert!(h.ctx.janitor.is_protected(SECOND, msg_b));
        // the owner's /cancel cancels nothing of B's
        h.say_as(OWNER, "/cancel", 61);
        assert_eq!(h.last_sent_to(OWNER), "ℹ️ Nothing to cancel.");
        assert!(h.bot.pending_nonce_for(SECOND).is_some());
        // both can have their own confirmation at the same time; B's is not superseded
        h.say_as(OWNER, "/restart", 62);
        let (nonce_a, msg_a) = h.tg.last_confirmation_in(OWNER);
        assert!(h.bot.pending_nonce_for(SECOND).is_some());
        assert!(!h.tg.all_text().contains("Superseded"));
        // B cannot confirm A's either
        h.press_as(SECOND, &format!("cf:{nonce_a}"), msg_a);
        assert_eq!(h.sys.executed(), 0);
        // each one confirms their own
        h.press_as(SECOND, &format!("cf:{nonce_b}"), msg_b);
        h.press_as(OWNER, &format!("cf:{nonce_a}"), msg_a);
        assert_eq!(h.sys.count("execute_power:shutdown"), 1);
        assert_eq!(h.sys.count("execute_power:restart"), 1);
        // /clear in one chat discards only that user's confirmation
        h.say_as(SECOND, "/sleep", 63);
        h.say_as(OWNER, "/hibernate", 64);
        h.say_as(OWNER, "/clear", 65);
        assert!(h.bot.pending_nonce_for(OWNER).is_none());
        assert!(h.bot.pending_nonce_for(SECOND).is_some());
        // an expired confirmation of any user is released by the sweep hook
        let (_, sleep_dialog) = h.tg.last_confirmation_in(SECOND);
        h.bot.age_pending(Duration::from_secs(61));
        assert!(h.bot.release_expired_confirmation());
        assert!(!h.ctx.janitor.is_protected(SECOND, sleep_dialog));
    }

    /// A user removed outside the bot (tray, CLI, IPC) keeps no power: their old dialog cannot
    /// be confirmed, not even after they are paired again before it would expire.
    #[test]
    fn a_dialog_older_than_the_users_pairing_cannot_be_confirmed() {
        let h = harness();
        h.add_second();
        h.say_as(SECOND, "/shutdown", 60);
        let (nonce, msg) = h.tg.last_confirmation_in(SECOND);
        h.bot.age_pending(Duration::from_secs(5)); // still well within the 60 s timeout
        // removed and paired again elsewhere (the bot's own pending map is not told)
        h.ctx.settings.remove_user(SECOND).unwrap();
        let again = AuthorizedUser::new(SECOND, "bob", UserRole::User, now_unix());
        assert_eq!(h.ctx.settings.add_user(again).unwrap(), AddUserOutcome::Added);
        h.tg.clear();
        h.press_as(SECOND, &format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.tg.answers(), vec![(Some(ui::CONFIRMATION_INVALID.to_string()), true)]);
        assert!(h.bot.pending_nonce_for(SECOND).is_none());
        // a fresh dialog works as usual
        h.say_as(SECOND, "/shutdown", 61);
        let (nonce, msg) = h.tg.last_confirmation_in(SECOND);
        h.press_as(SECOND, &format!("cf:{nonce}"), msg);
        assert_eq!(h.sys.count("execute_power:shutdown"), 1);
    }

    #[test]
    fn users_list_remove_buttons_only_for_admins() {
        let h = harness();
        h.add_second();
        h.cmd("/users");
        let t = h.last_sent_to(OWNER);
        assert!(t.contains(&OWNER.to_string()) && t.contains(&SECOND.to_string()) && t.contains("bob"), "{t}");
        let d = h.tg.last_keyboard_in(OWNER).unwrap().callback_datas();
        assert!(d.contains(&format!("um:rm:{SECOND}")), "{d:?}");
        assert!(!d.contains(&format!("um:rm:{OWNER}")), "no button for the admin themselves");
        h.say_as(SECOND, "/users", 70);
        let d = h.tg.last_keyboard_in(SECOND).unwrap().callback_datas();
        assert!(d.iter().all(|x| !x.starts_with("um:rm:")), "{d:?}");
        assert!(d.contains(&"um:ls".to_string()));
        // a plain user pressing a remove button is refused
        h.tg.clear();
        h.press_as(SECOND, &format!("um:rm:{OWNER}"), MENU_MSG);
        assert_eq!(h.tg.answers(), vec![(Some(ui::ONLY_ADMINS.to_string()), true)]);
        assert!(h.ctx.settings.is_authorized(OWNER));
        // an admin cannot remove themselves here (and the last admin never goes)
        h.tg.clear();
        h.press(&format!("um:rm:{OWNER}"));
        assert_eq!(h.tg.answers(), vec![(Some(ui::CANNOT_REMOVE_SELF.to_string()), true)]);
        assert!(h.ctx.settings.is_authorized(OWNER));
        // a remove button pressed while PREDATOR was offline is not executed
        h.tg.clear();
        h.press_backlog(&format!("um:rm:{SECOND}"));
        assert!(h.ctx.settings.is_authorized(SECOND));
        assert_eq!(h.tg.last_text(), ui::BACKLOG_IGNORED);
        // refresh works for everyone, also from the backlog
        h.press_as(SECOND, "um:ls", MENU_MSG);
        assert!(h.tg.last_text().contains("TELEGRAM USERS"));
        h.tg.clear();
        h.press_backlog("um:ls");
        assert!(h.tg.last_text().contains("TELEGRAM USERS"));
        assert!(h.ctx.queue.is_empty(), "nothing was removed");
    }

    #[test]
    fn removing_a_user_revokes_access_immediately() {
        let h = harness();
        h.add_second();
        h.say_as(SECOND, "/shutdown", 80);
        let (nonce_b, msg_b) = h.tg.last_confirmation_in(SECOND);
        h.cmd("/users");
        let list = h.tg.last_sent_id();
        h.tg.clear();
        h.press_on(&format!("um:rm:{SECOND}"), list);
        assert!(!h.ctx.settings.is_authorized(SECOND));
        assert_eq!(h.tg.answers(), vec![(Some("Removed bob".to_string()), false)]);
        // the list is refreshed in place
        let (edited, html) = h.tg.edits().pop().unwrap();
        assert_eq!(edited, list);
        assert!(!html.contains(&SECOND.to_string()), "{html}");
        // every remaining user is told
        let n = h.ctx.queue.front().unwrap();
        assert_eq!(n.kind, NotificationKind::Security);
        assert!(n.html.contains("TELEGRAM USER REMOVED") && n.html.contains("bob"), "{}", n.html);
        assert!(n.delivered_to.is_empty());
        // the removed user's pending confirmation is gone and its dialog released
        assert!(h.bot.pending_nonce_for(SECOND).is_none());
        assert!(!h.ctx.janitor.is_protected(SECOND, msg_b));
        // revoked at once: commands, buttons and the old confirmation
        h.tg.clear();
        h.say_as(SECOND, "/status", 81);
        assert_eq!(h.tg.sends(), vec![(SECOND, ui::ACCESS_DENIED.to_string())]);
        h.press_as(SECOND, &format!("cf:{nonce_b}"), msg_b);
        h.press_as(SECOND, "nav:status", MENU_MSG);
        assert_eq!(h.tg.answers(), vec![(Some(ui::NOT_AUTHORIZED.to_string()), true); 2]);
        assert_eq!(h.sys.executed(), 0);
        assert_eq!(h.sys.count("system_status"), 0);
        // removing someone who is gone already is answered, never "unknown"
        h.tg.clear();
        h.press_on(&format!("um:rm:{SECOND}"), list);
        let answers = h.tg.answers();
        assert_eq!(answers.len(), 1);
        assert!(answers[0].0.as_deref().is_some_and(|t| t.contains("not authorized")), "{answers:?}");
    }

    /// The chat cleanup works per chat: one user's commands never delete another user's messages.
    #[test]
    fn chat_cleanup_is_per_chat() {
        let h = harness();
        h.add_second();
        h.say("/status", 90);
        let owner_reply = h.tg.last_sent_id();
        h.say_as(SECOND, "/status", 91);
        let second_reply = h.tg.last_sent_id();
        h.tg.deletes.lock().unwrap().clear();
        h.say_as(SECOND, "/network", 92);
        let deleted = h.tg.deleted();
        assert!(deleted.contains(&91) && deleted.contains(&second_reply), "{deleted:?}");
        assert!(!deleted.contains(&90) && !deleted.contains(&owner_reply), "{deleted:?}");
        assert!(lock(&h.tg.deletes).iter().all(|(c, _)| *c == SECOND));
        // /clear in the owner's chat leaves the second user's messages alone
        h.say("/clear", 93);
        assert!(h.ctx.janitor.contains(SECOND, 92));
        assert!(!h.ctx.janitor.contains(OWNER, 90) && !h.ctx.janitor.contains(OWNER, owner_reply));
        assert!(lock(&h.tg.deletes).iter().filter(|(c, _)| *c == OWNER).all(|(_, ids)| ids.contains(&93)));
    }
}
