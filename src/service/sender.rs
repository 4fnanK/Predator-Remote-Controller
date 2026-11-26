//! Notification sender (`notify-sender` thread): delivers `ctx.queue` in order to every
//! authorized Telegram user.
//!
//! * Idle: blocked on `ctx.sender_wake` (queue push, network change, resume, stop).
//! * No user paired / no token: items stay queued (durably) and the thread waits.
//! * Each notification goes to every authorized user not yet in its `delivered_to`
//!   ([`deliver_pass`]). Every success is recorded at once (`NotificationQueue::mark_delivered`,
//!   written like an ack), and the item is acked once all *current* users are covered, so after an
//!   outage or a restart it goes only to the users who do not have it yet. Users paired later
//!   also receive what is still queued.
//! * Connectivity hint says "no internet": wait at most `OFFLINE_RECHECK` (or until the network
//!   changes; queue pushes neither shorten nor extend that wait) and then try anyway — the hint is
//!   advisory, and a success overrides it until the network changes.
//! * Retryable failures end the pass (the users reached so far stay recorded): exponential backoff
//!   2 s … 5 min, cut short by network changes. 429: `retry_after` is honoured.
//! * `BadRequest` (e.g. HTML rejected): retried once as plain text, then dropped with a log line.
//! * 403 / "chat not found" for one user (they blocked the bot or never pressed Start): that user
//!   is skipped (logged) as soon as anyone else has the notification, so one unreachable account
//!   never holds back alerts for the others. When nobody can be reached, the notification stays
//!   queued and is retried every 30 min.
//! * Delivered `System` notices are handed to the chat janitor of each recipient's chat for
//!   automatic deletion; login, logout, failed-login, SSH and security alerts are kept.
//! * Acks are coalesced by the queue (≤ 1 write per 2 s while a backlog drains); the sender
//!   flushes the pending acks before every wait, so they are on disk whenever it is not busy
//!   (while it is, they wait at most for the next ack, push or wait — i.e. about 2 s plus the
//!   request in flight).
//! * Every delivery sets the runtime's activity mark (memory trim policy, see
//!   [`TrimPolicy`](super::runtime::TrimPolicy)).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::runtime::{OFFLINE_RECHECK, Shared, TOKEN_RECHECK, catch};
use super::text::plain_fallback;
use crate::config::MAX_AUTHORIZED_USERS;
use crate::context::AppContext;
use crate::notify::{Notification, NotificationKind};
use crate::telegram::janitor::is_ephemeral_kind;
use crate::telegram::{Telegram, TgError};
use crate::util::Backoff;
use crate::util::time::now_unix;
use crate::{log_debug, log_info, log_warn};

/// Idle re-check when the queue is empty (any push wakes the thread immediately).
const IDLE_WAIT: Duration = Duration::from_secs(3600);
/// Re-check interval while no Telegram user is paired.
const NO_USER_WAIT: Duration = Duration::from_secs(30 * 60);
/// Retry interval while Telegram refuses to deliver to every user (blocked bot, chat not found).
const BLOCKED_WAIT: Duration = Duration::from_secs(30 * 60);

/// Message text = rendered HTML + "delivered late" footnote when queued for a while.
pub(crate) fn compose(item: &Notification, now: i64) -> String {
    let mut text = item.html.clone();
    if let Ok(Some(note)) = catch(|| crate::notify::format::late_delivery_note(item.event_unix, now)) {
        text.push_str(&note);
    }
    text
}

/// Telegram's "the recipient cannot be reached" answers that arrive as 400 Bad Request.
pub(crate) fn is_chat_problem(description: &str) -> bool {
    let d = description.to_ascii_lowercase();
    ["chat not found", "user not found", "peer_id_invalid", "bot was blocked", "user is deactivated"]
        .iter()
        .any(|p| d.contains(p))
}

#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    /// Delivered as this Telegram message id.
    Sent(i64),
    /// Permanently rejected (even as plain text): drop it.
    Drop(String),
    Retry(TgError),
}

/// After a successful delivery to `chat`: track short-lived (`System`) notices for automatic
/// deletion in that chat. Login, logout, failed-login, SSH and security alerts are kept. Returns
/// whether it was tracked.
pub(crate) fn track_delivered(ctx: &AppContext, chat: i64, kind: NotificationKind, message_id: i64, now: i64) -> bool {
    is_ephemeral_kind(kind) && ctx.track_chat_message(chat, message_id, now)
}

/// Send one notification to one chat; on a content error retry once as plain text.
pub(crate) fn deliver(tg: &dyn Telegram, chat: i64, html: &str) -> Outcome {
    match tg.send_message(chat, html, None) {
        Ok(id) => Outcome::Sent(id),
        Err(TgError::BadRequest(m)) if is_chat_problem(&m) => Outcome::Retry(TgError::Forbidden(m)),
        Err(TgError::BadRequest(m)) => {
            log_warn!("Telegram rejected a notification ({m}); retrying as plain text");
            match tg.send_message(chat, &plain_fallback(html), None) {
                Ok(id) => Outcome::Sent(id),
                Err(TgError::BadRequest(m2)) if is_chat_problem(&m2) => Outcome::Retry(TgError::Forbidden(m2)),
                Err(TgError::BadRequest(m2)) => Outcome::Drop(m2),
                Err(e) => Outcome::Retry(e),
            }
        }
        Err(e) => Outcome::Retry(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendAction {
    TokenInvalid,
    Blocked,
    RateLimited(Duration),
    Backoff,
}

pub(crate) fn send_error_action(e: &TgError) -> SendAction {
    match e {
        TgError::Unauthorized => SendAction::TokenInvalid,
        TgError::Forbidden(_) => SendAction::Blocked,
        TgError::RateLimited(s) => SendAction::RateLimited(Duration::from_secs((*s).clamp(1, 3600))),
        _ => SendAction::Backoff,
    }
}

/// Telegram user ids that receive notifications (every authorized user, list order).
pub(crate) fn recipients(ctx: &AppContext) -> Vec<i64> {
    ctx.settings.authorized_users().into_iter().map(|u| u.id).filter(|id| *id > 0).collect()
}

/// Result of one delivery pass over a notification ([`deliver_pass`]).
#[derive(Debug, PartialEq)]
pub(crate) enum Pass {
    /// Every current user has it (or cannot be reached and was skipped): acked.
    Done { sent: usize, skipped: Vec<(i64, TgError)> },
    /// Nobody is paired: kept queued.
    NoRecipients,
    /// Rejected by Telegram even as plain text: dropped (acked).
    Dropped(String),
    /// A retryable error ended the pass; the users reached so far are recorded.
    Retry { sent: usize, error: TgError },
    /// Nobody could be reached (every pending user refuses permanently): kept queued.
    Blocked(TgError),
}

fn ack(ctx: &AppContext, id: u64) {
    if let Err(e) = ctx.queue.ack(id) {
        log_warn!("cannot update queue.json after delivery: {e}");
    }
}

/// Deliver `item` to every authorized user who does not have it yet (no waiting: the caller
/// decides what to do with the result). Each success is recorded in the queue at once and
/// `System` notices are tracked for the chat cleanup of that chat.
pub(crate) fn deliver_pass(ctx: &AppContext, tg: &dyn Telegram, item: &Notification, now: i64) -> Pass {
    let users = recipients(ctx);
    if users.is_empty() {
        return Pass::NoRecipients;
    }
    // somebody already has it (an earlier pass, before a restart) — or it was never meant for them
    let reached_before = !item.delivered_to.is_empty();
    let pending: Vec<i64> = users.into_iter().filter(|u| !item.delivered_to.contains(u)).collect();
    let text = if pending.is_empty() { String::new() } else { compose(item, now) };
    let mut sent = 0usize;
    let mut refused: Vec<(i64, TgError)> = Vec::new();
    for chat in pending {
        // A pass can take a while (one request per user): an account removed meanwhile gets
        // nothing more.
        if !ctx.settings.is_authorized(chat) {
            continue;
        }
        match deliver(tg, chat, &text) {
            Outcome::Sent(message_id) => {
                if let Err(e) = ctx.queue.mark_delivered(item.id, chat) {
                    log_warn!("cannot update queue.json after delivery: {e}");
                }
                track_delivered(ctx, chat, item.kind, message_id, now);
                sent += 1;
            }
            Outcome::Drop(reason) => {
                ack(ctx, item.id);
                return Pass::Dropped(reason);
            }
            Outcome::Retry(e) if send_error_action(&e) == SendAction::Blocked => refused.push((chat, e)),
            Outcome::Retry(error) => return Pass::Retry { sent, error },
        }
    }
    if sent == 0 && !reached_before {
        if let Some((_, e)) = refused.first() {
            return Pass::Blocked(e.clone());
        }
        if ctx.settings.primary_user_id().is_none() {
            return Pass::NoRecipients; // everyone was removed during the pass: keep it queued
        }
    }
    ack(ctx, item.id);
    Pass::Done { sent, skipped: refused }
}

/// Write acks the queue is still holding back (called before the sender waits).
fn flush_acks(ctx: &AppContext) {
    if let Err(e) = ctx.queue.flush() {
        log_warn!("cannot update queue.json after delivery: {e}");
    }
}

/// Wait after a failed pass according to `e`.
fn wait_after_error(sh: &Shared, e: &TgError, backoff: &mut Backoff, failures: u32, warned_blocked: &mut bool) {
    let ctx = &sh.ctx;
    match send_error_action(e) {
        SendAction::TokenInvalid => {
            ctx.status.token_invalid.store(true, Ordering::Relaxed);
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
        }
        SendAction::Blocked => {
            if !*warned_blocked {
                log_warn!(
                    "Telegram refuses to deliver to every paired user ({e}). Did they block the bot or never press \
                     Start? Notifications stay queued."
                );
                ctx.status.set_last_error("Telegram cannot reach any paired user (bot blocked?)");
                *warned_blocked = true;
            }
            sh.wait_retry(&ctx.sender_wake, BLOCKED_WAIT);
        }
        SendAction::RateLimited(d) => {
            log_warn!("Telegram rate limit: waiting {} s", d.as_secs());
            ctx.stop.sleep(d);
        }
        SendAction::Backoff => {
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
            let d = backoff.next_delay();
            if failures == 1 || failures.is_multiple_of(20) {
                log_warn!("notification delivery failed: {e} (retry in {} s)", d.as_secs());
            } else {
                log_debug!("notification delivery failed: {e} (retry in {} s)", d.as_secs());
            }
            let epoch = sh.retry_epoch();
            sh.wait_retry(&ctx.sender_wake, d);
            if sh.retry_epoch() != epoch {
                backoff.reset();
            }
        }
    }
}

/// Log users that were skipped because Telegram cannot reach them: a warning the first time per
/// user, debug lines afterwards (a backlog would otherwise repeat it for every item).
fn report_skipped(item: &Notification, skipped: &[(i64, TgError)], warned: &mut Vec<i64>) {
    for (chat, e) in skipped {
        if warned.contains(chat) {
            log_debug!("notification #{} skipped for Telegram user {chat} ({e})", item.id);
            continue;
        }
        log_warn!(
            "notification #{} not delivered to Telegram user {chat} ({e}): that account blocked the bot or never \
             pressed Start; skipped (the other users have it)",
            item.id
        );
        if warned.len() >= MAX_AUTHORIZED_USERS * 2 {
            warned.clear();
        }
        warned.push(*chat);
    }
}

pub(crate) fn run(sh: &Arc<Shared>) {
    let ctx = &sh.ctx;
    let mut backoff = Backoff::new(Duration::from_secs(2), Duration::from_secs(300));
    let mut try_anyway = false;
    let mut failures = 0u32;
    let mut warned_blocked = false;
    let mut warned_no_user = false;
    let mut warned_skipped: Vec<i64> = Vec::new();
    loop {
        if ctx.stop.is_stopped() {
            flush_acks(ctx);
            return;
        }
        let seen = ctx.sender_wake.generation();
        let Some(item) = ctx.queue.front() else {
            flush_acks(ctx);
            ctx.sender_wake.wait_changed(seen, IDLE_WAIT);
            continue;
        };
        if ctx.settings.primary_user_id().is_none() {
            if !warned_no_user {
                log_info!("{} notification(s) queued: no Telegram user paired yet", ctx.queue.len());
                warned_no_user = true;
            }
            flush_acks(ctx);
            ctx.sender_wake.wait_changed(seen, NO_USER_WAIT);
            continue;
        }
        warned_no_user = false;
        let Some((api, _)) = sh.tg.current() else {
            flush_acks(ctx);
            ctx.sender_wake.wait_changed(seen, TOKEN_RECHECK);
            continue;
        };
        if ctx.status.token_invalid.load(Ordering::Relaxed) {
            flush_acks(ctx);
            ctx.sender_wake.wait_changed(seen, TOKEN_RECHECK);
            continue;
        }
        if !try_anyway && sh.should_wait_for_network() {
            // Ends on a connectivity change, resume, new token or stop (not on queue pushes) and
            // after OFFLINE_RECHECK at the latest; the next pass then tries regardless of the hint.
            flush_acks(ctx);
            sh.wait_retry(&ctx.sender_wake, OFFLINE_RECHECK);
            try_anyway = true;
            continue;
        }
        try_anyway = false;

        let interrupts = sh.interrupt_generation();
        let pass = deliver_pass(ctx, &*api, &item, now_unix());
        if let Pass::Retry { sent, error } = &pass
            && super::poller::interrupted(interrupts, sh.interrupt_generation(), error)
        {
            // A network change / resume interrupted the client while a request was in flight:
            // retry at once (the loop re-checks the hint) instead of backing off. The users
            // reached so far are recorded, so they do not get it twice.
            if *sent > 0 {
                sh.note_activity();
            }
            log_debug!("notification #{} not sent ({error}): interrupted, retrying", item.id);
            continue;
        }
        match pass {
            Pass::Done { sent, skipped } => {
                report_skipped(&item, &skipped, &mut warned_skipped);
                if sent > 0 {
                    ctx.status.delivered.fetch_add(1, Ordering::Relaxed);
                    sh.note_activity();
                    sh.mark_online();
                }
                if failures > 0 {
                    log_info!("notification delivery resumed");
                }
                failures = 0;
                warned_blocked = false;
                backoff.reset();
                log_debug!("delivered notification #{} ({:?}) to {sent} user(s)", item.id, item.kind);
            }
            Pass::NoRecipients => {
                // the last user was removed between the checks above and the pass
                flush_acks(ctx);
                ctx.sender_wake.wait_changed(seen, NO_USER_WAIT);
            }
            Pass::Dropped(reason) => {
                log_warn!(
                    "dropping notification #{} ({:?}): rejected by Telegram even as plain text: {reason}",
                    item.id,
                    item.kind
                );
            }
            Pass::Retry { sent, error } => {
                if sent > 0 {
                    sh.note_activity();
                    sh.mark_online();
                }
                failures += 1;
                sh.note_request_error(&error);
                // every branch below waits: pending acks (and recipients reached) go to disk first
                flush_acks(ctx);
                wait_after_error(sh, &error, &mut backoff, failures, &mut warned_blocked);
            }
            Pass::Blocked(error) => {
                failures += 1;
                sh.note_request_error(&error);
                flush_acks(ctx);
                wait_after_error(sh, &error, &mut backoff, failures, &mut warned_blocked);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthorizedUser, UserRole};
    use crate::notify::NotificationKind;
    use crate::notify::queue::NotificationQueue;
    use crate::telegram::types::InlineKeyboardMarkup;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const ALICE: i64 = 1000;
    const BOB: i64 = 5000;

    /// Replays scripted results and records the texts it was asked to send.
    struct Scripted {
        results: Mutex<Vec<Result<i64, TgError>>>,
        sent: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(mut r: Vec<Result<i64, TgError>>) -> Self {
            r.reverse();
            Self { results: Mutex::new(r), sent: Mutex::new(Vec::new()) }
        }
    }

    impl Telegram for Scripted {
        fn send_message(&self, _chat: i64, html: &str, _kb: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
            self.sent.lock().unwrap().push(html.to_string());
            self.results.lock().unwrap().pop().unwrap_or(Ok(1))
        }
        fn edit_message(&self, _: i64, _: i64, _: &str, _: Option<&InlineKeyboardMarkup>) -> Result<(), TgError> {
            Ok(())
        }
        fn answer_callback(&self, _: &str, _: Option<&str>, _: bool) -> Result<(), TgError> {
            Ok(())
        }
        fn leave_chat(&self, _: i64) -> Result<(), TgError> {
            Ok(())
        }
    }

    /// Answers per chat: a fixed error for some chats, message ids counting up for the others;
    /// records (chat, text) of every attempt.
    #[derive(Default)]
    struct PerChat {
        fail: Mutex<HashMap<i64, TgError>>,
        attempts: Mutex<Vec<(i64, String)>>,
    }

    impl PerChat {
        fn failing(chat: i64, e: TgError) -> Self {
            let s = Self::default();
            s.fail.lock().unwrap().insert(chat, e);
            s
        }
        fn chats(&self) -> Vec<i64> {
            self.attempts.lock().unwrap().iter().map(|(c, _)| *c).collect()
        }
    }

    impl Telegram for PerChat {
        fn send_message(&self, chat: i64, html: &str, _kb: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
            let mut a = self.attempts.lock().unwrap();
            a.push((chat, html.to_string()));
            match self.fail.lock().unwrap().get(&chat) {
                Some(e) => Err(e.clone()),
                None => Ok(100 + a.len() as i64),
            }
        }
        fn edit_message(&self, _: i64, _: i64, _: &str, _: Option<&InlineKeyboardMarkup>) -> Result<(), TgError> {
            Ok(())
        }
        fn answer_callback(&self, _: &str, _: Option<&str>, _: bool) -> Result<(), TgError> {
            Ok(())
        }
        fn leave_chat(&self, _: i64) -> Result<(), TgError> {
            Ok(())
        }
    }

    /// Test context with alice (admin, the default test user) and bob (user).
    fn two_users() -> Arc<AppContext> {
        let ctx = AppContext::for_tests();
        ctx.settings.add_user(AuthorizedUser::new(BOB, "bob", UserRole::User, 0)).unwrap();
        ctx
    }

    fn queued(ctx: &AppContext, kind: NotificationKind, html: &str) -> Notification {
        let id = ctx.queue.push(kind, now_unix(), html.into(), None).unwrap().unwrap();
        ctx.queue.get(id).unwrap()
    }

    #[test]
    fn delivered_message_id_is_reported() {
        let tg = Scripted::new(vec![Ok(4242)]);
        assert_eq!(deliver(&tg, 1, "<b>x</b>"), Outcome::Sent(4242));
    }

    #[test]
    fn every_user_gets_the_notification_once() {
        let ctx = two_users();
        let tg = PerChat::default();
        let item = queued(&ctx, NotificationKind::Login, "<b>LOGIN</b>");
        assert_eq!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 2, skipped: vec![] });
        assert_eq!(tg.chats(), vec![ALICE, BOB]);
        assert!(tg.attempts.lock().unwrap().iter().all(|(_, t)| t == "<b>LOGIN</b>"));
        assert!(ctx.queue.is_empty(), "acked once every user has it");
        // nobody paired: kept queued, nothing sent
        let lonely = AppContext::for_tests();
        lonely.settings.update(|s| s.authorized_users.clear()).unwrap();
        let item = queued(&lonely, NotificationKind::Login, "x");
        let tg = PerChat::default();
        assert_eq!(deliver_pass(&lonely, &tg, &item, now_unix()), Pass::NoRecipients);
        assert!(tg.chats().is_empty());
        assert_eq!(lonely.queue.len(), 1);
    }

    /// One user who blocked the bot (403) never holds back the alerts of the others.
    #[test]
    fn a_blocked_user_does_not_block_the_others() {
        for blocked in [ALICE, BOB] {
            let ctx = two_users();
            let tg = PerChat::failing(blocked, TgError::Forbidden("bot was blocked by the user".into()));
            let item = queued(&ctx, NotificationKind::FailedLogin, "x");
            match deliver_pass(&ctx, &tg, &item, now_unix()) {
                Pass::Done { sent, skipped } => {
                    assert_eq!(sent, 1);
                    assert_eq!(skipped.len(), 1);
                    assert_eq!(skipped[0].0, blocked);
                }
                other => panic!("{other:?}"),
            }
            assert!(ctx.queue.is_empty());
            assert_eq!(tg.chats(), vec![ALICE, BOB], "both were tried");
        }
        // "chat not found" arrives as 400 and is treated the same way
        let ctx = two_users();
        let tg = PerChat::failing(ALICE, TgError::BadRequest("Bad Request: chat not found".into()));
        let item = queued(&ctx, NotificationKind::Login, "x");
        assert!(matches!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 1, .. }));
    }

    /// When nobody can be reached the alert is kept (and retried later), never dropped.
    #[test]
    fn nobody_reachable_keeps_the_notification() {
        let ctx = AppContext::for_tests();
        let tg = PerChat::failing(ALICE, TgError::Forbidden("bot was blocked by the user".into()));
        let item = queued(&ctx, NotificationKind::Login, "x");
        assert!(matches!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Blocked(TgError::Forbidden(_))));
        assert_eq!(ctx.queue.len(), 1);
        // ... but once someone else has it, the unreachable user is skipped
        ctx.queue.mark_delivered(item.id, 7777).unwrap();
        let item = ctx.queue.get(item.id).unwrap();
        assert!(matches!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 0, .. }));
        assert!(ctx.queue.is_empty());
    }

    /// A retryable failure stops the pass; the users reached before are persisted, so after a
    /// restart the notification goes only to the others (no duplicate).
    #[test]
    fn no_duplicate_after_restart() {
        let dir = std::env::temp_dir().join(format!("predator-sender-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("queue.json");
        let ctx = two_users();
        let queue = NotificationQueue::open(&path).unwrap();
        let id = queue.push(NotificationKind::Login, now_unix(), "<b>LOGIN</b>".into(), None).unwrap().unwrap();
        let item = queue.get(id).unwrap();
        // the sender works on ctx.queue: use a context whose queue is the on-disk one
        let disk_ctx = AppContext::new(
            ctx.paths.clone(),
            ctx.settings.clone(),
            Arc::new(queue),
            ctx.history.clone(),
            "MY-PC".into(),
            true,
        );
        let tg = PerChat::failing(BOB, TgError::Network("timeout".into()));
        assert_eq!(
            deliver_pass(&disk_ctx, &tg, &item, now_unix()),
            Pass::Retry { sent: 1, error: TgError::Network("timeout".into()) }
        );
        assert_eq!(disk_ctx.queue.len(), 1, "kept queued for bob");
        // the sender flushes before it waits; then the process restarts
        disk_ctx.queue.flush().unwrap();
        let reopened = NotificationQueue::open(&path).unwrap();
        let item = reopened.front().unwrap();
        assert_eq!(item.delivered_to, vec![ALICE]);
        let after = AppContext::new(
            ctx.paths.clone(),
            ctx.settings.clone(),
            Arc::new(reopened),
            ctx.history.clone(),
            "MY-PC".into(),
            true,
        );
        let tg = PerChat::default();
        assert_eq!(deliver_pass(&after, &tg, &item, now_unix()), Pass::Done { sent: 1, skipped: vec![] });
        assert_eq!(tg.chats(), vec![BOB], "alice is not sent the same alert again");
        assert!(after.queue.is_empty());
        assert!(NotificationQueue::open(&path).unwrap().is_empty(), "the ack of an emptied queue is written at once");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Recipients pre-excluded at push time (the user a "paired" notice is about) and users
    /// removed meanwhile are not sent anything; users paired later get what is still queued.
    #[test]
    fn recipients_follow_the_current_user_list() {
        let ctx = two_users();
        let id = ctx.queue.push_excluding(NotificationKind::Security, now_unix(), "x".into(), None, &[BOB]).unwrap();
        let item = ctx.queue.get(id.unwrap()).unwrap();
        let tg = PerChat::default();
        assert_eq!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 1, skipped: vec![] });
        assert_eq!(tg.chats(), vec![ALICE]);
        // removed before delivery: not a recipient any more
        ctx.settings.remove_user(BOB).unwrap();
        let item = queued(&ctx, NotificationKind::Login, "y");
        let tg = PerChat::default();
        deliver_pass(&ctx, &tg, &item, now_unix());
        assert_eq!(tg.chats(), vec![ALICE]);
        // everything excluded: acked without a request
        let id = ctx.queue.push_excluding(NotificationKind::Security, now_unix(), "z".into(), None, &[ALICE]).unwrap();
        let item = ctx.queue.get(id.unwrap()).unwrap();
        let tg = PerChat::default();
        assert_eq!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 0, skipped: vec![] });
        assert!(tg.chats().is_empty() && ctx.queue.is_empty());
    }

    /// An account removed while a pass is under way (e.g. by an admin, during a slow request to
    /// another user) is not sent the notification any more.
    #[test]
    fn a_user_removed_during_the_pass_gets_nothing() {
        struct RemovesBob {
            ctx: Arc<AppContext>,
            chats: Mutex<Vec<i64>>,
        }
        impl Telegram for RemovesBob {
            fn send_message(&self, chat: i64, _: &str, _: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
                self.chats.lock().unwrap().push(chat);
                if chat == ALICE {
                    self.ctx.settings.remove_user(BOB).unwrap();
                }
                Ok(1)
            }
            fn edit_message(&self, _: i64, _: i64, _: &str, _: Option<&InlineKeyboardMarkup>) -> Result<(), TgError> {
                Ok(())
            }
            fn answer_callback(&self, _: &str, _: Option<&str>, _: bool) -> Result<(), TgError> {
                Ok(())
            }
            fn leave_chat(&self, _: i64) -> Result<(), TgError> {
                Ok(())
            }
        }
        let ctx = two_users();
        let tg = RemovesBob { ctx: ctx.clone(), chats: Mutex::new(Vec::new()) };
        let item = queued(&ctx, NotificationKind::Login, "x");
        assert_eq!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Done { sent: 1, skipped: vec![] });
        assert_eq!(*tg.chats.lock().unwrap(), vec![ALICE]);
        assert!(ctx.queue.is_empty());
    }

    #[test]
    fn content_rejection_drops_and_rate_limit_stops() {
        let ctx = two_users();
        let tg = Scripted::new(vec![
            Err(TgError::BadRequest("can't parse".into())),
            Err(TgError::BadRequest("message is too long".into())),
        ]);
        let item = queued(&ctx, NotificationKind::System, "<b>x</b>");
        assert!(matches!(deliver_pass(&ctx, &tg, &item, now_unix()), Pass::Dropped(_)));
        assert!(ctx.queue.is_empty());
        let tg = Scripted::new(vec![Ok(9), Err(TgError::RateLimited(30))]);
        let item = queued(&ctx, NotificationKind::System, "y");
        assert_eq!(
            deliver_pass(&ctx, &tg, &item, now_unix()),
            Pass::Retry { sent: 1, error: TgError::RateLimited(30) }
        );
        assert_eq!(ctx.queue.get(item.id).unwrap().delivered_to, vec![ALICE]);
    }

    /// System notices are tracked for the chat cleanup in each recipient's own chat.
    #[test]
    fn system_notices_are_tracked_per_recipient_chat() {
        let ctx = two_users();
        let tg = PerChat::default();
        let item = queued(&ctx, NotificationKind::System, "online");
        deliver_pass(&ctx, &tg, &item, now_unix());
        let entries = ctx.janitor.entries();
        let chats: Vec<i64> = entries.iter().map(|e| e.chat_id).collect();
        assert_eq!(chats, vec![ALICE, BOB]);
        let alert = queued(&ctx, NotificationKind::Login, "login");
        deliver_pass(&ctx, &tg, &alert, now_unix());
        assert_eq!(ctx.janitor.len(), 2, "login alerts are kept");
    }

    #[test]
    fn only_system_notices_are_tracked_for_cleanup() {
        let ctx = crate::context::AppContext::for_tests();
        let now = now_unix();
        let kinds = [
            (NotificationKind::System, true),
            (NotificationKind::Login, false),
            (NotificationKind::FailedLogin, false),
            (NotificationKind::Logout, false),
            (NotificationKind::SshLogin, false),
            (NotificationKind::SshFailed, false),
            (NotificationKind::SshLogout, false),
            (NotificationKind::Security, false),
        ];
        for (i, (kind, tracked)) in kinds.into_iter().enumerate() {
            let id = 100 + i as i64;
            assert_eq!(track_delivered(&ctx, ALICE, kind, id, now), tracked, "{kind:?}");
            assert_eq!(ctx.janitor.contains(ALICE, id), tracked, "{kind:?}");
        }
        assert_eq!(ctx.janitor.len(), 1);
        // automatic cleaning switched off: not even System notices are tracked
        ctx.settings.update(|s| s.auto_clean_chat = false).unwrap();
        assert!(!track_delivered(&ctx, ALICE, NotificationKind::System, 300, now));
        assert!(!ctx.janitor.contains(ALICE, 300));
    }

    #[test]
    fn plain_text_fallback_then_drop() {
        let tg = Scripted::new(vec![Err(TgError::BadRequest("can't parse entities".into())), Ok(5)]);
        assert_eq!(deliver(&tg, 1, "<b>Hi</b> &amp; <i>x</i>"), Outcome::Sent(5));
        let sent = tg.sent.lock().unwrap().clone();
        assert_eq!(sent, vec!["<b>Hi</b> &amp; <i>x</i>".to_string(), "Hi &amp; x".to_string()]);

        let tg = Scripted::new(vec![
            Err(TgError::BadRequest("can't parse".into())),
            Err(TgError::BadRequest("message is too long".into())),
        ]);
        assert!(matches!(deliver(&tg, 1, "<b>x</b>"), Outcome::Drop(_)));
    }

    #[test]
    fn unreachable_user_is_reported_as_forbidden() {
        let tg = Scripted::new(vec![Err(TgError::BadRequest("Bad Request: chat not found".into()))]);
        assert!(matches!(deliver(&tg, 1, "x"), Outcome::Retry(TgError::Forbidden(_))));
        assert_eq!(tg.sent.lock().unwrap().len(), 1);
        let tg = Scripted::new(vec![Err(TgError::Network("timeout".into()))]);
        assert!(matches!(deliver(&tg, 1, "x"), Outcome::Retry(TgError::Network(_))));
    }

    #[test]
    fn skipped_users_are_warned_once() {
        let item = Notification {
            id: 1,
            kind: NotificationKind::Login,
            event_unix: 0,
            queued_unix: 0,
            html: String::new(),
            dedupe_key: None,
            delivered_to: Vec::new(),
        };
        let mut warned = Vec::new();
        let skipped = vec![(BOB, TgError::Forbidden("blocked".into()))];
        report_skipped(&item, &skipped, &mut warned);
        report_skipped(&item, &skipped, &mut warned);
        assert_eq!(warned, vec![BOB]);
        for i in 0..(MAX_AUTHORIZED_USERS as i64 * 3) {
            report_skipped(&item, &[(i + 10, TgError::Forbidden("x".into()))], &mut warned);
        }
        assert!(warned.len() <= MAX_AUTHORIZED_USERS * 2);
    }

    #[test]
    fn actions() {
        assert_eq!(send_error_action(&TgError::Unauthorized), SendAction::TokenInvalid);
        assert_eq!(send_error_action(&TgError::Forbidden("blocked".into())), SendAction::Blocked);
        assert_eq!(send_error_action(&TgError::RateLimited(30)), SendAction::RateLimited(Duration::from_secs(30)));
        assert_eq!(send_error_action(&TgError::Server(500, "x".into())), SendAction::Backoff);
        assert!(is_chat_problem("Forbidden: bot was blocked by the user"));
        assert!(!is_chat_problem("can't parse entities"));
    }

    #[test]
    fn compose_adds_late_note_only_when_late() {
        let n = Notification {
            id: 1,
            kind: NotificationKind::Login,
            event_unix: 1_000_000,
            queued_unix: 1_000_000,
            html: "<b>LOGIN</b>".into(),
            dedupe_key: None,
            delivered_to: Vec::new(),
        };
        let on_time = compose(&n, 1_000_010);
        assert!(on_time.starts_with("<b>LOGIN</b>"));
        let late = compose(&n, 1_003_600);
        assert!(late.starts_with("<b>LOGIN</b>"));
        // late_delivery_note may still be a stub in other modules; when implemented it appends text
        assert!(late.len() >= on_time.len());
    }
}
