//! Automatic Telegram chat cleanup ("the chat keeps only the login/logout alerts").
//!
//! Every message that only matters for a moment is *ephemeral* and tracked here: the bot's
//! interactive replies (menus, screens, results, confirmations, errors, hints), the users' own
//! commands and texts in their private chats, and `System` notifications (online, going offline,
//! resumed, feature changed, audit policy, monitor gap ...). Login, logout, failed-login, SSH and
//! security alerts are never tracked, so they stay in the chat forever
//! ([`is_ephemeral_kind`]).
//!
//! Everything is kept per chat: every authorized user has a private chat with the bot, and what
//! one user does never deletes anything in another user's chat. Tracked messages are deleted
//! * when the user sends a new message or command in that chat (everything earlier in the chat
//!   goes once the reply is out, except the message holding a power confirmation that can still
//!   be confirmed — see [`ChatJanitor::protect`]);
//! * by `/clear` (everything in that chat, at once);
//! * by the time-based sweep once they were inactive for `chat_clean_after_secs` (the poller runs
//!   it after every getUpdates cycle — no extra thread or timer).
//!
//! Telegram cannot delete messages older than 48 hours, so entries are forgotten after
//! [`MAX_DELETE_AGE_SECS`] (47 h). The list is bounded ([`MAX_TRACKED`]) and persisted atomically
//! in `chat-cleanup.json`, so messages sent before a restart are still cleaned up afterwards.
//! The pure bookkeeping lives in [`ChatJanitor`]; [`purge`] performs the Telegram calls.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::Telegram;
use crate::notify::NotificationKind;

/// Upper bound of tracked messages; beyond it the oldest entries are forgotten (never deleted).
pub const MAX_TRACKED: usize = 500;
/// Telegram refuses to delete messages older than 48 hours; entries this old are dropped.
pub const MAX_DELETE_AGE_SECS: i64 = 47 * 3600;
/// Shortest accepted `chat_clean_after_secs` (a reply must stay readable for a moment).
pub const MIN_CLEAN_AFTER_SECS: u64 = 60;
/// Longest useful `chat_clean_after_secs` (older messages can no longer be deleted).
pub const MAX_CLEAN_AFTER_SECS: u64 = MAX_DELETE_AGE_SECS as u64;
/// At most this many protected messages (one pending confirmation per authorized user).
const MAX_PROTECTED: usize = crate::config::MAX_AUTHORIZED_USERS + 4;
/// `chat-cleanup.json` format version.
const FILE_VERSION: u32 = 1;

/// Whether a notification of `kind` is auto-deleted (only `System` notices). Login-related and
/// security alerts are what the users want to keep, so they are never tracked.
pub fn is_ephemeral_kind(kind: NotificationKind) -> bool {
    match kind {
        NotificationKind::System => true,
        NotificationKind::Login
        | NotificationKind::FailedLogin
        | NotificationKind::Logout
        | NotificationKind::SshLogin
        | NotificationKind::SshFailed
        | NotificationKind::SshLogout
        | NotificationKind::Security => false,
    }
}

/// `chat_clean_after_secs` limited to the useful range.
pub fn clamp_clean_after(secs: u64) -> u64 {
    secs.clamp(MIN_CLEAN_AFTER_SECS, MAX_CLEAN_AFTER_SECS)
}

/// One message that will be deleted later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedMessage {
    pub chat_id: i64,
    pub message_id: i64,
    /// When the message was sent (Unix seconds) — Telegram's 48-hour delete limit counts from here.
    pub sent_unix: i64,
    /// Last time the message was used (sent, or one of its buttons pressed); the inactivity
    /// timeout counts from here, so a menu in use does not vanish under the user's finger.
    #[serde(default)]
    pub active_unix: i64,
}

impl TrackedMessage {
    fn last_active(&self) -> i64 {
        self.active_unix.max(self.sent_unix)
    }

    /// Too old for Telegram to delete it (with a one-hour safety margin).
    fn undeletable(&self, now: i64) -> bool {
        now.saturating_sub(self.sent_unix) >= MAX_DELETE_AGE_SECS
    }

    fn same(&self, chat_id: i64, message_id: i64) -> bool {
        self.chat_id == chat_id && self.message_id == message_id
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CleanupFile {
    #[serde(default)]
    version: u32,
    /// The bot the message ids belong to (absent in files written before the bot was known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bot_id: Option<i64>,
    #[serde(default)]
    entries: Vec<TrackedMessage>,
}

#[derive(Debug, Default)]
struct State {
    /// Oldest first.
    entries: Vec<TrackedMessage>,
    /// (chat, message) pairs that must not be deleted (a pending power confirmation). Not
    /// persisted: confirmations do not survive a restart either.
    protected: Vec<(i64, i64)>,
    /// Telegram id of the bot whose messages are listed ([`ChatJanitor::bind_bot`]).
    bot_id: Option<i64>,
}

impl State {
    fn position(&self, chat_id: i64, message_id: i64) -> Option<usize> {
        self.entries.iter().position(|e| e.same(chat_id, message_id))
    }

    fn is_protected(&self, e: &TrackedMessage) -> bool {
        self.protected.contains(&(e.chat_id, e.message_id))
    }

    /// Forget entries Telegram can no longer delete. Returns whether anything was removed.
    fn drop_undeletable(&mut self, now: i64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !e.undeletable(now));
        self.entries.len() != before
    }

    /// Keep at most [`MAX_TRACKED`] entries (the oldest are forgotten).
    fn enforce_bound(&mut self) {
        if self.entries.len() > MAX_TRACKED {
            let excess = self.entries.len() - MAX_TRACKED;
            crate::log_debug!("chat cleanup: {excess} old message(s) forgotten (more than {MAX_TRACKED} tracked)");
            self.entries.drain(..excess);
        }
    }

    /// Insert or refresh. Returns whether the persisted content changed.
    fn add(&mut self, e: TrackedMessage) -> bool {
        match self.position(e.chat_id, e.message_id) {
            Some(i) => {
                let cur = &mut self.entries[i];
                if e.active_unix > cur.active_unix {
                    cur.active_unix = e.active_unix;
                }
                false
            }
            None => {
                self.entries.push(e);
                self.enforce_bound();
                true
            }
        }
    }

    /// Remove and return the entries matching `pick` (order preserved).
    fn take_where(&mut self, mut pick: impl FnMut(&State, &TrackedMessage) -> bool) -> Vec<TrackedMessage> {
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(self.entries.len());
        for e in std::mem::take(&mut self.entries) {
            if pick(self, &e) {
                taken.push(e);
            } else {
                kept.push(e);
            }
        }
        self.entries = kept;
        taken
    }
}

/// Persistent, bounded list of ephemeral chat messages (thread-safe; pure bookkeeping, no I/O
/// except writing `chat-cleanup.json`).
#[derive(Debug)]
pub struct ChatJanitor {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

impl ChatJanitor {
    /// Non-persistent janitor (tests, contexts built without a data directory).
    pub fn in_memory() -> Self {
        Self { path: None, state: Mutex::new(State::default()) }
    }

    /// Load `path` (missing → empty). Never fails: a corrupt file is renamed to
    /// `chat-cleanup.json.corrupt` and an unreadable one is ignored — at worst a few old
    /// messages are not deleted automatically.
    pub fn open(path: &Path) -> Self {
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<CleanupFile>(&bytes).unwrap_or_else(|e| {
                crate::log_warn!("chat-cleanup.json is corrupt ({e}); starting with an empty list");
                let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                CleanupFile::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CleanupFile::default(),
            Err(e) => {
                crate::log_warn!("cannot read chat-cleanup.json ({e}); starting with an empty list");
                CleanupFile::default()
            }
        };
        let mut state = State { bot_id: file.bot_id, ..State::default() };
        for e in file.entries.into_iter().filter(|e| e.chat_id != 0 && e.message_id > 0) {
            state.add(e);
        }
        Self { path: Some(path.to_path_buf()), state: Mutex::new(state) }
    }

    /// The poller connected as bot `bot_id` (`getMe`). Message ids are only meaningful for the
    /// bot that sent or received the messages: when the list was kept for another bot (the token
    /// was replaced), its entries are forgotten — never deleted, because the same ids may name
    /// the new bot's own messages, login alerts included. A list without a recorded bot (nothing
    /// bound yet) is adopted. Returns whether entries were forgotten.
    pub fn bind_bot(&self, bot_id: i64) -> bool {
        let mut st = self.lock();
        let previous = st.bot_id;
        if previous == Some(bot_id) {
            return false;
        }
        st.bot_id = Some(bot_id);
        let forgotten = st.entries.len();
        if previous.is_some() {
            st.entries.clear();
            st.protected.clear();
        }
        if previous.is_some() || forgotten > 0 {
            // an empty list needs no write yet: the next track() records the bot with it
            self.persist(&st);
        }
        if previous.is_some() && forgotten > 0 {
            crate::log_info!(
                "chat cleanup: the bot changed; {forgotten} message(s) of the previous bot are no longer tracked"
            );
            return true;
        }
        false
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the list (called with the lock held, so the file always matches memory order).
    fn persist(&self, st: &State) {
        let Some(p) = &self.path else { return };
        let file = CleanupFile { version: FILE_VERSION, bot_id: st.bot_id, entries: st.entries.clone() };
        let result = serde_json::to_vec(&file)
            .map_err(std::io::Error::other)
            .and_then(|json| crate::paths::atomic_write(p, &json));
        if let Err(e) = result {
            crate::log_warn!("cannot save chat-cleanup.json: {e}");
        }
    }

    /// Track `message_id` for deletion. `sent_unix` is when Telegram got it (a future time is
    /// clamped to `now`); messages already too old to delete are not tracked.
    pub fn track(&self, chat_id: i64, message_id: i64, sent_unix: i64, now: i64) {
        if chat_id == 0 || message_id <= 0 {
            return;
        }
        let sent = if sent_unix > 0 { sent_unix.min(now) } else { now };
        let e = TrackedMessage { chat_id, message_id, sent_unix: sent, active_unix: now };
        if e.undeletable(now) {
            return;
        }
        let mut st = self.lock();
        if st.add(e) {
            self.persist(&st);
        }
    }

    /// A user pressed a button on `message_id`: restart its inactivity timeout (tracking it
    /// when it is not tracked yet, e.g. a menu sent before a restart). Refreshing an existing
    /// entry does not rewrite the file.
    pub fn touch(&self, chat_id: i64, message_id: i64, sent_unix: i64, now: i64) {
        self.track(chat_id, message_id, sent_unix, now);
    }

    /// Never delete `message_id` (it holds a pending power confirmation) until [`unprotect`]ed
    /// — the bot does so when the confirmation is confirmed, cancelled, replaced or expired.
    ///
    /// [`unprotect`]: ChatJanitor::unprotect
    pub fn protect(&self, chat_id: i64, message_id: i64) {
        let mut st = self.lock();
        if !st.protected.contains(&(chat_id, message_id)) {
            st.protected.push((chat_id, message_id));
            if st.protected.len() > MAX_PROTECTED {
                st.protected.remove(0);
            }
        }
    }

    pub fn unprotect(&self, chat_id: i64, message_id: i64) {
        self.lock().protected.retain(|p| *p != (chat_id, message_id));
    }

    pub fn is_protected(&self, chat_id: i64, message_id: i64) -> bool {
        self.lock().protected.contains(&(chat_id, message_id))
    }

    /// "New command → clear the previous ones", step 1 (read-only): the ids of the tracked
    /// messages of `chat` that the new command replaces — all except protected ones, `keep` and
    /// those too old to delete. Take them with [`take_ids`] once the reply went out, so they stay
    /// tracked (and are cleaned later) if handling the command fails or the process dies first.
    ///
    /// [`take_ids`]: ChatJanitor::take_ids
    pub fn deletable_ids(&self, chat_id: i64, keep: &[i64], now: i64) -> Vec<i64> {
        let st = self.lock();
        st.entries
            .iter()
            .filter(|e| e.chat_id == chat_id && !keep.contains(&e.message_id))
            .filter(|e| !e.undeletable(now) && !st.is_protected(e))
            .map(|e| e.message_id)
            .collect()
    }

    /// Step 2: remove and return the tracked messages of `chat` among `ids` that are still not
    /// protected. Entries too old to delete (any chat) are dropped.
    pub fn take_ids(&self, chat_id: i64, ids: &[i64], now: i64) -> Vec<TrackedMessage> {
        if ids.is_empty() {
            return Vec::new();
        }
        let mut st = self.lock();
        let dropped = st.drop_undeletable(now);
        let taken = st.take_where(|st, e| e.chat_id == chat_id && ids.contains(&e.message_id) && !st.is_protected(e));
        if dropped || !taken.is_empty() {
            self.persist(&st);
        }
        taken
    }

    /// `/clear`: remove and return every tracked message of `chat` except protected ones and
    /// `keep`. Entries too old to delete (any chat) are dropped.
    pub fn take_all_except(&self, chat_id: i64, keep: &[i64], now: i64) -> Vec<TrackedMessage> {
        let mut st = self.lock();
        let dropped = st.drop_undeletable(now);
        let taken = st.take_where(|st, e| e.chat_id == chat_id && !keep.contains(&e.message_id) && !st.is_protected(e));
        if dropped || !taken.is_empty() {
            self.persist(&st);
        }
        taken
    }

    /// Time-based sweep: remove and return the (unprotected) messages inactive for at least
    /// `ttl_secs`. Entries too old to delete are dropped. Writes the file only on a change, so
    /// an idle sweep costs a lock and a scan of the (usually empty) list.
    pub fn take_expired(&self, now: i64, ttl_secs: u64) -> Vec<TrackedMessage> {
        let ttl = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        let mut st = self.lock();
        if st.entries.is_empty() {
            return Vec::new();
        }
        let dropped = st.drop_undeletable(now);
        let taken = st.take_where(|st, e| now.saturating_sub(e.last_active()) >= ttl && !st.is_protected(e));
        if dropped || !taken.is_empty() {
            self.persist(&st);
        }
        taken
    }

    /// Put back messages whose deletion failed with a retryable error (network, rate limit),
    /// so the next sweep tries again. Entries already tracked again or too old are skipped.
    pub fn restore(&self, entries: &[TrackedMessage], now: i64) {
        let mut st = self.lock();
        let mut changed = false;
        for e in entries.iter().filter(|e| !e.undeletable(now)) {
            changed |= st.add(*e);
        }
        if changed {
            // restored entries are older than most others: keep the list ordered by time
            st.entries.sort_by_key(|e| e.sent_unix);
            self.persist(&st);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    pub fn contains(&self, chat_id: i64, message_id: i64) -> bool {
        self.lock().position(chat_id, message_id).is_some()
    }

    /// Snapshot of the tracked messages (oldest first).
    pub fn entries(&self) -> Vec<TrackedMessage> {
        self.lock().entries.clone()
    }
}

/// Group `entries` by chat (first-seen chat order, message order kept).
fn by_chat(entries: &[TrackedMessage]) -> Vec<(i64, Vec<TrackedMessage>)> {
    let mut groups: Vec<(i64, Vec<TrackedMessage>)> = Vec::new();
    for e in entries {
        match groups.iter_mut().find(|(c, _)| *c == e.chat_id) {
            Some((_, list)) => list.push(*e),
            None => groups.push((e.chat_id, vec![*e])),
        }
    }
    groups
}

/// Delete `entries` (taken from `janitor`) through `tg`, one request per chat. A retryable
/// failure (network, rate limit, server error) puts that chat's entries back for the next sweep;
/// any other failure (e.g. that user blocked the bot) forgets them. Returns how many deletions
/// Telegram accepted.
pub fn purge(tg: &dyn Telegram, janitor: &ChatJanitor, entries: &[TrackedMessage], now: i64) -> usize {
    let mut deleted = 0;
    for (chat_id, list) in by_chat(entries) {
        let ids: Vec<i64> = list.iter().map(|e| e.message_id).collect();
        match tg.delete_messages(chat_id, &ids) {
            Ok(()) => deleted += ids.len(),
            Err(e) if e.is_retryable() => {
                crate::log_debug!("chat cleanup: deleting {} message(s) failed ({e}); retrying later", ids.len());
                janitor.restore(&list, now);
            }
            Err(e) => crate::log_warn!("chat cleanup: cannot delete {} message(s): {e}", ids.len()),
        }
    }
    if deleted > 0 {
        crate::log_debug!("chat cleanup: deleted {deleted} message(s)");
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::TgError;
    use crate::telegram::types::InlineKeyboardMarkup;

    const CHAT: i64 = 1000;
    const T0: i64 = 1_800_000_000;

    fn ids(v: &[TrackedMessage]) -> Vec<i64> {
        v.iter().map(|e| e.message_id).collect()
    }

    #[test]
    fn only_system_notifications_are_ephemeral() {
        assert!(is_ephemeral_kind(NotificationKind::System));
        for k in [
            NotificationKind::Login,
            NotificationKind::FailedLogin,
            NotificationKind::Logout,
            NotificationKind::SshLogin,
            NotificationKind::SshFailed,
            NotificationKind::SshLogout,
            NotificationKind::Security,
        ] {
            assert!(!is_ephemeral_kind(k), "{k:?} must be kept");
        }
    }

    #[test]
    fn clean_after_is_clamped() {
        assert_eq!(clamp_clean_after(0), MIN_CLEAN_AFTER_SECS);
        assert_eq!(clamp_clean_after(600), 600);
        assert_eq!(clamp_clean_after(u64::MAX), MAX_CLEAN_AFTER_SECS);
    }

    #[test]
    fn track_dedupes_and_ignores_invalid() {
        let j = ChatJanitor::in_memory();
        j.track(CHAT, 5, T0, T0);
        j.track(CHAT, 5, T0, T0 + 10);
        j.track(CHAT, 0, T0, T0);
        j.track(CHAT, -3, T0, T0);
        j.track(0, 9, T0, T0);
        assert_eq!(j.len(), 1);
        assert_eq!(
            j.entries()[0],
            TrackedMessage { chat_id: CHAT, message_id: 5, sent_unix: T0, active_unix: T0 + 10 }
        );
        // a message already too old for Telegram to delete is not tracked
        j.track(CHAT, 6, T0 - MAX_DELETE_AGE_SECS, T0);
        assert!(!j.contains(CHAT, 6));
        // a sender clock in the future is clamped; a missing date means "now"
        j.track(CHAT, 7, T0 + 999, T0);
        j.track(CHAT, 8, 0, T0);
        let e = j.entries();
        assert_eq!(e[1].sent_unix, T0);
        assert_eq!(e[2].sent_unix, T0);
    }

    #[test]
    fn take_all_except_spares_protected_kept_and_other_chats() {
        let j = ChatJanitor::in_memory();
        for id in 1..=5 {
            j.track(CHAT, id, T0, T0);
        }
        j.track(2000, 9, T0, T0);
        j.protect(CHAT, 3);
        let taken = j.take_all_except(CHAT, &[4], T0 + 1);
        assert_eq!(ids(&taken), vec![1, 2, 5]);
        assert!(j.contains(CHAT, 3) && j.contains(CHAT, 4) && j.contains(2000, 9));
        // once the confirmation is resolved the message is cleaned like any other
        j.unprotect(CHAT, 3);
        assert!(!j.is_protected(CHAT, 3));
        assert_eq!(ids(&j.take_all_except(CHAT, &[], T0 + 2)), vec![3, 4]);
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn deletable_ids_are_only_noted_until_taken() {
        let j = ChatJanitor::in_memory();
        for id in 1..=4 {
            j.track(CHAT, id, T0, T0);
        }
        j.track(2000, 9, T0, T0);
        j.protect(CHAT, 2);
        // read-only: nothing leaves the list before the reply went out
        let noted = j.deletable_ids(CHAT, &[4], T0 + 1);
        assert_eq!(noted, vec![1, 3]);
        assert_eq!(j.len(), 5);
        // a message tracked in the meantime (the reply) is not noted, so it stays; a noted one
        // protected in the meantime stays too, and an id of another chat never matches
        j.track(CHAT, 5, T0 + 2, T0 + 2);
        j.protect(CHAT, 3);
        let mut wanted = noted.clone();
        wanted.push(9);
        assert_eq!(ids(&j.take_ids(CHAT, &wanted, T0 + 3)), vec![1]);
        assert!(j.contains(CHAT, 3) && j.contains(CHAT, 5) && j.contains(2000, 9));
        assert!(j.take_ids(CHAT, &[], T0 + 3).is_empty());
        // too old to delete: not offered, and dropped when taking
        let late = T0 + 2 + MAX_DELETE_AGE_SECS;
        assert!(j.deletable_ids(CHAT, &[], late).is_empty());
        assert!(j.take_ids(CHAT, &[4], late).is_empty());
        assert!(j.is_empty(), "{:?}", j.entries());
    }

    #[test]
    fn ttl_sweep_counts_from_last_activity() {
        let j = ChatJanitor::in_memory();
        j.track(CHAT, 1, T0, T0);
        j.track(CHAT, 2, T0 + 100, T0 + 100);
        j.track(CHAT, 3, T0, T0);
        j.protect(CHAT, 3);
        assert!(j.take_expired(T0 + 599, 600).is_empty());
        // a button press restarts the timeout of message 1
        j.touch(CHAT, 1, T0, T0 + 500);
        assert!(j.take_expired(T0 + 600, 600).is_empty());
        assert_eq!(ids(&j.take_expired(T0 + 700, 600)), vec![2]);
        assert_eq!(ids(&j.take_expired(T0 + 1100, 600)), vec![1]);
        // protected messages are never swept
        assert!(j.take_expired(T0 + 5000, 600).is_empty());
        assert!(j.contains(CHAT, 3));
        // touching an unknown message starts tracking it
        j.touch(CHAT, 44, T0 + 5000, T0 + 5000);
        assert!(j.contains(CHAT, 44));
    }

    #[test]
    fn entries_older_than_47_hours_are_dropped_not_returned() {
        let j = ChatJanitor::in_memory();
        j.track(CHAT, 1, T0, T0);
        j.track(CHAT, 2, T0 + 3600, T0 + 3600);
        j.protect(CHAT, 1);
        let later = T0 + MAX_DELETE_AGE_SECS;
        // message 1 can no longer be deleted: forgotten even though protected; 2 is returned
        assert_eq!(ids(&j.take_expired(later, 600)), vec![2]);
        assert!(j.is_empty());
        // the same housekeeping happens on take_all_except
        j.track(CHAT, 3, later, later);
        j.track(CHAT, 4, later + 10, later + 10);
        assert_eq!(ids(&j.take_all_except(CHAT, &[], later + MAX_DELETE_AGE_SECS + 5)), vec![4]);
        assert!(j.is_empty());
        // restore skips entries that became too old meanwhile
        let old = TrackedMessage { chat_id: CHAT, message_id: 7, sent_unix: T0, active_unix: T0 };
        j.restore(&[old], T0 + MAX_DELETE_AGE_SECS);
        assert!(j.is_empty());
    }

    #[test]
    fn bounded_list_forgets_the_oldest() {
        let j = ChatJanitor::in_memory();
        for id in 1..=(MAX_TRACKED as i64 + 25) {
            j.track(CHAT, id, T0, T0);
        }
        assert_eq!(j.len(), MAX_TRACKED);
        assert!(!j.contains(CHAT, 25));
        assert!(j.contains(CHAT, 26));
        let n = MAX_PROTECTED as i64 + 12;
        for i in 0..n {
            j.protect(CHAT, i);
        }
        assert!(j.lock().protected.len() <= MAX_PROTECTED);
        assert!(j.is_protected(CHAT, n - 1) && !j.is_protected(CHAT, 0));
        // one pending confirmation per authorized user fits
        const { assert!(MAX_PROTECTED >= crate::config::MAX_AUTHORIZED_USERS) };
    }

    /// Several users, several private chats: every operation stays inside its chat.
    #[test]
    fn chats_are_independent() {
        const ALICE: i64 = 1000;
        const BOB: i64 = 5000;
        let j = ChatJanitor::in_memory();
        for id in 1..=3 {
            j.track(ALICE, id, T0, T0);
            j.track(BOB, id, T0, T0);
        }
        // the same message id in two chats are two entries
        assert_eq!(j.len(), 6);
        j.protect(BOB, 2);
        assert!(!j.is_protected(ALICE, 2));
        // a new command in alice's chat notes only her messages (bob's protected 2 is irrelevant)
        assert_eq!(j.deletable_ids(ALICE, &[3], T0 + 1), vec![1, 2]);
        assert_eq!(ids(&j.take_ids(ALICE, &[1, 2], T0 + 1)), vec![1, 2]);
        assert!(j.contains(BOB, 1) && j.contains(BOB, 2) && j.contains(ALICE, 3));
        // /clear in bob's chat spares his protected dialog and alice's messages
        assert_eq!(ids(&j.take_all_except(BOB, &[], T0 + 2)), vec![1, 3]);
        assert!(j.contains(ALICE, 3) && j.contains(BOB, 2));
        // the sweep works over every chat, the purge sends one request per chat
        j.track(ALICE, 9, T0, T0);
        let due = j.take_expired(T0 + 10_000, 600);
        assert_eq!(due.iter().map(|e| (e.chat_id, e.message_id)).collect::<Vec<_>>(), vec![(ALICE, 3), (ALICE, 9)]);
        j.unprotect(BOB, 2);
        let tg = DeleteMock::default();
        let mut all = due;
        all.extend(j.take_expired(T0 + 10_000, 600));
        assert_eq!(purge(&tg, &j, &all, T0 + 10_000), 3);
        assert_eq!(*tg.calls.lock().unwrap(), vec![(ALICE, vec![3, 9]), (BOB, vec![2])]);
        assert!(j.is_empty());
    }

    #[test]
    fn restore_puts_entries_back_in_time_order() {
        let j = ChatJanitor::in_memory();
        j.track(CHAT, 1, T0, T0);
        j.track(CHAT, 2, T0 + 10, T0 + 10);
        let taken = j.take_all_except(CHAT, &[], T0 + 20);
        j.track(CHAT, 3, T0 + 30, T0 + 30);
        j.restore(&taken, T0 + 40);
        assert_eq!(ids(&j.entries()), vec![1, 2, 3]);
        // restoring twice does not duplicate
        j.restore(&taken, T0 + 40);
        assert_eq!(j.len(), 3);
    }

    fn temp_file(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("predator-janitor-{tag}-{}", crate::util::rand::hex(4)));
        let p = dir.join("chat-cleanup.json");
        (dir, p)
    }

    #[test]
    fn persistence_roundtrip() {
        let (dir, p) = temp_file("rt");
        let j = ChatJanitor::open(&p);
        assert!(j.is_empty());
        assert!(!p.exists(), "nothing written until something is tracked");
        j.track(CHAT, 11, T0, T0);
        j.track(CHAT, 12, T0 + 5, T0 + 5);
        j.protect(CHAT, 12);
        let again = ChatJanitor::open(&p);
        assert_eq!(again.entries(), j.entries());
        assert!(!again.is_protected(CHAT, 12), "protection is not persisted");
        let json = std::fs::read_to_string(&p).unwrap();
        assert!(json.contains("\"message_id\":11") && json.contains("\"sent_unix\""), "{json}");
        // taking writes the file too
        j.take_all_except(CHAT, &[], T0 + 6);
        assert_eq!(ChatJanitor::open(&p).entries().len(), 1);
        // the documented minimal entry format (no active_unix) and unknown fields are accepted
        std::fs::write(&p, br#"{"entries":[{"chat_id":1000,"message_id":5,"sent_unix":1800000000,"x":1}],"y":2}"#)
            .unwrap();
        let j = ChatJanitor::open(&p);
        assert_eq!(j.entries(), vec![TrackedMessage { chat_id: CHAT, message_id: 5, sent_unix: T0, active_unix: 0 }]);
        assert_eq!(ids(&j.take_expired(T0 + 600, 600)), vec![5], "ttl counts from sent_unix without active_unix");
        // a corrupt file is moved aside and the janitor starts empty
        std::fs::write(&p, b"{not json").unwrap();
        let j = ChatJanitor::open(&p);
        assert!(j.is_empty());
        assert!(p.with_extension("json.corrupt").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Message ids belong to one bot: after a token change to another bot the old entries are
    /// forgotten (never deleted — the ids may name the new bot's login alerts).
    #[test]
    fn entries_are_bound_to_the_bot() {
        let (dir, p) = temp_file("bot");
        let j = ChatJanitor::open(&p);
        // nothing bound yet: entries tracked before getMe answered are adopted
        j.track(CHAT, 1, T0, T0);
        assert!(!j.bind_bot(111));
        assert!(j.contains(CHAT, 1));
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"bot_id\":111"));
        // same bot again (reconnect, restart): nothing changes
        j.protect(CHAT, 1);
        assert!(!j.bind_bot(111));
        let again = ChatJanitor::open(&p);
        assert!(!again.bind_bot(111));
        assert_eq!(again.entries(), j.entries());
        // another bot: forgotten, including the protection, and the file says so
        assert!(j.bind_bot(222));
        assert!(j.is_empty() && !j.is_protected(CHAT, 1));
        let reopened = ChatJanitor::open(&p);
        assert!(reopened.is_empty());
        assert!(!reopened.bind_bot(222));
        // a list of the previous bot that is already empty: just re-bound
        assert!(!j.bind_bot(333));
        j.track(CHAT, 2, T0, T0);
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"bot_id\":333"));
        // in memory: same rules, no file
        let m = ChatJanitor::in_memory();
        m.track(CHAT, 3, T0, T0);
        assert!(!m.bind_bot(1));
        assert!(m.bind_bot(2));
        assert!(m.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Records `delete_messages` calls and fails them on demand.
    #[derive(Default)]
    struct DeleteMock {
        calls: Mutex<Vec<(i64, Vec<i64>)>>,
        fail: Mutex<Option<TgError>>,
    }

    impl Telegram for DeleteMock {
        fn send_message(&self, _: i64, _: &str, _: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
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
        fn delete_messages(&self, chat_id: i64, message_ids: &[i64]) -> Result<(), TgError> {
            self.calls.lock().unwrap().push((chat_id, message_ids.to_vec()));
            match self.fail.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn purge_groups_by_chat_and_restores_on_retryable_errors() {
        let j = ChatJanitor::in_memory();
        let tg = DeleteMock::default();
        j.track(CHAT, 1, T0, T0);
        j.track(2000, 2, T0, T0);
        j.track(CHAT, 3, T0, T0);
        let all: Vec<TrackedMessage> = [j.take_all_except(CHAT, &[], T0), j.take_all_except(2000, &[], T0)].concat();
        assert_eq!(purge(&tg, &j, &all, T0), 3);
        assert_eq!(*tg.calls.lock().unwrap(), vec![(CHAT, vec![1, 3]), (2000, vec![2])]);
        assert!(j.is_empty());

        // network failure: kept for the next sweep
        *tg.fail.lock().unwrap() = Some(TgError::Network("timeout".into()));
        assert_eq!(purge(&tg, &j, &all, T0 + 1), 0);
        assert_eq!(j.len(), 3);
        // permanent failure (bot blocked): forgotten
        let all = j.take_expired(T0 + 10_000, 600);
        *tg.fail.lock().unwrap() = Some(TgError::Forbidden("bot was blocked by the user".into()));
        assert_eq!(purge(&tg, &j, &all, T0 + 10_000), 0);
        assert!(j.is_empty());
        // nothing to do: no call
        tg.calls.lock().unwrap().clear();
        assert_eq!(purge(&tg, &j, &[], T0), 0);
        assert!(tg.calls.lock().unwrap().is_empty());
    }
}
