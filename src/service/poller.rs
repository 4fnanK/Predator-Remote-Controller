//! Telegram long-poll loop (`telegram-poller` thread).
//!
//! * Waits (blocked on `ctx.poller_wake`) while there is no usable token. The connectivity hint
//!   is only advisory: while it says "no internet" the poller waits at most
//!   [`OFFLINE_RECHECK`](super::runtime::OFFLINE_RECHECK) (or until the network changes) and then
//!   tries anyway; a success overrides the hint until the network changes.
//! * Once per token: `getMe` (refresh `bot_username`, bind the polling position to the bot),
//!   `deleteWebhook`, `setMyCommands`.
//! * `getUpdates` long poll (50 s); every update is persisted to `telegram-state.json` *before*
//!   it is dispatched, so a command is never executed twice after a crash or restart.
//! * Updates that Telegram queued while Vigil was not polling (after a start, or after more
//!   than [`OUTAGE`] without a successful poll) are fetched with short polls and dispatched as
//!   *backlog*: their state-changing button presses are not executed.
//! * Automatic chat cleanup: after the setup and after every successful getUpdates cycle, the
//!   short-lived messages that were inactive for `chat_clean_after_secs` are deleted in every
//!   user's chat ([`sweep_chat`]; expired power confirmations are released first). The long poll already
//!   wakes the thread at least every ~50 s while online, so this needs no thread or timer of its
//!   own (and costs one lock when nothing is tracked).
//! * Memory hygiene ([`TrimPolicy`]): after a getUpdates cycle without updates — the quiet point
//!   of the loop — the working set is trimmed once after start-up and after on-demand bursts.
//!   Without a usable token the start-up trim is done from the idle wait instead (its first
//!   timeout is shortened once to the trim's due time).
//! * A network change or resume interrupts a long poll in flight
//!   ([`Shared::interrupt_long_poll`]); the interrupted request (a network error while the
//!   interrupt generation moved, see [`interrupted`]) is retried at once, without backoff or
//!   warning.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::runtime::{OFFLINE_RECHECK, Shared, TOKEN_RECHECK, TrimPolicy, catch};
use crate::context::AppContext;
use crate::telegram::api::{LONG_POLL_SECS, TelegramApi};
use crate::telegram::bot::Bot;
use crate::telegram::janitor;
use crate::telegram::types::Update;
use crate::telegram::{Telegram, TgError};
use crate::util::Backoff;
use crate::util::time::now_unix;
use crate::{log_debug, log_error, log_info, log_warn};

/// Telegram assigns a *random* next update id after a week without updates, so a persisted id
/// older than this is not trusted as an offset/filter (everything older was confirmed anyway).
const OFFSET_TRUST_SECS: i64 = 6 * 86_400;
/// No successful getUpdates for longer than this = an outage: the next batch is backlog.
pub(crate) const OUTAGE: Duration = Duration::from_secs(90);
/// getUpdates returns at most this many updates per call (Bot API default `limit`).
const GET_UPDATES_LIMIT: usize = 100;

/// Persisted polling position (`telegram-state.json`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PollState {
    /// Highest processed update id.
    #[serde(default)]
    pub last_update_id: i64,
    /// When it was processed (Unix seconds).
    #[serde(default)]
    pub updated_unix: i64,
}

/// On-disk layout of `telegram-state.json`: the position plus the bot it belongs to (update ids
/// are per bot). `bot_id` may be absent (a file written while the bot was not known yet).
#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    last_update_id: i64,
    #[serde(default)]
    updated_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bot_id: Option<i64>,
}

impl PollState {
    /// Position and the id of the bot it belongs to (None when unknown).
    pub fn load_with_bot(path: &Path) -> (PollState, Option<i64>) {
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<StateFile>(&bytes).unwrap_or_else(|e| {
                log_warn!("telegram-state.json is corrupt ({e}); starting from the oldest pending update");
                StateFile::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFile::default(),
            Err(e) => {
                log_warn!("cannot read telegram-state.json ({e}); starting from the oldest pending update");
                StateFile::default()
            }
        };
        (PollState { last_update_id: file.last_update_id, updated_unix: file.updated_unix }, file.bot_id)
    }

    /// Save without a bot id (the poller adopts the current bot on its next start).
    #[cfg(test)]
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        self.save_for_bot(path, None)
    }

    /// Save, recording which bot the update ids belong to.
    pub fn save_for_bot(&self, path: &Path, bot_id: Option<i64>) -> std::io::Result<()> {
        let file = StateFile { last_update_id: self.last_update_id, updated_unix: self.updated_unix, bot_id };
        let json = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        crate::paths::atomic_write(path, &json)
    }

    fn trusted(&self, now: i64) -> bool {
        self.last_update_id > 0 && now - self.updated_unix < OFFSET_TRUST_SECS
    }

    /// `offset` parameter for getUpdates (0 = the oldest unconfirmed update).
    pub fn offset(&self, now: i64) -> i64 {
        if self.trusted(now) { self.last_update_id + 1 } else { 0 }
    }

    /// Whether `update_id` has not been processed yet.
    pub fn is_new(&self, update_id: i64, now: i64) -> bool {
        !self.trusted(now) || update_id > self.last_update_id
    }

    pub fn record(&mut self, update_id: i64, now: i64) {
        self.last_update_id = update_id;
        self.updated_unix = now;
    }
}

/// Result of binding the persisted position to the bot `getMe` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BotBinding {
    /// Same bot as recorded.
    Unchanged,
    /// No bot recorded yet (older file or written by `pair`): the position is kept.
    Adopted,
    /// A different bot: its update ids are unrelated, so the position was discarded.
    Reset { previous: i64 },
}

/// F03: update ids are per bot. Keep the position only for the bot it was recorded for.
pub(crate) fn bind_to_bot(state: &mut PollState, stored: &mut Option<i64>, bot_id: i64) -> BotBinding {
    match *stored {
        Some(prev) if prev == bot_id => BotBinding::Unchanged,
        Some(prev) => {
            *state = PollState::default();
            *stored = Some(bot_id);
            BotBinding::Reset { previous: prev }
        }
        None => {
            *stored = Some(bot_id);
            BotBinding::Adopted
        }
    }
}

/// I2: decides which getUpdates batches are *backlog* — updates Telegram queued while Vigil
/// was not polling. That is everything pending at process start (or after the bot changed) and
/// after an outage (no successful getUpdates for more than [`OUTAGE`]). Such batches are fetched
/// with a zero-timeout poll so they contain only what was already queued (a button pressed
/// during a long poll is live, not backlog); a full batch means more may be queued, so catching
/// up continues until a batch comes back with room to spare.
#[derive(Debug, Clone)]
pub(crate) struct Backlog {
    /// Completion of the last successful getUpdates (monotonic, wall clock).
    last_ok: Option<(Instant, i64)>,
    catching_up: bool,
}

impl Backlog {
    pub fn new() -> Self {
        Self { last_ok: None, catching_up: true }
    }

    /// Forget the polling history (new bot): the next batch is backlog again.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Called right before a getUpdates request: whether it catches up on a backlog. Both clocks
    /// are checked (the monotonic one may or may not include time spent in sleep/hibernation).
    pub fn before_request(&mut self, now: Instant, now_unix: i64) -> bool {
        match self.last_ok {
            None => self.catching_up = true,
            Some((t, unix)) => {
                if now.saturating_duration_since(t) > OUTAGE || now_unix - unix > OUTAGE.as_secs() as i64 {
                    self.catching_up = true;
                }
            }
        }
        self.catching_up
    }

    /// A getUpdates request started with `catching_up` succeeded with `count` updates.
    pub fn after_success(&mut self, now: Instant, now_unix: i64, count: usize, catching_up: bool) {
        self.last_ok = Some((now, now_unix));
        if catching_up && count < GET_UPDATES_LIMIT {
            self.catching_up = false;
        }
    }
}

/// What to do after a failed Telegram request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorAction {
    /// Exponential backoff (network, 5xx, 409 conflict, unexpected responses).
    Backoff,
    /// Honour `retry_after`.
    Wait(Duration),
    /// 401 — stop using the token until it is replaced.
    TokenInvalid,
}

pub(crate) fn poll_error_action(e: &TgError) -> ErrorAction {
    match e {
        TgError::Unauthorized => ErrorAction::TokenInvalid,
        TgError::RateLimited(s) => ErrorAction::Wait(Duration::from_secs((*s).clamp(1, 3600))),
        _ => ErrorAction::Backoff,
    }
}

pub(crate) fn run(sh: &Arc<Shared>) {
    let ctx = &sh.ctx;
    let state_path = ctx.paths.telegram_state();
    let (mut state, mut bot_id) = PollState::load_with_bot(&state_path);
    let mut backoff = Backoff::new(Duration::from_secs(2), Duration::from_secs(300));
    let mut backlog = Backlog::new();
    let mut setup_generation = 0u64;
    let mut try_anyway = false;
    let mut failures = 0u32;
    let mut logged_no_token = false;
    let mut logged_invalid = false;
    let mut trim = TrimPolicy::default();
    loop {
        if ctx.stop.is_stopped() {
            return;
        }
        let seen = ctx.poller_wake.generation();
        let Some((api, generation)) = sh.tg.current() else {
            if !logged_no_token {
                log_info!("Telegram poller idle: no usable bot token (re-checked every 30 minutes)");
                logged_no_token = true;
            }
            if idle_wait(sh, &mut trim, seen, TOKEN_RECHECK) && !ctx.stop.is_stopped() {
                sh.reload_token();
            }
            continue;
        };
        logged_no_token = false;

        if ctx.status.token_invalid.load(Ordering::Relaxed) {
            if !logged_invalid {
                log_error!(
                    "Telegram rejected the bot token (401 Unauthorized). Store a new one with \
                     'predator-service set-token'; re-checking every 30 minutes."
                );
                ctx.status.set_last_error("Telegram bot token rejected (401)");
                logged_invalid = true;
            }
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
            if !idle_wait(sh, &mut trim, seen, TOKEN_RECHECK) {
                continue; // only the start-up trim was due: keep waiting
            }
            if ctx.stop.is_stopped() {
                return;
            }
            if !sh.reload_token() && matches!(catch(|| api.get_me()), Ok(Ok(_))) {
                log_info!("the bot token is accepted again");
                sh.mark_online();
                sh.kick_sender();
            }
            continue;
        }
        logged_invalid = false;

        if !try_anyway && sh.should_wait_for_network() {
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
            // Returns on a connectivity change, resume, new token or stop — not later than
            // OFFLINE_RECHECK — and then Telegram is tried regardless of the hint.
            sh.wait_retry(&ctx.poller_wake, OFFLINE_RECHECK);
            try_anyway = true;
            continue;
        }
        try_anyway = false;

        if setup_generation != generation {
            match setup(sh, &api) {
                Ok(me_id) => {
                    setup_generation = generation;
                    rebind(&mut state, &mut bot_id, me_id, &state_path, &mut backlog);
                    if failures > 0 {
                        log_info!("Telegram connection restored");
                    }
                    failures = 0;
                    backoff.reset();
                    // tracked message ids belong to one bot: forget those of a replaced bot
                    ctx.janitor.bind_bot(me_id);
                    // start-up sweep: messages that expired while Vigil was stopped or offline
                    sweep(sh);
                }
                Err(e) => {
                    failures += 1;
                    on_error(sh, &e, &mut backoff, failures, "getMe");
                    continue;
                }
            }
        }

        let catching_up = backlog.before_request(Instant::now(), now_unix());
        let timeout = if catching_up { 0 } else { LONG_POLL_SECS };
        let interrupts = sh.interrupt_generation();
        let result = {
            let _active = LongPollActive::enter(sh);
            api.get_updates(state.offset(now_unix()), timeout)
        };
        match result {
            Ok(updates) => {
                if failures > 0 {
                    log_info!("Telegram connection restored");
                }
                failures = 0;
                backoff.reset();
                sh.mark_online();
                backlog.after_success(Instant::now(), now_unix(), updates.len(), catching_up);
                if catching_up && !updates.is_empty() {
                    log_info!(
                        "{} Telegram update(s) were queued while Vigil was not polling; buttons pressed in the \
                         meantime are not executed",
                        updates.len()
                    );
                }
                let idle_cycle = updates.is_empty();
                process_batch(sh, &mut state, bot_id, &state_path, updates, catching_up);
                sweep(sh);
                if idle_cycle {
                    sh.maybe_trim(&mut trim);
                }
            }
            Err(e) if interrupted(interrupts, sh.interrupt_generation(), &e) => {
                // network change / resume: poll again at once (the loop re-checks the stop flag
                // and the connectivity hint first)
                log_debug!("Telegram getUpdates interrupted ({e}); polling again");
            }
            Err(e) => {
                failures += 1;
                on_error(sh, &e, &mut backoff, failures, "getUpdates");
            }
        }
    }
}

/// Did request error `e` come from an interrupt (generation `before` → `after` moved while the
/// request was in flight)? A cancelled request always fails with a network error; any other
/// answer (401, 429 `retry_after`, 409, …) is a real reply from Telegram and keeps its normal
/// handling even when an interrupt happened at the same time.
pub(crate) fn interrupted(before: u64, after: u64, e: &TgError) -> bool {
    before != after && matches!(e, TgError::Network(_))
}

/// Marks the poller as being inside getUpdates for its lifetime (also when the request panics).
struct LongPollActive<'a>(&'a Shared);

impl<'a> LongPollActive<'a> {
    fn enter(sh: &'a Shared) -> Self {
        sh.set_long_poll_active(true);
        Self(sh)
    }
}

impl Drop for LongPollActive<'_> {
    fn drop(&mut self) {
        self.0.set_long_poll_active(false);
    }
}

/// Wait on `poller_wake` for up to `max` while nothing can be polled (no usable or a rejected
/// token). While the start-up trim is pending, the wait ends once at its due time to do it
/// (that is the only wake-up the poller has then). Returns true when the wait ended because of a
/// signal (or `max` elapsed), false when it ended only for the trim.
fn idle_wait(sh: &Shared, trim: &mut TrimPolicy, seen: u64, max: Duration) -> bool {
    let wake = &sh.ctx.poller_wake;
    match trim.startup_due_in(sh.clock_ms(), sh.last_activity_ms()) {
        Some(due) if due < max => {
            if wake.wait_changed(seen, due) != seen || sh.ctx.stop.is_stopped() {
                return true;
            }
            sh.maybe_trim(trim);
            false
        }
        _ => {
            wake.wait_changed(seen, max);
            true
        }
    }
}

/// Apply [`bind_to_bot`] after `getMe` and persist the result.
fn rebind(state: &mut PollState, bot_id: &mut Option<i64>, me_id: i64, path: &Path, backlog: &mut Backlog) {
    match bind_to_bot(state, bot_id, me_id) {
        BotBinding::Unchanged => return,
        BotBinding::Adopted => log_debug!("Telegram polling position bound to bot id {me_id}"),
        BotBinding::Reset { previous } => {
            log_warn!(
                "the Telegram bot changed (id {previous} -> {me_id}); the polling position of the previous bot was \
                 discarded"
            );
            backlog.reset();
        }
    }
    if let Err(e) = state.save_for_bot(path, *bot_id) {
        log_warn!("cannot save telegram-state.json: {e}");
    }
}

/// Once per token: validate it, refresh the bot username, drop any webhook, register commands.
/// Returns the bot's user id.
fn setup(sh: &Shared, api: &TelegramApi) -> Result<i64, TgError> {
    let me = api.get_me()?;
    sh.mark_online();
    if let Some(name) = me.username.as_ref().filter(|u| !u.is_empty()) {
        if sh.ctx.settings.get().bot_username.as_deref() != Some(name.as_str()) {
            let n = name.clone();
            if let Err(e) = sh.ctx.settings.update(move |s| s.bot_username = Some(n)) {
                log_warn!("cannot save the bot username: {e}");
            }
        }
        log_info!("connected to Telegram as @{name}");
    }
    match api.delete_webhook() {
        Ok(()) => {}
        Err(TgError::Unauthorized) => return Err(TgError::Unauthorized),
        Err(e) => log_warn!("deleteWebhook failed: {e}"),
    }
    let commands = catch(Bot::command_list).unwrap_or_default();
    if !commands.is_empty() {
        match api.set_my_commands(&commands) {
            Ok(()) => {}
            Err(TgError::Unauthorized) => return Err(TgError::Unauthorized),
            Err(e) => log_warn!("setMyCommands failed: {e}"),
        }
    }
    Ok(me.id)
}

fn process_batch(
    sh: &Shared,
    state: &mut PollState,
    bot_id: Option<i64>,
    path: &Path,
    mut updates: Vec<Update>,
    from_backlog: bool,
) {
    updates.sort_by_key(|u| u.update_id);
    let mut handled = false;
    for u in updates {
        if sh.ctx.stop.is_stopped() {
            return;
        }
        let now = now_unix();
        if !state.is_new(u.update_id, now) {
            log_debug!("skipping already processed update {}", u.update_id);
            continue;
        }
        // Persist first: at-most-once execution even if dispatching crashes the process.
        state.record(u.update_id, now);
        if let Err(e) = state.save_for_bot(path, bot_id) {
            log_warn!("cannot save telegram-state.json: {e}");
        }
        if let Err(e) = catch(|| sh.bot.handle_update_with(&u, from_backlog)) {
            log_error!("dispatcher crashed on update {}: {e}", u.update_id);
        }
        handled = true;
    }
    if handled {
        // An on-demand burst just ended (commands, helper processes such as ssid-helper): the
        // memory trim policy waits for quiet after this mark.
        sh.note_activity();
        // A user is active: deliver anything still queued right away.
        sh.kick_sender();
    }
}

/// Time-based chat cleanup: delete the tracked short-lived messages that were inactive for
/// `chat_clean_after_secs` (nothing when automatic cleaning is off). Failed deletions with a
/// retryable error are kept for the next sweep. Returns how many messages were deleted.
pub(crate) fn sweep_chat(ctx: &AppContext, tg: &dyn Telegram, now: i64) -> usize {
    if ctx.janitor.is_empty() {
        return 0; // the common idle case: no settings snapshot, no scan
    }
    let Some(ttl) = ctx.auto_clean_after() else { return 0 };
    let due = ctx.janitor.take_expired(now, ttl);
    if due.is_empty() {
        return 0;
    }
    janitor::purge(tg, &ctx.janitor, &due, now)
}

/// [`sweep_chat`] for the running service: a confirmation dialog that has expired is released
/// first (otherwise it would stay protected until that user's next message). Skipped while the
/// service stops — the shutdown must not wait for deletions.
pub(crate) fn sweep_service(ctx: &AppContext, bot: &Bot, tg: &dyn Telegram, now: i64) -> usize {
    if ctx.stop.is_stopped() || ctx.janitor.is_empty() {
        return 0;
    }
    bot.release_expired_confirmation();
    sweep_chat(ctx, tg, now)
}

fn sweep(sh: &Shared) {
    if let Err(e) = catch(|| sweep_service(&sh.ctx, &sh.bot, &*sh.tg, now_unix())) {
        log_error!("chat cleanup crashed: {e}");
    }
}

fn on_error(sh: &Shared, e: &TgError, backoff: &mut Backoff, failures: u32, what: &str) {
    let ctx = &sh.ctx;
    sh.note_request_error(e);
    match poll_error_action(e) {
        ErrorAction::TokenInvalid => {
            ctx.status.token_invalid.store(true, Ordering::Relaxed);
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
        }
        ErrorAction::Wait(d) => {
            log_warn!("Telegram {what}: {e}");
            ctx.stop.sleep(d);
        }
        ErrorAction::Backoff => {
            ctx.status.telegram_online.store(false, Ordering::Relaxed);
            ctx.status.set_last_error(format!("Telegram: {e}"));
            let d = backoff.next_delay();
            let hint = if matches!(e, TgError::Conflict(_)) {
                " — another program is polling this bot (is 'pair' running, or a second installation?)"
            } else {
                ""
            };
            if failures == 1 || failures.is_multiple_of(20) {
                log_warn!("Telegram {what} failed: {e}{hint} (retry in {} s, attempt {failures})", d.as_secs());
            } else {
                log_debug!("Telegram {what} failed: {e} (retry in {} s, attempt {failures})", d.as_secs());
            }
            // A connectivity change (or resume / new token) ends the wait and resets the backoff.
            let epoch = sh.retry_epoch();
            sh.wait_retry(&ctx.poller_wake, d);
            if sh.retry_epoch() != epoch {
                backoff.reset();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    /// Only a network error during an interrupt is "interrupted" (retried at once); real answers
    /// from Telegram keep their handling (token invalid, retry_after, backoff).
    #[test]
    fn interrupted_needs_a_moved_generation_and_a_network_error() {
        let net = TgError::Network("request cancelled (network change, resume or stop)".into());
        assert!(interrupted(4, 5, &net));
        assert!(!interrupted(5, 5, &net), "no interrupt: a real failure (backoff)");
        for real in [
            TgError::Unauthorized,
            TgError::RateLimited(30),
            TgError::Conflict("terminated by other getUpdates request".into()),
            TgError::Server(502, "Bad Gateway".into()),
            TgError::Parse("x".into()),
        ] {
            assert!(!interrupted(4, 5, &real), "{real:?}");
        }
        // ... so a 401 or a 429 that coincides with an interrupt is still acted upon
        assert_eq!(poll_error_action(&TgError::Unauthorized), ErrorAction::TokenInvalid);
        assert_eq!(poll_error_action(&TgError::RateLimited(30)), ErrorAction::Wait(Duration::from_secs(30)));
    }

    #[test]
    fn fresh_state_offsets_and_filters() {
        let now = 1_800_000_000;
        let mut st = PollState::default();
        assert_eq!(st.offset(now), 0);
        assert!(st.is_new(5, now));
        st.record(100, now);
        assert_eq!(st.offset(now + 10), 101);
        assert!(!st.is_new(100, now + 10));
        assert!(!st.is_new(99, now + 10));
        assert!(st.is_new(101, now + 10));
    }

    #[test]
    fn stale_state_is_not_trusted() {
        let now = 1_800_000_000;
        let st = PollState { last_update_id: 500, updated_unix: now - 7 * DAY };
        // Telegram may have restarted ids at a random lower value: poll from the oldest
        // unconfirmed update and process whatever comes.
        assert_eq!(st.offset(now), 0);
        assert!(st.is_new(42, now));
        let recent = PollState { last_update_id: 500, updated_unix: now - DAY };
        assert_eq!(recent.offset(now), 501);
        assert!(!recent.is_new(42, now));
    }

    fn temp_state(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("predator-poll-{tag}-{}", crate::util::rand::hex(4)));
        let p = dir.join("telegram-state.json");
        (dir, p)
    }

    #[test]
    fn state_file_roundtrip() {
        let (dir, p) = temp_state("rt");
        let load = |p: &Path| PollState::load_with_bot(p).0;
        assert_eq!(load(&p), PollState::default());
        let st = PollState { last_update_id: 123_456_789, updated_unix: 1_700_000_000 };
        st.save(&p).unwrap();
        assert_eq!(load(&p), st);
        let json = std::fs::read_to_string(&p).unwrap();
        assert!(json.contains("\"last_update_id\":123456789"));
        assert!(!json.contains("bot_id"), "{json}");
        // the documented minimal format is accepted
        std::fs::write(&p, br#"{"last_update_id":77}"#).unwrap();
        assert_eq!(load(&p).last_update_id, 77);
        std::fs::write(&p, b"{garbage").unwrap();
        assert_eq!(PollState::load_with_bot(&p), (PollState::default(), None));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F03: the bot id is persisted next to the position, and older files load without it.
    #[test]
    fn bot_id_persistence() {
        let (dir, p) = temp_state("bot");
        let st = PollState { last_update_id: 870_000_000, updated_unix: 1_800_000_000 };
        st.save_for_bot(&p, Some(111)).unwrap();
        assert_eq!(PollState::load_with_bot(&p), (st, Some(111)));
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"bot_id\":111"));
        // `pair` and older versions write no bot id
        st.save(&p).unwrap();
        assert_eq!(PollState::load_with_bot(&p), (st, None));
        std::fs::write(&p, br#"{"last_update_id":5,"updated_unix":6,"bot_id":7,"future_field":true}"#).unwrap();
        assert_eq!(PollState::load_with_bot(&p), (PollState { last_update_id: 5, updated_unix: 6 }, Some(7)));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F03: a position recorded for another bot is discarded, so the new bot's (lower) update ids
    /// are neither skipped nor confirmed away.
    #[test]
    fn position_is_reset_when_the_bot_changes() {
        let now = 1_800_000_000;
        let recorded = PollState { last_update_id: 870_000_000, updated_unix: now - DAY };

        let (mut st, mut bot) = (recorded, Some(1));
        assert_eq!(bind_to_bot(&mut st, &mut bot, 1), BotBinding::Unchanged);
        assert_eq!(st, recorded);
        assert_eq!(st.offset(now), 870_000_001);

        assert_eq!(bind_to_bot(&mut st, &mut bot, 2), BotBinding::Reset { previous: 1 });
        assert_eq!(bot, Some(2));
        assert_eq!(st.offset(now), 0);
        assert!(st.is_new(300_000_000, now));

        // unknown owner of the position (older file / pair): keep it and remember the bot
        let (mut st, mut bot) = (recorded, None);
        assert_eq!(bind_to_bot(&mut st, &mut bot, 9), BotBinding::Adopted);
        assert_eq!((st, bot), (recorded, Some(9)));
        assert_eq!(bind_to_bot(&mut st, &mut bot, 9), BotBinding::Unchanged);
    }

    #[test]
    fn rebind_persists_and_restarts_the_backlog() {
        let (dir, p) = temp_state("rebind");
        let mut st = PollState { last_update_id: 870_000_000, updated_unix: 1_800_000_000 };
        let mut bot = Some(1);
        let mut backlog = Backlog::new();
        let t0 = Instant::now();
        backlog.before_request(t0, 1_800_000_000);
        backlog.after_success(t0, 1_800_000_000, 0, true);
        assert!(!backlog.before_request(t0, 1_800_000_001));
        rebind(&mut st, &mut bot, 2, &p, &mut backlog);
        assert_eq!(PollState::load_with_bot(&p), (PollState::default(), Some(2)));
        assert!(backlog.before_request(t0, 1_800_000_001), "first batch of the new bot is backlog");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I2: the first batch after start and the first after an outage (> 90 s without a successful
    /// getUpdates) are backlog; ordinary long polls are not.
    #[test]
    fn backlog_decision() {
        let t0 = Instant::now();
        let u0 = 1_800_000_000;
        let mut b = Backlog::new();
        // process start
        assert!(b.before_request(t0, u0));
        b.after_success(t0 + Duration::from_millis(200), u0, 3, true);
        // the catch-up batch was not full: everything queued has been seen; live from now on
        assert!(!b.before_request(t0 + Duration::from_secs(1), u0 + 1));
        b.after_success(t0 + Duration::from_secs(51), u0 + 51, 1, false);
        assert!(!b.before_request(t0 + Duration::from_secs(52), u0 + 52));
        // a failed request does not count as success: 91 s later it is an outage
        assert!(b.before_request(t0 + Duration::from_secs(51 + 91), u0 + 51 + 91));
        b.after_success(t0 + Duration::from_secs(143), u0 + 143, 0, true);
        assert!(!b.before_request(t0 + Duration::from_secs(144), u0 + 144));
        // exactly at the limit is not an outage
        b.after_success(t0 + Duration::from_secs(150), u0 + 150, 0, false);
        assert!(!b.before_request(t0 + Duration::from_secs(240), u0 + 240));
    }

    #[test]
    fn full_backlog_batches_keep_catching_up() {
        let t0 = Instant::now();
        let u0 = 1_800_000_000;
        let mut b = Backlog::new();
        assert!(b.before_request(t0, u0));
        b.after_success(t0, u0, GET_UPDATES_LIMIT, true);
        // more may still be queued
        assert!(b.before_request(t0 + Duration::from_secs(1), u0 + 1));
        b.after_success(t0 + Duration::from_secs(1), u0 + 1, 12, true);
        assert!(!b.before_request(t0 + Duration::from_secs(2), u0 + 2));
        // a full *live* batch does not turn into backlog
        b.after_success(t0 + Duration::from_secs(3), u0 + 3, GET_UPDATES_LIMIT, false);
        assert!(!b.before_request(t0 + Duration::from_secs(4), u0 + 4));
    }

    #[test]
    fn wall_clock_gap_also_counts() {
        // e.g. the monotonic clock did not advance during hibernation
        let t0 = Instant::now();
        let mut b = Backlog::new();
        b.before_request(t0, 1_000);
        b.after_success(t0, 1_000, 0, true);
        assert!(b.before_request(t0 + Duration::from_secs(5), 1_000 + 3_600));
    }

    /// Records `delete_messages` calls; optionally fails them.
    #[derive(Default)]
    struct Deletes {
        calls: std::sync::Mutex<Vec<(i64, Vec<i64>)>>,
        fail: Option<TgError>,
    }

    impl Telegram for Deletes {
        fn send_message(
            &self,
            _: i64,
            _: &str,
            _: Option<&crate::telegram::types::InlineKeyboardMarkup>,
        ) -> Result<i64, TgError> {
            Ok(1)
        }
        fn edit_message(
            &self,
            _: i64,
            _: i64,
            _: &str,
            _: Option<&crate::telegram::types::InlineKeyboardMarkup>,
        ) -> Result<(), TgError> {
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
            self.fail.clone().map_or(Ok(()), Err)
        }
    }

    /// The time-based sweep deletes only messages inactive for `chat_clean_after_secs`.
    #[test]
    fn ttl_sweep_deletes_expired_messages() {
        let ctx = AppContext::for_tests();
        let t0 = 1_800_000_000;
        let tg = Deletes::default();
        ctx.janitor.track(1000, 1, t0, t0);
        ctx.janitor.track(1000, 2, t0 + 300, t0 + 300);
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 599), 0);
        assert!(tg.calls.lock().unwrap().is_empty(), "nothing due: no request");
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 600), 1);
        assert_eq!(*tg.calls.lock().unwrap(), vec![(1000, vec![1])]);
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 900), 1);
        assert!(ctx.janitor.is_empty());
        // a shorter setting applies at the next sweep
        ctx.settings.update(|s| s.chat_clean_after_secs = 120).unwrap();
        ctx.janitor.track(1000, 3, t0 + 1000, t0 + 1000);
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 1120), 1);
    }

    /// Several authorized users: the sweep cleans every private chat, one request per chat.
    #[test]
    fn ttl_sweep_covers_every_users_chat() {
        let ctx = AppContext::for_tests();
        let t0 = 1_800_000_000;
        let tg = Deletes::default();
        ctx.janitor.track(1000, 1, t0, t0);
        ctx.janitor.track(5000, 1, t0, t0);
        ctx.janitor.track(5000, 2, t0 + 500, t0 + 500);
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 600), 2);
        assert_eq!(*tg.calls.lock().unwrap(), vec![(1000, vec![1]), (5000, vec![1])]);
        assert!(ctx.janitor.contains(5000, 2), "still in use");
    }

    #[test]
    fn sweep_keeps_messages_when_telegram_is_unreachable_or_cleaning_is_off() {
        let ctx = AppContext::for_tests();
        let t0 = 1_800_000_000;
        ctx.janitor.track(1000, 1, t0, t0);
        let offline = Deletes { fail: Some(TgError::Network("timeout".into())), ..Default::default() };
        assert_eq!(sweep_chat(&ctx, &offline, t0 + 700), 0);
        assert!(ctx.janitor.contains(1000, 1), "retried at the next sweep");
        // switched off: nothing is deleted
        ctx.settings.update(|s| s.auto_clean_chat = false).unwrap();
        let tg = Deletes::default();
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 5000), 0);
        assert!(tg.calls.lock().unwrap().is_empty());
        // back on after two days: messages older than 47 h are only forgotten (Telegram can no
        // longer delete them), so no request is made
        ctx.settings.update(|s| s.auto_clean_chat = true).unwrap();
        ctx.janitor.track(1000, 2, t0 + 100, t0 + 100);
        assert_eq!(sweep_chat(&ctx, &tg, t0 + 100 + crate::telegram::janitor::MAX_DELETE_AGE_SECS), 0);
        assert!(ctx.janitor.is_empty());
        assert!(tg.calls.lock().unwrap().is_empty(), "too old to delete: no request");
    }

    /// Power actions are available; nothing else is ever called by the test below.
    struct PowerOnly;

    impl crate::sys::SystemActions for PowerOnly {
        fn check_power(&self, _: crate::sys::PowerAction) -> Result<(), String> {
            Ok(())
        }
        fn execute_power(&self, _: crate::sys::PowerAction) -> Result<String, String> {
            Err("not used".into())
        }
        fn lock(&self) -> Result<String, String> {
            Err("not used".into())
        }
        fn logout(&self) -> Result<String, String> {
            Err("not used".into())
        }
        fn network(&self) -> Result<crate::sys::NetworkInfo, String> {
            Err("not used".into())
        }
        fn battery(&self) -> Result<crate::sys::BatteryInfo, String> {
            Err("not used".into())
        }
        fn tailscale_status(&self) -> crate::sys::TailscaleStatus {
            unreachable!("not used")
        }
        fn tailscale_up(&self) -> crate::sys::TailscaleOpResult {
            unreachable!("not used")
        }
        fn tailscale_down(&self) -> crate::sys::TailscaleOpResult {
            unreachable!("not used")
        }
        fn system_status(&self) -> crate::sys::SystemStatus {
            unreachable!("not used")
        }
        fn is_dry_run(&self) -> bool {
            true
        }
    }

    /// The owner asks for a shutdown and then sends nothing: the periodic sweep deletes the
    /// command at once, the dialog only after the confirmation expired. Nothing is deleted while
    /// the service stops.
    #[test]
    fn service_sweep_releases_an_expired_confirmation_and_skips_while_stopping() {
        use crate::telegram::types::{Chat, Message, User};
        let ctx = AppContext::for_tests();
        let tg = Arc::new(Deletes::default());
        let bot = Bot::new(ctx.clone(), tg.clone(), Arc::new(PowerOnly));
        let owner = User { id: 1000, is_bot: false, first_name: "O".into(), last_name: None, username: None };
        let chat = Chat { id: 1000, kind: "private".into(), title: None, username: None };
        let now = now_unix();
        let message = Message { message_id: 50, date: now, chat, from: Some(owner), text: Some("/shutdown".into()) };
        bot.handle_update(&Update {
            update_id: 1,
            message: Some(message),
            edited_message: None,
            callback_query: None,
            my_chat_member: None,
        });
        let dialog = 1; // the mock gives every sent message id 1
        assert!(ctx.janitor.is_protected(1000, dialog));
        let later = now + 3600;
        assert_eq!(sweep_service(&ctx, &bot, &*tg, later), 1);
        assert_eq!(*tg.calls.lock().unwrap(), vec![(1000, vec![50])], "the dialog can still be confirmed");
        bot.age_pending(Duration::from_secs(61));
        assert_eq!(sweep_service(&ctx, &bot, &*tg, later), 1);
        assert_eq!(tg.calls.lock().unwrap().last(), Some(&(1000, vec![dialog])));
        assert!(ctx.janitor.is_empty());
        // stopping: no request at all
        ctx.janitor.track(1000, 7, now, now);
        ctx.stop.stop();
        assert_eq!(sweep_service(&ctx, &bot, &*tg, later), 0);
        assert!(ctx.janitor.contains(1000, 7));
        assert_eq!(tg.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn error_actions() {
        assert_eq!(poll_error_action(&TgError::Unauthorized), ErrorAction::TokenInvalid);
        assert_eq!(poll_error_action(&TgError::RateLimited(7)), ErrorAction::Wait(Duration::from_secs(7)));
        assert_eq!(poll_error_action(&TgError::RateLimited(0)), ErrorAction::Wait(Duration::from_secs(1)));
        assert_eq!(poll_error_action(&TgError::Network("x".into())), ErrorAction::Backoff);
        assert_eq!(poll_error_action(&TgError::Conflict("x".into())), ErrorAction::Backoff);
        assert_eq!(poll_error_action(&TgError::Server(502, "x".into())), ErrorAction::Backoff);
    }
}
