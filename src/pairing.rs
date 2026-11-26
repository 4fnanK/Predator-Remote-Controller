//! One-time pairing codes that add Telegram accounts to `settings.authorized_users`.
//!
//! An administrator starts pairing on the PC (tray, CLI or setup menu): the service creates ONE
//! active 8-digit code ([`PairingSlot::start`]) that is shown locally only — it is never sent to
//! Telegram and never logged at INFO. The new account sends `/pair CODE` (or opens the deep link
//! `https://t.me/<bot>?start=pair-CODE`) and the bot redeems it ([`PairingSlot::redeem`]).
//!
//! Brute-force protection (a code has 10^8 values):
//! * a code is single use and expires after 60 … 3600 s;
//! * after [`MAX_WRONG_PER_CODE`] wrong guesses in total the code is invalidated;
//! * every Telegram user gets at most [`MAX_WRONG_PER_USER`] wrong guesses per hour across all
//!   codes; further attempts count as wrong without being compared (bounded table);
//! * the comparison is constant-time ([`ct_eq`]);
//! * input that is not a well-formed 8-digit code (a bare `/pair` from the command menu) cannot
//!   match, so it is refused without counting as a guess.
//!
//! The bot answers every failure with the same generic reply as any unauthorized message, so an
//! outsider cannot even learn whether a code is active. Codes live in memory only: a restart
//! cancels pairing.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use crate::config::{AuthorizedUser, UserRole};

/// Digits of a pairing code.
pub const CODE_DIGITS: usize = 8;
/// Shortest / longest lifetime of a code.
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 3600;
/// Wrong guesses (all users together) after which the active code is invalidated.
pub const MAX_WRONG_PER_CODE: u32 = 5;
/// Wrong guesses one Telegram user may make per [`USER_WINDOW_SECS`] (across codes).
pub const MAX_WRONG_PER_USER: u32 = 5;
pub const USER_WINDOW_SECS: i64 = 3600;
/// Upper bound of the per-user attempt table.
const MAX_TRACKED_USERS: usize = 256;
/// Longer inputs are not even normalized.
const MAX_INPUT_CHARS: usize = 64;
const MAX_CREATED_BY_CHARS: usize = 64;

/// The active code. `Debug` never prints the code itself.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    /// 8 digits.
    pub code: String,
    /// Role the redeeming account gets.
    pub role: UserRole,
    pub expires_unix: i64,
    /// Who started the pairing (account name on the PC), for log lines.
    pub created_by: String,
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCode")
            .field("code", &"<hidden>")
            .field("role", &self.role)
            .field("expires_unix", &self.expires_unix)
            .field("created_by", &self.created_by)
            .finish()
    }
}

impl PairingCode {
    /// `1234 5678` (easier to read and type; spaces are accepted when redeeming).
    pub fn display(&self) -> String {
        match (self.code.get(..4), self.code.get(4..)) {
            (Some(a), Some(b)) if !b.is_empty() => format!("{a} {b}"),
            _ => self.code.clone(),
        }
    }

    /// Payload of the deep link `https://t.me/<bot>?start=pair-12345678`.
    pub fn deep_link_payload(&self) -> String {
        format!("pair-{}", self.code)
    }
}

/// Why a redemption failed (for local logs only — the bot never tells the sender).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedeemError {
    NoActiveCode,
    Wrong,
    Expired,
    /// Invalidated after too many wrong guesses.
    Exhausted,
}

impl RedeemError {
    pub fn describe(self) -> &'static str {
        match self {
            RedeemError::NoActiveCode => "no pairing code is active",
            RedeemError::Wrong => "wrong code",
            RedeemError::Expired => "the code has expired",
            RedeemError::Exhausted => "the code was invalidated after too many wrong attempts",
        }
    }
}

/// What the tray / CLI may know about pairing (the code text is never part of it).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PairingStatus {
    /// A code can be redeemed right now.
    pub active: bool,
    pub expires_unix: Option<i64>,
    /// The account paired since the last [`PairingSlot::start`], with the pairing time.
    pub last_paired: Option<(AuthorizedUser, i64)>,
}

struct ActiveCode {
    code: PairingCode,
    wrong: u32,
    /// Too many wrong guesses: kept (inactive) until replaced, so later attempts say so in the log.
    exhausted: bool,
}

#[derive(Clone, Copy, Debug)]
struct UserAttempts {
    window_start: i64,
    wrong: u32,
}

impl UserAttempts {
    fn current(&self, now: i64) -> bool {
        now >= self.window_start && now - self.window_start < USER_WINDOW_SECS
    }
}

#[derive(Default)]
struct SlotState {
    active: Option<ActiveCode>,
    attempts: HashMap<i64, UserAttempts>,
    last_paired: Option<(AuthorizedUser, i64)>,
}

impl SlotState {
    /// The user used up their wrong guesses for the current hour.
    fn user_blocked(&self, user: i64, now: i64) -> bool {
        self.attempts.get(&user).is_some_and(|a| a.current(now) && a.wrong >= MAX_WRONG_PER_USER)
    }

    fn note_wrong(&mut self, user: i64, now: i64) {
        if let Some(a) = self.attempts.get_mut(&user) {
            if a.current(now) {
                a.wrong = a.wrong.saturating_add(1);
            } else {
                *a = UserAttempts { window_start: now, wrong: 1 };
            }
            return;
        }
        if self.attempts.len() >= MAX_TRACKED_USERS {
            self.attempts.retain(|_, a| a.current(now));
            if self.attempts.len() >= MAX_TRACKED_USERS
                && let Some(oldest) = self.attempts.iter().min_by_key(|(_, a)| a.window_start).map(|(k, _)| *k)
            {
                self.attempts.remove(&oldest);
            }
        }
        self.attempts.insert(user, UserAttempts { window_start: now, wrong: 1 });
    }
}

/// Constant-time equality of two byte strings (the length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The code inside a user's input: spaces and dashes are removed and a `pair-` / `pair_`
/// deep-link prefix is accepted (`1234 5678`, `1234-5678`, `pair-12345678`). `None` unless
/// exactly [`CODE_DIGITS`] digits remain.
pub fn normalize_code(input: &str) -> Option<String> {
    let s = input.trim();
    if s.chars().count() > MAX_INPUT_CHARS {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let rest = lower.strip_prefix("pair-").or_else(|| lower.strip_prefix("pair_")).unwrap_or(&lower);
    let digits: String = rest.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (digits.len() == CODE_DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// The single active pairing code of the service (thread-safe, in memory only).
pub struct PairingSlot {
    state: Mutex<SlotState>,
}

impl Default for PairingSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingSlot {
    pub fn new() -> Self {
        Self { state: Mutex::new(SlotState::default()) }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Create (replace) the single active code: 8 random digits, `ttl_secs` clamped to
    /// 60 … 3600 s. Clears the "last paired" result of an earlier code.
    pub fn start(&self, role: UserRole, ttl_secs: u64, created_by: &str, now_unix: i64) -> PairingCode {
        let ttl = ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let cleaned: String = created_by.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        let code = PairingCode {
            code: crate::util::rand::digits(CODE_DIGITS),
            role,
            expires_unix: now_unix.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX)),
            created_by: crate::util::truncate_chars(cleaned.trim(), MAX_CREATED_BY_CHARS),
        };
        let mut st = self.lock();
        st.active = Some(ActiveCode { code: code.clone(), wrong: 0, exhausted: false });
        st.last_paired = None;
        code
    }

    /// Forget the active code (if any).
    pub fn cancel(&self) {
        self.lock().active = None;
    }

    /// Try `input` (normalized, see [`normalize_code`]) for `telegram_user_id`. Success consumes
    /// the code and returns its role. Wrong guesses count against the code (invalidated after
    /// [`MAX_WRONG_PER_CODE`]) and the user ([`MAX_WRONG_PER_USER`] per hour; beyond that every
    /// attempt is `Wrong` without being compared). Input that is not a well-formed code is
    /// `Wrong` too but is not counted (it cannot match, so it is no guess).
    pub fn redeem(&self, input: &str, telegram_user_id: i64, now_unix: i64) -> Result<UserRole, RedeemError> {
        let mut st = self.lock();
        if st.user_blocked(telegram_user_id, now_unix) {
            return Err(RedeemError::Wrong);
        }
        let outcome = {
            let Some(active) = st.active.as_mut() else { return Err(RedeemError::NoActiveCode) };
            if active.exhausted {
                return Err(RedeemError::Exhausted);
            }
            if now_unix >= active.code.expires_unix {
                st.active = None;
                return Err(RedeemError::Expired);
            }
            // Not a well-formed code (e.g. a bare `/pair` sent from the command menu): it cannot
            // match, so it is no guess and costs neither the code nor the user an attempt.
            let Some(guess) = normalize_code(input) else { return Err(RedeemError::Wrong) };
            if ct_eq(guess.as_bytes(), active.code.code.as_bytes()) {
                Ok(active.code.role)
            } else {
                active.wrong = active.wrong.saturating_add(1);
                if active.wrong >= MAX_WRONG_PER_CODE {
                    active.exhausted = true;
                    Err(RedeemError::Exhausted)
                } else {
                    Err(RedeemError::Wrong)
                }
            }
        };
        match outcome {
            Ok(role) => {
                st.active = None; // single use
                Ok(role)
            }
            Err(e) => {
                st.note_wrong(telegram_user_id, now_unix);
                Err(e)
            }
        }
    }

    /// Whether a code can be redeemed now, its expiry, and the last successful pairing.
    pub fn status(&self, now_unix: i64) -> PairingStatus {
        let st = self.lock();
        let live = st.active.as_ref().filter(|a| !a.exhausted && now_unix < a.code.expires_unix);
        PairingStatus {
            active: live.is_some(),
            expires_unix: live.map(|a| a.code.expires_unix),
            last_paired: st.last_paired.clone(),
        }
    }

    /// The bot added `user` after a successful [`redeem`](Self::redeem) (time = `added_unix`,
    /// or now when unknown).
    pub fn record_paired(&self, user: AuthorizedUser) {
        let when = if user.added_unix > 0 { user.added_unix } else { crate::util::time::now_unix() };
        self.lock().last_paired = Some((user, when));
    }

    /// Number of users in the attempt table (tests of the bound).
    #[cfg(test)]
    fn tracked_users(&self) -> usize {
        self.lock().attempts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;
    const ALICE: i64 = 123_456_789;
    const MALLORY: i64 = 987_654_321;

    fn spaced(code: &str) -> String {
        format!("{} {}", &code[..4], &code[4..])
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize_code("12345678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("1234 5678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("  1234-5678 ").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("pair-12345678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("pair_12345678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("PAIR-1234-5678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code("1 2 3 4\t5 6 7 8").as_deref(), Some("12345678"));
        for bad in ["", "1234567", "123456789", "1234567a", "pair-", "pair 12345678", "１２３４５６７８", "12_345678"]
        {
            assert_eq!(normalize_code(bad), None, "{bad:?}");
        }
        assert_eq!(normalize_code(&format!("{}12345678", "-".repeat(70))), None, "overlong input");
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"12345678", b"12345678"));
        assert!(!ct_eq(b"12345678", b"12345679"));
        assert!(!ct_eq(b"12345678", b"02345678"));
        assert!(!ct_eq(b"1234567", b"12345678"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn code_shape_ttl_and_privacy() {
        let slot = PairingSlot::new();
        let c = slot.start(UserRole::User, 600, "PC\\alice", T0);
        assert_eq!(c.code.len(), CODE_DIGITS);
        assert!(c.code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(c.expires_unix, T0 + 600);
        assert_eq!(c.created_by, "PC\\alice");
        assert_eq!(c.display(), spaced(&c.code));
        assert_eq!(c.deep_link_payload(), format!("pair-{}", c.code));
        let debug = format!("{c:?}");
        assert!(!debug.contains(&c.code) && debug.contains("<hidden>"), "{debug}");
        // ttl is clamped
        assert_eq!(slot.start(UserRole::User, 5, "x", T0).expires_unix, T0 + MIN_TTL_SECS as i64);
        assert_eq!(slot.start(UserRole::User, 99_999, "x", T0).expires_unix, T0 + MAX_TTL_SECS as i64);
        // a new start replaces the old code
        let a = slot.start(UserRole::User, 600, "x", T0);
        let b = slot.start(UserRole::Admin, 600, "x", T0);
        if a.code != b.code {
            assert_eq!(slot.redeem(&a.code, ALICE, T0 + 1), Err(RedeemError::Wrong));
        }
        assert_eq!(slot.redeem(&b.code, ALICE, T0 + 1), Ok(UserRole::Admin));
    }

    #[test]
    fn every_accepted_form_redeems_once() {
        let forms: [fn(&str) -> String; 3] = [|c| c.to_string(), |c| spaced(c), |c| format!("{}-{}", &c[..4], &c[4..])];
        for form in forms {
            let slot = PairingSlot::new();
            let c = slot.start(UserRole::User, 600, "x", T0);
            assert_eq!(slot.redeem(&form(&c.code), ALICE, T0 + 10), Ok(UserRole::User));
            // single use
            assert_eq!(slot.redeem(&c.code, ALICE, T0 + 11), Err(RedeemError::NoActiveCode));
        }
        for prefix in ["pair-", "pair_"] {
            let slot = PairingSlot::new();
            let c = slot.start(UserRole::Admin, 600, "x", T0);
            assert_eq!(slot.redeem(&format!("{prefix}{}", c.code), ALICE, T0 + 10), Ok(UserRole::Admin));
        }
    }

    #[test]
    fn expiry() {
        let slot = PairingSlot::new();
        let c = slot.start(UserRole::User, 60, "x", T0);
        assert!(slot.status(T0 + 59).active);
        assert!(!slot.status(T0 + 60).active);
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 60), Err(RedeemError::Expired));
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 61), Err(RedeemError::NoActiveCode));
        // an expired attempt is not a wrong guess
        let c = slot.start(UserRole::User, 60, "x", T0 + 100);
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 101), Ok(UserRole::User));
    }

    #[test]
    fn five_wrong_attempts_invalidate_the_code() {
        let slot = PairingSlot::new();
        let c = slot.start(UserRole::User, 600, "x", T0);
        let wrong = if c.code == "00000000" { "11111111" } else { "00000000" };
        // spread over several users so the per-user limit is not what stops them
        for i in 0..(MAX_WRONG_PER_CODE - 1) {
            assert_eq!(slot.redeem(wrong, MALLORY + i64::from(i), T0 + 1), Err(RedeemError::Wrong));
            assert!(slot.status(T0 + 1).active);
        }
        assert_eq!(slot.redeem(wrong, MALLORY + 100, T0 + 2), Err(RedeemError::Exhausted));
        assert!(!slot.status(T0 + 2).active);
        // even the right code no longer works
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 3), Err(RedeemError::Exhausted));
        // a fresh code works again
        let c = slot.start(UserRole::User, 600, "x", T0 + 4);
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 5), Ok(UserRole::User));
    }

    /// Malformed input (a bare `/pair` from the command menu, words, too few digits) is refused
    /// like a wrong code but burns neither the code nor the sender's attempts.
    #[test]
    fn malformed_input_is_no_guess() {
        let slot = PairingSlot::new();
        let c = slot.start(UserRole::User, 600, "x", T0);
        for _ in 0..(MAX_WRONG_PER_CODE * 4) {
            for bad in ["", "let me in", "1234", "pair-", "123456789"] {
                assert_eq!(slot.redeem(bad, ALICE, T0 + 1), Err(RedeemError::Wrong), "{bad:?}");
            }
        }
        assert!(slot.status(T0 + 1).active, "the code is not burnt");
        assert_eq!(slot.tracked_users(), 0, "the sender is not counted");
        assert_eq!(slot.redeem(&spaced(&c.code), ALICE, T0 + 2), Ok(UserRole::User));
        // without an active code malformed input is simply "no code"
        assert_eq!(slot.redeem("junk", ALICE, T0 + 3), Err(RedeemError::NoActiveCode));
    }

    #[test]
    fn per_user_rate_limit_across_codes() {
        let slot = PairingSlot::new();
        let mut wrong_total = 0;
        // two codes, the same user guesses wrong on both
        for round in 0..2 {
            let c = slot.start(UserRole::User, 3600, "x", T0 + round);
            let wrong = if c.code == "00000000" { "11111111" } else { "00000000" };
            for _ in 0..3 {
                if wrong_total < MAX_WRONG_PER_USER {
                    let r = slot.redeem(wrong, MALLORY, T0 + 10);
                    assert!(matches!(r, Err(RedeemError::Wrong)), "{r:?}");
                    wrong_total += 1;
                }
            }
        }
        assert_eq!(wrong_total, MAX_WRONG_PER_USER);
        let c = slot.start(UserRole::User, 3600, "x", T0 + 20);
        // blocked: even the right code counts as wrong, and the code itself is not touched
        for _ in 0..10 {
            assert_eq!(slot.redeem(&c.code, MALLORY, T0 + 30), Err(RedeemError::Wrong));
        }
        assert!(slot.status(T0 + 30).active, "a blocked user cannot burn the code");
        // other users are not affected
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 31), Ok(UserRole::User));
        // an hour later the user may try again
        let later = T0 + 10 + USER_WINDOW_SECS;
        let c = slot.start(UserRole::User, 3600, "x", later);
        assert_eq!(slot.redeem(&c.code, MALLORY, later + 1), Ok(UserRole::User));
    }

    #[test]
    fn attempt_table_is_bounded() {
        let slot = PairingSlot::new();
        for i in 0..2000 {
            let c = slot.start(UserRole::User, 600, "x", T0);
            let wrong = if c.code == "00000000" { "11111111" } else { "00000000" };
            let _ = slot.redeem(wrong, 1 + i, T0 + 1);
        }
        assert!(slot.tracked_users() <= MAX_TRACKED_USERS);
    }

    #[test]
    fn no_active_code_and_cancel() {
        let slot = PairingSlot::new();
        assert_eq!(slot.redeem("12345678", ALICE, T0), Err(RedeemError::NoActiveCode));
        assert_eq!(slot.status(T0), PairingStatus::default());
        let c = slot.start(UserRole::User, 600, "x", T0);
        let st = slot.status(T0);
        assert!(st.active);
        assert_eq!(st.expires_unix, Some(T0 + 600));
        slot.cancel();
        assert!(!slot.status(T0).active);
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 1), Err(RedeemError::NoActiveCode));
        // no-code attempts are not wrong guesses: the user is not blocked by them
        for _ in 0..20 {
            assert_eq!(slot.redeem("12345678", ALICE, T0 + 2), Err(RedeemError::NoActiveCode));
        }
        let c = slot.start(UserRole::User, 600, "x", T0 + 3);
        assert_eq!(slot.redeem(&c.code, ALICE, T0 + 4), Ok(UserRole::User));
        for e in [RedeemError::NoActiveCode, RedeemError::Wrong, RedeemError::Expired, RedeemError::Exhausted] {
            assert!(!e.describe().is_empty());
        }
    }

    #[test]
    fn last_paired_is_reported_until_the_next_start() {
        let slot = PairingSlot::new();
        slot.start(UserRole::User, 600, "x", T0);
        let alice = AuthorizedUser::new(ALICE, "@alice", UserRole::User, T0 + 5);
        slot.record_paired(alice.clone());
        assert_eq!(slot.status(T0 + 6).last_paired, Some((alice, T0 + 5)));
        slot.start(UserRole::User, 600, "x", T0 + 10);
        assert_eq!(slot.status(T0 + 11).last_paired, None);
        let unknown_time = AuthorizedUser::new(MALLORY, "bob", UserRole::User, 0);
        slot.record_paired(unknown_time);
        assert!(slot.status(T0).last_paired.unwrap().1 > 0);
    }
}
