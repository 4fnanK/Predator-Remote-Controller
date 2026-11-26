//! Persistent settings (`settings.json`) with change notification.
//!
//! The bot token is NOT stored here — see [`crate::secrets`] (DPAPI).
//!
//! # Authorized Telegram users
//! `authorized_users` lists every Telegram account that may control the PC (at most
//! [`MAX_AUTHORIZED_USERS`]). Authorization is decided by the numeric Telegram user id only;
//! the stored name is for display. Admins may also remove other users from Telegram; the last
//! admin can never be removed, and the first user added to an empty list is always an admin.
//!
//! Files written before multi-user support hold a single `owner_telegram_id`. It is still read
//! and migrated on load (`[{id, name: "owner", role: admin}]` when the list is empty) but never
//! written again.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::features::{Feature, FeatureSet};

/// Upper bound of `authorized_users`.
pub const MAX_AUTHORIZED_USERS: usize = 20;
/// Longest stored display name (characters).
pub const MAX_USER_NAME_CHARS: usize = 64;
/// Name given to the account migrated from the legacy `owner_telegram_id`.
pub const LEGACY_OWNER_NAME: &str = "owner";
/// [`SettingsStore::remove_user`] refuses to remove the last admin with this message.
pub const LAST_ADMIN_ERROR: &str = "The last admin cannot be removed (pair another admin first).";

/// What an authorized Telegram user may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Everything a user can do, plus removing other users from the list.
    Admin,
    /// Every command and button (status, power, Tailscale, features ...).
    #[default]
    User,
}

impl UserRole {
    /// `Admin` / `User`.
    pub fn label(self) -> &'static str {
        match self {
            UserRole::Admin => "Admin",
            UserRole::User => "User",
        }
    }

    /// `admin` / `user` (the serialized form).
    pub fn key(self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }

    pub fn is_admin(self) -> bool {
        self == UserRole::Admin
    }
}

/// One Telegram account allowed to use the bot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedUser {
    /// Numeric Telegram user id — the ONLY identity used for authorization.
    pub id: i64,
    /// Display only: `@username` or the first name (sanitized, ≤ [`MAX_USER_NAME_CHARS`]).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub role: UserRole,
    /// When the account was added (Unix seconds; 0 = unknown, e.g. migrated from an old file).
    #[serde(default)]
    pub added_unix: i64,
}

impl AuthorizedUser {
    /// A user with a sanitized `name`.
    pub fn new(id: i64, name: &str, role: UserRole, added_unix: i64) -> Self {
        Self { id, name: clean_user_name(name), role, added_unix }
    }

    /// Display name of a Telegram account: `@username` when it has one, otherwise the first
    /// name (sanitized). Never used for authorization.
    pub fn display_name(username: Option<&str>, first_name: &str) -> String {
        match username.map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => clean_user_name(&format!("@{}", u.trim_start_matches('@'))),
            None => clean_user_name(first_name),
        }
    }

    /// The name for screens and log lines (`user 123456789` when no name is stored).
    pub fn label(&self) -> String {
        if self.name.trim().is_empty() { format!("user {}", self.id) } else { self.name.clone() }
    }
}

/// Bidirectional-text controls (LRM/RLM, embeddings, overrides, isolates, ALM). A display name
/// is chosen by the account itself; these could reorder how the rest of a line — the numeric id
/// in the user list, for example — is shown.
pub(crate) fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Control characters become spaces and bidirectional-text controls are removed; trimmed; at
/// most [`MAX_USER_NAME_CHARS`] characters.
pub fn clean_user_name(raw: &str) -> String {
    let cleaned: String =
        raw.chars().filter(|c| !is_bidi_control(*c)).map(|c| if c.is_control() { ' ' } else { c }).collect();
    crate::util::truncate_chars(cleaned.trim(), MAX_USER_NAME_CHARS)
}

/// Result of [`SettingsStore::add_user`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddUserOutcome {
    Added,
    /// The id was already in the list (nothing changed).
    AlreadyAuthorized,
    /// [`MAX_AUTHORIZED_USERS`] reached (nothing changed).
    LimitReached,
}

fn default_stale_secs() -> u64 {
    300
}
fn default_confirm_secs() -> u64 {
    60
}
fn default_version() -> u32 {
    1
}
fn default_true() -> bool {
    true
}
fn default_clean_after_secs() -> u64 {
    600
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    #[serde(default = "default_version")]
    pub version: u32,
    /// DEPRECATED (single-owner versions). Read from old files and migrated into
    /// `authorized_users`, never written to disk. In memory it mirrors
    /// [`Settings::primary_user_id`] so code written before multi-user support keeps working;
    /// assigning it inside [`SettingsStore::update`] keeps its old meaning ("the only authorized
    /// controller": `Some(id)` replaces the list with that admin — even when `id` is already the
    /// primary user — and `None` empties it), unless the same mutation also changes
    /// `authorized_users`. Inside an `update` closure it does not hold the mirror (see there).
    /// New code uses the user API instead.
    #[serde(default, skip_serializing)]
    pub owner_telegram_id: Option<i64>,
    /// Telegram accounts allowed to use the bot (empty = not paired yet: the bot then rejects
    /// everything except a pairing code).
    #[serde(default)]
    pub authorized_users: Vec<AuthorizedUser>,
    /// Windows SID allowed to control the service through the tray IPC pipe (besides SYSTEM and
    /// elevated administrators). Set by the installer to the interactive user.
    #[serde(default)]
    pub owner_windows_sid: Option<String>,
    /// Bot @username (filled from getMe), used for the tray "Open Dashboard" link.
    #[serde(default)]
    pub bot_username: Option<String>,
    #[serde(default)]
    pub features: FeatureSet,
    /// Simulate power, lock, logout and Tailscale up/down actions instead of executing them.
    /// Read at start.
    #[serde(default)]
    pub dry_run: bool,
    /// State-changing commands older than this (seconds) are ignored (e.g. queued while offline).
    #[serde(default = "default_stale_secs")]
    pub stale_command_secs: u64,
    /// Lifetime of a shutdown/restart/sleep/hibernate confirmation.
    #[serde(default = "default_confirm_secs")]
    pub confirm_timeout_secs: u64,
    /// Send "service online"/"going offline" lifecycle messages.
    #[serde(default = "default_true")]
    pub lifecycle_notifications: bool,
    /// Delete Vigil's short-lived chat messages automatically: menus, replies, the users'
    /// commands and system notices (online, offline, resumed ...). Login, logout, failed-login,
    /// SSH and security alerts are always kept. `false` = nothing is tracked or deleted.
    #[serde(default = "default_true")]
    pub auto_clean_chat: bool,
    /// Short-lived messages are deleted after this many seconds without use (60 s … 47 h; they
    /// also go as soon as the user sends the next command in that chat).
    #[serde(default = "default_clean_after_secs")]
    pub chat_clean_after_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: 1,
            owner_telegram_id: None,
            authorized_users: Vec::new(),
            owner_windows_sid: None,
            bot_username: None,
            features: FeatureSet::default(),
            dry_run: false,
            stale_command_secs: default_stale_secs(),
            confirm_timeout_secs: default_confirm_secs(),
            lifecycle_notifications: true,
            auto_clean_chat: true,
            chat_clean_after_secs: default_clean_after_secs(),
        }
    }
}

impl Settings {
    /// Whether `id` is an authorized Telegram user (ids ≤ 0 never are).
    pub fn is_authorized(&self, id: i64) -> bool {
        id > 0 && self.authorized_users.iter().any(|u| u.id == id)
    }

    pub fn user(&self, id: i64) -> Option<&AuthorizedUser> {
        self.authorized_users.iter().find(|u| u.id == id)
    }

    /// The first admin, else the first user (`None` = nobody is paired).
    pub fn primary_user_id(&self) -> Option<i64> {
        self.authorized_users.iter().find(|u| u.role.is_admin()).or_else(|| self.authorized_users.first()).map(|u| u.id)
    }

    pub fn admin_count(&self) -> usize {
        self.authorized_users.iter().filter(|u| u.role.is_admin()).count()
    }

    /// For settings as they were read (a file, or a value built by code): migrate the legacy
    /// `owner_telegram_id` (only into an empty list), then [`clean`](Self::clean). Applied to
    /// everything read from disk and to [`SettingsStore::in_memory`].
    pub fn normalize(&mut self) {
        if self.authorized_users.is_empty()
            && let Some(id) = self.owner_telegram_id.filter(|id| *id > 0)
        {
            self.authorized_users.push(AuthorizedUser {
                id,
                name: LEGACY_OWNER_NAME.into(),
                role: UserRole::Admin,
                added_unix: 0,
            });
        }
        self.clean();
    }

    /// Clean the user list (ids > 0, no duplicates, sanitized names, at most
    /// [`MAX_AUTHORIZED_USERS`]) and refresh the in-memory `owner_telegram_id` mirror. Applied
    /// after every mutation (which must never re-run the migration: emptying the list really
    /// empties it).
    pub fn clean(&mut self) {
        let mut seen: Vec<i64> = Vec::with_capacity(self.authorized_users.len());
        self.authorized_users.retain(|u| {
            let keep = u.id > 0 && !seen.contains(&u.id);
            if keep {
                seen.push(u.id);
            }
            keep
        });
        self.authorized_users.truncate(MAX_AUTHORIZED_USERS);
        for u in &mut self.authorized_users {
            let clean = clean_user_name(&u.name);
            if clean != u.name {
                u.name = clean;
            }
        }
        self.owner_telegram_id = self.primary_user_id();
    }

    /// A mutation assigned the deprecated `owner_telegram_id` (code written for the single-owner
    /// versions): keep the meaning it always had — the only authorized controller.
    fn apply_legacy_owner_write(&mut self, owner: Option<i64>) {
        match owner.filter(|id| *id > 0) {
            Some(id) => {
                let kept = self.user(id).cloned();
                self.authorized_users = vec![AuthorizedUser {
                    id,
                    name: kept.as_ref().map(|u| u.name.clone()).unwrap_or_else(|| LEGACY_OWNER_NAME.into()),
                    role: UserRole::Admin,
                    added_unix: kept.map(|u| u.added_unix).unwrap_or(0),
                }];
            }
            None => self.authorized_users.clear(),
        }
    }
}

/// What the deprecated `owner_telegram_id` holds while a [`SettingsStore::update`] closure runs:
/// the mirror negated (never a valid Telegram id, but `is_some()` still means "someone is
/// paired"), so that assigning ANY value — the primary user's own id included — is detected as a
/// legacy single-owner write.
fn legacy_owner_marker(mirror: Option<i64>) -> Option<i64> {
    mirror.filter(|id| *id > 0).map(|id| -id)
}

type Listener = Box<dyn Fn(&Settings) + Send + Sync>;

/// Identity of the on-disk file at the time the in-memory copy was last synchronised with it.
///
/// `atomic_write` always renames a freshly written file over `settings.json`, so the NTFS file id
/// changes with every write (by this process or by the CLI); size and last-write time are
/// compared as well for writers that edit the file in place (e.g. a text editor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DiskStamp {
    volume: u32,
    file_index: u64,
    size: u64,
    modified: u64,
}

/// Cheap metadata check (no read of the content). `Ok(None)` when the file does not exist.
fn disk_stamp(path: &Path) -> std::io::Result<Option<DiskStamp>> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    };
    let file = match std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: valid open file handle (owned by `file` for the whole call); `info` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some(DiskStamp {
        volume: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    }))
}

/// Read and parse `path` (normalized, see [`Settings::normalize`]). `Ok(None)` when it does not
/// exist; a parse error is `InvalidData`.
fn read_settings(path: &Path) -> std::io::Result<Option<Settings>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Settings>(&bytes)
            .map(|mut s| {
                s.normalize();
                Some(s)
            })
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{} is not valid: {e}", path.display()))
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

struct Inner {
    settings: Settings,
    /// Stamp of the file when `settings` was last loaded from / written to it.
    synced: Option<DiskStamp>,
}

/// Thread-safe settings holder. Every successful mutation is persisted atomically and then
/// broadcast to listeners (monitors use this to start/stop subscriptions immediately).
///
/// Several processes may write `settings.json` (the service and the elevated CLI). Before a
/// mutation is applied, the file's identity is compared with the one last seen; when another
/// process replaced it, the file is re-read first, so a stale in-memory copy can never overwrite
/// a change made elsewhere (e.g. `set-owner` revoking a compromised Telegram account).
pub struct SettingsStore {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
    listeners: Mutex<Vec<Listener>>,
}

impl SettingsStore {
    /// Load from `path`; a missing file yields defaults (not written until first change).
    /// A corrupt file is renamed to `settings.json.corrupt` and defaults are used.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let synced = disk_stamp(path).unwrap_or(None);
        let settings = match read_settings(path) {
            Ok(Some(s)) => s,
            Ok(None) => Settings::default(),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                crate::log_error!("settings.json is corrupt ({e}); using defaults");
                let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                Settings::default()
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            path: Some(path.to_path_buf()),
            inner: Mutex::new(Inner { settings, synced }),
            listeners: Mutex::new(Vec::new()),
        })
    }

    /// Non-persistent store (tests, dry runs). `s` is normalized (a legacy `owner_telegram_id`
    /// becomes the only admin).
    pub fn in_memory(mut s: Settings) -> Self {
        s.normalize();
        Self { path: None, inner: Mutex::new(Inner { settings: s, synced: None }), listeners: Mutex::new(Vec::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Snapshot of the current settings.
    pub fn get(&self) -> Settings {
        self.lock().settings.clone()
    }

    pub fn feature(&self, f: Feature) -> bool {
        self.lock().settings.features.is_enabled(f)
    }

    /// Every authorized Telegram user (primary admin first is not guaranteed: list order).
    pub fn authorized_users(&self) -> Vec<AuthorizedUser> {
        self.lock().settings.authorized_users.clone()
    }

    /// Whether `id` (a numeric Telegram user id) may use the bot.
    pub fn is_authorized(&self, id: i64) -> bool {
        self.lock().settings.is_authorized(id)
    }

    pub fn user(&self, id: i64) -> Option<AuthorizedUser> {
        self.lock().settings.user(id).cloned()
    }

    /// The first admin, else the first user (`None` = nobody is paired).
    pub fn primary_user_id(&self) -> Option<i64> {
        self.lock().settings.primary_user_id()
    }

    /// DEPRECATED alias of [`SettingsStore::primary_user_id`] (single-owner API).
    pub fn owner_id(&self) -> Option<i64> {
        self.primary_user_id()
    }

    /// Authorize another Telegram account (persisted + announced like [`SettingsStore::update`]).
    /// The name is sanitized; the first user of an empty list always becomes an admin (someone
    /// must be able to manage the list). `Err` = invalid id or settings.json could not be written.
    pub fn add_user(&self, u: AuthorizedUser) -> Result<AddUserOutcome, String> {
        if u.id <= 0 {
            return Err(format!("{} is not a valid Telegram user id", u.id));
        }
        let mut outcome = AddUserOutcome::Added;
        self.update(|s| {
            if s.is_authorized(u.id) {
                outcome = AddUserOutcome::AlreadyAuthorized;
                return;
            }
            if s.authorized_users.len() >= MAX_AUTHORIZED_USERS {
                outcome = AddUserOutcome::LimitReached;
                return;
            }
            let mut u = u;
            u.name = clean_user_name(&u.name);
            if s.authorized_users.is_empty() {
                u.role = UserRole::Admin;
            }
            s.authorized_users.push(u);
        })
        .map_err(|e| format!("cannot save settings.json: {e}"))?;
        Ok(outcome)
    }

    /// Revoke a Telegram account (persisted + announced). Refuses to remove the last admin
    /// ([`LAST_ADMIN_ERROR`]) and unknown ids. Returns the removed entry.
    pub fn remove_user(&self, id: i64) -> Result<AuthorizedUser, String> {
        let mut result = Err(format!("Telegram user {id} is not authorized."));
        self.update(|s| {
            let Some(pos) = s.authorized_users.iter().position(|u| u.id == id) else { return };
            if s.authorized_users[pos].role.is_admin() && s.admin_count() <= 1 {
                result = Err(LAST_ADMIN_ERROR.to_string());
                return;
            }
            result = Ok(s.authorized_users.remove(pos));
        })
        .map_err(|e| format!("cannot save settings.json: {e}"))?;
        result
    }

    fn notify(&self, snapshot: &Settings) {
        for l in self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            l(snapshot);
        }
    }

    /// Under the lock: when the file was replaced or edited since the last sync, re-read it into
    /// `g`. Returns whether the in-memory settings changed. A missing file keeps the in-memory
    /// copy (the next write recreates it); an unreadable or invalid file is an error and the
    /// in-memory copy is left untouched.
    fn refresh_locked(path: &Path, g: &mut Inner, force: bool) -> std::io::Result<bool> {
        let stamp = disk_stamp(path)?;
        if !force && stamp == g.synced {
            return Ok(false);
        }
        let Some(disk) = read_settings(path)? else {
            g.synced = None;
            return Ok(false);
        };
        // Re-stamp after reading: a write that raced with the read is detected next time.
        g.synced = stamp;
        if disk == g.settings {
            return Ok(false);
        }
        g.settings = disk;
        Ok(true)
    }

    /// Re-read `settings.json` and replace the in-memory copy when it differs (notifying the
    /// listeners). Returns whether anything changed. Used by the service when the CLI edited the
    /// file (`IpcRequest::ReloadSettings`). A missing file changes nothing.
    pub fn reload_from_disk(&self) -> std::io::Result<bool> {
        let Some(p) = &self.path else { return Ok(false) };
        let snapshot = {
            let mut g = self.lock();
            if !Self::refresh_locked(p, &mut g, true)? {
                return Ok(false);
            }
            g.settings.clone()
        };
        self.notify(&snapshot);
        Ok(true)
    }

    /// Enable/disable a feature. Returns whether it changed. Persists + notifies on change.
    pub fn set_feature(&self, f: Feature, on: bool) -> std::io::Result<bool> {
        let mut changed = false;
        self.update(|s| changed = s.features.set(f, on))?;
        Ok(changed)
    }

    /// Flip a feature; returns its new state.
    pub fn toggle_feature(&self, f: Feature) -> std::io::Result<bool> {
        let mut v = false;
        self.update(|s| v = s.features.toggle(f))?;
        Ok(v)
    }

    /// Write `g.settings` to `p` and remember the new file identity.
    fn write_locked(p: &Path, g: &mut Inner) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(&g.settings).map_err(std::io::Error::other)?;
        crate::paths::atomic_write(p, &json)?;
        g.synced = disk_stamp(p).unwrap_or(None);
        Ok(())
    }

    /// Apply an arbitrary mutation, persist it, notify listeners. If persisting fails the
    /// in-memory value is rolled back so memory and disk never disagree.
    ///
    /// When another process changed `settings.json` since it was last read, the file is re-read
    /// first and the mutation is applied on top of it (if the changed file cannot be read or is
    /// invalid, the update fails rather than overwrite it).
    ///
    /// The result is cleaned ([`Settings::clean`]); a mutation that assigns the deprecated
    /// `owner_telegram_id` keeps its single-owner meaning (see the field) — also when it assigns
    /// the id of the current primary user (e.g. `set-owner` revoking everyone else). Inside `f`
    /// that field holds a marker (`Some(negative)` while someone is paired, `None` otherwise),
    /// so read [`Settings::primary_user_id`] there instead. A mutation that changes
    /// `authorized_users` itself always wins over the deprecated field. `f` works on a copy: if
    /// it panics, nothing changes.
    pub fn update(&self, f: impl FnOnce(&mut Settings)) -> std::io::Result<()> {
        let snapshot = {
            let mut g = self.lock();
            let refreshed = match &self.path {
                Some(p) => Self::refresh_locked(p, &mut g, false)?,
                None => false,
            };
            let before = g.settings.clone();
            let mut next = before.clone();
            let marker = legacy_owner_marker(before.owner_telegram_id);
            next.owner_telegram_id = marker;
            f(&mut next);
            if next.owner_telegram_id != marker && next.authorized_users == before.authorized_users {
                let owner = next.owner_telegram_id;
                next.apply_legacy_owner_write(owner);
            }
            next.clean();
            g.settings = next;
            if g.settings != before {
                if let Some(p) = &self.path
                    && let Err(e) = Self::write_locked(p, &mut g)
                {
                    g.settings = before;
                    if refreshed {
                        // Memory still reflects the newer file: tell the listeners.
                        let s = g.settings.clone();
                        drop(g);
                        self.notify(&s);
                    }
                    return Err(e);
                }
            } else if !refreshed {
                return Ok(());
            }
            g.settings.clone()
        };
        self.notify(&snapshot);
        Ok(())
    }

    /// Force-write the current settings to disk (used by the installer/CLI). A newer file
    /// written by another process is merged in first (see [`SettingsStore::update`]).
    pub fn save(&self) -> std::io::Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let snapshot = {
            let mut g = self.lock();
            let refreshed = Self::refresh_locked(p, &mut g, false)?;
            Self::write_locked(p, &mut g)?;
            refreshed.then(|| g.settings.clone())
        };
        if let Some(s) = snapshot {
            self.notify(&s);
        }
        Ok(())
    }

    /// Register a change listener. Listeners run synchronously on the mutating thread and must
    /// be fast (typically: set a Win32 event / notify a Signal).
    pub fn on_change(&self, l: impl Fn(&Settings) + Send + Sync + 'static) {
        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).push(Box::new(l));
    }
}

/// Shared handle type.
pub type SharedSettings = Arc<SettingsStore>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn admin(id: i64, name: &str) -> AuthorizedUser {
        AuthorizedUser::new(id, name, UserRole::Admin, 1_800_000_000)
    }

    fn member(id: i64, name: &str) -> AuthorizedUser {
        AuthorizedUser::new(id, name, UserRole::User, 1_800_000_000)
    }

    fn ids(s: &SettingsStore) -> Vec<i64> {
        s.authorized_users().iter().map(|u| u.id).collect()
    }

    #[test]
    fn persist_and_notify() {
        let dir = std::env::temp_dir().join(format!("predator-cfg-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json");
        let store = SettingsStore::load(&p).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        store.on_change(move |_| {
            h2.fetch_add(1, Ordering::SeqCst);
        });
        assert!(store.set_feature(Feature::SshMonitoring, false).unwrap());
        assert!(!store.set_feature(Feature::SshMonitoring, false).unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(store.add_user(admin(42, "alice")).unwrap(), AddUserOutcome::Added);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let again = SettingsStore::load(&p).unwrap();
        assert!(!again.feature(Feature::SshMonitoring));
        assert_eq!(again.primary_user_id(), Some(42));
        assert_eq!(again.owner_id(), Some(42), "deprecated alias");
        assert_eq!(again.user(42).unwrap().name, "alice");
        // the legacy field is never written again
        let json = std::fs::read_to_string(&p).unwrap();
        assert!(!json.contains("owner_telegram_id"), "{json}");
        assert!(json.contains("\"authorized_users\""), "{json}");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn temp_settings(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("predator-cfg-{tag}-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json");
        (dir, p)
    }

    /// Files written by the single-owner versions: the owner becomes the only admin, and the
    /// legacy field disappears from the file at the next write.
    #[test]
    fn migration_from_owner_telegram_id() {
        let (dir, p) = temp_settings("migrate");
        std::fs::write(&p, br#"{"version":1,"owner_telegram_id":123456789,"bot_username":"ExampleBot"}"#).unwrap();
        let store = SettingsStore::load(&p).unwrap();
        let users = store.authorized_users();
        assert_eq!(
            users,
            vec![AuthorizedUser { id: 123456789, name: "owner".into(), role: UserRole::Admin, added_unix: 0 }]
        );
        assert!(store.is_authorized(123456789));
        assert_eq!(store.primary_user_id(), Some(123456789));
        // nothing is written just by loading
        assert!(std::fs::read_to_string(&p).unwrap().contains("owner_telegram_id"));
        store.set_feature(Feature::SshMonitoring, false).unwrap();
        let json = std::fs::read_to_string(&p).unwrap();
        assert!(!json.contains("owner_telegram_id"), "{json}");
        let reloaded = SettingsStore::load(&p).unwrap();
        assert_eq!(reloaded.authorized_users(), users);
        assert_eq!(reloaded.get().bot_username.as_deref(), Some("ExampleBot"));

        // a list that already exists wins over a stale legacy value
        std::fs::write(
            &p,
            br#"{"owner_telegram_id":5,"authorized_users":[{"id":7,"name":"bob"},{"id":8,"name":"carol","role":"admin"}]}"#,
        )
        .unwrap();
        let s = SettingsStore::load(&p).unwrap();
        assert_eq!(ids(&s), vec![7, 8]);
        assert!(!s.is_authorized(5));
        assert_eq!(s.user(7).unwrap().role, UserRole::User, "role defaults to user");
        assert_eq!(s.primary_user_id(), Some(8), "the first admin is the primary user");
        // invalid legacy ids are not migrated
        let raw: Settings = serde_json::from_str(r#"{"owner_telegram_id": -4}"#).unwrap();
        let s = SettingsStore::in_memory(raw);
        assert!(s.authorized_users().is_empty());
        assert_eq!(s.primary_user_id(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn normalize_cleans_the_list() {
        let mut s = Settings {
            authorized_users: vec![
                member(0, "zero"),
                member(-5, "negative"),
                member(10, "first\r\nline"),
                admin(10, "duplicate"),
                member(11, &"x".repeat(200)),
            ],
            ..Settings::default()
        };
        for i in 0..30 {
            s.authorized_users.push(member(100 + i, "more"));
        }
        s.normalize();
        assert_eq!(s.authorized_users.len(), MAX_AUTHORIZED_USERS);
        assert_eq!(s.authorized_users[0].id, 10);
        assert_eq!(s.authorized_users[0].name, "first  line");
        assert_eq!(s.authorized_users[0].role, UserRole::User, "the first entry of an id wins");
        assert_eq!(s.authorized_users[1].name.chars().count(), MAX_USER_NAME_CHARS);
        assert_eq!(s.owner_telegram_id, Some(10), "mirror of the primary user (no admin: first user)");
        assert!(!s.is_authorized(0) && !s.is_authorized(-5));
    }

    #[test]
    fn add_remove_last_admin_and_limit() {
        let store = SettingsStore::in_memory(Settings::default());
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        store.on_change(move |_| {
            h2.fetch_add(1, Ordering::SeqCst);
        });
        // the first user of an empty list is always an admin
        assert_eq!(store.add_user(member(1001, "alice")).unwrap(), AddUserOutcome::Added);
        assert_eq!(store.user(1001).unwrap().role, UserRole::Admin);
        assert_eq!(store.add_user(member(1002, "bob")).unwrap(), AddUserOutcome::Added);
        assert_eq!(store.user(1002).unwrap().role, UserRole::User);
        assert_eq!(store.add_user(admin(1002, "bob again")).unwrap(), AddUserOutcome::AlreadyAuthorized);
        assert_eq!(store.user(1002).unwrap().name, "bob", "unchanged");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "no-ops are not announced");
        assert!(store.add_user(member(0, "x")).is_err());
        assert!(store.add_user(member(-1, "x")).is_err());
        assert!(store.is_authorized(1001) && store.is_authorized(1002) && !store.is_authorized(1003));

        // the last admin stays
        assert_eq!(store.remove_user(1001).unwrap_err(), LAST_ADMIN_ERROR);
        assert!(store.is_authorized(1001));
        assert!(store.remove_user(4242).unwrap_err().contains("not authorized"));
        let removed = store.remove_user(1002).unwrap();
        assert_eq!(removed.name, "bob");
        assert!(!store.is_authorized(1002), "revoked at once");
        // with a second admin the first one can go
        store.add_user(admin(1003, "carol")).unwrap();
        assert_eq!(store.remove_user(1001).unwrap().id, 1001);
        assert_eq!(store.primary_user_id(), Some(1003));
        assert_eq!(store.remove_user(1003).unwrap_err(), LAST_ADMIN_ERROR);

        // limit
        for i in 0..(MAX_AUTHORIZED_USERS as i64 - 1) {
            assert_eq!(store.add_user(member(2000 + i, "u")).unwrap(), AddUserOutcome::Added);
        }
        assert_eq!(store.authorized_users().len(), MAX_AUTHORIZED_USERS);
        assert_eq!(store.add_user(member(9999, "late")).unwrap(), AddUserOutcome::LimitReached);
        assert!(!store.is_authorized(9999));
        // names are sanitized on the way in
        store.remove_user(2000).unwrap();
        store.add_user(member(3000, "\u{7}evil\nname")).unwrap();
        assert_eq!(store.user(3000).unwrap().name, "evil name");
    }

    #[test]
    fn user_names() {
        assert_eq!(AuthorizedUser::display_name(Some("alice"), "Alice"), "@alice");
        assert_eq!(AuthorizedUser::display_name(Some("@alice"), "Alice"), "@alice");
        assert_eq!(AuthorizedUser::display_name(Some("  "), "Alice\tB"), "Alice B");
        assert_eq!(AuthorizedUser::display_name(None, ""), "");
        assert_eq!(AuthorizedUser::new(5, "", UserRole::User, 0).label(), "user 5");
        assert_eq!(AuthorizedUser::new(5, "bob", UserRole::User, 0).label(), "bob");
        // bidirectional overrides/isolates cannot reorder the rest of a line
        assert_eq!(clean_user_name("\u{202E}nimda\u{202C} x"), "nimda x");
        assert_eq!(AuthorizedUser::display_name(None, "\u{2067}eve\u{2069}\u{200F}"), "eve");
        assert_eq!(clean_user_name("\u{202E}"), "");
        assert_eq!(clean_user_name("Zoë 李"), "Zoë 李", "ordinary letters are kept");
        assert_eq!(UserRole::Admin.label(), "Admin");
        assert_eq!(UserRole::User.key(), "user");
        assert_eq!(serde_json::to_string(&UserRole::Admin).unwrap(), "\"admin\"");
    }

    /// Code written for the single-owner versions still behaves as before: assigning
    /// `owner_telegram_id` makes that account the only (admin) user.
    #[test]
    fn legacy_owner_writes_keep_their_meaning() {
        let store = SettingsStore::in_memory(Settings::default());
        store.add_user(admin(1, "alice")).unwrap();
        store.add_user(member(2, "bob")).unwrap();
        assert_eq!(store.get().owner_telegram_id, Some(1), "mirror");
        store.update(|s| s.owner_telegram_id = Some(2)).unwrap();
        assert_eq!(store.authorized_users(), vec![AuthorizedUser { role: UserRole::Admin, ..member(2, "bob") }]);
        store.update(|s| s.owner_telegram_id = Some(77)).unwrap();
        assert_eq!(ids(&store), vec![77]);
        assert_eq!(store.user(77).unwrap().name, LEGACY_OWNER_NAME);
        store.update(|s| s.owner_telegram_id = None).unwrap();
        assert!(store.authorized_users().is_empty());
        // ordinary updates leave the list alone
        store.add_user(admin(5, "carol")).unwrap();
        store.update(|s| s.dry_run = true).unwrap();
        assert_eq!(ids(&store), vec![5]);
        // emptying the list through the new API never re-runs the migration from the mirror
        store.update(|s| s.authorized_users.clear()).unwrap();
        assert!(store.authorized_users().is_empty());
        assert_eq!(store.get().owner_telegram_id, None);
        assert_eq!(store.primary_user_id(), None);
    }

    /// `set-owner` is the documented way to revoke a compromised account: assigning the
    /// PRIMARY user's own id must still make it the only user (it used to be a silent no-op,
    /// because the in-memory mirror already held that value).
    #[test]
    fn legacy_owner_write_of_the_primary_revokes_everyone_else() {
        let store = SettingsStore::in_memory(Settings::default());
        store.add_user(admin(1, "alice")).unwrap();
        store.add_user(member(2, "mallory")).unwrap();
        store.add_user(admin(3, "carol")).unwrap();
        assert_eq!(store.primary_user_id(), Some(1));
        store.update(|s| s.owner_telegram_id = Some(1)).unwrap();
        assert_eq!(ids(&store), vec![1], "only the named account is left");
        assert_eq!(store.user(1).unwrap().role, UserRole::Admin);
        assert_eq!(store.user(1).unwrap().name, "alice", "its entry is kept");
        // None keeps meaning "nobody" when someone is paired
        store.update(|s| s.owner_telegram_id = None).unwrap();
        assert!(store.authorized_users().is_empty());
    }

    /// Inside `update` the deprecated field reads like the mirror for `is_some()` checks, and a
    /// closure that writes the list itself wins over the field (whole-struct assignments).
    #[test]
    fn legacy_field_inside_update_closures() {
        let store = SettingsStore::in_memory(Settings::default());
        store.update(|s| assert_eq!(s.owner_telegram_id, None)).unwrap();
        store.add_user(admin(1, "alice")).unwrap();
        store.add_user(member(2, "bob")).unwrap();
        store.update(|s| assert!(s.owner_telegram_id.is_some(), "someone is paired")).unwrap();
        assert_eq!(ids(&store), vec![1, 2], "reading it is not a write");
        // a freshly built value with its own list (field None): the list is used as given
        let fresh = Settings { authorized_users: vec![admin(7, "dave"), member(8, "erin")], ..Settings::default() };
        store.update(|s| *s = fresh.clone()).unwrap();
        assert_eq!(ids(&store), vec![7, 8]);
        assert_eq!(store.get().owner_telegram_id, Some(7), "mirror refreshed");
    }

    /// A panic inside the mutation leaves the settings exactly as they were.
    #[test]
    fn panicking_mutation_changes_nothing() {
        let store = SettingsStore::in_memory(Settings::default());
        store.add_user(admin(1, "alice")).unwrap();
        let before = store.get();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.update(|s| {
                s.authorized_users.clear();
                s.dry_run = true;
                panic!("boom");
            });
        }));
        assert!(r.is_err());
        assert_eq!(store.get(), before);
        assert!(store.is_authorized(1));
    }

    /// F04: a service-side write must not revert a change another process made to the file.
    #[test]
    fn stale_copy_never_overwrites_another_writer() {
        let (dir, p) = temp_settings("stale");
        let seed = SettingsStore::load(&p).unwrap();
        seed.add_user(admin(1111, "alice")).unwrap();
        seed.update(|s| s.owner_windows_sid = Some("S-1-5-21-1-2-3-1001".into())).unwrap();
        // the "service" loads its copy
        let service = SettingsStore::load(&p).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        service.on_change(move |s| {
            assert!(s.is_authorized(2222) && !s.is_authorized(1111));
            h2.fetch_add(1, Ordering::SeqCst);
        });
        // the "CLI" replaces the user and the tray SID (two separate writes)
        let cli = SettingsStore::load(&p).unwrap();
        cli.add_user(admin(2222, "bob")).unwrap();
        cli.remove_user(1111).unwrap();
        cli.save().unwrap();
        let cli2 = SettingsStore::load(&p).unwrap();
        cli2.update(|s| s.owner_windows_sid = Some("S-1-5-21-1-2-3-1002".into())).unwrap();
        // the service toggles a feature from its (stale) copy
        assert!(!service.toggle_feature(Feature::SshMonitoring).unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "listeners see the merged state once");
        let disk = SettingsStore::load(&p).unwrap();
        assert_eq!(ids(&disk), vec![2222]);
        assert_eq!(disk.get().owner_windows_sid.as_deref(), Some("S-1-5-21-1-2-3-1002"));
        assert!(!disk.feature(Feature::SshMonitoring));
        // and the service now uses the new user too
        assert!(service.is_authorized(2222) && !service.is_authorized(1111));
        assert_eq!(service.primary_user_id(), Some(2222));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A no-op mutation still picks up (and announces) a newer file.
    #[test]
    fn noop_update_refreshes_from_disk() {
        let (dir, p) = temp_settings("noop");
        let service = SettingsStore::load(&p).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        service.on_change(move |_| {
            h2.fetch_add(1, Ordering::SeqCst);
        });
        SettingsStore::load(&p).unwrap().add_user(admin(5, "alice")).unwrap();
        assert!(!service.set_feature(Feature::BatteryInfo, true).unwrap()); // already on: no write
        assert!(service.is_authorized(5));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // unchanged file: nothing re-read, nothing announced
        assert!(!service.set_feature(Feature::BatteryInfo, true).unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // a user added by another process is seen by add_user (no duplicate, no lost entry)
        SettingsStore::load(&p).unwrap().add_user(member(6, "bob")).unwrap();
        assert_eq!(service.add_user(member(6, "bob")).unwrap(), AddUserOutcome::AlreadyAuthorized);
        assert_eq!(ids(&service), vec![5, 6]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I3: explicit reload (IPC ReloadSettings).
    #[test]
    fn reload_from_disk_reports_changes() {
        let (dir, p) = temp_settings("reload");
        let service = SettingsStore::load(&p).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        service.on_change(move |_| {
            h2.fetch_add(1, Ordering::SeqCst);
        });
        // missing file: nothing to reload
        assert!(!service.reload_from_disk().unwrap());
        SettingsStore::load(&p).unwrap().add_user(admin(77, "alice")).unwrap();
        assert!(service.reload_from_disk().unwrap());
        assert_eq!(service.primary_user_id(), Some(77));
        assert!(!service.reload_from_disk().unwrap(), "same content: unchanged");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // an edit in place (same file id) with different content is detected as well
        let mut s = service.get();
        s.authorized_users = vec![admin(78, "bob")];
        std::fs::write(&p, serde_json::to_vec_pretty(&s).unwrap()).unwrap();
        assert!(service.reload_from_disk().unwrap());
        assert_eq!(service.primary_user_id(), Some(78));
        assert!(!service.is_authorized(77), "a user removed in the file loses access at the reload");
        // invalid file: error, in-memory copy kept, and updates refuse to overwrite it
        std::fs::write(&p, b"{ not json").unwrap();
        assert_eq!(service.reload_from_disk().unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(service.primary_user_id(), Some(78));
        assert!(service.set_feature(Feature::SshMonitoring, false).is_err());
        assert!(service.add_user(member(79, "x")).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"{ not json");
        // in-memory stores never touch the disk
        assert!(!SettingsStore::in_memory(Settings::default()).reload_from_disk().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_stamp_tracks_replacement() {
        let (dir, p) = temp_settings("stamp");
        assert_eq!(disk_stamp(&p).unwrap(), None);
        crate::paths::atomic_write(&p, b"{}").unwrap();
        let a = disk_stamp(&p).unwrap().unwrap();
        assert_eq!(disk_stamp(&p).unwrap(), Some(a));
        crate::paths::atomic_write(&p, b"{}").unwrap();
        let b = disk_stamp(&p).unwrap().unwrap();
        assert_ne!(a, b, "a replaced file has a new identity even with identical content");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tolerant_parse() {
        let mut s: Settings = serde_json::from_str(r#"{"owner_telegram_id": 7, "future_option": true}"#).unwrap();
        s.normalize();
        assert!(s.is_authorized(7));
        assert_eq!(s.confirm_timeout_secs, 60);
        assert!(s.features.is_enabled(Feature::PowerManagement));
    }

    #[test]
    fn chat_cleanup_settings() {
        // files written before the option existed: cleanup on, 10 minutes
        let s: Settings = serde_json::from_str(r#"{"owner_telegram_id": 7}"#).unwrap();
        assert!(s.auto_clean_chat);
        assert_eq!(s.chat_clean_after_secs, 600);
        let mut unpaired = s.clone();
        unpaired.owner_telegram_id = None;
        assert_eq!(Settings::default(), unpaired);
        let off: Settings =
            serde_json::from_str(r#"{"auto_clean_chat": false, "chat_clean_after_secs": 120}"#).unwrap();
        assert!(!off.auto_clean_chat);
        assert_eq!(off.chat_clean_after_secs, 120);
        // round trip
        let json = serde_json::to_string(&off).unwrap();
        assert!(json.contains("\"auto_clean_chat\":false") && json.contains("\"chat_clean_after_secs\":120"));
        assert_eq!(serde_json::from_str::<Settings>(&json).unwrap(), off);
    }
}
