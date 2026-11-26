//! Login history ring buffer (last N login/logout/failed/SSH events), persisted as JSON.
//!
//! Writes are coalesced: the first record after a quiet period is written at once, later ones
//! at most every [`PERSIST_INTERVAL`] (a password spray must not cost one fsync per attempt).
//! Pending changes are written by [`LoginHistory::flush_if_due`] (monitor thread) and
//! [`LoginHistory::flush`] (service stop). Entries recorded with an idempotency key (the
//! event-log record identity) are recorded once, even when the same event is replayed.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::EventDetails;

const DEFAULT_CAPACITY: usize = 50;
/// Minimum time between two writes of history.json while records keep arriving.
pub const PERSIST_INTERVAL: Duration = Duration::from_secs(5);

/// One stored entry. The details are flattened, so the file stays a plain array of
/// `EventDetails` objects (older files load unchanged; `key` is simply absent there).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Entry {
    #[serde(flatten)]
    details: EventDetails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

struct Inner {
    entries: VecDeque<Entry>,
    /// Entries changed since the last successful write.
    dirty: bool,
    /// Last write attempt (successful or not) — the coalescing clock.
    last_write: Option<Instant>,
    /// Last write error (logged once per distinct error).
    last_error: Option<String>,
}

pub struct LoginHistory {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
    capacity: usize,
}

impl LoginHistory {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let entries = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice::<VecDeque<Entry>>(&b).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
            Err(e) => return Err(e),
        };
        Ok(Self::with(Some(path.to_path_buf()), entries))
    }

    pub fn in_memory() -> Self {
        Self::with(None, VecDeque::new())
    }

    fn with(path: Option<PathBuf>, entries: VecDeque<Entry>) -> Self {
        let inner = Inner { entries, dirty: false, last_write: None, last_error: None };
        Self { path, inner: Mutex::new(inner), capacity: DEFAULT_CAPACITY }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record an event (oldest entries are evicted). Persistence errors are logged, not returned.
    pub fn record(&self, e: EventDetails) {
        self.record_keyed(e, None);
    }

    /// Record an event unless an entry with the same idempotency `key` is already stored (a
    /// replayed or retried event). Returns whether the event was recorded.
    pub fn record_keyed(&self, e: EventDetails, key: Option<&str>) -> bool {
        let mut g = self.lock();
        if let Some(k) = key
            && g.entries.iter().any(|x| x.key.as_deref() == Some(k))
        {
            return false;
        }
        g.entries.push_back(Entry { details: e, key: key.map(str::to_string) });
        while g.entries.len() > self.capacity {
            g.entries.pop_front();
        }
        g.dirty = true;
        if Self::write_due(&g, Instant::now()) {
            let _ = self.write_locked(&mut g); // logged inside; retried by flush_if_due/flush
        }
        true
    }

    fn write_due(g: &Inner, now: Instant) -> bool {
        g.last_write.is_none_or(|t| now.saturating_duration_since(t) >= PERSIST_INTERVAL)
    }

    /// Write the ring to disk (caller holds the lock). Errors are logged once per distinct error.
    fn write_locked(&self, g: &mut Inner) -> std::io::Result<()> {
        let Some(p) = &self.path else {
            g.dirty = false;
            return Ok(());
        };
        g.last_write = Some(Instant::now());
        let res = serde_json::to_vec(&g.entries)
            .map_err(std::io::Error::other)
            .and_then(|json| crate::paths::atomic_write(p, &json));
        match &res {
            Ok(()) => {
                g.dirty = false;
                g.last_error = None;
            }
            Err(err) => {
                let text = err.to_string();
                if g.last_error.as_deref() != Some(text.as_str()) {
                    crate::log_warn!("could not save login history: {text}");
                    g.last_error = Some(text);
                }
            }
        }
        res
    }

    /// Write pending changes now (service stop). No-op when nothing changed.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut g = self.lock();
        if !g.dirty {
            return Ok(());
        }
        self.write_locked(&mut g)
    }

    /// Write pending changes if the coalescing interval has passed. Returns whether a write
    /// was attempted.
    pub fn flush_if_due(&self) -> bool {
        let mut g = self.lock();
        if !g.dirty || !Self::write_due(&g, Instant::now()) {
            return false;
        }
        let _ = self.write_locked(&mut g); // logged inside
        true
    }

    /// Time until [`LoginHistory::flush_if_due`] will write pending changes; `None` when there
    /// is nothing to write.
    pub fn pending_flush_in(&self) -> Option<Duration> {
        let g = self.lock();
        if !g.dirty {
            return None;
        }
        Some(g.last_write.map_or(Duration::ZERO, |t| PERSIST_INTERVAL.saturating_sub(t.elapsed())))
    }

    /// Up to `n` most recent entries, newest first.
    pub fn recent(&self, n: usize) -> Vec<EventDetails> {
        self.lock().entries.iter().rev().take(n).map(|e| e.details.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::NotificationKind;

    fn temp_path(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("predator-hist-{tag}-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("history.json");
        (dir, p)
    }

    fn ev(user: &str, t: i64) -> EventDetails {
        EventDetails { user: user.into(), event_unix: t, kind: NotificationKind::FailedLogin, ..Default::default() }
    }

    fn stored(p: &Path) -> Vec<EventDetails> {
        let b = std::fs::read(p).unwrap();
        serde_json::from_slice::<Vec<EventDetails>>(&b).unwrap()
    }

    #[test]
    fn ring() {
        let h = LoginHistory::in_memory();
        for i in 0..60 {
            h.record(EventDetails { user: format!("u{i}"), event_unix: i, ..Default::default() });
        }
        assert_eq!(h.len(), DEFAULT_CAPACITY);
        let r = h.recent(3);
        assert_eq!(r[0].user, "u59");
        assert_eq!(r[2].user, "u57");
        assert_eq!(h.pending_flush_in(), None, "in-memory history never schedules writes");
    }

    #[test]
    fn keyed_records_are_idempotent() {
        let h = LoginHistory::in_memory();
        assert!(h.record_keyed(ev("a", 1), Some("security:7:100")));
        assert!(!h.record_keyed(ev("a", 1), Some("security:7:100")), "replay of the same record");
        assert!(h.record_keyed(ev("b", 2), Some("security:7:200")), "same record id after a log clear");
        assert!(h.record_keyed(ev("c", 3), None));
        assert!(h.record_keyed(ev("c", 3), None), "events without a key are always recorded");
        assert_eq!(h.len(), 4);
    }

    #[test]
    fn writes_are_coalesced_and_flushed() {
        let (dir, p) = temp_path("coalesce");
        let h = LoginHistory::open(&p).unwrap();
        h.record(ev("first", 1));
        assert_eq!(stored(&p).len(), 1, "first record after a quiet period is written at once");
        assert_eq!(h.pending_flush_in(), None);
        for i in 0..20 {
            h.record(ev("burst", 10 + i));
        }
        assert_eq!(stored(&p).len(), 1, "a burst is not written record by record");
        let wait = h.pending_flush_in().expect("pending write");
        assert!(wait <= PERSIST_INTERVAL);
        assert!(!h.flush_if_due(), "not due yet (written less than PERSIST_INTERVAL ago)");
        h.flush().unwrap();
        assert_eq!(stored(&p).len(), 21);
        assert_eq!(h.pending_flush_in(), None);
        h.flush().unwrap(); // nothing pending: no-op
        // keys survive a reopen, so a replay after a restart is still recognized
        h.record_keyed(ev("keyed", 99), Some("openssh:5:123"));
        h.flush().unwrap();
        let h2 = LoginHistory::open(&p).unwrap();
        assert_eq!(h2.len(), 22);
        assert!(!h2.record_keyed(ev("keyed", 99), Some("openssh:5:123")));
        assert_eq!(h2.recent(1)[0].user, "keyed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn old_file_format_loads() {
        let (dir, p) = temp_path("old");
        let old = vec![ev("legacy", 5)];
        std::fs::write(&p, serde_json::to_vec(&old).unwrap()).unwrap();
        let h = LoginHistory::open(&p).unwrap();
        assert_eq!(h.recent(5), old);
        std::fs::remove_dir_all(&dir).ok();
    }
}
