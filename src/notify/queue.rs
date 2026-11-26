//! Persistent FIFO of outgoing notifications.
//!
//! * **Pushes are synchronous and durable**: every push is written to disk (atomic replace)
//!   *before* it returns, i.e. before the caller advances its event-log bookmark, so a crash or
//!   power loss can never lose a login alert.
//! * **Acks are coalesced**: delivering an item removes it in memory at once (and remembers its
//!   dedupe key in memory at once), but the file is rewritten at most every [`ACK_WRITE_INTERVAL`]
//!   — immediately when the queue becomes empty, with the next push, or on [`flush`]
//!   (the sender flushes before it goes idle or waits, the runtime flushes on stop). Draining an
//!   offline backlog of N items therefore costs about one write per 2 s instead of N full
//!   rewrites + fsyncs (which was O(N²) bytes).
//!
//!   Consequence (still at-least-once): after a crash or power loss, items whose ack had not
//!   reached the disk yet may be delivered a second time after the restart — those acked less
//!   than [`ACK_WRITE_INTERVAL`] after the previous write, until the next write (the next due ack,
//!   push or flush; while the sender is busy that can be one request later). Their dedupe keys
//!   are only in memory until then. Nothing is ever lost: pushes are never deferred.
//! * **Per-recipient progress** ([`mark_delivered`]) is recorded in the item's `delivered_to`
//!   and written like an ack (coalesced), so a notification that reached some users before an
//!   outage or a restart is later delivered only to the others (at-least-once per recipient).
//!
//! Notifications survive service restarts and internet outages and are delivered with their
//! original event timestamps. After a burst the item buffer is shrunk again (see
//! [`shrunk_capacity`]) so a drained 1000-item backlog does not keep its memory.
//!
//! [`flush`]: NotificationQueue::flush
//! [`mark_delivered`]: NotificationQueue::mark_delivered

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{Notification, NotificationKind};
use crate::util::Signal;

/// Maximum queued items; beyond this the oldest are dropped (and counted).
const MAX_ITEMS: usize = 1000;
/// Number of recently delivered dedupe keys remembered.
const MAX_RECENT_KEYS: usize = 256;
/// Acks are written to disk at most this often (unless the queue became empty or on flush).
pub(crate) const ACK_WRITE_INTERVAL: Duration = Duration::from_secs(2);
/// The item buffer is only shrunk when its capacity is above this (small buffers are kept).
const SHRINK_ABOVE: usize = 64;
/// Upper bound of one item's `delivered_to` (authorized users are capped far below it; ids of
/// users removed meanwhile may stay in the list).
const MAX_DELIVERED_TO: usize = 64;

#[derive(Default, Serialize, Deserialize)]
struct QueueFile {
    next_id: u64,
    items: VecDeque<Notification>,
    #[serde(default)]
    recent_keys: VecDeque<String>,
    #[serde(default)]
    dropped: u64,
}

/// In-memory state: the persisted part plus the write bookkeeping for coalesced acks.
#[derive(Default)]
struct State {
    file: QueueFile,
    /// Acks applied in memory that are not on disk yet.
    dirty: bool,
    /// Last successful write (None = not written since open).
    last_write: Option<Instant>,
}

pub struct NotificationQueue {
    path: Option<PathBuf>,
    state: Mutex<State>,
    waker: Mutex<Option<Arc<Signal>>>,
}

/// Should an ack be written now? Yes when the queue became empty (the common single-alert case
/// and the end of a backlog), when nothing was written since open, or when the last write is at
/// least [`ACK_WRITE_INTERVAL`] old; otherwise it is deferred (coalesced).
pub(crate) fn ack_write_due(queue_empty: bool, last_write: Option<Instant>, now: Instant) -> bool {
    queue_empty || last_write.is_none_or(|t| now.saturating_duration_since(t) >= ACK_WRITE_INTERVAL)
}

/// New capacity for a buffer holding `len` items with `capacity` slots after removals, or
/// `None` to keep it: shrink once it is less than a quarter full and larger than
/// [`SHRINK_ABOVE`], to twice the length (at least [`SHRINK_ABOVE`] / 4) — the hysteresis means
/// a queue that fluctuates does not reallocate on every ack.
pub(crate) fn shrunk_capacity(len: usize, capacity: usize) -> Option<usize> {
    (capacity > SHRINK_ABOVE && len < capacity / 4).then(|| (len * 2).max(SHRINK_ABOVE / 4))
}

impl NotificationQueue {
    /// Open (or create) the queue at `path`. A corrupt file is renamed aside.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice::<QueueFile>(&b).unwrap_or_else(|e| {
                crate::log_error!("queue.json is corrupt ({e}); starting empty");
                let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                QueueFile::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => QueueFile::default(),
            Err(e) => return Err(e),
        };
        let state = State { file, ..State::default() };
        Ok(Self { path: Some(path.to_path_buf()), state: Mutex::new(state), waker: Mutex::new(None) })
    }

    /// Non-persistent queue (tests / console dry-runs).
    pub fn in_memory() -> Self {
        Self { path: None, state: Mutex::new(State::default()), waker: Mutex::new(None) }
    }

    /// Signal notified whenever an item is pushed (the sender thread waits on it).
    pub fn set_waker(&self, s: Arc<Signal>) {
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the whole state (atomic replace). On success the pending acks are on disk.
    fn persist(&self, st: &mut State, now: Instant) -> std::io::Result<()> {
        if let Some(p) = &self.path {
            let json = serde_json::to_vec(&st.file).map_err(std::io::Error::other)?;
            crate::paths::atomic_write(p, &json)?;
        }
        st.dirty = false;
        st.last_write = Some(now);
        Ok(())
    }

    fn has_key(st: &QueueFile, k: &str) -> bool {
        st.recent_keys.iter().any(|x| x == k) || st.items.iter().any(|n| n.dedupe_key.as_deref() == Some(k))
    }

    /// True when a notification with this idempotency key is queued or was delivered recently
    /// (lets callers skip every other side effect of a replayed event).
    pub fn contains_key(&self, key: &str) -> bool {
        Self::has_key(&self.lock().file, key)
    }

    /// Append a notification. Returns `Ok(None)` if `dedupe_key` was already queued/delivered.
    ///
    /// `Err` means the notification is NOT queued: the in-memory state is rolled back, so a
    /// retry of the same event really retries (instead of being reported as a duplicate of an
    /// item that exists only in memory).
    pub fn push(
        &self,
        kind: NotificationKind,
        event_unix: i64,
        html: String,
        dedupe_key: Option<String>,
    ) -> std::io::Result<Option<u64>> {
        self.push_excluding(kind, event_unix, html, dedupe_key, &[])
    }

    /// [`push`](Self::push) for everyone except the chats in `exclude` (they count as delivered
    /// already, e.g. the user a "new user paired" notice is about).
    pub fn push_excluding(
        &self,
        kind: NotificationKind,
        event_unix: i64,
        html: String,
        dedupe_key: Option<String>,
        exclude: &[i64],
    ) -> std::io::Result<Option<u64>> {
        let mut delivered_to: Vec<i64> = Vec::new();
        for &chat in exclude.iter().take(MAX_DELIVERED_TO) {
            if !delivered_to.contains(&chat) {
                delivered_to.push(chat);
            }
        }
        let id = {
            let mut guard = self.lock();
            let st = &mut *guard;
            if let Some(k) = &dedupe_key
                && Self::has_key(&st.file, k)
            {
                return Ok(None);
            }
            st.file.next_id += 1;
            let id = st.file.next_id;
            st.file.items.push_back(Notification {
                id,
                kind,
                event_unix,
                queued_unix: crate::util::time::now_unix(),
                html,
                dedupe_key,
                delivered_to,
            });
            let mut evicted = Vec::new();
            while st.file.items.len() > MAX_ITEMS {
                if let Some(old) = st.file.items.pop_front() {
                    evicted.push(old);
                }
                st.file.dropped += 1;
            }
            // Synchronous and durable (pending acks are written with it).
            if let Err(e) = self.persist(st, Instant::now()) {
                // undo: drop the new item, put the evicted ones back in their original order
                st.file.items.pop_back();
                st.file.dropped -= evicted.len() as u64;
                for old in evicted.into_iter().rev() {
                    st.file.items.push_front(old);
                }
                return Err(e);
            }
            id
        };
        if let Some(w) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            w.notify();
        }
        Ok(Some(id))
    }

    /// Oldest pending notification (not removed).
    pub fn front(&self) -> Option<Notification> {
        self.lock().file.items.front().cloned()
    }

    /// The pending notification with this id.
    pub fn get(&self, id: u64) -> Option<Notification> {
        self.lock().file.items.iter().find(|n| n.id == id).cloned()
    }

    /// Record that notification `id` reached `chat_id` (one recipient of several). Written like
    /// an ack: at once when the last write is at least [`ACK_WRITE_INTERVAL`] old, otherwise with
    /// the next write or [`flush`](Self::flush). Nothing changes for an unknown id or a chat
    /// already listed. `Err` = the write that was due failed (it stays pending).
    pub fn mark_delivered(&self, id: u64, chat_id: i64) -> std::io::Result<()> {
        self.mark_delivered_at(id, chat_id, Instant::now())
    }

    /// [`mark_delivered`](Self::mark_delivered) with an explicit clock (unit tests).
    pub(crate) fn mark_delivered_at(&self, id: u64, chat_id: i64, now: Instant) -> std::io::Result<()> {
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(n) = st.file.items.iter_mut().find(|n| n.id == id) else { return Ok(()) };
        if n.delivered_to.contains(&chat_id) {
            return Ok(());
        }
        n.delivered_to.push(chat_id);
        if n.delivered_to.len() > MAX_DELIVERED_TO {
            n.delivered_to.remove(0);
        }
        st.dirty = true;
        if ack_write_due(false, st.last_write, now) {
            self.persist(st, now)?;
        }
        Ok(())
    }

    /// Remove a delivered notification by id (remembering its dedupe key at once, in memory).
    /// Nothing changes for an unknown or already acked id. The removal reaches the disk at once
    /// when the queue became empty or the last write is at least [`ACK_WRITE_INTERVAL`] old;
    /// otherwise it is written with the next ack, push or [`flush`](Self::flush) (see the module
    /// documentation for what that means after a crash). `Err` = the write that was due failed;
    /// the removal stays pending and is retried by the next write.
    pub fn ack(&self, id: u64) -> std::io::Result<()> {
        self.ack_at(id, Instant::now())
    }

    /// [`ack`](Self::ack) with an explicit clock (unit tests).
    pub(crate) fn ack_at(&self, id: u64, now: Instant) -> std::io::Result<()> {
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(pos) = st.file.items.iter().position(|n| n.id == id) else { return Ok(()) };
        if let Some(n) = st.file.items.remove(pos)
            && let Some(k) = n.dedupe_key
        {
            st.file.recent_keys.push_back(k);
            while st.file.recent_keys.len() > MAX_RECENT_KEYS {
                st.file.recent_keys.pop_front();
            }
        }
        st.dirty = true;
        if let Some(cap) = shrunk_capacity(st.file.items.len(), st.file.items.capacity()) {
            st.file.items.shrink_to(cap);
        }
        if ack_write_due(st.file.items.is_empty(), st.last_write, now) {
            self.persist(st, now)?;
        }
        Ok(())
    }

    /// Write pending (coalesced) acks now. Does nothing when everything is on disk already.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut guard = self.lock();
        if !guard.dirty {
            return Ok(());
        }
        self.persist(&mut guard, Instant::now())
    }

    /// Whether acks are waiting to be written (see [`flush`](Self::flush)).
    pub fn has_pending_writes(&self) -> bool {
        self.lock().dirty
    }

    pub fn len(&self) -> usize {
        self.lock().file.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of notifications dropped because the queue overflowed (since install).
    pub fn dropped(&self) -> u64 {
        self.lock().file.dropped
    }

    /// Slots allocated for queued items (tests of the post-burst shrink).
    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.lock().file.items.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_dedupe_persist() {
        let dir = std::env::temp_dir().join(format!("predator-q-{}", crate::util::rand::hex(4)));
        let p = dir.join("queue.json");
        std::fs::create_dir_all(&dir).unwrap();
        let q = NotificationQueue::open(&p).unwrap();
        let a = q.push(NotificationKind::Login, 100, "a".into(), Some("k1".into())).unwrap();
        assert!(a.is_some());
        assert!(q.push(NotificationKind::Login, 100, "a".into(), Some("k1".into())).unwrap().is_none());
        q.push(NotificationKind::System, 200, "b".into(), None).unwrap();
        assert_eq!(q.len(), 2);
        let q2 = NotificationQueue::open(&p).unwrap();
        assert_eq!(q2.len(), 2);
        let f = q2.front().unwrap();
        assert_eq!(f.html, "a");
        assert_eq!(f.event_unix, 100);
        q2.ack(f.id).unwrap();
        // delivered key stays remembered
        assert!(q2.push(NotificationKind::Login, 100, "a".into(), Some("k1".into())).unwrap().is_none());
        assert_eq!(q2.front().unwrap().html, "b");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn contains_key_covers_queued_and_delivered() {
        let q = NotificationQueue::in_memory();
        assert!(!q.contains_key("security:1:2"));
        let id = q.push(NotificationKind::Login, 1, "x".into(), Some("security:1:2".into())).unwrap().unwrap();
        assert!(q.contains_key("security:1:2"));
        q.ack(id).unwrap();
        assert!(q.contains_key("security:1:2"), "delivered keys are remembered");
        assert!(!q.contains_key("security:1:3"));
    }

    #[test]
    fn failed_persist_is_rolled_back() {
        let dir = std::env::temp_dir().join(format!("predator-q-rb-{}", crate::util::rand::hex(4)));
        let p = dir.join("queue.json");
        std::fs::create_dir_all(&dir).unwrap();
        let q = NotificationQueue::open(&p).unwrap();
        q.push(NotificationKind::System, 1, "kept".into(), None).unwrap();
        // a directory where atomic_write wants its temp file: every write now fails
        let blocker = dir.join("queue.json.tmp");
        std::fs::create_dir_all(&blocker).unwrap();
        assert!(q.push(NotificationKind::Login, 2, "lost".into(), Some("k".into())).is_err());
        assert_eq!(q.len(), 1, "the failed item is not kept in memory");
        assert!(!q.contains_key("k"), "a retry must not be treated as a duplicate");
        assert!(q.push(NotificationKind::Login, 2, "lost".into(), Some("k".into())).is_err(), "retry really retries");
        std::fs::remove_dir_all(&blocker).unwrap();
        assert!(q.push(NotificationKind::Login, 2, "saved".into(), Some("k".into())).unwrap().is_some());
        let q2 = NotificationQueue::open(&p).unwrap();
        assert_eq!(q2.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rollback_restores_evicted_items() {
        let mut q = NotificationQueue::in_memory();
        for i in 0..MAX_ITEMS {
            q.push(NotificationKind::System, i as i64, format!("{i}"), None).unwrap();
        }
        // from now on every write fails (a directory blocks atomic_write's temp file)
        let dir = std::env::temp_dir().join(format!("predator-q-ev-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(dir.join("queue.json.tmp")).unwrap();
        q.path = Some(dir.join("queue.json"));
        assert!(q.push(NotificationKind::System, 0, "new".into(), None).is_err());
        assert_eq!(q.len(), MAX_ITEMS);
        assert_eq!(q.dropped(), 0);
        assert_eq!(q.front().unwrap().html, "0", "the evicted oldest item is back in front");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ack_of_unknown_id_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("predator-q-ack-{}", crate::util::rand::hex(4)));
        let p = dir.join("queue.json");
        std::fs::create_dir_all(&dir).unwrap();
        let q = NotificationQueue::open(&p).unwrap();
        let id = q.push(NotificationKind::System, 1, "a".into(), None).unwrap().unwrap();
        q.ack(id).unwrap();
        std::fs::remove_file(&p).unwrap();
        q.ack(id).unwrap(); // already acked
        q.ack(12345).unwrap(); // never existed
        assert!(!p.exists(), "no rewrite when nothing changed");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn temp_queue(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("predator-q-{tag}-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("queue.json");
        (dir, p)
    }

    #[test]
    fn ack_write_policy() {
        let t0 = Instant::now();
        // nothing written since open: write
        assert!(ack_write_due(false, None, t0));
        // written just now: defer while items remain ...
        assert!(!ack_write_due(false, Some(t0), t0 + Duration::from_millis(500)));
        assert!(!ack_write_due(false, Some(t0), t0 + ACK_WRITE_INTERVAL - Duration::from_millis(1)));
        // ... but not when the queue became empty, or once the interval is over
        assert!(ack_write_due(true, Some(t0), t0 + Duration::from_millis(1)));
        assert!(ack_write_due(false, Some(t0), t0 + ACK_WRITE_INTERVAL));
        // a clock that seems to go backwards never forces a write storm (saturating)
        assert!(!ack_write_due(false, Some(t0 + Duration::from_secs(5)), t0));
    }

    #[test]
    fn shrink_policy() {
        assert_eq!(shrunk_capacity(0, 64), None, "small buffers are kept");
        assert_eq!(shrunk_capacity(10, 128), Some(20));
        assert_eq!(shrunk_capacity(0, 1024), Some(SHRINK_ABOVE / 4));
        assert_eq!(shrunk_capacity(1, 1024), Some(SHRINK_ABOVE / 4));
        assert_eq!(shrunk_capacity(255, 1024), Some(510));
        assert_eq!(shrunk_capacity(256, 1024), None, "a quarter full is kept");
        // hysteresis: right after a shrink the buffer is about half full, so neither growing nor
        // shrinking again is due
        let len = 100;
        let cap = shrunk_capacity(len, 1024).unwrap();
        assert!(len <= cap && shrunk_capacity(len, cap).is_none());
    }

    /// Acks inside the 2 s window are kept in memory only (dirty) and written by the next write
    /// that is due, by a push, by `flush`, or when the queue becomes empty. A crash in between
    /// (simulated by reopening the file) re-delivers the acked item: at-least-once, never lost.
    #[test]
    fn acks_are_coalesced_flushed_and_at_least_once() {
        let (dir, p) = temp_queue("coalesce");
        let q = NotificationQueue::open(&p).unwrap();
        let ids: Vec<u64> = (0..4)
            .map(|i| q.push(NotificationKind::Login, i, format!("n{i}"), Some(format!("k{i}"))).unwrap().unwrap())
            .collect();
        assert!(!q.has_pending_writes(), "pushes are written synchronously");
        let t0 = Instant::now();
        // the last write (the push) is recent: the ack is deferred
        q.ack_at(ids[0], t0).unwrap();
        assert_eq!(q.len(), 3);
        assert!(q.has_pending_writes());
        assert!(q.contains_key("k0"), "dedupe works in memory before the write");
        assert!(q.push(NotificationKind::Login, 0, "dup".into(), Some("k0".into())).unwrap().is_none());
        // crash now: the acked item is still on disk and would be sent again
        let crashed = NotificationQueue::open(&p).unwrap();
        assert_eq!(crashed.len(), 4);
        assert_eq!(crashed.front().unwrap().html, "n0");
        assert!(!crashed.contains_key("missing"));
        // explicit flush writes it (and is a no-op afterwards)
        q.flush().unwrap();
        assert!(!q.has_pending_writes());
        q.flush().unwrap();
        let reopened = NotificationQueue::open(&p).unwrap();
        assert_eq!(reopened.len(), 3);
        assert!(reopened.contains_key("k0"), "the delivered key was persisted with the write");

        // the next due write carries earlier deferred acks with it
        let t1 = Instant::now();
        q.ack_at(ids[1], t1).unwrap(); // flush just wrote: deferred
        assert!(q.has_pending_writes());
        q.ack_at(ids[2], t1 + ACK_WRITE_INTERVAL).unwrap(); // interval over: written
        assert!(!q.has_pending_writes());
        assert_eq!(NotificationQueue::open(&p).unwrap().len(), 1);

        // a push writes pending acks too
        q.push(NotificationKind::System, 9, "new".into(), None).unwrap();
        let t2 = Instant::now();
        q.ack_at(ids[3], t2).unwrap();
        assert!(q.has_pending_writes(), "one item left: deferred");
        q.push(NotificationKind::System, 10, "newer".into(), None).unwrap();
        assert!(!q.has_pending_writes());
        let on_disk = NotificationQueue::open(&p).unwrap();
        assert_eq!(on_disk.len(), 2);
        assert!(on_disk.contains_key("k3"));

        // the queue becoming empty is written at once, however recent the last write was
        while let Some(n) = q.front() {
            q.ack_at(n.id, t2).unwrap();
        }
        assert!(!q.has_pending_writes());
        assert_eq!(NotificationQueue::open(&p).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_deferred_write_stays_pending() {
        let (dir, p) = temp_queue("pending");
        let q = NotificationQueue::open(&p).unwrap();
        let a = q.push(NotificationKind::System, 1, "a".into(), None).unwrap().unwrap();
        q.push(NotificationKind::System, 2, "b".into(), None).unwrap();
        q.ack_at(a, Instant::now()).unwrap();
        assert!(q.has_pending_writes());
        let blocker = dir.join("queue.json.tmp");
        std::fs::create_dir_all(&blocker).unwrap();
        assert!(q.flush().is_err());
        assert!(q.has_pending_writes(), "retried by the next write");
        std::fs::remove_dir_all(&blocker).unwrap();
        q.flush().unwrap();
        assert_eq!(NotificationQueue::open(&p).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn capacity_shrinks_after_a_burst() {
        let q = NotificationQueue::in_memory();
        let ids: Vec<u64> = (0..MAX_ITEMS)
            .map(|i| q.push(NotificationKind::System, i as i64, String::new(), None).unwrap().unwrap())
            .collect();
        let full = q.capacity();
        assert!(full >= MAX_ITEMS);
        for id in &ids[..MAX_ITEMS - 10] {
            q.ack(*id).unwrap();
        }
        assert_eq!(q.len(), 10);
        let cap = q.capacity();
        assert!(cap < full / 4 && cap <= 128, "capacity {full} -> {cap}");
        // order is kept through the reallocations
        assert_eq!(q.front().unwrap().id, ids[MAX_ITEMS - 10]);
        for id in &ids[MAX_ITEMS - 10..] {
            q.ack(*id).unwrap();
        }
        assert!(q.is_empty());
        assert!(q.capacity() <= SHRINK_ABOVE);
    }

    /// Per-recipient progress survives a restart once written (coalesced like acks), and old
    /// files without `delivered_to` still load.
    #[test]
    fn delivered_to_is_persisted_and_coalesced() {
        let (dir, p) = temp_queue("recipients");
        let q = NotificationQueue::open(&p).unwrap();
        let id = q.push(NotificationKind::Login, 1, "a".into(), Some("k".into())).unwrap().unwrap();
        assert!(q.front().unwrap().delivered_to.is_empty());
        let t0 = Instant::now();
        // the push just wrote: deferred, but visible in memory at once
        q.mark_delivered_at(id, 111, t0).unwrap();
        assert!(q.has_pending_writes());
        assert_eq!(q.get(id).unwrap().delivered_to, vec![111]);
        assert!(NotificationQueue::open(&p).unwrap().front().unwrap().delivered_to.is_empty(), "not on disk yet");
        // duplicates and unknown ids change nothing
        q.mark_delivered_at(id, 111, t0).unwrap();
        q.mark_delivered_at(999, 222, t0).unwrap();
        assert_eq!(q.get(id).unwrap().delivered_to, vec![111]);
        assert!(q.get(999).is_none());
        // the flush before the sender waits writes it
        q.flush().unwrap();
        assert_eq!(NotificationQueue::open(&p).unwrap().front().unwrap().delivered_to, vec![111]);
        // a due write happens at once
        q.mark_delivered_at(id, 222, t0 + ACK_WRITE_INTERVAL * 2).unwrap();
        assert!(!q.has_pending_writes());
        assert_eq!(NotificationQueue::open(&p).unwrap().front().unwrap().delivered_to, vec![111, 222]);
        // an empty list is not written at all (old readers and small files)
        q.push(NotificationKind::System, 2, "b".into(), None).unwrap();
        let json = std::fs::read_to_string(&p).unwrap();
        assert_eq!(json.matches("delivered_to").count(), 1, "{json}");
        // a file from before per-recipient delivery
        std::fs::write(
            &p,
            br#"{"next_id":3,"items":[{"id":3,"kind":"login","event_unix":1,"queued_unix":1,"html":"x"}]}"#,
        )
        .unwrap();
        let old = NotificationQueue::open(&p).unwrap();
        assert_eq!(old.front().unwrap().delivered_to, Vec::<i64>::new());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn push_excluding_prefills_recipients() {
        let q = NotificationQueue::in_memory();
        let id = q.push_excluding(NotificationKind::Security, 1, "x".into(), None, &[5, 5, 6]).unwrap().unwrap();
        assert_eq!(q.get(id).unwrap().delivered_to, vec![5, 6]);
        // bounded
        let many: Vec<i64> = (0..500).collect();
        let id = q.push_excluding(NotificationKind::Security, 1, "y".into(), None, &many).unwrap().unwrap();
        assert_eq!(q.get(id).unwrap().delivered_to.len(), MAX_DELIVERED_TO);
        for chat in 1000..1100 {
            q.mark_delivered(id, chat).unwrap();
        }
        let d = q.get(id).unwrap().delivered_to;
        assert_eq!(d.len(), MAX_DELIVERED_TO);
        assert_eq!(d.last(), Some(&1099), "the newest recipients are kept");
    }

    #[test]
    fn overflow_drops_oldest() {
        let q = NotificationQueue::in_memory();
        for i in 0..(MAX_ITEMS + 5) {
            q.push(NotificationKind::System, i as i64, format!("{i}"), None).unwrap();
        }
        assert_eq!(q.len(), MAX_ITEMS);
        assert_eq!(q.dropped(), 5);
        assert_eq!(q.front().unwrap().html, "5");
    }
}
