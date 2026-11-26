//! wevtapi pull-mode subscriptions with persistent bookmarks.
//!
//! Pull mode (no callbacks): `EvtSubscribe` gets a manual-reset signal event that wevtapi sets
//! when new matching records arrive; the monitor thread waits on it, resets it and drains the
//! subscription with `EvtNext` (batches of [`BATCH`]). Errors surface synchronously from
//! `EvtSubscribe`/`EvtNext`, so an EventLog service restart (RPC errors) is simply "reopen".
//!
//! `EvtNext` protocol of a pull subscription (measured on Windows 11 26200 as a normal user on
//! OpenSSH/Operational with a throwaway program; identical for Timeout 0, 200, 1000 ms and
//! INFINITE, for `ToFutureEvents` and `StartAtOldestRecord`):
//! * a fresh subscription can be read at once (the signal is NOT set initially);
//! * reading to the end returns `ERROR_NO_MORE_ITEMS` (259); from then on wevtapi waits for new
//!   records, and EVERY further `EvtNext` fails with `ERROR_INVALID_OPERATION` (4317, "The
//!   operation identifier is not valid") until wevtapi sets the signal event (≈0.5–1 s after a
//!   matching record was written). Setting the event ourselves does not help;
//! * after the signal the subscription delivers normally again — 4317 is "nothing new yet", not
//!   a broken subscription (see [`Fetch::Waiting`]).
//!
//! Treating 4317 as a read failure caused the production spin (reopen → clean first read →
//! unsignalled read → 4317 → reopen …, ~1000 times/s on all channels).
//!
//! Bookmarks (`<BookmarkList><Bookmark Channel='Security' RecordId='123' .../></BookmarkList>`)
//! are kept in memory (`EvtUpdateBookmark` after each event that was durably handled) and
//! persisted with [`crate::paths::atomic_write`]. Resuming uses
//! `EvtSubscribeStartAfterBookmark | EvtSubscribeStrict`; an unusable bookmark (15011 / 1168 /
//! 15012 — log cleared or rolled over) falls back to `EvtSubscribeToFutureEvents` with a fresh
//! bookmark and reports a gap. The stale bookmark file is kept until the caller has reported
//! the gap (a failed fallback subscribe therefore re-detects the same gap on the next attempt).
//! Behaviour verified on Windows 11 with the live tests in this module.
//!
//! Every subscription reads ONE channel: a bookmark of a multi-channel subscription stores the
//! non-current channels at their next record id, which a Strict resume rejects (15011) when that
//! channel has no newer record yet (measured with OpenSSH/Operational + OpenSSH/Admin).

use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_QUERY_RESULT_INVALID_POSITION,
    ERROR_EVT_QUERY_RESULT_STALE, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_OPERATION,
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_TIMEOUT, HANDLE,
};
use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtChannelConfigEnabled, EvtClose, EvtCreateBookmark, EvtGetChannelConfigProperty,
    EvtNext, EvtOpenChannelConfig, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection,
    EvtRender, EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe, EvtSubscribeStartAfterBookmark, EvtSubscribeStrict,
    EvtSubscribeToFutureEvents, EvtUpdateBookmark, EvtVarTypeBoolean,
};

use crate::util::win::{WinError, from_wide, last_error, wide};

/// Events fetched per `EvtNext` call.
pub const BATCH: usize = 32;
/// `EvtNext` time budget. It only bounds the server-side scan of one batch: a pull subscription
/// never waits for NEW records (measured: 259 comes back at once with 0, 1000 ms and INFINITE;
/// a full scan of a 20 MB System log with a non-matching filter took 58 ms). Microsoft's pull
/// sample uses INFINITE; a bound keeps stop requests responsive.
pub const NEXT_TIMEOUT_MS: u32 = 1000;

/// What one `EvtNext` call on a pull subscription returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// Events were returned.
    Events,
    /// Read to the end (`ERROR_NO_MORE_ITEMS`, or success with no events). wevtapi sets the
    /// signal event when new matching records arrive.
    Drained,
    /// `ERROR_INVALID_OPERATION` (4317): still nothing new since the last [`Fetch::Drained`] —
    /// wevtapi is waiting for the next record and signals it. Not an error.
    Waiting,
    /// `ERROR_TIMEOUT`: the server did not finish the batch within [`NEXT_TIMEOUT_MS`].
    Timeout,
}

/// Interpret an `EvtNext` result (`ok` = returned TRUE, `returned` = handle count, `err` = last
/// error when it failed). `Err(code)` = the subscription is unusable and must be reopened.
pub fn fetch_status(ok: bool, returned: u32, err: u32) -> Result<Fetch, u32> {
    if ok {
        return Ok(if returned > 0 { Fetch::Events } else { Fetch::Drained });
    }
    match err {
        ERROR_NO_MORE_ITEMS => Ok(Fetch::Drained),
        ERROR_INVALID_OPERATION => Ok(Fetch::Waiting),
        ERROR_TIMEOUT => Ok(Fetch::Timeout),
        code => Err(code),
    }
}
/// Upper bound of one rendered event/bookmark (UTF-16 units) — far above real events (~3 K).
const MAX_RENDER_CHARS: usize = 1 << 20;
/// Render buffers above this size are released after use.
const KEEP_RENDER_CHARS: usize = 16 * 1024;

/// RPC errors seen while the EventLog service stops/restarts (`Win32::System::Rpc`, as u32).
const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
const RPC_S_UNKNOWN_IF: u32 = 1717;
const RPC_S_CALL_CANCELLED: u32 = 1818;
const RPC_S_CALL_FAILED: u32 = 1726;
const RPC_S_CALL_FAILED_DNE: u32 = 1727;
const EPT_S_NOT_REGISTERED: u32 = 1753;
const RPC_X_SS_IN_NULL_CONTEXT: u32 = 1775;

/// Owned `EVT_HANDLE`, closed with `EvtClose` on drop.
#[derive(Debug)]
pub struct EvtHandle(EVT_HANDLE);

impl EvtHandle {
    /// Wrap a raw handle; `None` for the null handle.
    pub fn from_raw(h: EVT_HANDLE) -> Option<Self> {
        (h != 0).then_some(Self(h))
    }

    pub fn raw(&self) -> EVT_HANDLE {
        self.0
    }
}

impl Drop for EvtHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: we own this handle and close it exactly once.
            unsafe {
                EvtClose(self.0);
            }
        }
    }
}

/// What an error code means for the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Saved position is gone (log cleared/rolled over) or the bookmark is invalid.
    BookmarkUnusable,
    /// The channel does not exist (e.g. OpenSSH Server not installed).
    ChannelNotFound,
    AccessDenied,
    /// EventLog service stopped/restarting (RPC failure, dead handle): reopen with backoff.
    ServiceUnavailable,
    Other,
}

pub fn classify_error(code: u32) -> ErrorClass {
    match code {
        ERROR_EVT_QUERY_RESULT_STALE | ERROR_NOT_FOUND | ERROR_EVT_QUERY_RESULT_INVALID_POSITION => {
            ErrorClass::BookmarkUnusable
        }
        ERROR_EVT_CHANNEL_NOT_FOUND => ErrorClass::ChannelNotFound,
        ERROR_ACCESS_DENIED => ErrorClass::AccessDenied,
        RPC_S_SERVER_UNAVAILABLE
        | RPC_S_UNKNOWN_IF
        | RPC_S_CALL_CANCELLED
        | RPC_S_CALL_FAILED
        | RPC_S_CALL_FAILED_DNE
        | EPT_S_NOT_REGISTERED
        | RPC_X_SS_IN_NULL_CONTEXT
        | ERROR_INVALID_HANDLE
        | ERROR_INVALID_PARAMETER => ErrorClass::ServiceUnavailable,
        _ => ErrorClass::Other,
    }
}

/// Reusable UTF-16 buffer for `EvtRender` (two-call pattern, grows on demand).
#[derive(Default)]
pub struct Renderer {
    buf: Vec<u16>,
}

impl Renderer {
    /// Render `h` with `flags` (`EvtRenderEventXml` / `EvtRenderBookmark`) to a string.
    pub fn render(&mut self, h: EVT_HANDLE, flags: u32) -> Result<String, WinError> {
        let mut used: u32 = 0;
        let mut props: u32 = 0;
        for _ in 0..3 {
            let size_bytes = u32::try_from(self.buf.len() * 2).unwrap_or(u32::MAX);
            let ptr = if self.buf.is_empty() { std::ptr::null_mut() } else { self.buf.as_mut_ptr().cast() };
            // SAFETY: `ptr` is null (size 0) or points to `size_bytes` writable bytes.
            let ok = unsafe { EvtRender(0, h, flags, size_bytes, ptr, &mut used, &mut props) };
            if ok != 0 {
                let n = (used as usize / 2).min(self.buf.len());
                let s = from_wide(&self.buf[..n]);
                if self.buf.len() > KEEP_RENDER_CHARS {
                    self.buf = Vec::new();
                }
                return Ok(s);
            }
            let err = last_error();
            if err != ERROR_INSUFFICIENT_BUFFER {
                return Err(WinError::new(err, "EvtRender"));
            }
            let need = (used as usize).div_ceil(2) + 1;
            if need > MAX_RENDER_CHARS {
                return Err(WinError::new(err, "EvtRender (event too large)"));
            }
            self.buf.resize(need.max(512), 0);
        }
        Err(WinError::new(ERROR_INSUFFICIENT_BUFFER, "EvtRender"))
    }
}

/// `RecordId` of the first `<Bookmark>` in bookmark XML (`None` for an empty bookmark).
pub fn bookmark_record_id(xml: &str) -> Option<u64> {
    let start = xml.find("<Bookmark ")?;
    let tag = &xml[start..];
    let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
    let at = tag.find("RecordId=")? + "RecordId=".len();
    let rest = tag.get(at..)?;
    let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let rest = &rest[1..];
    let end = rest.find(quote)?;
    rest[..end].trim().parse().ok()
}

fn create_bookmark(xml: Option<&str>) -> Result<EvtHandle, WinError> {
    let w = xml.map(wide);
    let p = w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
    // SAFETY: `p` is null or a NUL-terminated UTF-16 string that outlives the call.
    let h = unsafe { EvtCreateBookmark(p) };
    EvtHandle::from_raw(h).ok_or_else(|| WinError::last("EvtCreateBookmark"))
}

fn subscribe(signal: HANDLE, query: &str, bookmark: EVT_HANDLE, flags: u32) -> Result<EvtHandle, WinError> {
    let q = wide(query);
    // SAFETY: valid NUL-terminated query, live signal event and bookmark handles; pull mode
    // (no callback/context). A structured QueryList query ignores the channel path.
    let h = unsafe { EvtSubscribe(0, signal, std::ptr::null(), q.as_ptr(), bookmark, std::ptr::null(), None, flags) };
    EvtHandle::from_raw(h).ok_or_else(|| WinError::last("EvtSubscribe"))
}

/// Read a saved bookmark file; `None` when missing/empty/unreadable.
fn load_bookmark(path: &Path) -> Option<String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let s = String::from_utf8_lossy(&bytes).trim().to_string();
            (!s.is_empty()).then_some(s)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            crate::log_warn!("cannot read bookmark {}: {e}", path.display());
            None
        }
    }
}

/// Delete a channel's bookmark file (missing is fine).
pub fn delete_bookmark(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        crate::log_warn!("cannot delete bookmark {}: {e}", path.display());
    }
}

/// The saved position could not be used; events may have been missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// Last record id we had processed, when known.
    pub last_record_id: Option<u64>,
    /// Win32 error that made the bookmark unusable.
    pub code: u32,
}

/// An open pull-mode subscription plus its bookmark.
pub struct Subscription {
    channel: String,
    handle: EvtHandle,
    bookmark: EvtHandle,
    bookmark_path: PathBuf,
    /// Bookmark has a position (loaded or updated at least once). Empty bookmarks are never saved.
    positioned: bool,
    /// Bookmark changed since the last successful save.
    dirty: bool,
    /// Last XML written to disk (skip identical writes).
    saved_xml: Option<String>,
    renderer: Renderer,
}

impl Subscription {
    /// Subscribe to `query` on `channel`, resuming after the bookmark stored at `bookmark_path`
    /// when there is one. `signal` must be a manual-reset event; it is NOT set here — the caller
    /// sets it once so the existing backlog is drained (wevtapi only signals new records).
    ///
    /// When the saved position is unusable the subscription starts with new events and a
    /// [`Gap`] is returned. The stale bookmark file is left in place: the caller reports the gap
    /// and then lets the new position overwrite it (or deletes it with [`delete_bookmark`]).
    /// If even the fallback subscription fails, the file is still there and the next attempt
    /// reports the same gap — it is never lost.
    pub fn open(
        channel: &str,
        query: &str,
        signal: HANDLE,
        bookmark_path: &Path,
    ) -> Result<(Subscription, Option<Gap>), WinError> {
        let mut gap = None;
        if let Some(xml) = load_bookmark(bookmark_path) {
            let last = bookmark_record_id(&xml);
            if last.is_some() {
                match create_bookmark(Some(&xml)) {
                    Ok(bm) => {
                        let flags = EvtSubscribeStartAfterBookmark | EvtSubscribeStrict;
                        match subscribe(signal, query, bm.raw(), flags) {
                            Ok(handle) => {
                                let sub = Subscription {
                                    channel: channel.to_string(),
                                    handle,
                                    bookmark: bm,
                                    bookmark_path: bookmark_path.to_path_buf(),
                                    positioned: true,
                                    dirty: false,
                                    saved_xml: Some(xml),
                                    renderer: Renderer::default(),
                                };
                                return Ok((sub, None));
                            }
                            Err(e) if classify_error(e.code) == ErrorClass::BookmarkUnusable => {
                                crate::log_warn!(
                                    "{channel}: saved position (record {}) is no longer available ({e}); continuing with new events",
                                    last.unwrap_or(0)
                                );
                                gap = Some(Gap { last_record_id: last, code: e.code });
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(e) => {
                        crate::log_warn!("{channel}: saved bookmark is invalid ({e}); continuing with new events");
                        gap = Some(Gap { last_record_id: last, code: e.code });
                    }
                }
            } else {
                // empty/corrupt file without a position: never resume from it again
                delete_bookmark(bookmark_path);
            }
        }
        let bm = create_bookmark(None)?;
        let handle = subscribe(signal, query, 0, EvtSubscribeToFutureEvents)?;
        let sub = Subscription {
            channel: channel.to_string(),
            handle,
            bookmark: bm,
            bookmark_path: bookmark_path.to_path_buf(),
            positioned: false,
            dirty: false,
            saved_xml: None,
            renderer: Renderer::default(),
        };
        Ok((sub, gap))
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// True when the bookmark holds a position (it is persisted).
    pub fn is_positioned(&self) -> bool {
        self.positioned
    }

    /// Fetch up to [`BATCH`] events into `out` (never waits for new records). `Err(code)` =
    /// the subscription is broken and must be reopened; see [`Fetch`] for the rest.
    pub fn next_batch(&mut self, out: &mut Vec<EvtHandle>) -> Result<Fetch, u32> {
        let mut raw = [0 as EVT_HANDLE; BATCH];
        let mut n: u32 = 0;
        // SAFETY: `raw` has room for BATCH handles; ownership of the returned handles passes to us.
        let ok = unsafe { EvtNext(self.handle.raw(), BATCH as u32, raw.as_mut_ptr(), NEXT_TIMEOUT_MS, 0, &mut n) } != 0;
        let err = if ok { 0 } else { last_error() };
        let fetch = fetch_status(ok, n, err)?;
        if ok {
            // `n` is only meaningful on success (MS-EVEN6: "If the method fails, the client MUST
            // NOT use the value")
            out.extend(raw.iter().take((n as usize).min(BATCH)).filter_map(|&h| EvtHandle::from_raw(h)));
        }
        Ok(fetch)
    }

    /// Event XML (`EvtRenderEventXml`).
    pub fn render_xml(&mut self, ev: &EvtHandle) -> Result<String, WinError> {
        self.renderer.render(ev.raw(), EvtRenderEventXml)
    }

    /// Move the in-memory bookmark to `ev` (call only after the event was durably handled).
    pub fn advance(&mut self, ev: &EvtHandle) -> Result<(), WinError> {
        // SAFETY: both handles are live.
        if unsafe { EvtUpdateBookmark(self.bookmark.raw(), ev.raw()) } == 0 {
            return Err(WinError::last("EvtUpdateBookmark"));
        }
        self.positioned = true;
        self.dirty = true;
        Ok(())
    }

    /// Current bookmark XML (`None` while it has no position).
    pub fn bookmark_xml(&mut self) -> Result<Option<String>, WinError> {
        if !self.positioned {
            return Ok(None);
        }
        self.renderer.render(self.bookmark.raw(), EvtRenderBookmark).map(Some)
    }

    /// Persist the bookmark if it changed. Returns whether a file was written.
    pub fn save_bookmark(&mut self) -> Result<bool, String> {
        if !self.dirty {
            return Ok(false);
        }
        let Some(xml) = self.bookmark_xml().map_err(|e| e.to_string())? else {
            return Ok(false);
        };
        if self.saved_xml.as_deref() == Some(xml.as_str()) {
            self.dirty = false;
            return Ok(false);
        }
        crate::paths::atomic_write(&self.bookmark_path, xml.as_bytes())
            .map_err(|e| format!("cannot save bookmark {}: {e}", self.bookmark_path.display()))?;
        self.saved_xml = Some(xml);
        self.dirty = false;
        Ok(true)
    }

    /// Test helper: subscribe from the oldest record (`EvtSubscribeStartAtOldestRecord`) with
    /// a fresh bookmark persisted to `bookmark_path`.
    #[cfg(test)]
    pub(super) fn open_at_oldest(
        channel: &str,
        query: &str,
        signal: HANDLE,
        bookmark_path: &Path,
    ) -> Result<Subscription, WinError> {
        use windows_sys::Win32::System::EventLog::EvtSubscribeStartAtOldestRecord;
        let bookmark = create_bookmark(None)?;
        let handle = subscribe(signal, query, 0, EvtSubscribeStartAtOldestRecord)?;
        Ok(Subscription {
            channel: channel.to_string(),
            handle,
            bookmark,
            bookmark_path: bookmark_path.to_path_buf(),
            positioned: false,
            dirty: false,
            saved_xml: None,
            renderer: Renderer::default(),
        })
    }
}

/// Newest record of `channel` (reverse `EvtQuery`), `None` when the channel is empty. Used to
/// position a fresh bookmark and for the periodic idle refresh, so the saved position never
/// points at a record that was overwritten long ago (which would look like a gap on restart).
pub fn newest_record(channel: &str) -> Result<Option<EvtHandle>, WinError> {
    edge_record(channel, EvtQueryChannelPath | EvtQueryReverseDirection)
}

/// Oldest record still present in `channel`, `None` when the channel is empty.
pub fn oldest_record(channel: &str) -> Result<Option<EvtHandle>, WinError> {
    edge_record(channel, EvtQueryChannelPath | EvtQueryForwardDirection)
}

fn edge_record(channel: &str, flags: u32) -> Result<Option<EvtHandle>, WinError> {
    let path = wide(channel);
    let q = wide("*");
    // SAFETY: valid NUL-terminated strings for the duration of the call.
    let h = unsafe { EvtQuery(0, path.as_ptr(), q.as_ptr(), flags) };
    let query = EvtHandle::from_raw(h).ok_or_else(|| WinError::last("EvtQuery"))?;
    let mut ev: EVT_HANDLE = 0;
    let mut n: u32 = 0;
    // SAFETY: room for exactly one handle.
    let ok = unsafe { EvtNext(query.raw(), 1, &mut ev, 2_000, 0, &mut n) };
    if ok == 0 {
        let e = last_error();
        return if e == ERROR_NO_MORE_ITEMS { Ok(None) } else { Err(WinError::new(e, "EvtNext")) };
    }
    Ok(if n >= 1 { EvtHandle::from_raw(ev) } else { None })
}

/// Whether `channel` exists and is enabled. `Err` carries 15007 when it does not exist.
pub fn channel_enabled(channel: &str) -> Result<bool, WinError> {
    let path = wide(channel);
    // SAFETY: valid NUL-terminated channel path.
    let h = unsafe { EvtOpenChannelConfig(0, path.as_ptr(), 0) };
    let cfg = EvtHandle::from_raw(h).ok_or_else(|| WinError::last("EvtOpenChannelConfig"))?;
    // SAFETY: EVT_VARIANT is plain data; all-zero is a valid (null) value.
    let mut v: EVT_VARIANT = unsafe { std::mem::zeroed() };
    let mut used: u32 = 0;
    let size = std::mem::size_of::<EVT_VARIANT>() as u32;
    // SAFETY: `v` provides `size` writable bytes; a boolean property fits in one EVT_VARIANT.
    let ok = unsafe { EvtGetChannelConfigProperty(cfg.raw(), EvtChannelConfigEnabled, 0, size, &mut v, &mut used) };
    if ok == 0 {
        return Err(WinError::last("EvtGetChannelConfigProperty"));
    }
    if v.Type != EvtVarTypeBoolean as u32 {
        return Ok(true); // unexpected type: assume enabled rather than report a false problem
    }
    // SAFETY: Type == EvtVarTypeBoolean, so BooleanVal is the active union member.
    Ok(unsafe { v.Anonymous.BooleanVal } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bookmark_xml_record_id() {
        let x =
            "<BookmarkList>\r\n  <Bookmark Channel='System' RecordId='255118' IsCurrent='true'/>\r\n</BookmarkList>";
        assert_eq!(bookmark_record_id(x), Some(255_118));
        let x = r#"<BookmarkList><Bookmark Channel="Application" RecordId="2004" IsCurrent="True"/></BookmarkList>"#;
        assert_eq!(bookmark_record_id(x), Some(2004));
        assert_eq!(bookmark_record_id("<BookmarkList>\r\n</BookmarkList>"), None);
        assert_eq!(bookmark_record_id("garbage"), None);
        assert_eq!(bookmark_record_id("<Bookmark RecordId='x'/>"), None);
        assert_eq!(bookmark_record_id("<Bookmark RecordId='12"), None);
    }

    #[test]
    fn error_classes() {
        assert_eq!(classify_error(15011), ErrorClass::BookmarkUnusable);
        assert_eq!(classify_error(1168), ErrorClass::BookmarkUnusable);
        assert_eq!(classify_error(15012), ErrorClass::BookmarkUnusable);
        assert_eq!(classify_error(15007), ErrorClass::ChannelNotFound);
        assert_eq!(classify_error(5), ErrorClass::AccessDenied);
        for c in [1722, 1717, 1818, 6, 87] {
            assert_eq!(classify_error(c), ErrorClass::ServiceUnavailable, "{c}");
        }
        assert_eq!(classify_error(15001), ErrorClass::Other);
    }

    #[test]
    fn evtnext_results() {
        assert_eq!(fetch_status(true, 3, 0), Ok(Fetch::Events));
        assert_eq!(fetch_status(true, 0, 0), Ok(Fetch::Drained));
        assert_eq!(fetch_status(false, 0, 259), Ok(Fetch::Drained));
        // 4317 after a drain is "no new record yet", never a reason to reopen
        assert_eq!(fetch_status(false, 0, 4317), Ok(Fetch::Waiting));
        assert_eq!(fetch_status(false, 7, 1460), Ok(Fetch::Timeout));
        for code in [6, 87, 1717, 1722, 15011] {
            assert_eq!(fetch_status(false, 0, code), Err(code));
        }
        assert_eq!(classify_error(4317), ErrorClass::Other);
    }

    /// A System-log subscription that never has anything to deliver.
    fn idle_system_subscription(signal: HANDLE, flags: u32) -> Subscription {
        let q = "<QueryList><Query Id=\"0\" Path=\"System\"><Select Path=\"System\">\
                 *[System[Provider[@Name='Predator-No-Such-Provider'] and EventID=65001]]</Select></Query></QueryList>";
        Subscription {
            channel: "System".into(),
            handle: subscribe(signal, q, 0, flags).unwrap(),
            bookmark: create_bookmark(None).unwrap(),
            bookmark_path: PathBuf::from("unused.xml"),
            positioned: false,
            dirty: false,
            saved_xml: None,
            renderer: Renderer::default(),
        }
    }

    /// The root cause of the production spin, reproduced: once a pull subscription was read to
    /// the end, every further unsignalled `EvtNext` fails with 4317 — whatever the timeout.
    #[test]
    fn unsignalled_read_after_the_end_is_waiting_not_broken() {
        use windows_sys::Win32::System::EventLog::EvtSubscribeStartAtOldestRecord;
        let signal = crate::util::win::OwnedEvent::create(true, false).unwrap();
        for flags in [EvtSubscribeToFutureEvents, EvtSubscribeStartAtOldestRecord] {
            let mut sub = idle_system_subscription(signal.raw(), flags);
            let mut out = Vec::new();
            assert_eq!(sub.next_batch(&mut out), Ok(Fetch::Drained), "flags {flags}");
            assert_eq!(sub.next_batch(&mut out), Ok(Fetch::Waiting), "flags {flags}");
            // Timeout 0 (what the service used before) behaves the same
            let mut raw = [0 as EVT_HANDLE; 1];
            let mut n = 0u32;
            // SAFETY: room for one handle; nothing is returned.
            let ok = unsafe { EvtNext(sub.handle.raw(), 1, raw.as_mut_ptr(), 0, 0, &mut n) } != 0;
            assert!(!ok);
            assert_eq!(last_error(), ERROR_INVALID_OPERATION);
            assert_eq!(sub.next_batch(&mut out), Ok(Fetch::Waiting), "flags {flags}");
            assert!(out.is_empty());
        }
        assert!(!signal.wait(std::time::Duration::ZERO), "nothing new: wevtapi did not signal");
    }

    /// Live: after 4317 the subscription delivers again as soon as wevtapi signals a new record.
    /// Writes one event (ID 65002, source "PredatorSpinTest") to the Application log.
    /// Run with `cargo test --lib monitor::eventlog::tests::live_waiting -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_waiting_subscription_recovers_on_signal() {
        use windows_sys::Win32::System::EventLog::{
            DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
        };
        let signal = crate::util::win::OwnedEvent::create(true, false).unwrap();
        let q = "<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*[System[EventID=65002]]</Select></Query></QueryList>";
        let h = subscribe(signal.raw(), q, 0, EvtSubscribeToFutureEvents).unwrap();
        let next = |out: &mut Vec<EvtHandle>| {
            let mut raw = [0 as EVT_HANDLE; BATCH];
            let mut n = 0u32;
            // SAFETY: room for BATCH handles.
            let ok = unsafe { EvtNext(h.raw(), BATCH as u32, raw.as_mut_ptr(), NEXT_TIMEOUT_MS, 0, &mut n) } != 0;
            let r = fetch_status(ok, n, if ok { 0 } else { last_error() });
            if ok {
                out.extend(raw.iter().take(n as usize).filter_map(|&e| EvtHandle::from_raw(e)));
            }
            r
        };
        let mut out = Vec::new();
        assert_eq!(next(&mut out), Ok(Fetch::Drained));
        assert_eq!(next(&mut out), Ok(Fetch::Waiting));
        signal.set();
        assert_eq!(next(&mut out), Ok(Fetch::Waiting), "setting the event ourselves does not end the wait");
        signal.reset();
        let src = wide("PredatorSpinTest");
        // SAFETY: local event log, NUL-terminated strings, handle deregistered below.
        unsafe {
            let es = RegisterEventSourceW(std::ptr::null(), src.as_ptr());
            assert!(!es.is_null());
            let body = wide("predator spin test");
            let strings = [body.as_ptr()];
            ReportEventW(
                es,
                EVENTLOG_INFORMATION_TYPE,
                0,
                65002,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            );
            DeregisterEventSource(es);
        }
        let t = std::time::Instant::now();
        assert!(signal.wait(std::time::Duration::from_secs(10)), "wevtapi signals the new record");
        println!("signalled after {} ms", t.elapsed().as_millis());
        signal.reset();
        assert_eq!(next(&mut out), Ok(Fetch::Events));
        assert_eq!(out.len(), 1);
        assert_eq!(next(&mut out), Ok(Fetch::Drained));
        assert_eq!(next(&mut out), Ok(Fetch::Waiting));
    }

    #[test]
    fn missing_channel_reports_15007() {
        let e = channel_enabled("Predator-No-Such/Channel").unwrap_err();
        assert_eq!(e.code, ERROR_EVT_CHANNEL_NOT_FOUND);
        assert!(channel_enabled("System").unwrap());
    }

    /// The Security query's XPath must be accepted by the wevtapi query engine. The Security
    /// channel itself needs admin rights, so validate the same expressions against System.
    #[test]
    fn security_query_is_accepted_by_wevtapi() {
        let q = super::super::logon::SECURITY_QUERY.replace("\"Security\"", "\"System\"");
        let w = wide(&q);
        // SAFETY: valid query string; result handle closed by EvtHandle.
        let h = unsafe { EvtQuery(0, std::ptr::null(), w.as_ptr(), EvtQueryChannelPath | EvtQueryForwardDirection) };
        let h = EvtHandle::from_raw(h);
        assert!(h.is_some(), "query rejected: {}", WinError::last("EvtQuery"));
        for (query, channel) in [
            (super::super::ssh::OPENSSH_QUERY, super::super::ssh::OPENSSH_CHANNEL),
            (super::super::ssh::OPENSSH_ADMIN_QUERY, super::super::ssh::OPENSSH_ADMIN_CHANNEL),
        ] {
            let ssh = query.replace(channel, "System");
            let w = wide(&ssh);
            // SAFETY: as above.
            let h =
                unsafe { EvtQuery(0, std::ptr::null(), w.as_ptr(), EvtQueryChannelPath | EvtQueryForwardDirection) };
            assert!(EvtHandle::from_raw(h).is_some(), "ssh query rejected: {}", WinError::last("EvtQuery"));
        }
    }

    /// Live: a bookmark taken from a reverse query (`Direction='backward'`, as produced by the
    /// fresh-start positioning) must resume FORWARD after that record with Strict.
    #[test]
    #[ignore]
    fn live_backward_bookmark_resumes_forward() {
        let ch = super::super::ssh::OPENSSH_CHANNEL;
        let path = wide(ch);
        let q = wide("*");
        // SAFETY: valid strings; handles owned by EvtHandle.
        let h = unsafe { EvtQuery(0, path.as_ptr(), q.as_ptr(), EvtQueryChannelPath | EvtQueryReverseDirection) };
        let Some(query) = EvtHandle::from_raw(h) else {
            println!("OpenSSH channel unavailable");
            return;
        };
        let mut raw = [0 as EVT_HANDLE; 5];
        let mut n = 0u32;
        // SAFETY: room for 5 handles.
        assert_ne!(unsafe { EvtNext(query.raw(), 5, raw.as_mut_ptr(), 2000, 0, &mut n) }, 0);
        let evs: Vec<EvtHandle> = raw.iter().take(n as usize).filter_map(|&h| EvtHandle::from_raw(h)).collect();
        assert_eq!(evs.len(), 5);
        let mut r = Renderer::default();
        let ids: Vec<u64> = evs
            .iter()
            .map(|e| super::super::xml::parse_event(&r.render(e.raw(), EvtRenderEventXml).unwrap()).unwrap().record_id)
            .collect();
        let bm = create_bookmark(None).unwrap();
        // SAFETY: live handles. Position on the 5th newest record.
        assert_ne!(unsafe { EvtUpdateBookmark(bm.raw(), evs[4].raw()) }, 0);
        let xml = r.render(bm.raw(), EvtRenderBookmark).unwrap();
        println!("reverse-query bookmark: {}", xml.replace("\r\n", " "));
        let signal = crate::util::win::OwnedEvent::create(true, true).unwrap();
        let sub = subscribe(
            signal.raw(),
            super::super::ssh::OPENSSH_QUERY,
            create_bookmark(Some(&xml)).unwrap().raw(),
            EvtSubscribeStartAfterBookmark | EvtSubscribeStrict,
        );
        let sub = sub.unwrap();
        let mut got = [0 as EVT_HANDLE; 16];
        let mut m = 0u32;
        // SAFETY: room for 16 handles.
        let ok = unsafe { EvtNext(sub.raw(), 16, got.as_mut_ptr(), 0, 0, &mut m) };
        let got: Vec<EvtHandle> = if ok != 0 {
            got.iter().take(m as usize).filter_map(|&h| EvtHandle::from_raw(h)).collect()
        } else {
            vec![]
        };
        let got_ids: Vec<u64> = got
            .iter()
            .map(|e| super::super::xml::parse_event(&r.render(e.raw(), EvtRenderEventXml).unwrap()).unwrap().record_id)
            .collect();
        println!("newest five (reverse) = {ids:?}; delivered after bookmark = {got_ids:?}");
        let mut expected: Vec<u64> = ids[..4].to_vec();
        expected.reverse();
        assert_eq!(got_ids, expected);
    }

    #[test]
    fn unusable_bookmark_reports_gap_and_keeps_the_file() {
        let dir = std::env::temp_dir().join(format!("predator-evt-gap-{}", crate::util::rand::hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("system.xml");
        // a position far beyond the end of the System log (as after a clear + restart)
        std::fs::write(
            &path,
            "<BookmarkList><Bookmark Channel='System' RecordId='999999999999' IsCurrent='true'/></BookmarkList>",
        )
        .unwrap();
        let signal = crate::util::win::OwnedEvent::create(true, true).unwrap();
        let q = "<QueryList><Query Id=\"0\" Path=\"System\"><Select Path=\"System\">*[System[EventID=65000]]</Select></Query></QueryList>";
        let (sub, gap) = Subscription::open("System", q, signal.raw(), &path).unwrap();
        let gap = gap.expect("unusable bookmark must be reported as a gap");
        assert_eq!(gap.last_record_id, Some(999_999_999_999));
        assert_eq!(classify_error(gap.code), ErrorClass::BookmarkUnusable, "code {}", gap.code);
        assert!(!sub.is_positioned());
        assert!(path.exists(), "stale bookmark kept until the caller reported the gap");
        drop(sub);
        // the gap is detected again by the next attempt (e.g. after a failed fallback)
        let (_sub, again) = Subscription::open("System", q, signal.raw(), &path).unwrap();
        assert_eq!(again, Some(gap));
        // an empty bookmark (no position) is simply discarded, without a gap
        std::fs::write(&path, "<BookmarkList>\r\n</BookmarkList>").unwrap();
        let (_sub, none) = Subscription::open("System", q, signal.raw(), &path).unwrap();
        assert_eq!(none, None);
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bookmark_roundtrip_on_system_channel() {
        let Ok(Some(newest)) = newest_record("System") else {
            return; // empty/inaccessible System log: nothing to verify
        };
        let mut r = Renderer::default();
        let xml = r.render(newest.raw(), EvtRenderEventXml).unwrap();
        let rec = super::super::xml::parse_event(&xml).unwrap();
        assert!(rec.record_id > 0);
        assert_eq!(rec.channel, "System");
        let bm = create_bookmark(None).unwrap();
        // SAFETY: live handles.
        assert_ne!(unsafe { EvtUpdateBookmark(bm.raw(), newest.raw()) }, 0);
        let bxml = r.render(bm.raw(), EvtRenderBookmark).unwrap();
        assert_eq!(bookmark_record_id(&bxml), Some(rec.record_id));
        assert!(create_bookmark(Some(&bxml)).is_ok());
        // measured here: 87 (ERROR_INVALID_PARAMETER) for this input, 15008 for other malformed
        // XML — `Subscription::open` treats any EvtCreateBookmark failure as "start fresh + gap"
        let bad = create_bookmark(Some("<not a bookmark")).unwrap_err();
        assert!(bad.code == 87 || bad.code == 15008, "unexpected {bad}");
    }
}
