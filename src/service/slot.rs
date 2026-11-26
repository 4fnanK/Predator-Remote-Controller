//! Indirection layers handed to the bot dispatcher:
//!
//! * [`TelegramSlot`] — implements [`Telegram`] by delegating to the current [`TelegramApi`]
//!   (which can be (re)loaded at runtime when the token is configured or replaced). In console
//!   mode it also echoes every outgoing bot call to stdout, and without a token it simulates them
//!   so the full dispatcher can be exercised offline.
//! * [`ObservedSystem`] — wraps [`RealSystem`] and remembers the last Tailscale status so the tray
//!   status (IPC) never has to spawn `tailscale.exe`.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::sys::{
    BatteryInfo, NetworkInfo, PowerAction, RealSystem, ServiceState, SystemActions, SystemStatus, TailscaleOpResult,
    TailscaleStatus,
};
use crate::telegram::api::TelegramApi;
use crate::telegram::types::InlineKeyboardMarkup;
use crate::telegram::{Telegram, TgError};

struct Current {
    api: Arc<TelegramApi>,
    generation: u64,
    fingerprint: u64,
}

pub(crate) struct TelegramSlot {
    current: RwLock<Option<Current>>,
    generation: AtomicU64,
    /// Console mode: print every bot call; simulate them when no token is configured.
    echo: bool,
    fake_ids: AtomicI64,
}

/// Non-reversible fingerprint of a token (to detect a changed token.dat without keeping a copy).
pub(crate) fn token_fingerprint(token: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    token.hash(&mut h);
    h.finish()
}

impl TelegramSlot {
    pub fn new(echo: bool) -> Self {
        Self { current: RwLock::new(None), generation: AtomicU64::new(0), echo, fake_ids: AtomicI64::new(1_000_000) }
    }

    /// Install (or clear) the API client. Returns the new generation.
    pub fn set(&self, api: Option<TelegramApi>, fingerprint: u64) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) =
            api.map(|a| Current { api: Arc::new(a), generation, fingerprint });
        generation
    }

    /// Current client and its generation (changes whenever the token is replaced).
    pub fn current(&self) -> Option<(Arc<TelegramApi>, u64)> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| (c.api.clone(), c.generation))
    }

    pub fn fingerprint(&self) -> Option<u64> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| c.fingerprint)
    }

    pub fn is_configured(&self) -> bool {
        self.current.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    fn api(&self) -> Option<Arc<TelegramApi>> {
        self.current().map(|(a, _)| a)
    }

    fn not_configured() -> TgError {
        TgError::Network("Telegram is not configured (no bot token)".into())
    }

    fn print(&self, what: &str, chat_id: i64, html: Option<&str>, keyboard: Option<&InlineKeyboardMarkup>) {
        let mut out = format!("\n[bot → chat {chat_id}] {what}");
        if let Some(h) = html {
            out.push('\n');
            out.push_str(&super::text::html_to_plain(h));
        }
        if let Some(kb) = keyboard {
            for row in &kb.inline_keyboard {
                let cells: Vec<String> = row
                    .iter()
                    .map(|b| match (&b.callback_data, &b.url) {
                        (Some(d), _) => format!("[{} ({d})]", b.text),
                        (None, Some(u)) => format!("[{} <{u}>]", b.text),
                        _ => format!("[{}]", b.text),
                    })
                    .collect();
                out.push_str("\n  ");
                out.push_str(&cells.join(" "));
            }
        }
        println!("{out}");
    }
}

impl Telegram for TelegramSlot {
    fn send_message(&self, chat_id: i64, html: &str, keyboard: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
        match self.api() {
            Some(api) => {
                let r = api.send_message(chat_id, html, keyboard);
                if self.echo {
                    let what = match &r {
                        Ok(id) => format!("sendMessage → message {id}"),
                        Err(e) => format!("sendMessage FAILED: {e}"),
                    };
                    self.print(&what, chat_id, Some(html), keyboard);
                }
                r
            }
            None if self.echo => {
                let id = self.fake_ids.fetch_add(1, Ordering::Relaxed);
                self.print(&format!("sendMessage (simulated, message {id})"), chat_id, Some(html), keyboard);
                Ok(id)
            }
            None => Err(Self::not_configured()),
        }
    }

    fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        keyboard: Option<&InlineKeyboardMarkup>,
    ) -> Result<(), TgError> {
        match self.api() {
            Some(api) => {
                let r = api.edit_message(chat_id, message_id, html, keyboard);
                if self.echo {
                    let what = match &r {
                        Ok(()) => format!("editMessage {message_id}"),
                        Err(e) => format!("editMessage {message_id} FAILED: {e}"),
                    };
                    self.print(&what, chat_id, Some(html), keyboard);
                }
                r
            }
            None if self.echo => {
                self.print(&format!("editMessage {message_id} (simulated)"), chat_id, Some(html), keyboard);
                Ok(())
            }
            None => Err(Self::not_configured()),
        }
    }

    fn answer_callback(&self, callback_id: &str, text: Option<&str>, show_alert: bool) -> Result<(), TgError> {
        if self.echo {
            let t = text.unwrap_or("");
            println!("[bot] answerCallback {callback_id}: {t}{}", if show_alert { " (alert)" } else { "" });
        }
        match self.api() {
            Some(api) => api.answer_callback(callback_id, text, show_alert),
            None if self.echo => Ok(()),
            None => Err(Self::not_configured()),
        }
    }

    fn leave_chat(&self, chat_id: i64) -> Result<(), TgError> {
        if self.echo {
            println!("[bot] leaveChat {chat_id}");
        }
        match self.api() {
            Some(api) => api.leave_chat(chat_id),
            None if self.echo => Ok(()),
            None => Err(Self::not_configured()),
        }
    }

    fn delete_messages(&self, chat_id: i64, message_ids: &[i64]) -> Result<(), TgError> {
        if message_ids.is_empty() {
            return Ok(());
        }
        match self.api() {
            Some(api) => {
                let r = api.delete_messages(chat_id, message_ids);
                if self.echo {
                    let outcome = match &r {
                        Ok(()) => "ok".to_string(),
                        Err(e) => format!("FAILED: {e}"),
                    };
                    println!("[bot → chat {chat_id}] deleteMessages {message_ids:?}: {outcome}");
                }
                r
            }
            None if self.echo => {
                println!("[bot → chat {chat_id}] deleteMessages {message_ids:?} (simulated)");
                Ok(())
            }
            None => Err(Self::not_configured()),
        }
    }
}

/// [`RealSystem`] plus a passive cache of the last Tailscale status.
pub(crate) struct ObservedSystem {
    inner: Arc<RealSystem>,
    last_ts: Mutex<Option<(i64, TailscaleStatus)>>,
}

impl ObservedSystem {
    pub fn new(inner: Arc<RealSystem>) -> Self {
        Self { inner, last_ts: Mutex::new(None) }
    }

    fn remember(&self, s: &TailscaleStatus) {
        *self.last_ts.lock().unwrap_or_else(|e| e.into_inner()) = Some((crate::util::time::now_unix(), s.clone()));
    }

    /// Last known Tailscale status if younger than `max_age_secs`. Never spawns anything.
    pub fn cached_tailscale(&self, max_age_secs: i64) -> Option<TailscaleStatus> {
        let now = crate::util::time::now_unix();
        self.last_ts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|(t, _)| now - *t <= max_age_secs)
            .map(|(_, s)| s.clone())
    }
}

impl SystemActions for ObservedSystem {
    fn check_power(&self, action: PowerAction) -> Result<(), String> {
        self.inner.check_power(action)
    }
    fn execute_power(&self, action: PowerAction) -> Result<String, String> {
        self.inner.execute_power(action)
    }
    fn lock(&self) -> Result<String, String> {
        self.inner.lock()
    }
    fn logout(&self) -> Result<String, String> {
        self.inner.logout()
    }
    fn network(&self) -> Result<NetworkInfo, String> {
        self.inner.network()
    }
    fn battery(&self) -> Result<BatteryInfo, String> {
        self.inner.battery()
    }
    fn tailscale_status(&self) -> TailscaleStatus {
        let s = self.inner.tailscale_status();
        self.remember(&s);
        s
    }
    fn tailscale_up(&self) -> TailscaleOpResult {
        let r = self.inner.tailscale_up();
        self.remember(&r.status);
        r
    }
    fn tailscale_down(&self) -> TailscaleOpResult {
        let r = self.inner.tailscale_down();
        self.remember(&r.status);
        r
    }
    fn system_status(&self) -> SystemStatus {
        self.inner.system_status()
    }
    fn is_dry_run(&self) -> bool {
        self.inner.is_dry_run()
    }
}

/// One-line Tailscale summary for the tray, e.g. `Connected · 100.64.0.5`.
pub(crate) fn tailscale_summary(s: &TailscaleStatus) -> String {
    if !s.installed {
        return "Not installed".into();
    }
    if s.connected {
        return match &s.ipv4 {
            Some(ip) => format!("Connected · {ip}"),
            None => "Connected".into(),
        };
    }
    match s.backend_state.as_deref() {
        Some("NeedsLogin") => "Needs login".into(),
        Some("NeedsMachineAuth") => "Waiting for admin approval".into(),
        Some("Stopped") => "Disconnected".into(),
        Some("Starting") => "Connecting…".into(),
        Some(other) if !other.is_empty() => format!("Disconnected ({other})"),
        _ => match (&s.service, &s.error) {
            (ServiceState::Stopped, _) => "Disconnected (service stopped)".into(),
            (_, Some(e)) => format!("Unknown: {}", crate::util::truncate_chars(e, 80)),
            (st, None) => format!("Disconnected (service {})", st.label().to_lowercase()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries() {
        let mut s = TailscaleStatus::default();
        assert_eq!(tailscale_summary(&s), "Not installed");
        s.installed = true;
        s.connected = true;
        s.ipv4 = Some("100.64.0.5".into());
        assert_eq!(tailscale_summary(&s), "Connected · 100.64.0.5");
        s.connected = false;
        s.backend_state = Some("NeedsLogin".into());
        assert_eq!(tailscale_summary(&s), "Needs login");
        s.backend_state = Some("Stopped".into());
        assert_eq!(tailscale_summary(&s), "Disconnected");
        s.backend_state = None;
        s.service = ServiceState::Stopped;
        assert_eq!(tailscale_summary(&s), "Disconnected (service stopped)");
        s.service = ServiceState::Running;
        s.error = Some("boom".into());
        assert_eq!(tailscale_summary(&s), "Unknown: boom");
    }

    #[test]
    fn slot_without_token() {
        let slot = TelegramSlot::new(false);
        assert!(!slot.is_configured());
        assert!(slot.send_message(1, "x", None).is_err());
        let echo = TelegramSlot::new(true);
        let a = echo.send_message(1, "<b>hi</b>", None).unwrap();
        let b = echo.send_message(1, "again", None).unwrap();
        assert_ne!(a, b);
        assert!(echo.edit_message(1, a, "edit", None).is_ok());
        assert_ne!(token_fingerprint("a:b"), token_fingerprint("a:c"));
    }

    #[test]
    fn slot_delete_messages() {
        // nothing to delete never needs a client
        let slot = TelegramSlot::new(false);
        assert_eq!(slot.delete_messages(1, &[]), Ok(()));
        // without a token the deletion is a retryable failure (the janitor keeps the ids) ...
        let e = slot.delete_messages(1, &[5]).unwrap_err();
        assert!(e.is_retryable(), "{e:?}");
        // ... except in console mode, where it is simulated
        assert_eq!(TelegramSlot::new(true).delete_messages(1, &[5, 6]), Ok(()));
    }

    #[test]
    fn passive_cache() {
        let sys = ObservedSystem::new(RealSystem::new(true, 0));
        assert!(sys.cached_tailscale(3600).is_none());
        sys.remember(&TailscaleStatus { installed: true, ..Default::default() });
        assert!(sys.cached_tailscale(3600).is_some());
        assert!(sys.cached_tailscale(-1).is_none());
    }
}
