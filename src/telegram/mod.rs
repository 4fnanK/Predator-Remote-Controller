//! Telegram Bot API: types, HTTPS client (direct SChannel transport, WinHTTP fallback), UI builders
//! and the command dispatcher.

pub mod api;
pub mod bot;
pub mod janitor;
pub mod types;
pub mod ui;

use std::fmt;

use types::InlineKeyboardMarkup;

/// Telegram API error classification (drives retry/backoff decisions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TgError {
    /// DNS/TCP/TLS/timeout — retry with backoff.
    Network(String),
    /// HTTP 401 — the bot token is invalid/revoked. Retrying will not help.
    Unauthorized,
    /// HTTP 403 — e.g. the user blocked the bot / bot kicked from chat.
    Forbidden(String),
    /// HTTP 400 — malformed request (bad HTML, message not found ...). Do not retry as-is.
    BadRequest(String),
    /// HTTP 409 — another getUpdates consumer or a webhook is active.
    Conflict(String),
    /// HTTP 429 — retry after the given number of seconds.
    RateLimited(u64),
    /// HTTP 5xx or other unexpected status.
    Server(u16, String),
    /// Response could not be parsed.
    Parse(String),
}

impl TgError {
    /// Whether retrying the same request later can succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, TgError::Network(_) | TgError::RateLimited(_) | TgError::Server(..) | TgError::Conflict(_))
    }
}

impl fmt::Display for TgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TgError::Network(m) => write!(f, "network error: {m}"),
            TgError::Unauthorized => write!(f, "invalid bot token (401 Unauthorized)"),
            TgError::Forbidden(m) => write!(f, "forbidden: {m}"),
            TgError::BadRequest(m) => write!(f, "bad request: {m}"),
            TgError::Conflict(m) => write!(f, "conflict: {m}"),
            TgError::RateLimited(s) => write!(f, "rate limited, retry after {s}s"),
            TgError::Server(c, m) => write!(f, "server error {c}: {m}"),
            TgError::Parse(m) => write!(f, "invalid response: {m}"),
        }
    }
}

impl std::error::Error for TgError {}

/// The subset of the Bot API the dispatcher needs. Implemented by [`api::TelegramApi`] and by
/// recording mocks in tests. All text is Telegram HTML (`parse_mode=HTML`).
pub trait Telegram: Send + Sync {
    /// Send a message; returns the new message id.
    fn send_message(&self, chat_id: i64, html: &str, keyboard: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError>;
    /// Edit a message's text + keyboard in place. "message is not modified" must be treated as Ok.
    fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        keyboard: Option<&InlineKeyboardMarkup>,
    ) -> Result<(), TgError>;
    /// Answer a callback query (stops the button spinner). Errors for stale queries are expected.
    fn answer_callback(&self, callback_id: &str, text: Option<&str>, show_alert: bool) -> Result<(), TgError>;
    /// Leave a group/channel the bot was added to.
    fn leave_chat(&self, chat_id: i64) -> Result<(), TgError>;
    /// Delete messages in a chat (automatic chat cleanup). Ids Telegram cannot find or may not
    /// delete (already gone, older than 48 hours) are skipped, not reported as errors. The default
    /// does nothing, so implementations without cleanup support need no change.
    fn delete_messages(&self, chat_id: i64, message_ids: &[i64]) -> Result<(), TgError> {
        let _ = (chat_id, message_ids);
        Ok(())
    }
}
