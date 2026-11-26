//! Notifications: structured login/system events, their persistent outgoing queue, and the
//! login history ring buffer.

pub mod format;
pub mod history;
pub mod queue;

use serde::{Deserialize, Serialize};

/// What kind of event a notification describes (drives feature gating and formatting).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    /// Successful interactive / RDP / unlock / cached Windows logon (4624) or RDP reconnect (4778).
    #[default]
    Login,
    /// Failed Windows logon (4625).
    FailedLogin,
    /// Windows logoff (4647/4634) or RDP disconnect (4779).
    Logout,
    /// Successful SSH authentication ("Accepted ...").
    SshLogin,
    /// Failed SSH authentication ("Failed password ...", "Invalid user ...").
    SshFailed,
    /// SSH session closed ("Disconnected from user ...").
    SshLogout,
    /// Service lifecycle / informational (online, offline, resumed, audit-policy drift ...).
    System,
    /// Security relevant (unauthorized Telegram access, audit log cleared ...).
    Security,
}

impl NotificationKind {
    /// Login-type events that are recorded in the login history.
    pub fn is_history(self) -> bool {
        !matches!(self, NotificationKind::System | NotificationKind::Security)
    }

    /// True for SSH-sourced events.
    pub fn is_ssh(self) -> bool {
        matches!(self, NotificationKind::SshLogin | NotificationKind::SshFailed | NotificationKind::SshLogout)
    }
}

/// Structured description of a login-related event, produced by the monitors and rendered to
/// Telegram HTML by [`format::render_event`]. Also the element type of the login history.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventDetails {
    pub kind: NotificationKind,
    /// Computer name (e.g. `MY-PC`).
    pub computer: String,
    /// Account name for display (`alice`, `MY-PC\alice`, `AzureAD\JohnDoe`, `user@contoso.com`).
    pub user: String,
    /// Login method for display: `Interactive`, `Remote Desktop`, `Unlock`, `Cached credentials`,
    /// `SSH (publickey)`, `Network`, `Session reconnected` ...
    pub method: String,
    /// Source IP when known (RDP, SSH, network logons).
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Remote client host name when known (RDP ClientName / workstation name).
    #[serde(default)]
    pub source_host: Option<String>,
    /// Failure reason (failed logins) or logout type (`User-initiated logoff`, `Session disconnected`).
    #[serde(default)]
    pub reason: Option<String>,
    /// Original event time (Unix seconds, from the event record — preserved through the queue).
    pub event_unix: i64,
    /// Success flag (false for failures).
    #[serde(default)]
    pub success: bool,
    /// Optional extra key/value lines (e.g. `Key: ED25519 SHA256:...`).
    #[serde(default)]
    pub extra: Vec<(String, String)>,
}

/// One queued outgoing Telegram message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    /// Monotonic id within the queue.
    pub id: u64,
    pub kind: NotificationKind,
    /// Time of the underlying event (Unix seconds).
    pub event_unix: i64,
    /// Time it was queued (Unix seconds).
    pub queued_unix: i64,
    /// Telegram-HTML message body (already escaped/rendered).
    pub html: String,
    /// Optional idempotency key (`<channel>:<EventRecordID>:<TimeCreated FILETIME>`, e.g.
    /// `security:5:134400621151884769` — survives log clears) used to drop
    /// duplicates after a crash/replay.
    #[serde(default)]
    pub dedupe_key: Option<String>,
    /// Chats (= Telegram user ids) that already have it. The sender delivers to every authorized
    /// user not listed here and acks the notification once all of them are covered; the list is
    /// persisted (coalesced like acks), so a restart does not deliver it to them again. Also
    /// pre-filled to exclude recipients (e.g. the user a "new user paired" notice is about).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivered_to: Vec<i64>,
}
