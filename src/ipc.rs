//! Local IPC between the tray app and the service over a named pipe
//! (`\\.\pipe\PredatorRemoteController`).
//!
//! Protocol: one request per connection. The client writes one JSON [`IpcRequest`] terminated by
//! `\n`, the server answers one JSON [`IpcResponse`] terminated by `\n`, then closes.
//!
//! Security:
//! * Pipe DACL: SYSTEM + Administrators full, Interactive users read/write, network logons denied,
//!   `PIPE_REJECT_REMOTE_CLIENTS`.
//! * Server authorizes every request by impersonating the client: allowed = LocalSystem, the
//!   configured owner Windows SID, or an elevated Administrator. Others get `Denied`. Codes for
//!   Admin accounts and `RemoveUser` additionally need LocalSystem or elevation (`Error`
//!   otherwise): every unelevated process of the owner's session has the owner SID.
//! * Client verifies the server: `GetNamedPipeServerProcessId` must equal the PID the SCM reports
//!   for the Predator service (prevents pipe squatting by another process).
//!
//! Compatibility: variants and fields are only ever added (older trays and CLIs keep working
//! with a newer service, and an older service answers a request it does not know with `Error`).
//!
//! Pairing (adding a Telegram account): `StartPairing` creates the single active one-time code in
//! the service (see [`crate::pairing`]). The code travels only over this pipe to the caller,
//! which shows it on the PC; it is never sent to Telegram and never logged.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Service status snapshot (cheap; uses cached Tailscale state).
    Status,
    /// Enable/disable a feature by key (see `Feature::key`).
    SetFeature { feature: String, enabled: bool },
    /// Refresh and return Tailscale status (spawns the Tailscale CLI).
    TailscaleStatus,
    /// Restart the Predator service (performed by a detached SYSTEM helper).
    RestartService,
    /// Re-read `settings.json` (sent by CLI commands that edited it while the service runs).
    ReloadSettings,
    /// Create (replace) the one-time pairing code; `ttl_secs` is clamped to 60 … 3600 by the
    /// service. `admin` = the account that redeems it becomes an Admin (the first account of an
    /// empty list always does); `admin: true` needs LocalSystem or an elevated administrator
    /// (the owner SID alone gets `Error`). Answered with [`IpcResponse::Pairing`].
    StartPairing { ttl_secs: u64, admin: bool },
    /// Whether the code is still active, and who paired since it was created
    /// ([`IpcResponse::PairingState`]).
    PairingStatus,
    /// Forget the active pairing code.
    CancelPairing,
    /// Every authorized Telegram account ([`IpcResponse::Users`]).
    ListUsers,
    /// Revoke a Telegram account (by numeric user id). The last admin cannot be removed. Needs
    /// LocalSystem or an elevated administrator (the owner SID alone gets `Error`).
    RemoveUser { id: i64 },
}

/// One authorized Telegram account as reported over IPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// Numeric Telegram user id (the identity used for authorization).
    pub id: i64,
    /// Display only (`@username`, the first name, or `user <id>`).
    pub name: String,
    /// `admin` or `user` (the serialized [`crate::config::UserRole`]).
    pub role: String,
    /// When the account was added (Unix seconds; 0 = unknown).
    pub added_unix: i64,
}

impl UserInfo {
    pub fn from_user(u: &crate::config::AuthorizedUser) -> Self {
        Self { id: u.id, name: u.label(), role: u.role.key().to_string(), added_unix: u.added_unix }
    }

    /// `Admin` / `User` (unknown values from a newer service are shown cleaned up as they are).
    pub fn role_label(&self) -> String {
        match self.role.trim().to_ascii_lowercase().as_str() {
            "admin" => "Admin".into(),
            "user" => "User".into(),
            _ => one_line(&self.role),
        }
    }

    pub fn is_admin(&self) -> bool {
        self.role.trim().eq_ignore_ascii_case("admin")
    }

    /// The name on one line (never empty).
    pub fn display_name(&self) -> String {
        let n = one_line(&self.name);
        if n.is_empty() { format!("user {}", self.id) } else { n }
    }
}

/// Runs of control characters and whitespace become one space; trimmed. Values from the other
/// side of the pipe can never add lines to a dialog or the console.
fn one_line(s: &str) -> String {
    s.split(|c: char| c.is_control() || c.is_whitespace()).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ")
}

/// A syntactically valid bot username without the `@` (letters, digits, `_`; at most 64).
pub fn bot_username(raw: &str) -> Option<&str> {
    let u = raw.trim().trim_start_matches('@');
    (!u.is_empty() && u.len() <= 64 && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')).then_some(u)
}

/// The deep link that opens the bot and redeems `code` with one tap on Start:
/// `https://t.me/<bot>?start=pair-<code>`. `None` for an invalid username or a code that is not
/// 8 digits.
pub fn pairing_deep_link(bot: &str, code: &str) -> Option<String> {
    let bot = bot_username(bot)?;
    let code = crate::pairing::normalize_code(code)?;
    Some(format!("https://t.me/{bot}?start=pair-{code}"))
}

/// Where a pairing started by this client stands (from one `PairingState` reply).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingProgress {
    /// Our code is still active.
    Waiting,
    /// An account was paired with the code.
    Paired {
        name: String,
        id: i64,
    },
    Expired,
    /// Another code replaced ours (pairing was started again, here or elsewhere).
    Replaced,
    /// Cancelled, invalidated after too many wrong guesses, or lost with a service restart.
    Invalidated,
}

/// Classify a `PairingState` reply for the code that expires at `ours` (the `expires_unix` of
/// our `Pairing` reply; it identifies the code without revealing it).
pub fn pairing_progress(
    active: bool,
    expires_unix: Option<i64>,
    paired: Option<(String, i64)>,
    ours: i64,
    now: i64,
) -> PairingProgress {
    if let Some((name, id)) = paired {
        return PairingProgress::Paired { name, id };
    }
    match (active, expires_unix) {
        (true, Some(e)) if e == ours => PairingProgress::Waiting,
        (true, _) => PairingProgress::Replaced,
        (false, _) if now >= ours => PairingProgress::Expired,
        (false, _) => PairingProgress::Invalidated,
    }
}

/// [`pairing_progress`] for a whole reply (`None` for any other reply).
pub fn progress_of(resp: &IpcResponse, ours: i64, now: i64) -> Option<PairingProgress> {
    match resp {
        IpcResponse::PairingState { active, expires_unix, paired_name, paired_id, .. } => {
            let paired = paired_id.map(|id| {
                let name = paired_name.as_deref().map(one_line).filter(|n| !n.is_empty());
                (name.unwrap_or_else(|| format!("user {id}")), id)
            });
            Some(pairing_progress(*active, *expires_unix, paired, ours, now))
        }
        _ => None,
    }
}

/// `1234 5678` (easier to read and type; the bot accepts it with or without the space).
pub fn spaced_code(code: &str) -> String {
    match (code.get(..4), code.get(4..)) {
        (Some(a), Some(b)) if !b.is_empty() => format!("{a} {b}"),
        _ => code.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeatureState {
    pub key: String,
    pub label: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ServiceStatusInfo {
    pub version: String,
    pub pid: u32,
    pub uptime_secs: u64,
    /// "online" / "offline" / "invalid token" / "not configured".
    pub telegram: String,
    pub bot_username: Option<String>,
    pub owner_configured: bool,
    pub features: Vec<FeatureState>,
    pub security_monitor: String,
    pub ssh_monitor: String,
    pub queued_notifications: usize,
    pub private_bytes: u64,
    pub working_set_bytes: u64,
    /// One-line Tailscale summary from cache, e.g. "Connected · 100.64.0.5" (None if unknown).
    pub tailscale: Option<String>,
    pub dry_run: bool,
    /// HTTPS transport used for Telegram, e.g. "direct (SChannel)" or "WinHTTP (default proxy)".
    /// Absent from older services (serde default), so old and new tray/service versions interoperate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
}

// A response is built once, serialized and dropped (or parsed once and consumed); boxing the
// large Status variant would only add a heap allocation per request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    Status(ServiceStatusInfo),
    Ok {
        message: String,
    },
    Tailscale {
        summary: String,
        connected: bool,
    },
    Denied {
        reason: String,
    },
    Error {
        message: String,
    },
    /// Reply to `StartPairing`: the new code (8 digits), when it expires, and the bot to send it
    /// to (None while the bot username is not known yet).
    Pairing {
        code: String,
        expires_unix: i64,
        bot_username: Option<String>,
    },
    /// Reply to `PairingStatus`. `active` = the code can be redeemed now; `paired_*` = the
    /// account paired since the last `StartPairing` (None while nobody has).
    PairingState {
        active: bool,
        expires_unix: Option<i64>,
        paired_name: Option<String>,
        paired_id: Option<i64>,
        paired_unix: Option<i64>,
    },
    /// Reply to `ListUsers`.
    Users {
        users: Vec<UserInfo>,
    },
}

/// Send one request to the service and wait for the reply (client side, used by the tray).
/// Verifies the pipe server is the real Predator service process.
pub fn request(req: &IpcRequest, timeout: Duration) -> Result<IpcResponse, String> {
    crate::service::pipe::client_request(
        crate::paths::PIPE_NAME,
        req,
        timeout,
        crate::service::pipe::ServerCheck::PredatorService,
    )
}

/// Like [`request`], for a caller that has just queried the SCM itself: the pipe server must be
/// `service_pid` (saves a second SCM round trip). `service_pid == 0` is always refused.
pub fn request_to_pid(req: &IpcRequest, timeout: Duration, service_pid: u32) -> Result<IpcResponse, String> {
    crate::service::pipe::client_request(
        crate::paths::PIPE_NAME,
        req,
        timeout,
        crate::service::pipe::ServerCheck::Pid(service_pid),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r = IpcRequest::SetFeature { feature: "ssh_monitoring".into(), enabled: false };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"cmd":"set_feature","feature":"ssh_monitoring","enabled":false}"#);
        assert_eq!(serde_json::from_str::<IpcRequest>(r#"{"cmd":"status"}"#).unwrap(), IpcRequest::Status);
        assert_eq!(serde_json::to_string(&IpcRequest::ReloadSettings).unwrap(), r#"{"cmd":"reload_settings"}"#);
        assert_eq!(
            serde_json::from_str::<IpcRequest>(r#"{"cmd":"reload_settings"}"#).unwrap(),
            IpcRequest::ReloadSettings
        );
        let resp = IpcResponse::Denied { reason: "x".into() };
        let s = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<IpcResponse>(&s).unwrap(), resp);
    }

    fn roundtrip_request(r: &IpcRequest, json: &str) {
        assert_eq!(serde_json::to_string(r).unwrap(), json);
        assert_eq!(&serde_json::from_str::<IpcRequest>(json).unwrap(), r);
    }

    fn roundtrip_response(r: &IpcResponse, json: &str) {
        assert_eq!(serde_json::to_string(r).unwrap(), json);
        assert_eq!(&serde_json::from_str::<IpcResponse>(json).unwrap(), r);
    }

    #[test]
    fn pairing_and_user_wire_format() {
        roundtrip_request(
            &IpcRequest::StartPairing { ttl_secs: 600, admin: false },
            r#"{"cmd":"start_pairing","ttl_secs":600,"admin":false}"#,
        );
        roundtrip_request(&IpcRequest::PairingStatus, r#"{"cmd":"pairing_status"}"#);
        roundtrip_request(&IpcRequest::CancelPairing, r#"{"cmd":"cancel_pairing"}"#);
        roundtrip_request(&IpcRequest::ListUsers, r#"{"cmd":"list_users"}"#);
        roundtrip_request(&IpcRequest::RemoveUser { id: 123456789 }, r#"{"cmd":"remove_user","id":123456789}"#);

        roundtrip_response(
            &IpcResponse::Pairing { code: "12345678".into(), expires_unix: 1_800_000_600, bot_username: None },
            r#"{"type":"pairing","code":"12345678","expires_unix":1800000600,"bot_username":null}"#,
        );
        roundtrip_response(
            &IpcResponse::PairingState {
                active: false,
                expires_unix: None,
                paired_name: Some("@alice".into()),
                paired_id: Some(123456789),
                paired_unix: Some(1_800_000_100),
            },
            r#"{"type":"pairing_state","active":false,"expires_unix":null,"paired_name":"@alice","paired_id":123456789,"paired_unix":1800000100}"#,
        );
        roundtrip_response(
            &IpcResponse::Users {
                users: vec![UserInfo { id: 123456789, name: "@alice".into(), role: "admin".into(), added_unix: 0 }],
            },
            r#"{"type":"users","users":[{"id":123456789,"name":"@alice","role":"admin","added_unix":0}]}"#,
        );
        // the existing variants are unchanged
        roundtrip_request(&IpcRequest::Status, r#"{"cmd":"status"}"#);
        roundtrip_response(&IpcResponse::Ok { message: "m".into() }, r#"{"type":"ok","message":"m"}"#);
    }

    #[test]
    fn older_peers_interoperate() {
        // A newer request that an older service does not know is a parse error (it answers
        // `Error`), never a different request.
        assert!(serde_json::from_str::<IpcRequest>(r#"{"cmd":"frobnicate"}"#).is_err());
        // Missing fields are refused rather than defaulted (no accidental admin codes).
        assert!(serde_json::from_str::<IpcRequest>(r#"{"cmd":"start_pairing","ttl_secs":600}"#).is_err());
        assert!(serde_json::from_str::<IpcRequest>(r#"{"cmd":"remove_user"}"#).is_err());
        // Unknown extra fields from a newer peer are ignored.
        assert_eq!(serde_json::from_str::<IpcRequest>(r#"{"cmd":"list_users","x":1}"#).unwrap(), IpcRequest::ListUsers);
    }

    #[test]
    fn user_info_helpers() {
        let u = crate::config::AuthorizedUser::new(987654321, "bob", crate::config::UserRole::User, 1_800_000_000);
        let info = UserInfo::from_user(&u);
        assert_eq!(
            info,
            UserInfo { id: 987654321, name: "bob".into(), role: "user".into(), added_unix: 1_800_000_000 }
        );
        assert_eq!(info.role_label(), "User");
        assert!(!info.is_admin());
        let nameless = crate::config::AuthorizedUser::new(5, "", crate::config::UserRole::Admin, 0);
        let info = UserInfo::from_user(&nameless);
        assert_eq!((info.name.as_str(), info.role_label().as_str(), info.is_admin()), ("user 5", "Admin", true));
        let odd = UserInfo { id: 7, name: " a\nb ".into(), role: "Owner\r\n".into(), added_unix: 0 };
        assert_eq!((odd.display_name().as_str(), odd.role_label().as_str()), ("a b", "Owner"));
        assert_eq!(UserInfo { name: "  ".into(), ..odd }.display_name(), "user 7");
    }

    #[test]
    fn pairing_progress_classification() {
        use PairingProgress::*;
        let ours = 1_800_000_600;
        let now = ours - 300;
        assert_eq!(pairing_progress(true, Some(ours), None, ours, now), Waiting);
        assert_eq!(
            pairing_progress(false, None, Some(("@alice".into(), 123456789)), ours, now),
            Paired { name: "@alice".into(), id: 123456789 }
        );
        // a pairing result wins even when it is reported after the expiry
        assert!(matches!(pairing_progress(false, None, Some(("bob".into(), 5)), ours, ours + 10), Paired { .. }));
        assert_eq!(pairing_progress(true, Some(ours + 60), None, ours, now), Replaced);
        assert_eq!(pairing_progress(true, None, None, ours, now), Replaced);
        assert_eq!(pairing_progress(false, None, None, ours, ours), Expired);
        assert_eq!(pairing_progress(false, None, None, ours, now), Invalidated);

        let reply = |name: Option<&str>, id: Option<i64>| IpcResponse::PairingState {
            active: false,
            expires_unix: None,
            paired_name: name.map(str::to_string),
            paired_id: id,
            paired_unix: id.map(|_| now),
        };
        assert_eq!(
            progress_of(&reply(Some("@alice\n"), Some(7)), ours, now),
            Some(Paired { name: "@alice".into(), id: 7 })
        );
        assert_eq!(progress_of(&reply(None, Some(7)), ours, now), Some(Paired { name: "user 7".into(), id: 7 }));
        assert_eq!(progress_of(&reply(Some(" "), Some(7)), ours, now), Some(Paired { name: "user 7".into(), id: 7 }));
        assert_eq!(progress_of(&reply(None, None), ours, now), Some(Invalidated));
        assert_eq!(progress_of(&IpcResponse::Ok { message: String::new() }, ours, now), None);
    }

    #[test]
    fn deep_links_and_codes() {
        assert_eq!(
            pairing_deep_link("ExampleBot", "12345678").as_deref(),
            Some("https://t.me/ExampleBot?start=pair-12345678")
        );
        assert_eq!(
            pairing_deep_link("@example_bot", "1234 5678").as_deref(),
            Some("https://t.me/example_bot?start=pair-12345678")
        );
        for (bot, code) in [
            ("", "12345678"),
            ("@", "12345678"),
            ("bad/../bot", "12345678"),
            ("a b", "12345678"),
            ("ExampleBot", "1234567"),
            ("ExampleBot", "12345678&x=1"),
            ("ExampleBot", ""),
        ] {
            assert_eq!(pairing_deep_link(bot, code), None, "{bot:?} {code:?}");
        }
        assert_eq!(pairing_deep_link(&"b".repeat(65), "12345678"), None);
        assert_eq!(bot_username(" @ExampleBot "), Some("ExampleBot"));
        assert_eq!(spaced_code("12345678"), "1234 5678");
        assert_eq!(spaced_code("1234"), "1234");
        assert_eq!(spaced_code(""), "");
    }
}
