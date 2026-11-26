//! OpenSSH (Win32-OpenSSH) operational log payload parsing.
//!
//! Every OpenSSH event carries two data fields: `process` (`sshd`, `sshd-session` on 9.8+) and
//! `payload` (the log line). Only the payload is parsed — no message-table formatting needed.
//! Formats (OpenSSH 9.5 inbox, 9.8+ preview builds):
//!
//! * `Accepted <method> for <user> from <ip> port <n> ssh2[: <KEY>]`
//! * `Failed <method> for [invalid user ]<user> from <ip> port <n> ssh2[: <KEY>]`
//! * `Invalid user <user> from <ip> port <n>`
//! * `[error: ]maximum authentication attempts exceeded for [invalid user ]<user> from <ip> port <n> ssh2`
//! * `Disconnected from user <user> <ip> port <n>` / `Disconnected from <ip> port <n>`
//! * `Connection closed by <ip> port <n>` / `Connection reset by <ip> port <n>` /
//!   `Timeout, client not responding from <ip> port <n>` / `Connection from <ip> port <n> timed out`
//!   (post-authentication: the session ended without a clean disconnect)
//!
//! Informational lines are written to `OpenSSH/Operational`; `error:`/`fatal:` lines (e.g.
//! MaxAuthTries) go to `OpenSSH/Admin`, which is read by a second, independent subscription
//! (a two-channel bookmark cannot be resumed with `EvtSubscribeStrict`, see [`OPENSSH_ADMIN_QUERY`]).
//!
//! optionally wrapped as `user: <user>: <line> [preauth]` / `[postauth]` (9.8+). User names are
//! logged as typed by the client, with every backslash escaped (twice for `[preauth]` lines on
//! 9.5); runs of backslashes are collapsed because Windows account names cannot contain them.

use std::collections::HashMap;
use std::path::PathBuf;

use super::Outcome;
use super::xml::EventRecord;
use crate::notify::{EventDetails, NotificationKind};

/// Channel of the OpenSSH server's informational events.
pub const OPENSSH_CHANNEL: &str = "OpenSSH/Operational";

/// Channel of the OpenSSH server's `error:` / `fatal:` events (MaxAuthTries, session errors).
pub const OPENSSH_ADMIN_CHANNEL: &str = "OpenSSH/Admin";

/// Structured subscription query for the OpenSSH operational log.
pub const OPENSSH_QUERY: &str = concat!(
    "<QueryList>",
    "<Query Id=\"0\" Path=\"OpenSSH/Operational\">",
    "<Select Path=\"OpenSSH/Operational\">*[System[Provider[@Name='OpenSSH']]]</Select>",
    "</Query>",
    "</QueryList>"
);

/// Structured subscription query for the OpenSSH admin log. It is deliberately NOT a second
/// `<Select>` of [`OPENSSH_QUERY`]: a bookmark taken from a two-channel subscription records the
/// non-current channel at its *next* record id, so a Strict resume fails with 15011 whenever
/// that channel had no newer record (measured on this machine), and a single-channel bookmark
/// would replay the other channel from its oldest record.
pub const OPENSSH_ADMIN_QUERY: &str = concat!(
    "<QueryList>",
    "<Query Id=\"0\" Path=\"OpenSSH/Admin\">",
    "<Select Path=\"OpenSSH/Admin\">*[System[Provider[@Name='OpenSSH']]]</Select>",
    "</Query>",
    "</QueryList>"
);

/// Maximum characters kept from a public-key description.
const MAX_KEY_CHARS: usize = 200;
/// Maximum tracked SSH sessions / connections.
const MAX_TRACKED: usize = 256;

/// One recognised OpenSSH log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshLine {
    Accepted {
        method: String,
        user: String,
        ip: String,
        port: u16,
        key: Option<String>,
    },
    Failed {
        method: String,
        user: String,
        invalid_user: bool,
        ip: String,
        port: u16,
    },
    InvalidUser {
        user: String,
        ip: String,
        port: u16,
    },
    MaxAuthTries {
        user: String,
        invalid_user: bool,
        ip: String,
        port: u16,
    },
    /// Post-authentication disconnect; `user` is known only for the `Disconnected from user X` form.
    Disconnected {
        user: Option<String>,
        ip: String,
        port: u16,
    },
    /// The connection ended without a clean disconnect (`Connection closed by`, `Connection
    /// reset by`, timeouts). Ends a tracked session; ignored for unknown connections.
    ConnectionLost {
        ip: String,
        port: u16,
        /// Short reason for the logout alert.
        reason: &'static str,
    },
}

/// A payload with its wrappers removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized<'a> {
    pub body: &'a str,
    /// User from a 9.8+ `user: X: ` prefix.
    pub prefix_user: Option<&'a str>,
    /// Line was logged before authentication completed (`[preauth]`).
    pub preauth: bool,
    /// `error` / `fatal` severity prefix, if any.
    pub severity: Option<&'a str>,
}

/// Strip `error: ` / `fatal: ` severities, the `user: X: ` prefix and `[preauth]`/`[postauth]`.
pub fn normalize(payload: &str) -> Normalized<'_> {
    let mut body = payload.trim_end_matches(['\r', '\n', ' ', '\t', '\0']);
    let mut prefix_user = None;
    let mut severity = None;
    for _ in 0..3 {
        if let Some(rest) = body.strip_prefix("error: ") {
            severity = Some("error");
            body = rest;
        } else if let Some(rest) = body.strip_prefix("fatal: ") {
            severity = Some("fatal");
            body = rest;
        } else if let Some(rest) = body.strip_prefix("user: ") {
            match rest.find(": ") {
                Some(i) if prefix_user.is_none() => {
                    prefix_user = Some(&rest[..i]);
                    body = &rest[i + 2..];
                }
                _ => break,
            }
        } else {
            break;
        }
    }
    let mut preauth = false;
    if let Some(rest) = body.strip_suffix(" [preauth]") {
        preauth = true;
        body = rest;
    } else if let Some(rest) = body.strip_suffix(" [postauth]") {
        body = rest;
    }
    Normalized { body, prefix_user, preauth, severity }
}

/// Collapse every run of backslashes to one (undo OpenSSH's strnvis escaping of `DOMAIN\user`).
pub fn unescape_user(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_backslash = false;
    for c in raw.chars() {
        if c == '\\' {
            if !prev_backslash {
                out.push(c);
            }
            prev_backslash = true;
        } else {
            out.push(c);
            prev_backslash = false;
        }
    }
    out
}

fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn valid_ip(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_whitespace)
}

/// Parse `<ip> port <n>` + (when `ssh2`) ` ssh2[: <key>]` covering the whole of `rem`.
fn parse_ip_port_tail(rem: &str, ssh2: bool) -> Option<(String, u16, Option<String>)> {
    let (ip, after_ip) = rem.split_once(' ')?;
    if !valid_ip(ip) {
        return None;
    }
    let after_port_kw = after_ip.strip_prefix("port ")?;
    let digits_end = after_port_kw.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(after_port_kw.len());
    let port = parse_port(&after_port_kw[..digits_end])?;
    let tail = &after_port_kw[digits_end..];
    if !ssh2 {
        return tail.is_empty().then(|| (ip.to_string(), port, None));
    }
    let tail = tail.strip_prefix(" ssh2")?;
    if tail.is_empty() {
        return Some((ip.to_string(), port, None));
    }
    let key = tail.strip_prefix(": ")?.trim();
    let key = (!key.is_empty()).then(|| crate::util::truncate_chars(key, MAX_KEY_CHARS));
    Some((ip.to_string(), port, key))
}

/// Split `<user> from <ip> port <n>[ ssh2[: key]]`. The user part is greedy: the LAST ` from `
/// whose remainder parses wins (Windows user names may contain spaces or even " from ").
fn split_user_from(tail: &str, ssh2: bool) -> Option<(String, String, u16, Option<String>)> {
    let mut end = tail.len();
    while let Some(idx) = tail.get(..end).and_then(|s| s.rfind(" from ")) {
        if let Some((ip, port, key)) = parse_ip_port_tail(&tail[idx + 6..], ssh2) {
            return Some((unescape_user(&tail[..idx]), ip, port, key));
        }
        end = idx;
    }
    // "Invalid user  from ..." with an empty user name has the separator at offset 0 only when
    // the leading space was consumed by the caller's prefix; handle "from ..." directly.
    let rest = tail.strip_prefix("from ")?;
    let (ip, port, key) = parse_ip_port_tail(rest, ssh2)?;
    Some((String::new(), ip, port, key))
}

/// Parse `<user> <ip> port <n>` (the user may be empty or contain spaces).
fn split_user_ip_port(rest: &str) -> Option<(String, String, u16)> {
    let (left, port) = rest.rsplit_once(" port ")?;
    let port = parse_port(port)?;
    let (user, ip) = match left.rsplit_once(' ') {
        Some((u, ip)) => (u, ip),
        None => ("", left),
    };
    valid_ip(ip).then(|| (unescape_user(user), ip.to_string(), port))
}

/// Parse an `Accepted`/`Failed` line body after the keyword.
fn parse_auth(rest: &str, accepted: bool) -> Option<SshLine> {
    let (method, after) = rest.split_once(' ')?;
    if method.is_empty() {
        return None;
    }
    let mut tail = after.strip_prefix("for ")?;
    let mut invalid_user = false;
    if !accepted && let Some(t) = tail.strip_prefix("invalid user ") {
        invalid_user = true;
        tail = t;
    }
    let (user, ip, port, key) = split_user_from(tail, true)?;
    let method = method.to_string();
    Some(if accepted {
        SshLine::Accepted { method, user, ip, port, key }
    } else {
        SshLine::Failed { method, user, invalid_user, ip, port }
    })
}

/// Parse one OpenSSH payload. Unrelated lines (`Server listening ...`, pre-auth disconnects,
/// `Received disconnect ...`) return `None`.
pub fn parse_payload(payload: &str) -> Option<SshLine> {
    let n = normalize(payload);
    let body = n.body;
    if let Some(rest) = body.strip_prefix("Accepted ") {
        return parse_auth(rest, true);
    }
    if let Some(rest) = body.strip_prefix("Failed ") {
        return parse_auth(rest, false);
    }
    if let Some(rest) = body.strip_prefix("Invalid user ") {
        let (user, ip, port, _) = split_user_from(rest, false)?;
        return Some(SshLine::InvalidUser { user, ip, port });
    }
    if let Some(rest) = body.strip_prefix("maximum authentication attempts exceeded for ") {
        let (rest, invalid_user) = match rest.strip_prefix("invalid user ") {
            Some(r) => (r, true),
            None => (rest, false),
        };
        let (user, ip, port, _) = split_user_from(rest, true)?;
        return Some(SshLine::MaxAuthTries { user, invalid_user, ip, port });
    }
    if let Some(rest) = body.strip_prefix("Disconnected from ") {
        let (user, ip, port) = parse_remote_id(rest, &n)?;
        return Some(SshLine::Disconnected { user, ip, port });
    }
    let lost = if let Some(rest) = body.strip_prefix("Connection closed by ") {
        Some((rest, "Connection closed"))
    } else if let Some(rest) = body.strip_prefix("Connection reset by ") {
        Some((rest, "Connection reset"))
    } else if let Some(rest) = body.strip_prefix("Timeout, client not responding from ") {
        Some((rest, "Client stopped responding (timeout)"))
    } else {
        body.strip_prefix("Connection from ")
            .and_then(|r| r.strip_suffix(" timed out"))
            .map(|r| (r, "Connection timed out"))
    };
    if let Some((rest, reason)) = lost {
        let (_, ip, port) = parse_remote_id(rest, &n)?;
        return Some(SshLine::ConnectionLost { ip, port, reason });
    }
    None
}

/// Parse the post-authentication connection id `[user <user> ]<ip> port <n>` of a session-end
/// line. Lines logged before authentication completed (`[preauth]`, `authenticating user`,
/// `invalid user`) are not session ends and return `None`.
fn parse_remote_id(rest: &str, n: &Normalized<'_>) -> Option<(Option<String>, String, u16)> {
    if n.preauth || rest.starts_with("authenticating user ") || rest.starts_with("invalid user ") {
        return None; // connection ended before authentication: not a logout
    }
    if let Some(r) = rest.strip_prefix("user ") {
        let (user, ip, port) = split_user_ip_port(r)?;
        return Some((Some(user), ip, port));
    }
    let (ip, port) = rest.split_once(" port ")?;
    let port = parse_port(port)?;
    if !valid_ip(ip) {
        return None;
    }
    Some((n.prefix_user.map(unescape_user), ip.to_string(), port))
}

/// Display label for an SSH authentication method.
pub fn method_label(method: &str) -> String {
    if method.is_empty() { "SSH".to_string() } else { format!("SSH ({method})") }
}

fn display_user(user: &str) -> String {
    if user.trim().is_empty() { "(empty user name)".to_string() } else { user.to_string() }
}

fn failure_reason(method: &str, invalid_user: bool) -> String {
    if invalid_user {
        "Invalid user".to_string()
    } else if method == "password" {
        "Wrong password".to_string()
    } else if method == "publickey" {
        "Public key rejected".to_string()
    } else {
        format!("Authentication failed ({method})")
    }
}

/// Small bounded map keyed by connection (ip, port), evicting the oldest insertion.
#[derive(Default)]
struct ConnMap<V> {
    map: HashMap<(String, u16), (u64, V)>,
    seq: u64,
}

impl<V> ConnMap<V> {
    fn insert(&mut self, k: (String, u16), v: V) {
        self.seq += 1;
        self.map.insert(k, (self.seq, v));
        if self.map.len() > MAX_TRACKED
            && let Some(oldest) = self.map.iter().min_by_key(|(_, (s, _))| *s).map(|(k, _)| k.clone())
        {
            self.map.remove(&oldest);
        }
    }
    fn remove(&mut self, k: &(String, u16)) -> Option<V> {
        self.map.remove(k).map(|(_, v)| v)
    }
    fn contains(&self, k: &(String, u16)) -> bool {
        self.map.contains_key(k)
    }
}

/// Stateful OpenSSH event classifier: remembers authenticated connections so that the plain
/// `Disconnected from <ip> port <n>` line (9.5 never logs the user there) can be reported as a
/// logout of the right user, and reports an invalid user name only once per connection.
pub struct SshTracker {
    computer: String,
    /// (ip, port) → (user, method label) of accepted sessions.
    sessions: ConnMap<(String, String)>,
    /// Connections already reported as "Invalid user".
    invalid: ConnMap<()>,
}

impl SshTracker {
    pub fn new(computer: &str) -> Self {
        Self { computer: computer.to_string(), sessions: ConnMap::default(), invalid: ConnMap::default() }
    }

    fn details(&self, kind: NotificationKind, user: &str, method: String, ip: &str, unix: i64) -> EventDetails {
        EventDetails {
            kind,
            computer: self.computer.clone(),
            user: display_user(user),
            method,
            source_ip: Some(ip.to_string()),
            source_host: None,
            reason: None,
            event_unix: unix,
            success: matches!(kind, NotificationKind::SshLogin | NotificationKind::SshLogout),
            extra: Vec::new(),
        }
    }

    /// Classify one OpenSSH/Operational event.
    pub fn classify(&mut self, ev: &EventRecord) -> Outcome {
        let process = ev.field("process");
        if !process.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("sshd")) {
            return Outcome::Ignore("not an sshd event");
        }
        let Some(line) = parse_payload(ev.field("payload")) else {
            return Outcome::Ignore("unrelated OpenSSH line");
        };
        let unix = ev.time_unix.unwrap_or_else(crate::util::time::now_unix);
        self.classify_line(line, unix)
    }

    /// Classify an already parsed line (separated for tests).
    pub fn classify_line(&mut self, line: SshLine, unix: i64) -> Outcome {
        match line {
            SshLine::Accepted { method, user, ip, port, key } => {
                let label = method_label(&method);
                self.sessions.insert((ip.clone(), port), (user.clone(), label.clone()));
                let mut d = self.details(NotificationKind::SshLogin, &user, label, &ip, unix);
                if let Some(k) = key {
                    d.extra.push(("Key".to_string(), k));
                }
                Outcome::Event(d)
            }
            SshLine::Failed { method, user, invalid_user, ip, port } => {
                let conn = (ip.clone(), port);
                if invalid_user && self.invalid.contains(&conn) {
                    return Outcome::Ignore("invalid user already reported for this connection");
                }
                if invalid_user {
                    self.invalid.insert(conn, ());
                }
                let mut d = self.details(NotificationKind::SshFailed, &user, method_label(&method), &ip, unix);
                d.reason = Some(failure_reason(&method, invalid_user));
                Outcome::Event(d)
            }
            SshLine::InvalidUser { user, ip, port } => {
                let conn = (ip.clone(), port);
                if self.invalid.contains(&conn) {
                    return Outcome::Ignore("invalid user already reported for this connection");
                }
                self.invalid.insert(conn, ());
                let mut d = self.details(NotificationKind::SshFailed, &user, "SSH".to_string(), &ip, unix);
                d.reason = Some("Invalid user".to_string());
                Outcome::Event(d)
            }
            SshLine::MaxAuthTries { user, invalid_user, ip, .. } => {
                let mut d = self.details(NotificationKind::SshFailed, &user, "SSH".to_string(), &ip, unix);
                d.reason = Some(if invalid_user {
                    "Too many authentication failures (invalid user)".to_string()
                } else {
                    "Too many authentication failures".to_string()
                });
                Outcome::Event(d)
            }
            SshLine::Disconnected { user, ip, port } => {
                let tracked = self.sessions.remove(&(ip.clone(), port));
                self.invalid.remove(&(ip.clone(), port));
                let (user, method) = match (user, tracked) {
                    (_, Some((u, m))) => (u, m),
                    (Some(u), None) => (u, "SSH".to_string()),
                    (None, None) => return Outcome::Ignore("disconnect of an unknown session"),
                };
                let mut d = self.details(NotificationKind::SshLogout, &user, method, &ip, unix);
                d.reason = Some("Disconnected".to_string());
                Outcome::Event(d)
            }
            SshLine::ConnectionLost { ip, port, reason } => {
                let conn = (ip, port);
                self.invalid.remove(&conn);
                let Some((user, method)) = self.sessions.remove(&conn) else {
                    return Outcome::Ignore("connection end of an unknown session");
                };
                let mut d = self.details(NotificationKind::SshLogout, &user, method, &conn.0, unix);
                d.reason = Some(reason.to_string());
                Outcome::Event(d)
            }
        }
    }
}

/// `%ProgramData%\ssh\sshd_config`.
pub fn sshd_config_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("ssh").join("sshd_config")
}

fn split_keyword(line: &str) -> (&str, &str) {
    match line.split_once(|c: char| c.is_whitespace() || c == '=') {
        Some((k, v)) => (k, v.trim_start_matches(|c: char| c.is_whitespace() || c == '=')),
        None => (line, ""),
    }
}

fn first_value(v: &str) -> String {
    v.split_whitespace().next().unwrap_or("").trim_matches('"').to_string()
}

/// Check sshd_config text for settings that hide logins from the OpenSSH event log
/// (keywords are case-insensitive, the first value wins). `Err` carries an explanation of what
/// to change, suitable for showing to the user.
pub fn check_sshd_config(text: &str, path_display: &str) -> Result<(), String> {
    let mut facility: Option<String> = None;
    let mut level: Option<String> = None;
    let mut match_level: Option<String> = None;
    let mut in_match = false;
    for raw in text.lines() {
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (kw, val) = split_keyword(line);
        if kw.eq_ignore_ascii_case("match") {
            in_match = true;
            continue;
        }
        if kw.eq_ignore_ascii_case("syslogfacility") && !in_match && facility.is_none() {
            facility = Some(first_value(val));
        } else if kw.eq_ignore_ascii_case("loglevel") {
            if !in_match && level.is_none() {
                level = Some(first_value(val));
            } else if in_match && match_level.is_none() && hides_logins(&first_value(val)) {
                match_level = Some(first_value(val));
            }
        }
    }
    let restart = "then restart the \"OpenSSH SSH Server\" (sshd) service";
    if facility.as_deref().is_some_and(|f| f.eq_ignore_ascii_case("LOCAL0")) {
        return Err(format!(
            "sshd_config sets 'SyslogFacility LOCAL0', so OpenSSH writes logins to a text file instead of the \
             Windows event log. Remove that line (or use 'SyslogFacility AUTH') in {path_display}, {restart}."
        ));
    }
    if let Some(l) = level.filter(|l| hides_logins(l)) {
        return Err(format!(
            "sshd_config sets 'LogLevel {l}', which hides SSH logins. Set 'LogLevel INFO' (or VERBOSE) in \
             {path_display}, {restart}."
        ));
    }
    if let Some(l) = match_level {
        return Err(format!(
            "sshd_config sets 'LogLevel {l}' inside a Match block, which hides SSH logins of the matching users. \
             Remove it or use 'LogLevel INFO' in {path_display}, {restart}."
        ));
    }
    Ok(())
}

fn hides_logins(level: &str) -> bool {
    ["QUIET", "FATAL", "ERROR"].iter().any(|l| level.eq_ignore_ascii_case(l))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(method: &str, user: &str, ip: &str, port: u16, key: Option<&str>) -> SshLine {
        SshLine::Accepted {
            method: method.into(),
            user: user.into(),
            ip: ip.into(),
            port,
            key: key.map(str::to_string),
        }
    }

    #[test]
    fn accepted_password_and_publickey() {
        assert_eq!(
            parse_payload("Accepted password for alex from 100.64.0.21 port 38652 ssh2"),
            Some(acc("password", "alex", "100.64.0.21", 38652, None))
        );
        assert_eq!(
            parse_payload(
                "Accepted publickey for alex from 100.64.0.21 port 57760 ssh2: ED25519 SHA256:EXAMPLEfingerprintEXAMPLEfingerprintEXAMPLE"
            ),
            Some(acc(
                "publickey",
                "alex",
                "100.64.0.21",
                57760,
                Some("ED25519 SHA256:EXAMPLEfingerprintEXAMPLEfingerprintEXAMPLE")
            ))
        );
        // IPv6 with zone id, user with spaces and a literal " from " inside the name
        assert_eq!(
            parse_payload(
                "Accepted password for John from Accounting from fe80::cd23:df1c:3817:f30e%10 port 33443 ssh2"
            ),
            Some(acc("password", "John from Accounting", "fe80::cd23:df1c:3817:f30e%10", 33443, None))
        );
        assert_eq!(
            parse_payload("Accepted keyboard-interactive for bob from 10.0.0.5 port 22 ssh2\r\n"),
            Some(acc("keyboard-interactive", "bob", "10.0.0.5", 22, None))
        );
    }

    #[test]
    fn failed_and_invalid_users() {
        assert_eq!(
            parse_payload("Failed password for alex from 100.64.0.22 port 59435 ssh2"),
            Some(SshLine::Failed {
                method: "password".into(),
                user: "alex".into(),
                invalid_user: false,
                ip: "100.64.0.22".into(),
                port: 59435
            })
        );
        assert_eq!(
            parse_payload("Failed password for invalid user macarl@microsoft.com from fe80::1%10 port 2029 ssh2"),
            Some(SshLine::Failed {
                method: "password".into(),
                user: "macarl@microsoft.com".into(),
                invalid_user: true,
                ip: "fe80::1%10".into(),
                port: 2029
            })
        );
        assert_eq!(
            parse_payload("Invalid user admin from 203.0.113.9 port 51234"),
            Some(SshLine::InvalidUser { user: "admin".into(), ip: "203.0.113.9".into(), port: 51234 })
        );
        assert_eq!(
            parse_payload("Invalid user  from 203.0.113.9 port 51234"),
            Some(SshLine::InvalidUser { user: "".into(), ip: "203.0.113.9".into(), port: 51234 })
        );
        assert_eq!(
            parse_payload(
                "error: maximum authentication attempts exceeded for invalid user root from 203.0.113.9 port 4 ssh2 [preauth]"
            ),
            Some(SshLine::MaxAuthTries { user: "root".into(), invalid_user: true, ip: "203.0.113.9".into(), port: 4 })
        );
    }

    #[test]
    fn disconnects() {
        assert_eq!(
            parse_payload("Disconnected from user alex 100.64.0.21 port 34840"),
            Some(SshLine::Disconnected { user: Some("alex".into()), ip: "100.64.0.21".into(), port: 34840 })
        );
        assert_eq!(
            parse_payload("Disconnected from 100.64.0.21 port 34840"),
            Some(SshLine::Disconnected { user: None, ip: "100.64.0.21".into(), port: 34840 })
        );
        assert_eq!(
            parse_payload("user: alex: Disconnected from 100.64.0.21 port 34840 [postauth]"),
            Some(SshLine::Disconnected { user: Some("alex".into()), ip: "100.64.0.21".into(), port: 34840 })
        );
        assert_eq!(parse_payload("Disconnected from authenticating user alex 1.2.3.4 port 5 [preauth]"), None);
        assert_eq!(parse_payload("Disconnected from invalid user x 1.2.3.4 port 5 [preauth]"), None);
        assert_eq!(parse_payload("Disconnected from 1.2.3.4 port 5 [preauth]"), None);
    }

    fn lost(ip: &str, port: u16, reason: &'static str) -> Option<SshLine> {
        Some(SshLine::ConnectionLost { ip: ip.into(), port, reason })
    }

    #[test]
    fn post_auth_connection_ends() {
        assert_eq!(
            parse_payload("Connection reset by 100.64.0.22 port 59437"),
            lost("100.64.0.22", 59437, "Connection reset")
        );
        assert_eq!(
            parse_payload("Connection closed by 100.64.0.21 port 38070"),
            lost("100.64.0.21", 38070, "Connection closed")
        );
        assert_eq!(
            parse_payload("Timeout, client not responding from 10.0.0.5 port 2222"),
            lost("10.0.0.5", 2222, "Client stopped responding (timeout)")
        );
        assert_eq!(
            parse_payload("Timeout, client not responding from user alex 10.0.0.5 port 2222"),
            lost("10.0.0.5", 2222, "Client stopped responding (timeout)")
        );
        assert_eq!(
            parse_payload("Connection from fe80::1%10 port 5 timed out"),
            lost("fe80::1%10", 5, "Connection timed out")
        );
        // 9.8+ wrapper
        assert_eq!(
            parse_payload("user: alex: Connection reset by 1.2.3.4 port 5 [postauth]"),
            lost("1.2.3.4", 5, "Connection reset")
        );
        // pre-authentication forms are not session ends
        for l in [
            "Connection closed by 1.2.3.4 port 5 [preauth]",
            "Connection reset by invalid user x 1.2.3.4 port 5 [preauth]",
            "Connection closed by authenticating user alex 1.2.3.4 port 5",
            "Connection from 1.2.3.4 port 5 on 10.0.0.1 port 22",
            "Connection reset by 1.2.3.4 port x",
        ] {
            assert_eq!(parse_payload(l), None, "{l}");
        }
    }

    #[test]
    fn connection_loss_ends_only_tracked_sessions() {
        let mut t = SshTracker::new("DESKTOP-01");
        assert!(matches!(t.classify(&rec("sshd", "Connection reset by 100.64.0.22 port 59437")), Outcome::Ignore(_)));
        event(t.classify(&rec("sshd", "Accepted password for alex from 100.64.0.22 port 59437 ssh2")));
        let d = event(t.classify(&rec("sshd", "Connection reset by 100.64.0.22 port 59437")));
        assert_eq!(d.kind, NotificationKind::SshLogout);
        assert_eq!(d.user, "alex");
        assert_eq!(d.method, "SSH (password)");
        assert_eq!(d.reason.as_deref(), Some("Connection reset"));
        assert_eq!(d.source_ip.as_deref(), Some("100.64.0.22"));
        // the session is closed: a later disconnect line for it is not reported again
        assert!(matches!(t.classify(&rec("sshd", "Disconnected from 100.64.0.22 port 59437")), Outcome::Ignore(_)));
        // another session on a different port is unaffected
        event(t.classify(&rec("sshd", "Accepted publickey for bob from 10.0.0.9 port 1000 ssh2")));
        assert!(matches!(t.classify(&rec("sshd", "Connection closed by 10.0.0.9 port 1001")), Outcome::Ignore(_)));
        let d = event(t.classify(&rec("sshd", "Timeout, client not responding from 10.0.0.9 port 1000")));
        assert_eq!(d.user, "bob");
    }

    #[test]
    fn admin_channel_lines() {
        let mut t = SshTracker::new("DESKTOP-01");
        let d = event(t.classify(&rec(
            "sshd",
            "error: maximum authentication attempts exceeded for alex from 203.0.113.9 port 4022 ssh2 [preauth]",
        )));
        assert_eq!(d.kind, NotificationKind::SshFailed);
        assert_eq!(d.user, "alex");
        assert_eq!(d.reason.as_deref(), Some("Too many authentication failures"));
        assert_eq!(d.source_ip.as_deref(), Some("203.0.113.9"));
        // other admin lines (timeouts before authentication, protocol errors) are not alerts
        for l in [
            "fatal: Timeout before authentication for 100.64.0.21 port 34476",
            "error: Received disconnect from 1.2.3.4 port 5:3: com.jcraft.jsch.JSchException: Auth fail [preauth]",
            "error: kex_exchange_identification: Connection closed by remote host",
            "error: unable to get security token for user alex",
        ] {
            assert!(matches!(t.classify(&rec("sshd", l)), Outcome::Ignore(_)), "{l}");
        }
    }

    #[test]
    fn preauth_suffix_and_98_prefix() {
        let n = normalize("user: alex: Failed password for alex from 1.2.3.4 port 22 ssh2 [preauth]");
        assert_eq!(n.prefix_user, Some("alex"));
        assert!(n.preauth);
        assert_eq!(n.body, "Failed password for alex from 1.2.3.4 port 22 ssh2");
        assert_eq!(
            parse_payload("user: alex: Failed password for alex from 1.2.3.4 port 22 ssh2 [preauth]"),
            Some(SshLine::Failed {
                method: "password".into(),
                user: "alex".into(),
                invalid_user: false,
                ip: "1.2.3.4".into(),
                port: 22
            })
        );
        let n = normalize("fatal: Timeout before authentication for 1.2.3.4 port 34476");
        assert_eq!(n.severity, Some("fatal"));
        assert_eq!(parse_payload("fatal: Timeout before authentication for 1.2.3.4 port 34476"), None);
    }

    #[test]
    fn domain_user_backslashes_collapse() {
        // 9.5 escapes "\" once in post-auth lines and twice in [preauth] lines
        assert_eq!(
            parse_payload(r"Accepted publickey for redmond\\macarl from fe80::1%10 port 33443 ssh2: RSA SHA256:er4Hn6"),
            Some(acc("publickey", r"redmond\macarl", "fe80::1%10", 33443, Some("RSA SHA256:er4Hn6")))
        );
        assert_eq!(
            parse_payload(r"Failed password for desktop-01\\\\alex from 1.2.3.4 port 9 ssh2 [preauth]"),
            Some(SshLine::Failed {
                method: "password".into(),
                user: r"desktop-01\alex".into(),
                invalid_user: false,
                ip: "1.2.3.4".into(),
                port: 9
            })
        );
        assert_eq!(unescape_user(r"a\\\\b\c"), r"a\b\c");
        assert_eq!(unescape_user(r"DESKTOP-01\\nadia"), r"DESKTOP-01\nadia");
    }

    #[test]
    fn unrelated_lines_ignored() {
        for l in [
            "Server listening on 0.0.0.0 port 22.",
            "Server listening on :: port 22.",
            "Received signal 8; terminating.",
            "Received disconnect from 100.64.0.21 port 34840:11: disconnected by user",
            "Connection closed by authenticating user alex 100.64.0.21 port 38070 [preauth]",
            "Connection reset by authenticating user alex 100.64.0.22 port 59437 [preauth]",
            "Partial publickey for alex from 1.2.3.4 port 1 ssh2: ED25519 SHA256:x",
            "Accepted password for alex from 1.2.3.4 port notaport ssh2",
            "Accepted password for alex from 1.2.3.4 port 99999 ssh2",
            "Accepted password for alex",
            "Accepted",
            "",
            "Failed none for alex from 1.2.3.4 port 22 ssh3",
        ] {
            assert_eq!(parse_payload(l), None, "{l}");
        }
    }

    fn rec(process: &str, payload: &str) -> EventRecord {
        EventRecord {
            provider: "OpenSSH".into(),
            event_id: 4,
            record_id: 7,
            time_unix: Some(1_795_588_515),
            time_filetime: None,
            channel: OPENSSH_CHANNEL.into(),
            computer: "DESKTOP-01".into(),
            process_id: Some(6100),
            data: vec![("process".into(), process.into()), ("payload".into(), payload.into())],
        }
    }

    fn event(o: Outcome) -> EventDetails {
        match o {
            Outcome::Event(d) => d,
            other => panic!("expected event, got {other:?}"),
        }
    }

    #[test]
    fn tracker_reports_login_logout_and_failures() {
        let mut t = SshTracker::new("DESKTOP-01");
        let d = event(t.classify(&rec(
            "sshd",
            "Accepted publickey for alex from 100.64.0.21 port 57760 ssh2: ED25519 SHA256:EXAM",
        )));
        assert_eq!(d.kind, NotificationKind::SshLogin);
        assert_eq!(d.user, "alex");
        assert_eq!(d.method, "SSH (publickey)");
        assert_eq!(d.source_ip.as_deref(), Some("100.64.0.21"));
        assert_eq!(d.extra, vec![("Key".to_string(), "ED25519 SHA256:EXAM".to_string())]);
        assert_eq!(d.event_unix, 1_795_588_515);
        assert!(d.success);
        assert_eq!(d.computer, "DESKTOP-01");

        // 9.5: plain "Disconnected from" — user comes from the tracked session
        let d = event(t.classify(&rec("sshd", "Disconnected from 100.64.0.21 port 57760")));
        assert_eq!(d.kind, NotificationKind::SshLogout);
        assert_eq!(d.user, "alex");
        assert_eq!(d.method, "SSH (publickey)");
        // second disconnect for the same connection is not reported again
        assert!(matches!(t.classify(&rec("sshd", "Disconnected from 100.64.0.21 port 57760")), Outcome::Ignore(_)));

        let d = event(t.classify(&rec("sshd-session", "Failed password for alex from 1.2.3.4 port 5 ssh2")));
        assert_eq!(d.kind, NotificationKind::SshFailed);
        assert_eq!(d.reason.as_deref(), Some("Wrong password"));
        assert!(!d.success);

        // invalid user: reported once per connection
        let d = event(t.classify(&rec("sshd", "Invalid user admin from 9.9.9.9 port 40000")));
        assert_eq!(d.reason.as_deref(), Some("Invalid user"));
        assert_eq!(d.user, "admin");
        assert!(matches!(
            t.classify(&rec("sshd", "Failed password for invalid user admin from 9.9.9.9 port 40000 ssh2")),
            Outcome::Ignore(_)
        ));
        let d = event(t.classify(&rec("sshd", "Failed password for invalid user root from 9.9.9.9 port 40001 ssh2")));
        assert_eq!(d.reason.as_deref(), Some("Invalid user"));

        let d = event(t.classify(&rec("sshd", "Disconnected from user bob 5.5.5.5 port 1")));
        assert_eq!(d.kind, NotificationKind::SshLogout);
        assert_eq!(d.user, "bob");

        assert!(matches!(
            t.classify(&rec("sftp-server", "Accepted password for a from 1.1.1.1 port 1 ssh2")),
            Outcome::Ignore(_)
        ));
        assert!(matches!(t.classify(&rec("sshd", "Server listening on :: port 22.")), Outcome::Ignore(_)));
        assert!(matches!(t.classify(&rec("sshd", "Disconnected from 8.8.8.8 port 1")), Outcome::Ignore(_)));
    }

    #[test]
    fn tracker_is_bounded() {
        let mut t = SshTracker::new("PC");
        for i in 0..(MAX_TRACKED as u16 + 50) {
            t.classify_line(acc("password", "u", "1.1.1.1", i, None), 0);
        }
        assert_eq!(t.sessions.map.len(), MAX_TRACKED);
    }

    #[test]
    fn sshd_config_checks() {
        let p = r"C:\ProgramData\ssh\sshd_config";
        let default_cfg = "# defaults\n#SyslogFacility AUTH\n#LogLevel INFO\nAuthorizedKeysFile .ssh/authorized_keys\nSubsystem sftp sftp-server.exe\nMatch Group administrators\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n";
        assert!(check_sshd_config(default_cfg, p).is_ok());
        let e = check_sshd_config("\u{feff}syslogfacility local0\n", p).unwrap_err();
        assert!(e.contains("LOCAL0") && e.contains(p) && e.contains("restart"));
        let e = check_sshd_config("LogLevel=QUIET\n", p).unwrap_err();
        assert!(e.contains("LogLevel QUIET"));
        assert!(check_sshd_config("LOGLEVEL error\n", p).is_err());
        // first value wins
        assert!(check_sshd_config("LogLevel VERBOSE\nLogLevel QUIET\n", p).is_ok());
        assert!(check_sshd_config("SyslogFacility AUTH\nSyslogFacility LOCAL0\n", p).is_ok());
        // Match block
        let e = check_sshd_config("LogLevel INFO\nMatch User svc\n  LogLevel FATAL\n", p).unwrap_err();
        assert!(e.contains("Match block"));
        assert!(check_sshd_config("Match User x\n SyslogFacility LOCAL0\n", p).is_ok());
    }

    #[test]
    fn query_is_well_formed() {
        for (q, channel) in [(OPENSSH_QUERY, OPENSSH_CHANNEL), (OPENSSH_ADMIN_QUERY, OPENSSH_ADMIN_CHANNEL)] {
            assert!(q.starts_with("<QueryList>") && q.ends_with("</QueryList>"));
            assert_eq!(q.matches("<Select").count(), 1, "one channel per subscription (Strict bookmarks)");
            assert_eq!(q.matches("<Select").count(), q.matches("</Select>").count());
            assert_eq!(q.matches("Path=\"").count(), 2);
            assert_eq!(q.matches(&format!("Path=\"{channel}\"")).count(), 2, "{q}");
            assert!(!q.contains('&'));
        }
    }
}
