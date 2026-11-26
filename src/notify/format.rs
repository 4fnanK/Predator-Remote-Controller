//! Telegram-HTML rendering of login/system notifications.
//!
//! Every dynamic value is truncated to a sane length and HTML-escaped, so a hostile user name,
//! host name or failure reason can neither break the markup nor push a message past Telegram's
//! 4096-character limit.

use super::{EventDetails, NotificationKind};
use crate::util::time::{fmt_date, fmt_datetime, fmt_time, to_local};
use crate::util::truncate_chars;

/// A notification delivered this many seconds (or more) after its event gets a late-delivery note.
pub const LATE_DELIVERY_THRESHOLD_SECS: i64 = 60;

/// Per-field character limits (before escaping).
const MAX_COMPUTER: usize = 64;
const MAX_USER: usize = 128;
const MAX_METHOD: usize = 64;
const MAX_ADDR: usize = 128;
const MAX_REASON: usize = 300;
const MAX_EXTRA_KEY: usize = 40;
const MAX_EXTRA_VALUE: usize = 300;
const MAX_EXTRAS: usize = 10;
const MAX_SYSTEM_LINES: usize = 30;
const MAX_SYSTEM_VALUE: usize = 500;
const MAX_TITLE: usize = 100;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Escape text for Telegram HTML parse mode (`&`, `<`, `>`, `"`).
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Truncate to `max` characters, then escape. Control characters (newlines, tabs, ...) are
/// replaced by spaces so a value can never inject extra lines into a message; bidirectional-text
/// controls are removed so a name chosen by an outsider cannot visually reorder its line.
pub fn esc(s: &str, max: usize) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .filter(|c| !crate::config::is_bidi_control(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    escape_html(&truncate_chars(&cleaned, max))
}

/// `14:30:25 · 25 Nov 2026` (local time).
pub fn fmt_event_time(unix: i64) -> String {
    format!("{} · {}", fmt_time(unix), fmt_date(unix))
}

/// Compact `25 Nov 14:30` (local time), used for history lines.
pub fn fmt_short_datetime(unix: i64) -> String {
    let t = to_local(unix);
    let m = MONTHS.get(usize::from(t.month).wrapping_sub(1)).copied().unwrap_or("???");
    format!("{:02} {} {:02}:{:02}", t.day, m, t.hour, t.minute)
}

/// `15:02:11` when `unix` falls on the same local day as `reference`, otherwise
/// `26 Nov 2026, 15:02:11`.
pub fn fmt_time_relative(unix: i64, reference: i64) -> String {
    let (a, b) = (to_local(unix), to_local(reference));
    if (a.year, a.month, a.day) == (b.year, b.month, b.day) { fmt_time(unix) } else { fmt_datetime(unix) }
}

fn title_for(kind: NotificationKind) -> (&'static str, &'static str) {
    match kind {
        NotificationKind::Login => ("🔐", "NEW WINDOWS LOGIN"),
        NotificationKind::FailedLogin => ("⚠️", "FAILED WINDOWS LOGIN"),
        NotificationKind::Logout => ("🚪", "WINDOWS LOGOUT"),
        NotificationKind::SshLogin => ("🔐", "NEW SSH LOGIN"),
        NotificationKind::SshFailed => ("⚠️", "FAILED SSH LOGIN"),
        NotificationKind::SshLogout => ("🚪", "SSH SESSION CLOSED"),
        NotificationKind::System => ("ℹ️", "SYSTEM EVENT"),
        NotificationKind::Security => ("🚨", "SECURITY EVENT"),
    }
}

/// `SSH (publickey)` → `publickey`; anything else unchanged.
fn ssh_auth_method(method: &str) -> &str {
    let m = method.trim();
    m.strip_prefix("SSH (").and_then(|r| r.strip_suffix(')')).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(m)
}

fn push_line(out: &mut String, line: &str) {
    out.push('\n');
    out.push_str(line);
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Render a login/logout/failed/SSH event as a Telegram-HTML message, e.g.
///
/// ```text
/// 🔐 NEW WINDOWS LOGIN
///
/// 🖥 Computer: DESKTOP-01
/// 👤 User: alex
/// 🔑 Login Method: Interactive
/// 🕒 Time: 14:30:25 · 25 Nov 2026
/// ✅ Status: Successful
/// ```
pub fn render_event(d: &EventDetails) -> String {
    use NotificationKind as K;
    let (emoji, title) = title_for(d.kind);
    let mut out = String::with_capacity(512);
    out.push_str(emoji);
    out.push_str(" <b>");
    out.push_str(title);
    out.push_str("</b>\n");

    let computer = if d.computer.trim().is_empty() { "unknown" } else { d.computer.as_str() };
    push_line(&mut out, &format!("🖥 Computer: <code>{}</code>", esc(computer, MAX_COMPUTER)));
    let user = if d.user.trim().is_empty() { "unknown" } else { d.user.as_str() };
    push_line(&mut out, &format!("👤 User: <code>{}</code>", esc(user, MAX_USER)));

    let method = d.method.trim();
    if !method.is_empty() {
        if d.kind.is_ssh() {
            push_line(&mut out, &format!("🔑 Auth Method: {}", esc(ssh_auth_method(method), MAX_METHOD)));
        } else {
            push_line(&mut out, &format!("🔑 Login Method: {}", esc(method, MAX_METHOD)));
        }
    }
    if let Some(ip) = non_empty(&d.source_ip) {
        push_line(&mut out, &format!("🌍 Source IP: {}", esc(ip, MAX_ADDR)));
    }
    if let Some(host) = non_empty(&d.source_host) {
        push_line(&mut out, &format!("💻 Client: {}", esc(host, MAX_ADDR)));
    }
    if let Some(reason) = non_empty(&d.reason) {
        let label = match d.kind {
            K::FailedLogin | K::SshFailed => "❗ Reason",
            K::Logout | K::SshLogout => "📝 Type",
            _ => "📝 Details",
        };
        push_line(&mut out, &format!("{label}: {}", esc(reason, MAX_REASON)));
    }
    for (k, v) in d.extra.iter().take(MAX_EXTRAS) {
        let key = k.trim();
        if key.eq_ignore_ascii_case("key") || key.to_ascii_lowercase().contains("fingerprint") {
            push_line(&mut out, &format!("🗝 {}: <code>{}</code>", esc(key, MAX_EXTRA_KEY), esc(v, MAX_EXTRA_VALUE)));
        } else if key.is_empty() {
            push_line(&mut out, &format!("🔹 {}", esc(v, MAX_EXTRA_VALUE)));
        } else {
            push_line(&mut out, &format!("🔹 {}: {}", esc(key, MAX_EXTRA_KEY), esc(v, MAX_EXTRA_VALUE)));
        }
    }
    push_line(&mut out, &format!("🕒 Time: {}", fmt_event_time(d.event_unix)));
    match d.kind {
        K::Login | K::SshLogin => push_line(&mut out, "✅ Status: Successful"),
        K::FailedLogin | K::SshFailed => push_line(&mut out, "❌ Status: Failed"),
        K::Logout | K::SshLogout => {}
        K::System | K::Security => {
            push_line(&mut out, if d.success { "✅ Status: Successful" } else { "❌ Status: Failed" })
        }
    }
    out
}

/// Render a system/lifecycle message: `<emoji> <b>TITLE</b>` + key/value lines + time.
pub fn render_system(emoji: &str, title: &str, lines: &[(String, String)], event_unix: i64) -> String {
    let mut out = String::with_capacity(256);
    let emoji = esc(emoji, 8);
    if !emoji.is_empty() {
        out.push_str(&emoji);
        out.push(' ');
    }
    out.push_str("<b>");
    out.push_str(&esc(title, MAX_TITLE));
    out.push_str("</b>\n");
    for (k, v) in lines.iter().take(MAX_SYSTEM_LINES) {
        let key = k.trim();
        if key.is_empty() {
            push_line(&mut out, &esc(v, MAX_SYSTEM_VALUE));
        } else {
            push_line(&mut out, &format!("{}: {}", esc(key, MAX_EXTRA_KEY), esc(v, MAX_SYSTEM_VALUE)));
        }
    }
    push_line(&mut out, &format!("🕒 Time: {}", fmt_event_time(event_unix)));
    out
}

/// Footnote appended by the sender when a notification is delivered late (queued while offline),
/// e.g. `\n\n📨 <i>Delivered late — queued while offline (sent 15:02:11)</i>`.
/// The sent time includes the date when it is on a different day than the event.
/// Returns `None` when the delay is under 60 seconds (or negative because of clock changes).
pub fn late_delivery_note(event_unix: i64, sent_unix: i64) -> Option<String> {
    let delay = sent_unix.checked_sub(event_unix)?;
    if delay < LATE_DELIVERY_THRESHOLD_SECS {
        return None;
    }
    Some(format!(
        "\n\n📨 <i>Delivered late — queued while offline (sent {})</i>",
        fmt_time_relative(sent_unix, event_unix)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_795_588_515; // 2026-11-25 06:35:15 UTC

    fn ev(kind: NotificationKind) -> EventDetails {
        EventDetails {
            kind,
            computer: "DESKTOP-01".into(),
            user: "alex".into(),
            method: "Interactive".into(),
            event_unix: T,
            success: !matches!(kind, NotificationKind::FailedLogin | NotificationKind::SshFailed),
            ..Default::default()
        }
    }

    fn lines(s: &str) -> Vec<&str> {
        s.lines().collect()
    }

    #[test]
    fn escape() {
        assert_eq!(escape_html(r#"<b>evil&"x"</b>"#), "&lt;b&gt;evil&amp;&quot;x&quot;&lt;/b&gt;");
        assert_eq!(esc("a\nb\tc", 10), "a b c");
        assert_eq!(esc("abcdefghij", 5), "abcd…");
        // bidirectional overrides chosen by an outsider (e.g. an SSH user name) are removed
        assert_eq!(esc("evil\u{202E}gnp.exe\u{2066}x\u{200F}", 40), "evilgnp.exex");
    }

    #[test]
    fn windows_login_layout() {
        let mut d = ev(NotificationKind::Login);
        d.source_ip = Some("192.168.1.20".into());
        d.source_host = Some("LAPTOP-X".into());
        let s = render_event(&d);
        let l = lines(&s);
        assert_eq!(l[0], "🔐 <b>NEW WINDOWS LOGIN</b>");
        assert_eq!(l[1], "");
        assert_eq!(l[2], "🖥 Computer: <code>DESKTOP-01</code>");
        assert_eq!(l[3], "👤 User: <code>alex</code>");
        assert_eq!(l[4], "🔑 Login Method: Interactive");
        assert_eq!(l[5], "🌍 Source IP: 192.168.1.20");
        assert_eq!(l[6], "💻 Client: LAPTOP-X");
        assert!(l[7].starts_with("🕒 Time: ") && l[7].contains(" · ") && l[7].contains("2026"));
        assert_eq!(l[8], "✅ Status: Successful");
        assert_eq!(l.len(), 9);
    }

    #[test]
    fn optional_lines_omitted() {
        let s = render_event(&ev(NotificationKind::Login));
        assert!(!s.contains("Source IP"));
        assert!(!s.contains("Client:"));
        assert!(!s.contains("Reason"));
    }

    #[test]
    fn failed_login() {
        let mut d = ev(NotificationKind::FailedLogin);
        d.reason = Some("Unknown user name or bad password".into());
        let s = render_event(&d);
        assert!(s.starts_with("⚠️ <b>FAILED WINDOWS LOGIN</b>"));
        assert!(s.contains("\n❗ Reason: Unknown user name or bad password"));
        assert!(s.ends_with("\n❌ Status: Failed"));
    }

    #[test]
    fn logout() {
        let mut d = ev(NotificationKind::Logout);
        d.reason = Some("User-initiated logoff".into());
        let s = render_event(&d);
        assert!(s.starts_with("🚪 <b>WINDOWS LOGOUT</b>"));
        assert!(s.contains("\n📝 Type: User-initiated logoff"));
        assert!(!s.contains("Status:"));
        assert!(s.contains("\n🕒 Time: "));
    }

    #[test]
    fn ssh_login_with_key_extra() {
        let mut d = ev(NotificationKind::SshLogin);
        d.method = "SSH (publickey)".into();
        d.source_ip = Some("100.64.0.22".into());
        d.extra = vec![("Key".into(), "ED25519 SHA256:abc".into()), ("Port".into(), "59435".into())];
        let s = render_event(&d);
        let l = lines(&s);
        assert_eq!(l[0], "🔐 <b>NEW SSH LOGIN</b>");
        assert!(s.contains("\n👤 User: <code>alex</code>"));
        assert!(s.contains("\n🌍 Source IP: 100.64.0.22"));
        assert!(s.contains("\n🔑 Auth Method: publickey"));
        assert!(s.contains("\n🗝 Key: <code>ED25519 SHA256:abc</code>"));
        assert!(s.contains("\n🔹 Port: 59435"));
        // extras come before the time line, status is last
        let key_pos = s.find("🗝 Key").unwrap();
        let time_pos = s.find("🕒 Time").unwrap();
        assert!(key_pos < time_pos);
        assert!(s.ends_with("\n✅ Status: Successful"));
    }

    #[test]
    fn ssh_failed_and_logout() {
        let mut d = ev(NotificationKind::SshFailed);
        d.method = "SSH (password)".into();
        d.reason = Some("Failed password".into());
        let s = render_event(&d);
        assert!(s.starts_with("⚠️ <b>FAILED SSH LOGIN</b>"));
        assert!(s.contains("\n🔑 Auth Method: password"));
        assert!(s.contains("\n❗ Reason: Failed password"));
        assert!(s.ends_with("\n❌ Status: Failed"));

        let s = render_event(&ev(NotificationKind::SshLogout));
        assert!(s.starts_with("🚪 <b>SSH SESSION CLOSED</b>"));
        assert!(!s.contains("Status:"));
    }

    #[test]
    fn system_and_security_kinds_render() {
        assert!(render_event(&ev(NotificationKind::System)).starts_with("ℹ️ <b>SYSTEM EVENT</b>"));
        assert!(render_event(&ev(NotificationKind::Security)).starts_with("🚨 <b>SECURITY EVENT</b>"));
    }

    #[test]
    fn hostile_values_are_escaped_and_bounded() {
        let mut d = ev(NotificationKind::FailedLogin);
        d.user = "<b>evil&".into();
        d.computer = "PC\n🔐 <b>FAKE</b>".into();
        d.reason = Some("x".repeat(10_000));
        d.extra = (0..50).map(|i| (format!("k{i}"), "<i>".into())).collect();
        let s = render_event(&d);
        assert!(s.contains("<code>&lt;b&gt;evil&amp;</code>"));
        assert!(!s.contains("<b>evil"));
        assert!(!s.contains("<b>FAKE"));
        assert!(!s.contains("\n🔐 &lt;b&gt;FAKE")); // newline in the value was neutralised
        assert!(s.chars().count() < 4096);
        assert_eq!(s.matches("🔹").count(), MAX_EXTRAS);
    }

    #[test]
    fn empty_user_and_computer() {
        let d = EventDetails { kind: NotificationKind::Login, event_unix: T, ..Default::default() };
        let s = render_event(&d);
        assert!(s.contains("🖥 Computer: <code>unknown</code>"));
        assert!(s.contains("👤 User: <code>unknown</code>"));
        assert!(!s.contains("Login Method"));
    }

    #[test]
    fn system_message() {
        let s = render_system(
            "🟢",
            "VIGIL ONLINE",
            &[("Version".into(), "1.0.0".into()), ("".into(), "a <tag>".into())],
            T,
        );
        let l = lines(&s);
        assert_eq!(l[0], "🟢 <b>VIGIL ONLINE</b>");
        assert_eq!(l[1], "");
        assert_eq!(l[2], "Version: 1.0.0");
        assert_eq!(l[3], "a &lt;tag&gt;");
        assert!(l[4].starts_with("🕒 Time: "));
        let s = render_system("🚨", "UNAUTHORIZED <ACCESS>", &[], T);
        assert!(s.starts_with("🚨 <b>UNAUTHORIZED &lt;ACCESS&gt;</b>\n\n🕒 Time: "));
    }

    #[test]
    fn late_note_thresholds() {
        assert_eq!(late_delivery_note(T, T), None);
        assert_eq!(late_delivery_note(T, T + 59), None);
        assert_eq!(late_delivery_note(T, T - 3600), None); // clock went backwards
        assert_eq!(late_delivery_note(i64::MIN, i64::MAX), None); // overflow-safe
        let n = late_delivery_note(T, T + 60).unwrap();
        assert!(n.starts_with("\n\n📨 <i>Delivered late — queued while offline (sent "));
        assert!(n.ends_with(")</i>"));
        assert!(n.contains(&fmt_time(T + 60)));
        // a delivery on another day mentions the date
        let n = late_delivery_note(T, T + 3 * 86_400).unwrap();
        assert!(n.contains(&fmt_date(T + 3 * 86_400)));
    }

    #[test]
    fn short_datetime_shape() {
        let s = fmt_short_datetime(T);
        // "25 Nov 14:30"
        assert_eq!(s.len(), 12);
        assert_eq!(&s[2..3], " ");
        assert_eq!(&s[9..10], ":");
        assert!(MONTHS.iter().any(|m| s.contains(m)));
    }

    #[test]
    fn ssh_method_strip() {
        assert_eq!(ssh_auth_method("SSH (publickey)"), "publickey");
        assert_eq!(ssh_auth_method("password"), "password");
        assert_eq!(ssh_auth_method("SSH ()"), "SSH ()");
    }
}
