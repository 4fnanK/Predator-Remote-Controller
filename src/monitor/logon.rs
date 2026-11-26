//! Security-log event classification (4624/4625/4634/4647/4778/4779) and de-duplication.
//!
//! Rules:
//! * a 4624 is a human logon when LogonType ∈ {2,10,11,12} (session) or {7,13} (unlock), the
//!   TargetUserSid is a real account (`S-1-5-21-…` local/AD, `S-1-12-1-…` Entra ID), it is not
//!   a virtual account (DWM-n `S-1-5-90-…`, UMFD-n `S-1-5-96-…`, `VirtualAccount = %%1842`) and it
//!   was not produced by sshd (the OpenSSH monitor reports those, with the client IP);
//! * UAC split-token logons produce two linked 4624s (`TargetLinkedLogonId`) — reported once;
//! * Windows Hello produces a type 11 next to the type 7 unlock (or type 2 sign-in) — collapsed;
//! * 4634 is reported only for sessions we reported (transient unlock sessions are not tracked),
//!   4647 ("user initiated logoff") always, without a duplicate 4634;
//! * an RDP reconnect logs a 4624 (type 10/7/12/13) and a 4778 for the same account within a
//!   moment — reported once (whichever comes first). A console 4779 that accompanies an RDP
//!   takeover is folded into it: when it arrives after the RDP logon it is dropped, when it
//!   arrives first it is held back for [`RDP_WINDOW_SECS`] (see [`LogonTracker::take_expired`])
//!   and dropped if the RDP logon follows;
//! * 4719 (system audit policy changed) makes the monitor re-check the logon audit policy.

use std::collections::HashMap;

use super::Outcome;
use super::xml::EventRecord;
use crate::notify::{EventDetails, NotificationKind};

/// Structured query for the Security channel. Every `<Select>` stays well below the
/// 20-expression limit. DWM/UMFD virtual sessions are suppressed server-side (XPath has no
/// `starts-with`, so the definitive SID filter is in [`LogonTracker`]).
pub const SECURITY_QUERY: &str = concat!(
    "<QueryList>",
    "<Query Id=\"0\" Path=\"Security\">",
    "<Select Path=\"Security\">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624]",
    " and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10'",
    " or Data[@Name='LogonType']='11' or Data[@Name='LogonType']='12' or Data[@Name='LogonType']='13']]</Select>",
    "<Select Path=\"Security\">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4634]",
    " and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11'",
    " or Data[@Name='LogonType']='12']]</Select>",
    "<Select Path=\"Security\">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]",
    " and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='3' or Data[@Name='LogonType']='7'",
    " or Data[@Name='LogonType']='8' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11'",
    " or Data[@Name='LogonType']='12' or Data[@Name='LogonType']='13']]</Select>",
    "<Select Path=\"Security\">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4647",
    " or EventID=4719 or EventID=4778 or EventID=4779)]]</Select>",
    "<Select Path=\"Security\">*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=1102]]</Select>",
    "<Suppress Path=\"Security\">*[EventData[Data[@Name='TargetDomainName']='Window Manager'",
    " or Data[@Name='TargetDomainName']='Font Driver Host' or Data[@Name='VirtualAccount']='%%1842']]</Suppress>",
    "</Query>",
    "</QueryList>"
);

const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG_PROVIDER: &str = "Microsoft-Windows-Eventlog";
/// "Yes" in VirtualAccount / ElevatedToken (msobjs.dll message id, locale independent).
const YES: &str = "%%1842";
/// Linked-logon pair de-duplication window.
const PAIR_TTL_SECS: i64 = 120;
/// Window for collapsing Hello twins (type 7 + 11 ...) of the same account.
const TWIN_WINDOW_SECS: i64 = 5;
/// Window in which a 4647 after a reported 4634 (or vice versa) is considered the same logoff.
const LOGOFF_TTL_SECS: i64 = 120;
/// Upper bound of every tracking map.
const MAX_TRACKED: usize = 256;
/// Window in which an RDP/unlock logon (4624), its session reconnect (4778) and the console
/// disconnect (4779) of an RDP takeover describe ONE user action.
pub const RDP_WINDOW_SECS: i64 = 10;
/// Most console disconnects held back at once (more are reported immediately).
const MAX_HELD: usize = 16;

/// Human label of a logon type.
pub fn logon_type_label(t: u32) -> &'static str {
    match t {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "Network (cleartext)",
        9 => "New credentials",
        10 => "Remote Desktop",
        11 => "Cached credentials",
        12 => "Remote Desktop (cached)",
        13 => "Unlock (cached)",
        _ => "Other",
    }
}

/// Real user accounts: local/AD (`S-1-5-21-`) or Entra ID (`S-1-12-1-`) — never DWM/UMFD
/// (`S-1-5-90-`, `S-1-5-96-`), SYSTEM, LOCAL/NETWORK SERVICE or virtual accounts.
pub fn is_human_sid(sid: &str) -> bool {
    let s = sid.trim();
    (s.starts_with("S-1-5-21-") || s.starts_with("S-1-12-1-"))
        && !s.starts_with("S-1-5-90-")
        && !s.starts_with("S-1-5-96-")
}

/// True when the process path's file name starts with `sshd` (sshd.exe, sshd-session.exe).
pub fn process_is_sshd(path: &str) -> bool {
    let name = path.trim().rsplit(['\\', '/']).next().unwrap_or("");
    name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("sshd"))
}

/// Parse `0x5e5d7` (hex) or a plain decimal number.
pub fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Text for an NTSTATUS logon failure code.
pub fn status_text(code: u32) -> Option<&'static str> {
    Some(match code {
        0xC000_006A => "Wrong password",
        0xC000_0064 => "Unknown user name",
        0xC000_006D => "Unknown user name or bad password",
        0xC000_0234 => "Account locked out",
        0xC000_0072 => "Account disabled",
        0xC000_015B => "Logon type not granted to this account",
        0xC000_0071 => "Password expired",
        0xC000_0193 => "Account expired",
        0xC000_0224 => "Password must be changed at next logon",
        0xC000_006F => "Logon outside allowed hours",
        0xC000_0070 => "Logon from this workstation not allowed",
        0xC000_006E => "Account restriction",
        0xC000_0133 => "Clock out of sync with the domain controller",
        0xC000_005E => "No logon servers available",
        0xC000_0192 => "Netlogon service not started",
        0xC000_018C => "Domain trust relationship failed",
        0xC000_0413 => "Blocked by the authentication firewall",
        0xC000_009A => "Insufficient system resources",
        0xC000_00DC => "Server in the wrong state",
        0xC000_0225 => "Domain not found",
        _ => return None,
    })
}

/// Failure reason from 4625 Status/SubStatus (SubStatus is more specific when present).
pub fn failure_reason(status: u32, sub: u32) -> String {
    let sub_txt = if sub != 0 { status_text(sub) } else { None };
    match sub_txt.or_else(|| status_text(status)) {
        Some(t) => t.to_string(),
        None if sub != 0 => format!("Logon failure (status 0x{status:08X}, sub-status 0x{sub:08X})"),
        None => format!("Logon failure (status 0x{status:08X})"),
    }
}

fn meaningful(v: &str) -> Option<&str> {
    let v = v.trim();
    (!v.is_empty() && v != "-").then_some(v)
}

/// Source IP worth showing (not empty, `-`, or loopback).
pub fn source_ip(v: &str) -> Option<String> {
    let v = meaningful(v)?;
    if matches!(v, "::1" | "127.0.0.1" | "::ffff:127.0.0.1") {
        return None;
    }
    Some(v.to_string())
}

fn first_label(host: &str) -> &str {
    host.split('.').next().unwrap_or(host)
}

/// Equal ignoring case and DNS suffix (`DESKTOP-01` vs `desktop-01.lan`).
fn same_host(a: &str, b: &str) -> bool {
    let (a, b) = (first_label(a.trim()), first_label(b.trim()));
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

/// Account name for display: `user` when the domain is this computer (`computer` or the event's
/// `<Computer>`), empty or `.`; otherwise `DOMAIN\user`. Empty/`-` names become `(unknown)`.
pub fn display_account(name: &str, domain: &str, computer: &str, event_computer: &str) -> String {
    let Some(name) = meaningful(name) else {
        return "(unknown)".to_string();
    };
    match meaningful(domain) {
        None | Some(".") => name.to_string(),
        Some(d) if same_host(d, computer) || same_host(d, event_computer) => name.to_string(),
        Some(d) => format!("{d}\\{name}"),
    }
}

fn same_seq<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

/// Cached-logon types that Windows Hello / RDP log next to a "real" logon.
fn is_cached(t: u32) -> bool {
    matches!(t, 11..=13)
}

/// Two logons of the same account within the twin window that describe ONE user action.
fn is_twin(a: u32, b: u32) -> bool {
    a == b || matches!((a.min(b), a.max(b)), (7, 11) | (2, 11) | (10, 12) | (7, 13) | (11, 13))
}

/// Session types whose 4634 means "the user's session ended".
fn is_session_type(t: u32) -> bool {
    matches!(t, 2 | 10 | 11 | 12)
}

#[derive(Debug, Clone)]
struct Tracked {
    user: String,
    method: String,
    /// Every logon id belonging to this user session (UAC pair, Hello twins).
    group: Vec<u64>,
    seq: u64,
}

#[derive(Debug, Clone)]
struct Recent {
    time: i64,
    logon_type: u32,
    ids: Vec<u64>,
}

/// Recent session-start events of one account (RDP reconnect collapsing).
#[derive(Debug, Clone, Copy, Default)]
struct SessionMark {
    /// A 4624 of type 7/10/12/13 was seen (reported or collapsed).
    logon_at: Option<i64>,
    /// A 4778 (any session) was seen.
    reconnect_at: Option<i64>,
    /// A 4778 of a Remote Desktop session was seen.
    rdp_reconnect_at: Option<i64>,
}

impl SessionMark {
    fn latest(&self) -> Option<i64> {
        [self.logon_at, self.reconnect_at, self.rdp_reconnect_at].into_iter().flatten().max()
    }
}

fn within(t: Option<i64>, now: i64) -> bool {
    t.is_some_and(|t| (now - t).abs() <= RDP_WINDOW_SECS)
}

/// Case-insensitive account key for correlating 4624 / 4778 / 4779 of one account.
fn account_key(display_user: &str) -> String {
    display_user.to_lowercase()
}

/// A console disconnect (4779) held back for [`RDP_WINDOW_SECS`]: when an RDP logon of the same
/// account follows, it was part of that takeover and is dropped; otherwise it is reported late.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldEvent {
    pub details: EventDetails,
    /// EventRecordID / TimeCreated of the 4779 (idempotency key of the alert).
    pub record_id: u64,
    pub time_filetime: Option<u64>,
    account: String,
}

/// Stateful Security-event classifier (single-threaded, owned by the monitor thread).
pub struct LogonTracker {
    computer: String,
    /// Linked-logon pair key → event time.
    pairs: HashMap<(u64, u64), i64>,
    /// SID → last reported logon (Hello twin collapsing).
    recent: HashMap<String, Recent>,
    /// Logon id → reported session.
    sessions: HashMap<u64, Tracked>,
    /// Logon id → time a logoff was reported (4634/4647 de-duplication).
    logoffs: HashMap<u64, i64>,
    /// Account → recent RDP/unlock logon and reconnect times.
    marks: HashMap<String, SessionMark>,
    /// Console disconnects waiting for a possible RDP takeover.
    held: Vec<HeldEvent>,
    /// Latest event time classified so far.
    latest: i64,
    seq: u64,
}

impl LogonTracker {
    pub fn new(computer: &str) -> Self {
        Self {
            computer: computer.to_string(),
            pairs: HashMap::new(),
            recent: HashMap::new(),
            sessions: HashMap::new(),
            logoffs: HashMap::new(),
            marks: HashMap::new(),
            held: Vec::new(),
            latest: 0,
            seq: 0,
        }
    }

    /// Held console disconnects whose window has passed at `now` (event-time or wall-clock
    /// seconds), oldest first. The caller reports them (and [`LogonTracker::requeue`]s them
    /// when that fails).
    pub fn take_expired(&mut self, now: i64) -> Vec<HeldEvent> {
        let (due, keep): (Vec<HeldEvent>, Vec<HeldEvent>) =
            std::mem::take(&mut self.held).into_iter().partition(|h| now - h.details.event_unix > RDP_WINDOW_SECS);
        self.held = keep;
        due
    }

    /// Every held console disconnect (service stop / monitoring switched off).
    pub fn take_all(&mut self) -> Vec<HeldEvent> {
        std::mem::take(&mut self.held)
    }

    /// Put back held events that could not be reported (front of the list, order kept).
    pub fn requeue(&mut self, mut events: Vec<HeldEvent>) {
        events.append(&mut self.held);
        self.held = events;
    }

    /// When the oldest held event becomes due (`None` when nothing is held).
    pub fn next_release(&self) -> Option<i64> {
        self.held.iter().map(|h| h.details.event_unix + RDP_WINDOW_SECS + 1).min()
    }

    /// Latest event time classified so far (0 before the first event).
    pub fn latest_event_time(&self) -> i64 {
        self.latest
    }

    /// Drop held console disconnects of `account` near `unix`: they belong to this RDP takeover.
    fn fold_held(&mut self, account: &str, unix: i64) {
        self.held.retain(|h| !(h.account == account && (unix - h.details.event_unix).abs() <= RDP_WINDOW_SECS));
    }

    fn mark(&mut self, account: &str) -> &mut SessionMark {
        self.marks.entry(account.to_string()).or_default()
    }

    /// `user` for local accounts (domain = this computer, empty or `.`), else `DOMAIN\user`.
    pub fn display_user(&self, name: &str, domain: &str, event_computer: &str) -> String {
        display_account(name, domain, &self.computer, event_computer)
    }

    fn details(&self, kind: NotificationKind, user: String, method: String, unix: i64) -> EventDetails {
        EventDetails {
            kind,
            computer: self.computer.clone(),
            user,
            method,
            source_ip: None,
            source_host: None,
            reason: None,
            event_unix: unix,
            success: !matches!(kind, NotificationKind::FailedLogin),
            extra: Vec::new(),
        }
    }

    /// Client machine name worth showing (not `-`, `Unknown` or this computer).
    fn source_host(&self, v: &str, event_computer: &str) -> Option<String> {
        let v = meaningful(v)?;
        if v.eq_ignore_ascii_case("unknown") || same_host(v, &self.computer) || same_host(v, event_computer) {
            return None;
        }
        Some(v.to_string())
    }

    /// Classify one Security-channel event.
    pub fn classify(&mut self, ev: &EventRecord) -> Outcome {
        let unix = ev.time_unix.unwrap_or_else(crate::util::time::now_unix);
        if ev.event_id == 1102 {
            if !ev.provider.is_empty() && !ev.provider.eq_ignore_ascii_case(EVENTLOG_PROVIDER) {
                return Outcome::Ignore("1102 from an unexpected provider");
            }
            return self.log_cleared(ev, unix);
        }
        if !ev.provider.is_empty() && !ev.provider.eq_ignore_ascii_case(SECURITY_PROVIDER) {
            return Outcome::Ignore("unexpected provider");
        }
        self.latest = self.latest.max(unix);
        self.prune(unix);
        let out = match ev.event_id {
            4624 => self.logon(ev, unix),
            4625 => self.failed(ev, unix),
            4634 => self.logoff(ev, unix),
            4647 => self.user_logoff(ev, unix),
            4719 => Outcome::AuditPolicyChanged,
            4778 => self.reconnect(ev, unix),
            4779 => self.disconnect(ev, unix),
            _ => Outcome::Ignore("unhandled event id"),
        };
        self.prune(unix);
        out
    }

    /// Drop expired de-duplication entries; a pathological burst clears a map instead of
    /// letting it grow without bound (worst case: one duplicate alert).
    fn prune(&mut self, now: i64) {
        self.pairs.retain(|_, t| (now - *t).abs() <= PAIR_TTL_SECS);
        self.recent.retain(|_, r| (now - r.time).abs() <= TWIN_WINDOW_SECS * 4);
        self.logoffs.retain(|_, t| (now - *t).abs() <= LOGOFF_TTL_SECS);
        self.marks.retain(|_, m| m.latest().is_some_and(|t| (now - t).abs() <= RDP_WINDOW_SECS * 4));
        if self.marks.len() > MAX_TRACKED {
            self.marks.clear();
        }
        if self.pairs.len() > MAX_TRACKED {
            self.pairs.clear();
        }
        if self.recent.len() > MAX_TRACKED {
            self.recent.clear();
        }
        if self.logoffs.len() > MAX_TRACKED {
            self.logoffs.clear();
        }
    }

    fn track(&mut self, ids: &[u64], user: &str, method: &str) {
        let ids: Vec<u64> = ids.iter().copied().filter(|&i| i != 0).collect();
        if ids.is_empty() {
            return;
        }
        self.seq += 1;
        let t = Tracked { user: user.to_string(), method: method.to_string(), group: ids.clone(), seq: self.seq };
        for id in &ids {
            self.sessions.insert(*id, t.clone());
        }
        while self.sessions.len() > MAX_TRACKED {
            let Some(oldest) = self.sessions.values().min_by_key(|t| t.seq).map(|t| t.group.clone()) else { break };
            for id in oldest {
                self.sessions.remove(&id);
            }
        }
    }

    /// Remove the session containing `id` (with its whole group); returns it.
    fn untrack(&mut self, id: u64) -> Option<Tracked> {
        let t = self.sessions.remove(&id)?;
        for g in &t.group {
            self.sessions.remove(g);
        }
        Some(t)
    }

    /// Remove only `ids` from whatever groups they belong to.
    fn untrack_ids(&mut self, ids: &[u64]) {
        for id in ids {
            if let Some(t) = self.sessions.remove(id) {
                let rest: Vec<u64> = t.group.iter().copied().filter(|g| !ids.contains(g)).collect();
                for g in &rest {
                    if let Some(m) = self.sessions.get_mut(g) {
                        m.group = rest.clone();
                    }
                }
            }
        }
    }

    /// Add `ids` to the session group of `existing` (or start a new one).
    fn extend_group(&mut self, existing: &[u64], ids: &[u64], user: &str, method: &str) {
        let base = existing.iter().find_map(|i| self.sessions.get(i).cloned());
        match base {
            Some(mut t) => {
                for id in ids.iter().copied().filter(|&i| i != 0) {
                    if !t.group.contains(&id) {
                        t.group.push(id);
                    }
                }
                for id in t.group.clone() {
                    self.sessions.insert(id, t.clone());
                }
            }
            None => self.track(ids, user, method),
        }
    }

    fn logon(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        let Some(lt) = parse_num(ev.field("LogonType")).and_then(|v| u32::try_from(v).ok()) else {
            return Outcome::Ignore("missing LogonType");
        };
        if !matches!(lt, 2 | 7 | 10 | 11 | 12 | 13) {
            return Outcome::Ignore("non-interactive logon type");
        }
        let sid = ev.field("TargetUserSid").trim().to_string();
        if !is_human_sid(&sid) {
            return Outcome::Ignore("not a user account");
        }
        if ev.field("VirtualAccount").trim() == YES {
            return Outcome::Ignore("virtual account");
        }
        if process_is_sshd(ev.field("ProcessName")) {
            return Outcome::Ignore("sshd logon (reported by the SSH monitor)");
        }
        let id = parse_num(ev.field("TargetLogonId")).unwrap_or(0);
        let linked = parse_num(ev.field("TargetLinkedLogonId")).unwrap_or(0);
        if linked != 0 && id != 0 {
            let key = (id.min(linked), id.max(linked));
            if self.pairs.contains_key(&key) {
                return Outcome::Ignore("second event of a linked (UAC) logon pair");
            }
            self.pairs.insert(key, unix);
        }
        let ids: Vec<u64> = [id, linked].into_iter().filter(|&i| i != 0).collect();
        let user = self.display_user(ev.field("TargetUserName"), ev.field("TargetDomainName"), &ev.computer);
        let method = logon_type_label(lt).to_string();

        if let Some(prev) = self.recent.get(&sid).cloned()
            && (unix - prev.time).abs() <= TWIN_WINDOW_SECS
            && is_twin(prev.logon_type, lt)
        {
            // One user action logged twice (Hello PIN/biometrics, cached twin, pair without
            // linked id). Keep the non-cached logon's session for later logoff matching.
            if is_cached(prev.logon_type) && !same_seq(&prev.ids, &ids) {
                self.untrack_ids(&prev.ids);
            }
            if matches!(lt, 2 | 10) {
                self.extend_group(&prev.ids, &ids, &user, &method);
            }
            return Outcome::Ignore("collapsed with a logon of the same account a moment ago");
        }
        self.recent.insert(sid, Recent { time: unix, logon_type: lt, ids: ids.clone() });
        if is_session_type(lt) {
            self.track(&ids, &user, &method);
        }
        if matches!(lt, 7 | 10 | 12 | 13) {
            // RDP reconnect / remote unlock: one alert with its 4778, console 4779 folded in
            let account = account_key(&user);
            self.fold_held(&account, unix);
            let mark = self.mark(&account);
            let reconnected = within(mark.reconnect_at, unix);
            mark.logon_at = Some(unix);
            if reconnected {
                return Outcome::Ignore("collapsed with the session reconnect (4778) of the same account");
            }
        }
        let mut d = self.details(NotificationKind::Login, user, method, unix);
        d.source_ip = source_ip(ev.field("IpAddress"));
        d.source_host = self.source_host(ev.field("WorkstationName"), &ev.computer);
        Outcome::Event(d)
    }

    fn failed(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        let Some(lt) = parse_num(ev.field("LogonType")).and_then(|v| u32::try_from(v).ok()) else {
            return Outcome::Ignore("missing LogonType");
        };
        if !matches!(lt, 2 | 3 | 7 | 8 | 10 | 11 | 12 | 13) {
            return Outcome::Ignore("logon type not monitored");
        }
        if process_is_sshd(ev.field("ProcessName")) {
            return Outcome::Ignore("sshd failure (reported by the SSH monitor)");
        }
        let name = ev.field("TargetUserName").trim();
        let domain = ev.field("TargetDomainName").trim();
        if name.eq_ignore_ascii_case("FakeUser") && domain.eq_ignore_ascii_case("FakeDomain") {
            return Outcome::Ignore("OpenSSH FakeUser probe");
        }
        let status = parse_num(ev.field("Status")).and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
        let sub = parse_num(ev.field("SubStatus")).and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
        let user = self.display_user(name, domain, &ev.computer);
        let mut d = self.details(NotificationKind::FailedLogin, user, logon_type_label(lt).to_string(), unix);
        d.reason = Some(failure_reason(status, sub));
        d.source_ip = source_ip(ev.field("IpAddress"));
        d.source_host = self.source_host(ev.field("WorkstationName"), &ev.computer);
        Outcome::Event(d)
    }

    fn logoff(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        let id = parse_num(ev.field("TargetLogonId")).unwrap_or(0);
        if id == 0 {
            return Outcome::Ignore("missing TargetLogonId");
        }
        let Some(t) = self.untrack(id) else {
            return Outcome::Ignore("logoff of a session that was not reported");
        };
        for g in &t.group {
            self.logoffs.insert(*g, unix);
        }
        let mut d = self.details(NotificationKind::Logout, t.user, t.method, unix);
        d.reason = Some("Logoff".to_string());
        Outcome::Event(d)
    }

    fn user_logoff(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        if !is_human_sid(ev.field("TargetUserSid")) {
            return Outcome::Ignore("not a user account");
        }
        let id = parse_num(ev.field("TargetLogonId")).unwrap_or(0);
        if id != 0 && self.logoffs.contains_key(&id) {
            return Outcome::Ignore("logoff already reported");
        }
        let tracked = if id != 0 { self.untrack(id) } else { None };
        let (user, method, group) = match tracked {
            Some(t) => (t.user, t.method, t.group),
            None => (
                self.display_user(ev.field("TargetUserName"), ev.field("TargetDomainName"), &ev.computer),
                "Windows session".to_string(),
                vec![id],
            ),
        };
        for g in group.into_iter().filter(|&g| g != 0) {
            self.logoffs.insert(g, unix);
        }
        let mut d = self.details(NotificationKind::Logout, user, method, unix);
        d.reason = Some("User-initiated logoff".to_string());
        Outcome::Event(d)
    }

    fn session_source(&self, ev: &EventRecord, d: &mut EventDetails) {
        let addr = ev.field("ClientAddress").trim();
        if !addr.eq_ignore_ascii_case("LOCAL") && !addr.eq_ignore_ascii_case("unknown") {
            d.source_ip = source_ip(addr);
        }
        d.source_host = self.source_host(ev.field("ClientName"), &ev.computer);
    }

    fn is_console(ev: &EventRecord) -> bool {
        ev.field("SessionName").trim().eq_ignore_ascii_case("console")
    }

    fn reconnect(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        let user = self.display_user(ev.field("AccountName"), ev.field("AccountDomain"), &ev.computer);
        let console = Self::is_console(ev);
        let account = account_key(&user);
        if !console {
            self.fold_held(&account, unix);
        }
        let mark = self.mark(&account);
        let logged_on = within(mark.logon_at, unix);
        mark.reconnect_at = Some(unix);
        if !console {
            mark.rdp_reconnect_at = Some(unix);
        }
        if logged_on {
            return Outcome::Ignore("collapsed with the logon (4624) of the same account");
        }
        let method = if console { "Session reconnected (console)" } else { "Session reconnected (RDP)" };
        let mut d = self.details(NotificationKind::Login, user, method.to_string(), unix);
        self.session_source(ev, &mut d);
        Outcome::Event(d)
    }

    fn disconnect(&mut self, ev: &EventRecord, unix: i64) -> Outcome {
        let user = self.display_user(ev.field("AccountName"), ev.field("AccountDomain"), &ev.computer);
        let console = Self::is_console(ev);
        let account = account_key(&user);
        let method = if console { "Console session" } else { "Remote Desktop" };
        let mut d = self.details(NotificationKind::Logout, user, method.to_string(), unix);
        d.reason = Some("Session disconnected".to_string());
        self.session_source(ev, &mut d);
        if console {
            let taken_over =
                self.marks.get(&account).is_some_and(|m| within(m.logon_at, unix) || within(m.rdp_reconnect_at, unix));
            if taken_over {
                return Outcome::Ignore("console disconnect of an RDP takeover (folded into the RDP logon)");
            }
            if self.held.len() < MAX_HELD {
                self.held.push(HeldEvent {
                    details: d,
                    record_id: ev.record_id,
                    time_filetime: ev.time_filetime,
                    account,
                });
                return Outcome::Ignore("console disconnect held back (possible RDP takeover)");
            }
        }
        Outcome::Event(d)
    }

    fn log_cleared(&self, ev: &EventRecord, unix: i64) -> Outcome {
        let by = self.display_user(ev.field("SubjectUserName"), ev.field("SubjectDomainName"), &ev.computer);
        Outcome::Security {
            title: "SECURITY LOG CLEARED".to_string(),
            lines: vec![
                ("Computer".to_string(), self.computer.clone()),
                ("Cleared by".to_string(), by),
                ("Time".to_string(), crate::util::time::fmt_datetime(unix)),
                (
                    "Note".to_string(),
                    "The Windows Security audit log was erased. Login records before this moment are gone.".to_string(),
                ),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::xml::parse_event;
    use super::*;

    const ADMIN_SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const T0: &str = "2026-11-25T06:35:15.1884769Z";
    const T0_UNIX: i64 = 1_795_588_515;

    struct L4624<'a> {
        rec: u64,
        time: &'a str,
        lt: u32,
        sid: &'a str,
        user: &'a str,
        domain: &'a str,
        id: &'a str,
        linked: &'a str,
        ip: &'a str,
        ws: &'a str,
        process: &'a str,
        virt: &'a str,
        elevated: &'a str,
    }

    impl Default for L4624<'_> {
        fn default() -> Self {
            Self {
                rec: 1000,
                time: T0,
                lt: 2,
                sid: ADMIN_SID,
                user: "alex",
                domain: "DESKTOP-01",
                id: "0x602cc",
                linked: "0x0",
                ip: "127.0.0.1",
                ws: "DESKTOP-01",
                process: r"C:\Windows\System32\svchost.exe",
                virt: "%%1843",
                elevated: "%%1843",
            }
        }
    }

    impl L4624<'_> {
        fn xml(&self) -> String {
            format!(
                "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{time}'/><EventRecordID>{rec}</EventRecordID><Correlation ActivityID='{{7d6a9a6e-5c5b-0001-cf9a-6a7d5b5cdd01}}'/><Execution ProcessID='1032' ThreadID='1200'/><Channel>Security</Channel><Computer>DESKTOP-01</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-01$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>{sid}</Data><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>{domain}</Data><Data Name='TargetLogonId'>{id}</Data><Data Name='LogonType'>{lt}</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>{ws}</Data><Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x408</Data><Data Name='ProcessName'>{process}</Data><Data Name='IpAddress'>{ip}</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>{virt}</Data><Data Name='TargetLinkedLogonId'>{linked}</Data><Data Name='ElevatedToken'>{elevated}</Data></EventData></Event>",
                time = self.time,
                rec = self.rec,
                sid = self.sid,
                user = self.user,
                domain = self.domain,
                id = self.id,
                lt = self.lt,
                ws = self.ws,
                process = self.process,
                ip = self.ip,
                virt = self.virt,
                linked = self.linked,
                elevated = self.elevated,
            )
        }
    }

    fn security_event(id: u32, rec: u64, time: &str, data: &[(&str, &str)]) -> String {
        let mut s = format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>{id}</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{time}'/><EventRecordID>{rec}</EventRecordID><Correlation/><Execution ProcessID='1032' ThreadID='1100'/><Channel>Security</Channel><Computer>DESKTOP-01</Computer><Security/></System><EventData>"
        );
        for (k, v) in data {
            s.push_str(&format!("<Data Name='{k}'>{v}</Data>"));
        }
        s.push_str("</EventData></Event>");
        s
    }

    fn classify(t: &mut LogonTracker, xml: &str) -> Outcome {
        let ev = parse_event(xml).expect("valid xml");
        t.classify(&ev)
    }

    fn event(o: Outcome) -> EventDetails {
        match o {
            Outcome::Event(d) => d,
            other => panic!("expected an event, got {other:?}"),
        }
    }

    fn ignored(o: &Outcome) -> bool {
        matches!(o, Outcome::Ignore(_))
    }

    #[test]
    fn interactive_logon_type_2() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let d = event(classify(&mut t, &L4624::default().xml()));
        assert_eq!(d.kind, NotificationKind::Login);
        assert_eq!(d.user, "alex");
        assert_eq!(d.method, "Interactive");
        assert_eq!(d.source_ip, None, "loopback is not a source");
        assert_eq!(d.source_host, None, "own computer is not a client");
        assert_eq!(d.event_unix, T0_UNIX);
        assert_eq!(d.computer, "DESKTOP-01");
        assert!(d.success);
    }

    #[test]
    fn unlock_rdp_and_cached() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let d = event(classify(&mut t, &L4624 { lt: 7, id: "0x1", ..Default::default() }.xml()));
        assert_eq!(d.method, "Unlock");
        let d = event(classify(
            &mut t,
            &L4624 {
                lt: 10,
                id: "0x2",
                user: "bob",
                sid: "S-1-5-21-1-2-3-1002",
                domain: "CONTOSO",
                ip: "192.168.1.20",
                ws: "LAPTOP-X",
                time: "2026-11-25T07:00:00Z",
                ..Default::default()
            }
            .xml(),
        ));
        assert_eq!(d.method, "Remote Desktop");
        assert_eq!(d.user, r"CONTOSO\bob");
        assert_eq!(d.source_ip.as_deref(), Some("192.168.1.20"));
        assert_eq!(d.source_host.as_deref(), Some("LAPTOP-X"));
        let d = event(classify(
            &mut t,
            &L4624 {
                lt: 11,
                id: "0x3",
                sid: "S-1-12-1-111-222-333-444",
                user: "JohnDoe",
                domain: "AzureAD",
                time: "2026-11-25T08:00:00Z",
                ..Default::default()
            }
            .xml(),
        ));
        assert_eq!(d.method, "Cached credentials");
        assert_eq!(d.user, r"AzureAD\JohnDoe");
    }

    #[test]
    fn noise_is_ignored() {
        let mut t = LogonTracker::new("DESKTOP-01");
        // DWM-1 (Window Manager virtual account)
        let dwm = L4624 {
            sid: "S-1-5-90-0-1",
            user: "DWM-1",
            domain: "Window Manager",
            virt: "%%1842",
            process: r"C:\Windows\System32\winlogon.exe",
            ..Default::default()
        };
        assert!(ignored(&classify(&mut t, &dwm.xml())));
        // UMFD-0 (font driver host)
        let umfd = L4624 { sid: "S-1-5-96-0-0", user: "UMFD-0", domain: "Font Driver Host", ..Default::default() };
        assert!(ignored(&classify(&mut t, &umfd.xml())));
        // SYSTEM (type 5 would be filtered by the query; type 2 SYSTEM still ignored)
        let system = L4624 { sid: "S-1-5-18", user: "SYSTEM", domain: "NT AUTHORITY", ..Default::default() };
        assert!(ignored(&classify(&mut t, &system.xml())));
        let service = L4624 { lt: 5, ..Default::default() };
        assert!(ignored(&classify(&mut t, &service.xml())));
        // sshd-created logon
        let sshd = L4624 { lt: 2, process: r"C:\Windows\System32\OpenSSH\sshd.exe", ..Default::default() };
        assert!(ignored(&classify(&mut t, &sshd.xml())));
        // virtual account flag alone
        let virt = L4624 { virt: "%%1842", ..Default::default() };
        assert!(ignored(&classify(&mut t, &virt.xml())));
    }

    #[test]
    fn linked_pair_is_reported_once_and_logoff_once() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let elevated = L4624 { rec: 1, id: "0x602CC", linked: "0x5E5D7", elevated: "%%1842", ..Default::default() };
        let limited = L4624 { rec: 2, id: "0x5E5D7", linked: "0x602CC", elevated: "%%1843", ..Default::default() };
        assert!(matches!(classify(&mut t, &elevated.xml()), Outcome::Event(_)));
        assert!(ignored(&classify(&mut t, &limited.xml())));
        // two 4634 at logoff → one alert
        let l1 = security_event(
            4634,
            3,
            "2026-11-25T09:00:00Z",
            &[
                ("TargetUserSid", ADMIN_SID),
                ("TargetUserName", "alex"),
                ("TargetDomainName", "DESKTOP-01"),
                ("TargetLogonId", "0x5e5d7"),
                ("LogonType", "2"),
            ],
        );
        let l2 = l1.replace("0x5e5d7", "0x602cc").replace("<EventRecordID>3<", "<EventRecordID>4<");
        let d = event(classify(&mut t, &l1));
        assert_eq!(d.kind, NotificationKind::Logout);
        assert_eq!(d.reason.as_deref(), Some("Logoff"));
        assert_eq!(d.method, "Interactive");
        assert_eq!(d.user, "alex");
        assert!(ignored(&classify(&mut t, &l2)));
    }

    #[test]
    fn hello_unlock_twins_collapse() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let unlock = L4624 { lt: 7, id: "0x10", ..Default::default() };
        let hello = L4624 { lt: 11, id: "0x11", time: "2026-11-25T06:35:17Z", ..Default::default() };
        assert!(matches!(classify(&mut t, &unlock.xml()), Outcome::Event(_)));
        assert!(ignored(&classify(&mut t, &hello.xml())));
        // the transient type-11 session must not produce a logoff alert
        let off = security_event(
            4634,
            9,
            "2026-11-25T06:35:20Z",
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x11"), ("LogonType", "11")],
        );
        assert!(ignored(&classify(&mut t, &off)));
        // outside the window → separate event
        let later = L4624 { lt: 7, id: "0x12", time: "2026-11-25T06:40:00Z", ..Default::default() };
        assert!(matches!(classify(&mut t, &later.xml()), Outcome::Event(_)));
    }

    #[test]
    fn hello_cached_first_then_interactive_keeps_real_session() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let hello = L4624 { lt: 11, id: "0x21", ..Default::default() };
        let real = L4624 { lt: 2, id: "0x22", time: "2026-11-25T06:35:16Z", ..Default::default() };
        assert!(matches!(classify(&mut t, &hello.xml()), Outcome::Event(_)));
        assert!(ignored(&classify(&mut t, &real.xml())));
        let off11 = security_event(
            4634,
            5,
            T0,
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x21"), ("LogonType", "11")],
        );
        assert!(ignored(&classify(&mut t, &off11)), "transient cached session is untracked");
        let off2 =
            security_event(4634, 6, T0, &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x22"), ("LogonType", "2")]);
        let d = event(classify(&mut t, &off2));
        assert_eq!(d.reason.as_deref(), Some("Logoff"));
    }

    #[test]
    fn user_initiated_logoff_suppresses_4634() {
        let mut t = LogonTracker::new("DESKTOP-01");
        assert!(matches!(classify(&mut t, &L4624 { id: "0x77", ..Default::default() }.xml()), Outcome::Event(_)));
        let x4647 = security_event(
            4647,
            20,
            "2026-11-25T10:00:00Z",
            &[
                ("TargetUserSid", ADMIN_SID),
                ("TargetUserName", "alex"),
                ("TargetDomainName", "DESKTOP-01"),
                ("TargetLogonId", "0x77"),
            ],
        );
        let d = event(classify(&mut t, &x4647));
        assert_eq!(d.kind, NotificationKind::Logout);
        assert_eq!(d.reason.as_deref(), Some("User-initiated logoff"));
        assert_eq!(d.method, "Interactive");
        let x4634 = security_event(
            4634,
            21,
            "2026-11-25T10:00:01Z",
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x77"), ("LogonType", "2")],
        );
        assert!(ignored(&classify(&mut t, &x4634)));
        // 4634 first (reported), then a late 4647 for the same session → not repeated
        assert!(matches!(
            classify(&mut t, &L4624 { id: "0x88", time: "2026-11-25T11:00:00Z", ..Default::default() }.xml()),
            Outcome::Event(_)
        ));
        let a = security_event(
            4634,
            30,
            "2026-11-25T11:30:00Z",
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x88"), ("LogonType", "2")],
        );
        assert!(matches!(classify(&mut t, &a), Outcome::Event(_)));
        let b = security_event(
            4647,
            31,
            "2026-11-25T11:30:01Z",
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0x88")],
        );
        assert!(ignored(&classify(&mut t, &b)));
        // untracked 4647 (e.g. after a service restart) is still reported
        let c = security_event(
            4647,
            32,
            "2026-11-25T12:00:00Z",
            &[
                ("TargetUserSid", ADMIN_SID),
                ("TargetUserName", "alex"),
                ("TargetDomainName", "DESKTOP-01"),
                ("TargetLogonId", "0x99"),
            ],
        );
        let d = event(classify(&mut t, &c));
        assert_eq!(d.user, "alex");
        assert_eq!(d.method, "Windows session");
        // untracked 4634 is ignored
        let e = security_event(
            4634,
            33,
            "2026-11-25T12:00:00Z",
            &[("TargetUserSid", ADMIN_SID), ("TargetLogonId", "0xabc"), ("LogonType", "2")],
        );
        assert!(ignored(&classify(&mut t, &e)));
    }

    #[test]
    fn failed_logons() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let bad_pw = security_event(
            4625,
            40,
            T0,
            &[
                ("SubjectUserSid", "S-1-0-0"),
                ("TargetUserSid", "S-1-0-0"),
                ("TargetUserName", "alex"),
                ("TargetDomainName", "DESKTOP-01"),
                ("Status", "0xc000006d"),
                ("FailureReason", "%%2313"),
                ("SubStatus", "0xc000006a"),
                ("LogonType", "3"),
                ("LogonProcessName", "NtLmSsp "),
                ("AuthenticationPackageName", "NTLM"),
                ("WorkstationName", "KALI"),
                ("ProcessName", "-"),
                ("IpAddress", "203.0.113.7"),
                ("IpPort", "51515"),
            ],
        );
        let d = event(classify(&mut t, &bad_pw));
        assert_eq!(d.kind, NotificationKind::FailedLogin);
        assert_eq!(d.reason.as_deref(), Some("Wrong password"));
        assert_eq!(d.source_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(d.source_host.as_deref(), Some("KALI"));
        assert_eq!(d.method, "Network");
        assert_eq!(d.user, "alex");
        assert!(!d.success);

        // sshd invalid-user attempt (NOUSER) — the SSH monitor reports it with the real name
        let nouser = security_event(
            4625,
            41,
            T0,
            &[
                ("TargetUserName", "NOUSER"),
                ("TargetDomainName", ""),
                ("Status", "0xc000006d"),
                ("SubStatus", "0xc0000064"),
                ("LogonType", "8"),
                ("ProcessName", r"C:\Windows\System32\OpenSSH\sshd.exe"),
                ("IpAddress", "-"),
            ],
        );
        assert!(ignored(&classify(&mut t, &nouser)));
        let fake = security_event(
            4625,
            42,
            T0,
            &[
                ("TargetUserName", "FakeUser"),
                ("TargetDomainName", "FakeDomain"),
                ("LogonType", "8"),
                ("ProcessName", "-"),
            ],
        );
        assert!(ignored(&classify(&mut t, &fake)));
        let locked = security_event(
            4625,
            43,
            T0,
            &[
                ("TargetUserName", "guest"),
                ("TargetDomainName", "."),
                ("Status", "0xc0000234"),
                ("SubStatus", "0x0"),
                ("LogonType", "2"),
                ("ProcessName", r"C:\Windows\System32\svchost.exe"),
                ("IpAddress", "127.0.0.1"),
                ("WorkstationName", "DESKTOP-01"),
            ],
        );
        let d = event(classify(&mut t, &locked));
        assert_eq!(d.reason.as_deref(), Some("Account locked out"));
        assert_eq!(d.user, "guest");
        assert_eq!(d.source_ip, None);
        assert_eq!(d.source_host, None);
        let batch = security_event(4625, 44, T0, &[("TargetUserName", "x"), ("LogonType", "4")]);
        assert!(ignored(&classify(&mut t, &batch)));
    }

    #[test]
    fn rdp_reconnect_and_disconnect() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let rc = security_event(
            4778,
            50,
            T0,
            &[
                ("AccountName", "alex"),
                ("AccountDomain", "DESKTOP-01"),
                ("LogonID", "0x602cc"),
                ("SessionName", "RDP-Tcp#3"),
                ("ClientName", "LAPTOP-X"),
                ("ClientAddress", "192.168.1.20"),
            ],
        );
        let d = event(classify(&mut t, &rc));
        assert_eq!(d.kind, NotificationKind::Login);
        assert_eq!(d.method, "Session reconnected (RDP)");
        assert_eq!(d.source_ip.as_deref(), Some("192.168.1.20"));
        assert_eq!(d.source_host.as_deref(), Some("LAPTOP-X"));
        let console = security_event(
            4778,
            51,
            T0,
            &[
                ("AccountName", "alex"),
                ("AccountDomain", "DESKTOP-01"),
                ("SessionName", "Console"),
                ("ClientName", "Unknown"),
                ("ClientAddress", "LOCAL"),
            ],
        );
        let d = event(classify(&mut t, &console));
        assert_eq!(d.method, "Session reconnected (console)");
        assert_eq!(d.source_ip, None);
        assert_eq!(d.source_host, None);
        let dc = rc.replace("<EventID>4778<", "<EventID>4779<");
        let d = event(classify(&mut t, &dc));
        assert_eq!(d.kind, NotificationKind::Logout);
        assert_eq!(d.reason.as_deref(), Some("Session disconnected"));
        assert_eq!(d.method, "Remote Desktop");
    }

    fn session_event(id: u32, rec: u64, time: &str, session: &str, client: &str, addr: &str) -> String {
        security_event(
            id,
            rec,
            time,
            &[
                ("AccountName", "alex"),
                ("AccountDomain", "DESKTOP-01"),
                ("LogonID", "0x602cc"),
                ("SessionName", session),
                ("ClientName", client),
                ("ClientAddress", addr),
            ],
        )
    }

    fn rdp_logon(lt: u32, time: &str) -> String {
        L4624 { lt, id: "0x7001", ip: "192.168.1.20", ws: "LAPTOP-X", time, ..Default::default() }.xml()
    }

    #[test]
    fn rdp_reconnect_is_one_alert_in_either_order() {
        // 4624 type 10 first, then 4778
        let mut t = LogonTracker::new("DESKTOP-01");
        let d = event(classify(&mut t, &rdp_logon(10, "2026-11-25T07:00:00Z")));
        assert_eq!(d.method, "Remote Desktop");
        let rc = session_event(4778, 61, "2026-11-25T07:00:01Z", "RDP-Tcp#3", "LAPTOP-X", "192.168.1.20");
        assert!(ignored(&classify(&mut t, &rc)), "4778 collapsed into the 4624");
        // 4778 first, then 4624 type 7 (reconnect to a locked session)
        let mut t = LogonTracker::new("DESKTOP-01");
        let rc = session_event(4778, 62, "2026-11-25T07:00:00Z", "RDP-Tcp#4", "LAPTOP-X", "192.168.1.20");
        let d = event(classify(&mut t, &rc));
        assert_eq!(d.method, "Session reconnected (RDP)");
        assert!(ignored(&classify(&mut t, &rdp_logon(7, "2026-11-25T07:00:03Z"))), "4624 collapsed into the 4778");
        // outside the window → two separate actions
        let mut t = LogonTracker::new("DESKTOP-01");
        assert!(matches!(classify(&mut t, &rdp_logon(10, "2026-11-25T07:00:00Z")), Outcome::Event(_)));
        let late = session_event(4778, 63, "2026-11-25T07:00:30Z", "RDP-Tcp#5", "LAPTOP-X", "192.168.1.20");
        assert!(matches!(classify(&mut t, &late), Outcome::Event(_)));
        // a different account is never collapsed
        let mut t = LogonTracker::new("DESKTOP-01");
        assert!(matches!(classify(&mut t, &rdp_logon(10, "2026-11-25T07:00:00Z")), Outcome::Event(_)));
        let other = session_event(4778, 64, "2026-11-25T07:00:01Z", "RDP-Tcp#6", "LAPTOP-X", "192.168.1.20")
            .replace(">alex<", ">bob<");
        assert!(matches!(classify(&mut t, &other), Outcome::Event(_)));
    }

    #[test]
    fn console_disconnect_of_rdp_takeover_is_folded() {
        // usual order: 4624 → 4779 (console) → 4778 (RDP): one alert
        let mut t = LogonTracker::new("DESKTOP-01");
        assert!(matches!(classify(&mut t, &rdp_logon(10, "2026-11-25T07:00:00Z")), Outcome::Event(_)));
        let dc = session_event(4779, 70, "2026-11-25T07:00:01Z", "Console", "Unknown", "LOCAL");
        assert!(ignored(&classify(&mut t, &dc)));
        let rc = session_event(4778, 71, "2026-11-25T07:00:01Z", "RDP-Tcp#3", "LAPTOP-X", "192.168.1.20");
        assert!(ignored(&classify(&mut t, &rc)));
        assert_eq!(t.next_release(), None, "nothing held");

        // console 4779 first: held back, then dropped when the RDP logon follows
        let mut t = LogonTracker::new("DESKTOP-01");
        let dc = session_event(4779, 80, "2026-11-25T07:00:00Z", "Console", "Unknown", "LOCAL");
        assert!(ignored(&classify(&mut t, &dc)));
        assert!(t.next_release().is_some());
        assert!(t.take_expired(T0_UNIX - 1_000).is_empty());
        let d = event(classify(
            &mut t,
            &session_event(4778, 81, "2026-11-25T07:00:02Z", "RDP-Tcp#3", "LAPTOP-X", "192.168.1.20"),
        ));
        assert_eq!(d.method, "Session reconnected (RDP)");
        assert!(ignored(&classify(&mut t, &rdp_logon(10, "2026-11-25T07:00:02Z"))));
        assert_eq!(t.next_release(), None, "folded into the takeover");
        assert!(t.take_all().is_empty());
    }

    #[test]
    fn lone_console_disconnect_is_released_after_the_window() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let dc = session_event(4779, 90, T0, "Console", "Unknown", "LOCAL");
        assert!(ignored(&classify(&mut t, &dc)));
        assert_eq!(t.next_release(), Some(T0_UNIX + RDP_WINDOW_SECS + 1));
        assert!(t.take_expired(T0_UNIX + RDP_WINDOW_SECS).is_empty(), "still inside the window");
        let due = t.take_expired(T0_UNIX + RDP_WINDOW_SECS + 1);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].record_id, 90);
        assert!(due[0].time_filetime.is_some());
        let d = &due[0].details;
        assert_eq!(d.kind, NotificationKind::Logout);
        assert_eq!(d.method, "Console session");
        assert_eq!(d.reason.as_deref(), Some("Session disconnected"));
        assert_eq!(t.next_release(), None);
        // a failed report puts it back
        t.requeue(due);
        assert_eq!(t.take_all().len(), 1);
        // an RDP disconnect is never held
        let rdp = session_event(4779, 91, T0, "RDP-Tcp#3", "LAPTOP-X", "192.168.1.20");
        assert!(matches!(classify(&mut t, &rdp), Outcome::Event(_)));
        assert_eq!(t.latest_event_time(), T0_UNIX);
    }

    #[test]
    fn audit_policy_change_triggers_a_recheck() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let x = security_event(
            4719,
            100,
            T0,
            &[
                ("SubjectUserSid", "S-1-5-18"),
                ("SubcategoryGuid", "{0CCE9215-69AE-11D9-BED3-505054503030}"),
                ("AuditPolicyChanges", "%%8448"),
            ],
        );
        assert_eq!(classify(&mut t, &x), Outcome::AuditPolicyChanged);
    }

    #[test]
    fn audit_log_cleared() {
        let mut t = LogonTracker::new("DESKTOP-01");
        let xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-11-25T10:00:00.000000000Z'/><EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='1428' ThreadID='9036'/><Channel>Security</Channel><Computer>DESKTOP-01</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>mallory</SubjectUserName><SubjectDomainName>EVILCORP</SubjectDomainName><SubjectLogonId>0x5e5d7</SubjectLogonId></LogFileCleared></UserData></Event>";
        match classify(&mut t, xml) {
            Outcome::Security { title, lines } => {
                assert_eq!(title, "SECURITY LOG CLEARED");
                assert!(lines.iter().any(|(k, v)| k == "Cleared by" && v == r"EVILCORP\mallory"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(failure_reason(0xC000_006D, 0xC000_006A), "Wrong password");
        assert_eq!(failure_reason(0xC000_006D, 0xC000_0064), "Unknown user name");
        assert_eq!(failure_reason(0xC000_006D, 0), "Unknown user name or bad password");
        assert_eq!(failure_reason(0xC000_006E, 0xC000_0072), "Account disabled");
        assert_eq!(failure_reason(0xC000_0071, 0x0), "Password expired");
        assert_eq!(failure_reason(0xC000_0193, 0), "Account expired");
        assert_eq!(failure_reason(0xC000_0224, 0), "Password must be changed at next logon");
        assert_eq!(failure_reason(0xC000_015B, 0), "Logon type not granted to this account");
        assert!(failure_reason(0xC000_1234, 0xC000_5678).contains("0xC0005678"));
        assert_eq!(parse_num("0x5E5D7"), Some(0x5e5d7));
        assert_eq!(parse_num(" 42 "), Some(42));
        assert_eq!(parse_num("-"), None);
        assert!(process_is_sshd(r"C:\Windows\System32\OpenSSH\sshd.exe"));
        assert!(process_is_sshd("C:/x/SSHD-session.exe"));
        assert!(!process_is_sshd(r"C:\Windows\System32\svchost.exe"));
        assert!(!process_is_sshd("-"));
        assert!(is_human_sid("S-1-5-21-1-2-3-500"));
        assert!(is_human_sid("S-1-12-1-1-2-3-4"));
        assert!(!is_human_sid("S-1-5-18"));
        assert!(!is_human_sid("S-1-5-90-0-1"));
        assert!(!is_human_sid("S-1-5-96-0-0"));
        assert_eq!(source_ip("::1"), None);
        assert_eq!(source_ip("-"), None);
        assert_eq!(source_ip(" 10.0.0.2 ").as_deref(), Some("10.0.0.2"));
        let t = LogonTracker::new("DESKTOP-01");
        assert_eq!(t.display_user("alex", "desktop-01", ""), "alex");
        assert_eq!(t.display_user("alex", ".", ""), "alex");
        assert_eq!(t.display_user("alex", "", ""), "alex");
        assert_eq!(t.display_user("alex", "DESKTOP-01", "desktop-01.lan"), "alex");
        assert_eq!(t.display_user("a@b.com", "MicrosoftAccount", "DESKTOP-01"), r"MicrosoftAccount\a@b.com");
        assert_eq!(t.display_user("-", "X", ""), "(unknown)");
    }

    #[test]
    fn tracking_is_bounded() {
        let mut t = LogonTracker::new("DESKTOP-01");
        for i in 0..(MAX_TRACKED as u64 * 2) {
            let sid = format!("S-1-5-21-9-9-9-{i}");
            let id = format!("0x{:x}", 0x1000 + i);
            let xml = L4624 { sid: &sid, id: &id, rec: i, ..Default::default() }.xml();
            let _ = classify(&mut t, &xml);
        }
        assert!(t.sessions.len() <= MAX_TRACKED);
        assert!(t.pairs.len() <= MAX_TRACKED && t.recent.len() <= MAX_TRACKED);
    }

    /// Count comparisons in each `<Select>`/`<Suppress>`; wevtapi requires < 20 per expression.
    #[test]
    fn query_is_well_formed() {
        let q = SECURITY_QUERY;
        assert!(q.starts_with("<QueryList>") && q.ends_with("</QueryList>"));
        assert_eq!(q.matches("<Query ").count(), 1);
        assert_eq!(q.matches("</Query>").count(), 1);
        assert_eq!(q.matches("<Select ").count(), 5);
        assert_eq!(q.matches("</Select>").count(), 5);
        assert_eq!(q.matches("<Suppress ").count(), q.matches("</Suppress>").count());
        assert!(!q.contains('&'), "no unescaped entities");
        for part in q.split("<Select ").skip(1).chain(q.split("<Suppress ").skip(1)) {
            let body = part.split('<').next().unwrap_or("");
            assert_eq!(body.matches('[').count(), body.matches(']').count(), "balanced brackets: {body}");
            assert_eq!(body.matches('\'').count() % 2, 0, "balanced quotes: {body}");
            // conservative: every '=' (including each Data[@Name='X'] selector) counts as one
            let comparisons = body.matches('=').count();
            assert!(comparisons < 20, "too many expressions ({comparisons}): {body}");
        }
        for id in ["4624", "4625", "4634", "4647", "4719", "4778", "4779", "1102"] {
            assert!(q.contains(&format!("EventID={id}")), "{id}");
        }
        // failed logons of service/batch/new-credential types are filtered server-side
        let failed = q.split("<Select ").find(|s| s.contains("EventID=4625")).unwrap();
        for lt in ["2", "3", "7", "8", "10", "11", "12", "13"] {
            assert!(failed.contains(&format!("Data[@Name='LogonType']='{lt}'")), "{lt}");
        }
        assert!(!failed.contains("='5'") && !failed.contains("='4'"));
    }
}
