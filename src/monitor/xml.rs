//! Tiny extractor for rendered event XML (`<Data Name='X'>v</Data>`, System fields).
//!
//! `EvtRender(EvtRenderEventXml)` produces compact, well-formed XML (single-quoted attributes,
//! escaped text). This module extracts exactly what the classifiers need without an XML crate:
//! the `System` fields, `EventData/Data[@Name]` values and simple `UserData` leaf elements.
//! It never panics on malformed input — missing pieces come back as `None`/defaults.

use std::borrow::Cow;

/// The parts of one rendered event record that the monitors use.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventRecord {
    /// `System/Provider/@Name`.
    pub provider: String,
    /// `System/EventID`.
    pub event_id: u32,
    /// `System/EventRecordID` (0 when absent).
    pub record_id: u64,
    /// `System/TimeCreated/@SystemTime` as Unix seconds.
    pub time_unix: Option<i64>,
    /// `System/TimeCreated/@SystemTime` as a FILETIME value (100-ns units since 1601, full
    /// precision). Together with the record id it identifies a record even after a log clear
    /// restarted the record numbering.
    pub time_filetime: Option<u64>,
    /// `System/Channel`.
    pub channel: String,
    /// `System/Computer`.
    pub computer: String,
    /// `System/Execution/@ProcessID`.
    pub process_id: Option<u32>,
    /// `EventData/Data[@Name]` values (or `UserData` leaf elements), entity-decoded, in order.
    pub data: Vec<(String, String)>,
}

impl EventRecord {
    /// Value of the named data field.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.data.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Value of the named data field, or `""` when absent.
    pub fn field(&self, name: &str) -> &str {
        self.get(name).unwrap_or("")
    }
}

/// Parse a rendered event. Returns `None` when there is no `System` element or no numeric
/// `EventID` (the XML is then not an event record).
pub fn parse_event(xml: &str) -> Option<EventRecord> {
    let system = find_element(xml, "System", 0)?;
    let sys = system.inner_str(xml).unwrap_or("");
    let event_id = element_text(sys, "EventID")?.trim().parse::<u32>().ok()?;
    let record_id = element_text(sys, "EventRecordID").and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    let provider = element_attr(sys, "Provider", "Name").unwrap_or_default();
    let system_time = element_attr(sys, "TimeCreated", "SystemTime");
    let time_unix = system_time.as_deref().and_then(crate::util::time::parse_iso8601_utc);
    let time_filetime = system_time.as_deref().and_then(parse_filetime);
    let process_id = element_attr(sys, "Execution", "ProcessID").and_then(|v| v.trim().parse::<u32>().ok());
    let channel = element_text(sys, "Channel").unwrap_or_default();
    let computer = element_text(sys, "Computer").unwrap_or_default();
    let data = if let Some(ed) = find_element(xml, "EventData", system.end) {
        data_values(ed.inner_str(xml).unwrap_or(""))
    } else if let Some(ud) = find_element(xml, "UserData", system.end) {
        leaf_elements(ud.inner_str(xml).unwrap_or(""))
    } else {
        Vec::new()
    };
    Some(EventRecord { provider, event_id, record_id, time_unix, time_filetime, channel, computer, process_id, data })
}

/// Seconds between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_DIFF_SECS: i64 = 11_644_473_600;

/// Parse an event `SystemTime` (`2026-11-25T06:35:15.1884769Z`) into a FILETIME value with the
/// full 100-ns precision of the fraction (extra digits are truncated, missing ones are zero).
pub fn parse_filetime(s: &str) -> Option<u64> {
    let s = s.trim();
    let secs = crate::util::time::parse_iso8601_utc(s)?;
    let mut frac: u64 = 0;
    if let Some(rest) = s.get(19..).and_then(|r| r.strip_prefix('.')) {
        let digits: Vec<u8> = rest.bytes().take_while(u8::is_ascii_digit).take(7).collect();
        for i in 0..7 {
            frac = frac * 10 + u64::from(digits.get(i).map_or(0, |d| d - b'0'));
        }
    }
    let base = u64::try_from(secs.checked_add(FILETIME_EPOCH_DIFF_SECS)?).ok()?;
    base.checked_mul(10_000_000)?.checked_add(frac)
}

/// Decode the five predefined XML entities plus decimal/hex character references.
/// Unknown or malformed references are kept literally.
pub fn decode_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let decoded = after.find(';').filter(|&semi| semi > 0 && semi <= 10).and_then(|semi| {
            let ent = &after[..semi];
            let ch = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => {
                    if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                        parse_digits(hex, 16)
                    } else if let Some(dec) = ent.strip_prefix('#') {
                        parse_digits(dec, 10)
                    } else {
                        None
                    }
                }
            };
            ch.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn parse_digits(digits: &str, radix: u32) -> Option<char> {
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok().and_then(char::from_u32)
}

/// Entity-decoded text content of the first `<name>` element in `hay` (`""` for `<name/>`).
pub fn element_text(hay: &str, name: &str) -> Option<String> {
    let el = find_element(hay, name, 0)?;
    Some(el.inner_str(hay).map(|t| decode_entities(t).into_owned()).unwrap_or_default())
}

/// Entity-decoded attribute `attr` of the first `<name>` element in `hay`.
pub fn element_attr(hay: &str, name: &str, attr: &str) -> Option<String> {
    let el = find_element(hay, name, 0)?;
    attr_value(el.attrs_str(hay), attr)
}

/// Location of one element inside a haystack (byte offsets into that haystack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Element {
    /// Raw attribute text between the tag name and `>` / `/>`.
    attrs: (usize, usize),
    /// Content between the start and end tags; `None` for self-closing elements.
    inner: Option<(usize, usize)>,
    /// Offset just past the element.
    end: usize,
}

impl Element {
    fn attrs_str<'a>(&self, hay: &'a str) -> &'a str {
        hay.get(self.attrs.0..self.attrs.1).unwrap_or("")
    }
    fn inner_str<'a>(&self, hay: &'a str) -> Option<&'a str> {
        self.inner.and_then(|(a, b)| hay.get(a..b))
    }
}

fn is_name_delim(b: Option<&u8>) -> bool {
    matches!(b, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'))
}

/// Index of the `>` that closes the tag starting before `from`, ignoring `>` inside quotes.
fn find_tag_end(hay: &str, from: usize) -> Option<usize> {
    let bytes = hay.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = from;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'\'' || b == b'"' => quote = Some(b),
            None if b == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }
    None
}

/// Find `</name>` at or after `from`; returns (start of `</`, offset after `>`).
fn find_close(hay: &str, name: &str, from: usize) -> Option<(usize, usize)> {
    let mut pos = from;
    loop {
        let at = pos + hay.get(pos..)?.find("</")?;
        let name_start = at + 2;
        let name_end = name_start + name.len();
        if hay.get(name_start..name_end) == Some(name) {
            let next = hay.as_bytes().get(name_end);
            if matches!(next, Some(b'>' | b' ' | b'\t' | b'\r' | b'\n')) {
                let gt = name_end + hay.get(name_end..)?.find('>')?;
                return Some((at, gt + 1));
            }
        }
        pos = at + 2;
    }
}

/// Find the first `<name ...>` element starting at or after byte offset `from`.
fn find_element(hay: &str, name: &str, from: usize) -> Option<Element> {
    let bytes = hay.as_bytes();
    let mut pos = from;
    while pos < hay.len() {
        let lt = pos + hay.get(pos..)?.find('<')?;
        let name_start = lt + 1;
        let name_end = name_start + name.len();
        if hay.get(name_start..name_end) == Some(name) && is_name_delim(bytes.get(name_end)) {
            let gt = find_tag_end(hay, name_end)?;
            let self_closing = gt > name_end && bytes[gt - 1] == b'/';
            let attrs_end = if self_closing { gt - 1 } else { gt };
            if self_closing {
                return Some(Element { attrs: (name_end, attrs_end), inner: None, end: gt + 1 });
            }
            let (close_at, after) = find_close(hay, name, gt + 1)?;
            return Some(Element { attrs: (name_end, attrs_end), inner: Some((gt + 1, close_at)), end: after });
        }
        pos = lt + 1;
    }
    None
}

/// Value of attribute `name` in raw attribute text such as ` Name='X' Guid="{..}"`.
fn attr_value(attrs: &str, name: &str) -> Option<String> {
    let b = attrs.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < n && !b[i].is_ascii_whitespace() && b[i] != b'=' {
            i += 1;
        }
        let key = &attrs[name_start..i];
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n || b[i] != b'=' {
            // attribute without a value (not valid XML) — skip the token
            if i == name_start {
                i += 1;
            }
            continue;
        }
        i += 1; // '='
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            return None;
        }
        let (value_start, value_end) = if b[i] == b'\'' || b[i] == b'"' {
            let q = b[i];
            let start = i + 1;
            let mut j = start;
            while j < n && b[j] != q {
                j += 1;
            }
            i = (j + 1).min(n);
            (start, j)
        } else {
            let start = i;
            while i < n && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            (start, i)
        };
        if key == name {
            return Some(decode_entities(&attrs[value_start..value_end]).into_owned());
        }
    }
    None
}

/// All `<Data Name='X'>v</Data>` (or `<Data Name='X'/>`) pairs in an `EventData` section.
fn data_values(section: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(el) = find_element(section, "Data", pos) {
        let name = attr_value(el.attrs_str(section), "Name").unwrap_or_default();
        let value = el.inner_str(section).map(|t| decode_entities(t).into_owned()).unwrap_or_default();
        out.push((name, value));
        if el.end <= pos {
            break;
        }
        pos = el.end;
    }
    out
}

/// Simple `<Name>text</Name>` / `<Name/>` leaf elements of a `UserData` section (wrapper
/// elements containing other elements are descended into, not reported).
fn leaf_elements(section: &str) -> Vec<(String, String)> {
    let bytes = section.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(rel) = section.get(pos..).and_then(|s| s.find('<')) {
        let lt = pos + rel;
        let first = bytes.get(lt + 1).copied();
        if matches!(first, Some(b'/' | b'?' | b'!') | None) {
            pos = lt + 1;
            continue;
        }
        let name_start = lt + 1;
        let mut name_end = name_start;
        while name_end < bytes.len() && !is_name_delim(bytes.get(name_end)) {
            name_end += 1;
        }
        let Some(gt) = find_tag_end(section, name_end) else { break };
        let name = &section[name_start..name_end];
        if gt > name_end && bytes[gt - 1] == b'/' {
            out.push((name.to_string(), String::new()));
            pos = gt + 1;
            continue;
        }
        let content_start = gt + 1;
        let next_lt = section.get(content_start..).and_then(|s| s.find('<')).map(|r| content_start + r);
        match next_lt {
            Some(close) if section.get(close..).is_some_and(|s| s.starts_with("</")) => {
                if let Some((close_at, after)) = find_close(section, name, content_start)
                    && close_at == close
                {
                    let text = &section[content_start..close_at];
                    out.push((name.to_string(), decode_entities(text).into_owned()));
                    pos = after;
                    continue;
                }
                pos = content_start;
            }
            _ => pos = content_start, // wrapper element: descend into it
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSH_EVENT: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{c4b57d35-0636-4bc3-a262-370f249f9802}'/><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2026-11-25T06:35:15.1884769Z'/><EventRecordID>121</EventRecordID><Correlation/><Execution ProcessID='6100' ThreadID='6552'/><Channel>OpenSSH/Operational</Channel><Computer>DESKTOP-01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Accepted password for alex from 100.64.0.21 port 38652 ssh2</Data></EventData></Event>";

    #[test]
    fn parses_system_and_data() {
        let e = parse_event(SSH_EVENT).unwrap();
        assert_eq!(e.provider, "OpenSSH");
        assert_eq!(e.event_id, 4);
        assert_eq!(e.record_id, 121);
        assert_eq!(e.time_unix, Some(1_795_588_515));
        assert_eq!(e.time_filetime, Some(134_400_621_151_884_769));
        assert_eq!(e.channel, "OpenSSH/Operational");
        assert_eq!(e.computer, "DESKTOP-01");
        assert_eq!(e.process_id, Some(6100));
        assert_eq!(e.get("process"), Some("sshd"));
        assert_eq!(e.field("payload"), "Accepted password for alex from 100.64.0.21 port 38652 ssh2");
        assert_eq!(e.get("missing"), None);
        assert_eq!(e.field("missing"), "");
    }

    #[test]
    fn double_quotes_qualifiers_and_empty_data() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID Qualifiers="0">4647</EventID>
    <TimeCreated SystemTime="2015-09-09T22:35:39.893829400Z" />
    <EventRecordID>237</EventRecordID>
    <Execution ProcessID = "516" ThreadID="1464" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
    <Data Name="TargetUserName">dadmin</Data>
    <Data Name="Empty"/>
    <Data Name="Empty2"></Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
  </EventData>
</Event>"#;
        let e = parse_event(xml).unwrap();
        assert_eq!(e.event_id, 4647);
        assert_eq!(e.record_id, 237);
        assert_eq!(e.process_id, Some(516));
        assert_eq!(e.time_unix, Some(1_441_838_139));
        assert_eq!(e.time_filetime, Some((1_441_838_139u64 + 11_644_473_600) * 10_000_000 + 8_938_294));
        assert_eq!(e.computer, "DC01.contoso.local");
        assert_eq!(e.get("Empty"), Some(""));
        assert_eq!(e.get("Empty2"), Some(""));
        assert_eq!(e.get("TargetDomainName"), Some("CONTOSO"));
        assert_eq!(e.data.len(), 5);
    }

    #[test]
    fn entities_are_decoded() {
        assert_eq!(decode_entities("plain"), "plain");
        assert!(matches!(decode_entities("plain"), Cow::Borrowed(_)));
        assert_eq!(decode_entities("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"), "a & b <c> \"d\" 'e'");
        assert_eq!(decode_entities("&#65;&#x42;&#X43;&#233;"), "ABCé");
        assert_eq!(decode_entities("&unknown; & &#xZZ; &#; &"), "&unknown; & &#xZZ; &#; &");
        assert_eq!(decode_entities("&#x110000;"), "&#x110000;");
        assert_eq!(decode_entities("tail &amp"), "tail &amp");
        let xml = "<Event><System><EventID>4</EventID></System><EventData><Data Name='payload'>Accepted for a&amp;b &lt;x&gt; from 1.2.3.4</Data><Data Name='q&apos;n'>&#x41;</Data></EventData></Event>";
        let e = parse_event(xml).unwrap();
        assert_eq!(e.field("payload"), "Accepted for a&b <x> from 1.2.3.4");
        assert_eq!(e.get("q'n"), Some("A"));
        assert_eq!(e.record_id, 0);
        assert_eq!(e.time_unix, None);
    }

    #[test]
    fn user_data_leaf_elements() {
        let xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-11-25T10:00:00.000000000Z'/><EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='1428' ThreadID='9036'/><Channel>Security</Channel><Computer>DESKTOP-01</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>alex</SubjectUserName><SubjectDomainName>DESKTOP-01</SubjectDomainName><SubjectLogonId>0x5e5d7</SubjectLogonId><Empty/></LogFileCleared></UserData></Event>";
        let e = parse_event(xml).unwrap();
        assert_eq!(e.event_id, 1102);
        assert_eq!(e.provider, "Microsoft-Windows-Eventlog");
        assert_eq!(e.get("SubjectUserName"), Some("alex"));
        assert_eq!(e.get("SubjectDomainName"), Some("DESKTOP-01"));
        assert_eq!(e.get("SubjectLogonId"), Some("0x5e5d7"));
        assert_eq!(e.get("Empty"), Some(""));
        assert_eq!(e.get("LogFileCleared"), None);
    }

    #[test]
    fn similar_tag_names_are_not_confused() {
        let xml = "<Event><System><EventIDX>9</EventIDX><EventID>7</EventID></System><EventData><DataItem>x</DataItem><Data Name='a'>1</Data></EventData></Event>";
        let e = parse_event(xml).unwrap();
        assert_eq!(e.event_id, 7);
        assert_eq!(e.data, vec![("a".to_string(), "1".to_string())]);
        assert_eq!(element_attr("<X a='1>2' b=\"q\"/>", "X", "b").as_deref(), Some("q"));
        assert_eq!(element_attr("<X a='1>2' b=\"q\"/>", "X", "a").as_deref(), Some("1>2"));
        assert_eq!(element_attr("<X a=unquoted b='2'/>", "X", "a").as_deref(), Some("unquoted"));
        assert_eq!(element_attr("<X novalue b='2'/>", "X", "b").as_deref(), Some("2"));
    }

    #[test]
    fn filetime_keeps_sub_second_precision() {
        let base = (1_795_588_515u64 + 11_644_473_600) * 10_000_000;
        assert_eq!(parse_filetime("2026-11-25T06:35:15.1884769Z"), Some(base + 1_884_769));
        // 9 fraction digits are truncated to 100-ns units, short fractions are padded
        assert_eq!(parse_filetime("2026-11-25T06:35:15.188476912Z"), Some(base + 1_884_769));
        assert_eq!(parse_filetime("2026-11-25T06:35:15.5Z"), Some(base + 5_000_000));
        assert_eq!(parse_filetime("2026-11-25T06:35:15Z"), Some(base));
        assert_eq!(parse_filetime("2026-11-25T06:35:15"), Some(base));
        assert_eq!(parse_filetime("1601-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_filetime("1600-01-01T00:00:00Z"), None);
        assert_eq!(parse_filetime("garbage"), None);
        // two records written in the same second stay distinguishable
        assert_ne!(parse_filetime("2026-11-25T06:35:15.1000000Z"), parse_filetime("2026-11-25T06:35:15.1000001Z"));
    }

    #[test]
    fn malformed_input_never_panics() {
        let cases = [
            "",
            "<",
            "<System",
            "<System>",
            "<System><EventID>abc</EventID></System>",
            "<System><EventID>4</EventID>",
            "<Event><System><EventID>4</EventID></System><EventData><Data Name='x'>unterminated",
            "<Event><System><EventID>4</EventID></System><EventData><Data Name='x",
            "<Event><System><EventID>4</EventID></System><UserData><A><B>t</B",
            "<Event><System><EventID>4</EventID></System><UserData><A x='",
            "<Event><System><EventID>4</EventID><TimeCreated SystemTime='bad'/></System></Event>",
            "<Ä><System><EventID>4</EventID></System><EventData><Data Name='é'>ü</Data></EventData></Ä>",
        ];
        for c in cases {
            let _ = parse_event(c);
        }
        assert!(parse_event("<System><EventID>abc</EventID></System>").is_none());
        let e = parse_event(cases[11]).unwrap();
        assert_eq!(e.get("é"), Some("ü"));
        let e = parse_event(cases[10]).unwrap();
        assert_eq!(e.time_unix, None);
    }
}
