//! Minimal HTTP/1.1 client message handling for the direct transport (pure, no I/O of its own).
//!
//! * [`write_request_head`] builds a `POST` request head (the body is written by the caller).
//! * [`read_response`] reads one response from any [`BufRead`]: status line, headers (block
//!   capped, names case-insensitive, obs-fold unfolded), interim 1xx responses skipped, body by
//!   `Content-Length`, `chunked` (extensions and trailers accepted) or until the connection closes
//!   (capped), and decides whether the connection may be reused (HTTP/1.1, no `Connection: close`,
//!   self-delimited body).
//!
//! Nothing here ever formats the request target into an error: the Telegram path carries the bot
//! token.

use std::io::{self, BufRead};

/// Largest response head (status line + headers, and separately the chunked trailers) accepted.
pub(crate) const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Longest chunk-size line (size + extensions) accepted.
const MAX_CHUNK_LINE: usize = 4 * 1024;
/// Interim (1xx) responses skipped before the final one.
const MAX_INTERIM_RESPONSES: usize = 8;

/// Size limits for one response.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub head: usize,
    pub body: usize,
}

/// A complete response.
#[derive(Debug)]
pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    /// The connection may carry another request (HTTP/1.1, not `Connection: close`, body framed
    /// by length or chunking and read completely).
    pub reusable: bool,
}

/// Why reading a response failed.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The transport failed (includes time-outs and cancellation; the caller classifies them).
    Io(io::Error),
    /// The connection closed before the first byte of a response.
    Eof,
    /// The connection closed in the middle of the response.
    Truncated,
    /// The peer did not speak HTTP/1.x correctly.
    Malformed(&'static str),
    HeadTooLarge,
    BodyTooLarge,
}

/// A failed read plus whether any response byte had arrived (decides whether a retry is safe).
#[derive(Debug)]
pub(crate) struct ResponseError {
    pub kind: ReadError,
    pub received_any: bool,
}

/// `POST {path} HTTP/1.1` head with `Host`, `User-Agent`, `Content-Type: application/json`,
/// `Content-Length` and `Connection: keep-alive`, appended to `out`.
///
/// `host` and `path` must have passed [`valid_host`] / [`valid_path`]; `user_agent` must come from
/// [`sanitize_header_value`]. `port` is added to `Host` only when it is not 443.
pub(crate) fn write_request_head(
    out: &mut Vec<u8>,
    host: &str,
    port: u16,
    path: &str,
    user_agent: &str,
    body_len: usize,
) {
    out.extend_from_slice(b"POST ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    if port != 443 {
        out.push(b':');
        push_decimal(out, u64::from(port));
    }
    out.extend_from_slice(b"\r\nUser-Agent: ");
    out.extend_from_slice(user_agent.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    push_decimal(out, body_len as u64);
    out.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
}

fn push_decimal(out: &mut Vec<u8>, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// A DNS name or IPv4 literal: 1..=253 bytes of `[A-Za-z0-9.-]`, not starting with `-` or `.`.
pub(crate) fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// An origin-form request target: starts with `/`, only visible ASCII (no space, no controls).
pub(crate) fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 8 * 1024 && path.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// Header value safe to send: visible ASCII and spaces only (anything else becomes `_`), ≤ 256.
pub(crate) fn sanitize_header_value(value: &str) -> String {
    value.chars().take(256).map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '_' }).collect()
}

/// Read one response (interim 1xx responses are skipped). `scratch` is a reusable buffer for the
/// head and chunk lines; it never grows beyond `limits.head` plus one line.
pub(crate) fn read_response<R: BufRead>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
    limits: Limits,
) -> Result<Response, ResponseError> {
    let mut r = Tracked { inner: reader, any: false };
    let result = read_response_inner(&mut r, scratch, limits);
    scratch.clear();
    result.map_err(|kind| ResponseError { kind, received_any: r.any })
}

fn read_response_inner<R: BufRead>(
    r: &mut Tracked<'_, R>,
    scratch: &mut Vec<u8>,
    limits: Limits,
) -> Result<Response, ReadError> {
    let mut interim = 0;
    let head = loop {
        read_head(r, scratch, limits.head)?;
        let head = parse_head(scratch).map_err(ReadError::Malformed)?;
        match head.status {
            101 => return Err(ReadError::Malformed("unexpected protocol switch")),
            100..=199 => {
                interim += 1;
                if interim > MAX_INTERIM_RESPONSES {
                    return Err(ReadError::Malformed("too many interim responses"));
                }
            }
            _ => break head,
        }
    };
    let framing = head.framing();
    let body = match framing {
        Framing::Empty => Vec::new(),
        Framing::Length(n) => read_exact_body(r, n, limits.body)?,
        Framing::Chunked => read_chunked_body(r, scratch, limits)?,
        Framing::UntilClose => read_body_to_eof(r, limits.body)?,
    };
    Ok(Response { status: head.status, body, reusable: head.reusable(framing) })
}

/// `BufRead` wrapper that remembers whether any byte was received.
struct Tracked<'a, R> {
    inner: &'a mut R,
    any: bool,
}

impl<R: BufRead> Tracked<'_, R> {
    fn fill(&mut self) -> Result<&[u8], ReadError> {
        let buf = self.inner.fill_buf().map_err(ReadError::Io)?;
        if !buf.is_empty() {
            self.any = true;
        }
        Ok(buf)
    }

    fn consume(&mut self, n: usize) {
        self.inner.consume(n);
    }
}

/// Read up to and including the empty line that ends a head (CRLF CRLF, or bare LF LF).
fn read_head<R: BufRead>(r: &mut Tracked<'_, R>, out: &mut Vec<u8>, max: usize) -> Result<(), ReadError> {
    out.clear();
    loop {
        let avail = r.fill()?;
        if avail.is_empty() {
            return Err(if out.is_empty() { ReadError::Eof } else { ReadError::Truncated });
        }
        let (take, done) = match find_head_end(out, avail) {
            Some(end) => (end, true),
            None => (avail.len(), false),
        };
        if out.len().saturating_add(take) > max {
            return Err(ReadError::HeadTooLarge);
        }
        out.extend_from_slice(&avail[..take]);
        r.consume(take);
        if done {
            return Ok(());
        }
    }
}

/// Number of bytes of `next` up to and including the end of the head that started in `prev`
/// (`\n\n` or `\n\r\n`, possibly split between the two slices).
fn find_head_end(prev: &[u8], next: &[u8]) -> Option<usize> {
    let before = |i: usize, k: usize| -> Option<u8> {
        // Byte `k` positions before next[i].
        if i >= k { next.get(i - k).copied() } else { prev.len().checked_sub(k - i).map(|j| prev[j]) }
    };
    for (i, &b) in next.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        match before(i, 1) {
            Some(b'\n') => return Some(i + 1),
            Some(b'\r') if before(i, 2) == Some(b'\n') => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// What the head says about the message.
#[derive(Debug, Default, PartialEq, Eq)]
struct Head {
    /// `HTTP/1.<minor>`.
    minor: u8,
    status: u16,
    content_length: Option<u64>,
    /// A `Transfer-Encoding` header was present.
    transfer_encoding: bool,
    /// ... and its final coding is `chunked`.
    chunked: bool,
    connection_close: bool,
}

/// How the body is delimited (RFC 9112 §6.3, for a response to a non-HEAD request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Empty,
    Length(u64),
    Chunked,
    UntilClose,
}

impl Head {
    fn framing(&self) -> Framing {
        if (100..200).contains(&self.status) || self.status == 204 || self.status == 304 {
            Framing::Empty
        } else if self.transfer_encoding {
            if self.chunked { Framing::Chunked } else { Framing::UntilClose }
        } else if let Some(n) = self.content_length {
            if n == 0 { Framing::Empty } else { Framing::Length(n) }
        } else {
            Framing::UntilClose
        }
    }

    fn reusable(&self, framing: Framing) -> bool {
        self.minor >= 1
            && !self.connection_close
            && framing != Framing::UntilClose
            // Both headers at once is a smuggling signature: never reuse such a connection.
            && !(self.transfer_encoding && self.content_length.is_some())
    }
}

/// Parse a complete head (status line + header lines + empty line).
fn parse_head(raw: &[u8]) -> Result<Head, &'static str> {
    let mut lines = raw.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next().ok_or("empty response")?;
    let (minor, status) = parse_status_line(status_line)?;
    let mut head = Head { minor, status, ..Head::default() };

    // The header being collected (only the three we interpret are kept), so that obs-fold
    // continuation lines can be appended before it is applied.
    let mut pending: Option<(Field, Vec<u8>)> = None;
    let mut ended = false;
    for line in lines {
        if ended {
            if !line.is_empty() {
                return Err("data after the end of the header");
            }
            continue;
        }
        if line.is_empty() {
            ended = true;
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            // obs-fold: the line continues the previous field value (RFC 9112 §5.2).
            if let Some((_, value)) = pending.as_mut() {
                value.push(b' ');
                value.extend_from_slice(trim(line));
            }
            continue;
        }
        if let Some((field, value)) = pending.take() {
            apply_field(&mut head, field, &value)?;
        }
        let colon = line.iter().position(|&b| b == b':').ok_or("invalid header line")?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_token_byte(b)) {
            return Err("invalid header name");
        }
        if let Some(field) = Field::of(name) {
            pending = Some((field, trim(&line[colon + 1..]).to_vec()));
        }
    }
    if let Some((field, value)) = pending.take() {
        apply_field(&mut head, field, &value)?;
    }
    if !ended {
        return Err("incomplete header");
    }
    Ok(head)
}

/// `HTTP/1.x SP 3DIGIT [SP reason]` → (minor version, status).
fn parse_status_line(line: &[u8]) -> Result<(u8, u16), &'static str> {
    let rest = line.strip_prefix(b"HTTP/1.").ok_or("not an HTTP/1.x response")?;
    let (&minor, rest) = rest.split_first().ok_or("not an HTTP/1.x response")?;
    if !minor.is_ascii_digit() {
        return Err("not an HTTP/1.x response");
    }
    let rest = rest.strip_prefix(b" ").ok_or("invalid status line")?;
    let code = rest.get(..3).ok_or("invalid status line")?;
    if !code.iter().all(u8::is_ascii_digit) || !(rest.len() == 3 || rest[3] == b' ') {
        return Err("invalid status code");
    }
    let status = code.iter().fold(0u16, |acc, &d| acc * 10 + u16::from(d - b'0'));
    if status < 100 {
        return Err("invalid status code");
    }
    Ok((minor - b'0', status))
}

/// Header fields that influence framing or connection reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    ContentLength,
    TransferEncoding,
    Connection,
}

impl Field {
    fn of(name: &[u8]) -> Option<Self> {
        if name.eq_ignore_ascii_case(b"content-length") {
            Some(Self::ContentLength)
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            Some(Self::TransferEncoding)
        } else if name.eq_ignore_ascii_case(b"connection") {
            Some(Self::Connection)
        } else {
            None
        }
    }
}

fn apply_field(head: &mut Head, field: Field, value: &[u8]) -> Result<(), &'static str> {
    match field {
        Field::ContentLength => {
            // "5" or a list of identical values ("5, 5"); several header lines must agree too.
            for item in value.split(|&b| b == b',') {
                let n = parse_decimal(trim(item)).ok_or("invalid Content-Length")?;
                match head.content_length {
                    Some(existing) if existing != n => return Err("conflicting Content-Length"),
                    _ => head.content_length = Some(n),
                }
            }
        }
        Field::TransferEncoding => {
            for coding in value.split(|&b| b == b',').map(trim).filter(|c| !c.is_empty()) {
                head.transfer_encoding = true;
                // Only the final coding decides; a later non-chunked coding resets it.
                head.chunked = coding.eq_ignore_ascii_case(b"chunked");
            }
        }
        Field::Connection => {
            if value.split(|&b| b == b',').map(trim).any(|t| t.eq_ignore_ascii_case(b"close")) {
                head.connection_close = true;
            }
        }
    }
    Ok(())
}

fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &d| acc.checked_mul(10)?.checked_add(u64::from(d - b'0')))
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn read_exact_body<R: BufRead>(r: &mut Tracked<'_, R>, len: u64, max: usize) -> Result<Vec<u8>, ReadError> {
    let len = usize::try_from(len).ok().filter(|&n| n <= max).ok_or(ReadError::BodyTooLarge)?;
    let mut body = Vec::with_capacity(len);
    copy_exact(r, &mut body, len)?;
    Ok(body)
}

/// Append exactly `n` bytes to `body`.
fn copy_exact<R: BufRead>(r: &mut Tracked<'_, R>, body: &mut Vec<u8>, mut n: usize) -> Result<(), ReadError> {
    while n > 0 {
        let avail = r.fill()?;
        if avail.is_empty() {
            return Err(ReadError::Truncated);
        }
        let take = avail.len().min(n);
        body.extend_from_slice(&avail[..take]);
        r.consume(take);
        n -= take;
    }
    Ok(())
}

fn read_body_to_eof<R: BufRead>(r: &mut Tracked<'_, R>, max: usize) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        let avail = r.fill()?;
        if avail.is_empty() {
            return Ok(body);
        }
        if body.len().saturating_add(avail.len()) > max {
            return Err(ReadError::BodyTooLarge);
        }
        let n = avail.len();
        body.extend_from_slice(avail);
        r.consume(n);
    }
}

fn read_chunked_body<R: BufRead>(
    r: &mut Tracked<'_, R>,
    line: &mut Vec<u8>,
    limits: Limits,
) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        read_line(r, line, MAX_CHUNK_LINE)?;
        let size = parse_chunk_size(line).ok_or(ReadError::Malformed("invalid chunk size"))?;
        if size == 0 {
            break;
        }
        let size = usize::try_from(size)
            .ok()
            .filter(|&s| body.len().saturating_add(s) <= limits.body)
            .ok_or(ReadError::BodyTooLarge)?;
        body.reserve(size);
        copy_exact(r, &mut body, size)?;
        read_line(r, line, MAX_CHUNK_LINE)?;
        if !line.is_empty() {
            return Err(ReadError::Malformed("missing CRLF after a chunk"));
        }
    }
    // Trailer section: header lines until an empty line, bounded like a head.
    let mut trailer_bytes = 0usize;
    loop {
        read_line(r, line, limits.head)?;
        if line.is_empty() {
            return Ok(body);
        }
        trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
        if trailer_bytes > limits.head {
            return Err(ReadError::HeadTooLarge);
        }
    }
}

/// `1*HEXDIG [ BWS ; chunk-ext ]`.
fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let digits = trim(line.split(|&b| b == b';').next().unwrap_or(line));
    if digits.is_empty() || digits.len() > 15 {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &b| {
        let d = (b as char).to_digit(16)?;
        Some(acc * 16 + u64::from(d))
    })
}

/// Read one line (without its CRLF / LF) into `line`; at most `max` bytes.
fn read_line<R: BufRead>(r: &mut Tracked<'_, R>, line: &mut Vec<u8>, max: usize) -> Result<(), ReadError> {
    line.clear();
    loop {
        let avail = r.fill()?;
        if avail.is_empty() {
            return Err(ReadError::Truncated);
        }
        let (take, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if line.len().saturating_add(take) > max.saturating_add(2) {
            return Err(ReadError::Malformed("line too long"));
        }
        line.extend_from_slice(&avail[..take]);
        r.consume(take);
        if done {
            line.pop(); // '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor, Read};

    const LIMITS: Limits = Limits { head: MAX_HEAD_BYTES, body: 4 * 1024 * 1024 };

    /// Delivers its data in the given chunk sizes (cycled), then EOF — or an error if set.
    struct Dribble {
        data: Vec<u8>,
        pos: usize,
        sizes: Vec<usize>,
        turn: usize,
        fail_at_end: Option<io::ErrorKind>,
    }

    impl Dribble {
        fn new(data: &[u8], sizes: &[usize]) -> Self {
            Self { data: data.to_vec(), pos: 0, sizes: sizes.to_vec(), turn: 0, fail_at_end: None }
        }
    }

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return match self.fail_at_end {
                    Some(kind) => Err(io::Error::from(kind)),
                    None => Ok(0),
                };
            }
            let want = self.sizes[self.turn % self.sizes.len()].max(1);
            self.turn += 1;
            let n = want.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn parse_with(data: &[u8], sizes: &[usize], buf_cap: usize) -> Result<Response, ResponseError> {
        let mut r = BufReader::with_capacity(buf_cap, Dribble::new(data, sizes));
        let mut scratch = Vec::new();
        read_response(&mut r, &mut scratch, LIMITS)
    }

    /// (status, body, reusable) or the error kind as text.
    type Outcome = Result<(u16, Vec<u8>, bool), String>;

    /// Parse `data` under many read patterns; all must agree.
    fn parse_all_ways(data: &[u8]) -> Outcome {
        let mut first: Option<Outcome> = None;
        for (sizes, cap) in [
            (vec![usize::MAX], 64 * 1024),
            (vec![1], 1),
            (vec![1], 8 * 1024),
            (vec![3, 7, 1, 13], 5),
            (vec![2, 5], 4096),
            (vec![17], 17),
        ] {
            let got = match parse_with(data, &sizes, cap) {
                Ok(r) => Ok((r.status, r.body, r.reusable)),
                Err(e) => Err(format!("{:?}", e.kind)),
            };
            match &first {
                None => first = Some(got),
                Some(f) => assert_eq!(f, &got, "read pattern {sizes:?}/{cap} disagrees"),
            }
        }
        first.unwrap_or_else(|| Err("no run".into()))
    }

    #[test]
    fn request_head_layout() {
        let mut out = Vec::new();
        write_request_head(&mut out, "api.telegram.org", 443, "/botX/getMe", "Agent/1.0", 2);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /botX/getMe HTTP/1.1\r\nHost: api.telegram.org\r\nUser-Agent: Agent/1.0\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n"
        );
        let mut out = Vec::new();
        write_request_head(&mut out, "127.0.0.1", 8443, "/", "A", 0);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Host: 127.0.0.1:8443\r\n") && s.contains("Content-Length: 0\r\n"), "{s}");
        let mut out = Vec::new();
        push_decimal(&mut out, u64::MAX);
        assert_eq!(out, u64::MAX.to_string().as_bytes());
    }

    #[test]
    fn target_validation() {
        assert!(valid_host("api.telegram.org"));
        assert!(valid_host("127.0.0.1"));
        for bad in ["", "-x", ".x", "a b", "a\r\nb", "host:443", "h/x", "ü.de", &"a".repeat(254)] {
            assert!(!valid_host(bad), "{bad:?}");
        }
        assert!(valid_path("/bot123:ABC-_x/getMe"));
        for bad in ["", "bot/x", "/a b", "/a\r\nHost: x", "/\u{7f}", "/ü"] {
            assert!(!valid_path(bad), "{bad:?}");
        }
        assert_eq!(sanitize_header_value("Predator/1.0 (x)"), "Predator/1.0 (x)");
        assert_eq!(sanitize_header_value("a\r\nb\tü"), "a__b__");
        assert_eq!(sanitize_header_value(&"x".repeat(300)).len(), 256);
    }

    #[test]
    fn content_length_body() {
        let r = parse_all_ways(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .unwrap();
        assert_eq!(r, (200, b"{\"ok\":true}".to_vec(), true));
        // case-insensitive names, OWS, empty body
        let r = parse_all_ways(b"HTTP/1.1 401 Unauthorized\r\ncOnTeNt-LeNgTh:   0  \r\n\r\n").unwrap();
        assert_eq!(r, (401, Vec::new(), true));
        // identical duplicates are accepted
        let r = parse_all_ways(b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\nContent-Length: 2\r\n\r\nab").unwrap();
        assert_eq!(r.1, b"ab");
    }

    #[test]
    fn chunked_body_with_extensions_and_trailers() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            4;name=value\r\nWiki\r\n\
            5 ; ext\r\npedia\r\n\
            E\r\n in\r\n\r\nchunks.\r\n\
            0;last\r\nX-Trailer: 1\r\nX-Other: 2\r\n\r\n";
        let r = parse_all_ways(data).unwrap();
        assert_eq!(r, (200, b"Wikipedia in\r\n\r\nchunks.".to_vec(), true));
        // gzip, chunked → chunked is final; "chunked, gzip" → not chunked → until close
        let r =
            parse_all_ways(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, CHUNKED\r\n\r\n2\r\nhi\r\n0\r\n\r\n").unwrap();
        assert_eq!(r, (200, b"hi".to_vec(), true));
        let r = parse_all_ways(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nraw").unwrap();
        assert_eq!(r, (200, b"raw".to_vec(), false));
        // bare LF line endings are tolerated
        let r = parse_all_ways(b"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n3\nabc\n0\n\n").unwrap();
        assert_eq!(r, (200, b"abc".to_vec(), true));
    }

    #[test]
    fn chunked_errors() {
        for bad in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n",
        ] {
            let e = parse_all_ways(bad).unwrap_err();
            assert!(e.contains("Malformed"), "{e} for {:?}", String::from_utf8_lossy(bad));
        }
        // truncated in the middle of a chunk / before the last chunk
        let e = parse_all_ways(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab").unwrap_err();
        assert_eq!(e, "Truncated");
        let e = parse_all_ways(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n").unwrap_err();
        assert_eq!(e, "Truncated");
    }

    #[test]
    fn connection_close_and_http10() {
        let r =
            parse_all_ways(b"HTTP/1.1 200 OK\r\nConnection: keep-alive, Close\r\nContent-Length: 1\r\n\r\nx").unwrap();
        assert_eq!(r, (200, b"x".to_vec(), false));
        let r = parse_all_ways(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx").unwrap();
        assert_eq!(r, (200, b"x".to_vec(), false));
        let r = parse_all_ways(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nx").unwrap();
        assert!(!r.2, "HTTP/1.0 connections are never reused");
        // no length: body until the connection closes, never reusable
        let r = parse_all_ways(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nuntil close").unwrap();
        assert_eq!(r, (200, b"until close".to_vec(), false));
        // both headers: chunked wins, connection not reused
        let r = parse_all_ways(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r, (200, b"z".to_vec(), false));
    }

    #[test]
    fn no_body_statuses_and_interim_responses() {
        let r = parse_all_ways(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(r, (204, Vec::new(), true));
        let r = parse_all_ways(b"HTTP/1.1 304 Not Modified\r\n\r\n").unwrap();
        assert_eq!(r, (304, Vec::new(), true));
        let r = parse_all_ways(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .unwrap();
        assert_eq!(r, (200, b"ok".to_vec(), true));
        let e = parse_all_ways(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n").unwrap_err();
        assert!(e.contains("Malformed"), "{e}");
        let many = "HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INTERIM_RESPONSES + 1);
        assert!(parse_all_ways(many.as_bytes()).unwrap_err().contains("Malformed"));
    }

    #[test]
    fn obs_fold_is_unfolded() {
        let r = parse_all_ways(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,\r\n chunked\r\nX-A: 1\r\n\r\n1\r\nq\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r, (200, b"q".to_vec(), true));
        let r = parse_all_ways(b"HTTP/1.1 200 OK\r\nConnection: keep-alive,\r\n\tclose\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        assert!(!r.2);
    }

    #[test]
    fn malformed_heads() {
        for bad in [
            &b"HTTP/2 200\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 099 x\r\n\r\n",
            b"HTTP/1.x 200 OK\r\n\r\n",
            b"ICY 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNo colon here\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
        ] {
            let e = parse_all_ways(bad).unwrap_err();
            assert!(e.contains("Malformed"), "{e} for {:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn size_caps() {
        // header block over 16 KiB
        let big = format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\n\r\n", "a".repeat(MAX_HEAD_BYTES));
        assert_eq!(parse_all_ways(big.as_bytes()).unwrap_err(), "HeadTooLarge");
        // exactly at the cap is fine
        let prefix = "HTTP/1.1 200 OK\r\nX-Pad: ";
        let suffix = "\r\nContent-Length: 0\r\n\r\n";
        let exact = format!("{prefix}{}{suffix}", "p".repeat(MAX_HEAD_BYTES - prefix.len() - suffix.len()));
        assert_eq!(exact.len(), MAX_HEAD_BYTES);
        assert_eq!(parse_all_ways(exact.as_bytes()).unwrap().0, 200);
        // Content-Length beyond the cap is refused before reading
        let r = parse_with(b"HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n", &[usize::MAX], 4096);
        assert!(matches!(r.unwrap_err().kind, ReadError::BodyTooLarge));
        // chunked and until-close bodies are capped while reading
        let small = Limits { head: MAX_HEAD_BYTES, body: 8 };
        let mut s = Vec::new();
        let mut r = Cursor::new(
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n5\r\n67890\r\n0\r\n\r\n"[..],
        );
        assert!(matches!(read_response(&mut r, &mut s, small).unwrap_err().kind, ReadError::BodyTooLarge));
        let mut r = Cursor::new(&b"HTTP/1.1 200 OK\r\n\r\n123456789"[..]);
        assert!(matches!(read_response(&mut r, &mut s, small).unwrap_err().kind, ReadError::BodyTooLarge));
        let mut r = Cursor::new(&b"HTTP/1.1 200 OK\r\n\r\n12345678"[..]);
        assert_eq!(read_response(&mut r, &mut s, small).unwrap().body, b"12345678");
        // trailers are capped too
        let trailers =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{}\r\n", "T: v\r\n".repeat(4000));
        assert!(parse_all_ways(trailers.as_bytes()).unwrap_err().contains("TooLarge"));
        // the scratch buffer stays bounded and is left empty
        let mut s = Vec::new();
        let mut r = Cursor::new(big.as_bytes());
        let _ = read_response(&mut r, &mut s, LIMITS);
        assert!(s.is_empty() && s.capacity() <= 2 * MAX_HEAD_BYTES + 64 * 1024);
    }

    #[test]
    fn eof_and_truncation_report_received_bytes() {
        let e = parse_with(b"", &[1], 16).unwrap_err();
        assert!(matches!(e.kind, ReadError::Eof));
        assert!(!e.received_any, "nothing arrived: a fresh retry is safe");
        let e = parse_with(b"HTTP/1.1 200 OK\r\nContent-Le", &[4], 16).unwrap_err();
        assert!(matches!(e.kind, ReadError::Truncated));
        assert!(e.received_any);
        let e = parse_with(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", &[4], 16).unwrap_err();
        assert!(matches!(e.kind, ReadError::Truncated) && e.received_any);
        // an I/O error before any byte vs. after the head
        let mut d = Dribble::new(b"", &[1]);
        d.fail_at_end = Some(io::ErrorKind::ConnectionReset);
        let mut r = BufReader::new(d);
        let e = read_response(&mut r, &mut Vec::new(), LIMITS).unwrap_err();
        assert!(matches!(&e.kind, ReadError::Io(io) if io.kind() == io::ErrorKind::ConnectionReset));
        assert!(!e.received_any);
        let mut d = Dribble::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", &[9]);
        d.fail_at_end = Some(io::ErrorKind::TimedOut);
        let mut r = BufReader::new(d);
        let e = read_response(&mut r, &mut Vec::new(), LIMITS).unwrap_err();
        assert!(matches!(&e.kind, ReadError::Io(io) if io.kind() == io::ErrorKind::TimedOut));
        assert!(e.received_any);
    }

    #[test]
    fn leftover_bytes_after_response_are_not_consumed() {
        // Two pipelined responses: the reader stops after the first one.
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nb";
        let mut r = BufReader::with_capacity(4, Dribble::new(data, &[3]));
        let mut s = Vec::new();
        let a = read_response(&mut r, &mut s, LIMITS).unwrap();
        assert_eq!((a.status, a.body.as_slice()), (200, &b"a"[..]));
        let b = read_response(&mut r, &mut s, LIMITS).unwrap();
        assert_eq!((b.status, b.body.as_slice()), (201, &b"b"[..]));
    }

    #[test]
    fn head_end_detection_across_reads() {
        assert_eq!(find_head_end(b"", b"a\r\n\r\nrest"), Some(5));
        assert_eq!(find_head_end(b"a\r\n", b"\r\nrest"), Some(2));
        assert_eq!(find_head_end(b"a\r\n\r", b"\nrest"), Some(1));
        assert_eq!(find_head_end(b"a\n", b"\nrest"), Some(1));
        assert_eq!(find_head_end(b"", b"\r\n"), None);
        assert_eq!(find_head_end(b"a\r", b"\nb\r\n"), None);
    }

    #[test]
    fn chunk_size_parsing() {
        assert_eq!(parse_chunk_size(b"0"), Some(0));
        assert_eq!(parse_chunk_size(b"1a"), Some(26));
        assert_eq!(parse_chunk_size(b"FF ; a=b"), Some(255));
        assert_eq!(parse_chunk_size(b"ff;x"), Some(255));
        assert_eq!(parse_chunk_size(b""), None);
        assert_eq!(parse_chunk_size(b";x"), None);
        assert_eq!(parse_chunk_size(b"g"), None);
        assert_eq!(parse_chunk_size(b"1234567890abcdef"), None);
        assert_eq!(parse_decimal(b"18446744073709551615"), None); // 20 digits
        assert_eq!(parse_decimal(b"9999999999999999999"), Some(9_999_999_999_999_999_999));
    }
}
