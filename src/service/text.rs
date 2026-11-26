//! Text helpers: Telegram-HTML → plain text (fallback when Telegram rejects a message's HTML)
//! and small formatting utilities for CLI output.

/// Strip tags and decode the entities Telegram HTML uses (`&lt; &gt; &amp; &quot; &#39; &#NN; &#xNN;`).
pub(crate) fn html_to_plain(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut chars = html.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '<' => {
                // skip to the closing '>' (an unterminated '<' is kept literally)
                let rest = &html[i..];
                match rest.find('>') {
                    Some(end) => {
                        let stop = i + end;
                        while let Some(&(j, _)) = chars.peek() {
                            if j > stop {
                                break;
                            }
                            chars.next();
                        }
                    }
                    None => out.push('<'),
                }
            }
            '&' => {
                let rest = &html[i..];
                match rest.find(';').filter(|&e| e <= 10).and_then(|e| decode_entity(&rest[1..e]).map(|ch| (e, ch))) {
                    Some((end, ch)) => {
                        out.push(ch);
                        let stop = i + end;
                        while let Some(&(j, _)) = chars.peek() {
                            if j > stop {
                                break;
                            }
                            chars.next();
                        }
                    }
                    None => out.push('&'),
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn decode_entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        _ => {
            let num = name.strip_prefix('#')?;
            let code = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse::<u32>().ok()?,
            };
            char::from_u32(code)
        }
    }
}

/// Plain-text version of a notification that is still valid in HTML parse mode (re-escaped,
/// length-limited for Telegram's 4096-character limit).
pub(crate) fn plain_fallback(html: &str) -> String {
    let plain = crate::util::truncate_chars(&html_to_plain(html), 3500);
    crate::notify::format::escape_html(&plain)
}

/// `12.3 MB` (1 decimal).
pub(crate) fn fmt_mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_tags_and_entities() {
        assert_eq!(
            html_to_plain("🔐 <b>NEW LOGIN</b>\n\n👤 User: <code>a&amp;b</code>"),
            "🔐 NEW LOGIN\n\n👤 User: a&b"
        );
        assert_eq!(html_to_plain("&lt;tag&gt; &quot;q&quot; &#39;x&#39; &#x41;"), "<tag> \"q\" 'x' A");
        assert_eq!(html_to_plain("a < b"), "a < b");
        assert_eq!(html_to_plain("AT&T rocks &unknown; &"), "AT&T rocks &unknown; &");
        assert_eq!(html_to_plain("<a href=\"https://x\">link</a> <i>it</i>"), "link it");
        assert_eq!(html_to_plain("ünï <b>cødé</b>"), "ünï cødé");
    }

    #[test]
    fn fallback_is_escaped() {
        let f = plain_fallback("<b>x</b> &lt;y&gt;");
        assert_eq!(f, "x &lt;y&gt;");
        let long = "a".repeat(5000);
        assert!(plain_fallback(&long).chars().count() <= 3500);
        assert_eq!(fmt_mb(3 * 1024 * 1024 + 104_858), "3.1 MB");
    }
}
