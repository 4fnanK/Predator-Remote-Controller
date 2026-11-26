//! Telegram Bot API client over [`crate::net::http::HttpClient`] (direct TcpStream + SChannel
//! HTTP/1.1 keep-alive transport; WinHTTP only as the proxy fallback).
//!
//! Security: the token is part of the request path. It must never be logged, never appear in
//! `Debug` output and never be included in error strings (the transports never put the host or
//! the path into an error).

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde_json::{Value, json};

use super::types::{ApiResponse, InlineKeyboardMarkup, Update, User};
use super::{Telegram, TgError};
use crate::net::http::{HttpClient, HttpError, Interruptible};

/// Long-poll seconds used by the service for getUpdates.
pub const LONG_POLL_SECS: u32 = 50;

/// Bot API host.
pub const API_HOST: &str = "api.telegram.org";
/// Overall receive timeout for ordinary calls.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
/// Callback answers are only useful while the client spinner is still showing.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Receive slack on top of the getUpdates long-poll duration.
const LONG_POLL_SLACK_SECS: u64 = 15;
/// Message text limit (after entity parsing), counted conservatively in UTF-16 code units.
pub const MAX_MESSAGE_LEN: usize = 4096;
/// Callback answer text limit.
const MAX_CALLBACK_TEXT_LEN: usize = 200;
/// `retry_after` assumed when a 429 reply does not carry one.
const DEFAULT_RETRY_AFTER_SECS: u64 = 5;
/// Update kinds requested from getUpdates.
const ALLOWED_UPDATES: [&str; 3] = ["message", "callback_query", "my_chat_member"];
/// Longest error description kept from a Telegram reply.
const MAX_DESCRIPTION_CHARS: usize = 300;
/// `deleteMessages` accepts at most this many ids per call.
const MAX_DELETE_BATCH: usize = 100;

pub struct TelegramApi {
    http: HttpClient,
    token: String,
    /// The Bot API server does not know `deleteMessages` (a self-hosted server older than Bot
    /// API 7.0): delete one message at a time from now on.
    legacy_delete: AtomicBool,
}

impl std::fmt::Debug for TelegramApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TelegramApi { token: <redacted> }")
    }
}

impl TelegramApi {
    /// Create a client for `token` (format already validated by the caller). No network I/O.
    ///
    /// A token with an invalid shape is rejected with [`TgError::Unauthorized`] (it could never
    /// authenticate, and it must not be able to alter the request path).
    pub fn new(token: &str) -> Result<Self, TgError> {
        if !is_valid_token_format(token) {
            return Err(TgError::Unauthorized);
        }
        let agent = format!("Vigil/{}", crate::VERSION);
        let http = HttpClient::new(&agent).map_err(|e| network_error(&e))?;
        Ok(Self { http, token: token.to_owned(), legacy_delete: AtomicBool::new(false) })
    }

    /// Abort the requests in flight at once (network change, resume): a blocked `getUpdates` long
    /// poll returns immediately with [`TgError::Network`]. Idle connections are closed too; later
    /// calls work normally. A `sendMessage` is only aborted while it is still connecting or
    /// sending: once Telegram may have received it, it runs to its reply or its time limit, so an
    /// interrupt never makes the sender deliver a message twice. No-op while the WinHTTP fallback
    /// is in use.
    pub fn interrupt(&self) {
        self.http.interrupt();
    }

    /// The HTTPS backend in use (`"direct (SChannel)"`, `"WinHTTP (default proxy)"` or
    /// `"WinHTTP (automatic proxy)"`), for status and selftest output.
    pub fn transport_name(&self) -> &'static str {
        self.http.transport_name()
    }

    /// `getMe` — validates the token, returns the bot user.
    pub fn get_me(&self) -> Result<User, TgError> {
        self.call("getMe", &json!({}), DEFAULT_TIMEOUT)
    }

    /// `getUpdates` long poll. `offset` = last processed update_id + 1. Allowed updates:
    /// message, callback_query, my_chat_member.
    pub fn get_updates(&self, offset: i64, timeout_secs: u32) -> Result<Vec<Update>, TgError> {
        let timeout = Duration::from_secs(u64::from(timeout_secs) + LONG_POLL_SLACK_SECS);
        let raw: Vec<Value> = self.call("getUpdates", &get_updates_body(offset, timeout_secs), timeout)?;
        Ok(parse_updates(raw))
    }

    /// `setMyCommands` (private-chat scope).
    pub fn set_my_commands(&self, commands: &[(&str, &str)]) -> Result<(), TgError> {
        self.call::<IgnoredAny>("setMyCommands", &set_my_commands_body(commands), DEFAULT_TIMEOUT).map(|_| ())
    }

    /// `deleteWebhook` (getUpdates fails with 409 while a webhook is set).
    pub fn delete_webhook(&self) -> Result<(), TgError> {
        self.call::<IgnoredAny>("deleteWebhook", &json!({ "drop_pending_updates": false }), DEFAULT_TIMEOUT).map(|_| ())
    }

    /// `sendMessage` with an explicit overall timeout (used during shutdown).
    pub fn send_message_with_timeout(
        &self,
        chat_id: i64,
        html: &str,
        keyboard: Option<&InlineKeyboardMarkup>,
        timeout: Duration,
    ) -> Result<i64, TgError> {
        let body = send_message_body(chat_id, html, keyboard)?;
        let sent: SentMessage = self.call("sendMessage", &body, timeout)?;
        Ok(sent.message_id)
    }

    /// `deleteMessage` for each id; ids Telegram refuses (already gone, too old) are skipped.
    fn delete_each(&self, chat_id: i64, ids: &[i64]) -> Result<(), TgError> {
        for &id in ids {
            match self.call::<IgnoredAny>("deleteMessage", &delete_message_body(chat_id, id), DEFAULT_TIMEOUT) {
                Ok(_) => {}
                Err(e) if single_delete_skippable(&e) => {
                    crate::log_debug!("deleteMessage({id}) skipped: {e}");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// POST `body` to `method` and classify the reply. Errors never contain the token.
    fn call<T: DeserializeOwned>(&self, method: &str, body: &Value, timeout: Duration) -> Result<T, TgError> {
        let payload = serde_json::to_vec(body)
            .map_err(|e| TgError::Parse(format!("cannot encode the {method} request: {}", json_error_text(&e))))?;
        let path = method_path(&self.token, method);
        let reply = self.http.post_json_with(API_HOST, &path, &payload, timeout, interrupt_policy(method));
        drop(path);
        let result = match reply {
            Ok(resp) => classify_response(resp.status, &resp.body),
            Err(e) => Err(network_error(&e)),
        };
        result.map_err(|e| scrub_error(e, &self.token))
    }
}

impl Telegram for TelegramApi {
    fn send_message(&self, chat_id: i64, html: &str, keyboard: Option<&InlineKeyboardMarkup>) -> Result<i64, TgError> {
        self.send_message_with_timeout(chat_id, html, keyboard, DEFAULT_TIMEOUT)
    }

    fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        keyboard: Option<&InlineKeyboardMarkup>,
    ) -> Result<(), TgError> {
        let body = edit_message_body(chat_id, message_id, html, keyboard)?;
        match self.call::<IgnoredAny>("editMessageText", &body, DEFAULT_TIMEOUT) {
            Ok(_) => Ok(()),
            Err(e) if is_not_modified(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn answer_callback(&self, callback_id: &str, text: Option<&str>, show_alert: bool) -> Result<(), TgError> {
        self.call::<IgnoredAny>(
            "answerCallbackQuery",
            &answer_callback_body(callback_id, text, show_alert),
            CALLBACK_TIMEOUT,
        )
        .map(|_| ())
    }

    fn leave_chat(&self, chat_id: i64) -> Result<(), TgError> {
        self.call::<IgnoredAny>("leaveChat", &json!({ "chat_id": chat_id }), DEFAULT_TIMEOUT).map(|_| ())
    }

    /// `deleteMessages` in batches of ≤ 100 ids (Telegram skips ids it cannot find or delete).
    /// Falls back to `deleteMessage` per id when the server does not know the method (remembered
    /// for the lifetime of this client) or refuses a whole batch.
    fn delete_messages(&self, chat_id: i64, message_ids: &[i64]) -> Result<(), TgError> {
        for batch in delete_batches(message_ids) {
            if !self.legacy_delete.load(Ordering::Relaxed) {
                let body = delete_messages_body(chat_id, &batch);
                match self.call::<IgnoredAny>("deleteMessages", &body, DEFAULT_TIMEOUT) {
                    Ok(_) => continue,
                    Err(e) => match batch_failure(&e, batch.len()) {
                        BatchFailure::MethodMissing => {
                            if !self.legacy_delete.swap(true, Ordering::Relaxed) {
                                crate::log_info!(
                                    "the Telegram server does not support deleteMessages ({e}); deleting one message \
                                     at a time"
                                );
                            }
                        }
                        BatchFailure::TryEach => crate::log_debug!("deleteMessages refused ({e}); trying one by one"),
                        BatchFailure::Skip => {
                            crate::log_debug!("deleteMessages skipped: {e}");
                            continue;
                        }
                        BatchFailure::Fail => return Err(e),
                    },
                }
            }
            self.delete_each(chat_id, &batch)?;
        }
        Ok(())
    }
}

/// Validate the shape of a bot token (`<bot id digits>:<35+ chars [A-Za-z0-9_-]>`).
pub fn is_valid_token_format(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else { return false };
    !id.is_empty()
        && id.len() <= 20
        && id.bytes().all(|b| b.is_ascii_digit())
        && secret.len() >= 30
        && secret.len() <= 100
        && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------------------------------
// Request building (pure)
// ---------------------------------------------------------------------------------------------

/// `/bot<token>/<method>` — contains the secret; never log or return it.
fn method_path(token: &str, method: &str) -> String {
    format!("/bot{token}/{method}")
}

/// How [`TelegramApi::interrupt`] may stop a call. `sendMessage` is the only call whose repetition
/// is visible (a second copy of the message), and the sender repeats every send that failed with
/// a network error — so once its request is on the wire it is left to finish. Every other method
/// is idempotent or harmless to repeat (an edit reports "not modified", a delete "not found").
/// Only the long poll may be cut at any time (that is what `interrupt()` exists for: a getUpdates
/// stuck on a dead connection). Every other call can only be cancelled while it is still being
/// connected/sent — once the request reached Telegram it runs to its reply, so an owner's reply,
/// an edit or a delete is never lost and a sendMessage is never duplicated by an interrupt.
fn interrupt_policy(method: &str) -> Interruptible {
    if method == "getUpdates" { Interruptible::Always } else { Interruptible::UntilSent }
}

/// The part of a sendMessage reply we need.
#[derive(Debug, Deserialize)]
struct SentMessage {
    message_id: i64,
}

fn get_updates_body(offset: i64, timeout_secs: u32) -> Value {
    json!({ "offset": offset, "timeout": timeout_secs, "allowed_updates": ALLOWED_UPDATES })
}

fn set_my_commands_body(commands: &[(&str, &str)]) -> Value {
    let list: Vec<Value> = commands
        .iter()
        .map(|(command, description)| json!({ "command": command, "description": description }))
        .collect();
    json!({ "commands": list, "scope": { "type": "all_private_chats" } })
}

fn answer_callback_body(callback_id: &str, text: Option<&str>, show_alert: bool) -> Value {
    let mut body = json!({ "callback_query_id": callback_id, "show_alert": show_alert });
    if let Some(t) = text {
        body["text"] = Value::String(truncate_utf16(t, MAX_CALLBACK_TEXT_LEN).into_owned());
    }
    body
}

fn delete_messages_body(chat_id: i64, message_ids: &[i64]) -> Value {
    json!({ "chat_id": chat_id, "message_ids": message_ids })
}

fn delete_message_body(chat_id: i64, message_id: i64) -> Value {
    json!({ "chat_id": chat_id, "message_id": message_id })
}

/// Valid (positive), de-duplicated ids in their original order, split into `deleteMessages`
/// batches of at most [`MAX_DELETE_BATCH`].
fn delete_batches(message_ids: &[i64]) -> Vec<Vec<i64>> {
    let mut unique: Vec<i64> = Vec::with_capacity(message_ids.len());
    for &id in message_ids {
        if id > 0 && !unique.contains(&id) {
            unique.push(id);
        }
    }
    unique.chunks(MAX_DELETE_BATCH).map(<[i64]>::to_vec).collect()
}

/// What to do when a `deleteMessages` batch failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchFailure {
    /// The server does not know the method: switch to `deleteMessage` for good.
    MethodMissing,
    /// The batch as a whole was refused: delete the ids one by one (the others may work).
    TryEach,
    /// A single id was refused (already gone, too old): nothing more to try.
    Skip,
    /// Transport, permission, rate-limit or server problem: report it (the caller may retry).
    Fail,
}

/// Unknown Bot API method: HTTP 404 `Not Found` from api.telegram.org, or a 400 naming the
/// method from other servers.
fn is_method_missing(e: &TgError) -> bool {
    match e {
        TgError::Server(404, _) => true,
        TgError::BadRequest(d) => {
            let d = d.to_ascii_lowercase();
            d.contains("method not found") || d.contains("unknown method") || d.trim() == "not found"
        }
        _ => false,
    }
}

/// A 400 about the chat itself ("chat not found", invalid peer ...): no message of it can be
/// deleted, so trying the ids one by one would only multiply the failing requests.
fn is_chat_error(e: &TgError) -> bool {
    let TgError::BadRequest(d) = e else { return false };
    let d = d.to_ascii_lowercase();
    ["chat not found", "user not found", "peer_id_invalid", "chat_id is empty", "user is deactivated"]
        .iter()
        .any(|p| d.contains(p))
}

fn batch_failure(e: &TgError, batch_len: usize) -> BatchFailure {
    if is_method_missing(e) {
        BatchFailure::MethodMissing
    } else if matches!(e, TgError::BadRequest(_)) && !is_chat_error(e) {
        if batch_len > 1 { BatchFailure::TryEach } else { BatchFailure::Skip }
    } else {
        BatchFailure::Fail
    }
}

/// `deleteMessage` errors that only concern that message ("message to delete not found",
/// "message can't be deleted"): skip it and continue with the next id.
fn single_delete_skippable(e: &TgError) -> bool {
    matches!(e, TgError::BadRequest(_)) && !is_chat_error(e)
}

fn send_message_body(chat_id: i64, html: &str, keyboard: Option<&InlineKeyboardMarkup>) -> Result<Value, TgError> {
    let mut body = json!({ "chat_id": chat_id });
    add_text_fields(&mut body, html, keyboard)?;
    Ok(body)
}

/// editMessageText body; omitting the keyboard removes any existing inline keyboard.
fn edit_message_body(
    chat_id: i64,
    message_id: i64,
    html: &str,
    keyboard: Option<&InlineKeyboardMarkup>,
) -> Result<Value, TgError> {
    let mut body = json!({ "chat_id": chat_id, "message_id": message_id });
    add_text_fields(&mut body, html, keyboard)?;
    Ok(body)
}

/// text (+ parse_mode HTML unless degraded to plain text), link previews off, optional keyboard.
fn add_text_fields(body: &mut Value, html: &str, keyboard: Option<&InlineKeyboardMarkup>) -> Result<(), TgError> {
    let prepared = prepare_text(html, MAX_MESSAGE_LEN);
    body["text"] = Value::String(prepared.text.into_owned());
    if prepared.html {
        body["parse_mode"] = json!("HTML");
    }
    body["link_preview_options"] = json!({ "is_disabled": true });
    if let Some(kb) = keyboard {
        body["reply_markup"] = serde_json::to_value(kb)
            .map_err(|e| TgError::Parse(format!("cannot encode the keyboard: {}", json_error_text(&e))))?;
    }
    Ok(())
}

/// Message text ready to send.
#[derive(Debug, PartialEq, Eq)]
struct PreparedText<'a> {
    text: Cow<'a, str>,
    /// Send with `parse_mode=HTML`.
    html: bool,
}

/// Fit `html` into Telegram's `limit`:
/// * fits (raw, or after entity parsing) → unchanged HTML;
/// * no markup at all → truncated, still valid as HTML;
/// * otherwise cutting could break tags/entities → tags stripped, entities decoded, truncated,
///   and sent as plain text (no parse_mode).
fn prepare_text(html: &str, limit: usize) -> PreparedText<'_> {
    if utf16_len(html) <= limit {
        return PreparedText { text: Cow::Borrowed(html), html: true };
    }
    if !html.contains(['<', '>', '&']) {
        return PreparedText { text: truncate_utf16(html, limit), html: true };
    }
    let plain = html_to_plain(html);
    if utf16_len(&plain) <= limit {
        // Telegram applies the limit after entity parsing.
        return PreparedText { text: Cow::Borrowed(html), html: true };
    }
    PreparedText { text: Cow::Owned(truncate_utf16(&plain, limit).into_owned()), html: false }
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Truncate to at most `limit` UTF-16 code units (never splitting a character), ending with `…`.
fn truncate_utf16(s: &str, limit: usize) -> Cow<'_, str> {
    if utf16_len(s) <= limit {
        return Cow::Borrowed(s);
    }
    if limit == 0 {
        return Cow::Owned(String::new());
    }
    let budget = limit - 1; // room for the ellipsis (1 UTF-16 unit)
    let mut used = 0;
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if used + c.len_utf16() > budget {
            break;
        }
        used += c.len_utf16();
        end = i + c.len_utf8();
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push('…');
    Cow::Owned(out)
}

/// Strip Telegram-HTML tags and decode entities (`&lt; &gt; &amp; &quot; &apos; &#NN; &#xHH;`).
fn html_to_plain(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(i) = rest.find(['<', '&']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if tail.starts_with('<') {
            match tail.find('>') {
                Some(end) => rest = &tail[end + 1..],
                None => {
                    // Unterminated tag: keep the text rather than lose it.
                    out.push_str(tail);
                    rest = "";
                }
            }
        } else {
            match decode_entity(tail) {
                Some((c, len)) => {
                    out.push(c);
                    rest = &tail[len..];
                }
                None => {
                    out.push('&');
                    rest = &tail[1..];
                }
            }
        }
    }
    out.push_str(rest);
    out
}

/// Decode the entity at the start of `s` (which starts with `&`): (char, bytes consumed).
fn decode_entity(s: &str) -> Option<(char, usize)> {
    let end = s.bytes().take(12).position(|b| b == b';')?;
    let name = s.get(1..end)?;
    let c = match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let num = name.strip_prefix('#')?;
            let code = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse::<u32>().ok()?,
            };
            char::from_u32(code)?
        }
    };
    Some((c, end + 1))
}

// ---------------------------------------------------------------------------------------------
// Response handling (pure)
// ---------------------------------------------------------------------------------------------

/// Classify a Bot API reply: HTTP 2xx + `ok` → `Ok(result)`, otherwise a [`TgError`].
fn classify_response<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, TgError> {
    match serde_json::from_slice::<ApiResponse<T>>(body) {
        Ok(envelope) => classify_envelope(status, envelope),
        Err(e) if is_success(status) => {
            Err(TgError::Parse(format!("unexpected Telegram reply ({})", json_error_text(&e))))
        }
        // Non-JSON error page (proxy, load balancer...): classify by HTTP status alone.
        Err(_) => Err(status_error(status, None, None)),
    }
}

fn classify_envelope<T>(status: u16, envelope: ApiResponse<T>) -> Result<T, TgError> {
    if is_success(status) && envelope.ok {
        return envelope.result.ok_or_else(|| TgError::Parse("Telegram reply has no result".into()));
    }
    let code = if is_success(status) { envelope.error_code.unwrap_or(status) } else { status };
    let retry_after = envelope.parameters.as_ref().and_then(|p| p.retry_after);
    Err(status_error(code, envelope.description, retry_after))
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn status_error(code: u16, description: Option<String>, retry_after: Option<u64>) -> TgError {
    let description = description
        .map(|d| clean_description(&d))
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| default_description(code).to_string());
    match code {
        401 => TgError::Unauthorized,
        403 => TgError::Forbidden(description),
        400 => TgError::BadRequest(description),
        409 => TgError::Conflict(description),
        429 => TgError::RateLimited(retry_after.unwrap_or(DEFAULT_RETRY_AFTER_SECS)),
        _ => TgError::Server(code, description),
    }
}

/// Single line, bounded length.
fn clean_description(d: &str) -> String {
    let one_line = d.split_whitespace().collect::<Vec<_>>().join(" ");
    crate::util::truncate_chars(&one_line, MAX_DESCRIPTION_CHARS)
}

fn default_description(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "unexpected HTTP status",
    }
}

/// editMessageText's "message is not modified" (same text + keyboard) is a success for us.
fn is_not_modified(e: &TgError) -> bool {
    matches!(e, TgError::BadRequest(d) if d.to_ascii_lowercase().contains("message is not modified"))
}

/// Transport failure → [`TgError::Network`] (HttpError texts never contain the host/path).
fn network_error(e: &HttpError) -> TgError {
    TgError::Network(e.to_string())
}

/// Defence in depth: remove the token from any error text.
fn scrub_error(e: TgError, token: &str) -> TgError {
    let scrub = |s: String| if !token.is_empty() && s.contains(token) { s.replace(token, "<redacted>") } else { s };
    match e {
        TgError::Network(m) => TgError::Network(scrub(m)),
        TgError::Forbidden(m) => TgError::Forbidden(scrub(m)),
        TgError::BadRequest(m) => TgError::BadRequest(scrub(m)),
        TgError::Conflict(m) => TgError::Conflict(scrub(m)),
        TgError::Server(c, m) => TgError::Server(c, scrub(m)),
        TgError::Parse(m) => TgError::Parse(scrub(m)),
        other @ (TgError::Unauthorized | TgError::RateLimited(_)) => other,
    }
}

/// Describe a JSON error without echoing payload content (it may contain message text).
fn json_error_text(e: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let kind = match e.classify() {
        Category::Io => "I/O error",
        Category::Syntax => "malformed JSON",
        Category::Data => "unexpected JSON structure",
        Category::Eof => "truncated JSON",
    };
    if e.line() > 0 { format!("{kind} at line {} column {}", e.line(), e.column()) } else { kind.to_string() }
}

/// Convert raw updates one by one, so a single update with an unexpected shape cannot block the
/// whole batch (it is replaced by an empty update carrying its id, so the offset still advances).
fn parse_updates(raw: Vec<Value>) -> Vec<Update> {
    raw.into_iter()
        .filter_map(|v| {
            let id = v.get("update_id").and_then(Value::as_i64);
            match serde_json::from_value::<Update>(v) {
                Ok(u) => Some(u),
                Err(e) => {
                    let why = json_error_text(&e);
                    match id {
                        Some(update_id) => {
                            crate::log_warn!("Telegram update {update_id} skipped: {why}");
                            Some(Update {
                                update_id,
                                message: None,
                                edited_message: None,
                                callback_query: None,
                                my_chat_member: None,
                            })
                        }
                        None => {
                            crate::log_warn!("Telegram update without update_id skipped: {why}");
                            None
                        }
                    }
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::types::InlineKeyboardButton;

    const TEST_TOKEN: &str = "123456:AAFakeTokenForTestsOnly_0123456789a";

    #[test]
    fn token_format() {
        assert!(is_valid_token_format("123456:AAFakeTokenForTestsOnly_0123456789a"));
        assert!(!is_valid_token_format("123456AAFakeTo"));
        assert!(!is_valid_token_format("abc:AAFakeTokenForTestsOnly_0123456789a"));
        assert!(!is_valid_token_format("123:short"));
        assert!(!is_valid_token_format("123:AAFakeTokenForTestsOnly_0123456789a/../x"));
    }

    // ---- response classification -------------------------------------------------------------

    #[test]
    fn ok_result() {
        let body = br#"{"ok":true,"result":{"id":7,"is_bot":true,"first_name":"Predator","username":"PredBot"}}"#;
        let u: User = classify_response(200, body).unwrap();
        assert_eq!(u.id, 7);
        assert_eq!(u.username.as_deref(), Some("PredBot"));
        let sent: SentMessage =
            classify_response(200, br#"{"ok":true,"result":{"message_id":99,"chat":{"id":1,"type":"private"}}}"#)
                .unwrap();
        assert_eq!(sent.message_id, 99);
        let _: IgnoredAny = classify_response(200, br#"{"ok":true,"result":true}"#).unwrap();
    }

    #[test]
    fn ok_but_unexpected_or_missing_result_is_parse_error() {
        let r: Result<User, _> = classify_response(200, br#"{"ok":true,"result":"text"}"#);
        assert!(matches!(r, Err(TgError::Parse(_))), "{r:?}");
        let r: Result<User, _> = classify_response(200, br#"{"ok":true}"#);
        assert!(matches!(r, Err(TgError::Parse(_))), "{r:?}");
        let r: Result<User, _> = classify_response(200, b"<html>hello</html>");
        assert!(matches!(r, Err(TgError::Parse(_))), "{r:?}");
        let r: Result<User, _> = classify_response(200, b"");
        assert!(matches!(r, Err(TgError::Parse(_))), "{r:?}");
    }

    #[test]
    fn parse_error_does_not_echo_content() {
        let r: Result<User, _> = classify_response(200, br#"{"ok":true,"result":"secret message text"}"#);
        let Err(TgError::Parse(m)) = r else { panic!("expected Parse") };
        assert!(!m.contains("secret"), "{m}");
    }

    #[test]
    fn error_statuses() {
        let r: Result<User, _> =
            classify_response(401, br#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#);
        assert_eq!(r.unwrap_err(), TgError::Unauthorized);
        let r: Result<User, _> = classify_response(401, b"not json");
        assert_eq!(r.unwrap_err(), TgError::Unauthorized);

        let r: Result<User, _> = classify_response(
            403,
            br#"{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}"#,
        );
        assert_eq!(r.unwrap_err(), TgError::Forbidden("Forbidden: bot was blocked by the user".into()));

        let r: Result<User, _> = classify_response(
            400,
            br#"{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities"}"#,
        );
        assert_eq!(r.unwrap_err(), TgError::BadRequest("Bad Request: can't parse entities".into()));

        let r: Result<User, _> = classify_response(
            409,
            br#"{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}"#,
        );
        assert_eq!(r.unwrap_err(), TgError::Conflict("Conflict: terminated by other getUpdates request".into()));

        let r: Result<User, _> = classify_response(
            429,
            br#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 17","parameters":{"retry_after":17}}"#,
        );
        assert_eq!(r.unwrap_err(), TgError::RateLimited(17));
        let r: Result<User, _> = classify_response(429, br#"{"ok":false,"error_code":429}"#);
        assert_eq!(r.unwrap_err(), TgError::RateLimited(5));
        let r: Result<User, _> = classify_response(429, b"");
        assert_eq!(r.unwrap_err(), TgError::RateLimited(5));

        let r: Result<User, _> =
            classify_response(500, br#"{"ok":false,"error_code":500,"description":"Internal Server Error"}"#);
        assert_eq!(r.unwrap_err(), TgError::Server(500, "Internal Server Error".into()));
        let r: Result<User, _> = classify_response(502, b"<html><body>502 Bad Gateway</body></html>");
        assert_eq!(r.unwrap_err(), TgError::Server(502, "Bad Gateway".into()));
        let r: Result<User, _> = classify_response(404, br#"{"ok":false,"error_code":404,"description":"Not Found"}"#);
        assert_eq!(r.unwrap_err(), TgError::Server(404, "Not Found".into()));
        let r: Result<User, _> = classify_response(302, b"");
        assert_eq!(r.unwrap_err(), TgError::Server(302, "unexpected HTTP status".into()));
    }

    #[test]
    fn ok_false_with_200_uses_error_code() {
        let r: Result<User, _> = classify_response(200, br#"{"ok":false,"error_code":400,"description":"Bad"}"#);
        assert_eq!(r.unwrap_err(), TgError::BadRequest("Bad".into()));
        let r: Result<User, _> = classify_response(200, br#"{"ok":false}"#);
        assert!(matches!(r, Err(TgError::Server(200, _))));
    }

    #[test]
    fn descriptions_are_single_line_and_bounded() {
        let long = format!(r#"{{"ok":false,"error_code":400,"description":"a\nb {}"}}"#, "x".repeat(1000));
        let r: Result<User, _> = classify_response(400, long.as_bytes());
        let Err(TgError::BadRequest(d)) = r else { panic!("expected BadRequest") };
        assert!(d.starts_with("a b "));
        assert!(d.chars().count() <= MAX_DESCRIPTION_CHARS);
        let r: Result<User, _> = classify_response(400, br#"{"ok":false,"description":"   "}"#);
        assert_eq!(r.unwrap_err(), TgError::BadRequest("Bad Request".into()));
    }

    #[test]
    fn not_modified_detection() {
        let e = TgError::BadRequest(
            "Bad Request: message is not modified: specified new message content and reply markup are exactly the same"
                .into(),
        );
        assert!(is_not_modified(&e));
        assert!(is_not_modified(&TgError::BadRequest("Bad Request: Message is not modified".into())));
        assert!(!is_not_modified(&TgError::BadRequest("Bad Request: message to edit not found".into())));
        assert!(!is_not_modified(&TgError::Forbidden("message is not modified".into())));
        // Via the full classification path.
        let r: Result<IgnoredAny, _> = classify_response(
            400,
            br#"{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message"}"#,
        );
        assert!(is_not_modified(&r.unwrap_err()));
    }

    // ---- updates -----------------------------------------------------------------------------

    #[test]
    fn updates_are_parsed_individually() {
        let body = br#"{"ok":true,"result":[
            {"update_id":10,"message":{"message_id":5,"date":1700000000,"chat":{"id":42,"type":"private"},"from":{"id":42,"is_bot":false,"first_name":"A"},"text":"/start"}},
            {"update_id":11,"message":{"message_id":"broken"}},
            {"no_id":true},
            {"update_id":12,"callback_query":{"id":"abc","from":{"id":42,"is_bot":false,"first_name":"A"},"data":"nav:main"}}
        ]}"#;
        let raw: Vec<Value> = classify_response(200, body).unwrap();
        let updates = parse_updates(raw);
        assert_eq!(updates.iter().map(|u| u.update_id).collect::<Vec<_>>(), vec![10, 11, 12]);
        assert_eq!(updates[0].message.as_ref().unwrap().text.as_deref(), Some("/start"));
        assert!(updates[1].message.is_none() && updates[1].callback_query.is_none());
        assert_eq!(updates[2].callback_query.as_ref().unwrap().data.as_deref(), Some("nav:main"));
        let empty: Vec<Value> = classify_response(200, br#"{"ok":true,"result":[]}"#).unwrap();
        assert!(parse_updates(empty).is_empty());
    }

    // ---- request bodies ----------------------------------------------------------------------

    fn keyboard() -> InlineKeyboardMarkup {
        InlineKeyboardMarkup::new(vec![
            vec![InlineKeyboardButton::callback("📊 Status", "nav:status")],
            vec![InlineKeyboardButton::callback("A", "x"), InlineKeyboardButton::url("Open", "https://t.me/x")],
        ])
    }

    #[test]
    fn send_body_with_keyboard() {
        let body = send_message_body(42, "<b>Hi</b>", Some(&keyboard())).unwrap();
        assert_eq!(
            body,
            json!({
                "chat_id": 42,
                "text": "<b>Hi</b>",
                "parse_mode": "HTML",
                "link_preview_options": { "is_disabled": true },
                "reply_markup": { "inline_keyboard": [
                    [ { "text": "📊 Status", "callback_data": "nav:status" } ],
                    [ { "text": "A", "callback_data": "x" }, { "text": "Open", "url": "https://t.me/x" } ]
                ] }
            })
        );
    }

    #[test]
    fn send_body_without_keyboard_has_no_reply_markup() {
        let body = send_message_body(-5, "plain", None).unwrap();
        assert_eq!(
            body,
            json!({ "chat_id": -5, "text": "plain", "parse_mode": "HTML", "link_preview_options": { "is_disabled": true } })
        );
    }

    #[test]
    fn edit_body() {
        let with = edit_message_body(42, 7, "x", Some(&keyboard())).unwrap();
        assert_eq!(with["message_id"], json!(7));
        assert_eq!(with["chat_id"], json!(42));
        assert_eq!(with["parse_mode"], json!("HTML"));
        assert!(with.get("reply_markup").is_some());
        let without = edit_message_body(42, 7, "x", None).unwrap();
        assert!(without.get("reply_markup").is_none(), "omitting the keyboard removes it");
        assert_eq!(without["link_preview_options"], json!({ "is_disabled": true }));
    }

    #[test]
    fn get_updates_body_shape() {
        assert_eq!(
            get_updates_body(101, 50),
            json!({ "offset": 101, "timeout": 50, "allowed_updates": ["message", "callback_query", "my_chat_member"] })
        );
    }

    #[test]
    fn set_my_commands_body_shape() {
        assert_eq!(
            set_my_commands_body(&[("status", "System status"), ("help", "Help")]),
            json!({
                "commands": [
                    { "command": "status", "description": "System status" },
                    { "command": "help", "description": "Help" }
                ],
                "scope": { "type": "all_private_chats" }
            })
        );
    }

    // ---- message deletion --------------------------------------------------------------------

    #[test]
    fn delete_bodies() {
        assert_eq!(delete_messages_body(42, &[5, 6]), json!({ "chat_id": 42, "message_ids": [5, 6] }));
        assert_eq!(delete_message_body(42, 5), json!({ "chat_id": 42, "message_id": 5 }));
    }

    #[test]
    fn delete_batches_dedupe_filter_and_split() {
        assert!(delete_batches(&[]).is_empty());
        assert!(delete_batches(&[0, -4]).is_empty());
        assert_eq!(delete_batches(&[3, 1, 3, 0, 2, 1]), vec![vec![3, 1, 2]]);
        let many: Vec<i64> = (1..=250).collect();
        let batches = delete_batches(&many);
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), vec![100, 100, 50]);
        assert_eq!(batches[1][0], 101);
        assert_eq!(batches.concat(), many);
    }

    #[test]
    fn delete_failure_classification() {
        // api.telegram.org answers an unknown method with 404 Not Found
        let r: Result<IgnoredAny, _> =
            classify_response(404, br#"{"ok":false,"error_code":404,"description":"Not Found"}"#);
        let e = r.unwrap_err();
        assert_eq!(batch_failure(&e, 3), BatchFailure::MethodMissing);
        assert_eq!(
            batch_failure(&TgError::BadRequest("Bad Request: method not found".into()), 1),
            BatchFailure::MethodMissing
        );
        assert_eq!(
            batch_failure(&TgError::BadRequest("unknown method deleteMessages".into()), 2),
            BatchFailure::MethodMissing
        );
        // a refused batch is retried one by one; a refused single id is skipped
        let refused = TgError::BadRequest("Bad Request: message can't be deleted".into());
        assert_eq!(batch_failure(&refused, 5), BatchFailure::TryEach);
        assert_eq!(batch_failure(&refused, 1), BatchFailure::Skip);
        assert_eq!(
            batch_failure(&TgError::BadRequest("Bad Request: message to delete not found".into()), 4),
            BatchFailure::TryEach
        );
        // everything else is reported (retryable ones are retried by the janitor)
        for e in [
            TgError::Network("timeout".into()),
            TgError::RateLimited(3),
            TgError::Server(502, "Bad Gateway".into()),
            TgError::Forbidden("bot was blocked by the user".into()),
            TgError::Unauthorized,
        ] {
            assert_eq!(batch_failure(&e, 2), BatchFailure::Fail, "{e:?}");
            assert!(!single_delete_skippable(&e), "{e:?}");
        }
        assert!(single_delete_skippable(&TgError::BadRequest("Bad Request: message to delete not found".into())));
        // a problem with the chat itself is reported at once (no request per id)
        for d in ["Bad Request: chat not found", "Bad Request: PEER_ID_INVALID", "Bad Request: chat_id is empty"] {
            let e = TgError::BadRequest(d.into());
            assert_eq!(batch_failure(&e, 5), BatchFailure::Fail, "{d}");
            assert_eq!(batch_failure(&e, 1), BatchFailure::Fail, "{d}");
            assert!(!single_delete_skippable(&e), "{d}");
            assert!(!e.is_retryable(), "forgotten by the janitor: {d}");
        }
    }

    #[test]
    fn telegram_api_is_send_sync_with_delete_state() {
        fn check<T: Send + Sync>() {}
        check::<TelegramApi>();
        let api = TelegramApi::new(TEST_TOKEN).expect("client");
        assert!(!api.legacy_delete.load(Ordering::Relaxed));
        // nothing valid to delete: no request is made at all
        assert_eq!(api.delete_messages(42, &[]), Ok(()));
        assert_eq!(api.delete_messages(42, &[0, -1]), Ok(()));
    }

    #[test]
    fn answer_callback_body_shape() {
        assert_eq!(
            answer_callback_body("cb1", None, false),
            json!({ "callback_query_id": "cb1", "show_alert": false })
        );
        assert_eq!(
            answer_callback_body("cb1", Some("⛔ Not authorized"), true),
            json!({ "callback_query_id": "cb1", "show_alert": true, "text": "⛔ Not authorized" })
        );
        let long = "y".repeat(500);
        let body = answer_callback_body("cb1", Some(&long), false);
        assert_eq!(utf16_len(body["text"].as_str().unwrap()), MAX_CALLBACK_TEXT_LEN);
    }

    // ---- text preparation / truncation -------------------------------------------------------

    #[test]
    fn short_text_unchanged() {
        let p = prepare_text("<b>Hello</b> &amp; bye", MAX_MESSAGE_LEN);
        assert_eq!(p, PreparedText { text: Cow::Borrowed("<b>Hello</b> &amp; bye"), html: true });
    }

    #[test]
    fn long_plain_text_truncated_keeps_html_mode() {
        let s = "a".repeat(5000);
        let p = prepare_text(&s, MAX_MESSAGE_LEN);
        assert!(p.html);
        assert_eq!(utf16_len(&p.text), MAX_MESSAGE_LEN);
        assert!(p.text.ends_with('…'));
    }

    #[test]
    fn long_html_degrades_to_plain_text() {
        let s = format!("<b>TITLE</b>\n<code>{}</code> &lt;tail&gt;", "z".repeat(5000));
        let p = prepare_text(&s, MAX_MESSAGE_LEN);
        assert!(!p.html, "must be sent without parse_mode");
        assert!(utf16_len(&p.text) <= MAX_MESSAGE_LEN);
        assert!(p.text.starts_with("TITLE\nzzz"));
        assert!(!p.text.contains('<') && !p.text.contains("&lt;"));
        assert!(p.text.ends_with('…'));
        // The body built from it has no parse_mode.
        let body = send_message_body(1, &s, None).unwrap();
        assert!(body.get("parse_mode").is_none());
    }

    #[test]
    fn long_markup_whose_visible_text_fits_is_kept() {
        // 3000 visible chars but > 4096 raw chars because of tags/entities.
        let s = "<b>&amp;</b>".repeat(3000);
        assert!(utf16_len(&s) > MAX_MESSAGE_LEN);
        let p = prepare_text(&s, MAX_MESSAGE_LEN);
        assert!(p.html);
        assert_eq!(p.text, s);
    }

    #[test]
    fn truncation_counts_utf16_and_never_splits_chars() {
        let s = "😀".repeat(3000); // 6000 UTF-16 units
        let p = prepare_text(&s, MAX_MESSAGE_LEN);
        assert!(utf16_len(&p.text) <= MAX_MESSAGE_LEN);
        assert!(p.text.ends_with('…'));
        assert!(p.text.trim_end_matches('…').chars().all(|c| c == '😀'));
        assert_eq!(truncate_utf16("abc", 3), "abc");
        assert_eq!(truncate_utf16("abcd", 3), "ab…");
        assert_eq!(truncate_utf16("😀😀", 3), "😀…");
        assert_eq!(truncate_utf16("😀😀", 2), "…");
        assert_eq!(truncate_utf16("abcd", 0), "");
    }

    #[test]
    fn html_to_plain_decodes() {
        assert_eq!(html_to_plain("<b>a</b> &lt;b&gt; &amp;amp; &quot;q&quot; &#39;s&#x27;"), "a <b> &amp; \"q\" 's'");
        assert_eq!(html_to_plain(r#"<a href="https://x.y/?a=1&amp;b=2">link</a>"#), "link");
        assert_eq!(html_to_plain("AT&T & co &bogus; &#xZZ;"), "AT&T & co &bogus; &#xZZ;");
        assert_eq!(html_to_plain("broken <b tag"), "broken <b tag");
        assert_eq!(html_to_plain("ünï <i>cødé</i> ✓"), "ünï cødé ✓");
    }

    // ---- secrecy -----------------------------------------------------------------------------

    #[test]
    fn debug_and_errors_never_contain_the_token() {
        let api = TelegramApi::new(TEST_TOKEN).expect("client");
        let dbg = format!("{api:?}");
        assert!(!dbg.contains(TEST_TOKEN) && !dbg.contains("AAFakeTo"), "{dbg}");
        assert_eq!(dbg, "TelegramApi { token: <redacted> }");

        // The path carries the token, so errors are scrubbed defensively.
        let path = method_path(TEST_TOKEN, "getMe");
        assert!(path.contains(TEST_TOKEN));
        for e in [
            TgError::Network(format!("failed {path}")),
            TgError::BadRequest(format!("x {TEST_TOKEN}")),
            TgError::Forbidden(TEST_TOKEN.into()),
            TgError::Conflict(TEST_TOKEN.into()),
            TgError::Server(500, TEST_TOKEN.into()),
            TgError::Parse(TEST_TOKEN.into()),
        ] {
            let s = scrub_error(e, TEST_TOKEN);
            assert!(!s.to_string().contains(TEST_TOKEN) && !format!("{s:?}").contains(TEST_TOKEN), "{s:?}");
        }
        assert_eq!(scrub_error(TgError::Unauthorized, TEST_TOKEN), TgError::Unauthorized);

        // Transport errors are built from HttpError texts, which carry no host/path.
        for h in [
            HttpError::Timeout,
            HttpError::Network { code: 12007, message: "The server name or address could not be resolved".into() },
            HttpError::Other("response is larger than 4 MiB; aborted".into()),
        ] {
            let e = network_error(&h);
            assert!(matches!(e, TgError::Network(_)));
            assert!(!e.to_string().contains("api.telegram.org") && !e.to_string().contains("/bot"));
        }
    }

    #[test]
    fn malformed_token_is_rejected_without_echo() {
        let bad = "123:AAFakeTokenForTestsOnly_0123456789a/../evil";
        let e = TelegramApi::new(bad).unwrap_err();
        assert_eq!(e, TgError::Unauthorized);
        assert!(!format!("{e:?} {e}").contains("AAFakeTo"));
    }

    #[test]
    fn only_send_message_is_protected_from_interrupts_once_sent() {
        assert_eq!(interrupt_policy("getUpdates"), Interruptible::Always);
        for m in [
            "sendMessage",
            "getMe",
            "setMyCommands",
            "deleteWebhook",
            "editMessageText",
            "answerCallbackQuery",
            "leaveChat",
            "deleteMessages",
            "deleteMessage",
        ] {
            assert_eq!(interrupt_policy(m), Interruptible::UntilSent, "{m}");
        }
    }

    #[test]
    fn interrupt_and_transport_name_without_requests() {
        let api = TelegramApi::new(TEST_TOKEN).expect("client");
        api.interrupt(); // nothing in flight: harmless
        assert!(!api.transport_name().is_empty());
        assert!(!api.transport_name().contains(TEST_TOKEN));
    }

    /// Live check of the transport (DNS + TCP + TLS + HTTP) without any real token:
    /// `cargo test --lib telegram::api -- --ignored`.
    #[test]
    #[ignore = "needs internet access to api.telegram.org"]
    fn live_invalid_token_reaches_telegram() {
        let http = HttpClient::new("PredatorTest/1.0").expect("client");
        println!("transport: {}", http.transport_name());
        for _ in 0..2 {
            let resp = http
                .post_json(API_HOST, "/botINVALID/getMe", b"{}", Duration::from_secs(20))
                .unwrap_or_else(|e| panic!("transport failed: {e}"));
            println!("HTTP {} body: {}", resp.status, String::from_utf8_lossy(&resp.body));
            assert!(resp.status == 401 || resp.status == 404, "unexpected status {}", resp.status);
            let classified: Result<User, TgError> = classify_response(resp.status, &resp.body);
            println!("classified as: {classified:?}");
            assert!(matches!(classified, Err(TgError::Unauthorized) | Err(TgError::Server(404, _))));
        }
    }
}
