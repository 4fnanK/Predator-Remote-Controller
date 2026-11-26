//! Minimal Telegram Bot API types (only the fields we use; unknown fields are ignored).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Chat {
    pub id: i64,
    /// "private", "group", "supergroup" or "channel".
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

impl Chat {
    pub fn is_private(&self) -> bool {
        self.kind == "private"
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Message {
    pub message_id: i64,
    /// Unix seconds (sender time).
    #[serde(default)]
    pub date: i64,
    pub chat: Chat,
    #[serde(default)]
    pub from: Option<User>,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub data: Option<String>,
}

/// `my_chat_member` update (bot added to / removed from a chat).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChatMemberUpdated {
    pub chat: Chat,
    pub from: User,
    #[serde(default)]
    pub date: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub edited_message: Option<Message>,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
    #[serde(default)]
    pub my_chat_member: Option<ChatMemberUpdated>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InlineKeyboardButton {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub callback_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
}

impl InlineKeyboardButton {
    pub fn callback(text: impl Into<String>, data: impl Into<String>) -> Self {
        Self { text: text.into(), callback_data: Some(data.into()), url: None }
    }
    pub fn url(text: impl Into<String>, url: impl Into<String>) -> Self {
        Self { text: text.into(), callback_data: None, url: Some(url.into()) }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InlineKeyboardMarkup {
    pub inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

impl InlineKeyboardMarkup {
    pub fn new(rows: Vec<Vec<InlineKeyboardButton>>) -> Self {
        Self { inline_keyboard: rows }
    }
    /// All callback_data values (tests use this to check every button is wired).
    pub fn callback_datas(&self) -> Vec<String> {
        self.inline_keyboard.iter().flatten().filter_map(|b| b.callback_data.clone()).collect()
    }
}

/// Generic Bot API envelope.
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub ok: bool,
    #[serde(default = "Option::default")]
    pub result: Option<T>,
    #[serde(default)]
    pub error_code: Option<u16>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Option<ResponseParameters>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResponseParameters {
    #[serde(default)]
    pub retry_after: Option<u64>,
    #[serde(default)]
    pub migrate_to_chat_id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_updates() {
        let json = r#"{"ok":true,"result":[
          {"update_id":10,"message":{"message_id":5,"date":1700000000,"chat":{"id":42,"type":"private","first_name":"A"},"from":{"id":42,"is_bot":false,"first_name":"A","username":"aa"},"text":"/start"}},
          {"update_id":11,"callback_query":{"id":"abc","from":{"id":42,"is_bot":false,"first_name":"A"},"message":{"message_id":6,"date":1,"chat":{"id":42,"type":"private"}},"chat_instance":"x","data":"nav:main"}}
        ]}"#;
        let r: ApiResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        let u = r.result.unwrap();
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].message.as_ref().unwrap().text.as_deref(), Some("/start"));
        assert!(u[0].message.as_ref().unwrap().chat.is_private());
        assert_eq!(u[1].callback_query.as_ref().unwrap().data.as_deref(), Some("nav:main"));
    }

    #[test]
    fn keyboard_json() {
        let kb = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback("A", "x")]]);
        let s = serde_json::to_string(&kb).unwrap();
        assert_eq!(s, r#"{"inline_keyboard":[[{"text":"A","callback_data":"x"}]]}"#);
    }
}
