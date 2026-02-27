use super::traits::{Channel, ChannelMessage, SendMessage};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use uuid::Uuid;

const FROM_ME_CACHE_MAX: usize = 500;

/// A cached `fromMe` message — kept so reply context can be resolved when
/// the other party replies to something the bot sent.
struct FromMeCacheEntry {
    chat_guid: String,
    body: String,
    #[allow(dead_code)]
    timestamp: u64,
}

/// BlueBubbles channel — uses the BlueBubbles REST API to send and receive
/// iMessages via a locally-running BlueBubbles server on macOS.
///
/// This channel operates in webhook mode (push-based) rather than polling.
/// Messages are received via the gateway's `/bluebubbles` webhook endpoint.
/// The `listen` method is a keepalive placeholder; actual message handling
/// happens in the gateway when BlueBubbles POSTs webhook events.
///
/// BlueBubbles server must be configured to send webhooks to:
///   `https://<your-zeroclaw-host>/bluebubbles`
///
/// Authentication: BlueBubbles uses `?password=<password>` as a query
/// parameter on every API call (not an Authorization header).
pub struct BlueBubblesChannel {
    server_url: String,
    password: String,
    allowed_senders: Vec<String>,
    client: reqwest::Client,
    /// Cache of recent `fromMe` messages keyed by message GUID.
    /// Kept so the agent can resolve reply context (body/chat) when a user
    /// replies to a message the bot sent.
    from_me_cache: Mutex<HashMap<String, FromMeCacheEntry>>,
}

impl BlueBubblesChannel {
    pub fn new(server_url: String, password: String, allowed_senders: Vec<String>) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            password,
            allowed_senders,
            client: reqwest::Client::new(),
            from_me_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a sender address is allowed.
    ///
    /// Matches OpenClaw behaviour: empty list → allow all (no allowlist
    /// configured means "open"). Use `"*"` for explicit wildcard.
    fn is_sender_allowed(&self, sender: &str) -> bool {
        if self.allowed_senders.is_empty() {
            return true;
        }
        self.allowed_senders
            .iter()
            .any(|a| a == "*" || a.eq_ignore_ascii_case(sender))
    }

    /// Build a full API URL for the given endpoint path.
    fn api_url(&self, path: &str) -> String {
        format!("{}{path}", self.server_url)
    }

    /// Normalize a BlueBubbles handle, matching OpenClaw's `normalizeBlueBubblesHandle`:
    /// - Strip service prefixes: `imessage:`, `sms:`, `auto:`
    /// - Email addresses → lowercase
    /// - Phone numbers → strip internal whitespace only
    fn normalize_handle(raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let lower = trimmed.to_ascii_lowercase();
        let stripped = if lower.starts_with("imessage:") {
            &trimmed[9..]
        } else if lower.starts_with("sms:") {
            &trimmed[4..]
        } else if lower.starts_with("auto:") {
            &trimmed[5..]
        } else {
            trimmed
        };
        // Recurse if another prefix is still present
        let stripped_lower = stripped.to_ascii_lowercase();
        if stripped_lower.starts_with("imessage:")
            || stripped_lower.starts_with("sms:")
            || stripped_lower.starts_with("auto:")
        {
            return Self::normalize_handle(stripped);
        }
        if stripped.contains('@') {
            stripped.to_ascii_lowercase()
        } else {
            stripped.chars().filter(|c| !c.is_whitespace()).collect()
        }
    }

    /// Extract sender from multiple possible locations in the payload `data`
    /// object, matching OpenClaw's fallback chain.
    fn extract_sender(data: &serde_json::Value) -> Option<String> {
        // handle / sender nested object
        let handle = data.get("handle").or_else(|| data.get("sender"));
        if let Some(h) = handle {
            for key in &["address", "handle", "id"] {
                if let Some(addr) = h.get(key).and_then(|v| v.as_str()) {
                    let normalized = Self::normalize_handle(addr);
                    if !normalized.is_empty() {
                        return Some(normalized);
                    }
                }
            }
        }
        // Top-level fallbacks
        for key in &["senderId", "sender", "from"] {
            if let Some(v) = data.get(key).and_then(|v| v.as_str()) {
                let normalized = Self::normalize_handle(v);
                if !normalized.is_empty() {
                    return Some(normalized);
                }
            }
        }
        None
    }

    /// Extract the chat GUID from multiple possible locations in the `data`
    /// object. Preference order matches OpenClaw: direct fields, nested chat,
    /// then chats array.
    fn extract_chat_guid(data: &serde_json::Value) -> Option<String> {
        // Direct fields
        for key in &["chatGuid", "chat_guid"] {
            if let Some(g) = data.get(key).and_then(|v| v.as_str()) {
                let t = g.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
        // Nested chat/conversation object
        if let Some(chat) = data.get("chat").or_else(|| data.get("conversation")) {
            for key in &["chatGuid", "chat_guid", "guid"] {
                if let Some(g) = chat.get(key).and_then(|v| v.as_str()) {
                    let t = g.trim();
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                }
            }
        }
        // chats array (BB webhook format)
        if let Some(arr) = data.get("chats").and_then(|c| c.as_array()) {
            if let Some(first) = arr.first() {
                for key in &["chatGuid", "chat_guid", "guid"] {
                    if let Some(g) = first.get(key).and_then(|v| v.as_str()) {
                        let t = g.trim();
                        if !t.is_empty() {
                            return Some(t.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract the message GUID/ID from the `data` object.
    fn extract_message_id(data: &serde_json::Value) -> Option<String> {
        for key in &["guid", "id", "messageId"] {
            if let Some(v) = data.get(key).and_then(|v| v.as_str()) {
                let t = v.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
        None
    }

    /// Normalize a BB timestamp: values > 1e12 are milliseconds → convert to
    /// seconds. Values ≤ 1e12 are already seconds.
    fn normalize_timestamp(raw: u64) -> u64 {
        if raw > 1_000_000_000_000 {
            raw / 1000
        } else {
            raw
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn extract_timestamp(data: &serde_json::Value) -> u64 {
        data.get("dateCreated")
            .or_else(|| data.get("date"))
            .or_else(|| data.get("timestamp"))
            .and_then(|t| t.as_u64())
            .map(Self::normalize_timestamp)
            .unwrap_or_else(Self::now_secs)
    }

    /// Cache a `fromMe` message for later reply-context resolution.
    fn cache_from_me(&self, message_id: &str, chat_guid: &str, body: &str, timestamp: u64) {
        if message_id.is_empty() {
            return;
        }
        let mut cache = self.from_me_cache.lock();
        // Simple LRU eviction: remove the first (oldest) entry when full
        if cache.len() >= FROM_ME_CACHE_MAX {
            if let Some(oldest) = cache.keys().next().cloned() {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            message_id.to_string(),
            FromMeCacheEntry {
                chat_guid: chat_guid.to_string(),
                body: body.to_string(),
                timestamp,
            },
        );
    }

    /// Build the text content and attachment placeholder from a BB `data`
    /// object. Matches OpenClaw's `buildAttachmentPlaceholder` format:
    ///   `<media:image> (1 image)`, `<media:video> (2 videos)`, etc.
    fn extract_content(data: &serde_json::Value) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();

        // Text field (try several names)
        for key in &["text", "body", "subject"] {
            if let Some(text) = data.get(key).and_then(|t| t.as_str()) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                    break;
                }
            }
        }

        // Attachment placeholder
        if let Some(attachments) = data.get("attachments").and_then(|a| a.as_array()) {
            if !attachments.is_empty() {
                let mime_types: Vec<&str> = attachments
                    .iter()
                    .filter_map(|att| {
                        att.get("mimeType")
                            .or_else(|| att.get("mime_type"))
                            .and_then(|m| m.as_str())
                    })
                    .collect();

                let all_images =
                    !mime_types.is_empty() && mime_types.iter().all(|m| m.starts_with("image/"));
                let all_videos =
                    !mime_types.is_empty() && mime_types.iter().all(|m| m.starts_with("video/"));
                let all_audio =
                    !mime_types.is_empty() && mime_types.iter().all(|m| m.starts_with("audio/"));

                let (tag, label) = if all_images {
                    ("<media:image>", "image")
                } else if all_videos {
                    ("<media:video>", "video")
                } else if all_audio {
                    ("<media:audio>", "audio")
                } else {
                    ("<media:attachment>", "file")
                };

                let count = attachments.len();
                let suffix = if count == 1 {
                    label.to_string()
                } else {
                    format!("{label}s")
                };
                parts.push(format!("{tag} ({count} {suffix})"));
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n"))
        }
    }

    /// Parse an incoming webhook payload from BlueBubbles and extract messages.
    ///
    /// BlueBubbles webhook envelope:
    /// ```json
    /// {
    ///   "type": "new-message",
    ///   "data": {
    ///     "guid": "p:0/...",
    ///     "text": "Hello!",
    ///     "isFromMe": false,
    ///     "dateCreated": 1708987654321,
    ///     "handle": { "address": "+1234567890" },
    ///     "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
    ///     "attachments": []
    ///   }
    /// }
    /// ```
    ///
    /// `fromMe` messages are cached for reply-context resolution but are not
    /// returned as processable messages (the bot doesn't respond to itself).
    pub fn parse_webhook_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let mut messages = Vec::new();

        let event_type = payload
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if event_type != "new-message" {
            tracing::debug!("BlueBubbles: skipping non-message event: {event_type}");
            return messages;
        }

        let Some(data) = payload.get("data") else {
            return messages;
        };

        let is_from_me = data
            .get("isFromMe")
            .or_else(|| data.get("is_from_me"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if is_from_me {
            // Cache outgoing messages so reply context can be resolved later.
            let message_id = Self::extract_message_id(data).unwrap_or_default();
            let chat_guid = Self::extract_chat_guid(data).unwrap_or_default();
            let body = data
                .get("text")
                .or_else(|| data.get("body"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let timestamp = Self::extract_timestamp(data);
            self.cache_from_me(&message_id, &chat_guid, &body, timestamp);
            tracing::debug!("BlueBubbles: cached fromMe message {message_id}");
            return messages;
        }

        let Some(sender) = Self::extract_sender(data) else {
            tracing::debug!("BlueBubbles: skipping message with no sender");
            return messages;
        };

        if !self.is_sender_allowed(&sender) {
            tracing::warn!(
                "BlueBubbles: ignoring message from unauthorized sender: {sender}. \
                Add to channels.bluebubbles.allowed_senders in config.toml, \
                or use \"*\" to allow all senders."
            );
            return messages;
        }

        // Use chat GUID as reply_target — ensures replies go to the correct
        // conversation (important for group chats). Falls back to sender address.
        let reply_target = Self::extract_chat_guid(data)
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| sender.clone());

        let Some(content) = Self::extract_content(data) else {
            tracing::debug!("BlueBubbles: skipping empty message from {sender}");
            return messages;
        };

        let timestamp = Self::extract_timestamp(data);

        // Prefer the BB message GUID for deduplication; fall back to a new UUID.
        let id = Self::extract_message_id(data).unwrap_or_else(|| Uuid::new_v4().to_string());

        messages.push(ChannelMessage {
            id,
            sender,
            reply_target,
            content,
            channel: "bluebubbles".to_string(),
            timestamp,
            thread_ts: None,
        });

        messages
    }
}

#[async_trait]
impl Channel for BlueBubblesChannel {
    fn name(&self) -> &str {
        "bluebubbles"
    }

    /// Send a message via the BlueBubbles REST API.
    ///
    /// `message.recipient` must be a chat GUID (e.g. `iMessage;-;+15551234567`).
    /// Chat GUIDs are provided in the `reply_target` field of incoming messages.
    ///
    /// Authentication is via `?password=` query param (not a Bearer header).
    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        let url = self.api_url("/api/v1/message/text");

        let body = serde_json::json!({
            "chatGuid": message.recipient,
            "tempGuid": Uuid::new_v4().to_string(),
            "message": message.content,
        });

        let resp = self
            .client
            .post(&url)
            .query(&[("password", &self.password)])
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            return Ok(());
        }

        let status = resp.status();
        let error_body = resp.text().await.unwrap_or_default();
        let sanitized = crate::providers::sanitize_api_error(&error_body);
        tracing::error!("BlueBubbles send failed: {status} — {sanitized}");
        anyhow::bail!("BlueBubbles API error: {status}");
    }

    /// Keepalive placeholder — actual messages arrive via the `/bluebubbles` webhook.
    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        tracing::info!(
            "BlueBubbles channel active (webhook mode). \
            Configure your BlueBubbles server to POST webhooks to /bluebubbles."
        );
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    /// Verify the BlueBubbles server is reachable.
    /// Uses `/api/v1/ping` — the lightest probe endpoint (matches OpenClaw).
    /// Authentication is via `?password=` query param.
    async fn health_check(&self) -> bool {
        let url = self.api_url("/api/v1/ping");
        self.client
            .get(&url)
            .query(&[("password", &self.password)])
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_channel() -> BlueBubblesChannel {
        BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "test-password".into(),
            vec!["+1234567890".into()],
        )
    }

    fn make_open_channel() -> BlueBubblesChannel {
        BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        )
    }

    #[test]
    fn bluebubbles_channel_name() {
        let ch = make_channel();
        assert_eq!(ch.name(), "bluebubbles");
    }

    #[test]
    fn bluebubbles_sender_allowed_exact() {
        let ch = make_channel();
        assert!(ch.is_sender_allowed("+1234567890"));
        assert!(!ch.is_sender_allowed("+9876543210"));
    }

    #[test]
    fn bluebubbles_sender_allowed_wildcard() {
        let ch = make_open_channel();
        assert!(ch.is_sender_allowed("+1234567890"));
        assert!(ch.is_sender_allowed("user@example.com"));
    }

    #[test]
    fn bluebubbles_sender_allowed_empty_list_allows_all() {
        // Empty allowlist = no restriction (matches OpenClaw behaviour)
        let ch = BlueBubblesChannel::new("http://localhost:1234".into(), "pw".into(), vec![]);
        assert!(ch.is_sender_allowed("+1234567890"));
        assert!(ch.is_sender_allowed("anyone@example.com"));
    }

    #[test]
    fn bluebubbles_server_url_trailing_slash_trimmed() {
        let ch =
            BlueBubblesChannel::new("http://localhost:1234/".into(), "pw".into(), vec!["*".into()]);
        assert_eq!(
            ch.api_url("/api/v1/server/info"),
            "http://localhost:1234/api/v1/server/info"
        );
    }

    #[test]
    fn bluebubbles_normalize_handle_strips_service_prefix() {
        assert_eq!(
            BlueBubblesChannel::normalize_handle("iMessage:+1234567890"),
            "+1234567890"
        );
        assert_eq!(
            BlueBubblesChannel::normalize_handle("sms:+1234567890"),
            "+1234567890"
        );
        assert_eq!(
            BlueBubblesChannel::normalize_handle("auto:+1234567890"),
            "+1234567890"
        );
    }

    #[test]
    fn bluebubbles_normalize_handle_email_lowercased() {
        assert_eq!(
            BlueBubblesChannel::normalize_handle("User@Example.COM"),
            "user@example.com"
        );
    }

    #[test]
    fn bluebubbles_parse_valid_dm_message() {
        let ch = make_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/abc123",
                "text": "Hello ZeroClaw!",
                "isFromMe": false,
                "dateCreated": 1708987654321_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "p:0/abc123");
        assert_eq!(msgs[0].sender, "+1234567890");
        assert_eq!(msgs[0].content, "Hello ZeroClaw!");
        assert_eq!(msgs[0].reply_target, "iMessage;-;+1234567890");
        assert_eq!(msgs[0].channel, "bluebubbles");
        assert_eq!(msgs[0].timestamp, 1708987654); // ms → s
    }

    #[test]
    fn bluebubbles_parse_group_chat_message() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/def456",
                "text": "Group message",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1111111111" },
                "chats": [{ "guid": "iMessage;+;group-abc", "style": 43 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "+1111111111");
        assert_eq!(msgs[0].reply_target, "iMessage;+;group-abc");
    }

    #[test]
    fn bluebubbles_parse_skip_is_from_me() {
        let ch = make_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/sent",
                "text": "My own message",
                "isFromMe": true,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "fromMe messages must not be processed");
        // Verify it was cached
        let cache = ch.from_me_cache.lock();
        assert!(
            cache.contains_key("p:0/sent"),
            "fromMe message should be in reply cache"
        );
    }

    #[test]
    fn bluebubbles_parse_skip_non_message_event() {
        let ch = make_channel();
        let payload = serde_json::json!({
            "type": "updated-message",
            "data": { "guid": "p:0/abc", "isFromMe": false }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "Non new-message events should be skipped");
    }

    #[test]
    fn bluebubbles_parse_skip_unauthorized_sender() {
        let ch = make_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/spam",
                "text": "Spam",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+9999999999" },
                "chats": [{ "guid": "iMessage;-;+9999999999", "style": 45 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "Unauthorized senders should be filtered");
    }

    #[test]
    fn bluebubbles_parse_skip_empty_text_no_attachments() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/empty",
                "text": "",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "Empty text with no attachments should be skipped");
    }

    #[test]
    fn bluebubbles_parse_image_attachment() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/img",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": [{
                    "guid": "att-guid",
                    "transferName": "photo.jpg",
                    "mimeType": "image/jpeg",
                    "totalBytes": 102400
                }]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "<media:image> (1 image)");
    }

    #[test]
    fn bluebubbles_parse_non_image_attachment() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/doc",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": [{
                    "guid": "att-guid",
                    "transferName": "contract.pdf",
                    "mimeType": "application/pdf",
                    "totalBytes": 204800
                }]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "<media:attachment> (1 file)");
    }

    #[test]
    fn bluebubbles_parse_text_with_attachment() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/mixed",
                "text": "See attached",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "attachments": [{
                    "guid": "att-guid",
                    "transferName": "doc.pdf",
                    "mimeType": "application/pdf",
                    "totalBytes": 1024
                }]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "See attached\n<media:attachment> (1 file)");
    }

    #[test]
    fn bluebubbles_parse_fallback_reply_target_when_no_chats() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/nochats",
                "text": "Hi",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].reply_target, "+1234567890");
    }

    #[test]
    fn bluebubbles_parse_missing_data_field() {
        let ch = make_channel();
        let payload = serde_json::json!({ "type": "new-message" });
        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn bluebubbles_parse_email_handle() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["user@example.com".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/email",
                "text": "Hello via Apple ID",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "user@example.com" },
                "chats": [{ "guid": "iMessage;-;user@example.com", "style": 45 }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "user@example.com");
        assert_eq!(msgs[0].reply_target, "iMessage;-;user@example.com");
    }

    #[test]
    fn bluebubbles_parse_direct_chat_guid_field() {
        // chatGuid at the top-level data field (some BB versions)
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/direct",
                "text": "Hi",
                "isFromMe": false,
                "chatGuid": "iMessage;-;+1111111111",
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1111111111" },
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].reply_target, "iMessage;-;+1111111111");
    }

    #[test]
    fn bluebubbles_parse_timestamp_seconds_not_double_divided() {
        // Timestamp already in seconds (< 1e12) should not be divided again
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/ts",
                "text": "Hi",
                "isFromMe": false,
                "dateCreated": 1708987654_u64, // seconds
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890" }],
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs[0].timestamp, 1708987654);
    }

    #[test]
    fn bluebubbles_parse_video_attachment() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/vid",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890" }],
                "attachments": [{ "mimeType": "video/mp4", "transferName": "clip.mp4" }]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs[0].content, "<media:video> (1 video)");
    }

    #[test]
    fn bluebubbles_parse_multiple_images() {
        let ch = make_open_channel();
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/imgs",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890" }],
                "attachments": [
                    { "mimeType": "image/jpeg", "transferName": "a.jpg" },
                    { "mimeType": "image/png", "transferName": "b.png" }
                ]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs[0].content, "<media:image> (2 images)");
    }
}
