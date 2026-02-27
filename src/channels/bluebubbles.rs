use super::traits::{Channel, ChannelMessage, SendMessage};
use async_trait::async_trait;
use uuid::Uuid;

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
pub struct BlueBubblesChannel {
    server_url: String,
    password: String,
    allowed_senders: Vec<String>,
    client: reqwest::Client,
}

impl BlueBubblesChannel {
    pub fn new(server_url: String, password: String, allowed_senders: Vec<String>) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            password,
            allowed_senders,
            client: reqwest::Client::new(),
        }
    }

    /// Check if a sender address is allowed.
    /// Supports E.164 phone numbers, email addresses, and "*" wildcard.
    fn is_sender_allowed(&self, sender: &str) -> bool {
        self.allowed_senders
            .iter()
            .any(|a| a == "*" || a.eq_ignore_ascii_case(sender))
    }

    /// Build a full API URL for the given endpoint path.
    fn api_url(&self, path: &str) -> String {
        format!("{}{path}", self.server_url)
    }

    /// Extract text content and attachment markers from a BB message payload.
    ///
    /// Returns `None` if there is no usable content (e.g. empty text and no
    /// recognised attachments).
    fn extract_content(data: &serde_json::Value) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();

        // Primary text field
        if let Some(text) = data.get("text").and_then(|t| t.as_str()) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                parts.push(trimmed.to_string());
            }
        }

        // Attachment markers
        if let Some(attachments) = data.get("attachments").and_then(|a| a.as_array()) {
            for att in attachments {
                let filename = att
                    .get("transferName")
                    .or_else(|| att.get("originalFilename"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("attachment");
                let mime = att
                    .get("mimeType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if mime.starts_with("image/") {
                    parts.push(format!("[IMAGE:{filename}]"));
                } else if !mime.is_empty() {
                    parts.push(format!("[ATTACHMENT:{filename}]"));
                }
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
    ///     "handle": {
    ///       "address": "+1234567890",
    ///       "firstName": null,
    ///       "lastName": null
    ///     },
    ///     "chats": [
    ///       {
    ///         "guid": "iMessage;-;+1234567890",
    ///         "displayName": null,
    ///         "style": 45
    ///       }
    ///     ],
    ///     "hasAttachments": false,
    ///     "attachments": []
    ///   }
    /// }
    /// ```
    ///
    /// `style` values: `45` = DM, `43` = group chat.
    /// `chats[0].guid` is used as `reply_target` so replies are routed to
    /// the correct conversation.
    pub fn parse_webhook_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let mut messages = Vec::new();

        // Only handle new-message events
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

        // Skip messages sent by us
        let is_from_me = data
            .get("isFromMe")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_from_me {
            tracing::debug!("BlueBubbles: skipping isFromMe message");
            return messages;
        }

        // Extract sender address from handle
        let Some(sender) = data
            .get("handle")
            .and_then(|h| h.get("address"))
            .and_then(|a| a.as_str())
            .map(str::trim)
            .filter(|a| !a.is_empty())
        else {
            tracing::debug!("BlueBubbles: skipping message with no handle address");
            return messages;
        };

        // Check allowlist
        if !self.is_sender_allowed(sender) {
            tracing::warn!(
                "BlueBubbles: ignoring message from unauthorized sender: {sender}. \
                Add to channels.bluebubbles.allowed_senders in config.toml, \
                or use \"*\" to allow all senders."
            );
            return messages;
        }

        // Use chats[0].guid as reply_target — ensures replies go to the right
        // conversation (especially important for group chats).
        // Falls back to the sender address if no chat guid is available.
        let reply_target = data
            .get("chats")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|chat| chat.get("guid"))
            .and_then(|g| g.as_str())
            .filter(|g| !g.is_empty())
            .unwrap_or(sender)
            .to_string();

        // Extract content (text + attachment markers)
        let Some(content) = Self::extract_content(data) else {
            tracing::debug!("BlueBubbles: skipping empty message from {sender}");
            return messages;
        };

        // Timestamp: BB sends epoch milliseconds in dateCreated
        let timestamp = data
            .get("dateCreated")
            .and_then(|t| t.as_u64())
            .map(|ms| ms / 1000) // convert ms → seconds
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

        messages.push(ChannelMessage {
            id: Uuid::new_v4().to_string(),
            sender: sender.to_string(),
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
    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        let url = self.api_url("/api/v1/message/text");

        let body = serde_json::json!({
            "chatGuid": message.recipient,
            "message": message.content,
            "method": "apple-script"
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.password)
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
        // Keep alive until the runtime shuts this task down
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    /// Verify the BlueBubbles server is reachable.
    async fn health_check(&self) -> bool {
        let url = self.api_url("/api/v1/server/info");
        self.client
            .get(&url)
            .bearer_auth(&self.password)
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
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        assert!(ch.is_sender_allowed("+1234567890"));
        assert!(ch.is_sender_allowed("user@example.com"));
    }

    #[test]
    fn bluebubbles_sender_allowed_empty_list() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec![],
        );
        assert!(!ch.is_sender_allowed("+1234567890"));
    }

    #[test]
    fn bluebubbles_server_url_trailing_slash_trimmed() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234/".into(),
            "pw".into(),
            vec![],
        );
        assert_eq!(ch.api_url("/api/v1/server/info"), "http://localhost:1234/api/v1/server/info");
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
                "hasAttachments": false,
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "+1234567890");
        assert_eq!(msgs[0].content, "Hello ZeroClaw!");
        assert_eq!(msgs[0].reply_target, "iMessage;-;+1234567890");
        assert_eq!(msgs[0].channel, "bluebubbles");
        assert_eq!(msgs[0].timestamp, 1708987654); // ms → s
    }

    #[test]
    fn bluebubbles_parse_group_chat_message() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/def456",
                "text": "Group message",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1111111111" },
                "chats": [{ "guid": "iMessage;+;group-abc", "style": 43 }],
                "hasAttachments": false,
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
                "hasAttachments": false,
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "isFromMe messages should be skipped");
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
                "hasAttachments": false,
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "Unauthorized senders should be filtered");
    }

    #[test]
    fn bluebubbles_parse_skip_empty_text_no_attachments() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/empty",
                "text": "",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "hasAttachments": false,
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty(), "Empty text with no attachments should be skipped");
    }

    #[test]
    fn bluebubbles_parse_image_attachment() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/img",
                "text": null,
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "hasAttachments": true,
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
        assert_eq!(msgs[0].content, "[IMAGE:photo.jpg]");
    }

    #[test]
    fn bluebubbles_parse_non_image_attachment() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/doc",
                "text": null,
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "hasAttachments": true,
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
        assert_eq!(msgs[0].content, "[ATTACHMENT:contract.pdf]");
    }

    #[test]
    fn bluebubbles_parse_text_with_attachment() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/mixed",
                "text": "See attached",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [{ "guid": "iMessage;-;+1234567890", "style": 45 }],
                "hasAttachments": true,
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
        assert_eq!(msgs[0].content, "See attached\n[ATTACHMENT:doc.pdf]");
    }

    #[test]
    fn bluebubbles_parse_fallback_reply_target_when_no_chats() {
        let ch = BlueBubblesChannel::new(
            "http://localhost:1234".into(),
            "pw".into(),
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "p:0/nochats",
                "text": "Hi",
                "isFromMe": false,
                "dateCreated": 1708987654000_u64,
                "handle": { "address": "+1234567890" },
                "chats": [],
                "hasAttachments": false,
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
                "hasAttachments": false,
                "attachments": []
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "user@example.com");
        assert_eq!(msgs[0].reply_target, "iMessage;-;user@example.com");
    }
}
