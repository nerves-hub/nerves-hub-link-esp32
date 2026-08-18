//! Phoenix Channels v2 wire format.
//!
//! NervesHub's device socket negotiates its serializer from the `vsn` query
//! parameter: `2.0.0` selects JSON, `3.0.0` selects msgpack. We ask for JSON,
//! which puts `Phoenix.Socket.V2.JSONSerializer` on the other end — a five
//! element array rather than an object:
//!
//! ```text
//! [join_ref, ref, topic, event, payload]
//! ```
//!
//! `join_ref` and `ref` are nullable, which is why both are `Option<String>`
//! rather than being skipped: the array is positional, so a missing element
//! shifts everything after it.
//!
//! # Topic
//!
//! The device joins **`"device"`**, not `"device:<id>"`. NervesHub wraps the
//! standard serializer in `NervesHubWeb.Channels.DeviceJSONSerializer`, which
//! rewrites `device` to `device:<device_id>` on the way in and back again on
//! the way out. A device does not know its NervesHub device id, so sending the
//! qualified topic is wrong — it would be rewritten to `device:<device_id>:...`
//! and fail to route.

use serde_json::Value;

/// The topic a device joins. See the module docs — this is deliberately
/// unqualified.
pub const DEVICE_TOPIC: &str = "device";

/// Phoenix's own topic, used for heartbeats.
pub const CONTROL_TOPIC: &str = "phoenix";

/// Selects `DeviceJSONSerializer` on the server.
pub const SERIALIZER_VSN: &str = "2.0.0";

/// The device API version reported on join. NervesHub gates features on this —
/// archives require `>= 2.0.0`, for example.
pub const DEVICE_API_VERSION: &str = "2.2.0";

pub mod event {
    pub const JOIN: &str = "phx_join";
    pub const REPLY: &str = "phx_reply";
    pub const CLOSE: &str = "phx_close";
    pub const ERROR: &str = "phx_error";
    pub const HEARTBEAT: &str = "heartbeat";

    /// Server -> device: an update is available.
    pub const UPDATE: &str = "update";

    /// Device -> server: download/apply progress. The tool-neutral name; the
    /// server also accepts `fwup_progress`, which is what Nerves devices send.
    pub const UPDATE_PROGRESS: &str = "update_progress";

    /// Device -> server: the running firmware has proven itself. On ESP-IDF
    /// this pairs with `esp_ota_mark_app_valid_cancel_rollback`.
    pub const FIRMWARE_VALIDATED: &str = "firmware_validated";

    /// Device -> server: a general status change (`failed`, `ignored`, ...).
    pub const STATUS_UPDATE: &str = "status_update";

    /// Device -> server: about to reboot.
    pub const REBOOTING: &str = "rebooting";
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub join_ref: Option<String>,
    pub reference: Option<String>,
    pub topic: String,
    pub event: String,
    pub payload: Value,
}

impl Message {
    pub fn new(topic: &str, event: &str, payload: Value) -> Self {
        Self {
            join_ref: None,
            reference: None,
            topic: topic.to_string(),
            event: event.to_string(),
            payload,
        }
    }

    pub fn with_refs(mut self, join_ref: Option<String>, reference: Option<String>) -> Self {
        self.join_ref = join_ref;
        self.reference = reference;
        self
    }

    pub fn encode(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&(
            &self.join_ref,
            &self.reference,
            &self.topic,
            &self.event,
            &self.payload,
        ))
    }

    pub fn decode(raw: &str) -> Result<Self, serde_json::Error> {
        let (join_ref, reference, topic, event, payload): (
            Option<String>,
            Option<String>,
            String,
            String,
            Value,
        ) = serde_json::from_str(raw)?;

        Ok(Self {
            join_ref,
            reference,
            topic,
            event,
            payload,
        })
    }

    /// `true` if this is a successful `phx_reply` to `reference`.
    pub fn is_ok_reply_to(&self, reference: &str) -> bool {
        self.event == event::REPLY
            && self.reference.as_deref() == Some(reference)
            && self.payload.get("status").and_then(Value::as_str) == Some("ok")
    }

    /// The `response` body of a `phx_reply`, if there is one.
    pub fn reply_response(&self) -> Option<&Value> {
        self.payload.get("response")
    }
}

/// Monotonic message references.
///
/// Phoenix correlates a reply to a request by `ref`, and a channel's lifetime
/// by the `join_ref` fixed at join time — so these must not restart while a
/// connection is open.
#[derive(Debug, Default)]
pub struct RefGenerator {
    next: u64,
}

impl RefGenerator {
    pub fn next_ref(&mut self) -> String {
        self.next = self.next.wrapping_add(1);
        self.next.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encodes_as_a_five_element_array() {
        let msg = Message::new(DEVICE_TOPIC, event::JOIN, json!({"a": 1}))
            .with_refs(Some("1".into()), Some("1".into()));

        assert_eq!(
            msg.encode().unwrap(),
            r#"["1","1","device","phx_join",{"a":1}]"#
        );
    }

    #[test]
    fn encodes_null_refs_as_positional_nulls() {
        // A heartbeat carries no join_ref. The nulls must be present or every
        // later element shifts one position left.
        let msg = Message::new(CONTROL_TOPIC, event::HEARTBEAT, json!({}))
            .with_refs(None, Some("7".into()));

        assert_eq!(
            msg.encode().unwrap(),
            r#"[null,"7","phoenix","heartbeat",{}]"#
        );
    }

    #[test]
    fn round_trips() {
        let msg = Message::new(DEVICE_TOPIC, event::UPDATE_PROGRESS, json!({"value": 42}))
            .with_refs(Some("1".into()), Some("9".into()));

        assert_eq!(Message::decode(&msg.encode().unwrap()).unwrap(), msg);
    }

    #[test]
    fn decodes_a_server_reply() {
        let raw = r#"["1","1","device","phx_reply",{"status":"ok","response":{}}]"#;
        let msg = Message::decode(raw).unwrap();

        assert_eq!(msg.event, event::REPLY);
        assert!(msg.is_ok_reply_to("1"));
        assert!(!msg.is_ok_reply_to("2"));
    }

    #[test]
    fn decodes_an_update_push() {
        // Pushes from the server carry no ref.
        let raw = r#"[null,null,"device","update",{"update_available":true}]"#;
        let msg = Message::decode(raw).unwrap();

        assert_eq!(msg.event, event::UPDATE);
        assert_eq!(msg.reference, None);
        assert_eq!(msg.payload["update_available"], json!(true));
    }

    #[test]
    fn error_replies_are_not_ok() {
        let raw =
            r#"["1","1","device","phx_reply",{"status":"error","response":{"reason":"nope"}}]"#;
        assert!(!Message::decode(raw).unwrap().is_ok_reply_to("1"));
    }

    #[test]
    fn refs_are_monotonic() {
        let mut refs = RefGenerator::default();
        assert_eq!(refs.next_ref(), "1");
        assert_eq!(refs.next_ref(), "2");
    }
}
