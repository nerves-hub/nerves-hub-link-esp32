//! Phoenix Channels v2 wire format.
//!
//! NervesHub's device socket negotiates its serializer from the `vsn` query
//! parameter: `2.0.0` selects JSON, `3.0.0` selects msgpack (see
//! [`Serializer`]). Either way a message is a five element array rather than
//! an object:
//!
//! ```text
//! [join_ref, ref, topic, event, payload]
//! ```
//!
//! `join_ref` and `ref` are nullable, which is why both are `Option<String>`
//! rather than being skipped: the array is positional, so a missing element
//! shifts everything after it.
//!
//! JSON travels in text frames and msgpack in binary ones, in both directions;
//! NervesHub's msgpack serializer refuses a text frame outright.
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

/// The terminal topic, joined separately and only when asked for.
///
/// Unqualified like `device`, and rewritten server-side the same way.
pub const CONSOLE_TOPIC: &str = "console";

/// Sent on joining `console`. NervesHub records it against the session and
/// hands it to whoever attaches.
pub const CONSOLE_VERSION: &str = "1.0.0";

/// Phoenix's own topic, used for heartbeats.
pub const CONTROL_TOPIC: &str = "phoenix";

/// Selects `DeviceJSONSerializer` on the server.
pub const SERIALIZER_VSN: &str = "2.0.0";

/// Selects `DeviceMsgPackSerializer` on the server.
pub const MSGPACK_SERIALIZER_VSN: &str = "3.0.0";

/// How messages are written on the socket.
///
/// msgpack is smaller -- no quotes, colons or commas, one-byte headers for
/// short strings and small numbers -- which matters on a link billed by the
/// byte, and NervesHub has had it since July 2026. JSON is the default
/// because every NervesHub has it, and because a frame you can read in a
/// packet capture is worth something on a bench.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Serializer {
    #[default]
    Json,
    MsgPack,
}

impl Serializer {
    /// The `vsn` the socket URL asks for.
    pub fn vsn(self) -> &'static str {
        match self {
            Serializer::Json => SERIALIZER_VSN,
            Serializer::MsgPack => MSGPACK_SERIALIZER_VSN,
        }
    }
}

/// One websocket message: text for JSON, binary for msgpack.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}

impl Frame {
    pub fn len(&self) -> usize {
        match self {
            Frame::Text(text) => text.len(),
            Frame::Binary(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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

    /// Server -> device: restart now. Sent when an operator presses Reboot.
    pub const REBOOT: &str = "reboot";

    /// Server -> device: make yourself known. Sent when an operator presses
    /// Identify, so that someone standing in front of a shelf of identical
    /// boxes can tell which one they are looking at.
    pub const IDENTIFY: &str = "identify";

    /// Server -> device: join the extensions channel, and which versions of
    /// each extension the platform has. Sent once the device is joined, to a
    /// device declaring API 2.2.0 or later; NervesHub before 2.x named no
    /// versions.
    pub const EXTENSIONS_GET: &str = "extensions:get";

    /// Device -> server: console output.
    pub const UP: &str = "up";

    /// Server -> device: console input, a keystroke or a whole line.
    pub const DOWN: &str = "dn";

    /// Server -> device: start the console session over. On Nerves this
    /// restarts IEx; here there is only a part-typed line to discard.
    pub const RESTART: &str = "restart";

    /// Server -> device: a file, in three parts. Declined -- see `console`.
    pub const FILE_DATA_START: &str = "file-data/start";
    pub const FILE_DATA: &str = "file-data";
    pub const FILE_DATA_STOP: &str = "file-data/stop";

    // There is no `reconnect` constant, and that is not an omission.
    // NervesHub's third device command is served by closing the socket rather
    // than by sending anything: the platform broadcasts to the socket's own
    // `device_socket:<id>` topic and Phoenix drops the connection. The device
    // finds out the same way it finds out about a flaky access point, and
    // reconnects through the usual backoff -- so supporting it means having a
    // reconnect loop that works, which the network already required.
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

    /// This message as `serializer` writes it.
    pub fn encode_as(&self, serializer: Serializer) -> Result<Frame, crate::error::Error> {
        Ok(match serializer {
            Serializer::Json => Frame::Text(self.encode()?),
            Serializer::MsgPack => Frame::Binary(self.encode_msgpack()?),
        })
    }

    /// Read a frame, by what kind it is: text is JSON, binary is msgpack.
    pub fn decode_frame(frame: &Frame) -> Result<Self, crate::error::Error> {
        Ok(match frame {
            Frame::Text(text) => Self::decode(text)?,
            Frame::Binary(bytes) => Self::decode_msgpack(bytes)?,
        })
    }

    pub fn encode_msgpack(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        // A tuple, so an array; and `Value` maps as msgpack maps. (`to_vec`
        // would write a Rust struct as an array of its fields, which is why
        // nothing here is one.)
        rmp_serde::to_vec(&(
            &self.join_ref,
            &self.reference,
            &self.topic,
            &self.event,
            &self.payload,
        ))
    }

    /// The refs are read leniently. NervesHub sends back the strings the
    /// device sent, but msgpack lets another server send integers, and a ref
    /// is only ever compared as text.
    pub fn decode_msgpack(raw: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        let (join_ref, reference, topic, event, payload): (Value, Value, String, String, Value) =
            rmp_serde::from_slice(raw)?;

        Ok(Self {
            join_ref: reference_text(join_ref),
            reference: reference_text(reference),
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

fn reference_text(reference: Value) -> Option<String> {
    match reference {
        Value::Null => None,
        Value::String(text) => Some(text),
        other => Some(other.to_string()),
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

    // What Msgpax writes for `[nil, nil, "device", "update", %{...}]`, the
    // shape NervesHub's msgpack serializer pushes.
    #[test]
    fn decodes_a_msgpack_push_from_the_server() {
        let raw = rmp_serde::to_vec(&(
            None::<String>,
            None::<String>,
            "device",
            "update",
            json!({"update_available": true}),
        ))
        .unwrap();

        let msg = Message::decode_frame(&Frame::Binary(raw)).unwrap();

        assert_eq!(msg.event, event::UPDATE);
        assert_eq!(msg.reference, None);
        assert_eq!(msg.payload["update_available"], json!(true));
    }

    #[test]
    fn msgpack_round_trips() {
        let msg = Message::new(DEVICE_TOPIC, event::UPDATE_PROGRESS, json!({"value": 42, "f": 1.5}))
            .with_refs(Some("1".into()), Some("9".into()));

        let Frame::Binary(bytes) = msg.encode_as(Serializer::MsgPack).unwrap() else {
            panic!("msgpack is binary")
        };
        assert_eq!(Message::decode_msgpack(&bytes).unwrap(), msg);
    }

    #[test]
    fn integer_refs_read_as_text() {
        let raw = rmp_serde::to_vec(&(1u8, 2u8, "device", "phx_reply", json!({"status": "ok"})))
            .unwrap();

        let msg = Message::decode_msgpack(&raw).unwrap();

        assert!(msg.is_ok_reply_to("2"));
        assert_eq!(msg.join_ref.as_deref(), Some("1"));
    }

    // The payload is a map whatever its keys, never an array of values: the
    // server reads it by name.
    #[test]
    fn a_msgpack_payload_is_a_map() {
        let bytes = Message::new(DEVICE_TOPIC, event::JOIN, json!({"a": 1}))
            .encode_msgpack()
            .unwrap();

        // fixarray of 5, nil, nil, "device", "phx_join", then fixmap of 1.
        assert_eq!(bytes[0], 0x95);
        assert_eq!(bytes[bytes.len() - 4], 0x81);
    }

    #[test]
    fn json_is_text_and_msgpack_is_binary() {
        let msg = Message::new(CONTROL_TOPIC, event::HEARTBEAT, json!({}));

        assert!(matches!(msg.encode_as(Serializer::Json).unwrap(), Frame::Text(_)));
        assert!(matches!(msg.encode_as(Serializer::MsgPack).unwrap(), Frame::Binary(_)));
    }

    #[test]
    fn refs_are_monotonic() {
        let mut refs = RefGenerator::default();
        assert_eq!(refs.next_ref(), "1");
        assert_eq!(refs.next_ref(), "2");
    }
}
