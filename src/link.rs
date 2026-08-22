//! The channel state machine.
//!
//! Kept separate from the websocket so the whole join/update conversation can
//! be driven against a fake transport in tests — the parts most likely to be
//! wrong are the frames, not the socket.

use serde_json::{json, Value};

use crate::config::Config;
use crate::error::Error;
use crate::extensions::{Extensions, LogLine, Outgoing, EXTENSIONS_TOPIC};
use crate::message::{event, Message, RefGenerator, CONTROL_TOPIC, DEVICE_TOPIC};
use crate::metadata::FirmwareMetadata;
use crate::update::{Stage, UpdateDecision, UpdatePayload};

/// A bidirectional frame channel. Implemented over `esp_websocket_client` on
/// device, and over a queue in tests.
pub trait Transport {
    fn send(&mut self, frame: &str) -> Result<(), Error>;
    /// `None` means nothing arrived before the timeout.
    fn recv(&mut self) -> Result<Option<String>, Error>;
}

/// What the application must decide.
pub trait UpdateHandler {
    /// Whether to apply an available update. Defaults to applying.
    fn update_available(&mut self, _update: &UpdatePayload) -> UpdateDecision {
        UpdateDecision::Apply
    }

    fn progress(&mut self, _stage: Stage, _percent: u8) {}
}

/// An `UpdateHandler` that always applies.
pub struct AlwaysApply;
impl UpdateHandler for AlwaysApply {}

/// Something the run loop must act on outside the channel conversation.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// The platform asked for a reading only the application can produce.
    /// The caller answers with [`Link::send_extension`].
    Extension(Vec<Outgoing>),
    None,
    /// Download and apply this image, then reboot.
    ApplyUpdate(Box<UpdatePayload>),
    /// An operator pressed Reboot. Say so, then restart.
    Reboot,
    /// An operator pressed Identify. Blink something.
    Identify,
    /// The server closed or errored the channel; reconnect.
    Reconnect,
}

pub struct Link {
    config: Config,
    metadata: FirmwareMetadata,
    refs: RefGenerator,
    join_ref: Option<String>,
    extensions: Extensions,
    extensions_join_ref: Option<String>,
    joined: bool,
    downloading: Option<String>,
}

impl Link {
    pub fn new(config: Config, metadata: FirmwareMetadata) -> Self {
        let enabled = config.extensions;

        Self {
            config,
            metadata,
            refs: RefGenerator::default(),
            join_ref: None,
            extensions: Extensions::new(enabled),
            extensions_join_ref: None,
            joined: false,
            downloading: None,
        }
    }

    /// Record that this device is part-way through downloading `uuid`.
    ///
    /// Reported on the next join. NervesHub treats a device that joins *without*
    /// `currently_downloading_uuid` as idle and clears any inflight update it
    /// has for it — so a device that reconnects mid-download and stays silent
    /// loses the server's record of the update in progress.
    pub fn set_downloading(&mut self, uuid: Option<String>) {
        self.downloading = uuid;
    }

    pub fn joined(&self) -> bool {
        self.joined
    }

    /// Send `phx_join`. The reply is handled by `handle_frame`.
    pub fn send_join<T: Transport>(&mut self, transport: &mut T) -> Result<(), Error> {
        let reference = self.refs.next_ref();
        self.join_ref = Some(reference.clone());
        self.joined = false;

        let params = self
            .metadata
            .join_params(&self.config.device_api_version, self.downloading.as_deref());

        self.send(
            transport,
            Message::new(DEVICE_TOPIC, event::JOIN, params),
            Some(reference),
        )
    }

    pub fn send_heartbeat<T: Transport>(&mut self, transport: &mut T) -> Result<(), Error> {
        let reference = self.refs.next_ref();

        // Heartbeats go to the "phoenix" topic and carry no join_ref.
        let message = Message::new(CONTROL_TOPIC, event::HEARTBEAT, json!({}));
        let frame = message.with_refs(None, Some(reference)).encode()?;

        transport.send(&frame)
    }

    pub fn send_progress<T: Transport>(
        &mut self,
        transport: &mut T,
        stage: Stage,
        percent: u8,
    ) -> Result<(), Error> {
        let payload = json!({"value": percent, "stage": stage.as_str()});
        let reference = self.refs.next_ref();

        self.send(
            transport,
            Message::new(DEVICE_TOPIC, event::UPDATE_PROGRESS, payload),
            Some(reference),
        )
    }

    pub fn send_firmware_validated<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), Error> {
        let reference = self.refs.next_ref();

        self.send(
            transport,
            Message::new(DEVICE_TOPIC, event::FIRMWARE_VALIDATED, json!({})),
            Some(reference),
        )
    }

    pub fn send_status<T: Transport>(
        &mut self,
        transport: &mut T,
        status: &str,
        extra: Value,
    ) -> Result<(), Error> {
        let mut payload = json!({"status": status});

        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                payload[key] = value.clone();
            }
        }

        let reference = self.refs.next_ref();

        self.send(
            transport,
            Message::new(DEVICE_TOPIC, event::STATUS_UPDATE, payload),
            Some(reference),
        )
    }

    pub fn send_rebooting<T: Transport>(&mut self, transport: &mut T) -> Result<(), Error> {
        let reference = self.refs.next_ref();

        self.send(
            transport,
            Message::new(DEVICE_TOPIC, event::REBOOTING, json!({})),
            Some(reference),
        )
    }

    /// Feed one received frame in; get back what the caller must do.
    pub fn handle_frame<T: Transport, H: UpdateHandler>(
        &mut self,
        transport: &mut T,
        handler: &mut H,
        frame: &str,
    ) -> Result<Action, Error> {
        let message = Message::decode(frame)?;

        if message.topic == EXTENSIONS_TOPIC {
            return self.handle_extension_frame(transport, &message);
        }

        match message.event.as_str() {
            event::REPLY => self.handle_reply(transport, handler, &message),
            event::UPDATE => {
                let payload = UpdatePayload::parse(&message.payload)?;
                self.decide(transport, handler, payload)
            }
            event::REBOOT => Ok(Action::Reboot),
            event::IDENTIFY => Ok(Action::Identify),
            event::CLOSE | event::ERROR => {
                self.joined = false;
                self.extensions.disconnected();
                Ok(Action::Reconnect)
            }
            _ => Ok(Action::None),
        }
    }

    /// Whether the application asked for any extension.
    pub fn extensions_wanted(&self) -> bool {
        self.extensions.wanted()
    }

    pub fn extensions_joined(&self) -> bool {
        self.extensions.joined()
    }

    /// Join the extensions channel. Only after the device channel is joined —
    /// the platform decides what to attach from the device's product, which it
    /// knows once the device has identified itself.
    pub fn send_extensions_join<T: Transport>(&mut self, transport: &mut T) -> Result<(), Error> {
        let (reference, message) = self.extensions.join_message(&mut self.refs);
        self.extensions_join_ref = Some(reference.clone());

        let frame = message.with_refs(Some(reference.clone()), Some(reference)).encode()?;
        transport.send(&frame)
    }

    /// Perform frames produced by the extensions state machine.
    pub fn send_extension<T: Transport>(
        &mut self,
        transport: &mut T,
        outgoing: Vec<Outgoing>,
    ) -> Result<(), Error> {
        for out in outgoing {
            if let Outgoing::Send { event, payload } = out {
                let reference = self.refs.next_ref();
                let frame = Message::new(EXTENSIONS_TOPIC, &event, payload)
                    .with_refs(self.extensions_join_ref.clone(), Some(reference))
                    .encode()?;
                transport.send(&frame)?;
            }
        }

        Ok(())
    }

    /// The frames answering a location request.
    pub fn location_answer(&self, location: Option<crate::extensions::Location>) -> Vec<Outgoing> {
        self.extensions.location(location)
    }

    /// The frames answering a health check.
    pub fn health_answer(&self, report: &crate::extensions::HealthReport) -> Vec<Outgoing> {
        self.extensions.health(report)
    }

    /// Send a log line, if the logging extension is attached.
    pub fn send_log<T: Transport>(
        &mut self,
        transport: &mut T,
        line: &LogLine,
    ) -> Result<(), Error> {
        let outgoing = self.extensions.log(line);
        self.send_extension(transport, outgoing)
    }

    fn handle_extension_frame<T: Transport>(
        &mut self,
        transport: &mut T,
        message: &Message,
    ) -> Result<Action, Error> {
        if message.event == event::REPLY {
            let is_join_reply =
                self.extensions_join_ref.as_deref() == message.reference.as_deref();

            if is_join_reply {
                let response = message.reply_response().cloned().unwrap_or(Value::Array(vec![]));
                let confirmations = self.extensions.on_join_reply(&response);
                self.send_extension(transport, confirmations)?;
            }

            return Ok(Action::None);
        }

        let outgoing = self.extensions.on_event(&message.event, &message.payload);

        if outgoing.is_empty() {
            Ok(Action::None)
        } else {
            Ok(Action::Extension(outgoing))
        }
    }

    fn handle_reply<T: Transport, H: UpdateHandler>(
        &mut self,
        transport: &mut T,
        handler: &mut H,
        message: &Message,
    ) -> Result<Action, Error> {
        let is_join_reply = self.join_ref.as_deref() == message.reference.as_deref();

        if !is_join_reply {
            return Ok(Action::None);
        }

        if !message.is_ok_reply_to(self.join_ref.as_deref().unwrap_or_default()) {
            let reason = message
                .reply_response()
                .and_then(|r| r.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();

            return Err(Error::JoinRefused(reason));
        }

        self.joined = true;

        // NervesHub answers the join with the update payload, so a device that
        // rebooted mid-update picks it straight back up without waiting to be
        // told again.
        match message.reply_response() {
            Some(response) => {
                let payload = UpdatePayload::parse(response)?;
                self.decide(transport, handler, payload)
            }
            None => Ok(Action::None),
        }
    }

    fn decide<T: Transport, H: UpdateHandler>(
        &mut self,
        transport: &mut T,
        handler: &mut H,
        payload: UpdatePayload,
    ) -> Result<Action, Error> {
        if payload.actionable().is_none() {
            return Ok(Action::None);
        }

        match handler.update_available(&payload) {
            UpdateDecision::Apply => Ok(Action::ApplyUpdate(Box::new(payload))),

            UpdateDecision::Ignore { reason } => {
                self.send_status(transport, "ignored", json!({"reason": reason}))?;
                Ok(Action::None)
            }

            UpdateDecision::Reschedule { delay_ms, reason } => {
                self.send_status(
                    transport,
                    "rescheduled",
                    json!({"delay_for": delay_ms, "reason": reason}),
                )?;
                Ok(Action::None)
            }
        }
    }

    fn send<T: Transport>(
        &self,
        transport: &mut T,
        message: Message,
        reference: Option<String>,
    ) -> Result<(), Error> {
        let frame = message
            .with_refs(self.join_ref.clone(), reference)
            .encode()?;

        transport.send(&frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Credentials};

    #[derive(Default)]
    struct FakeTransport {
        sent: Vec<String>,
    }

    impl Transport for FakeTransport {
        fn send(&mut self, frame: &str) -> Result<(), Error> {
            self.sent.push(frame.to_string());
            Ok(())
        }

        fn recv(&mut self) -> Result<Option<String>, Error> {
            Ok(None)
        }
    }

    impl FakeTransport {
        fn last(&self) -> Message {
            Message::decode(self.sent.last().expect("nothing sent")).unwrap()
        }
    }

    struct Decider(UpdateDecision);

    impl UpdateHandler for Decider {
        fn update_available(&mut self, _update: &UpdatePayload) -> UpdateDecision {
            self.0.clone()
        }
    }

    fn link() -> Link {
        let config = Config::new(
            "devices.test",
            Credentials::client_certificate(b"cert-pem".to_vec(), b"key-pem".to_vec()).unwrap(),
        );

        let metadata = FirmwareMetadata {
            project_name: "my_app".into(),
            version: "1.0.0".into(),
            app_elf_sha256: "ab".repeat(32),
            idf_ver: "v5.2.1".into(),
            chip_id: 9,
        };

        Link::new(config, metadata)
    }

    fn update_response() -> Value {
        json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": 1024,
            "checksum": "DEADBEEF"
        })
    }

    #[test]
    fn join_targets_the_unqualified_device_topic() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let sent = transport.last();
        assert_eq!(sent.topic, "device");
        assert_eq!(sent.event, "phx_join");
        assert_eq!(sent.payload["update_tool"], "esp-idf");
        // join_ref and ref are the same on the join frame.
        assert_eq!(sent.join_ref, sent.reference);
    }

    // Without this, NervesHub clears the inflight update on reconnect because
    // it takes a silent device to be idle.
    #[test]
    fn a_download_in_progress_is_reported_on_join() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.set_downloading(Some("uuid-in-flight".into()));
        link.send_join(&mut transport).unwrap();

        assert_eq!(
            transport.last().payload["currently_downloading_uuid"],
            "uuid-in-flight"
        );
    }

    #[test]
    fn an_idle_device_sends_no_currently_downloading_uuid() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        assert!(transport
            .last()
            .payload
            .get("currently_downloading_uuid")
            .is_none());
    }

    #[test]
    fn heartbeats_go_to_the_phoenix_topic_without_a_join_ref() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();
        link.send_heartbeat(&mut transport).unwrap();

        let sent = transport.last();
        assert_eq!(sent.topic, "phoenix");
        assert_eq!(sent.event, "heartbeat");
        assert_eq!(sent.join_ref, None);
    }

    #[test]
    fn a_successful_join_reply_marks_the_link_joined() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = r#"["1","1","device","phx_reply",{"status":"ok","response":{"update_available":false}}]"#;

        let action = link
            .handle_frame(&mut transport, &mut AlwaysApply, frame)
            .unwrap();

        assert!(link.joined());
        assert_eq!(action, Action::None);
    }

    #[test]
    fn a_refused_join_is_an_error() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = r#"["1","1","device","phx_reply",{"status":"error","response":{"reason":"could not connect"}}]"#;

        let err = link
            .handle_frame(&mut transport, &mut AlwaysApply, frame)
            .unwrap_err();

        assert!(matches!(err, Error::JoinRefused(reason) if reason == "could not connect"));
        assert!(!link.joined());
    }

    // NervesHub answers phx_join with the update payload, so an update
    // interrupted by a reboot resumes on reconnect without a second push.
    #[test]
    fn an_update_in_the_join_reply_is_acted_on() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = format!(
            r#"["1","1","device","phx_reply",{{"status":"ok","response":{}}}]"#,
            update_response()
        );

        let action = link
            .handle_frame(&mut transport, &mut AlwaysApply, &frame)
            .unwrap();

        match action {
            Action::ApplyUpdate(payload) => {
                assert_eq!(
                    payload.firmware_url.as_deref(),
                    Some("https://example.test/fw.bin")
                )
            }
            other => panic!("expected an update, got {other:?}"),
        }
    }

    // The two commands NervesHub pushes at a device. `reconnect` is absent on
    // purpose -- see the note in `message::event`.
    #[test]
    fn a_reboot_request_is_acted_on() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = r#"[null,null,"device","reboot",{}]"#;

        assert_eq!(
            link.handle_frame(&mut transport, &mut AlwaysApply, frame).unwrap(),
            Action::Reboot
        );
    }

    #[test]
    fn an_identify_request_is_acted_on() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = r#"[null,null,"device","identify",{}]"#;

        assert_eq!(
            link.handle_frame(&mut transport, &mut AlwaysApply, frame).unwrap(),
            Action::Identify
        );
    }

    // `completed` says the image is written and the bootloader points at it.
    // The server records it against the inflight update, so the status has to
    // be exactly this string.
    #[test]
    fn a_completed_status_names_the_status_the_server_records() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();
        link.send_status(&mut transport, "completed", json!({})).unwrap();

        let sent = transport.last();
        assert_eq!(sent.topic, "device");
        assert_eq!(sent.event, "status_update");
        assert_eq!(sent.payload["status"], "completed");
    }

    #[test]
    fn a_pushed_update_is_acted_on() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = format!(r#"[null,null,"device","update",{}]"#, update_response());

        assert!(matches!(
            link.handle_frame(&mut transport, &mut AlwaysApply, &frame)
                .unwrap(),
            Action::ApplyUpdate(_)
        ));
    }

    #[test]
    fn ignoring_an_update_reports_it_rather_than_going_quiet() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let mut handler = Decider(UpdateDecision::Ignore {
            reason: "on battery".into(),
        });

        let frame = format!(r#"[null,null,"device","update",{}]"#, update_response());
        let action = link
            .handle_frame(&mut transport, &mut handler, &frame)
            .unwrap();

        assert_eq!(action, Action::None);

        let sent = transport.last();
        assert_eq!(sent.event, "status_update");
        assert_eq!(sent.payload["status"], "ignored");
        assert_eq!(sent.payload["reason"], "on battery");
    }

    #[test]
    fn rescheduling_sends_the_delay_the_server_expects() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let mut handler = Decider(UpdateDecision::Reschedule {
            delay_ms: 60_000,
            reason: "busy".into(),
        });

        let frame = format!(r#"[null,null,"device","update",{}]"#, update_response());
        link.handle_frame(&mut transport, &mut handler, &frame)
            .unwrap();

        let sent = transport.last();
        assert_eq!(sent.payload["status"], "rescheduled");
        // NervesHub reads `delay_for` in milliseconds.
        assert_eq!(sent.payload["delay_for"], 60_000);
    }

    #[test]
    fn an_update_with_nothing_to_download_is_ignored() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();

        let frame = r#"[null,null,"device","update",{"update_available":false}]"#;

        assert_eq!(
            link.handle_frame(&mut transport, &mut AlwaysApply, frame)
                .unwrap(),
            Action::None
        );
    }

    #[test]
    fn a_channel_close_asks_for_a_reconnect() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();
        link.joined = true;

        let frame = r#"[null,null,"device","phx_close",{}]"#;

        assert_eq!(
            link.handle_frame(&mut transport, &mut AlwaysApply, frame)
                .unwrap(),
            Action::Reconnect
        );
        assert!(!link.joined());
    }

    #[test]
    fn progress_uses_the_tool_neutral_event() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        link.send_join(&mut transport).unwrap();
        link.send_progress(&mut transport, Stage::Downloading, 42)
            .unwrap();

        let sent = transport.last();
        assert_eq!(sent.event, "update_progress");
        assert_eq!(sent.payload["value"], 42);
        assert_eq!(sent.payload["stage"], "downloading");
    }

    #[test]
    fn unknown_events_are_ignored_rather_than_fatal() {
        let (mut link, mut transport) = (link(), FakeTransport::default());
        let frame = r#"[null,null,"device","something_new",{}]"#;

        assert_eq!(
            link.handle_frame(&mut transport, &mut AlwaysApply, frame)
                .unwrap(),
            Action::None
        );
    }
}
