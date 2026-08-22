//! Extensions: geo, health, and logging.
//!
//! An extension is functionality layered onto the device connection that both
//! sides have to agree to. The device offers what it supports; the platform
//! replies with what the product has enabled. Neither can turn one on alone,
//! which is why nothing here happens unless the application asked for it *and*
//! the product allows it.
//!
//! # The protocol
//!
//! Extensions ride on their own Phoenix channel, joined separately from
//! `device`:
//!
//! ```text
//! → join "extensions"        {"geo": "0.0.1", "health": "0.0.1"}
//! ← reply                    ["geo"]                    // attached, geo only
//! → "geo:attached"           {}                         // device confirms
//! ← "geo:location:request"   {}
//! → "geo:location:update"    {"latitude": .., "longitude": .., "source": ".."}
//! ```
//!
//! The reply is the list of extensions the platform attached — not an
//! acknowledgement of what was offered. Offering `health` and being given only
//! `geo` is normal: the product has health disabled. An extension is live only
//! after the device has confirmed it with `<key>:attached`.
//!
//! Events are scoped as `<key>:<event>`, and the platform detaches any
//! extension it does not recognise, so unknown traffic is answered rather than
//! ignored.

use serde_json::{json, Map, Value};

use crate::message::{Message, RefGenerator};

/// The channel extensions are carried on.
pub const EXTENSIONS_TOPIC: &str = "extensions";

/// The protocol version offered for every extension. NervesHub matches this
/// with `~> 0.0.1`.
pub const EXTENSION_VERSION: &str = "0.0.1";

pub const GEO: &str = "geo";
pub const HEALTH: &str = "health";
pub const LOGGING: &str = "logging";

/// Where the device thinks it is.
///
/// NervesHub stores this against the connection as-is; there is no server-side
/// lookup, so whatever the device reports is what the fleet map shows.
#[derive(Clone, Debug, PartialEq)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    /// How the position was obtained — `"geoip"`, `"gnss"`, whatever the
    /// application knows it to be. Shown in the UI beside the position, so it
    /// should say something true about the accuracy to expect.
    pub source: String,
    pub accuracy: Option<f64>,
}

impl Location {
    pub fn payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("latitude".into(), json!(self.latitude));
        map.insert("longitude".into(), json!(self.longitude));
        map.insert("source".into(), json!(self.source));
        if let Some(accuracy) = self.accuracy {
            map.insert("accuracy".into(), json!(accuracy));
        }
        Value::Object(map)
    }
}

/// Answers "where is this device?" when the platform asks.
///
/// There is no useful default: an ESP32 has no idea where it is. A GNSS module
/// answers from a fix, and everything else answers by asking a service over the
/// network — which is a third party seeing the device's address, and so a
/// decision for the application rather than this library.
pub trait LocationProvider {
    fn location(&mut self) -> Option<Location>;
}

/// A health report.
///
/// `metrics` are numbers NervesHub charts over time and evaluates for status;
/// the keys it understands by default include `cpu_usage_percent`,
/// `mem_used_percent`, `mem_size_mb` and `mem_used_mb`. Any other key is stored
/// too, so device-specific readings are worth sending — but only the known ones
/// drive the health status shown in the UI.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthReport {
    pub metrics: Vec<(String, f64)>,
    /// Free-form facts about the device. Stored with the report, not charted.
    pub metadata: Vec<(String, String)>,
}

impl HealthReport {
    pub fn metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.push((name.into(), value));
        self
    }

    pub fn meta(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((name.into(), value.into()));
        self
    }

    pub fn payload(&self) -> Value {
        let metrics: Map<String, Value> =
            self.metrics.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        let metadata: Map<String, Value> =
            self.metadata.iter().map(|(k, v)| (k.clone(), json!(v))).collect();

        // The server reads `value.metrics` for the metrics table and keeps the
        // whole of `value` as the report.
        json!({ "value": { "metrics": metrics, "metadata": metadata } })
    }
}

/// Produces a health report when the platform asks for one.
pub trait HealthProvider {
    fn report(&mut self) -> HealthReport;
}

/// A log line for NervesHub.
///
/// # The time is not optional
///
/// NervesHub requires a timestamp and does *not* supply one on arrival: a line
/// that arrives without one fails validation and is dropped without a reply,
/// so the device cannot tell. It is carried as `meta.time`, in microseconds
/// since the epoch, as a string -- the same place and format Elixir devices put
/// it. Use [`LogLine::with_time`], or [`LogLine::has_time`] to check.
#[derive(Clone, Debug, PartialEq)]
pub struct LogLine {
    /// `"debug"`, `"info"`, `"warning"`, `"error"` — stored as given.
    pub level: String,
    pub message: String,
    /// Unused by NervesHub, which reads the time from `meta.time` instead.
    /// Kept because the field is part of the shape other clients send.
    pub timestamp: Option<String>,
    pub meta: Vec<(String, String)>,
}

impl LogLine {
    pub fn new(level: impl Into<String>, message: impl Into<String>) -> Self {
        Self { level: level.into(), message: message.into(), timestamp: None, meta: Vec::new() }
    }

    pub fn at(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.push((key.into(), value.into()));
        self
    }

    /// Stamp the line, in microseconds since the epoch.
    ///
    /// Required: see the type docs. A line without one is discarded server-side.
    pub fn with_time(self, unix_micros: u64) -> Self {
        self.meta("time", unix_micros.to_string())
    }

    pub fn has_time(&self) -> bool {
        self.meta.iter().any(|(key, _)| key == "time")
    }

    pub fn payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("level".into(), json!(self.level));
        map.insert("message".into(), json!(self.message));
        if let Some(timestamp) = &self.timestamp {
            map.insert("timestamp".into(), json!(timestamp));
        }
        if !self.meta.is_empty() {
            let meta: Map<String, Value> =
                self.meta.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            map.insert("meta".into(), Value::Object(meta));
        }
        Value::Object(map)
    }
}

/// Which extensions an application wants.
///
/// Off by default, each one individually: an extension sends data the operator
/// may not expect a device to send, and logging in particular is rate limited
/// server-side, so it is opt-in rather than something a library turns on.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Enabled {
    pub geo: bool,
    pub health: bool,
    pub logging: bool,
}

impl Enabled {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn geo(mut self) -> Self {
        self.geo = true;
        self
    }

    pub fn health(mut self) -> Self {
        self.health = true;
        self
    }

    pub fn logging(mut self) -> Self {
        self.logging = true;
        self
    }

    pub fn any(&self) -> bool {
        self.geo || self.health || self.logging
    }

    fn offered(&self) -> Vec<&'static str> {
        let mut offered = Vec::new();
        if self.geo {
            offered.push(GEO);
        }
        if self.health {
            offered.push(HEALTH);
        }
        if self.logging {
            offered.push(LOGGING);
        }
        offered
    }
}

/// What the caller should do next. Every variant is a frame to write.
#[derive(Clone, Debug, PartialEq)]
pub enum Outgoing {
    /// Send on the extensions channel.
    Send { event: String, payload: Value },
    /// The platform asked for a location; the caller should consult its
    /// provider and answer with [`Extensions::location`].
    NeedLocation,
    /// The platform asked for health; answer with [`Extensions::health`].
    NeedHealth,
}

/// The extensions channel, as a state machine.
///
/// Pure: no transport, no clock, no providers. The caller performs the frames
/// and supplies the readings, which is what lets the protocol be tested without
/// a device that has a position or a temperature.
#[derive(Clone, Debug)]
pub struct Extensions {
    enabled: Enabled,
    attached: Vec<String>,
    joined: bool,
}

impl Extensions {
    pub fn new(enabled: Enabled) -> Self {
        Self { enabled, attached: Vec::new(), joined: false }
    }

    pub fn enabled(&self) -> Enabled {
        self.enabled
    }

    /// Whether there is anything to join for.
    pub fn wanted(&self) -> bool {
        self.enabled.any()
    }

    pub fn joined(&self) -> bool {
        self.joined
    }

    /// What the platform attached. Empty until the join is answered.
    pub fn attached(&self) -> &[String] {
        &self.attached
    }

    pub fn is_attached(&self, key: &str) -> bool {
        self.attached.iter().any(|k| k == key)
    }

    /// The join payload: what this device supports, and at which version.
    pub fn join_params(&self) -> Value {
        let map: Map<String, Value> = self
            .enabled
            .offered()
            .into_iter()
            .map(|key| (key.to_string(), json!(EXTENSION_VERSION)))
            .collect();

        Value::Object(map)
    }

    /// A `phx_join` for the extensions topic.
    pub fn join_message(&self, refs: &mut RefGenerator) -> (String, Message) {
        let reference = refs.next_ref();
        (reference, Message::new(EXTENSIONS_TOPIC, "phx_join", self.join_params()))
    }

    /// Handle the join reply: a list of the extensions the platform attached.
    ///
    /// Anything absent from that list stays off, however it was offered.
    pub fn on_join_reply(&mut self, response: &Value) -> Vec<Outgoing> {
        self.joined = true;
        self.attached = response
            .as_array()
            .map(|keys| keys.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
            .unwrap_or_default();

        // An extension is not live until the device confirms it.
        self.attached
            .iter()
            .map(|key| Outgoing::Send { event: format!("{key}:attached"), payload: json!({}) })
            .collect()
    }

    /// The socket went away. The channel and every attachment go with it.
    pub fn disconnected(&mut self) {
        self.joined = false;
        self.attached.clear();
    }

    /// Handle an event the platform sent on the extensions channel.
    pub fn on_event(&mut self, event: &str, _payload: &Value) -> Vec<Outgoing> {
        match event {
            "geo:location:request" if self.is_attached(GEO) => vec![Outgoing::NeedLocation],
            "health:check" if self.is_attached(HEALTH) => vec![Outgoing::NeedHealth],
            _ => Vec::new(),
        }
    }

    /// The answer to [`Outgoing::NeedLocation`].
    ///
    /// `None` sends nothing: a device that cannot fix its position should stay
    /// quiet rather than report a made-up one, which would show on the map as
    /// though it were real.
    pub fn location(&self, location: Option<Location>) -> Vec<Outgoing> {
        match location {
            Some(location) => vec![Outgoing::Send {
                event: "geo:location:update".into(),
                payload: location.payload(),
            }],
            None => Vec::new(),
        }
    }

    /// The answer to [`Outgoing::NeedHealth`].
    pub fn health(&self, report: &HealthReport) -> Vec<Outgoing> {
        vec![Outgoing::Send { event: "health:report".into(), payload: report.payload() }]
    }

    /// A log line, if logging is attached.
    ///
    /// Silently dropped otherwise — the platform rate limits log traffic and
    /// detaches extensions it did not attach, so sending regardless would earn
    /// a detach rather than delivery.
    pub fn log(&self, line: &LogLine) -> Vec<Outgoing> {
        if !self.is_attached(LOGGING) {
            return Vec::new();
        }

        vec![Outgoing::Send { event: "logging:send".into(), payload: line.payload() }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attached(enabled: Enabled, keys: &[&str]) -> Extensions {
        let mut extensions = Extensions::new(enabled);
        let _ = extensions.on_join_reply(&json!(keys));
        extensions
    }

    #[test]
    fn nothing_is_offered_by_default() {
        let extensions = Extensions::new(Enabled::none());
        assert!(!extensions.wanted());
        assert_eq!(extensions.join_params(), json!({}));
    }

    #[test]
    fn only_what_was_enabled_is_offered() {
        let extensions = Extensions::new(Enabled::none().geo().logging());
        assert_eq!(
            extensions.join_params(),
            json!({"geo": "0.0.1", "logging": "0.0.1"})
        );
    }

    // The reply says what the platform attached, which is not necessarily what
    // was offered — the product may have the extension disabled.
    #[test]
    fn only_attached_extensions_are_confirmed() {
        let mut extensions = Extensions::new(Enabled::none().geo().health());
        let out = extensions.on_join_reply(&json!(["geo"]));

        assert_eq!(
            out,
            vec![Outgoing::Send { event: "geo:attached".into(), payload: json!({}) }]
        );
        assert!(extensions.is_attached(GEO));
        assert!(!extensions.is_attached(HEALTH));
    }

    #[test]
    fn an_empty_attach_list_confirms_nothing() {
        let mut extensions = Extensions::new(Enabled::none().geo());
        assert!(extensions.on_join_reply(&json!([])).is_empty());
        assert!(extensions.joined());
        assert!(!extensions.is_attached(GEO));
    }

    #[test]
    fn a_location_request_asks_the_application() {
        let mut extensions = attached(Enabled::none().geo(), &["geo"]);
        assert_eq!(
            extensions.on_event("geo:location:request", &json!({})),
            vec![Outgoing::NeedLocation]
        );
    }

    // An extension that was never attached must not be answered, or the
    // platform detaches it.
    #[test]
    fn requests_for_unattached_extensions_are_ignored() {
        let mut extensions = attached(Enabled::none().geo(), &[]);
        assert!(extensions.on_event("geo:location:request", &json!({})).is_empty());

        let mut extensions = attached(Enabled::none().health(), &["health"]);
        assert!(extensions.on_event("geo:location:request", &json!({})).is_empty());
    }

    #[test]
    fn a_location_is_reported_in_the_shape_the_server_stores() {
        let extensions = attached(Enabled::none().geo(), &["geo"]);
        let out = extensions.location(Some(Location {
            latitude: -41.286,
            longitude: 174.776,
            source: "gnss".into(),
            accuracy: Some(12.5),
        }));

        assert_eq!(
            out,
            vec![Outgoing::Send {
                event: "geo:location:update".into(),
                payload: json!({
                    "latitude": -41.286, "longitude": 174.776,
                    "source": "gnss", "accuracy": 12.5
                })
            }]
        );
    }

    // A device that cannot fix its position says nothing, rather than putting a
    // fabricated one on the map.
    #[test]
    fn no_location_sends_nothing() {
        let extensions = attached(Enabled::none().geo(), &["geo"]);
        assert!(extensions.location(None).is_empty());
    }

    #[test]
    fn a_health_check_asks_the_application() {
        let mut extensions = attached(Enabled::none().health(), &["health"]);
        assert_eq!(extensions.on_event("health:check", &json!({})), vec![Outgoing::NeedHealth]);
    }

    // The server reads `value.metrics`; nesting it anywhere else stores the
    // report but charts nothing.
    #[test]
    fn a_health_report_nests_metrics_where_the_server_reads_them() {
        let extensions = attached(Enabled::none().health(), &["health"]);
        let report = HealthReport::default()
            .metric("mem_used_percent", 41.0)
            .metric("cpu_usage_percent", 7.5)
            .meta("chip", "esp32");

        let out = extensions.health(&report);
        let Outgoing::Send { event, payload } = &out[0] else { panic!("expected a send") };

        assert_eq!(event, "health:report");
        assert_eq!(payload["value"]["metrics"]["mem_used_percent"], json!(41.0));
        assert_eq!(payload["value"]["metrics"]["cpu_usage_percent"], json!(7.5));
        assert_eq!(payload["value"]["metadata"]["chip"], json!("esp32"));
    }

    #[test]
    fn log_lines_carry_level_message_and_optional_time() {
        let extensions = attached(Enabled::none().logging(), &["logging"]);
        let out = extensions.log(&LogLine::new("warning", "brownout").at("2026-08-22T02:10:40Z"));
        let Outgoing::Send { event, payload } = &out[0] else { panic!("expected a send") };

        assert_eq!(event, "logging:send");
        assert_eq!(payload["level"], json!("warning"));
        assert_eq!(payload["message"], json!("brownout"));
        assert_eq!(payload["timestamp"], json!("2026-08-22T02:10:40Z"));
    }

    #[test]
    fn a_log_without_a_timestamp_omits_the_field() {
        let extensions = attached(Enabled::none().logging(), &["logging"]);
        let out = extensions.log(&LogLine::new("info", "hello"));
        let Outgoing::Send { payload, .. } = &out[0] else { panic!("expected a send") };

        assert!(payload.get("timestamp").is_none());
    }

    #[test]
    fn logging_before_attach_is_dropped() {
        let extensions = attached(Enabled::none().logging(), &[]);
        assert!(extensions.log(&LogLine::new("info", "hello")).is_empty());
    }

    // A reconnect starts over: the channel and every attachment went with the
    // socket, so nothing may be sent until the platform has attached it again.
    #[test]
    fn a_disconnect_clears_every_attachment() {
        let mut extensions = attached(Enabled::none().geo().logging(), &["geo", "logging"]);
        extensions.disconnected();

        assert!(!extensions.joined());
        assert!(!extensions.is_attached(GEO));
        assert!(extensions.log(&LogLine::new("info", "dropped")).is_empty());
        assert!(extensions.on_event("geo:location:request", &json!({})).is_empty());
    }

    #[test]
    fn unknown_events_are_ignored() {
        let mut extensions = attached(Enabled::none().geo(), &["geo"]);
        assert!(extensions.on_event("something:else", &json!({})).is_empty());
    }
}
