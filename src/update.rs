//! The `update` message and the decision of what to do with it.

use serde::Deserialize;
use serde_json::Value;

/// What NervesHub sends on the `update` event, and in the reply to `phx_join`.
///
/// Only `update_available` is guaranteed; every other field is absent when
/// there is nothing to do.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpdatePayload {
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub firmware_url: Option<String>,
    #[serde(default)]
    pub firmware_meta: Option<FirmwareMeta>,
    #[serde(default)]
    pub size: Option<u64>,
    /// SHA-256 of the whole image, uppercase hex.
    #[serde(default)]
    pub checksum: Option<String>,
    /// Per-chunk SHA-256s, for verifying a resumed download.
    #[serde(default)]
    pub partials_checksums: Option<Vec<String>>,
    #[serde(default)]
    pub deployment_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct FirmwareMeta {
    pub uuid: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
}

impl UpdatePayload {
    pub fn parse(payload: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(payload.clone())
    }

    /// The url and uuid, if this payload actually describes an update.
    ///
    /// An `update_available: true` with no url is not something to act on — it
    /// would otherwise become a download of nothing that reports failure.
    pub fn actionable(&self) -> Option<(&str, &str)> {
        if !self.update_available {
            return None;
        }

        match (self.firmware_url.as_deref(), self.firmware_meta.as_ref()) {
            (Some(url), Some(meta)) => Some((url, meta.uuid.as_str())),
            _ => None,
        }
    }
}

/// What the application wants done about an available update.
///
/// `Ignore` and `Reschedule` map onto NervesHub statuses that it already
/// understands — a rescheduled device is put in the penalty box for the delay
/// rather than simply going quiet.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateDecision {
    Apply,
    Ignore { reason: String },
    Reschedule { delay_ms: u64, reason: String },
}

/// Where an update is in its lifecycle. Sent as the `stage` of an
/// `update_progress` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Downloading,
    Updating,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Downloading => "downloading",
            Stage::Updating => "updating",
        }
    }
}

/// Decides when a progress message is worth sending.
///
/// NervesHub persists downloading/updating progress at most every 15 seconds,
/// so a device reporting every chunk is spending radio time to have the value
/// discarded. Reporting per whole percent is already generous.
#[derive(Debug)]
pub struct ProgressThrottle {
    last_reported: Option<u8>,
    step: u8,
}

impl ProgressThrottle {
    pub fn new(step: u8) -> Self {
        Self {
            last_reported: None,
            step: step.max(1),
        }
    }

    /// The percentage to report, or `None` to stay quiet.
    ///
    /// 100 always reports: it is what moves the update to `completed`.
    pub fn take(&mut self, downloaded: u64, total: u64) -> Option<u8> {
        if total == 0 {
            return None;
        }

        let percent = ((downloaded.min(total) as u128 * 100) / total as u128) as u8;

        let report = match self.last_reported {
            None => true,
            Some(_) if percent == 100 => true,
            Some(last) => percent >= last.saturating_add(self.step),
        };

        if report && self.last_reported != Some(percent) {
            self.last_reported = Some(percent);
            Some(percent)
        } else {
            None
        }
    }
}

impl Default for ProgressThrottle {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_no_update() {
        let payload = UpdatePayload::parse(&json!({"update_available": false})).unwrap();
        assert!(!payload.update_available);
        assert_eq!(payload.actionable(), None);
    }

    #[test]
    fn parses_an_available_update() {
        let payload = UpdatePayload::parse(&json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {
                "uuid": "abababab-abab-abab-abab-abababababab",
                "version": "1.2.3",
                "platform": "esp32s3",
                "architecture": "xtensa"
            },
            "size": 1_048_576,
            "checksum": "DEADBEEF",
            "deployment_id": 7
        }))
        .unwrap();

        assert_eq!(
            payload.actionable(),
            Some((
                "https://example.test/fw.bin",
                "abababab-abab-abab-abab-abababababab"
            ))
        );
        assert_eq!(payload.size, Some(1_048_576));
    }

    // The server can only send a url it has; a truncated payload should not be
    // turned into a download attempt.
    #[test]
    fn an_update_without_a_url_is_not_actionable() {
        let payload = UpdatePayload::parse(&json!({"update_available": true})).unwrap();
        assert_eq!(payload.actionable(), None);
    }

    #[test]
    fn tolerates_unknown_fields() {
        let payload = UpdatePayload::parse(&json!({
            "update_available": false,
            "something_added_later": 1
        }));
        assert!(payload.is_ok());
    }

    #[test]
    fn throttle_reports_first_and_then_by_step() {
        let mut throttle = ProgressThrottle::new(5);

        assert_eq!(throttle.take(1, 100), Some(1));
        assert_eq!(throttle.take(2, 100), None);
        assert_eq!(throttle.take(6, 100), Some(6));
        assert_eq!(throttle.take(7, 100), None);
    }

    #[test]
    fn throttle_always_reports_completion() {
        let mut throttle = ProgressThrottle::new(50);

        assert_eq!(throttle.take(1, 100), Some(1));
        assert_eq!(throttle.take(99, 100), Some(99));
        assert_eq!(throttle.take(100, 100), Some(100));
    }

    #[test]
    fn throttle_does_not_repeat_the_same_percent() {
        let mut throttle = ProgressThrottle::new(1);
        assert_eq!(throttle.take(100, 100), Some(100));
        assert_eq!(throttle.take(100, 100), None);
    }

    #[test]
    fn throttle_handles_unknown_size() {
        let mut throttle = ProgressThrottle::default();
        assert_eq!(throttle.take(10, 0), None);
    }

    #[test]
    fn stage_names_match_the_server() {
        assert_eq!(Stage::Downloading.as_str(), "downloading");
        assert_eq!(Stage::Updating.as_str(), "updating");
    }
}
