//! A default GeoIP resolver, using the Nerves project's `whenwhere` service.
//!
//! An ESP32 has no idea where it is. The usual answer is to ask a service that
//! looks at the address the request arrived from, which is what
//! [`nerves_hub_link`] does by default and what this does — same service, same
//! `source: "geoip"`, so a fleet of Nerves devices and a fleet of ESP32s land
//! on the same map with the same accuracy and the same caveats.
//!
//! ```ignore
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # use nerves_hub_link_esp32::{esp, AlwaysApply, Config, Credentials};
//! # use nerves_hub_link_esp32::extensions::Enabled;
//! use nerves_hub_link_esp32::whenwhere::Whenwhere;
//!
//! # let credentials = Credentials::shared_secret("device-1", "nhp_key", "secret");
//! # let mut config = Config::new("hub.example.test", credentials);
//! config.extensions = Enabled::none().geo();
//!
//! esp::agent_with(config, AlwaysApply)?
//!     .with_location(Whenwhere::new())
//!     .run()?;
//! # Ok(())
//! # }
//! ```
//!
//! # What it costs someone else
//!
//! The service is run by the Nerves project as a courtesy, with no guarantee of
//! availability and a request to use it within reason. Nothing here polls: a
//! lookup happens only when NervesHub asks, which is on attach and then rarely.
//! A device that wants a position more often than the platform asks for one
//! should be running its own instance — the server is open source, and
//! [`Whenwhere::at`] points this at it.
//!
//! # The nonce
//!
//! Each request carries a random `nonce` query parameter, and the answer is
//! rejected unless the `x-nonce` response header matches. It defeats a cached
//! or intercepted reply — a captive portal answering every request with its own
//! page would otherwise be taken as a position — and it is cheap enough that
//! there is no reason to skip it.
//!
//! # HTTPS, and the clock
//!
//! `whenwhere` defaults to plain HTTP because its main job is telling a device
//! what time it is, and TLS cannot be verified by a device whose clock reads
//! 1970. That reasoning does not apply here. This lookup runs on an established
//! NervesHub connection, and reaching that state already required a correct
//! clock — for the certificate dates on a `wss://` socket, or for the signature
//! window on a shared secret. So the clock is right by the time anything here
//! runs, and the request is made over HTTPS.
//!
//! [`nerves_hub_link`]: https://github.com/nerves-hub/nerves_hub_link

use crate::extensions::Location;
#[cfg(target_os = "espidf")]
use crate::extensions::LocationProvider;

/// The service `nerves_hub_link` uses. See the module docs before pointing a
/// large fleet at it.
pub const DEFAULT_URL: &str = "https://whenwhere.nerves-project.org/";

/// The header the service echoes the nonce back in.
pub const NONCE_HEADER: &str = "x-nonce";

/// Matches `Whenwhere.make_nonce/0`: 31 characters of lowercase base36.
const NONCE_LEN: usize = 31;
const NONCE_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// A reply from the service.
///
/// Everything but the position is optional, because everything but the position
/// is a bonus: the service answers what it can work out from the address, and
/// an address it cannot place resolves to no city and no region.
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    pub latitude: f64,
    pub longitude: f64,
    /// The server's clock as RFC3339 — the service's original purpose, kept
    /// here because it arrives in the same response. Nothing in this crate sets
    /// the device clock from it; that is the application's call, and SNTP is
    /// the better tool when it is reachable.
    pub now: Option<String>,
    pub time_zone: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
}

impl Reading {
    /// As a position to report to NervesHub.
    ///
    /// `accuracy` is left unset rather than guessed. GeoIP resolves to
    /// somewhere in a city, and a number would imply a precision that a lookup
    /// against an address range does not have.
    pub fn location(&self) -> Location {
        Location {
            latitude: self.latitude,
            longitude: self.longitude,
            source: "geoip".into(),
            accuracy: None,
        }
    }
}

/// A nonce from `bytes`, which must be random.
///
/// Folding a byte into 36 symbols is very slightly biased. That is fine for
/// what this is — a cache-buster and a reply-matcher, not a key — and the
/// alternative, rejection sampling, would need a variable amount of entropy for
/// no gain.
pub fn nonce(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(NONCE_LEN)
        .map(|byte| NONCE_ALPHABET[*byte as usize % NONCE_ALPHABET.len()] as char)
        .collect()
}

/// Parse a reply, having checked it answers the nonce that was sent.
///
/// The two are checked together because neither is worth anything alone: a
/// well-formed body from something that is not the service is exactly what a
/// captive portal produces.
pub fn parse(
    body: &str,
    sent_nonce: &str,
    returned_nonce: Option<&str>,
) -> Result<Reading, String> {
    match returned_nonce {
        Some(returned) if returned == sent_nonce => {}
        Some(_) => return Err("the reply answered a different nonce".into()),
        None => return Err(format!("the reply carried no {NONCE_HEADER} header")),
    }

    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("the reply was not JSON: {e}"))?;

    // Every field arrives as a string, including the coordinates.
    let number = |key: &str| -> Option<f64> {
        let field = value.get(key)?;
        field.as_f64().or_else(|| field.as_str()?.trim().parse().ok())
    };

    let text = |key: &str| -> Option<String> { value.get(key)?.as_str().map(str::to_string) };

    let (Some(latitude), Some(longitude)) = (number("latitude"), number("longitude")) else {
        return Err("the reply carried no position".into());
    };

    Ok(Reading {
        latitude,
        longitude,
        now: text("now"),
        time_zone: text("time_zone"),
        city: text("city"),
        country: text("country"),
    })
}

/// A [`LocationProvider`] that asks the `whenwhere` service.
#[cfg(target_os = "espidf")]
pub struct Whenwhere {
    url: String,
}

#[cfg(target_os = "espidf")]
impl Default for Whenwhere {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "espidf")]
impl Whenwhere {
    /// Ask the service the Nerves project runs.
    pub fn new() -> Self {
        Self::at(DEFAULT_URL)
    }

    /// Ask an instance of your own. The URL is used as given, so it needs the
    /// scheme and a trailing slash if the path is empty.
    pub fn at(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// One lookup, with the reason on failure.
    ///
    /// [`LocationProvider::location`] logs and discards this. It is public
    /// because the reading carries more than a position, and because a device
    /// being commissioned is worth being able to ask directly.
    pub fn read(&mut self) -> Result<Reading, String> {
        use esp_idf_svc::http::client::{Configuration, EspHttpConnection};
        use esp_idf_svc::http::Method;

        let mut entropy = [0u8; NONCE_LEN];
        unsafe {
            esp_idf_svc::sys::esp_fill_random(
                entropy.as_mut_ptr() as *mut core::ffi::c_void,
                entropy.len(),
            )
        };
        let sent = nonce(&entropy);

        let separator = if self.url.contains('?') { '&' } else { '?' };
        let url = format!("{}{separator}nonce={sent}", self.url);

        let configuration = Configuration {
            crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
            use_global_ca_store: true,
            // A position is a nicety. Waiting on it holds up the session loop,
            // and every second here is a second of heartbeats not sent.
            timeout: Some(core::time::Duration::from_secs(10)),
            ..Default::default()
        };

        let mut connection =
            EspHttpConnection::new(&configuration).map_err(|e| format!("http client: {e}"))?;

        connection
            .initiate_request(Method::Get, &url, &[("user-agent", "whenwhere")])
            .map_err(|e| format!("request: {e}"))?;
        connection.initiate_response().map_err(|e| format!("response: {e}"))?;

        let status = connection.status();
        if !(200..300).contains(&status) {
            return Err(format!("the service answered HTTP {status}"));
        }

        let returned = connection.header(NONCE_HEADER).map(str::to_string);

        // Bounded: the reply is a couple of hundred bytes, and an unbounded
        // read would let a broken or hostile server exhaust a device's heap.
        let mut body = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match connection.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    body.extend_from_slice(&chunk[..n]);
                    if body.len() > 4096 {
                        return Err("the reply was too large to be a whenwhere answer".into());
                    }
                }
                Err(e) => return Err(format!("reading the reply: {e}")),
            }
        }

        let body = core::str::from_utf8(&body).map_err(|_| "the reply was not text".to_string())?;

        parse(body, &sent, returned.as_deref())
    }
}

#[cfg(target_os = "espidf")]
impl LocationProvider for Whenwhere {
    fn location(&mut self) -> Option<Location> {
        match self.read() {
            Ok(reading) => Some(reading.location()),
            // Reported, not raised: a lookup that fails is a position NervesHub
            // does not get, and the extension answering with nothing is a
            // documented outcome. Taking the connection down over it would not
            // be.
            Err(reason) => {
                log::warn!("whenwhere lookup failed: {reason}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real reply, captured from the service.
    const REPLY: &str = r#"{"now":"2026-08-22T03:19:14.676Z","time_zone":"Pacific/Auckland","latitude":"-36.88690","longitude":"174.76900","country":"NZ","country_region":"AUK","city":"Auckland","address":"182.48.134.168:61580"}"#;

    #[test]
    fn a_real_reply_parses() {
        let reading = parse(REPLY, "abc", Some("abc")).unwrap();

        assert_eq!(reading.latitude, -36.88690);
        assert_eq!(reading.longitude, 174.76900);
        assert_eq!(reading.city.as_deref(), Some("Auckland"));
        assert_eq!(reading.country.as_deref(), Some("NZ"));
        assert_eq!(reading.time_zone.as_deref(), Some("Pacific/Auckland"));
        assert_eq!(reading.now.as_deref(), Some("2026-08-22T03:19:14.676Z"));
    }

    #[test]
    fn a_reading_reports_itself_as_geoip_without_claiming_accuracy() {
        let location = parse(REPLY, "abc", Some("abc")).unwrap().location();

        assert_eq!(location.source, "geoip");
        assert_eq!(location.accuracy, None);
    }

    // The case the nonce exists for: something on the network answering with a
    // page of its own, which parses fine and means nothing.
    #[test]
    fn a_reply_answering_a_different_nonce_is_refused() {
        assert!(parse(REPLY, "abc", Some("xyz")).is_err());
    }

    #[test]
    fn a_reply_with_no_nonce_at_all_is_refused() {
        assert!(parse(REPLY, "abc", None).is_err());
    }

    // The service answers with the rest of the fields even when it cannot place
    // the address, and a device with no position must report none rather than
    // default to a point in the ocean.
    #[test]
    fn a_reply_without_a_position_is_refused() {
        let body = r#"{"now":"2026-08-22T03:19:14.676Z","time_zone":"Etc/UTC"}"#;
        assert!(parse(body, "abc", Some("abc")).is_err());
    }

    #[test]
    fn coordinates_are_accepted_as_numbers_too() {
        let body = r#"{"latitude":-36.8869,"longitude":174.769}"#;
        let reading = parse(body, "abc", Some("abc")).unwrap();

        assert_eq!(reading.latitude, -36.8869);
        assert_eq!(reading.city, None);
    }

    #[test]
    fn a_body_that_is_not_json_is_refused() {
        assert!(parse("<html>captive portal</html>", "abc", Some("abc")).is_err());
    }

    #[test]
    fn a_nonce_is_the_length_and_alphabet_the_service_expects() {
        let generated = nonce(&[0u8; 64]);

        assert_eq!(generated.len(), NONCE_LEN);
        assert!(generated.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn a_nonce_spans_the_alphabet() {
        let bytes: Vec<u8> = (0..NONCE_LEN as u8).collect();
        assert_eq!(nonce(&bytes), "0123456789abcdefghijklmnopqrstu");
    }
}
