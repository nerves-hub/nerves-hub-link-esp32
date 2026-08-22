//! Connection configuration.

use std::ffi::{CStr, CString};

use crate::error::Error;
use crate::shared_secret::SharedSecret;
use crate::message::{DEVICE_API_VERSION, SERIALIZER_VSN};

/// How the device proves who it is.
///
/// Only mTLS is implemented. NervesHub also accepts an HMAC shared secret, but
/// that path requires reproducing Plug.Crypto's token format — PBKDF2 key
/// derivation with a negotiated digest/iteration/length, then `MessageVerifier`'s
/// encoding, over a specific multi-line salt. mTLS is a client certificate
/// handed to mbedTLS, which ESP-IDF already ships, so there is no crypto to
/// reimplement and nothing to get subtly and silently wrong.
///
/// # Why `&'static CStr`
///
/// ESP-IDF's TLS configuration takes `X509<'static>`, and mbedTLS wants PEM as
/// a NUL-terminated C string. Rather than leak on every reconnect, the bytes
/// are converted and leaked exactly once by [`Credentials::client_certificate`].
/// A device's identity lives as long as the program does, so a one-time leak is
/// an honest representation of that — the alternative is a self-referential
/// `Config`.
#[derive(Debug, Clone)]
pub enum Credentials {
    ClientCertificate {
        certificate: &'static CStr,
        private_key: &'static CStr,
    },
    /// An HMAC shared secret, issued per product or per device.
    ///
    /// Unlike a certificate, a shared secret says nothing about which device is
    /// presenting it, so the identifier is carried alongside. NervesHub will
    /// register an unknown identifier on first connection.
    SharedSecret {
        identifier: String,
        secret: SharedSecret,
    },
}

impl Credentials {
    /// Take PEM bytes and prepare them for mbedTLS.
    ///
    /// A trailing NUL is appended if absent: mbedTLS reads PEM as a C string,
    /// and an unterminated blob parses as a truncated certificate, which
    /// surfaces much later as an opaque handshake failure.
    /// Authenticate with a shared secret rather than a certificate.
    pub fn shared_secret(
        identifier: impl Into<String>,
        key: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Credentials::SharedSecret {
            identifier: identifier.into(),
            secret: SharedSecret::new(key, secret),
        }
    }

    pub fn client_certificate(certificate: Vec<u8>, private_key: Vec<u8>) -> Result<Self, Error> {
        Ok(Credentials::ClientCertificate {
            certificate: leak_pem(certificate, "certificate")?,
            private_key: leak_pem(private_key, "private key")?,
        })
    }
}

fn leak_pem(mut bytes: Vec<u8>, what: &str) -> Result<&'static CStr, Error> {
    if bytes.is_empty() {
        return Err(Error::Identity(format!("{what} is empty")));
    }

    // Trailing NULs are stripped so a blob that already has one does not end up
    // with two, which CString rejects as an interior NUL.
    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    let cstring =
        CString::new(bytes).map_err(|_| Error::Identity(format!("{what} contains a NUL byte")))?;

    Ok(Box::leak(cstring.into_boxed_c_str()))
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Host only — no scheme, no path. e.g. `devices.nerves-hub.org`.
    pub host: String,
    pub port: u16,
    pub credentials: Credentials,
    /// PEM root used to verify the server. `None` uses the IDF bundle.
    pub server_ca: Option<&'static CStr>,
    /// Whether to connect over TLS. True unless deliberately turned off.
    ///
    /// Plain `ws://` sends the shared-secret headers in clear and lets anything
    /// on the path impersonate the server, so it is for a bench on a trusted
    /// network and nothing else.
    pub use_tls: bool,
    /// Reported on join; NervesHub gates features on it.
    pub device_api_version: String,
    /// Phoenix heartbeat interval. Must stay under the server's socket timeout.
    pub heartbeat_interval_secs: u64,
    /// Reconnect backoff, in seconds, walked in order then repeating the last.
    pub reconnect_backoff_secs: Vec<u64>,
    /// Report download progress every N percent.
    pub progress_step_percent: u8,
}

impl Config {
    pub fn new(host: impl Into<String>, credentials: Credentials) -> Self {
        Self {
            host: host.into(),
            port: 443,
            credentials,
            server_ca: None,
            device_api_version: DEVICE_API_VERSION.to_string(),
            use_tls: true,
            heartbeat_interval_secs: 30,
            reconnect_backoff_secs: vec![1, 2, 5, 10, 30, 60],
            progress_step_percent: 5,
        }
    }

    /// The socket URL, including the `vsn` that selects the JSON serializer.
    pub fn socket_url(&self) -> String {
        let scheme = if self.use_tls { "wss" } else { "ws" };
        format!(
            "{}://{}:{}/device-socket/websocket?vsn={}",
            scheme, self.host, self.port, SERIALIZER_VSN
        )
    }

    pub fn backoff_for(&self, attempt: usize) -> u64 {
        let backoff = &self.reconnect_backoff_secs;

        if backoff.is_empty() {
            return 5;
        }

        *backoff
            .get(attempt)
            .unwrap_or_else(|| backoff.last().expect("checked non-empty above"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::new(
            "devices.nerves-hub.org",
            Credentials::client_certificate(b"cert-pem".to_vec(), b"key-pem".to_vec()).unwrap(),
        )
    }

    #[test]
    fn pem_is_nul_terminated_for_mbedtls() {
        let Credentials::ClientCertificate { certificate, .. } =
            Credentials::client_certificate(b"pem".to_vec(), b"key".to_vec()).unwrap()
        else {
            panic!("client_certificate must produce a ClientCertificate")
        };

        assert_eq!(certificate.to_bytes_with_nul(), b"pem\0");
    }

    #[test]
    fn an_already_terminated_pem_is_not_double_terminated() {
        let Credentials::ClientCertificate { certificate, .. } =
            Credentials::client_certificate(b"pem\0".to_vec(), b"key".to_vec()).unwrap()
        else {
            panic!("client_certificate must produce a ClientCertificate")
        };

        assert_eq!(certificate.to_bytes_with_nul(), b"pem\0");
    }

    #[test]
    fn empty_pem_is_rejected() {
        assert!(Credentials::client_certificate(vec![], b"key".to_vec()).is_err());
    }

    #[test]
    fn socket_url_requests_the_json_serializer() {
        assert_eq!(
            config().socket_url(),
            "wss://devices.nerves-hub.org:443/device-socket/websocket?vsn=2.0.0"
        );
    }

    #[test]
    fn backoff_walks_then_holds_at_the_last_value() {
        let config = config();

        assert_eq!(config.backoff_for(0), 1);
        assert_eq!(config.backoff_for(3), 10);
        assert_eq!(config.backoff_for(5), 60);
        // Past the end, keep retrying at the slowest rate rather than giving up.
        assert_eq!(config.backoff_for(500), 60);
    }

    #[test]
    fn backoff_survives_an_empty_schedule() {
        let mut config = config();
        config.reconnect_backoff_secs = vec![];
        assert_eq!(config.backoff_for(0), 5);
    }
}
