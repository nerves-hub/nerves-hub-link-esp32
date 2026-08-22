//! WebSocket transport over ESP-IDF's `esp_websocket_client`.
//!
//! **Not yet built or run.** The structure is right and the mTLS wiring is the
//! interesting part, but the `esp-idf-svc` API surface here needs checking
//! against the version you actually build with.
//!
//! # Why mTLS
//!
//! ESP-IDF's websocket client takes a client certificate and key straight
//! through to mbedTLS, so device authentication is configuration rather than
//! code. NervesHub's other option — an HMAC shared secret — would mean
//! reimplementing Plug.Crypto's signed-token format (PBKDF2 with a negotiated
//! digest/iteration count/key length, then `MessageVerifier`'s encoding, over a
//! multi-line salt). That is a lot of cryptographic detail to get exactly right
//! for no gain when mbedTLS is already there.
//!
//! Certificates should live in an NVS partition, ideally an encrypted one —
//! not compiled into the image, where every device in a fleet would share one
//! identity.

#![cfg(target_os = "espidf")]

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use esp_idf_svc::io::EspIOError;
use esp_idf_svc::tls::X509;
use esp_idf_svc::ws::client::{
    EspWebSocketClient, EspWebSocketClientConfig, WebSocketEvent, WebSocketEventType,
};
use esp_idf_svc::ws::FrameType;

use crate::config::{Config, Credentials};
use crate::error::Error;
use crate::link::Transport;

pub struct WebSocketTransport {
    client: EspWebSocketClient<'static>,
    incoming: Receiver<String>,
    recv_timeout: Duration,
}

impl WebSocketTransport {
    pub fn connect(config: &Config) -> Result<Self, Error> {
        let (tx, rx): (Sender<String>, Receiver<String>) = channel();

        // Both authentication modes are just configuration on the same client:
        // a certificate mbedTLS presents during the handshake, or headers sent
        // with the HTTP upgrade. Which an organization uses is its choice.
        let (client_cert, client_key, headers) = match &config.credentials {
            Credentials::ClientCertificate {
                certificate,
                private_key,
            } => (
                // Presented to NervesHub, which resolves it to a device via
                // NervesHub.Devices.Certificates.get_device_by_x509/1.
                Some(X509::pem(certificate)),
                Some(X509::pem(private_key)),
                None,
            ),
            Credentials::SharedSecret { identifier, secret } => {
                // The signature is only valid for a short window — 90 seconds by
                // default — so a device whose clock is wrong fails to join in a
                // way that looks like a bad secret. Run SNTP before connecting.
                let signed_at = crate::shared_secret::now_secs();
                let block = secret
                    .headers(identifier, signed_at)
                    .into_iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>();

                (None, None, Some(block))
            }
        };

        let ws_config = EspWebSocketClientConfig {
            client_cert,
            client_key,
            server_cert: config.server_ca.map(X509::pem),
            headers: headers.as_deref(),

            // Phoenix has its own heartbeat on the "phoenix" topic; this is the
            // transport-level one. Both are wanted — the transport ping detects
            // a dead TCP connection, the Phoenix heartbeat keeps the channel
            // alive server-side.
            ping_interval_sec: Duration::from_secs(config.heartbeat_interval_secs),

            ..Default::default()
        };

        let timeout = Duration::from_secs(10);

        let client =
            EspWebSocketClient::new(&config.socket_url(), &ws_config, timeout, move |event| {
                handle_event(&tx, event);
            })
            .map_err(|e: EspIOError| Error::Transport(e.to_string()))?;

        // The IDF client performs the handshake on its own task, so getting a
        // client back says nothing about the socket being up. The run loop
        // sends the join as soon as this returns, and sending before the
        // handshake completes is not a recoverable error in esp-idf-svc — it
        // panics. So this does not return until there is a connection, and a
        // handshake that never completes becomes a retryable error.
        let deadline = Instant::now() + timeout;
        while !client.is_connected() {
            if Instant::now() >= deadline {
                return Err(Error::Transport(
                    "timed out waiting for the WebSocket handshake".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(Self {
            client,
            incoming: rx,
            recv_timeout: Duration::from_millis(500),
        })
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }
}

// Text frames are forwarded to the run loop; everything else is the transport's
// own business. A frame that is not valid UTF-8 is dropped rather than killing
// the connection — Phoenix only ever sends text on this socket.
fn handle_event(tx: &Sender<String>, event: &Result<WebSocketEvent<'_>, EspIOError>) {
    let Ok(event) = event else { return };

    if let WebSocketEventType::Text(text) = event.event_type {
        let _ = tx.send(text.to_string());
    }
}

impl Transport for WebSocketTransport {
    fn send(&mut self, frame: &str) -> Result<(), Error> {
        self.client
            // `false` = not fragmented; the C client does not support
            // fragmented sends anyway.
            .send(FrameType::Text(false), frame.as_bytes())
            .map_err(|e| Error::Transport(e.to_string()))
    }

    fn recv(&mut self) -> Result<Option<String>, Error> {
        match self.incoming.recv_timeout(self.recv_timeout) {
            Ok(frame) => Ok(Some(frame)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(Error::Transport("websocket closed".into()))
            }
        }
    }
}
