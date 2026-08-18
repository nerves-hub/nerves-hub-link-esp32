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
use std::time::Duration;

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

        let Credentials::ClientCertificate {
            certificate,
            private_key,
        } = config.credentials;

        let ws_config = EspWebSocketClientConfig {
            // Presented to NervesHub, which resolves it to a device via
            // NervesHub.Devices.Certificates.get_device_by_x509/1.
            client_cert: Some(X509::pem(certificate)),
            client_key: Some(X509::pem(private_key)),
            server_cert: config.server_ca.map(X509::pem),

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
