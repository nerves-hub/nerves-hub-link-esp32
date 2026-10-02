//! WebSocket transport over ESP-IDF's `esp_websocket_client`.
//!
//! # Who owns reconnection
//!
//! The agent does. A socket that comes back without a `phx_join` on it carries
//! no Phoenix channel, and NervesHub records a device connection when the
//! *socket* connects — so a silently re-established socket shows the device as
//! online while it is deaf to everything. Only the agent can rebuild a session,
//! so a closed socket is reported up to it and it builds a new transport.
//!
//! The IDF client's own reconnect is left at its default rather than disabled.
//! It never gets to act on a close the agent has seen, because the agent drops
//! the client, and turning it off was tried: it left a device that could not
//! establish a session at all.
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

/// What the client's callback hands to the run loop.
///
/// A close has to travel the same channel as the frames, in order with them:
/// the run loop learns the socket is gone at the point it would have read the
/// next frame, rather than by a flag it might check at the wrong moment.
enum Incoming {
    Text(String),
    Closed,
}

pub struct WebSocketTransport {
    client: EspWebSocketClient<'static>,
    incoming: Receiver<Incoming>,
    recv_timeout: Duration,
}

impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        // The client's own Drop closes and destroys it. Until esp-idf-svc 0.53
        // it unwrapped both, and `esp_websocket_client_close` refuses a client
        // that is no longer running, which is every socket the server closed,
        // so dropping one aborted the device. This transport used to skip that
        // Drop and call `esp_websocket_client_destroy` itself, which leaked
        // the client's boxed event callback and, through the sender it holds,
        // the channel behind it: a few hundred bytes on every reconnect.
        // 0.53 logs a failed close or destroy instead of unwrapping it, so the
        // client is now simply dropped, and everything it holds with it.
        log::debug!("closing the websocket");
    }
}

impl WebSocketTransport {
    pub fn connect(config: &Config) -> Result<Self, Error> {
        let (tx, rx): (Sender<Incoming>, Receiver<Incoming>) = channel();

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

        let connect_timeout = Duration::from_secs(config.connect_timeout_secs);

        let ws_config = EspWebSocketClientConfig {
            client_cert,
            client_key,
            server_cert: config.server_ca.map(X509::pem),

            // esp-tls refuses to set up at all with no verification option:
            // "No server verification option set in esp_tls_cfg_t structure",
            // and then the client never connects. A named CA wins where there
            // is one; otherwise the roots ESP-IDF bundles, which is what any
            // public host needs and what CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is
            // turned on for.
            crt_bundle_attach: if config.server_ca.is_some() {
                None
            } else {
                Some(esp_idf_svc::sys::esp_crt_bundle_attach)
            },

            headers: headers.as_deref(),

            // Phoenix has its own heartbeat on the "phoenix" topic; this is the
            // transport-level one. Both are wanted — the transport ping detects
            // a dead TCP connection, the Phoenix heartbeat keeps the channel
            // alive server-side.
            ping_interval_sec: Duration::from_secs(config.heartbeat_interval_secs),

            // A frame larger than the client's buffer (1 KiB by default)
            // arrives as several DATA events, and `esp-idf-svc` hands each one
            // on as a text frame of its own, without the offsets that would put
            // them back together. An `update` from NervesCloud, whose firmware
            // URL carries a signed query string, is a little over 1 KiB, so its
            // pieces each failed to parse and the session silently restarted
            // instead of updating. Every message NervesHub sends a device fits
            // in this.
            buffer_size: 4096,

            // The IDF client's own bound on connecting -- DNS, TCP, TLS --
            // which it otherwise defaults to 10 s, too short for a TLS
            // handshake over a slow cellular link. See
            // `Config::connect_timeout_secs`.
            network_timeout_ms: connect_timeout,

            ..Default::default()
        };

        // Bounds each send and the close, not the connect.
        let send_timeout = Duration::from_secs(10);

        let client =
            EspWebSocketClient::new(&config.socket_url(), &ws_config, send_timeout, move |event| {
                handle_event(&tx, event);
            })
            .map_err(|e: EspIOError| Error::Transport(e.to_string()))?;

        // The IDF client performs the handshake on its own task, so getting a
        // client back says nothing about the socket being up. The run loop
        // sends the join as soon as this returns, and sending before the
        // handshake completes is not a recoverable error in esp-idf-svc — it
        // panics. So this does not return until there is a connection, and a
        // handshake that never completes becomes a retryable error.
        //
        // On that path the client is dropped. Its close fails on a client that
        // never connected, which esp-idf-svc 0.53 logs before destroying it;
        // earlier versions unwrapped it and aborted the device, turning a
        // refused connection into a boot loop.
        let deadline = Instant::now() + connect_timeout;
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

// Text frames and the end of the socket are the run loop's business; pings,
// pongs, and the handshake are the transport's own. Binary is ignored because
// Phoenix only ever sends text on this socket.
//
// Forwarding the close is the whole point of this function. Without it the
// channel stays open with nothing ever arriving on it, `recv` reports an idle
// socket forever, and the agent waits out the rest of its life for a frame
// from a connection that ended.
//
// An `Err` is the client's ERROR event, and it is deliberately *not* one of
// those. The IDF client raises it for anything it dislikes, including during a
// normal connect, and a device that abandoned the session on each one never
// got as far as joining. A genuine failure is followed by a close, so waiting
// for the close costs nothing and reads far more of what is happening.
fn handle_event(tx: &Sender<Incoming>, event: &Result<WebSocketEvent<'_>, EspIOError>) {
    let Ok(event) = event else {
        log::debug!("websocket error event");
        return;
    };

    match event.event_type {
        WebSocketEventType::Text(text) => {
            let _ = tx.send(Incoming::Text(text.to_string()));
        }
        WebSocketEventType::Disconnected
        | WebSocketEventType::Close(_)
        | WebSocketEventType::Closed => {
            let _ = tx.send(Incoming::Closed);
        }
        _ => {}
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
            Ok(Incoming::Text(frame)) => Ok(Some(frame)),

            // A close event from the client that is still connected belongs to
            // an earlier socket being torn down -- the events arrive on a task
            // of their own, so a previous client's last words can land here
            // after this one is up. Only the client's own view of itself
            // decides that the session is over.
            Ok(Incoming::Closed) => {
                if self.client.is_connected() {
                    log::debug!("ignoring a close for a socket that is still connected");
                    Ok(None)
                } else {
                    log::info!("websocket closed");
                    Err(Error::Transport("websocket closed".into()))
                }
            }
            // Nothing arrived, which is what most half-seconds look like.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(Error::Transport("websocket closed".into()))
            }
        }
    }
}
