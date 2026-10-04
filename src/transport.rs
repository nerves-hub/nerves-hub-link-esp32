//! WebSocket transport over ESP-IDF's `esp_websocket_client`.
//!
//! # Why the C client directly
//!
//! `esp-idf-svc` wraps the same client, but builds its transports itself, and
//! the TLS one it builds keeps its session where nothing can save it across a
//! deep sleep. The C client takes a transport from outside (`ext_transport`),
//! so this hands it a websocket transport over [`crate::tls`], whose session
//! lives in [`Config::tls_session`](crate::Config::tls_session). The rest is
//! what `esp-idf-svc` did: start the client, turn its events into frames, and
//! close and destroy it on drop.
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

use core::ffi::{c_int, c_void};
use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use esp_idf_svc::hal::delay::TickType;
use esp_idf_svc::sys;

use crate::config::{Config, Credentials};
use crate::error::Error;
use crate::link::Transport;
use crate::message::Frame;
use crate::tls;

/// Effectively never: see the client config in [`WebSocketTransport::connect`].
const WEBSOCKET_PING_INTERVAL_SECS: usize = 24 * 60 * 60;

/// What the client's callback hands to the run loop.
///
/// A close has to travel the same channel as the frames, in order with them:
/// the run loop learns the socket is gone at the point it would have read the
/// next frame, rather than by a flag it might check at the wrong moment.
enum Incoming {
    Frame(Frame),
    Closed,
}

pub struct WebSocketTransport {
    client: sys::esp_websocket_client_handle_t,
    // The client runs over these but does not own them: an `ext_transport` is
    // the caller's to destroy, and only once the client has stopped using it.
    // `base` is the TLS (or TCP) transport `ws` sits on.
    ws: sys::esp_transport_handle_t,
    base: sys::esp_transport_handle_t,
    /// For a `base` that is [`crate::tls`]'s rather than ESP-IDF's TCP
    /// transport.
    stopper: Option<tls::Stopper>,
    events: *mut Events,
    incoming: Receiver<Incoming>,
    recv_timeout: Duration,
    send_timeout: sys::TickType_t,
}

// The handles are only used from the thread that owns the transport; the
// client's own task reaches `events` through the pointer it was given, and
// `Events` is a Mutex.
unsafe impl Send for WebSocketTransport {}

impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        unsafe {
            // No close frame. The client's close would send one, take the
            // server's, then wait for the server to close TCP by asking the
            // transport under it for its socket -- which only ESP-IDF's own
            // transports can answer, so it sits out a full second for nothing.
            // NervesHub treats every disconnect alike, and dropping the
            // connection is what a device losing signal does anyway; leaving
            // it out saves a round trip and two frames.
            //
            // Destroying stops the client's task, which closes the connection
            // on its way out, after which no event can arrive, so `events` and
            // the transports under it can go. `stop` lets the task notice in a
            // tenth of a second rather than at its next one-second poll.
            if let Some(stopper) = &self.stopper {
                stopper.stop();
            }
            sys::esp_websocket_client_destroy(self.client);
            sys::esp_transport_destroy(self.ws);
            sys::esp_transport_destroy(self.base);
            drop(Box::from_raw(self.events));
        }
        log::debug!("closed the websocket");
    }
}

impl WebSocketTransport {
    pub fn connect(config: &Config) -> Result<Self, Error> {
        let (tx, rx): (Sender<Incoming>, Receiver<Incoming>) = channel();

        // Both authentication modes are just configuration on the same client:
        // a certificate mbedTLS presents during the handshake, or headers sent
        // with the HTTP upgrade. Which an organization uses is its choice.
        let (client_certificate, headers) = match &config.credentials {
            Credentials::ClientCertificate {
                certificate,
                private_key,
            } => (
                // Presented to NervesHub, which resolves it to a device via
                // NervesHub.Devices.Certificates.get_device_by_x509/1.
                Some((*certificate, *private_key)),
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

                (None, Some(block))
            }
        };

        let connect_timeout = Duration::from_secs(config.connect_timeout_secs);

        // From the first handle on, every early return has to give back what
        // was made before it; `Partial` does, until `Self` takes over.
        let mut partial = Partial::default();

        let stopper = if config.use_tls {
            let (base, stopper) = tls::transport(tls::Settings {
                server_ca: config.server_ca,
                client_certificate,
                session: config.tls_session.clone(),
            })?;
            partial.base = base;
            Some(stopper)
        } else {
            partial.base = nonnull(unsafe { sys::esp_transport_tcp_init() }, "TCP transport")?;
            None
        };
        partial.ws = nonnull(unsafe { sys::esp_transport_ws_init(partial.base) }, "websocket transport")?;

        // Which the client would otherwise set on a transport it made itself.
        // The ws transport copies each string, so these need only outlive the
        // call.
        let path = cstring(config.socket_path())?;
        let headers = headers.map(cstring).transpose()?;
        let ws_config = sys::esp_transport_ws_config_t {
            ws_path: path.as_ptr(),
            headers: headers.as_ref().map_or(core::ptr::null(), |h| h.as_ptr()),
            // As the client asks of its own transports: it answers pings and
            // sees the server's close itself, so it wants every frame.
            propagate_control_frames: true,
            ..Default::default()
        };
        esp(unsafe { sys::esp_transport_ws_set_config(partial.ws, &ws_config) })?;

        let uri = cstring(config.socket_url())?;
        let client_config = sys::esp_websocket_client_config_t {
            uri: uri.as_ptr(),
            ext_transport: partial.ws,

            // No websocket pings, near enough. The Phoenix heartbeat already
            // does both jobs: any frame keeps NervesHub's socket timeout at bay,
            // and an unanswered one is how the agent notices a dead connection
            // (see `Link::heartbeat_unanswered`). A ping on top doubled the
            // keepalive traffic, which on a metered cellular link is most of
            // what an idle session sends. The client can't switch pings off --
            // 0 means its 10 s default -- so they go once a day, and a missing
            // pong no longer ends the session.
            ping_interval_sec: WEBSOCKET_PING_INTERVAL_SECS,
            disable_pingpong_discon: true,

            // Frames bigger than the buffer arrive in pieces, which `Events`
            // puts back together, so this is about how many pieces rather than
            // whether a message survives. Every message NervesHub sends a
            // device -- the largest, an `update` with a signed firmware URL, is
            // a little over 1 KiB -- fits in one.
            buffer_size: 4096,

            // The IDF client's own bound on connecting -- DNS, TCP, TLS --
            // which it otherwise defaults to 10 s, too short for a TLS
            // handshake over a slow cellular link. See
            // `Config::connect_timeout_secs`.
            network_timeout_ms: connect_timeout.as_millis() as _,

            ..Default::default()
        };

        partial.client = unsafe { sys::esp_websocket_client_init(&client_config) };
        if partial.client.is_null() {
            return Err(Error::Transport("could not create the websocket client".into()));
        }

        partial.events = Box::into_raw(Box::new(Events::new(tx)));
        esp(unsafe {
            sys::esp_websocket_register_events(
                partial.client,
                sys::esp_websocket_event_id_t_WEBSOCKET_EVENT_ANY,
                Some(on_event),
                partial.events.cast(),
            )
        })?;
        esp(unsafe { sys::esp_websocket_client_start(partial.client) })?;

        // Bounds each send and the close, not the connect.
        let send_timeout: TickType = Duration::from_secs(10).into();
        let transport = partial.into_transport(rx, send_timeout.0, stopper);

        // The IDF client performs the handshake on its own task, so getting a
        // client back says nothing about the socket being up. The run loop
        // sends the join as soon as this returns, so this does not return until
        // there is a connection, and a handshake that never completes becomes a
        // retryable error. Dropping `transport` on that path closes (which
        // fails, harmlessly, on a client that never connected) and destroys it.
        let deadline = Instant::now() + connect_timeout;
        while !transport.is_connected() {
            if Instant::now() >= deadline {
                return Err(Error::Transport(
                    "timed out waiting for the WebSocket handshake".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        if config.use_tls {
            match config.tls_session.last_handshake() {
                Some(crate::Handshake::Resumed) => log::info!("TLS session resumed"),
                Some(crate::Handshake::Full) => log::info!("TLS full handshake"),
                None => {}
            }
        }

        Ok(transport)
    }

    pub fn is_connected(&self) -> bool {
        unsafe { sys::esp_websocket_client_is_connected(self.client) }
    }
}

/// The pieces of a transport not yet assembled, released in reverse if
/// assembly stops partway.
struct Partial {
    client: sys::esp_websocket_client_handle_t,
    ws: sys::esp_transport_handle_t,
    base: sys::esp_transport_handle_t,
    events: *mut Events,
}

impl Default for Partial {
    fn default() -> Self {
        Self {
            client: core::ptr::null_mut(),
            ws: core::ptr::null_mut(),
            base: core::ptr::null_mut(),
            events: core::ptr::null_mut(),
        }
    }
}

impl Partial {
    fn into_transport(
        self,
        incoming: Receiver<Incoming>,
        send_timeout: sys::TickType_t,
        stopper: Option<tls::Stopper>,
    ) -> WebSocketTransport {
        let this = core::mem::ManuallyDrop::new(self);
        WebSocketTransport {
            client: this.client,
            ws: this.ws,
            base: this.base,
            stopper,
            events: this.events,
            incoming,
            recv_timeout: Duration::from_millis(500),
            send_timeout,
        }
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        unsafe {
            if !self.client.is_null() {
                sys::esp_websocket_client_destroy(self.client);
            }
            if !self.ws.is_null() {
                sys::esp_transport_destroy(self.ws);
            }
            if !self.base.is_null() {
                sys::esp_transport_destroy(self.base);
            }
            if !self.events.is_null() {
                drop(Box::from_raw(self.events));
            }
        }
    }
}

fn nonnull(
    handle: sys::esp_transport_handle_t,
    what: &str,
) -> Result<sys::esp_transport_handle_t, Error> {
    if handle.is_null() {
        Err(Error::Transport(format!("no memory for the {what}")))
    } else {
        Ok(handle)
    }
}

fn cstring(s: String) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::Transport("a NUL byte in the socket settings".into()))
}

fn esp(err: sys::esp_err_t) -> Result<(), Error> {
    sys::EspError::convert(err).map_err(|e| Error::Transport(e.to_string()))
}

/// The client's events, turned into what the run loop reads.
///
/// Text and binary frames and the end of the socket are the run loop's
/// business; pings, pongs, and the handshake are the client's own. Which kind
/// of frame arrives is the serializer's choice: text for JSON, binary for
/// msgpack.
///
/// Forwarding the close is the whole point. Without it the channel stays open
/// with nothing ever arriving on it, `recv` reports an idle socket forever, and
/// the agent waits out the rest of its life for a frame from a connection that
/// ended.
///
/// The client's ERROR event is deliberately *not* one of those. The client
/// raises it for anything it dislikes, including during a normal connect, and a
/// device that abandoned the session on each one never got as far as joining.
/// A genuine failure is followed by a close, so waiting for the close costs
/// nothing and reads far more of what is happening.
struct Events {
    state: Mutex<EventState>,
}

struct EventState {
    tx: Sender<Incoming>,
    /// A message arriving in pieces: one per buffer-full of a frame, and one
    /// frame per fragment of a fragmented message.
    partial: Vec<u8>,
    /// Whether `partial` is binary. A continuation carries no kind of its
    /// own; it is whatever the frame that started the message was.
    partial_binary: bool,
}

impl Events {
    fn new(tx: Sender<Incoming>) -> Self {
        Self {
            state: Mutex::new(EventState {
                tx,
                partial: Vec::new(),
                partial_binary: false,
            }),
        }
    }
}

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;

unsafe extern "C" fn on_event(
    arg: *mut c_void,
    _base: sys::esp_event_base_t,
    id: i32,
    data: *mut c_void,
) {
    let Some(events) = (arg as *const Events).as_ref() else { return };
    let mut state = events.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    #[allow(non_upper_case_globals)]
    match id {
        sys::esp_websocket_event_id_t_WEBSOCKET_EVENT_DATA => {
            if let Some(data) = (data as *const sys::esp_websocket_event_data_t).as_ref() {
                state.data(data);
            }
        }
        sys::esp_websocket_event_id_t_WEBSOCKET_EVENT_DISCONNECTED
        | sys::esp_websocket_event_id_t_WEBSOCKET_EVENT_CLOSED => {
            let _ = state.tx.send(Incoming::Closed);
        }
        _ => {}
    }
}

impl EventState {
    fn data(&mut self, data: &sys::esp_websocket_event_data_t) {
        let piece: &[u8] = if data.data_ptr.is_null() || data.data_len <= 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(data.data_ptr.cast(), data.data_len as usize) }
        };

        match data.op_code {
            OPCODE_TEXT | OPCODE_BINARY | OPCODE_CONTINUATION => {
                // A text or binary frame's first piece starts a message;
                // anything else carries one on.
                if data.op_code != OPCODE_CONTINUATION && data.payload_offset == 0 {
                    self.partial.clear();
                    self.partial_binary = data.op_code == OPCODE_BINARY;
                }
                self.partial.extend_from_slice(piece);

                let frame_done = data.payload_offset + data.data_len >= data.payload_len;
                if frame_done && data.fin {
                    let message = core::mem::take(&mut self.partial);
                    if self.partial_binary {
                        let _ = self.tx.send(Incoming::Frame(Frame::Binary(message)));
                    } else {
                        match String::from_utf8(message) {
                            Ok(text) => {
                                let _ = self.tx.send(Incoming::Frame(Frame::Text(text)));
                            }
                            Err(_) => log::warn!("dropped a text frame that was not UTF-8"),
                        }
                    }
                }
            }
            OPCODE_CLOSE => {
                let _ = self.tx.send(Incoming::Closed);
            }
            _ => {}
        }
    }
}

impl Transport for WebSocketTransport {
    fn send(&mut self, frame: &str) -> Result<(), Error> {
        let sent = unsafe {
            sys::esp_websocket_client_send_text(
                self.client,
                frame.as_ptr().cast(),
                frame.len() as c_int,
                self.send_timeout,
            )
        };
        if sent < 0 {
            Err(Error::Transport("websocket send failed".into()))
        } else {
            Ok(())
        }
    }

    fn send_binary(&mut self, frame: &[u8]) -> Result<(), Error> {
        let sent = unsafe {
            sys::esp_websocket_client_send_bin(
                self.client,
                frame.as_ptr().cast(),
                frame.len() as c_int,
                self.send_timeout,
            )
        };
        if sent < 0 {
            Err(Error::Transport("websocket send failed".into()))
        } else {
            Ok(())
        }
    }

    // Text only, for a caller that never asked for msgpack and so never gets
    // a binary frame.
    fn recv(&mut self) -> Result<Option<String>, Error> {
        match self.recv_frame()? {
            Some(Frame::Text(text)) => Ok(Some(text)),
            Some(Frame::Binary(bytes)) => {
                log::debug!("ignoring a {}-byte binary frame", bytes.len());
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn recv_frame(&mut self) -> Result<Option<Frame>, Error> {
        match self.incoming.recv_timeout(self.recv_timeout) {
            Ok(Incoming::Frame(frame)) => Ok(Some(frame)),

            // A close event from the client that is still connected belongs to
            // an earlier socket being torn down -- the events arrive on a task
            // of their own, so a previous client's last words can land here
            // after this one is up. Only the client's own view of itself
            // decides that the session is over.
            Ok(Incoming::Closed) => {
                if self.is_connected() {
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
