//! A TLS session kept from one connection for the next.
//!
//! A full TLS 1.2 handshake with NervesCloud costs the device about 15 KB from
//! the server and three round trips, two of them waiting on public-key
//! arithmetic. A resumed one is a ServerHello and a Finished: 143 bytes and one
//! round trip. Over LTE-M that is the difference between a 6-12 second
//! handshake and a half-second one, on every connection.
//!
//! Within one boot this is automatic: the agent reconnects with the same
//! [`Config`](crate::Config), and the session the last handshake left here is
//! offered on the next. A device that deep-sleeps between reports loses its
//! RAM, so it keeps the session itself, in RTC memory, and hands it back:
//!
//! ```no_run
//! # use nerves_hub_link_esp32::{Config, Credentials, TlsSession};
//! # fn rtc() -> Vec<u8> { vec![] }
//! # fn save_to_rtc(_: &[u8]) {}
//! # let mut config = Config::new("devices.nervescloud.com", Credentials::shared_secret("id", "key", "secret"));
//! config.tls_session = TlsSession::restore(&rtc());
//! let session = config.tls_session.clone(); // the same slot, not a copy
//!
//! // ... run the agent ...
//!
//! if let Some(saved) = session.saved() {
//!     save_to_rtc(&saved);
//! }
//! ```
//!
//! # It is a secret
//!
//! The saved bytes hold the session's master secret: anyone with them can
//! read any traffic recorded under that session. RTC memory is the right place,
//! since it is gone at power-off and never leaves the chip; flash is not, and
//! neither is a log line, which is why `Debug` prints only the length.
//!
//! # When it isn't used
//!
//! Resumption is the server's choice. A server that has forgotten the session
//! -- restarted, evicted it, or is a different node behind a load balancer --
//! answers with a full handshake, which costs no more than not offering one,
//! and the new session replaces the old. Offering one needs
//! `CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS=y`; without it every handshake is
//! full and nothing is ever saved.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// What the last handshake through a [`TlsSession`] was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    /// The server took the offered session.
    Resumed,
    /// A full handshake: nothing was offered, or the server declined it.
    Full,
}

/// A slot for the TLS session, shared between the [`Config`](crate::Config)
/// that offers it and the application that keeps it.
///
/// Cloning shares the slot rather than copying the session.
#[derive(Clone, Default)]
pub struct TlsSession {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    saved: Option<Vec<u8>>,
    last: Option<Handshake>,
}

impl TlsSession {
    /// An empty slot: the first handshake is a full one.
    pub fn new() -> Self {
        Self::default()
    }

    /// A slot holding a session saved by an earlier [`saved`](Self::saved).
    ///
    /// Empty bytes are no session. Bytes that aren't one -- a different
    /// mbedTLS configuration wrote them, or RTC memory came up as noise -- are
    /// found out at the next handshake, which then is a full one.
    pub fn restore(saved: &[u8]) -> Self {
        let session = Self::new();
        if !saved.is_empty() {
            session.lock().saved = Some(saved.to_vec());
        }
        session
    }

    /// The session to keep for the next connection, if a handshake has left
    /// one.
    pub fn saved(&self) -> Option<Vec<u8>> {
        self.lock().saved.clone()
    }

    /// Whether the last handshake resumed the offered session. `None` before
    /// one has completed.
    pub fn last_handshake(&self) -> Option<Handshake> {
        self.lock().last
    }

    /// Drop the session, so the next handshake is a full one.
    pub fn forget(&self) {
        self.lock().saved = None;
    }

    // Only the device's TLS transport stores one.
    #[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
    pub(crate) fn store(&self, session: Vec<u8>, handshake: Handshake) {
        let mut inner = self.lock();
        inner.saved = Some(session);
        inner.last = Some(handshake);
    }

    // Nothing that holds the lock can panic, but a poisoned slot is still just
    // a session: the worst a half-written one does is fail to resume.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        f.debug_struct("TlsSession")
            .field("saved_bytes", &inner.saved.as_ref().map(Vec::len))
            .field("last", &inner.last)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restored_session_is_offered_back_unchanged() {
        assert_eq!(TlsSession::restore(b"session").saved(), Some(b"session".to_vec()));
    }

    #[test]
    fn empty_bytes_are_no_session() {
        assert_eq!(TlsSession::restore(&[]).saved(), None);
    }

    // The application keeps a clone and reads it after the agent, which owns
    // the config's copy, has finished with it.
    #[test]
    fn a_clone_sees_what_a_handshake_stores() {
        let config = TlsSession::new();
        let app = config.clone();

        config.store(b"new".to_vec(), Handshake::Full);

        assert_eq!(app.saved(), Some(b"new".to_vec()));
        assert_eq!(app.last_handshake(), Some(Handshake::Full));
    }

    #[test]
    fn forgetting_leaves_nothing_to_offer() {
        let session = TlsSession::restore(b"session");
        session.forget();
        assert_eq!(session.saved(), None);
    }

    // Config derives Debug, and a config ends up in logs.
    #[test]
    fn debug_shows_the_length_and_not_the_secret() {
        let shown = format!("{:?}", TlsSession::restore(b"master-secret"));
        assert!(shown.contains("13"), "{shown}");
        assert!(!shown.contains("master"), "{shown}");
    }
}
