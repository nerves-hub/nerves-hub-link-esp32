//! A TLS session kept from one connection for the next.
//!
//! A full TLS 1.2 handshake with NervesCloud costs the device about 15 KB from
//! the server and three round trips, two of them waiting on public-key
//! arithmetic. A resumed one is a ServerHello and a Finished: 143 bytes and one
//! round trip. Over LTE-M that is the difference between a 6-12 second
//! handshake and a half-second one, on every connection.
//!
//! TLS 1.3 resumes from a ticket instead, which the server sends after the
//! handshake rather than in it. It is kept once a read on the connection has
//! taken it in, so a connection that closes before reading anything leaves
//! the session it was offered. A saved TLS 1.3 session is mostly that
//! ticket, so its size is the server's choice.
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
//! # TLS 1.3 tickets across a deep sleep
//!
//! mbedTLS dates a TLS 1.3 ticket with `mbedtls_ms_time()`, and before offering
//! one checks that its age -- now, less that date -- is neither negative nor
//! past the ticket's lifetime. On ESP-IDF that clock counts from boot, and a
//! wake from deep sleep is a boot. So after a sleep the saved date was taken in
//! a boot that has ended, the age comes out negative unless this wake connects
//! later after boot than the last one took its ticket, and mbedTLS drops the
//! ticket as expired: a full handshake, about 4.5 KB more from the server, on
//! most reports.
//!
//! So a saved TLS 1.3 session carries the ticket's date on the wall clock,
//! which ESP-IDF keeps through deep sleep, and is moved back onto mbedTLS's
//! clock, keeping its age, when it is offered (see [`rebase`]). Bytes saved
//! before this hold a date on the old clock, read as long ago: they are
//! offered as expired once, and the full handshake that follows leaves bytes
//! in the new form.
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
    /// mbedTLS's name for the last connection's protocol, e.g. "TLSv1.3".
    protocol: Option<String>,
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

    /// The last connection's protocol as mbedTLS names it ("TLSv1.2",
    /// "TLSv1.3"). For the log line that says how a connection went.
    #[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
    pub(crate) fn last_protocol(&self) -> Option<String> {
        self.lock().protocol.clone()
    }

    #[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
    pub(crate) fn negotiated(&self, protocol: String) {
        self.lock().protocol = Some(protocol);
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

    /// What a handshake was, before there is a session to keep from it: a
    /// TLS 1.3 ticket comes later, and [`store`](Self::store) keeps it then.
    #[cfg_attr(
        not(all(target_os = "espidf", esp_idf_mbedtls_ssl_proto_tls1_3)),
        allow(dead_code)
    )]
    pub(crate) fn record(&self, handshake: Handshake) {
        self.lock().last = Some(handshake);
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

/// A time `at` on one clock, moved to another clock: the same age before
/// `to_now` as it had before `from_now`.
///
/// For a TLS 1.3 ticket's date, between mbedTLS's clock, which restarts at
/// every boot, and the wall clock, which goes on through deep sleep; see the
/// module docs. An age that comes out negative -- the wall clock set back since
/// the ticket came -- is taken as zero. The server judges a ticket's age by
/// its own clock, so the most a ticket offered as new can cost is a refusal.
#[cfg_attr(
    not(all(
        target_os = "espidf",
        esp_idf_esp_tls_client_session_tickets,
        esp_idf_mbedtls_ssl_proto_tls1_3,
        esp_idf_mbedtls_have_time
    )),
    allow(dead_code)
)]
pub(crate) fn rebase(at: i64, from_now: i64, to_now: i64) -> i64 {
    let age = from_now.saturating_sub(at).max(0);
    to_now.saturating_sub(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-06 22:00:00 UTC, in milliseconds.
    const WALL: i64 = 1_791_324_000_000;

    // A ticket taken 41 s after one boot, saved, slept on for ten minutes, and
    // offered 15 s after the next boot: ten minutes old, not -26 s.
    #[test]
    fn a_ticket_keeps_its_age_across_a_sleep() {
        let saved = rebase(41_000, 45_000, WALL);
        assert_eq!(saved, WALL - 4_000, "taken 4 s before it was saved");

        let woken = WALL + 600_000 + 11_000;
        let offered = rebase(saved, woken, 15_000);
        assert_eq!(15_000 - offered, 615_000, "its age when offered");
    }

    #[test]
    fn a_wall_clock_set_back_gives_a_new_ticket_not_a_negative_age() {
        let saved = rebase(41_000, 45_000, WALL);
        let offered = rebase(saved, WALL - 3_600_000, 15_000);
        assert_eq!(offered, 15_000, "age zero");
    }

    // Saved by a version that kept mbedTLS's own clock: read as a wall-clock
    // date it is decades old, so mbedTLS takes it as expired and the
    // handshake is a full one, as it was before.
    #[test]
    fn bytes_from_before_read_as_long_expired() {
        let offered = rebase(41_000, WALL, 15_000);
        assert!(15_000 - offered > 7 * 24 * 3_600 * 1_000, "past any ticket lifetime");
    }

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

    // A TLS 1.3 handshake is known before its ticket arrives, and until then
    // the session it was offered is the one to offer again.
    #[test]
    fn a_handshake_recorded_before_its_ticket_keeps_the_offered_session() {
        let session = TlsSession::restore(b"offered");
        session.record(Handshake::Resumed);

        assert_eq!(session.last_handshake(), Some(Handshake::Resumed));
        assert_eq!(session.saved(), Some(b"offered".to_vec()));
    }

    #[test]
    fn the_negotiated_protocol_is_kept_for_the_log() {
        let session = TlsSession::new();
        assert_eq!(session.last_protocol(), None);

        session.negotiated("TLSv1.3".into());
        assert_eq!(session.last_protocol().as_deref(), Some("TLSv1.3"));
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
