//! What arrives on the websocket, put back together for the run loop.
//!
//! ESP-IDF's websocket client hands its event handler a frame a buffer-full at
//! a time, and a message can be fragmented across frames besides. This puts
//! the pieces back into whole messages and decides what the run loop is told.
//! It is plain Rust, apart from the transport that feeds it, so it runs under
//! `cargo test`: the transport is only the glue between the client's events
//! and this.

// Only the device's transport uses this; the host builds it for the tests.
#![cfg_attr(not(target_os = "espidf"), allow(dead_code))]

use crate::message::Frame;

/// What the transport hands to the run loop.
///
/// A close has to travel the same channel as the frames, in order with them:
/// the run loop learns the socket is gone at the point it would have read the
/// next frame, rather than by a flag it might check at the wrong moment.
#[derive(Debug, PartialEq)]
pub(crate) enum Incoming {
    Frame(Frame),
    /// The client's `n`th report of a closed socket, counting from 1. See
    /// [`Inbound::ends_session`].
    Closed(u32),
}

pub(crate) const OPCODE_CONTINUATION: u8 = 0x0;
pub(crate) const OPCODE_TEXT: u8 = 0x1;
pub(crate) const OPCODE_BINARY: u8 = 0x2;
pub(crate) const OPCODE_CLOSE: u8 = 0x8;

/// One data event from the client: a piece of a frame.
pub(crate) struct Piece<'a> {
    pub(crate) opcode: u8,
    /// Whether the frame is the last of its message.
    pub(crate) fin: bool,
    /// Where in the frame's payload this piece starts.
    pub(crate) offset: usize,
    /// The length of the whole of the frame's payload.
    pub(crate) payload_len: usize,
    pub(crate) bytes: &'a [u8],
}

/// Messages on their way from the client's events to the run loop.
#[derive(Debug, Default)]
pub(crate) struct Inbound {
    /// A message arriving in pieces: one per buffer-full of a frame, and one
    /// frame per fragment of a fragmented message.
    partial: Vec<u8>,
    /// Whether `partial` is binary. A continuation carries no kind of its
    /// own; it is whatever the frame that started the message was.
    binary: bool,
    /// Closes reported so far.
    closes: u32,
    /// How many of them came before the client first connected.
    closes_before_connecting: Option<u32>,
}

impl Inbound {
    /// The client has connected.
    pub(crate) fn connected(&mut self) {
        self.closes_before_connecting.get_or_insert(self.closes);
    }

    /// The client has reported the socket closed.
    pub(crate) fn closed(&mut self) -> Incoming {
        self.closes += 1;
        Incoming::Closed(self.closes)
    }

    /// Whether the `n`th close ends the session.
    ///
    /// Any close after the client first connected does, including one the
    /// client has since recovered from by connecting again on its own, ten
    /// seconds later. A socket it brings back has no Phoenix channel on it, so
    /// a session that stayed would be deaf while NervesHub showed the device
    /// online, and nothing would notice: Phoenix answers heartbeats on a socket
    /// whether or not anything has joined. The run loop doesn't read while a
    /// download runs, so a reconnect can easily come before the close is read.
    ///
    /// A close before the first connection is an attempt that failed while
    /// the transport was still waiting to connect, which the client retried
    /// by itself.
    pub(crate) fn ends_session(&self, n: u32) -> bool {
        self.closes_before_connecting.is_some_and(|before| n > before)
    }

    /// Take in one piece, and say what the run loop should hear of it, if
    /// anything.
    ///
    /// Text and binary frames, and the end of the socket, are the run loop's
    /// business; pings and pongs are the client's own. Which kind of frame
    /// arrives is the serializer's choice: text for JSON, binary for msgpack.
    pub(crate) fn piece(&mut self, piece: Piece<'_>) -> Option<Incoming> {
        match piece.opcode {
            OPCODE_TEXT | OPCODE_BINARY | OPCODE_CONTINUATION => {
                // A text or binary frame's first piece starts a message;
                // anything else carries one on.
                if piece.opcode != OPCODE_CONTINUATION && piece.offset == 0 {
                    self.partial.clear();
                    self.binary = piece.opcode == OPCODE_BINARY;
                }
                self.partial.extend_from_slice(piece.bytes);

                let frame_done = piece.offset + piece.bytes.len() >= piece.payload_len;
                if !(frame_done && piece.fin) {
                    return None;
                }

                let message = core::mem::take(&mut self.partial);
                if self.binary {
                    return Some(Incoming::Frame(Frame::Binary(message)));
                }

                match String::from_utf8(message) {
                    Ok(text) => Some(Incoming::Frame(Frame::Text(text))),
                    Err(_) => {
                        log::warn!("dropped a text frame that was not UTF-8");
                        None
                    }
                }
            }
            OPCODE_CLOSE => Some(self.closed()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PING: u8 = 0x9;

    /// The whole of a frame, in one piece.
    fn frame(opcode: u8, fin: bool, bytes: &[u8]) -> Piece<'_> {
        Piece { opcode, fin, offset: 0, payload_len: bytes.len(), bytes }
    }

    /// The piece of a `payload_len`-byte frame starting at `offset`.
    fn piece_of(opcode: u8, offset: usize, payload_len: usize, bytes: &[u8]) -> Piece<'_> {
        Piece { opcode, fin: true, offset, payload_len, bytes }
    }

    fn text(text: &str) -> Option<Incoming> {
        Some(Incoming::Frame(Frame::Text(text.into())))
    }

    #[test]
    fn a_message_in_one_piece_comes_out_whole() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(frame(OPCODE_TEXT, true, b"[1]")), text("[1]"));
    }

    // msgpack travels in binary frames, and has to reach the run loop as one.
    #[test]
    fn a_binary_message_stays_binary() {
        let mut inbound = Inbound::default();

        assert_eq!(
            inbound.piece(frame(OPCODE_BINARY, true, &[0x95, 0xc0])),
            Some(Incoming::Frame(Frame::Binary(vec![0x95, 0xc0])))
        );
    }

    // A frame bigger than the client's buffer arrives a buffer-full at a time.
    #[test]
    fn a_frame_bigger_than_the_buffer_is_put_back_together() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(piece_of(OPCODE_TEXT, 0, 10, b"[\"abc")), None);
        assert_eq!(inbound.piece(piece_of(OPCODE_TEXT, 5, 10, b"def\"]")), text("[\"abcdef\"]"));
    }

    #[test]
    fn a_fragmented_message_keeps_the_kind_of_its_first_frame() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(frame(OPCODE_BINARY, false, &[1])), None);
        assert_eq!(inbound.piece(frame(OPCODE_CONTINUATION, false, &[2])), None);
        assert_eq!(
            inbound.piece(frame(OPCODE_CONTINUATION, true, &[3])),
            Some(Incoming::Frame(Frame::Binary(vec![1, 2, 3])))
        );
    }

    // A message cut off by a new one is dropped, not glued onto the front of it.
    #[test]
    fn a_new_message_starts_clean() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(piece_of(OPCODE_TEXT, 0, 100, b"[\"cut")), None);
        assert_eq!(inbound.piece(frame(OPCODE_TEXT, true, b"[2]")), text("[2]"));
    }

    #[test]
    fn text_that_is_not_utf8_is_dropped() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(frame(OPCODE_TEXT, true, &[0xff, 0xfe])), None);
    }

    // The server's close frame and the client's own report of the socket going
    // are both closes, numbered as they come.
    #[test]
    fn closes_are_numbered_as_they_come() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(frame(OPCODE_CLOSE, true, &[0x03, 0xe8])), Some(Incoming::Closed(1)));
        assert_eq!(inbound.closed(), Incoming::Closed(2));
    }

    #[test]
    fn a_close_after_connecting_ends_the_session() {
        let mut inbound = Inbound::default();
        inbound.connected();

        let Incoming::Closed(n) = inbound.closed() else { panic!("a close") };
        assert!(inbound.ends_session(n));
    }

    // The case this exists for. The client reconnects ten seconds after the
    // socket goes, by itself, and a run loop busy with a download reads the
    // close after that: the client is connected again, but not to anything
    // the session has joined.
    #[test]
    fn a_close_ends_the_session_even_once_the_client_has_reconnected() {
        let mut inbound = Inbound::default();
        inbound.connected();

        let Incoming::Closed(n) = inbound.closed() else { panic!("a close") };
        inbound.connected();

        assert!(inbound.ends_session(n));
    }

    // An attempt that failed while the transport waited to connect, which
    // the client then retried and got through.
    #[test]
    fn a_close_from_before_the_first_connection_is_passed_over() {
        let mut inbound = Inbound::default();

        let Incoming::Closed(n) = inbound.closed() else { panic!("a close") };
        assert!(!inbound.ends_session(n), "read before the connection was reported");

        inbound.connected();
        assert!(!inbound.ends_session(n), "read after");
    }

    // The client answers pings itself.
    #[test]
    fn a_ping_is_not_the_run_loops_business() {
        let mut inbound = Inbound::default();

        assert_eq!(inbound.piece(frame(PING, true, b"")), None);
    }
}
