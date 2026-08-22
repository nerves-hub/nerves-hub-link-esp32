//! Errors.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The socket could not be opened, or dropped.
    Transport(String),
    /// A frame could not be encoded or decoded.
    Protocol(String),
    /// The server refused the join.
    JoinRefused(String),
    /// Running firmware metadata could not be read.
    Metadata(&'static str),
    /// The device's certificate could not be loaded.
    Identity(String),
    /// Downloading the image failed.
    Download(String),
    /// Writing to the inactive OTA slot, or activating it, failed.
    Ota(String),
    /// The downloaded image did not match the checksum NervesHub advertised.
    ChecksumMismatch { expected: String, actual: String },
    /// A console command failed. Printed at the terminal that asked.
    Console(String),
}

/// So a command can write with `write!` and `?` like anywhere else.
///
/// Writing to a console `Output` cannot actually fail -- it is bounded and
/// drops the overflow -- but `write!` returns a `Result` and a command author
/// should not have to care which kind.
impl From<core::fmt::Error> for Error {
    fn from(_: core::fmt::Error) -> Self {
        Error::Console("could not format output".into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(msg) => write!(f, "transport error: {msg}"),
            Error::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Error::JoinRefused(msg) => write!(f, "join refused: {msg}"),
            Error::Metadata(msg) => write!(f, "could not read firmware metadata: {msg}"),
            Error::Identity(msg) => write!(f, "device identity unavailable: {msg}"),
            Error::Download(msg) => write!(f, "download failed: {msg}"),
            Error::Ota(msg) => write!(f, "ota failed: {msg}"),
            Error::ChecksumMismatch { expected, actual } => {
                write!(f, "checksum mismatch: expected {expected}, got {actual}")
            }
            Error::Console(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Protocol(err.to_string())
    }
}

/// The reason string sent to NervesHub with a `failed` status.
///
/// It surfaces in the device's audit log and in the deployment's failure
/// counting, so it should say what went wrong rather than that something did.
impl Error {
    pub fn status_reason(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mismatch_names_both_values() {
        let err = Error::ChecksumMismatch {
            expected: "AAAA".into(),
            actual: "BBBB".into(),
        };

        assert_eq!(
            err.status_reason(),
            "checksum mismatch: expected AAAA, got BBBB"
        );
    }

    #[test]
    fn json_errors_become_protocol_errors() {
        let err: Error = serde_json::from_str::<u32>("not json").unwrap_err().into();
        assert!(matches!(err, Error::Protocol(_)));
    }
}
