//! Image checksums.
//!
//! NervesHub computes `firmwares.checksum` as an uppercase-hex SHA-256 of the
//! whole file and sends it in the update payload, so the device can verify a
//! download before it is ever booted.

use sha2::{Digest, Sha256 as Inner};

#[derive(Debug, Default)]
pub struct Sha256 {
    inner: Inner,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
    }

    /// Uppercase hex, matching `NervesHub.Firmwares.firmware_checksum/1`
    /// (`Base.encode16/1` defaults to upper case).
    pub fn finalize_hex_upper(self) -> String {
        self.inner
            .finalize()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }
}

/// Compare a computed checksum against an advertised one.
///
/// Case-insensitive: the server sends upper case, but a value copied out of
/// another tool may not be, and a case mismatch is never a real corruption.
pub fn matches(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_in_uppercase_hex() {
        let mut hasher = Sha256::new();
        hasher.update(b"");

        // Known SHA-256 of the empty string.
        assert_eq!(
            hasher.finalize_hex_upper(),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut streamed = Sha256::new();
        streamed.update(b"nerves");
        streamed.update(b"hub");

        let mut one_shot = Sha256::new();
        one_shot.update(b"nerveshub");

        assert_eq!(streamed.finalize_hex_upper(), one_shot.finalize_hex_upper());
    }

    #[test]
    fn comparison_ignores_case() {
        assert!(matches("DEADBEEF", "deadbeef"));
        assert!(!matches("DEADBEEF", "DEADBEEE"));
    }
}
