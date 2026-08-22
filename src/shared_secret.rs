//! NervesHub shared-secret authentication.
//!
//! NervesHub accepts either a client certificate or an HMAC shared secret.
//! Which an organization uses is its own decision, so the agent supports both.
//!
//! The signature is a `Plug.Crypto` token, so a device has to reproduce what
//! `Plug.Crypto.sign/4` produces on the server:
//!
//! ```text
//! salt    = "NH1:device-socket:shared-secret:connect\n\nx-nh-alg=..\nx-nh-key=..\nx-nh-time=..\n"
//! key     = PBKDF2-HMAC-SHA256(secret, salt, iterations, key_length)
//! payload = :erlang.term_to_binary({identifier, signed_at_ms, max_age})
//! token   = "SFMyNTY." + b64url(payload) + "." + b64url(HMAC-SHA256(key, "SFMyNTY." + b64url(payload)))
//! ```
//!
//! # The payload
//!
//! That `term_to_binary` is Erlang's external term format, which this writes by
//! hand. The shape is fixed — a three-element tuple of a binary and two
//! integers — so there is no need for a general encoder, but the details matter:
//! a millisecond timestamp is too large for `INTEGER_EXT` and has to be written
//! as `SMALL_BIG_EXT`, whose digits are little-endian while everything else in
//! the format is big-endian.
//!
//! Getting that wrong produces a token the server rejects as `unauthorized`,
//! with nothing to debug from. The tests check against vectors produced by an
//! implementation that a running NervesHub accepted.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The `Plug.Crypto` protected header for HMAC-SHA256, base64url of `{"alg":"HS256"}`.
const PROTECTED: &str = "SFMyNTY";

const DEFAULT_ITERATIONS: u32 = 1000;
const DEFAULT_KEY_LENGTH: usize = 32;
const DEFAULT_MAX_AGE_SECS: i64 = 86_400;

/// A shared secret issued by NervesHub, for a product or a single device.
#[derive(Clone, Debug)]
pub struct SharedSecret {
    /// The key, `nhp_…` for a product secret or `nhd_…` for a device one.
    pub key: String,
    pub secret: String,
}

impl SharedSecret {
    pub fn new(key: impl Into<String>, secret: impl Into<String>) -> Self {
        Self { key: key.into(), secret: secret.into() }
    }

    /// The headers to send on the WebSocket handshake.
    ///
    /// `signed_at` is seconds since the epoch. The server rejects a signature
    /// older than its `max_age` — 90 seconds by default — so the device clock
    /// has to be roughly right. SNTP before connecting, or the first join fails
    /// in a way that looks like a bad secret.
    pub fn headers(&self, identifier: &str, signed_at: i64) -> Vec<(String, String)> {
        let alg = format!("SHA256-{}-{}", DEFAULT_ITERATIONS, DEFAULT_KEY_LENGTH);
        let salt = salt(&alg, &self.key, signed_at);

        let mut derived = [0u8; DEFAULT_KEY_LENGTH];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            self.secret.as_bytes(),
            salt.as_bytes(),
            DEFAULT_ITERATIONS,
            &mut derived,
        );

        // Plug.Crypto records the signing time in milliseconds; the header
        // carries seconds. Both come from the same value, and the salt binds
        // the two together.
        let payload = payload(identifier, signed_at * 1000, DEFAULT_MAX_AGE_SECS);

        vec![
            ("x-nh-alg".into(), format!("NH1-HMAC-{alg}")),
            ("x-nh-key".into(), self.key.clone()),
            ("x-nh-time".into(), signed_at.to_string()),
            ("x-nh-signature".into(), token(&derived, &payload)),
        ]
    }
}

/// The salt the signing key is derived from.
///
/// It repeats the headers, which is what binds the signature to them: changing
/// `x-nh-time` in flight changes the salt, so the key no longer derives.
fn salt(alg: &str, key: &str, signed_at: i64) -> String {
    format!(
        "NH1:device-socket:shared-secret:connect\n\nx-nh-alg=NH1-HMAC-{alg}\nx-nh-key={key}\nx-nh-time={signed_at}\n"
    )
}

/// Erlang external term format for `{identifier, signed_at_ms, max_age}`.
fn payload(identifier: &str, signed_at_ms: i64, max_age: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(131); // VERSION_MAGIC
    out.push(104); // SMALL_TUPLE_EXT
    out.push(3); // arity

    // BINARY_EXT: tag, 32 bit big-endian length, bytes.
    out.push(109);
    out.extend_from_slice(&(identifier.len() as u32).to_be_bytes());
    out.extend_from_slice(identifier.as_bytes());

    encode_integer(&mut out, signed_at_ms);
    encode_integer(&mut out, max_age);

    out
}

/// Matching what `term_to_binary/1` chooses, so a payload built here is
/// byte-identical to one built on the server.
fn encode_integer(out: &mut Vec<u8>, value: i64) {
    if (0..=255).contains(&value) {
        out.push(97); // SMALL_INTEGER_EXT
        out.push(value as u8);
    } else if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        out.push(98); // INTEGER_EXT, 32 bit big-endian, signed
        out.extend_from_slice(&(value as i32).to_be_bytes());
    } else {
        // SMALL_BIG_EXT: tag, byte count, sign, then little-endian digits.
        let mut digits = Vec::with_capacity(8);
        let mut remaining = value.unsigned_abs();
        while remaining > 0 {
            digits.push((remaining & 0xFF) as u8);
            remaining >>= 8;
        }
        out.push(110);
        out.push(digits.len() as u8);
        out.push(u8::from(value < 0));
        out.extend_from_slice(&digits);
    }
}

/// Sign a payload the way `Plug.Crypto.MessageVerifier` does.
fn token(signing_key: &[u8], payload: &[u8]) -> String {
    let plain_text = format!("{PROTECTED}.{}", base64url(payload));

    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC accepts any key length");
    mac.update(plain_text.as_bytes());
    let signature = mac.finalize().into_bytes();

    format!("{plain_text}.{}", base64url(&signature))
}

/// URL-safe base64 without padding, which is what `Plug.Crypto` emits.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);

        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Seconds since the epoch, for signing.
///
/// The server rejects a signature outside its `max_age` window, so a device
/// with an unset clock cannot authenticate at all. On ESP-IDF the clock reads
/// 1970 until SNTP has run, which fails to join in a way that looks like a bad
/// secret rather than a clock problem.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by the Erlang implementation in nerves_hub_link_atomvm_esp32,
    // whose headers a running NervesHub accepted. Checking against those rather
    // than against this implementation's own output is the point: an encoder
    // tested only against itself agrees with itself and with nothing else.
    const IDENTIFIER: &str = "my-device";
    const KEY: &str = "nhp_abc123";
    const SECRET: &str = "s3cret-value";
    const SIGNED_AT: i64 = 1_787_120_842;

    const SALT_HEX: &str = "4e48313a6465766963652d736f636b65743a7368617265642d7365637265743a636f6e6e6563740a0a782d6e682d616c673d4e48312d484d41432d5348413235362d313030302d33320a782d6e682d6b65793d6e68705f6162633132330a782d6e682d74696d653d313738373132303834320a";
    const DERIVED_HEX: &str = "7b3df9c32780d83f23b38b04128a43370094f282733587d1605c68fa8c6aea2e";
    const PAYLOAD_HEX: &str = "8368036d000000096d792d6465766963656e060010f5b318a0016200015180";
    const TOKEN: &str = "SFMyNTY.g2gDbQAAAAlteS1kZXZpY2VuBgAQ9bMYoAFiAAFRgA.9qXfZC7_ENQyT5_LZc6LsXd_uEoUB2V-IZDqcmNd7gQ";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn salt_matches_the_server() {
        assert_eq!(hex(salt("SHA256-1000-32", KEY, SIGNED_AT).as_bytes()), SALT_HEX);
    }

    #[test]
    fn key_derivation_matches() {
        let salt = salt("SHA256-1000-32", KEY, SIGNED_AT);
        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(SECRET.as_bytes(), salt.as_bytes(), 1000, &mut derived);
        assert_eq!(hex(&derived), DERIVED_HEX);
    }

    #[test]
    fn payload_matches_term_to_binary() {
        assert_eq!(hex(&payload(IDENTIFIER, SIGNED_AT * 1000, 86_400)), PAYLOAD_HEX);
    }

    #[test]
    fn token_matches() {
        let salt = salt("SHA256-1000-32", KEY, SIGNED_AT);
        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(SECRET.as_bytes(), salt.as_bytes(), 1000, &mut derived);
        assert_eq!(token(&derived, &payload(IDENTIFIER, SIGNED_AT * 1000, 86_400)), TOKEN);
    }

    #[test]
    fn headers_are_complete_and_named_correctly() {
        let headers = SharedSecret::new(KEY, SECRET).headers(IDENTIFIER, SIGNED_AT);
        let get = |name: &str| {
            headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap()
        };

        assert_eq!(get("x-nh-alg"), "NH1-HMAC-SHA256-1000-32");
        assert_eq!(get("x-nh-key"), KEY);
        assert_eq!(get("x-nh-time"), SIGNED_AT.to_string());
        assert_eq!(get("x-nh-signature"), TOKEN);
        assert_eq!(headers.len(), 4);
    }

    // The boundary the millisecond timestamp sits above: below it Erlang writes
    // INTEGER_EXT, above it SMALL_BIG_EXT with little-endian digits.
    #[test]
    fn integer_encoding_covers_each_form() {
        let mut out = Vec::new();
        encode_integer(&mut out, 0);
        assert_eq!(out, vec![97, 0]);

        out.clear();
        encode_integer(&mut out, 255);
        assert_eq!(out, vec![97, 255]);

        out.clear();
        encode_integer(&mut out, 256);
        assert_eq!(out, vec![98, 0, 0, 1, 0]);

        out.clear();
        encode_integer(&mut out, 2_147_483_647);
        assert_eq!(out, vec![98, 127, 255, 255, 255]);

        out.clear();
        encode_integer(&mut out, 4_294_967_296);
        assert_eq!(out, vec![110, 5, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn base64url_is_unpadded_and_url_safe() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert!(!base64url(&[0xff; 10]).contains('='));
    }
}
