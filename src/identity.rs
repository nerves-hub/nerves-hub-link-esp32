//! Loading the device's client certificate from NVS.
//!
//! **Not yet built or run.** The `esp-idf-svc` NVS API needs checking against
//! the version you build with.
//!
//! # Why not in the image
//!
//! A certificate compiled into the firmware is shared by every device that
//! firmware is flashed to, which means one identity for the whole fleet and no
//! way to revoke a single device. NervesHub identifies a device *by* its
//! certificate, so a fleet-wide identity is a fleet-wide account.
//!
//! Provision per-device into the `certs` NVS partition at manufacture instead
//! (see `partitions.csv`), and enable NVS encryption in production — otherwise
//! the private key is readable by anyone who can dump flash.

#[cfg(target_os = "espidf")]
use esp_idf_svc::nvs::{EspCustomNvsPartition, EspNvs, NvsCustom};

#[cfg(target_os = "espidf")]
use crate::config::Credentials;
#[cfg(target_os = "espidf")]
use crate::error::Error;

// ---------------------------------------------------------------------------
// The NVS contract.
//
// Deliberately outside the `espidf` gate: whatever builds the NVS image at
// manufacture has to agree with what the device reads, and a drift between the
// two shows up as "'device.crt' is not provisioned" or an opaque TLS handshake
// failure rather than as anything pointing at a renamed key. Host tooling
// should reference these rather than repeat the strings.
// ---------------------------------------------------------------------------

/// The NVS partition holding device identity. Must match `partitions.csv`.
pub const PARTITION: &str = "certs";

/// The namespace within that partition.
pub const NAMESPACE: &str = "nerves_hub";

pub const CERTIFICATE_KEY: &str = "device.crt";
pub const PRIVATE_KEY_KEY: &str = "device.key";

/// Largest blob we will read. A PEM certificate and key are a few KB; this is
/// generous without letting a corrupt length allocate unbounded memory.
#[cfg(target_os = "espidf")]
const MAX_BLOB: usize = 8 * 1024;

/// Read the device's certificate and private key.
#[cfg(target_os = "espidf")]
pub fn load() -> Result<Credentials, Error> {
    let partition = EspCustomNvsPartition::take(PARTITION)
        .map_err(|e| Error::Identity(format!("could not open the '{PARTITION}' partition: {e}")))?;

    let nvs = EspNvs::new(partition, NAMESPACE, false)
        .map_err(|e| Error::Identity(format!("could not open namespace '{NAMESPACE}': {e}")))?;

    // `client_certificate` owns the NUL-termination and leaking that mbedTLS
    // needs — see `Credentials` — so this only has to get the bytes out.
    Credentials::client_certificate(
        read_blob(&nvs, CERTIFICATE_KEY)?,
        read_blob(&nvs, PRIVATE_KEY_KEY)?,
    )
}

#[cfg(target_os = "espidf")]
fn read_blob(nvs: &EspNvs<NvsCustom>, key: &str) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0u8; MAX_BLOB];

    let value = nvs
        .get_blob(key, &mut buffer)
        .map_err(|e| Error::Identity(format!("could not read '{key}': {e}")))?
        .ok_or_else(|| Error::Identity(format!("'{key}' is not provisioned")))?;

    let len = value.len();

    if len == 0 {
        return Err(Error::Identity(format!("'{key}' is empty")));
    }

    buffer.truncate(len);

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are a contract with the tool that writes the NVS image. If one side
    // is renamed without the other, provisioning fails with a message that does
    // not mention the rename.
    #[test]
    fn the_nvs_contract_is_stable() {
        assert_eq!(PARTITION, "certs");
        assert_eq!(NAMESPACE, "nerves_hub");
        assert_eq!(CERTIFICATE_KEY, "device.crt");
        assert_eq!(PRIVATE_KEY_KEY, "device.key");
    }
}
