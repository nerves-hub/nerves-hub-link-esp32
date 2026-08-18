//! What the device tells NervesHub about the firmware it is running.
//!
//! NervesHub reads device-reported metadata through the update tool that
//! recognises it (`NervesHub.Firmwares.UpdateTool.for_device_metadata/2`). We
//! declare `update_tool: "esp-idf"` so the choice is explicit rather than
//! sniffed.
//!
//! # No UUID
//!
//! We deliberately do not send a firmware UUID. NervesHub derives it from
//! `app_elf_sha256` using the same rule it applied when the image was uploaded,
//! so there is exactly one implementation of that convention and a device agent
//! cannot drift from it. We send the hash; the server does the rest.

use serde_json::{json, Value};

/// The fields NervesHub reads, all sourced from the running app's
/// `esp_app_desc_t` and image header.
#[derive(Debug, Clone, PartialEq)]
pub struct FirmwareMetadata {
    /// `PROJECT_NAME` — must match the NervesHub product name.
    pub project_name: String,
    /// `PROJECT_VER` — NervesHub normalises this to SemVer and rejects what it
    /// cannot read, so set it explicitly in CMakeLists.txt.
    pub version: String,
    /// Lowercase hex of `esp_app_desc_t.app_elf_sha256`.
    pub app_elf_sha256: String,
    /// The ESP-IDF version the image was built against.
    pub idf_ver: String,
    /// `esp_image_header_t.chip_id`.
    ///
    /// Read from the image header rather than from `esp_chip_info()`: the
    /// runtime's `esp_chip_model_t` and the image's `esp_chip_id_t` are
    /// different enumerations that happen to agree for most parts but not for
    /// the original ESP32 (model 1, chip id 0).
    pub chip_id: u16,
}

impl FirmwareMetadata {
    /// The `phx_join` payload.
    ///
    /// `currently_downloading_uuid` lets NervesHub resume rather than restart an
    /// update that was interrupted by a reboot; `None` omits it.
    pub fn join_params(
        &self,
        device_api_version: &str,
        currently_downloading_uuid: Option<&str>,
    ) -> Value {
        let mut params = json!({
            "device_api_version": device_api_version,
            "update_tool": "esp-idf",
            "esp_idf_project_name": self.project_name,
            "esp_idf_version": self.version,
            "esp_idf_app_elf_sha256": self.app_elf_sha256,
            "esp_idf_ver": self.idf_ver,
            "esp_idf_chip_id": self.chip_id,
        });

        if let Some(uuid) = currently_downloading_uuid {
            params["currently_downloading_uuid"] = json!(uuid);
        }

        params
    }
}

/// Reads the running application's metadata.
///
/// `esp_app_get_description()` supplies everything except `chip_id`, which
/// lives in the image header at offset 12 of the running partition.
#[cfg(target_os = "espidf")]
pub fn running_firmware() -> Result<FirmwareMetadata, crate::Error> {
    use esp_idf_svc::sys;

    // SAFETY: both calls return pointers to static/flash-mapped data owned by
    // the IDF, valid for the lifetime of the program.
    unsafe {
        let desc = sys::esp_app_get_description();
        if desc.is_null() {
            return Err(crate::Error::Metadata("no app description"));
        }
        let desc = &*desc;

        Ok(FirmwareMetadata {
            project_name: cstr(&desc.project_name),
            version: cstr(&desc.version),
            app_elf_sha256: hex(&desc.app_elf_sha256),
            idf_ver: cstr(&desc.idf_ver),
            chip_id: running_chip_id()?,
        })
    }
}

/// `esp_image_header_t.chip_id` — a little-endian u16 at offset 12 of the
/// running partition. Mirrors what NervesHub parses out of the uploaded image,
/// so the device and the server always agree on the platform.
#[cfg(target_os = "espidf")]
fn running_chip_id() -> Result<u16, crate::Error> {
    use esp_idf_svc::sys;

    unsafe {
        let partition = sys::esp_ota_get_running_partition();
        if partition.is_null() {
            return Err(crate::Error::Metadata("no running partition"));
        }

        let mut header = [0u8; 24];
        let err = sys::esp_partition_read(
            partition,
            0,
            header.as_mut_ptr() as *mut core::ffi::c_void,
            header.len(),
        );

        if err != sys::ESP_OK {
            return Err(crate::Error::Metadata("could not read image header"));
        }

        Ok(u16::from_le_bytes([header[12], header[13]]))
    }
}

#[cfg(target_os = "espidf")]
fn cstr(bytes: &[core::ffi::c_char]) -> String {
    let bytes: Vec<u8> = bytes
        .iter()
        .map(|c| *c as u8)
        .take_while(|c| *c != 0)
        .collect();

    String::from_utf8_lossy(&bytes).trim().to_string()
}

#[cfg(target_os = "espidf")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> FirmwareMetadata {
        FirmwareMetadata {
            project_name: "my_app".into(),
            version: "1.2.3".into(),
            app_elf_sha256: "ab".repeat(32),
            idf_ver: "v5.2.1".into(),
            chip_id: 9,
        }
    }

    #[test]
    fn join_params_match_what_nerveshub_reads() {
        let params = metadata().join_params("2.2.0", None);

        // These key names are a contract with
        // NervesHub.Firmwares.UpdateTool.EspIdf.metadata_from_device/1.
        assert_eq!(params["update_tool"], "esp-idf");
        assert_eq!(params["esp_idf_project_name"], "my_app");
        assert_eq!(params["esp_idf_version"], "1.2.3");
        assert_eq!(params["esp_idf_ver"], "v5.2.1");
        assert_eq!(params["esp_idf_chip_id"], 9);
        assert_eq!(params["device_api_version"], "2.2.0");
    }

    #[test]
    fn no_uuid_is_sent() {
        let params = metadata().join_params("2.2.0", None);
        assert!(params.get("uuid").is_none());
        assert!(params.get("nerves_fw_uuid").is_none());
    }

    #[test]
    fn currently_downloading_is_omitted_when_absent() {
        let params = metadata().join_params("2.2.0", None);
        assert!(params.get("currently_downloading_uuid").is_none());
    }

    #[test]
    fn currently_downloading_is_included_when_present() {
        let params = metadata().join_params("2.2.0", Some("abc-123"));
        assert_eq!(params["currently_downloading_uuid"], "abc-123");
    }
}
