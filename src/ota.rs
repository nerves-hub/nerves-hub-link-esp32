//! Applying an image to the inactive OTA slot.
//!
//! The shape of an ESP-IDF update, and why it maps so cleanly onto NervesHub:
//!
//! 1. Write the image into whichever of `ota_0`/`ota_1` is not running.
//! 2. Mark that slot bootable and reboot.
//! 3. On the next boot the app must *confirm* itself, or the bootloader rolls
//!    back to the previous slot on the following reset.
//!
//! Step 3 is `esp_ota_mark_app_valid_cancel_rollback()`, and it means exactly
//! what NervesHub's `firmware_validated` message means. So "reconnected to
//! NervesHub successfully" is a sound definition of a good image, and the two
//! systems agree without either being bent to fit.
//!
//! This requires `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` and a partition
//! table with two app slots plus an `otadata` partition — see
//! `partitions.csv` and `sdkconfig.defaults`.

use crate::error::Error;
#[cfg(target_os = "espidf")]
use crate::install::ImageSink;

/// Whether the running image still has to prove itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingVerify {
    /// This boot is a freshly applied update awaiting confirmation.
    Yes,
    /// Already confirmed, or rollback is not enabled.
    No,
}

/// ESP-IDF's `OTA_SIZE_UNKNOWN`. Defined here rather than taken from the
/// bindings because it is a C `#define` and may not survive bindgen.
///
/// We could pass the real size — NervesHub tells us — but `install` does not
/// hand it to the sink, and with `OTA_SIZE_UNKNOWN` the IDF erases sector by
/// sector as we write instead of up front. That is slightly slower and
/// considerably simpler.
#[cfg(target_os = "espidf")]
const OTA_SIZE_UNKNOWN: usize = 0xffff_ffff;

/// Streams an image into the inactive OTA slot.
///
/// Calls `esp_ota_*` directly rather than using the `esp-ota` crate: no
/// published version of it works with `esp-idf-svc` 0.52 (it requires
/// `esp-idf-sys` ^0.36, which conflicts with the 0.37 that `esp-idf-svc` pulls,
/// and `esp-idf-sys` is a `links` crate so only one copy may exist). The C API
/// is six functions, which is less to maintain than a pinned-back stack.
///
/// Checksum verification lives in `crate::install`, not here — it is a decision
/// rather than a device operation, and keeping it out of this module is what
/// lets it be tested on the host.
#[cfg(target_os = "espidf")]
pub struct OtaWriter {
    partition: *const esp_idf_svc::sys::esp_partition_t,
    /// `None` once committed or aborted.
    handle: Option<esp_idf_svc::sys::esp_ota_handle_t>,
    written: u64,
}

#[cfg(target_os = "espidf")]
impl OtaWriter {
    pub fn begin() -> Result<Self, Error> {
        use esp_idf_svc::sys;

        // SAFETY: a null `start_from` asks for the partition after the running
        // one, which is what we want; the returned pointer is into the
        // flash-mapped partition table and outlives us.
        unsafe {
            let partition = sys::esp_ota_get_next_update_partition(core::ptr::null());

            if partition.is_null() {
                return Err(Error::Ota(
                    "no inactive OTA partition — the partition table needs ota_0, ota_1 and otadata"
                        .into(),
                ));
            }

            let mut handle: sys::esp_ota_handle_t = Default::default();
            check(
                sys::esp_ota_begin(partition, OTA_SIZE_UNKNOWN, &mut handle),
                "esp_ota_begin",
            )?;

            Ok(Self {
                partition,
                handle: Some(handle),
                written: 0,
            })
        }
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

#[cfg(target_os = "espidf")]
impl ImageSink for OtaWriter {
    fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        use esp_idf_svc::sys;

        let handle = self
            .handle
            .ok_or_else(|| Error::Ota("write after the update was finished".into()))?;

        // SAFETY: `chunk` is valid for `len` bytes for the duration of the call.
        unsafe {
            check(
                sys::esp_ota_write(
                    handle,
                    chunk.as_ptr() as *const core::ffi::c_void,
                    chunk.len(),
                ),
                "esp_ota_write",
            )?;
        }

        self.written += chunk.len() as u64;

        Ok(())
    }

    fn commit(&mut self) -> Result<(), Error> {
        use esp_idf_svc::sys;

        let handle = self
            .handle
            .take()
            .ok_or_else(|| Error::Ota("commit after the update was finished".into()))?;

        // SAFETY: `handle` came from esp_ota_begin and has not been ended;
        // `self.partition` is the pointer esp_ota_begin was given.
        unsafe {
            // esp_ota_end validates the image it just wrote. If that fails the
            // handle is already released, so there is nothing left to abort.
            check(sys::esp_ota_end(handle), "esp_ota_end")?;
            check(
                sys::esp_ota_set_boot_partition(self.partition),
                "esp_ota_set_boot_partition",
            )
        }
    }

    fn abort(&mut self) {
        use esp_idf_svc::sys;

        if let Some(handle) = self.handle.take() {
            // Releases the handle without touching the boot partition, so the
            // currently running image stays bootable.
            unsafe {
                let _ = sys::esp_ota_abort(handle);
            }
        }
    }
}

#[cfg(target_os = "espidf")]
fn check(err: esp_idf_svc::sys::esp_err_t, what: &str) -> Result<(), Error> {
    if err == esp_idf_svc::sys::ESP_OK {
        Ok(())
    } else {
        Err(Error::Ota(format!("{what} failed: {err}")))
    }
}

#[cfg(target_os = "espidf")]
pub fn restart() -> ! {
    esp_idf_svc::hal::reset::restart()
}

/// Whether this boot is an unconfirmed update.
#[cfg(target_os = "espidf")]
pub fn pending_verify() -> PendingVerify {
    use esp_idf_svc::sys;

    unsafe {
        let partition = sys::esp_ota_get_running_partition();
        let mut state: sys::esp_ota_img_states_t = 0;

        if partition.is_null()
            || sys::esp_ota_get_state_partition(partition, &mut state) != sys::ESP_OK
        {
            return PendingVerify::No;
        }

        if state == sys::esp_ota_img_states_t_ESP_OTA_IMG_PENDING_VERIFY {
            PendingVerify::Yes
        } else {
            PendingVerify::No
        }
    }
}

/// Whether the bootloader rolled back to the image now running.
///
/// An image that reboots while still on probation is marked
/// `ESP_OTA_IMG_INVALID` by the bootloader, which then boots the other slot.
/// So a device that finds the *other* slot marked invalid is a device running
/// its predecessor because an update failed to prove itself.
///
/// This is current state rather than an event, which is what NervesHub wants:
/// the flag reads true for as long as the failed image is still sitting there,
/// and clears by itself when a later update overwrites that slot. So a device
/// stays visibly reverted until something actually fixes it.
///
/// Only `INVALID` counts. `ABORTED` means a download was interrupted, which is
/// an update that never started rather than one that failed.
#[cfg(target_os = "espidf")]
pub fn auto_revert_detected() -> bool {
    use esp_idf_svc::sys;

    unsafe {
        // The next slot to be written is the one not running, which is where a
        // failed image is left behind.
        let other = sys::esp_ota_get_next_update_partition(core::ptr::null());
        let mut state: sys::esp_ota_img_states_t = 0;

        if other.is_null() || sys::esp_ota_get_state_partition(other, &mut state) != sys::ESP_OK {
            return false;
        }

        state == sys::esp_ota_img_states_t_ESP_OTA_IMG_INVALID
    }
}

/// Confirm the running image, cancelling the pending rollback.
///
/// Call this only once the device is genuinely working — here, once it has
/// reconnected and rejoined NervesHub. Calling it at startup would confirm an
/// image that cannot reach the server, which is the one failure rollback exists
/// to catch.
#[cfg(target_os = "espidf")]
pub fn mark_valid() -> Result<(), Error> {
    use esp_idf_svc::sys;

    unsafe {
        if sys::esp_ota_mark_app_valid_cancel_rollback() != sys::ESP_OK {
            return Err(Error::Ota("could not mark app valid".into()));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "espidf"))]
pub fn pending_verify() -> PendingVerify {
    PendingVerify::No
}

#[cfg(not(target_os = "espidf"))]
pub fn auto_revert_detected() -> bool {
    false
}

#[cfg(not(target_os = "espidf"))]
pub fn mark_valid() -> Result<(), Error> {
    Ok(())
}
