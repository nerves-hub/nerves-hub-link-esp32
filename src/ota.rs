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

/// First byte of every ESP-IDF application image. The bootloader requires it.
pub const ESP_IMAGE_MAGIC: u8 = 0xE9;

/// What arrived from NervesHub.
///
/// An update says nothing about which of these it is: `firmware_url` looks the
/// same for both and the checksum is of whatever was sent. The bytes have to
/// answer it, and they can -- an application image opens with a magic byte the
/// bootloader insists on, and a detools patch opens with its own header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload {
    /// A whole image, to be written to the inactive slot as it arrives.
    Image,
    /// A patch, to be applied against the running image.
    Patch,
}

/// Decide from the first byte of the download.
///
/// Reads the image case as the specific one and everything else as a patch,
/// rather than the other way round: the magic is fixed by the bootloader, while
/// a patch header is only fixed by the format NervesHub currently generates.
/// Guessing "patch" wrongly fails in `esp_delta_ota` with the slot untouched;
/// guessing "image" wrongly writes a patch into the slot and fails to boot.
pub fn classify(first_byte: u8) -> Payload {
    if first_byte == ESP_IMAGE_MAGIC {
        Payload::Image
    } else {
        Payload::Patch
    }
}

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
    mode: Mode,
}

/// How the bytes being written are being interpreted.
///
/// Undecided until the first byte arrives, because that is the first moment
/// anything knows. See [`classify`].
#[cfg(target_os = "espidf")]
enum Mode {
    Undecided,
    Image,
    Patch {
        handle: esp_idf_svc::sys::esp_delta_ota_handle_t,
        /// Boxed for a stable address: the component keeps this pointer and
        /// hands it back to the callbacks.
        context: Box<PatchContext>,
    },
}

/// What the patch callbacks need, on a fixed address.
#[cfg(target_os = "espidf")]
struct PatchContext {
    /// Where the rebuilt image goes: the same handle the image path writes to.
    ota: esp_idf_svc::sys::esp_ota_handle_t,
    /// What the patch is against: the image currently running.
    source: *const esp_idf_svc::sys::esp_partition_t,
    /// Bytes of rebuilt image, which is not the number of patch bytes fed in.
    written: u64,
}

/// Reads the running image for the component.
///
/// # Safety
///
/// Called by `esp_delta_ota` with the `user_data` given to `esp_delta_ota_init`,
/// which is the boxed [`PatchContext`] the writer holds for at least as long as
/// the delta handle.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn patch_read(
    buf: *mut u8,
    size: usize,
    offset: core::ffi::c_int,
    user_data: *mut core::ffi::c_void,
) -> esp_idf_svc::sys::esp_err_t {
    let context = &*(user_data as *const PatchContext);

    esp_idf_svc::sys::esp_partition_read(
        context.source,
        offset as usize,
        buf as *mut core::ffi::c_void,
        size,
    )
}

/// Writes the rebuilt image into the inactive slot.
///
/// # Safety
///
/// As [`patch_read`]. Called on the thread feeding the patch, so the exclusive
/// borrow does not race the writer's own use of the context.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn patch_write(
    buf: *const u8,
    size: usize,
    user_data: *mut core::ffi::c_void,
) -> esp_idf_svc::sys::esp_err_t {
    let context = &mut *(user_data as *mut PatchContext);

    let err = esp_idf_svc::sys::esp_ota_write(context.ota, buf as *const core::ffi::c_void, size);

    if err == esp_idf_svc::sys::ESP_OK {
        context.written += size as u64;
    }

    err
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
                mode: Mode::Undecided,
            })
        }
    }

    /// Bytes written into the slot.
    ///
    /// For a patch this is the size of the rebuilt image rather than the size
    /// of the patch, which is the number worth reporting: it is what the slot
    /// now holds.
    pub fn written(&self) -> u64 {
        match &self.mode {
            Mode::Patch { context, .. } => context.written,
            _ => self.written,
        }
    }

    /// Start applying a patch against the running image.
    fn begin_patch(&mut self) -> Result<(), Error> {
        use esp_idf_svc::sys;

        let ota = self
            .handle
            .ok_or_else(|| Error::Ota("patch started after the update was finished".into()))?;

        // SAFETY: returns a pointer into the flash-mapped partition table.
        let source = unsafe { sys::esp_ota_get_running_partition() };

        if source.is_null() {
            return Err(Error::Ota("no running partition to patch against".into()));
        }

        let mut context = Box::new(PatchContext {
            ota,
            source,
            written: 0,
        });

        let mut config = sys::esp_delta_ota_cfg_t {
            // Non-null is what selects the callbacks that take it; the
            // component falls back to the context-free pair when this is null.
            user_data: context.as_mut() as *mut PatchContext as *mut core::ffi::c_void,
            __bindgen_anon_1: sys::esp_delta_ota_cfg__bindgen_ty_1 {
                read_cb_with_user_data: Some(patch_read),
            },
            __bindgen_anon_2: sys::esp_delta_ota_cfg__bindgen_ty_2 {
                write_cb_with_user_data: Some(patch_write),
            },
        };

        // SAFETY: `config` is only read during the call; the context outlives
        // the handle, which is released in `commit` or `abort`.
        let handle = unsafe { sys::esp_delta_ota_init(&mut config) };

        if handle.is_null() {
            return Err(Error::Ota("esp_delta_ota_init failed".into()));
        }

        self.mode = Mode::Patch { handle, context };

        Ok(())
    }
}

#[cfg(target_os = "espidf")]
impl ImageSink for OtaWriter {
    fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        use esp_idf_svc::sys;

        if chunk.is_empty() {
            return Ok(());
        }

        // The first byte decides, and only the first byte of the whole
        // download -- not of each chunk.
        if matches!(self.mode, Mode::Undecided) {
            match classify(chunk[0]) {
                Payload::Image => {
                    self.mode = Mode::Image;
                    log::info!("update is a full image");
                }
                Payload::Patch => {
                    self.begin_patch()?;
                    log::info!("update is a patch; applying against the running image");
                }
            }
        }

        match &mut self.mode {
            Mode::Patch { handle, .. } => {
                // SAFETY: `chunk` is valid for the duration of the call, and
                // `handle` came from esp_delta_ota_init and is still open.
                unsafe {
                    check(
                        sys::esp_delta_ota_feed_patch(
                            *handle,
                            chunk.as_ptr(),
                            chunk.len() as core::ffi::c_int,
                        ),
                        "esp_delta_ota_feed_patch",
                    )?;
                }
            }

            _ => {
                let handle = self
                    .handle
                    .ok_or_else(|| Error::Ota("write after the update was finished".into()))?;

                // SAFETY: `chunk` is valid for `len` bytes for the duration of
                // the call.
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
            }
        }

        // Patch bytes in, not image bytes out. `written()` reports the right
        // number for each mode.
        self.written += chunk.len() as u64;

        Ok(())
    }

    fn commit(&mut self) -> Result<(), Error> {
        use esp_idf_svc::sys;

        // Finish rebuilding before ending the OTA write, because finalizing
        // is what flushes the last of the rebuilt image through the write
        // callback. Ending the OTA handle first would leave it nowhere to go.
        if let Mode::Patch { handle, .. } = self.mode {
            let finalized = unsafe { check(sys::esp_delta_ota_finalize(handle), "esp_delta_ota_finalize") };

            // Released either way: the handle is no use after finalize, and a
            // failure here still has to leave nothing behind.
            unsafe {
                let _ = sys::esp_delta_ota_deinit(handle);
            }

            self.mode = Mode::Image;
            finalized?;
        }

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

        if let Mode::Patch { handle, .. } = self.mode {
            unsafe {
                let _ = sys::esp_delta_ota_deinit(handle);
            }

            self.mode = Mode::Image;
        }

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
        Err(Error::Ota(format!("{what} failed: {}", error_name(err))))
    }
}

/// An esp_err_t as the IDF names it, falling back to the number.
///
/// The number alone is what this used to report, and a failed update reaching
/// NervesHub as "esp_ota_end failed: 5379" tells whoever reads it nothing.
/// `ESP_ERR_OTA_VALIDATE_FAILED` says the image did not survive the trip.
#[cfg(target_os = "espidf")]
fn error_name(err: esp_idf_svc::sys::esp_err_t) -> String {
    // SAFETY: returns a pointer to a static string in the IDF's table, or to
    // its "UNKNOWN ERROR" literal; valid for the lifetime of the program.
    let name = unsafe {
        let ptr = esp_idf_svc::sys::esp_err_to_name(err);

        if ptr.is_null() {
            None
        } else {
            core::ffi::CStr::from_ptr(ptr).to_str().ok()
        }
    };

    match name {
        Some(name) => format!("{name} ({err})"),
        None => err.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    // The bootloader will not start an image that does not begin with this, so
    // it is the one byte of an update that is guaranteed.
    #[test]
    fn an_image_is_recognised_by_the_magic_the_bootloader_requires() {
        assert_eq!(classify(0xE9), Payload::Image);
    }

    // Captured from `detools create_patch -c heatshrink` over two real ESP-IDF
    // images, which is what NervesHub generates.
    #[test]
    fn a_detools_patch_is_recognised() {
        assert_eq!(classify(0x04), Payload::Patch);
    }

    // Anything unrecognised is treated as a patch on purpose. Guessing wrong
    // that way fails inside esp_delta_ota with the slot untouched; guessing
    // wrong the other way writes rubbish into the slot and fails to boot.
    #[test]
    fn anything_unrecognised_is_treated_as_a_patch() {
        for byte in [0x00, 0x01, 0x7F, 0xE8, 0xEA, 0xFF] {
            assert_eq!(classify(byte), Payload::Patch, "byte {byte:#04x}");
        }
    }
}
