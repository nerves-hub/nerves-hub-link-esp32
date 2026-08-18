//! The simple path: three lines.
//!
//! Builds for ESP-IDF targets; on the host it explains how to build it, so
//! `cargo test` still compiles this file.

#[cfg(target_os = "espidf")]
fn main() -> Result<(), nerves_hub_link_esp32::Error> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Bring wifi up before this point; see esp-idf-svc's wifi examples.

    // Reads the client certificate from the `certs` NVS partition and the
    // running firmware from `esp_app_desc_t`, then connects and stays
    // connected, applying updates as NervesHub sends them.
    nerves_hub_link_esp32::esp::run("devices.nervescloud.com")?;

    Ok(())
}

#[cfg(not(target_os = "espidf"))]
fn main() {
    eprintln!("Build for a device: cargo +esp esp32s3 --example basic");
}
