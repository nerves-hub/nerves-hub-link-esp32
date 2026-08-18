//! The advanced path: an update policy, progress reporting, and a custom config.
//!
//! Everything here is optional. See `basic.rs` for the three-line version.

#[cfg(target_os = "espidf")]
fn main() -> Result<(), nerves_hub_link_esp32::Error> {
    use nerves_hub_link_esp32::{
        esp, identity, Config, Stage, UpdateDecision, UpdateHandler, UpdatePayload,
    };

    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Defer updates while the device is busy doing its actual job. NervesHub
    // understands both answers: `Ignore` is recorded against the deployment,
    // and `Reschedule` puts the device in the penalty box for the delay rather
    // than leaving the server to wonder.
    struct Policy;

    impl UpdateHandler for Policy {
        fn update_available(&mut self, update: &UpdatePayload) -> UpdateDecision {
            if busy_with_real_work() {
                UpdateDecision::Reschedule {
                    delay_ms: 5 * 60 * 1000,
                    reason: "mid-measurement".into(),
                }
            } else {
                log::info!("applying {:?}", update.firmware_meta);
                UpdateDecision::Apply
            }
        }

        fn progress(&mut self, stage: Stage, percent: u8) {
            log::info!("{} {}%", stage.as_str(), percent);
        }
    }

    let mut config = Config::new("devices.nervescloud.com", identity::load()?);
    config.heartbeat_interval_secs = 45;
    config.progress_step_percent = 10;
    config.reconnect_backoff_secs = vec![1, 5, 30, 120];

    esp::agent_with(config, Policy)?.run()?;

    Ok(())
}

#[cfg(target_os = "espidf")]
fn busy_with_real_work() -> bool {
    false
}

#[cfg(not(target_os = "espidf"))]
fn main() {
    eprintln!("Build for a device: cargo +esp esp32s3 --example advanced");
}
