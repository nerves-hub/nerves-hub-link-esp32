//! The ESP-IDF implementation of [`Platform`], and the one-call entry point.
//!
//! **Not yet run on hardware**, though it compiles for `xtensa-esp32s3-espidf`.

#![cfg(target_os = "espidf")]

use core::time::Duration;
use std::time::Instant;

use crate::agent::{Agent, Platform, Stopped};
use crate::config::Config;
use crate::error::Error;
use crate::http::EspHttpStream;
use crate::identity;
use crate::link::{AlwaysApply, UpdateHandler};
use crate::metadata::{self, FirmwareMetadata};
use crate::ota::{self, OtaWriter, PendingVerify};
use crate::transport::WebSocketTransport;

/// Runs the agent on real hardware.
pub struct EspPlatform {
    started: Instant,
}

impl Default for EspPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl EspPlatform {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Platform for EspPlatform {
    type Transport = WebSocketTransport;
    type Http = EspHttpStream;
    type Sink = OtaWriter;

    fn connect(&mut self, config: &Config) -> Result<Self::Transport, Error> {
        WebSocketTransport::connect(config)
    }

    fn http(&mut self) -> Result<Self::Http, Error> {
        EspHttpStream::new()
    }

    fn begin_update(&mut self) -> Result<Self::Sink, Error> {
        OtaWriter::begin()
    }

    fn pending_verify(&mut self) -> PendingVerify {
        ota::pending_verify()
    }

    fn auto_revert_detected(&mut self) -> bool {
        ota::auto_revert_detected()
    }

    fn mark_valid(&mut self) -> Result<(), Error> {
        ota::mark_valid()
    }

    fn restart(&mut self) {
        ota::restart()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn now_ms(&mut self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

/// Build an agent for this device.
///
/// Reads the client certificate from NVS and the running firmware's
/// `esp_app_desc_t`, so there is nothing for the caller to assemble.
///
/// ```no_run
/// # fn main() -> Result<(), nerves_hub_link_esp32::Error> {
/// nerves_hub_link_esp32::esp::agent("devices.nerves-hub.org")?.run()?;
/// # Ok(())
/// # }
/// ```
pub fn agent(host: impl Into<String>) -> Result<Agent<EspPlatform, AlwaysApply>, Error> {
    agent_with(Config::new(host, identity::load()?), AlwaysApply)
}

/// Build an agent with a custom config and update policy.
pub fn agent_with<H: UpdateHandler>(
    config: Config,
    handler: H,
) -> Result<Agent<EspPlatform, H>, Error> {
    let metadata: FirmwareMetadata = metadata::running_firmware()?;

    Ok(Agent::new(config, metadata, EspPlatform::new(), handler))
}

/// Connect and stay connected, applying updates as they arrive.
///
/// The whole integration, for an application with no opinion about when
/// updates land:
///
/// ```no_run
/// # fn main() -> Result<(), nerves_hub_link_esp32::Error> {
/// nerves_hub_link_esp32::esp::run("devices.nerves-hub.org")?;
/// # Ok(())
/// # }
/// ```
///
/// Blocks. Returns [`Stopped::Rebooting`] after an update is installed — on
/// real hardware the reboot happens first, so this is not usually reached.
pub fn run(host: impl Into<String>) -> Result<Stopped, Error> {
    agent(host)?.run()
}
