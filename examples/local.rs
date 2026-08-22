//! Bench bring-up against a NervesHub on your own network.
//!
//! Unlike `basic.rs` and `advanced.rs`, this one brings WiFi up itself and
//! authenticates with a shared secret, so there is nothing to provision onto
//! the device beforehand — no certificates, no NVS.
//!
//! Copy `local_config.rs.template` to `local_config.rs` in the crate root, fill
//! it in, then:
//!
//! ```text
//! cargo +esp esp32 --example local --release
//! ```

#[cfg(target_os = "espidf")]
mod config {
    include!("../local_config.rs");
}

#[cfg(target_os = "espidf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use esp_idf_svc::eventloop::EspSystemEventLoop;
    use esp_idf_svc::hal::gpio::PinDriver;
    use esp_idf_svc::hal::peripherals::Peripherals;
    use esp_idf_svc::nvs::EspDefaultNvsPartition;
    use esp_idf_svc::sntp::{EspSntp, SyncStatus};
    use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};

    use nerves_hub_link_esp32::extensions::Enabled;
    use nerves_hub_link_esp32::health::EspHealth;
    use nerves_hub_link_esp32::whenwhere::Whenwhere;
    use nerves_hub_link_esp32::{esp, AlwaysApply, Config, Credentials};

    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: config::WIFI_SSID.try_into().map_err(|_| "WIFI_SSID is too long")?,
        password: config::WIFI_PASSWORD
            .try_into()
            .map_err(|_| "WIFI_PASSWORD is too long")?,
        auth_method: AuthMethod::None,
        ..Default::default()
    }))?;

    wifi.start()?;
    log::info!("connecting to {}", config::WIFI_SSID);
    wifi.connect()?;
    wifi.wait_netif_up()?;

    let ip = wifi.wifi().sta_netif().get_ip_info()?;
    log::info!("got {:?}", ip.ip);

    // The shared-secret signature is only valid inside the server's max_age
    // window — 90 seconds by default — and the clock reads 1970 until SNTP has
    // run. Without this the first join fails as `unauthorized`, which looks
    // exactly like a wrong secret.
    let sntp = EspSntp::new_default()?;
    log::info!("waiting for the clock");
    while sntp.get_sync_status() != SyncStatus::Completed {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    log::info!("clock synchronised");

    let credentials = Credentials::shared_secret(
        config::DEVICE_IDENTIFIER,
        config::NH_SHARED_SECRET_KEY,
        config::NH_SHARED_SECRET,
    );

    let mut nh = Config::new(config::NH_HOST, credentials);
    nh.port = config::NH_PORT;
    nh.use_tls = config::NH_USE_TLS;

    // Offered, not assumed: the platform attaches these only if the product has
    // them enabled.
    nh.extensions = Enabled::none().health().geo();

    if !nh.use_tls {
        log::warn!("connecting over plain ws:// — bench use only");
    }

    // Most ESP32 devkits put an LED on GPIO2. On a board that does not, the pin
    // toggles harmlessly and the log line below is what you watch for.
    let mut led = PinDriver::output(peripherals.pins.gpio2)?;

    log::info!("connecting to {}", nh.socket_url());

    esp::agent_with(nh, AlwaysApply)?
        .with_health(EspHealth::new())
        .with_location(Whenwhere::new())
        .on_identify(move || {
            log::warn!("=== IDENTIFY: this is the device you are looking at ===");
            for _ in 0..10 {
                let _ = led.toggle();
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            let _ = led.set_low();
        })
        .run()?;

    Ok(())
}

#[cfg(not(target_os = "espidf"))]
fn main() {
    eprintln!(
        "Build for a device: cargo +esp esp32 --example local --release\n\
         (copy local_config.rs.template to local_config.rs first)"
    );
}
