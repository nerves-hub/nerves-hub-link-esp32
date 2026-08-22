# nerves-hub-link-esp32

A NervesHub device agent for ESP-IDF targets, in Rust.

This enables you to add your ESP32-IDF Rust applications to your 
[NervesCloud](https://nervescloud.com) account or self-hosted 
[NervesHub](https://nerves-hub.org) platform.

This crate orchestrates updates through `esp_ota` with the 
bootloader's rollback protection intact.

## Status

**Early development, use at your own risk**

Run on an ESP32-WROOM-32D against a NervesHub instance: connecting, updating
over the air, applying deltas, rolling back, and reporting health, position and
logs. It has not run on anything else, for any length of time, or on a fleet.

| Layer | State |
| --- | --- |
| Phoenix v2 frame codec | Host tested, run on hardware |
| Join payload / firmware metadata | Host tested, run on hardware |
| Update payload, decisions, progress throttling | Host tested, run on hardware |
| Checksums | Host tested, run on hardware |
| Install orchestration (download → verify → commit) | Host tested, run on hardware |
| Delta updates (`esp_delta_ota`) | Host tested, run on hardware |
| WebSocket transport (`esp_websocket_client`) | Run on hardware, over `ws://` and shared secrets |
| HTTP download (`EspHttpConnection`) | Run on hardware |
| `esp_ota` apply, rollback confirmation | Run on hardware, including a real rollback |
| Extensions: health, geo, logging | Run on hardware |
| Reboot and identify | Run on hardware |
| mTLS transport | Compiles, never run — the bench uses shared secrets |
| Device identity from NVS | Compiles, never run |
| Anything on a fleet, or for longer than an afternoon | **Not done** |

Two checks back the host side up:

- `cargo test` — 119 tests of the protocol, install, extensions and logging
  layers, on the host, with no ESP toolchain.
- `cargo +esp check-esp32 --all-targets` — the whole crate *and* the example
  agent type-checked against real ESP-IDF v5.2.3 headers.

## Requirements

- ESP-IDF, via `esp-idf-svc` (std). The `no_std` `esp-hal` stack is not
  supported: it brings no ESP-IDF, and therefore no `esp_ota`, no
  `esp_websocket_client`, and no mbedTLS.
- Two app partitions plus `otadata` — see `partitions.csv`.
- `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` — see `sdkconfig.defaults`.
- The `espressif/esp_websocket_client` managed component. It is **not** part of
  core ESP-IDF, and `esp_idf_svc::ws::client` is cfg-gated on its presence — so
  without it the module silently does not exist and you get an unresolved
  import. See the note below.
- The `espressif/esp_delta_ota` managed component, which applies the patches
  NervesHub generates. Without it, delta updates fail; full images still work.

### Things an application must repeat

`esp-idf-sys` reads `[package.metadata.esp-idf-sys]` only from the **root
package of the build**, so none of this is inherited from a library dependency.
An application using this crate must copy into its own `Cargo.toml`:

```toml
[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_websocket_client", version = "^1.0" }

[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_delta_ota", version = "^1.1" }
bindings_header = "include/delta_ota_bindings.h"
```

`esp_delta_ota` needs the `bindings_header` as well as the component. esp-idf-sys
generates bindings from a curated header list that covers the well-known
components; this is not one of them, so without a header that includes
`esp_delta_ota.h` the component builds and its symbols never reach Rust. Copy
`include/delta_ota_bindings.h` from this repo.

and into its own `sdkconfig.defaults`:

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
```

The partition table is deliberately *not* configured in this repo's
`sdkconfig.defaults`: `esp-idf-sys` builds ESP-IDF in its own output directory,
where a relative `partitions.csv` does not exist, so setting it here breaks the
library build. `partitions.csv` is a working example to copy.

Note also that cargo does not invalidate a build script when `package.metadata`
changes. After editing the `extra_components` block you must
`cargo clean -p esp-idf-sys` or the change is silently ignored.
- Xtensa parts (ESP32, S2, S3) need the `esp` rustc fork — `espup install`,
  then build with `+esp`. RISC-V parts (C3, C6, H2, P4) build on stable.

There is deliberately **no `rust-toolchain.toml`**: pinning the `esp` channel
would make `cargo test` fail on any machine without espup installed, and the
protocol layer is meant to be testable anywhere. Select the toolchain per build
instead:

```bash
cargo test                # host, no ESP toolchain
cargo +esp esp32          # device build
cargo +esp check-esp32    # device type-check, no linking
```

`esp32s3` and `check-esp32s3` are there too. The bench runs on a plain ESP32,
so that is the target with hardware behind it.

The device aliases live in `.cargo/config.toml`. They carry
`-Zbuild-std=std,panic_abort`, which the esp toolchain needs because it ships no
prebuilt `std` for the espidf targets — and which cannot go in `[unstable]`,
because that would apply to host builds and break `cargo test` on stable.

## Usage

Three layers. Start at the top; drop down only when you need to.

### 1. The whole integration

```rust
fn main() -> Result<(), nerves_hub_link_esp32::Error> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // ... bring wifi up ...

    nerves_hub_link_esp32::esp::run("devices.nervescloud.com")?;
    Ok(())
}
```

That reads the client certificate from NVS and the running firmware from
`esp_app_desc_t`, connects, joins, confirms the running image once NervesHub
accepts it, heartbeats, and installs updates as they arrive — rebooting into
each one. See `examples/basic.rs`.

Bring the clock up before this, with SNTP. See [Authentication](#authentication)
for why a device that believes it is 1970 cannot join.

### 2. A policy of your own

Most devices should not drop what they are doing to install firmware. Implement
[`UpdateHandler`] and NervesHub is told what you decided, rather than being left
to guess from silence:

```rust
struct Policy;

impl UpdateHandler for Policy {
    fn update_available(&mut self, _update: &UpdatePayload) -> UpdateDecision {
        if mid_measurement() {
            // Recorded server-side, and the device is held off for the delay.
            UpdateDecision::Reschedule { delay_ms: 300_000, reason: "busy".into() }
        } else {
            UpdateDecision::Apply
        }
    }

    fn progress(&mut self, stage: Stage, percent: u8) {
        log::info!("{} {}%", stage.as_str(), percent);
    }
}

let mut config = Config::new("devices.nervescloud.com", identity::load()?);
config.heartbeat_interval_secs = 45;

esp::agent_with(config, Policy)?.run()?;
```

See `examples/advanced.rs`.

### 3. You own everything

`Agent` is generic over a [`Platform`] — the trait holding every operation that
touches the world: connect, download, write flash, confirm, reboot, sleep, clock.
`EspPlatform` is one implementation. Supplying another gets you a different
transport, a different flash target, or a simulated device for testing your own
update policy without hardware.

Below that, the pieces are public and independent: `Link` (the channel state
machine, generic over `Transport`), `install` (download → verify → commit,
generic over `HttpStream` and `ImageSink`), `message` (the wire format).

The loop deliberately lives in the library rather than in an example. Its
sequencing has several things that are easy to get wrong and silent when you do
— confirming the running image only *after* the join succeeds, aborting a failed
install without rebooting, backing off only when a session never joined — and
none of that could be tested while it was code users copied.

One thing the loop does **not** do: it runs the download synchronously, so for
its duration no heartbeats are sent, no frames are read, and no logs are
drained. Progress messages keep the socket busy, which is enough for
NervesHub's 180 second timeout at the sizes and link speeds tried so far. A
slower link or a larger image would want the download to service the connection
between chunks.

## Project setup

Five things, none of which this crate can do for you.

**1. Cargo.toml.** `esp-idf-sys` reads `package.metadata` only from the root
package of a build, so this is *not* inherited from the dependency:

```toml
[dependencies]
nerves-hub-link-esp32 = "0.1"

[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_websocket_client", version = "^1.0" }

[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_delta_ota", version = "^1.1" }
bindings_header = "include/delta_ota_bindings.h"
```

**2. `sdkconfig.defaults`:**

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
CONFIG_ESP_MAIN_TASK_STACK_SIZE=10000

CONFIG_APP_PROJECT_VER_FROM_CONFIG=y
CONFIG_APP_PROJECT_VER="1.0.0"
```

The version is not optional. NervesHub reads it from `esp_app_desc_t`, at
upload and from the running device, and it has to parse as SemVer. Left unset,
ESP-IDF fills it from `git describe`, which does not — and a device reporting an
unparseable version has no firmware metadata server-side, so it can never match
a deployment while looking perfectly healthy.

**3. `partitions.csv`** — two app slots, `otadata`, and a `certs` partition.
Copy the one in this repo. Both app slots must be identical in size and large
enough for the biggest image you will ever ship; an image that outgrows its slot
fails on the device, in the field.

**4. The project name in the image.** NervesHub matches `esp_app_desc_t`'s
`project_name` against the product an image is uploaded to. ESP-IDF takes that
field from the CMake project name, which `esp-idf-sys` hardcodes to
`libespidf`, so every Rust image claims to be a product called `libespidf` and
no upload matches anything. There is no setting for it. Patch the ELF after
building and before `elf2image`:

```bash
scripts/set_app_desc.py --project-name MyProduct target/<target>/release/my-app
```

On the ELF, not the `.bin`: the image's SHA-256 is computed during
`elf2image`, so patching afterwards invalidates it and the bootloader refuses
to start the image.

**5. A device identity.** Either scheme works; the device needs one of them.

For **shared secrets**, nothing is provisioned — the identifier and secret are
configuration, and a product-wide secret registers unknown devices on first
connection. That is the quickest way to a working bench.

For **mTLS**, a device certificate in NVS. NervesHub identifies a device by its client
certificate — it pins the SHA-1 fingerprint of the DER, so the certificate does
**not** need a CA. A self-signed, per-device certificate is enough. [`nh`](https://github.com/nerves-hub/nh) 
does the whole identity half in one command:

```bash
nh device certificates generate my-device-001 --self-signed --upload
```

That generates a secp256r1 key, produces a self-signed client certificate with
the device identifier as the common name, and registers it with NervesHub.
Files land in `~/.nh/certificates/<org>/`.

Then write them into the `certs` partition and flash. `scripts/provision.sh`
does this, or by hand:

```bash
cat > nvs.csv <<'CSV'
key,type,encoding,value
nerves_hub,namespace,,
device.crt,file,binary,device.crt
device.key,file,binary,device.key
CSV

nvs_partition_gen.py generate nvs.csv certs.bin 0x10000
esptool.py --port /dev/tty.usbmodem write_flash 0x3E0000 certs.bin
```

Both tools ship with ESP-IDF. The `0x3E0000` offset is the `certs` partition in
`partitions.csv` — change it if you change the table.

The NVS partition, namespace and key names are exported from `identity`
(`PARTITION`, `NAMESPACE`, `CERTIFICATE_KEY`, `PRIVATE_KEY_KEY`) and are
deliberately visible off-device, so tooling that writes the image can reference
them rather than repeat the strings — a drift there surfaces as a TLS handshake
failure that says nothing about a renamed key.

In production, provision at manufacture and enable NVS encryption: the private
key is otherwise readable by anyone who can dump flash.

## Authentication

Both of NervesHub's schemes, as configuration on the same websocket client:
a client certificate handed to mbedTLS, or shared-secret headers on the HTTP
upgrade. Which one an organization uses is its choice.

```rust
Credentials::client_certificate(cert_pem, key_pem)?   // mTLS
Credentials::shared_secret(identifier, key, secret)   // HMAC headers
```

The shared-secret path reproduces Plug.Crypto's signed-token format: PBKDF2
with a negotiated digest, iteration count and key length, then
`MessageVerifier`'s encoding, over a multi-line salt that binds the headers.
It is checked byte for byte against vectors generated by the Elixir side, in
`shared_secret.rs`, because getting it subtly wrong fails in a way that looks
exactly like a wrong secret.

**The clock has to be right either way.** A signature is only valid inside the
server's window, 90 seconds by default, and TLS certificate dates cannot be
checked by a device that believes it is 1970. Run SNTP before connecting; a
device that does not will fail to join in a way that reads as bad credentials.

Keep certificates in an NVS partition, encrypted in production. Compiling them
into the image gives an entire fleet one identity.

## Why no `esp-ota` crate

`ota.rs` calls the six `esp_ota_*` C functions directly rather than using the
`esp-ota` crate. No published version of `esp-ota` works with `esp-idf-svc`
0.52: the newest (0.2.2) requires `esp-idf-sys` `^0.36`, `esp-idf-svc` 0.52
pulls `0.37`, and `esp-idf-sys` is a `links = "esp_idf"` crate so only one copy
may exist in the graph. Pinning the whole stack back to keep a thin wrapper was
the worse trade.

## Rollback

ESP-IDF's rollback protocol and NervesHub's `firmware_validated` work in harmony.

1. Write the image to the inactive slot, mark it bootable, reboot.
2. The new image comes up in `PENDING_VERIFY`.
3. It must call `esp_ota_mark_app_valid_cancel_rollback()`, or the bootloader
   reverts on the next reset.

This crate confirms only **after** rejoining NervesHub. Confirming at startup
would cancel the rollback for an image that cannot reach the server — the exact
failure rollback exists to catch.

## Delta updates

NervesHub sends a patch rather than a whole image where it has one. On the
firmware this project builds, a patch runs from 1.6% of the image for a version
bump to 7.3% for a release's worth of changes.

Nothing to configure on the device. An update says nothing about which it is —
`firmware_url` looks the same either way and the checksum is of whatever was
sent — so the agent reads the first byte: an application image opens with the
magic the bootloader insists on, and anything else is treated as a patch. A
patch is fed to `esp_delta_ota`, which reads the running slot and writes the
rebuilt image into the inactive one.

The rebuild is byte for byte, which is what makes this work under Secure Boot:
the signature block travels inside the image, so the device verifies the same
bytes it would have downloaded. Nothing is re-signed on the device.

A patch that does not rebuild the expected image is caught by `esp_ota_end`
before the boot partition moves, and reported as a failed update. The device
stays on the firmware it was running.

## Extensions

Off by default, each one asked for individually, and attached only if the
product allows it:

```rust
use nerves_hub_link_esp32::extensions::Enabled;
use nerves_hub_link_esp32::{health::EspHealth, logging, whenwhere::Whenwhere};

config.extensions = Enabled::none().health().geo().logging();

let logs = logging::install(log::LevelFilter::Info, log::Level::Info);

esp::agent_with(config, AlwaysApply)?
    .with_health(EspHealth::new())
    .with_location(Whenwhere::new())
    .with_logs(logs)
    .on_identify(|| blink())
    .run()?;
```

- **health** reports memory, WiFi RSSI and the reason for the last reset.
- **geo** answers with a GeoIP position from the Nerves project's `whenwhere`
  service, the same one `nerves_hub_link` uses. Supply your own
  `LocationProvider` for a GNSS fix.
- **logging** sends what the `log` crate is given. `logging::install` replaces
  `EspLogger::initialize_default()` and keeps writing to the console. It does
  not capture ESP-IDF's own C logging, which never reaches the `log` crate.

`on_identify` runs when an operator presses Identify in NervesHub. Reboot needs
nothing: the agent answers it and restarts.

## Not supported (yet)

- **Resumable downloads.** NervesHub sends `partials_checksums` so an
  interrupted transfer can be resumed and verified chunk-wise. This restarts
  from zero instead.
- **Updating the VM or bootloader.** Application partition only.
- **Console and support scripts.** Handled on the `device` channel by
  NervesHub, not by this agent.
- **Local shell and network identity extensions.** Health, geo and logging are
  implemented; these two are not.

## Layout

```
src/
  agent.rs      the run loop                  (trait: Platform)
  link.rs       the channel state machine     (trait: Transport)
  install.rs    download -> verify -> commit  (traits: HttpStream, ImageSink)
  message.rs    Phoenix v2 frames, topics, event names
  metadata.rs   esp_app_desc_t -> join payload
  update.rs     update payload, decisions, progress throttling
  checksum.rs   SHA-256 in NervesHub's format

  config.rs     connection config, credentials, backoff
  extensions.rs the extensions channel        (traits: LocationProvider, HealthProvider)
  logging.rs    a log::Log that keeps a copy for NervesHub
  shared_secret.rs  Plug.Crypto signed tokens, checked against Elixir vectors

  esp.rs        EspPlatform + the one-call entry point
  transport.rs  esp_websocket_client          (impl Transport)
  http.rs       EspHttpConnection             (impl HttpStream)
  ota.rs        esp_ota + esp_delta_ota       (impl ImageSink)
  health.rs     memory, RSSI, reset reason    (impl HealthProvider)
  whenwhere.rs  GeoIP position                (impl LocationProvider)
  identity.rs   client certificate from NVS
```

The top group is host-testable; the bottom group is the device. Each seam is a
trait, so the loop runs against a fake platform, `link.rs` against a fake
socket, and `install.rs` against a fake network and fake flash. The frames, the
sequencing and the install decisions are the parts most likely to be wrong; the
sockets are not.

That is also why `install.rs` — not `ota.rs` — owns checksum verification and
the decision to commit. "Never make a corrupt image bootable" is a rule worth a
test, and it can only have one on the host.

## Testing

```bash
cargo test                        # host: protocol, install, extensions, logging
cargo +esp check-esp32            # device type-check, no linking
cargo +esp esp32 --example local  # device build of the bench example
```

The host tests need no ESP toolchain, which is the point: the frames, the
sequencing and the install decisions are the parts most likely to be wrong.

`examples/local.rs` is the one that has actually been run — it brings WiFi up
itself, authenticates with a shared secret, and enables health, geo and
logging, so there is nothing to provision first. Copy
`local_config.rs.template` to `local_config.rs` in the crate root and fill it
in. `basic.rs` and `advanced.rs` are the mTLS shapes and have not been run.

## See also

`docs/esp_idf_support.md` in the NervesHub repository, for the server side and
the full list of what is not supported yet.
