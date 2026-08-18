# nerves-hub-link-esp32

A NervesHub device agent for ESP-IDF targets, in Rust.

This enables you to add your ESP32-IDF Rust applications to your 
[NervesCloud](https://nervescloud.com) account or self-hosted 
[NervesHub](https://nerves-hub.org) platform.

This crate orchestrates updates through `esp_ota` with the 
bootloader's rollback protection intact.

## Status

**Very early development, use at your own risk**

| Layer | State |
| --- | --- |
| Phoenix v2 frame codec | Implemented, unit tested on host |
| Join payload / firmware metadata | Implemented, unit tested on host |
| Update payload, decisions, progress throttling | Implemented, unit tested on host |
| Checksums | Implemented, unit tested on host |
| Install orchestration (download → verify → commit) | Implemented, unit tested on host |
| WebSocket transport (`esp_websocket_client` + mTLS) | Compiles for `xtensa-esp32s3-espidf`, never run |
| HTTP download (`EspHttpConnection`) | Compiles, never run |
| `esp_ota` apply, rollback confirmation | Compiles, never run |
| Device identity from NVS | Compiles, never run |
| Anything on real hardware | **Not done** |

Two independent checks back this up:

- `cargo test` — 56 tests of the protocol and install layers, on the host, with
  no ESP toolchain.
- `cargo +esp check-esp32s3 --all-targets` — the whole crate *and* the example
  agent type-checked against real ESP-IDF v5.2.3 headers for ESP32-S3.

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

### Things an application must repeat

`esp-idf-sys` reads `[package.metadata.esp-idf-sys]` only from the **root
package of the build**, so none of this is inherited from a library dependency.
An application using this crate must copy into its own `Cargo.toml`:

```toml
[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_websocket_client", version = "^1.0" }
```

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
cargo +esp esp32s3        # device build
cargo +esp check-esp32s3  # device type-check, no linking
```

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
install without rebooting, keeping heartbeats flowing during a download — and
none of that could be tested while it was code users copied.

## Project setup

Four things, none of which this crate can do for you.

**1. Cargo.toml.** `esp-idf-sys` reads `package.metadata` only from the root
package of a build, so this is *not* inherited from the dependency:

```toml
[dependencies]
nerves-hub-link-esp32 = "0.1"

[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_websocket_client", version = "^1.0" }
```

**2. `sdkconfig.defaults`:**

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
CONFIG_ESP_MAIN_TASK_STACK_SIZE=10000
```

**3. `partitions.csv`** — two app slots, `otadata`, and a `certs` partition.
Copy the one in this repo. Both app slots must be identical in size and large
enough for the biggest image you will ever ship; an image that outgrows its slot
fails on the device, in the field.

**4. A device certificate in NVS.** NervesHub identifies a device by its client
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

mTLS only. NervesHub also accepts an HMAC shared secret, but that requires
reproducing Plug.Crypto's signed-token format — PBKDF2 with a negotiated
digest, iteration count and key length, then `MessageVerifier`'s encoding, over
a specific multi-line salt. A client certificate is handed straight to mbedTLS,
which ESP-IDF already ships. There is no crypto to reimplement and nothing to
get subtly wrong.

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

## Not supported (yet)

- **Resumable downloads.** NervesHub sends `partials_checksums` so an
  interrupted transfer can be resumed and verified chunk-wise. This restarts
  from zero instead.
- **Delta updates.** NervesHub generates and stores whole-image xdelta3 patches
  but always sends full images to ESP-IDF devices, because applying a patch
  means reading back the inactive slot and patching into it. Nothing here does
  that yet.
- **Firmware signing.** NervesHub stores ESP-IDF images unsigned; its
  organization keys hold Ed25519 keys, which cannot represent Secure Boot v2's
  RSA-3072/ECDSA-P256. Use device-side Secure Boot v2, which the bootloader
  enforces independently.
- **Updating the VM or bootloader.** Application partition only.
- **Console, extensions, scripts.** The `device` channel only.

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

  esp.rs        EspPlatform + the one-call entry point
  transport.rs  esp_websocket_client + mTLS   (impl Transport)
  http.rs       EspHttpConnection             (impl HttpStream)
  ota.rs        esp_ota write/activate/confirm (impl ImageSink)
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
cargo test
```

## See also

`docs/esp_idf_support.md` in the NervesHub repository, for the server side and
the full list of what is not supported yet.
