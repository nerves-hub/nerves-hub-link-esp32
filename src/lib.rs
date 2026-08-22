//! NervesHub device agent for ESP-IDF targets.
//!
//! Connects an ESP32 to NervesHub over Phoenix Channels, reports what firmware
//! it is running, and applies over-the-air updates through `esp_ota` with the
//! bootloader's rollback protection intact.
//!
//! # Status
//!
//! Early sketch. The protocol layer — frame codec, join payload, update
//! payload, progress throttling, checksums — is implemented and unit tested on
//! the host. The device layer (`ota`, and the websocket transport) is written
//! against the esp-rs crates but has not been built or run on hardware; the
//! dependency versions in `Cargo.toml` still need resolving against a real
//! ESP-IDF build.
//!
//! # Shape of a session
//!
//! ```text
//!   connect (mTLS)
//!        │
//!        ├─ phx_join "device" ──────────────► esp_app_desc_t metadata
//!        │  ◄──── phx_reply { update_available, firmware_url, ... }
//!        │
//!        ├─ if this boot is PENDING_VERIFY:
//!        │     firmware_validated ──────────► and esp_ota_mark_app_valid()
//!        │
//!        ├─ heartbeat every 30s ────────────► "phoenix" topic
//!        │
//!        └─ on "update":
//!              download ──► esp_ota write ──► verify checksum
//!                 │              │
//!                 └─ update_progress (throttled)
//!                                └─► set_as_boot_partition ──► rebooting ──► restart
//! ```
//!
//! # Two contracts with the server
//!
//! Both are easy to get wrong and neither fails loudly:
//!
//! - The channel topic is **`"device"`**, unqualified. NervesHub rewrites it to
//!   `device:<device_id>` in its own serializer. See [`message`].
//! - The join payload sends `esp_idf_*` keys and **no UUID** — NervesHub derives
//!   the UUID from `app_elf_sha256`. See [`metadata`].

pub mod shared_secret;
pub mod agent;
pub mod checksum;
pub mod config;
pub mod error;
pub mod esp;
pub mod http;
pub mod identity;
pub mod install;
pub mod link;
pub mod message;
pub mod metadata;
pub mod ota;
pub mod transport;
pub mod update;

pub use agent::{Agent, Platform, Stopped};
pub use config::{Config, Credentials};
pub use error::Error;
pub use install::{install, HttpStream, ImageSink, InstallReport};
pub use link::{Action, AlwaysApply, Link, Transport, UpdateHandler};
pub use metadata::FirmwareMetadata;
pub use update::{Stage, UpdateDecision, UpdatePayload};
