//! The run loop, and the seam that makes it testable.
//!
//! This exists because the loop has several pieces of sequencing that are easy
//! to get subtly wrong and impossible to notice when they are:
//!
//! * the running image is confirmed only *after* NervesHub accepts the join —
//!   confirming at boot cancels the rollback for an image that cannot reach the
//!   server, which is the one failure rollback exists to catch;
//! * a failed update must report and carry on, not reboot or exit;
//! * heartbeats have to keep flowing while an update downloads.
//!
//! While that logic lived in an example, every user copied it and no test
//! covered it. Here it is library code with a fake [`Platform`] behind it.

use core::time::Duration;

use crate::config::Config;
use crate::error::Error;
use crate::install::{install, HttpStream, ImageSink};
use crate::link::{Action, Link, Transport, UpdateHandler};
use crate::metadata::FirmwareMetadata;
use crate::ota::PendingVerify;
use crate::update::Stage;

/// Everything the loop needs from the world outside it.
///
/// [`EspPlatform`](crate::esp::EspPlatform) is the implementation for real
/// hardware. Implementing this yourself is the escape hatch: a different
/// transport, a different flash target, or a simulated device for testing an
/// application's own update policy.
pub trait Platform {
    type Transport: Transport;
    type Http: HttpStream;
    type Sink: ImageSink;

    /// Open a connection to NervesHub. Failure is expected and retried.
    fn connect(&mut self, config: &Config) -> Result<Self::Transport, Error>;

    /// Start an HTTP download.
    fn http(&mut self) -> Result<Self::Http, Error>;

    /// Open the inactive image slot for writing.
    fn begin_update(&mut self) -> Result<Self::Sink, Error>;

    /// Whether this boot is an unconfirmed update.
    fn pending_verify(&mut self) -> PendingVerify;

    /// Confirm the running image, cancelling the pending rollback.
    fn mark_valid(&mut self) -> Result<(), Error>;

    /// Reboot. **Does not return on real hardware**; the loop treats a return
    /// as "stop", which is what lets a test observe it.
    fn restart(&mut self);

    fn sleep(&mut self, duration: Duration);

    /// Milliseconds from an arbitrary origin. Only differences are used.
    fn now_ms(&mut self) -> u64;
}

/// Why the loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// An update was applied and the device is rebooting into it.
    Rebooting,
}

/// A NervesHub device agent.
///
/// The simple path is [`Agent::new`] followed by [`Agent::run`]. To decide when
/// updates apply, supply an [`UpdateHandler`] with [`Agent::with_handler`].
pub struct Agent<P, H> {
    config: Config,
    metadata: FirmwareMetadata,
    platform: P,
    handler: H,
}

impl<P: Platform, H: UpdateHandler> Agent<P, H> {
    pub fn new(config: Config, metadata: FirmwareMetadata, platform: P, handler: H) -> Self {
        Self {
            config,
            metadata,
            platform,
            handler,
        }
    }

    /// Replace the update policy.
    pub fn with_handler<H2: UpdateHandler>(self, handler: H2) -> Agent<P, H2> {
        Agent {
            config: self.config,
            metadata: self.metadata,
            platform: self.platform,
            handler,
        }
    }

    /// Connect, stay connected, and apply updates. Returns only when rebooting.
    ///
    /// Connection failures are retried with the configured backoff rather than
    /// returned: a device that gives up because its network was briefly down is
    /// a device that needs a site visit.
    pub fn run(&mut self) -> Result<Stopped, Error> {
        let mut attempt = 0usize;

        loop {
            let mut transport = match self.platform.connect(&self.config) {
                Ok(transport) => {
                    attempt = 0;
                    transport
                }
                // A bad or missing certificate will not fix itself, and a
                // device silently retrying forever is worse than one that says
                // why it cannot connect.
                Err(err @ Error::Identity(_)) => return Err(err),
                Err(_) => {
                    let wait = self.config.backoff_for(attempt);
                    attempt = attempt.saturating_add(1);
                    self.platform.sleep(Duration::from_secs(wait));
                    continue;
                }
            };

            match self.session(&mut transport)? {
                Some(stopped) => return Ok(stopped),
                None => continue,
            }
        }
    }

    /// One connection's lifetime. `None` means reconnect.
    fn session(&mut self, transport: &mut P::Transport) -> Result<Option<Stopped>, Error> {
        let mut link = Link::new(self.config.clone(), self.metadata.clone());

        link.send_join(transport)?;

        let mut confirmed = false;
        let mut last_heartbeat = self.platform.now_ms();
        let heartbeat_ms = self.config.heartbeat_interval_secs * 1_000;

        loop {
            if link.joined() && !confirmed {
                self.confirm_running_image(&mut link, transport)?;
                confirmed = true;
            }

            let now = self.platform.now_ms();

            if now.saturating_sub(last_heartbeat) >= heartbeat_ms {
                link.send_heartbeat(transport)?;
                last_heartbeat = now;
            }

            let frame = match transport.recv() {
                Ok(Some(frame)) => frame,
                Ok(None) => continue,
                // The socket died. Not fatal — reconnect.
                Err(_) => return Ok(None),
            };

            match link.handle_frame(transport, &mut self.handler, &frame) {
                Ok(Action::ApplyUpdate(update)) => {
                    if self.apply(&mut link, transport, &update)? {
                        return Ok(Some(Stopped::Rebooting));
                    }
                }
                Ok(Action::Reconnect) => return Ok(None),
                Ok(Action::None) => {}
                Err(_) => return Ok(None),
            }
        }
    }

    /// Tell NervesHub the running image is good, and cancel any rollback.
    ///
    /// Only reached once the join succeeded, which is the whole point: "we can
    /// talk to NervesHub" is the definition of a working image.
    ///
    /// The rollback and the report are separate, and only one is conditional.
    /// Cancelling a rollback applies to an image the bootloader still has on
    /// probation — one installed by OTA — so it is skipped when nothing is
    /// pending. Reporting applies either way: an image flashed over a cable is
    /// never pending, but it is the image meant to be running and has just
    /// proved it works, and a device that stays silent is indistinguishable on
    /// the server from one that has never reported its firmware at all.
    fn confirm_running_image(
        &mut self,
        link: &mut Link,
        transport: &mut P::Transport,
    ) -> Result<(), Error> {
        if self.platform.pending_verify() == PendingVerify::Yes {
            self.platform.mark_valid()?;
        }

        link.send_firmware_validated(transport)?;

        Ok(())
    }

    /// Download and install. `true` if the device is now rebooting.
    ///
    /// A failure here is reported and swallowed: the running image is still
    /// bootable (see `install`), so the right move is to stay connected and let
    /// NervesHub decide whether to retry.
    fn apply(
        &mut self,
        link: &mut Link,
        transport: &mut P::Transport,
        update: &crate::update::UpdatePayload,
    ) -> Result<bool, Error> {
        if let Some((_url, uuid)) = update.actionable() {
            // So that a reconnect mid-download does not look idle to NervesHub,
            // which would clear the inflight update.
            link.set_downloading(Some(uuid.to_string()));
        }

        let outcome = self.download(link, transport, update);

        link.set_downloading(None);

        match outcome {
            Ok(()) => {
                link.send_progress(transport, Stage::Updating, 100)?;
                link.send_rebooting(transport)?;
                self.platform.restart();
                Ok(true)
            }
            Err(err) => {
                link.send_status(
                    transport,
                    "failed",
                    serde_json::json!({"reason": err.status_reason()}),
                )?;
                Ok(false)
            }
        }
    }

    fn download(
        &mut self,
        link: &mut Link,
        transport: &mut P::Transport,
        update: &crate::update::UpdatePayload,
    ) -> Result<(), Error> {
        let mut http = self.platform.http()?;
        let mut sink = self.platform.begin_update()?;
        let handler = &mut self.handler;
        let step = self.config.progress_step_percent;

        install(update, &mut http, &mut sink, step, &mut |stage, percent| {
            handler.progress(stage, percent);
            link.send_progress(transport, stage, percent)
        })
        .map(|_report| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Credentials;
    use crate::install::InstallReport;
    use crate::link::AlwaysApply;
    use crate::message::Message;
    use crate::update::{UpdateDecision, UpdatePayload};
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// One scripted frame the fake socket will hand back: a frame, "nothing
    /// yet", or a dead socket.
    type Incoming = Result<Option<String>, Error>;

    #[derive(Default)]
    struct Shared {
        sent: Vec<String>,
        connects: usize,
        slept: Vec<Duration>,
        marked_valid: usize,
        restarts: usize,
        commits: usize,
    }

    #[derive(Clone)]
    struct FakeTransport {
        shared: Rc<RefCell<Shared>>,
        incoming: Rc<RefCell<Vec<Incoming>>>,
    }

    impl Transport for FakeTransport {
        fn send(&mut self, frame: &str) -> Result<(), Error> {
            self.shared.borrow_mut().sent.push(frame.to_string());
            Ok(())
        }

        fn recv(&mut self) -> Result<Option<String>, Error> {
            let mut incoming = self.incoming.borrow_mut();

            if incoming.is_empty() {
                Err(Error::Transport("closed".into()))
            } else {
                incoming.remove(0)
            }
        }
    }

    struct FakeHttp(Vec<u8>, usize);

    impl HttpStream for FakeHttp {
        fn open(&mut self, _url: &str) -> Result<Option<u64>, Error> {
            Ok(Some(self.0.len() as u64))
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let take = (self.0.len() - self.1).min(buf.len());
            buf[..take].copy_from_slice(&self.0[self.1..self.1 + take]);
            self.1 += take;
            Ok(take)
        }
    }

    struct FakeSink(Rc<RefCell<Shared>>);

    impl ImageSink for FakeSink {
        fn write(&mut self, _chunk: &[u8]) -> Result<(), Error> {
            Ok(())
        }

        fn commit(&mut self) -> Result<(), Error> {
            self.0.borrow_mut().commits += 1;
            Ok(())
        }

        fn abort(&mut self) {}
    }

    struct FakePlatform {
        shared: Rc<RefCell<Shared>>,
        incoming: Vec<Vec<Incoming>>,
        pending: PendingVerify,
        image: Vec<u8>,
        connect_failures: usize,
        clock_ms: u64,
    }

    impl Platform for FakePlatform {
        type Transport = FakeTransport;
        type Http = FakeHttp;
        type Sink = FakeSink;

        fn connect(&mut self, _config: &Config) -> Result<Self::Transport, Error> {
            self.shared.borrow_mut().connects += 1;

            if self.connect_failures > 0 {
                self.connect_failures -= 1;
                return Err(Error::Transport("no route".into()));
            }

            if self.incoming.is_empty() {
                // Ends `run()`. Identity errors are the one class the agent
                // treats as fatal, which makes them the natural stop signal.
                return Err(Error::Identity("no more scripted sessions".into()));
            }

            let frames = self.incoming.remove(0);

            Ok(FakeTransport {
                shared: Rc::clone(&self.shared),
                incoming: Rc::new(RefCell::new(frames)),
            })
        }

        fn http(&mut self) -> Result<Self::Http, Error> {
            Ok(FakeHttp(self.image.clone(), 0))
        }

        fn begin_update(&mut self) -> Result<Self::Sink, Error> {
            Ok(FakeSink(Rc::clone(&self.shared)))
        }

        fn pending_verify(&mut self) -> PendingVerify {
            self.pending
        }

        fn mark_valid(&mut self) -> Result<(), Error> {
            self.shared.borrow_mut().marked_valid += 1;
            Ok(())
        }

        fn restart(&mut self) {
            self.shared.borrow_mut().restarts += 1;
        }

        fn sleep(&mut self, duration: Duration) {
            self.shared.borrow_mut().slept.push(duration);
            self.clock_ms += duration.as_millis() as u64;
        }

        fn now_ms(&mut self) -> u64 {
            self.clock_ms += 1;
            self.clock_ms
        }
    }

    fn metadata() -> FirmwareMetadata {
        FirmwareMetadata {
            project_name: "my_app".into(),
            version: "1.0.0".into(),
            app_elf_sha256: "ab".repeat(32),
            idf_ver: "v5.2.1".into(),
            chip_id: 9,
        }
    }

    fn config() -> Config {
        Config::new(
            "devices.test",
            Credentials::client_certificate(b"cert".to_vec(), b"key".to_vec()).unwrap(),
        )
    }

    fn join_reply(response: Value) -> Incoming {
        Ok(Some(format!(
            r#"["1","1","device","phx_reply",{{"status":"ok","response":{}}}]"#,
            response
        )))
    }

    fn sha256_upper(bytes: &[u8]) -> String {
        let mut hasher = crate::checksum::Sha256::new();
        hasher.update(bytes);
        hasher.finalize_hex_upper()
    }

    fn agent(platform: FakePlatform) -> Agent<FakePlatform, AlwaysApply> {
        Agent::new(config(), metadata(), platform, AlwaysApply)
    }

    fn platform(incoming: Vec<Vec<Incoming>>) -> FakePlatform {
        FakePlatform {
            shared: Rc::new(RefCell::new(Shared::default())),
            incoming,
            pending: PendingVerify::No,
            image: vec![],
            connect_failures: 0,
            clock_ms: 0,
        }
    }

    fn events(shared: &Rc<RefCell<Shared>>) -> Vec<String> {
        shared
            .borrow()
            .sent
            .iter()
            .map(|frame| Message::decode(frame).unwrap().event)
            .collect()
    }

    #[test]
    fn a_pending_image_is_confirmed_after_joining() {
        let mut plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        plat.pending = PendingVerify::Yes;
        let shared = Rc::clone(&plat.shared);

        // The socket then dies, so run() would loop forever; drive one session.
        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport);

        assert_eq!(shared.borrow().marked_valid, 1);
        assert!(events(&shared).contains(&"firmware_validated".to_string()));
    }

    // Confirming before the join succeeds would cancel the rollback for an image
    // that cannot reach NervesHub — precisely what rollback is for.
    #[test]
    fn nothing_is_confirmed_before_the_join_is_accepted() {
        let mut plat = platform(vec![vec![Err(Error::Transport("closed".into()))]]);
        plat.pending = PendingVerify::Yes;
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport);

        assert_eq!(shared.borrow().marked_valid, 0);
        assert!(!events(&shared).contains(&"firmware_validated".to_string()));
    }

    // A serially flashed image is never pending, so there is no rollback to
    // cancel — but it is running, and it has just joined.
    #[test]
    fn an_image_that_is_not_pending_is_reported_but_not_marked() {
        let plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport);

        assert_eq!(shared.borrow().marked_valid, 0);
        assert!(events(&shared).contains(&"firmware_validated".to_string()));
    }

    #[test]
    fn connection_failures_are_retried_with_backoff() {
        let mut plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        plat.connect_failures = 3;
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let _ = agent.run();

        // Three failures, the successful connect, then one more when that
        // session ends — which is the fake's stop signal.
        assert_eq!(shared.borrow().connects, 5);
        assert_eq!(
            shared.borrow().slept,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(5)
            ]
        );
    }

    #[test]
    fn an_update_is_installed_and_the_device_restarts() {
        let image = vec![7u8; 4096];

        let update = json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": image.len(),
            "checksum": sha256_upper(&image)
        });

        let mut plat = platform(vec![vec![join_reply(update)]]);
        plat.image = image;
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        assert_eq!(agent.run().unwrap(), Stopped::Rebooting);

        assert_eq!(shared.borrow().commits, 1);
        assert_eq!(shared.borrow().restarts, 1);

        let events = events(&shared);
        assert!(events.contains(&"update_progress".to_string()));
        assert!(events.contains(&"rebooting".to_string()));
    }

    // A bad download must not reboot: `install` leaves the running image
    // bootable, so the device should report and stay up.
    #[test]
    fn a_corrupt_update_is_reported_and_does_not_restart() {
        let image = vec![7u8; 4096];

        let update = json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": image.len(),
            "checksum": "00".repeat(32)
        });

        let mut plat = platform(vec![vec![join_reply(update)]]);
        plat.image = image;
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport);

        assert_eq!(shared.borrow().restarts, 0);
        assert_eq!(shared.borrow().commits, 0);

        let sent = shared.borrow().sent.clone();
        let status = sent
            .iter()
            .map(|f| Message::decode(f).unwrap())
            .find(|m| m.event == "status_update")
            .expect("a failure should be reported");

        assert_eq!(status.payload["status"], "failed");
        assert!(status.payload["reason"]
            .as_str()
            .unwrap()
            .contains("checksum"));
    }

    #[test]
    fn a_handler_can_decline_an_update() {
        struct Decline;

        impl UpdateHandler for Decline {
            fn update_available(&mut self, _update: &UpdatePayload) -> UpdateDecision {
                UpdateDecision::Ignore {
                    reason: "busy".into(),
                }
            }
        }

        let update = json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": 10
        });

        let plat = platform(vec![vec![join_reply(update)]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_handler(Decline);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport);

        assert_eq!(shared.borrow().commits, 0);
        assert_eq!(shared.borrow().restarts, 0);
        assert!(events(&shared).contains(&"status_update".to_string()));
    }

    #[test]
    fn install_report_is_unused_but_typed() {
        // Guards the signature `install` returns, which `download` maps away.
        let report = InstallReport {
            bytes: 1,
            checksum: "AA".into(),
        };
        assert_eq!(report.bytes, 1);
    }
}
