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

use core::fmt::Write;
use core::time::Duration;
use std::sync::Arc;

use crate::config::Config;
use crate::extensions::{HealthProvider, LocationProvider, Outgoing};
use crate::error::Error;
use crate::install::{install, HttpStream, ImageSink};
use crate::console::{self, LineReader, Output};
use crate::link::{Action, Link, Transport, UpdateHandler};
use crate::logging::LogBuffer;
use crate::metadata::{BootReport, FirmwareMetadata};
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

    /// Whether the bootloader rolled back to the image now running, because the
    /// last update failed to prove itself.
    ///
    /// Defaults to "no". A platform that cannot tell should say so rather than
    /// guess: NervesHub treats this as a device in trouble, and a false report
    /// is worse than no report.
    fn auto_revert_detected(&mut self) -> bool {
        false
    }

    /// Confirm the running image, cancelling the pending rollback.
    fn mark_valid(&mut self) -> Result<(), Error>;

    /// Reboot. **Does not return on real hardware**; the loop treats a return
    /// as "stop", which is what lets a test observe it.
    fn restart(&mut self);

    fn sleep(&mut self, duration: Duration);

    /// Milliseconds from an arbitrary origin. Only differences are used.
    fn now_ms(&mut self) -> u64;
}

/// How long to wait between log lines.
///
/// NervesHub allows five a second per device and drops the rest without
/// telling the device, so this stays under it with room to spare. A backlog
/// drains slowly, which is the intended trade: late beats discarded.
const LOG_SEND_INTERVAL_MS: u64 = 250;

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
    location: Option<Box<dyn LocationProvider>>,
    health: Option<Box<dyn HealthProvider>>,
    identify: Option<Box<dyn FnMut()>>,
    logs: Option<Arc<LogBuffer>>,
    console: Option<Console>,
}

/// What a command does when someone types its name.
///
/// A closure rather than a trait: a command set is a handful of functions, and
/// the registry is the only thing that needs to hold them together.
pub type CommandFn = Box<dyn FnMut(&[&str], &mut Output) -> Result<(), Error>>;

/// The terminal, and the commands reachable from it.
#[derive(Default)]
struct Console {
    reader: LineReader,
    commands: Vec<(String, String, CommandFn)>,
}

impl Console {
    /// Run one line, and return what to print.
    ///
    /// An unknown command says so and points at `help`, because silence is
    /// indistinguishable from a device that has stopped answering.
    ///
    /// `help`, `reboot` and `log` never reach here: they need the agent's own
    /// platform, restart and log buffer, so the caller handles them and this
    /// only sees what the registry can answer.
    fn run(&mut self, line: &str) -> String {
        let Some((name, args)) = console::parse(line) else {
            return String::new();
        };

        let mut out = Output::new();

        if name == "help" {
            let mut names: Vec<&(String, String, CommandFn)> = self.commands.iter().collect();
            names.sort_by(|a, b| a.0.cmp(&b.0));

            let _ = writeln!(out, "commands:\r");

            // Handled by the agent rather than the registry, so they are not
            // in the list below and have to be named here.
            for (name, help) in [
                ("help", "this list"),
                ("log [level]", "what is sent to NervesHub"),
                ("reboot", "restart the device"),
            ] {
                let _ = writeln!(out, "  {name:<14} {help}\r");
            }

            for (name, help, _) in names {
                let _ = writeln!(out, "  {name:<14} {help}\r");
            }

            return out.finish();
        }

        match self.commands.iter_mut().find(|(n, _, _)| n == name) {
            Some((_, _, run)) => {
                if let Err(err) = run(&args, &mut out) {
                    let _ = write!(out, "\r\n{name}: {err}");
                }
            }

            None => {
                let _ = write!(out, "{name}: unknown command, try `help`");
            }
        }

        out.finish()
    }
}

impl<P: Platform, H: UpdateHandler> Agent<P, H> {
    pub fn new(config: Config, metadata: FirmwareMetadata, platform: P, handler: H) -> Self {
        Self {
            location: None,
            health: None,
            identify: None,
            logs: None,
            console: None,
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
            location: self.location,
            health: self.health,
            identify: self.identify,
            logs: self.logs,
            console: self.console,
            handler,
        }
    }

    /// Answer `geo:location:request` with this.
    ///
    /// Without one the extension is offered but never answered, so set it
    /// whenever geo is enabled.
    pub fn with_location(mut self, provider: impl LocationProvider + 'static) -> Self {
        self.location = Some(Box::new(provider));
        self
    }

    /// Answer `health:check` with this.
    pub fn with_health(mut self, provider: impl HealthProvider + 'static) -> Self {
        self.health = Some(Box::new(provider));
        self
    }

    /// Send the device's log to NervesHub, from the buffer `logging::install`
    /// returns.
    ///
    /// Lines go out one at a time with a gap between them, because the platform
    /// rate limits log traffic per device and a device that trips that limit
    /// has its lines dropped server-side, where it cannot tell. Pacing on the
    /// device means a burst arrives late rather than not at all.
    pub fn with_logs(mut self, logs: Arc<LogBuffer>) -> Self {
        self.logs = Some(logs);
        self
    }

    /// Offer NervesHub a terminal, with a fixed set of commands behind it.
    ///
    /// Off unless asked for: it is a remote command surface, and a device that
    /// never calls this never joins the channel. See [`crate::console`] for
    /// what it is and, more importantly, what it is not.
    ///
    /// Brings `help`, `info`, `uptime` and `reboot` with it. The device build
    /// adds the ones that need ESP-IDF -- `heap`, `wifi`, `partitions`,
    /// `reset-reason` and `log`.
    pub fn with_console(mut self) -> Self {
        if self.console.is_none() {
            self.console = Some(Console::default());
        }

        let metadata = self.metadata.clone();

        let started = std::time::Instant::now();

        self.command("uptime", "time since boot", move |_args, out| {
            let seconds = started.elapsed().as_secs();

            write!(
                out,
                "{}d {:02}h {:02}m {:02}s",
                seconds / 86_400,
                (seconds % 86_400) / 3600,
                (seconds % 3600) / 60,
                seconds % 60
            )?;

            Ok(())
        })
        .device_commands()
        .command("info", "firmware and device identity", move |_args, out| {
            writeln!(out, "project   {}\r", metadata.project_name)?;
            writeln!(out, "version   {}\r", metadata.version)?;
            writeln!(out, "idf       {}\r", metadata.idf_ver)?;
            match crate::metadata::chip_name(metadata.chip_id) {
                Some(name) => writeln!(out, "chip      {name}\r")?,
                // Unknown rather than absent: a chip this build has never heard
                // of still has an id worth reporting.
                None => writeln!(out, "chip      unknown ({:#06x})\r", metadata.chip_id)?,
            }
            write!(out, "elf sha   {}", &metadata.app_elf_sha256[..16])?;
            Ok(())
        })
    }

    /// The commands that need ESP-IDF. Nothing on the host.
    #[cfg(target_os = "espidf")]
    fn device_commands(self) -> Self {
        self.command("heap", "memory, and how fragmented it is", |_args, out| {
            console::device::heap(out)
        })
        .command("wifi", "ssid, signal and address", |_args, out| {
            console::device::wifi(out)
        })
        .command("partitions", "which slot runs, and the other's state", |_args, out| {
            console::device::partitions(out)
        })
        .command("reset-reason", "why it last rebooted", |_args, out| {
            console::device::reset_reason(out)
        })
    }

    #[cfg(not(target_os = "espidf"))]
    fn device_commands(self) -> Self {
        self
    }

    /// Add a command, or replace one of the built-ins.
    ///
    /// Ignored unless [`Agent::with_console`] was called, so an application can
    /// register commands unconditionally and decide elsewhere whether the
    /// terminal is offered at all.
    pub fn command(
        mut self,
        name: &str,
        help: &str,
        run: impl FnMut(&[&str], &mut Output) -> Result<(), Error> + 'static,
    ) -> Self {
        if let Some(console) = self.console.as_mut() {
            console
                .commands
                .retain(|(existing, _, _)| existing != name);

            console
                .commands
                .push((name.to_string(), help.to_string(), Box::new(run)));
        }

        self
    }

    /// Make the device identifiable to someone standing next to it.
    ///
    /// Run when an operator presses Identify in NervesHub, which they press
    /// because they are looking at several identical boxes and need to know
    /// which one the browser is pointed at. Blink an LED, sound something,
    /// print to the console -- whatever is visible from where the device is.
    ///
    /// It runs on the session loop, so a long one delays heartbeats and
    /// everything else: keep it to a few seconds, and hand anything longer to
    /// a task.
    ///
    /// Without one, Identify is accepted and does nothing. That is not a
    /// failure the platform can see -- it has no reply -- so a device that
    /// should be identifiable needs this set.
    pub fn on_identify(mut self, identify: impl FnMut() + 'static) -> Self {
        self.identify = Some(Box::new(identify));
        self
    }

    /// Echo what was typed, run any completed line, and print the prompt.
    ///
    /// Commands run here, on the session loop, so a slow one delays heartbeats
    /// and everything else by however long it takes. The budget is
    /// milliseconds; anything longer belongs on a task, with the command
    /// reporting that it started rather than waiting for it to finish.
    /// `true` when a command asked the device to restart.
    fn answer_console<T: Transport>(
        &mut self,
        link: &mut Link,
        transport: &mut T,
        data: &str,
    ) -> Result<bool, Error> {
        let (echo, lines) = match self.console.as_mut() {
            Some(console) => console.reader.feed(data),
            None => return Ok(false),
        };

        link.send_console(transport, &echo)?;

        for line in lines {
            let parsed = console::parse(&line)
                .map(|(name, args)| (name.to_string(), args.iter().map(|a| a.to_string()).collect::<Vec<_>>()));

            let output = match parsed.as_ref().map(|(name, args)| (name.as_str(), args)) {
                // Announced before restarting rather than after: the socket is
                // about to go, and whoever typed it should see that it was
                // taken rather than watch the terminal die.
                Some(("reboot", _)) => {
                    link.send_console(transport, "rebooting\r\n")?;
                    self.platform.sleep(Duration::from_millis(250));
                    self.platform.restart();

                    return Ok(true);
                }

                Some(("log", args)) => self.log_command(args),

                _ => match self.console.as_mut() {
                    Some(console) => console.run(&line),
                    None => String::new(),
                },
            };

            if !output.is_empty() {
                link.send_console(transport, &output)?;
                link.send_console(transport, "\r\n")?;
            }

            link.send_console(transport, console::PROMPT)?;
        }

        Ok(false)
    }

    /// `log` — show or change what is forwarded to NervesHub.
    ///
    /// Lives here rather than in the registry because it needs the buffer the
    /// logger writes into, which the application supplies separately.
    fn log_command(&mut self, args: &[String]) -> String {
        let mut out = Output::new();

        let Some(logs) = self.logs.as_ref() else {
            let _ = write!(out, "log: this device is not sending logs to NervesHub");
            return out.finish();
        };

        match args.first().map(|a| a.as_str()) {
            None => {
                let _ = write!(out, "log level is {}", logs.level().as_str().to_lowercase());
            }

            Some(level) => match level.parse::<log::Level>() {
                Ok(level) => {
                    logs.set_level(level);
                    let _ = write!(out, "log level is now {}", level.as_str().to_lowercase());
                }

                Err(_) => {
                    let _ = write!(out, "log: unknown level {level:?}, try error/warn/info/debug/trace");
                }
            },
        }

        out.finish()
    }

    /// Resolve what the platform asked for, using the application's providers.
    fn answer_extension<T: Transport>(
        &mut self,
        link: &mut Link,
        transport: &mut T,
        needs: Vec<Outgoing>,
    ) -> Result<(), Error> {
        for need in needs {
            let answer = match need {
                Outgoing::NeedLocation => {
                    let location = self.location.as_mut().and_then(|p| p.location());
                    link.location_answer(location)
                }
                Outgoing::NeedHealth => match self.health.as_mut() {
                    Some(provider) => {
                        let report = provider.report();
                        link.health_answer(&report)
                    }
                    // Offered health but supplied no provider: say nothing
                    // rather than report an empty set of metrics, which would
                    // chart as a device whose memory suddenly reads zero.
                    None => Vec::new(),
                },
                other => vec![other],
            };

            link.send_extension(transport, answer)?;
        }

        Ok(())
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
                Ok(transport) => transport,
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

            let mut joined = false;
            let outcome = self.session(&mut transport, &mut joined);

            match outcome {
                Ok(Some(stopped)) => return Ok(stopped),
                Ok(None) => {}
                // Every send in a session is written as `?`, so a socket that
                // dies mid-write arrives here. That is a reconnect, not the end
                // of the agent: a device that stops talking to NervesHub
                // because one heartbeat missed its socket is a device that
                // needs a site visit.
                Err(Error::Transport(_)) => {}
                Err(err) => return Err(err),
            }

            // Opening a socket is not the same as having a session on it. Only
            // a session that got as far as a join counts as progress worth
            // resetting the backoff for -- otherwise a socket that connects and
            // dies immediately reconnects as fast as the hardware allows, which
            // is a device hammering a server that is already unhappy.
            if joined {
                attempt = 0;
            }

            let wait = self.config.backoff_for(attempt);

            if !joined {
                attempt = attempt.saturating_add(1);
            }
            log::info!("session ended (joined: {joined}); reconnecting in {wait}s");
            self.platform.sleep(Duration::from_secs(wait));
        }
    }

    /// One connection's lifetime. `None` means reconnect.
    ///
    /// `joined` is set once the platform accepts the join, which is what tells
    /// the caller whether this connection ever became a session.
    fn session(
        &mut self,
        transport: &mut P::Transport,
        joined: &mut bool,
    ) -> Result<Option<Stopped>, Error> {
        let mut link = Link::new(self.config.clone(), self.metadata.clone());

        if self.console.is_some() {
            link.want_console();
        }

        // Both facts are read from the join, not from a later message. That is
        // deliberate on the platform's side: a device that reverted may never
        // get far enough to send anything else, and the revert is exactly the
        // thing worth knowing about it.
        let boot = BootReport {
            firmware_validated: self.platform.pending_verify() == PendingVerify::No,
            firmware_auto_revert_detected: self.platform.auto_revert_detected(),
        };

        if boot.firmware_auto_revert_detected {
            log::warn!("the bootloader reverted to this image; the last update did not come up");
        }

        link.send_join(transport, boot)?;

        let mut confirmed = false;
        let mut extensions_joined = false;
        let mut extensions_reported = false;
        let mut console_joined = false;
        let mut last_log = self.platform.now_ms();
        let mut last_heartbeat = self.platform.now_ms();
        let heartbeat_ms = self.config.heartbeat_interval_secs * 1_000;

        loop {
            if link.joined() && !confirmed {
                *joined = true;
                self.confirm_running_image(&mut link, transport)?;
                confirmed = true;
            }

            // Only after the device channel is joined: the platform decides
            // what to attach from the device's product, which it knows once the
            // device has said who it is.
            if link.joined() && link.extensions_wanted() && !extensions_joined {
                link.send_extensions_join(transport)?;
                extensions_joined = true;
            }

            // Which extensions the platform actually attached is the answer to
            // most "why is nothing arriving" questions, and the device is the
            // only place both halves are visible.
            if link.joined() && link.console_wanted() && !console_joined {
                link.send_console_join(transport)?;
                console_joined = true;
            }

            if link.extensions_joined() && !extensions_reported {
                extensions_reported = true;
                log::info!(
                    "extensions attached: {:?}; {} log lines queued",
                    link.attached_extensions(),
                    self.logs.as_ref().map(|logs| logs.len()).unwrap_or(0)
                );
            }

            let now = self.platform.now_ms();

            if now.saturating_sub(last_heartbeat) >= heartbeat_ms {
                link.send_heartbeat(transport)?;
                last_heartbeat = now;
            }

            // One line per interval, and only once the platform has attached
            // logging -- popping before then would discard the line into a
            // channel nothing is listening on.
            if link.logging_attached() && now.saturating_sub(last_log) >= LOG_SEND_INTERVAL_MS {
                let pending = self
                    .logs
                    .as_ref()
                    .and_then(|logs| logs.pop_stamped(crate::logging::unix_micros()));

                if let Some(line) = pending {
                    link.send_log(transport, &line)?;
                    last_log = now;
                }
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
                Ok(Action::Reboot) => {
                    // Answered before restarting, not after: the socket is
                    // about to go, and a reboot the operator asked for should
                    // not be indistinguishable from a device that fell off the
                    // network on its own.
                    link.send_rebooting(transport)?;
                    self.platform.restart();
                    return Ok(Some(Stopped::Rebooting));
                }
                Ok(Action::Identify) => {
                    if let Some(identify) = self.identify.as_mut() {
                        identify();
                    }
                }
                Ok(Action::Console(data)) => {
                    if self.answer_console(&mut link, transport, &data)? {
                        return Ok(Some(Stopped::Rebooting));
                    }
                }
                Ok(Action::ConsoleRestart) => {
                    if let Some(console) = self.console.as_mut() {
                        console.reader = LineReader::new();
                    }

                    link.send_console(transport, "\r\n")?;
                    link.send_console(transport, console::PROMPT)?;
                }
                Ok(Action::Reconnect) => return Ok(None),
                Ok(Action::Extension(needs)) => {
                    self.answer_extension(&mut link, transport, needs)?;
                }
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

                // The image is written to the inactive slot and the bootloader
                // is pointed at it: downloaded and applied, which is what
                // `completed` claims. It is not a claim that the image works --
                // nothing has run it yet. That comes after the reboot, from
                // `firmware_validated`, and the two are deliberately separate:
                // an update that completes and then rolls back has to be
                // distinguishable from one that completes and stays.
                link.send_status(transport, "completed", serde_json::json!({}))?;

                link.send_rebooting(transport)?;

                // A send returns once the bytes reach the socket, not once they
                // reach the server, and `restart` is an immediate reset -- so
                // the last three messages of an update were being written into
                // a buffer that a reboot threw away. NervesHub saw the update
                // stop at whatever progress it had last heard, and inferred
                // completion from the device rejoining with a new UUID.
                //
                // A quarter second is not a guarantee of delivery, and nothing
                // here can be: the update is already applied, the device is
                // going to reboot either way, and none of these messages is
                // worth delaying that for long. It is enough for a LAN and
                // costs nothing that matters.
                log::info!("update applied; rebooting");
                self.platform.sleep(Duration::from_millis(250));

                self.platform.restart();
                Ok(true)
            }
            Err(err) => {
                // Logged as well as reported. `status_update` carries a reason
                // that lands on the update record, but a failed update is the
                // moment someone most wants the surrounding lines -- what the
                // device decided the download was, how far it got, what the
                // OTA layer said -- and those only reach NervesHub through the
                // log. The device stays up after this, so the queued lines get
                // sent rather than lost to a reboot.
                log::error!("update failed: {err}");

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
        let step = self.config.progress_step_percent;
        let heartbeat_ms = self.config.heartbeat_interval_secs * 1_000;

        // Disjoint borrows of two fields, which one `&mut self` would not give.
        let Self {
            platform, handler, logs, ..
        } = self;

        let now = platform.now_ms();

        let mut pump = Pump {
            link,
            transport,
            platform,
            handler,
            logs: logs.as_ref(),
            heartbeat_ms,
            last_heartbeat: now,
            last_log: now,
        };

        install(update, &mut http, &mut sink, step, &mut pump).map(|_report| ())
    }
}

/// Keeps the connection alive while an image comes down.
///
/// A download is the longest thing the agent does, and it used to own the loop
/// for its whole duration: no heartbeats, no logs, nothing read. On a fast
/// enough link that fits inside NervesHub's socket timeout by luck rather than
/// design, and the margin shrinks with every megabyte and every slow network.
///
/// Nothing is read here, and nothing needs to be. Frames arriving during a
/// download queue on the transport's channel and are handled when it finishes,
/// so a console command typed mid-update is answered late rather than lost. A
/// heartbeat that cannot be sent, on the other hand, is how the download learns
/// the connection has gone -- the error abandons it rather than writing the
/// rest of an image nobody will hear about.
struct Pump<'a, P: Platform, H: UpdateHandler> {
    link: &'a mut Link,
    transport: &'a mut P::Transport,
    platform: &'a mut P,
    handler: &'a mut H,
    logs: Option<&'a Arc<LogBuffer>>,
    heartbeat_ms: u64,
    last_heartbeat: u64,
    last_log: u64,
}

impl<P: Platform, H: UpdateHandler> crate::install::Progress for Pump<'_, P, H> {
    fn tick(&mut self) -> Result<(), Error> {
        let now = self.platform.now_ms();

        if now.saturating_sub(self.last_heartbeat) >= self.heartbeat_ms {
            self.link.send_heartbeat(self.transport)?;
            self.last_heartbeat = now;
        }

        if self.link.logging_attached() && now.saturating_sub(self.last_log) >= LOG_SEND_INTERVAL_MS
        {
            let pending = self
                .logs
                .and_then(|logs| logs.pop_stamped(crate::logging::unix_micros()));

            if let Some(line) = pending {
                self.link.send_log(self.transport, &line)?;
                self.last_log = now;
            }
        }

        Ok(())
    }

    fn report(&mut self, stage: Stage, percent: u8) -> Result<(), Error> {
        self.handler.progress(stage, percent);
        self.link.send_progress(self.transport, stage, percent)
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
        /// A socket that has gone away under a write, which is what a close
        /// racing a heartbeat looks like from the sending side.
        send_fails: bool,
    }

    impl Transport for FakeTransport {
        fn send(&mut self, frame: &str) -> Result<(), Error> {
            if self.send_fails {
                return Err(Error::Transport("closed".into()));
            }

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
        /// How far the fake clock jumps per reading. A download calls `now_ms`
        /// once per chunk, so a test wanting to reach a heartbeat interval
        /// winds this up rather than building a multi-megabyte image.
        clock_step_ms: u64,
        send_fails: bool,
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
                send_fails: self.send_fails,
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
            self.clock_ms += self.clock_step_ms;
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
            clock_step_ms: 1,
            send_fails: false,
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

    // A socket can die between the run loop deciding to write and the write
    // landing -- which is exactly what a NervesHub "reconnect" does. The agent
    // must treat that as a reconnect. Ending the run instead would leave a
    // device off NervesHub until someone power-cycled it.
    #[test]
    fn a_send_that_fails_reconnects_instead_of_ending_the_run() {
        let mut plat = platform(vec![
            vec![join_reply(json!({"update_available": false}))],
            vec![join_reply(json!({"update_available": false}))],
        ]);
        plat.send_fails = true;
        let shared = Rc::clone(&plat.shared);

        let mut agent = Agent::new(config(), metadata(), plat, AlwaysApply);

        // The scripted sessions run out, and `connect` then reports an identity
        // error, which is the fixture's way of stopping the loop. Reaching it
        // proves the agent kept reconnecting rather than returning on the first
        // failed write.
        assert!(matches!(agent.run(), Err(Error::Identity(_))));

        // Two scripted sessions plus the connect that ends the run.
        assert_eq!(shared.borrow().connects, 3);
    }

    /// Everything the device wrote to the terminal, joined.
    fn console_output(shared: &Rc<RefCell<Shared>>) -> String {
        shared
            .borrow()
            .sent
            .iter()
            .filter_map(|frame| {
                let message = Message::decode(frame).ok()?;

                if message.topic != "console" || message.event != "up" {
                    return None;
                }

                Some(message.payload["data"].as_str()?.to_string())
            })
            .collect()
    }

    fn typed(text: &str) -> Incoming {
        Ok(Some(format!(
            r#"[null,null,"console","dn",{{"data":{}}}]"#,
            serde_json::to_string(text).unwrap()
        )))
    }

    // The terminal is not offered unless the application asked for it: it is a
    // remote command surface, not a diagnostic that costs nothing.
    #[test]
    fn no_console_channel_is_joined_unless_asked_for() {
        let plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let joined_console = shared.borrow().sent.iter().any(|frame| {
            let message = Message::decode(frame).unwrap();
            message.topic == "console" && message.event == "phx_join"
        });

        assert!(!joined_console);
    }

    // The mirror of the test above, and the one that was missing: feeding a
    // `dn` frame proves dispatch works, but the server only ever sends one to a
    // device that joined the channel.
    #[test]
    fn the_console_channel_is_joined_when_asked_for() {
        let plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console();
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let joined = shared.borrow().sent.iter().any(|frame| {
            let message = Message::decode(frame).unwrap();
            message.topic == "console" && message.event == "phx_join"
        });

        assert!(joined, "the console channel was never joined");
    }

    #[test]
    fn a_command_runs_and_its_output_comes_back() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("ping\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console().command("ping", "say pong", |_args, out| {
            write!(out, "pong")?;
            Ok(())
        });

        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let output = console_output(&shared);

        assert!(output.contains("pong"), "{output:?}");
        // Echoed, and followed by a prompt: it should read as a terminal.
        assert!(output.contains("ping"), "{output:?}");
        assert!(output.contains(console::PROMPT), "{output:?}");
    }

    #[test]
    fn arguments_reach_the_command() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("relay on now\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat)
            .with_console()
            .command("relay", "drive it", |args, out| {
                write!(out, "got {}", args.join("+"))?;
                Ok(())
            });

        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        assert!(console_output(&shared).contains("got on+now"));
    }

    // Silence is indistinguishable from a device that has stopped answering.
    #[test]
    fn an_unknown_command_says_so() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("wat\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console();
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let output = console_output(&shared);

        assert!(output.contains("unknown command"), "{output:?}");
        assert!(output.contains("help"), "{output:?}");
    }

    // A command that fails should report why rather than print nothing.
    #[test]
    fn a_failing_command_reports_its_error() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("boom\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console().command("boom", "fail", |_args, _out| {
            Err(Error::Console("the relay is stuck".into()))
        });

        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        assert!(console_output(&shared).contains("the relay is stuck"));
    }

    #[test]
    fn help_lists_what_can_be_typed() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("help\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat)
            .with_console()
            .command("relay", "drive the relay", |_args, out| {
                write!(out, "ok")?;
                Ok(())
            });

        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let output = console_output(&shared);

        for expected in ["relay", "drive the relay", "info", "uptime", "reboot", "log"] {
            assert!(output.contains(expected), "{expected} missing from {output:?}");
        }
    }

    // The upload half of the channel has no use here, and a UI waiting for an
    // acknowledgement it will never get looks like a device that has stopped.
    #[test]
    fn a_file_transfer_is_declined_rather_than_ignored() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            Ok(Some(
                r#"[null,null,"console","file-data/start",{"filename":"x"}]"#.to_string(),
            )),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console();
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        assert!(console_output(&shared).contains("not supported"));
    }

    #[test]
    fn reboot_from_the_console_restarts_the_device() {
        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            typed("reboot\r"),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat).with_console();
        let mut transport = agent.platform.connect(&config()).unwrap();

        assert_eq!(
            agent.session(&mut transport, &mut false).unwrap(),
            Some(Stopped::Rebooting)
        );
        assert_eq!(shared.borrow().restarts, 1);
        assert!(console_output(&shared).contains("rebooting"));
    }

    #[test]
    fn a_pending_image_is_confirmed_after_joining() {
        let mut plat = platform(vec![vec![join_reply(json!({"update_available": false}))]]);
        plat.pending = PendingVerify::Yes;
        let shared = Rc::clone(&plat.shared);

        // The socket then dies, so run() would loop forever; drive one session.
        let mut agent = agent(plat);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

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
        let _ = agent.session(&mut transport, &mut false);

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
        let _ = agent.session(&mut transport, &mut false);

        assert_eq!(shared.borrow().marked_valid, 0);
        assert!(events(&shared).contains(&"firmware_validated".to_string()));
    }

    // Extensions are joined on their own channel, and only after the device
    // channel is up: the platform decides what to attach from the device's
    // product, which it does not know until the device has identified itself.
    #[test]
    fn extensions_are_joined_after_the_device_channel() {
        use crate::extensions::{Enabled, HealthReport};

        struct FakeHealth;
        impl crate::extensions::HealthProvider for FakeHealth {
            fn report(&mut self) -> HealthReport {
                HealthReport::default().metric("mem_used_percent", 42.0)
            }
        }

        let mut cfg = config();
        cfg.extensions = Enabled::none().health();

        let plat = platform(vec![vec![
            join_reply(json!({"update_available": false})),
            // The extensions join reply: the platform attached health. Ref 3
            // because references run join(1), firmware_validated(2), then this
            // join — and the reply is only accepted if the reference matches,
            // so a stale reply cannot attach anything.
            Ok(Some(
                r#"["3","3","extensions","phx_reply",{"status":"ok","response":["health"]}]"#
                    .to_string(),
            )),
            // And then asks for a report.
            Ok(Some(r#"[null,null,"extensions","health:check",{}]"#.to_string())),
        ]]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = Agent::new(cfg, metadata(), plat, AlwaysApply).with_health(FakeHealth);
        let mut transport = agent.platform.connect(&config()).unwrap();
        let _ = agent.session(&mut transport, &mut false);

        let sent = shared.borrow().sent.clone();

        // Offered health, confirmed the attach, and answered the check.
        assert!(sent.iter().any(|f| f.contains("\"extensions\"") && f.contains("phx_join")));
        assert!(sent.iter().any(|f| f.contains("health:attached")));

        let report = sent.iter().find(|f| f.contains("health:report")).expect("no report sent");
        assert!(report.contains("mem_used_percent"));
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
                Duration::from_secs(5),
                // The session joined, so the backoff starts over rather than
                // carrying on from where the failures left it.
                Duration::from_secs(1),
            ]
        );
    }

    // A socket that opens and dies without ever joining is not progress, and
    // reconnecting on it at full speed is a device hammering a server that is
    // already in trouble. Observed on hardware as roughly two connections a
    // second, indefinitely.
    #[test]
    fn a_session_that_never_joins_backs_off() {
        // Four sockets that connect and immediately report a dead socket.
        let plat = platform(vec![
            vec![Err(Error::Transport("closed".into()))],
            vec![Err(Error::Transport("closed".into()))],
            vec![Err(Error::Transport("closed".into()))],
            vec![Err(Error::Transport("closed".into()))],
        ]);
        let shared = Rc::clone(&plat.shared);

        let mut agent = agent(plat);
        let _ = agent.run();

        assert_eq!(
            shared.borrow().slept,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(10),
            ]
        );
    }

    // A download used to own the loop for its whole duration, so nothing was
    // sent while an image came down. NervesHub's socket timeout is generous
    // enough that this fit by luck rather than design, and the margin shrinks
    // with every megabyte and every slow link.
    #[test]
    fn heartbeats_keep_flowing_while_an_image_downloads() {
        let image = vec![7u8; 4096 * 12];

        let update = json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": image.len(),
            "checksum": sha256_upper(&image)
        });

        let mut plat = platform(vec![vec![join_reply(update)]]);
        plat.image = image;
        // Each chunk advances the clock half a heartbeat interval.
        plat.clock_step_ms = 500;
        let shared = Rc::clone(&plat.shared);

        let mut config = config();
        config.heartbeat_interval_secs = 1;

        let mut agent = Agent::new(config, metadata(), plat, AlwaysApply);
        assert_eq!(agent.run().unwrap(), Stopped::Rebooting);

        let events = events(&shared);

        let first_progress = events
            .iter()
            .position(|event| event == "update_progress")
            .expect("no progress was reported");

        let finished = events
            .iter()
            .position(|event| event == "status_update")
            .expect("the update never completed");

        let beats = events[first_progress..finished]
            .iter()
            .filter(|event| *event == "heartbeat")
            .count();

        assert!(
            beats > 0,
            "no heartbeat between the first progress report and the end of the update: {events:?}"
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
        let _ = agent.session(&mut transport, &mut false);

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
        let _ = agent.session(&mut transport, &mut false);

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
