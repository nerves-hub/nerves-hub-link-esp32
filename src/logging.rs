//! Getting the device's own log out to NervesHub.
//!
//! The device already writes a log; the only thing missing is that nobody who
//! is not holding a USB cable can read it. This captures what the `log` crate
//! is given, keeps a bounded amount of it, and hands it to the agent to send
//! over the logging extension.
//!
//! ```ignore
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # use nerves_hub_link_esp32::{esp, AlwaysApply, Config, Credentials};
//! # use nerves_hub_link_esp32::extensions::Enabled;
//! use log::{Level, LevelFilter};
//! use nerves_hub_link_esp32::logging;
//!
//! // Instead of EspLogger::initialize_default(): same output on the serial
//! // console, plus a copy of anything at `Level::Info` or worse kept for
//! // NervesHub.
//! let logs = logging::install(LevelFilter::Info, Level::Info);
//!
//! # let credentials = Credentials::shared_secret("device-1", "nhp_key", "secret");
//! # let mut config = Config::new("hub.example.test", credentials);
//! config.extensions = Enabled::none().logging();
//!
//! esp::agent_with(config, AlwaysApply)?.with_logs(logs).run()?;
//! # Ok(())
//! # }
//! ```
//!
//! # What it does not capture
//!
//! ESP-IDF's own C logging -- WiFi, the websocket client, the bootloader --
//! goes to the console through `esp_log_write` and never reaches the `log`
//! crate, so none of it appears here. Capturing it means replacing the IDF's
//! `vprintf` hook, which is a variadic C callback: `vsnprintf` is not in the
//! bindings and `va_list` comes through as an opaque array, so it would be
//! hand-written FFI whose failure mode is a device that panics in its logger.
//! That is worth doing deliberately, not as a side-effect of wanting logs.
//!
//! Everything this crate logs -- the connection lifecycle, closes, reverts,
//! update progress, extension failures -- is Rust and does arrive.
//!
//! # Losing lines on purpose
//!
//! NervesHub rate limits log traffic per device, so the connection drains this
//! queue slowly by design. A device that logs faster than that fills the queue,
//! and something has to give. New lines are dropped rather than old ones,
//! because the first line of a failure explains it and the hundredth repeats
//! it, and the count of what was lost is reported once the backlog clears.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "espidf")]
use std::sync::Arc;
use std::sync::Mutex;

use crate::extensions::LogLine;

/// How many lines are held while waiting for the connection.
///
/// At roughly a hundred bytes a line this is a few kilobytes, which is a real
/// amount of an ESP32's heap but small next to what a websocket already costs.
pub const DEFAULT_CAPACITY: usize = 64;

/// The level names NervesHub stores.
///
/// `warning` rather than `warn`, matching what Elixir devices send, so that one
/// fleet does not need two spellings of the same level. Rust's `Trace` has no
/// counterpart and is reported as `debug`.
pub fn level_name(level: log::Level) -> &'static str {
    match level {
        log::Level::Error => "error",
        log::Level::Warn => "warning",
        log::Level::Info => "info",
        log::Level::Debug | log::Level::Trace => "debug",
    }
}

/// Wall-clock microseconds since the epoch, or `None` before the clock is set.
///
/// An ESP32 boots believing it is 1970 and stays there until SNTP runs, so
/// "the clock has been set" is really "the year is plausible". Anything before
/// 2020 is taken as unset: a line stamped 1970 sorts to the beginning of the
/// device's history forever, which is worse than one stamped a few seconds
/// late.
pub fn unix_micros() -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // 2020-01-01T00:00:00Z.
    const PLAUSIBLE: u64 = 1_577_836_800_000_000;

    let micros = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_micros() as u64;

    (micros >= PLAUSIBLE).then_some(micros)
}

/// A bounded queue of log lines waiting to be sent.
///
/// Shared between whatever is logging and the agent that drains it, so all of
/// it is behind a lock and none of it allocates while holding one longer than
/// a push.
pub struct LogBuffer {
    lines: Mutex<VecDeque<LogLine>>,
    capacity: usize,
    dropped: AtomicUsize,
    /// The lowest level forwarded to NervesHub, as `log::Level as usize`.
    ///
    /// Shared rather than fixed at install so it can be raised for a few
    /// minutes and lowered again. Debug logging is unaffordable across a fleet
    /// and free on one device while someone watches it.
    threshold: AtomicUsize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::with_threshold(capacity, log::Level::Info)
    }

    pub fn with_threshold(capacity: usize, threshold: log::Level) -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY))),
            capacity,
            dropped: AtomicUsize::new(0),
            threshold: AtomicUsize::new(threshold as usize),
        }
    }

    /// The lowest level currently forwarded to NervesHub.
    pub fn level(&self) -> log::Level {
        match self.threshold.load(Ordering::Relaxed) {
            n if n == log::Level::Error as usize => log::Level::Error,
            n if n == log::Level::Warn as usize => log::Level::Warn,
            n if n == log::Level::Info as usize => log::Level::Info,
            n if n == log::Level::Debug as usize => log::Level::Debug,
            _ => log::Level::Trace,
        }
    }

    /// Change what is forwarded, from now on.
    ///
    /// Only affects what is kept for NervesHub. The console keeps whatever
    /// `install` set as the maximum, so raising this past that maximum reports
    /// nothing new -- there is nothing there to forward.
    pub fn set_level(&self, level: log::Level) {
        self.threshold.store(level as usize, Ordering::Relaxed);
    }

    /// Queue a line, or count it as lost.
    ///
    /// Never blocks and never fails: this runs inside a logging call, and a
    /// logger that can panic or deadlock is worse than one that loses a line.
    /// A poisoned lock is treated as a full queue for the same reason.
    pub fn push(&self, line: LogLine) {
        let Ok(mut lines) = self.lines.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        if lines.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        lines.push_back(line);
    }

    /// The next line to send, stamped if it was logged before the clock was.
    ///
    /// A line with no time is discarded by NervesHub without a reply, so an
    /// approximate time applied here is the difference between a boot-time log
    /// arriving late and not arriving.
    pub fn pop_stamped(&self, now_micros: Option<u64>) -> Option<LogLine> {
        let line = self.pop()?;

        Some(match (line.has_time(), now_micros) {
            (false, Some(micros)) => line.with_time(micros),
            _ => line,
        })
    }

    /// The next line to send, if there is one.
    ///
    /// The note about dropped lines comes last, once the backlog has cleared.
    /// Reporting it earlier would spend the device's rate limit describing the
    /// loss instead of sending what survived.
    pub fn pop(&self) -> Option<LogLine> {
        let mut lines = self.lines.lock().ok()?;

        if let Some(line) = lines.pop_front() {
            return Some(line);
        }

        match self.dropped.swap(0, Ordering::Relaxed) {
            0 => None,
            n => Some(LogLine::new(
                "warning",
                format!("{n} log lines were dropped: the device logged faster than NervesHub accepts"),
            )),
        }
    }

    pub fn len(&self) -> usize {
        self.lines.lock().map(|lines| lines.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lines lost since the last time the count was reported.
    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A `log::Log` that writes to the console as before and keeps a copy.
#[cfg(target_os = "espidf")]
struct Capture {
    inner: esp_idf_svc::log::EspIdfLogger,
    buffer: Arc<LogBuffer>,
}

#[cfg(target_os = "espidf")]
impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        // The console first, and unconditionally: someone on a serial cable
        // should see exactly what they saw before this was installed.
        self.inner.log(record);

        if record.level() > self.buffer.level() {
            return;
        }

        let line = LogLine::new(level_name(record.level()), record.args().to_string())
            .meta("target", record.target());

        // Stamped when it happened, not when it is sent, so a backlog drains
        // with the times it was written at. Lines from before the clock was set
        // go out unstamped and are stamped on the way out -- late, but kept.
        // NervesHub discards a line with no time at all.
        self.buffer.push(match unix_micros() {
            Some(micros) => line.with_time(micros),
            None => line,
        });
    }

    fn flush(&self) {
        self.inner.flush()
    }
}

/// Install the capturing logger, and return the buffer to hand to the agent.
///
/// Replaces `EspLogger::initialize_default()` -- the `log` crate allows one
/// logger, so this has to be the one. Console output is unchanged.
///
/// `max_level` is what gets logged at all; `send_from` is what is additionally
/// kept for NervesHub. Keeping them apart is the point: a device can log at
/// debug over the serial cable while sending only warnings and errors over a
/// connection that is rate limited and possibly metered.
#[cfg(target_os = "espidf")]
pub fn install(max_level: log::LevelFilter, send_from: log::Level) -> Arc<LogBuffer> {
    install_with_capacity(max_level, send_from, DEFAULT_CAPACITY)
}

#[cfg(target_os = "espidf")]
pub fn install_with_capacity(
    max_level: log::LevelFilter,
    send_from: log::Level,
    capacity: usize,
) -> Arc<LogBuffer> {
    let buffer = Arc::new(LogBuffer::with_threshold(capacity, send_from));

    let capture = Capture {
        inner: esp_idf_svc::log::EspIdfLogger::new(()),
        buffer: Arc::clone(&buffer),
    };

    // A second call would fail, and an application that already installed a
    // logger has made a choice worth keeping. It still gets a working buffer;
    // it will simply stay empty.
    if log::set_boxed_logger(Box::new(capture)).is_ok() {
        log::set_max_level(max_level);
    } else {
        // Whatever logger is already installed keeps working, so the console is
        // unaffected and the failure is otherwise invisible -- the buffer just
        // never fills and no logs ever reach NervesHub. Worth saying out loud.
        log::warn!("a logger was already installed; device logs will not reach NervesHub");
    }

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(message: &str) -> LogLine {
        LogLine::new("info", message)
    }

    #[test]
    fn lines_come_back_in_the_order_they_were_logged() {
        let buffer = LogBuffer::new(4);
        buffer.push(line("first"));
        buffer.push(line("second"));

        assert_eq!(buffer.pop().unwrap().message, "first");
        assert_eq!(buffer.pop().unwrap().message, "second");
        assert!(buffer.pop().is_none());
    }

    // The first line of a failure explains it; the hundredth repeats it.
    #[test]
    fn a_full_buffer_keeps_the_oldest_lines() {
        let buffer = LogBuffer::new(2);
        buffer.push(line("first"));
        buffer.push(line("second"));
        buffer.push(line("third"));

        assert_eq!(buffer.pop().unwrap().message, "first");
        assert_eq!(buffer.pop().unwrap().message, "second");
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn the_loss_is_reported_once_the_backlog_clears() {
        let buffer = LogBuffer::new(1);
        buffer.push(line("kept"));
        buffer.push(line("lost"));
        buffer.push(line("also lost"));

        assert_eq!(buffer.pop().unwrap().message, "kept");

        let note = buffer.pop().unwrap();
        assert_eq!(note.level, "warning");
        assert!(note.message.contains("2 log lines were dropped"));

        // Reported once, not on every poll after.
        assert!(buffer.pop().is_none());
        assert_eq!(buffer.dropped(), 0);
    }

    #[test]
    fn nothing_is_reported_when_nothing_was_lost() {
        let buffer = LogBuffer::new(4);
        assert!(buffer.pop().is_none());
        assert_eq!(buffer.dropped(), 0);
    }

    // NervesHub and the Elixir devices spell it "warning".
    // NervesHub requires a time and does not add one: an unstamped line is
    // dropped server-side without a reply, so the device never learns that its
    // logs are going nowhere. This is the guard against shipping that again.
    #[test]
    fn a_line_logged_before_the_clock_was_set_is_stamped_on_the_way_out() {
        let buffer = LogBuffer::new(4);
        buffer.push(line("logged at boot"));

        let sent = buffer.pop_stamped(Some(1_700_000_000_000_000)).unwrap();

        assert!(sent.has_time());
        assert_eq!(
            sent.payload()["meta"]["time"],
            serde_json::json!("1700000000000000")
        );
    }

    #[test]
    fn a_line_that_was_already_stamped_keeps_its_own_time() {
        let buffer = LogBuffer::new(4);
        buffer.push(line("logged after sntp").with_time(1_700_000_000_000_000));

        let sent = buffer.pop_stamped(Some(1_800_000_000_000_000)).unwrap();

        assert_eq!(
            sent.payload()["meta"]["time"],
            serde_json::json!("1700000000000000")
        );
    }

    #[test]
    fn levels_are_named_the_way_the_platform_names_them() {
        assert_eq!(level_name(log::Level::Error), "error");
        assert_eq!(level_name(log::Level::Warn), "warning");
        assert_eq!(level_name(log::Level::Info), "info");
        assert_eq!(level_name(log::Level::Debug), "debug");
        assert_eq!(level_name(log::Level::Trace), "debug");
    }
}
