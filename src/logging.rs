//! Getting the device's own log out to NervesHub.
//!
//! The device already writes a log; the only thing missing is that nobody who
//! is not holding a USB cable can read it. This captures what the `log` crate
//! is given, keeps a bounded amount of it (by lines and by bytes), and hands it
//! to the agent to send over the logging extension.
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
//! and something has to give. So does one that logs a lot before it connects:
//! the queue is capped in bytes as well as lines, because the first TLS
//! handshake, the most memory the connection ever needs, comes while it is
//! full. New lines are dropped rather than old ones, because the first line of
//! a failure explains it and the hundredth repeats it, and the count of what
//! was lost is reported once the backlog clears.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "espidf")]
use std::sync::Arc;
use std::sync::Mutex;

use crate::extensions::LogLine;

/// How many lines are held while waiting for the connection.
///
/// A line holds more heap than its text: the line itself, and each of its
/// strings as an allocation of its own. Measured on an ESP32-C6, a backlog of
/// 64 ordinary lines held about 16 KB, which is why the bytes are capped as
/// well (see [`DEFAULT_MAX_BYTES`]).
pub const DEFAULT_CAPACITY: usize = 64;

/// How much heap the held lines may take, by default.
///
/// A device that waits a while before connecting reaches its first handshake
/// with a full backlog, and a TLS handshake is the most memory the connection
/// ever needs at once. Lines past this are dropped and counted, as lines past
/// the count are.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024;

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
    backlog: Mutex<Backlog>,
    capacity: usize,
    max_bytes: usize,
    dropped: AtomicUsize,
    /// The lowest level forwarded to NervesHub, as `log::Level as usize`.
    ///
    /// Shared rather than fixed at install so it can be raised for a few
    /// minutes and lowered again. Debug logging is unaffordable across a fleet
    /// and free on one device while someone watches it.
    threshold: AtomicUsize,
}

/// The held lines, and the heap they hold, under one lock.
struct Backlog {
    lines: VecDeque<LogLine>,
    bytes: usize,
}

impl Backlog {
    fn pop_front(&mut self) -> Option<LogLine> {
        let line = self.lines.pop_front()?;
        self.bytes = self.bytes.saturating_sub(heap_cost(&line));
        Some(line)
    }
}

impl LogBuffer {
    /// Up to `capacity` lines, and [`DEFAULT_MAX_BYTES`] of them.
    pub fn new(capacity: usize) -> Self {
        Self::with_threshold(capacity, log::Level::Info)
    }

    pub fn with_threshold(capacity: usize, threshold: log::Level) -> Self {
        Self {
            backlog: Mutex::new(Backlog {
                lines: VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY)),
                bytes: 0,
            }),
            capacity,
            max_bytes: DEFAULT_MAX_BYTES,
            dropped: AtomicUsize::new(0),
            threshold: AtomicUsize::new(threshold as usize),
        }
    }

    /// Hold at most this much heap in lines, rather than [`DEFAULT_MAX_BYTES`].
    pub fn max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
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
        let Ok(mut backlog) = self.backlog.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        let cost = heap_cost(&line);
        if backlog.lines.len() >= self.capacity || backlog.bytes + cost > self.max_bytes {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        backlog.bytes += cost;
        backlog.lines.push_back(line);
    }

    /// Whether a line could be queued now, counting it as lost if not, as
    /// [`push`](Self::push) would.
    ///
    /// For the logger to ask before it builds a line. Formatting the message
    /// and allocating the line's strings is most of what logging one costs,
    /// and a device offline long enough to fill the backlog would otherwise
    /// pay that on every call, only for `push` to throw the line away.
    ///
    /// It never refuses what `push` would take: no line costs less than the
    /// line itself, so a backlog without room for that has room for nothing.
    #[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
    fn has_room(&self) -> bool {
        let room = self.backlog.lock().is_ok_and(|backlog| {
            backlog.lines.len() < self.capacity
                && backlog.bytes + core::mem::size_of::<LogLine>() <= self.max_bytes
        });

        if !room {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }

        room
    }

    /// The next line to send, stamped if it was logged before the clock was.
    ///
    /// A line with no time is discarded by NervesHub without a reply, so an
    /// approximate time applied here is the difference between a boot-time log
    /// arriving late and not arriving.
    pub fn pop_stamped(&self, now_micros: Option<u64>) -> Option<LogLine> {
        Some(stamp(self.pop()?, now_micros))
    }

    /// Lines to send as one batch, oldest first, each stamped as
    /// [`pop_stamped`](Self::pop_stamped) stamps it -- except that lines
    /// stamped here are a microsecond apart, in order. They would otherwise
    /// all share one time, and NervesHub, which orders by time, would show a
    /// boot's worth of lines in no particular order.
    ///
    /// Stops at `max_lines`, or before the line that would take the batch past
    /// roughly `max_bytes` of JSON -- though never before the first, so a
    /// single long line still goes. The note about dropped lines joins the
    /// batch that empties the backlog, as it follows the last line `pop` does.
    pub fn take_stamped(&self, max_lines: usize, max_bytes: usize, now_micros: Option<u64>) -> Vec<LogLine> {
        let mut batch = Vec::new();
        let mut bytes = 0;

        {
            let Ok(mut backlog) = self.backlog.lock() else { return batch };

            while batch.len() < max_lines {
                let Some(next) = backlog.lines.front() else { break };

                let size = approximate_json_len(next);
                if !batch.is_empty() && bytes + size > max_bytes {
                    return batch;
                }

                bytes += size;
                if let Some(line) = backlog.pop_front() {
                    batch.push(stamp(line, now_micros.map(|t| t + batch.len() as u64)));
                }
            }
        }

        if batch.len() < max_lines {
            if let Some(note) = self.pop() {
                batch.push(stamp(note, now_micros.map(|t| t + batch.len() as u64)));
            }
        }

        batch
    }

    /// The next line to send, if there is one.
    ///
    /// The note about dropped lines comes last, once the backlog has cleared.
    /// Reporting it earlier would spend the device's rate limit describing the
    /// loss instead of sending what survived.
    pub fn pop(&self) -> Option<LogLine> {
        let mut backlog = self.backlog.lock().ok()?;

        if let Some(line) = backlog.pop_front() {
            return Some(line);
        }

        match self.dropped.swap(0, Ordering::Relaxed) {
            0 => None,
            n => Some(LogLine::new(
                "warning",
                format!("{n} log lines were dropped: the device logged more than it keeps waiting to send"),
            )),
        }
    }

    pub fn len(&self) -> usize {
        self.backlog.lock().map(|backlog| backlog.lines.len()).unwrap_or(0)
    }

    /// The heap the held lines take, as [`max_bytes`](Self::max_bytes) counts it.
    pub fn bytes(&self) -> usize {
        self.backlog.lock().map(|backlog| backlog.bytes).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lines lost since the last time the count was reported.
    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn stamp(line: LogLine, now_micros: Option<u64>) -> LogLine {
    match (line.has_time(), now_micros) {
        (false, Some(micros)) => line.with_time(micros),
        _ => line,
    }
}

/// The heap a held line takes: the line itself, as the queue stores it, and
/// the buffer behind each of its strings. The allocator's own few bytes per
/// allocation are left out.
fn heap_cost(line: &LogLine) -> usize {
    let strings = line.level.capacity()
        + line.message.capacity()
        + line.timestamp.as_ref().map_or(0, String::capacity)
        + line.meta.iter().map(|(key, value)| key.capacity() + value.capacity()).sum::<usize>();
    core::mem::size_of::<LogLine>() + line.meta.capacity() * core::mem::size_of::<(String, String)>() + strings
}

/// About what a line costs as JSON in a batch: its strings, plus the keys,
/// quotes and punctuation around them. Escaping can make it more, which is why
/// the budget it is checked against leaves room.
pub(crate) fn approximate_json_len(line: &LogLine) -> usize {
    let meta: usize = line.meta.iter().map(|(key, value)| key.len() + value.len() + 6).sum();
    let timestamp = line.timestamp.as_ref().map_or(0, |t| t.len() + 16);
    line.level.len() + line.message.len() + timestamp + meta + 40
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

        // Before the line is built, not after: building it is most of what it
        // costs, and a full backlog would only throw it away.
        if !self.buffer.has_room() {
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
    fn a_batch_takes_lines_oldest_first_up_to_the_count() {
        let buffer = LogBuffer::new(8);
        for message in ["one", "two", "three"] {
            buffer.push(line(message));
        }

        let batch = buffer.take_stamped(2, 10_000, None);

        assert_eq!(batch.iter().map(|l| l.message.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        assert_eq!(buffer.len(), 1);
    }

    // Each line NervesHub stores needs a time, and a batch is no exception.
    #[test]
    fn a_batch_is_stamped() {
        let buffer = LogBuffer::new(8);
        buffer.push(line("unstamped"));

        let batch = buffer.take_stamped(10, 10_000, Some(1_790_000_000_000_000));

        assert!(batch[0].has_time());
    }

    #[test]
    fn a_batch_stamps_its_lines_in_order() {
        let buffer = LogBuffer::new(8);
        buffer.push(line("first"));
        buffer.push(line("second"));

        let batch = buffer.take_stamped(10, 10_000, Some(1_000));
        let times: Vec<_> = batch
            .iter()
            .map(|l| l.meta.iter().find(|(k, _)| k == "time").unwrap().1.clone())
            .collect();

        assert_eq!(times, ["1000", "1001"]);
    }

    // A batch stays within one websocket frame, so the rest waits for the next.
    #[test]
    fn a_batch_stops_before_the_byte_budget() {
        let buffer = LogBuffer::new(8);
        buffer.push(line(&"a".repeat(100)));
        buffer.push(line(&"b".repeat(100)));

        let batch = buffer.take_stamped(10, 200, None);

        assert_eq!(batch.len(), 1);
        assert_eq!(buffer.len(), 1);
    }

    // Otherwise a line longer than the budget would never leave.
    #[test]
    fn a_batch_always_takes_its_first_line() {
        let buffer = LogBuffer::new(8);
        buffer.push(line(&"a".repeat(500)));

        assert_eq!(buffer.take_stamped(10, 100, None).len(), 1);
    }

    #[test]
    fn the_batch_that_clears_the_backlog_reports_the_loss() {
        let buffer = LogBuffer::new(1);
        buffer.push(line("kept"));
        buffer.push(line("lost"));

        let batch = buffer.take_stamped(10, 10_000, None);

        assert_eq!(batch.len(), 2);
        assert!(batch[1].message.contains("1 log lines were dropped"));
        assert!(buffer.take_stamped(10, 10_000, None).is_empty());
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

    // A device that connects late reaches its first TLS handshake with a full
    // backlog, so the heap the lines hold is capped as well as their count.
    #[test]
    fn lines_past_the_byte_cap_are_dropped_and_counted() {
        let cost = heap_cost(&line("x"));
        let buffer = LogBuffer::new(64).max_bytes(cost * 2);

        for _ in 0..3 {
            buffer.push(line("x"));
        }

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.bytes(), cost * 2);
        assert_eq!(buffer.dropped(), 1);
    }

    // The logger asks before it builds a line, so a device offline long enough
    // to fill the backlog stops paying for lines it cannot keep. They are
    // still counted, for the note that follows the backlog out.
    #[test]
    fn a_full_backlog_turns_a_line_away_before_it_is_built() {
        let buffer = LogBuffer::new(1);
        buffer.push(line("kept"));

        assert!(!buffer.has_room());
        assert_eq!(buffer.dropped(), 1);
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn a_backlog_full_of_bytes_turns_a_line_away_too() {
        let buffer = LogBuffer::new(64).max_bytes(heap_cost(&line("x")));
        buffer.push(line("x"));

        assert!(!buffer.has_room());
        assert_eq!(buffer.dropped(), 1);
    }

    // Asking first must never cost a line that `push` would have kept.
    #[test]
    fn room_for_the_smallest_line_is_room_enough_to_ask() {
        let buffer = LogBuffer::new(64).max_bytes(heap_cost(&line("x")));

        assert!(buffer.has_room());
        assert_eq!(buffer.dropped(), 0);

        buffer.push(line("x"));
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn a_line_sent_gives_its_bytes_back() {
        let buffer = LogBuffer::new(8);
        buffer.push(line("one"));
        buffer.push(line("two"));

        let _ = buffer.take_stamped(1, 10_000, Some(1_790_000_000_000_000));
        assert_eq!(buffer.bytes(), heap_cost(&line("two")));

        let _ = buffer.pop();
        assert_eq!(buffer.bytes(), 0);
    }

    // What a line holds is more than its text: the line, and every string.
    #[test]
    fn a_lines_cost_counts_all_of_its_strings() {
        let bare = heap_cost(&line("message"));
        let with_meta = heap_cost(&line("message").meta("target", "app"));

        assert!(bare > "info".len() + "message".len());
        assert!(with_meta >= bare + "target".len() + "app".len());
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
