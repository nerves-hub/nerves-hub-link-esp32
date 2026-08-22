//! A debug terminal on the device, with a fixed set of commands.
//!
//! NervesHub can attach a terminal to a device. On Nerves the far end is an IEx
//! session, which is why it works there: something is already running that
//! takes text in and gives text back. An ESP32 has nothing equivalent, and
//! inventing one is not the interesting part of the problem.
//!
//! The channel does not care. It carries bytes both ways, and a fixed set of
//! commands is a legitimate thing to put on the far end. It answers the
//! question people actually have about a device on a roof -- what is it doing
//! -- without any of the machinery of a language.
//!
//! # Not arbitrary execution
//!
//! Every command is a Rust function compiled into the image. There is no eval
//! and no way to reach anything the firmware did not ship with. That is the
//! security property, and it is the reason to keep the vocabulary fixed even
//! when a general escape hatch would be convenient.
//!
//! NervesHub's support-scripts feature *does* ask a device to run supplied
//! code, and on devices reporting an older API it does so by typing that code
//! into this very channel. This agent reports a new enough version that scripts
//! arrive on the device channel instead, where they are declined. Anything
//! arriving here is treated as a command name and nothing else.
//!
//! # It is a terminal
//!
//! Typed characters are echoed and a prompt follows each command, because a
//! terminal that shows nothing while you type reads as broken rather than as
//! deliberate. The server also keeps about a thousand lines of scrollback per
//! device and replays it when someone attaches, so output is not wasted on an
//! empty room.

use core::fmt::Write;

/// What the device writes after each command, so the terminal looks like one.
pub const PROMPT: &str = "esp32> ";

/// The most one command may print.
///
/// A command that prints without limit floods the socket and fills the
/// server's scrollback with one device's opinion. Truncation is reported, so a
/// reader can tell the difference between a short answer and a cut-off one.
pub const MAX_OUTPUT: usize = 2048;

/// Where a command writes.
///
/// Bounded, and `core::fmt::Write` so `writeln!` works. Writing past the limit
/// is not an error -- a command should not have to handle a full buffer -- it
/// is simply dropped, and the truncation noted when the output is taken.
#[derive(Debug, Default)]
pub struct Output {
    text: String,
    truncated: bool,
}

impl Output {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The text, with a marker if anything was dropped.
    pub fn finish(mut self) -> String {
        if self.truncated {
            self.text.push_str("\r\n[output truncated]");
        }

        self.text
    }
}

impl Write for Output {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = MAX_OUTPUT.saturating_sub(self.text.len());

        if room == 0 {
            self.truncated = true;
            return Ok(());
        }

        if s.len() > room {
            // On a character boundary, so the result stays valid UTF-8.
            let mut cut = room;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }

            self.text.push_str(&s[..cut]);
            self.truncated = true;
        } else {
            self.text.push_str(s);
        }

        Ok(())
    }
}

/// Assembles the terminal's keystrokes into lines.
///
/// Input arrives as whatever chunks the transport produced, which is not
/// lines: a browser terminal sends a character at a time and `\r` for Enter,
/// while the REST API sends whole strings. Both end up here.
#[derive(Debug, Default)]
pub struct LineReader {
    line: String,
    /// Where we are in an escape sequence, which can span chunks.
    escape: Escape,
    /// A `\r` just ended a line, so an immediately following `\n` is the other
    /// half of the same Enter and not a second one.
    pending_newline: bool,
}

/// Terminals send arrow keys and the like as `ESC [ A`. The bracket and the
/// letter are ordinary printable characters, so without tracking the sequence
/// they end up in the command name and every command is unknown.
#[derive(Debug, Default, PartialEq, Eq)]
enum Escape {
    #[default]
    No,
    /// Saw `ESC`.
    Started,
    /// Saw `ESC [`; consuming until the final byte that ends it.
    Csi,
}

impl LineReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes; get back what to echo and any completed lines.
    ///
    /// Echo is built here rather than by the caller because it has to reflect
    /// what was *understood* -- a backspace echoes as erasing, an arrow key
    /// echoes as nothing -- and that is the same knowledge that assembles the
    /// line.
    pub fn feed(&mut self, data: &str) -> (String, Vec<String>) {
        let mut echo = String::new();
        let mut lines = Vec::new();

        for character in data.chars() {
            match self.escape {
                Escape::Started => {
                    self.escape = if character == '[' { Escape::Csi } else { Escape::No };
                    continue;
                }

                // A CSI sequence runs until a byte in 0x40..=0x7E.
                Escape::Csi => {
                    if ('\u{40}'..='\u{7e}').contains(&character) {
                        self.escape = Escape::No;
                    }
                    continue;
                }

                Escape::No => {}
            }

            let was_pending = core::mem::take(&mut self.pending_newline);

            match character {
                '\u{1b}' => self.escape = Escape::Started,

                '\n' if was_pending => {}

                '\r' | '\n' => {
                    self.pending_newline = character == '\r';
                    echo.push_str("\r\n");
                    lines.push(core::mem::take(&mut self.line));
                }

                // Backspace and delete. Erasing on the far end takes all three:
                // go back, overwrite with a space, go back again.
                '\u{8}' | '\u{7f}' => {
                    if self.line.pop().is_some() {
                        echo.push_str("\u{8} \u{8}");
                    }
                }

                // Anything else unprintable is dropped rather than allowed to
                // become part of a command name.
                c if c.is_control() => {}

                c => {
                    // A line long enough to be nonsense is dropped rather than
                    // grown without limit.
                    if self.line.len() < 256 {
                        self.line.push(c);
                        echo.push(c);
                    }
                }
            }
        }

        (echo, lines)
    }
}

/// Split a line into a command and its arguments.
///
/// Whitespace-separated, no quoting. Quoting is what a shell has, and the
/// point of this is that it is not one.
pub fn parse(line: &str) -> Option<(&str, Vec<&str>)> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?;

    Some((name, parts.collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(reader: &mut LineReader, data: &str) -> Vec<String> {
        reader.feed(data).1
    }

    // A browser terminal sends one character per frame.
    #[test]
    fn a_line_typed_one_character_at_a_time_arrives_whole() {
        let mut reader = LineReader::new();

        for chunk in ["h", "e", "a", "p"] {
            assert!(feed(&mut reader, chunk).is_empty());
        }

        assert_eq!(feed(&mut reader, "\r"), vec!["heap".to_string()]);
    }

    // The REST API sends whole strings, sometimes several lines of them.
    #[test]
    fn several_lines_in_one_chunk_all_arrive() {
        let mut reader = LineReader::new();

        assert_eq!(
            feed(&mut reader, "info\rheap\r"),
            vec!["info".to_string(), "heap".to_string()]
        );
    }

    // \r\n would otherwise submit twice, the second one empty.
    #[test]
    fn a_carriage_return_and_newline_together_are_one_line() {
        let mut reader = LineReader::new();

        assert_eq!(feed(&mut reader, "info\r\n"), vec!["info".to_string()]);
    }

    #[test]
    fn backspace_erases_and_says_so() {
        let mut reader = LineReader::new();

        let _ = reader.feed("hea");
        let (echo, _) = reader.feed("\u{8}");

        assert_eq!(echo, "\u{8} \u{8}");
        assert_eq!(feed(&mut reader, "\r"), vec!["he".to_string()]);
    }

    #[test]
    fn backspace_on_an_empty_line_does_nothing() {
        let mut reader = LineReader::new();

        let (echo, lines) = reader.feed("\u{8}");

        assert_eq!(echo, "");
        assert!(lines.is_empty());
    }

    // An arrow key is an escape sequence. Left in, it would become part of the
    // command name and every command would be unknown.
    #[test]
    fn escape_sequences_do_not_become_part_of_a_command() {
        let mut reader = LineReader::new();

        let _ = reader.feed("\u{1b}[Aheap");

        assert_eq!(feed(&mut reader, "\r"), vec!["heap".to_string()]);
    }

    #[test]
    fn a_line_is_not_allowed_to_grow_without_limit() {
        let mut reader = LineReader::new();

        let _ = reader.feed(&"x".repeat(1000));

        assert_eq!(feed(&mut reader, "\r")[0].len(), 256);
    }

    #[test]
    fn typing_is_echoed_back() {
        let mut reader = LineReader::new();

        assert_eq!(reader.feed("hi").0, "hi");
        assert_eq!(reader.feed("\r").0, "\r\n");
    }

    #[test]
    fn a_command_and_its_arguments_are_split_on_whitespace() {
        assert_eq!(parse("log debug"), Some(("log", vec!["debug"])));
        assert_eq!(parse("  heap  "), Some(("heap", vec![])));
        assert_eq!(parse("relay on now"), Some(("relay", vec!["on", "now"])));
    }

    #[test]
    fn an_empty_line_is_not_a_command() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
    }

    #[test]
    fn output_within_the_limit_is_returned_whole() {
        let mut out = Output::new();
        write!(out, "free 200000").unwrap();

        assert_eq!(out.finish(), "free 200000");
    }

    // A command should not have to handle a full buffer, so writing past the
    // limit succeeds and is reported once at the end.
    #[test]
    fn output_past_the_limit_is_cut_and_says_so() {
        let mut out = Output::new();

        for _ in 0..100 {
            write!(out, "{}", "x".repeat(100)).unwrap();
        }

        let text = out.finish();

        assert!(text.len() <= MAX_OUTPUT + 32);
        assert!(text.ends_with("[output truncated]"));
    }

    // Cutting mid-character would produce invalid UTF-8, which the JSON
    // encoder would then refuse.
    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let mut out = Output::new();
        write!(out, "{}", "é".repeat(MAX_OUTPUT)).unwrap();

        // Getting here at all means the string stayed valid.
        assert!(out.finish().ends_with("[output truncated]"));
    }
}

/// The commands that need ESP-IDF, kept together so `agent.rs` stays generic
/// over its platform and free of `unsafe`.
///
/// Each answers from something the agent already reads elsewhere: the same
/// heap figures it reports for health, the same partition states it reads to
/// notice a rollback, the same reset reason it sends with every health report.
/// A command needing new plumbing would be a feature wearing a command's
/// clothes.
#[cfg(target_os = "espidf")]
pub mod device {
    use super::Output;
    use crate::error::Error;
    use core::fmt::Write;

    pub fn heap(out: &mut Output) -> Result<(), Error> {
        use esp_idf_svc::sys;

        // SAFETY: all four are reads of allocator counters.
        let (total, free, min_free, largest) = unsafe {
            (
                sys::heap_caps_get_total_size(sys::MALLOC_CAP_INTERNAL),
                sys::esp_get_free_heap_size(),
                sys::esp_get_minimum_free_heap_size(),
                sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_INTERNAL),
            )
        };

        writeln!(out, "total     {total:>9}\r")?;
        writeln!(out, "free      {free:>9}\r")?;
        // Only ever falls, so a slow leak shows here as a slope while `free`
        // wanders.
        writeln!(out, "min free  {min_free:>9}   low-water mark\r")?;
        // Falls while `free` holds steady when the heap is fragmenting, which
        // is the failure where an allocation that used to work stops working.
        write!(out, "largest   {largest:>9}   largest single block")?;

        Ok(())
    }

    pub fn wifi(out: &mut Output) -> Result<(), Error> {
        use esp_idf_svc::sys;

        let mut info: sys::wifi_ap_record_t = unsafe { core::mem::zeroed() };

        // SAFETY: fails when the interface is down or unassociated, which is
        // not an error worth reporting -- it means there is no reading.
        if unsafe { sys::esp_wifi_sta_get_ap_info(&mut info) } != sys::ESP_OK {
            write!(out, "not associated")?;
            return Ok(());
        }

        let ssid = core::str::from_utf8(&info.ssid)
            .unwrap_or("<invalid>")
            .trim_end_matches('\0');

        writeln!(out, "ssid      {ssid}\r")?;
        writeln!(out, "rssi      {} dBm\r", info.rssi)?;
        write!(out, "channel   {}", info.primary)?;

        // SAFETY: the key is the one esp_netif registers the station under; a
        // null handle simply means there is no address to report.
        unsafe {
            let key = c"WIFI_STA_DEF";
            let netif = sys::esp_netif_get_handle_from_ifkey(key.as_ptr());

            if !netif.is_null() {
                let mut ip: sys::esp_netif_ip_info_t = core::mem::zeroed();

                if sys::esp_netif_get_ip_info(netif, &mut ip) == sys::ESP_OK {
                    let addr = ip.ip.addr.to_le_bytes();
                    write!(
                        out,
                        "\r\nip        {}.{}.{}.{}",
                        addr[0], addr[1], addr[2], addr[3]
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Which slot is running and what the bootloader thinks of the other.
    ///
    /// The reason this is worth a command: it separates "this device is on old
    /// firmware" from "this device tried the new firmware and the bootloader
    /// threw it out", which is otherwise only visible over a serial cable.
    pub fn partitions(out: &mut Output) -> Result<(), Error> {
        use esp_idf_svc::sys;

        // SAFETY: both return pointers into the flash-mapped partition table.
        unsafe {
            let running = sys::esp_ota_get_running_partition();
            let other = sys::esp_ota_get_next_update_partition(core::ptr::null());

            for (label, partition) in [("running", running), ("next", other)] {
                if partition.is_null() {
                    writeln!(out, "{label:<9} none\r")?;
                    continue;
                }

                let name = core::ffi::CStr::from_ptr((*partition).label.as_ptr())
                    .to_str()
                    .unwrap_or("?");

                write!(
                    out,
                    "{label:<9} {name:<8} at {:#08x}  {:>8} bytes  {}",
                    (*partition).address,
                    (*partition).size,
                    state_name(partition)
                )?;

                if label == "running" {
                    writeln!(out, "\r")?;
                }
            }
        }

        Ok(())
    }

    /// # Safety
    ///
    /// `partition` must be a valid partition pointer.
    unsafe fn state_name(partition: *const esp_idf_svc::sys::esp_partition_t) -> &'static str {
        use esp_idf_svc::sys;

        let mut state: sys::esp_ota_img_states_t = 0;

        if sys::esp_ota_get_state_partition(partition, &mut state) != sys::ESP_OK {
            return "state unknown";
        }

        match state {
            sys::esp_ota_img_states_t_ESP_OTA_IMG_NEW => "new",
            sys::esp_ota_img_states_t_ESP_OTA_IMG_PENDING_VERIFY => "pending verify",
            sys::esp_ota_img_states_t_ESP_OTA_IMG_VALID => "valid",
            // The one worth spotting: the bootloader rolled back from this.
            sys::esp_ota_img_states_t_ESP_OTA_IMG_INVALID => "INVALID, rolled back",
            sys::esp_ota_img_states_t_ESP_OTA_IMG_ABORTED => "aborted",
            _ => "undefined",
        }
    }

    pub fn reset_reason(out: &mut Output) -> Result<(), Error> {
        // SAFETY: reads a value latched at boot.
        let reason = unsafe { esp_idf_svc::sys::esp_reset_reason() };

        write!(out, "{}", crate::health::reset_reason_name(reason as u32))?;

        Ok(())
    }
}
