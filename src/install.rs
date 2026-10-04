//! Downloading an image and writing it to the inactive slot.
//!
//! The download and the flash write are one pass: an ESP32 has far less RAM
//! than a firmware image, so there is nowhere to buffer it.
//!
//! Both the network and the flash are behind traits, which is what lets the
//! part that actually has decisions in it — checksum verification, size
//! checking, when to report progress, and crucially *not* committing a bad
//! image — run under `cargo test` on the host. The device supplies
//! `EspHttpStream` and `OtaWriter`; the tests supply fakes.

use core::time::Duration;

use crate::checksum::{self, Sha256};
use crate::error::Error;
use crate::update::{ProgressThrottle, Stage, UpdatePayload};

/// Read size. Large enough that flash writes are not dominated by per-call
/// overhead, small enough to sit comfortably in RAM alongside TLS buffers.
pub const CHUNK_SIZE: usize = 4096;

/// The waits before each retry of a download that couldn't start: three
/// retries, the last a little over a minute after the first attempt.
///
/// Long enough for storage that answered `503` to have recovered, or a cell
/// that dropped the connection to have it back; short enough that a device
/// gives up and says so while whoever pushed the update is still watching.
const RETRY_WAITS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(45),
];

/// The longest a server's `Retry-After` is waited for. Asking for longer is
/// treated as asking for this, and if that doesn't do, the failure goes to
/// NervesHub to offer the update again later.
const RETRY_AFTER_MAX: Duration = Duration::from_secs(120);

/// A GET that can be read incrementally.
pub trait HttpStream {
    /// Open the URL and return the content length, if the server gave one.
    ///
    /// NervesHub firmware URLs are pre-signed and redirect to object storage,
    /// so an implementation **must** follow redirects.
    fn open(&mut self, url: &str) -> Result<Option<u64>, Error>;

    /// Read into `buf`, returning the number of bytes. `0` means EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/// Somewhere to put an image.
/// What the caller is told while an image is coming down.
///
/// Two methods rather than one closure because a download is long enough that
/// the connection needs attention during it, and that attention is wanted far
/// more often than a progress report is. `tick` runs after every chunk;
/// `report` only when progress crosses the configured step.
///
/// A closure still works where only reporting is wanted -- see the blanket
/// implementation below -- which is what the tests use.
pub trait Progress {
    /// After every chunk written.
    ///
    /// The download otherwise owns the agent for its whole duration: no
    /// heartbeats sent, no logs drained. Returning an error abandons the
    /// download, which is what should happen when the connection has gone --
    /// there is no point writing another megabyte to a slot nobody will be
    /// told about.
    fn tick(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// When progress crosses the reporting step.
    fn report(&mut self, stage: Stage, percent: u8) -> Result<(), Error>;

    /// Before another try at a download that couldn't start, for `duration`.
    ///
    /// The default sleeps. The agent instead spends the time as it spends a
    /// download's, sending heartbeats and logs, and as with `tick`, returning
    /// an error abandons the download.
    fn wait(&mut self, duration: Duration) -> Result<(), Error> {
        std::thread::sleep(duration);
        Ok(())
    }
}

impl<F> Progress for F
where
    F: FnMut(Stage, u8) -> Result<(), Error>,
{
    fn report(&mut self, stage: Stage, percent: u8) -> Result<(), Error> {
        self(stage, percent)
    }
}

pub trait ImageSink {
    fn write(&mut self, chunk: &[u8]) -> Result<(), Error>;

    /// Make what was written bootable. Only called once the image is verified.
    fn commit(&mut self) -> Result<(), Error>;

    /// Discard what was written. Must leave the current image bootable.
    fn abort(&mut self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub bytes: u64,
    pub checksum: String,
}

/// Download an update and commit it to the inactive slot.
///
/// On any failure the sink is aborted, so a partial or corrupt image is never
/// left bootable. Returns once the image is committed — the caller reboots.
pub fn install<H, S, P>(
    update: &UpdatePayload,
    http: &mut H,
    sink: &mut S,
    progress_step_percent: u8,
    on_progress: &mut P,
) -> Result<InstallReport, Error>
where
    H: HttpStream,
    S: ImageSink,
    P: Progress,
{
    let Some((url, _uuid)) = update.actionable() else {
        return Err(Error::Download("update has no firmware url".into()));
    };

    match download(update, url, http, sink, progress_step_percent, on_progress) {
        Ok(report) => {
            // Commit last, and only after the checksum matched. Rollback would
            // catch a corrupt image, but at the cost of two reboots and it
            // would look like a bad build rather than a bad transfer.
            sink.commit()?;
            Ok(report)
        }
        Err(err) => {
            sink.abort();
            Err(err)
        }
    }
}

fn download<H, S, P>(
    update: &UpdatePayload,
    url: &str,
    http: &mut H,
    sink: &mut S,
    progress_step_percent: u8,
    on_progress: &mut P,
) -> Result<InstallReport, Error>
where
    H: HttpStream,
    S: ImageSink,
    P: Progress,
{
    let content_length = open(url, http, on_progress)?;

    // Prefer what NervesHub told us over what the CDN claims: the deployment's
    // size is the value the checksum belongs to.
    let expected_size = update.size.or(content_length);

    let mut throttle = ProgressThrottle::new(progress_step_percent);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; CHUNK_SIZE];
    let mut written: u64 = 0;

    loop {
        let read = http.read(&mut buf)?;

        if read == 0 {
            break;
        }

        let chunk = &buf[..read];
        hasher.update(chunk);
        sink.write(chunk)?;
        written += read as u64;

        // Between chunks rather than between progress reports: reporting is
        // throttled to a few dozen times across a whole image, and a heartbeat
        // that arrives a few dozen times across ninety seconds is not a
        // heartbeat.
        on_progress.tick()?;

        if let Some(total) = expected_size {
            // A server that sends more than it promised is not something to
            // keep writing into a flash partition.
            if written > total {
                return Err(Error::Download(format!(
                    "image is longer than the expected {total} bytes"
                )));
            }

            if let Some(percent) = throttle.take(written, total) {
                on_progress.report(Stage::Downloading, percent)?;
            }
        }
    }

    if let Some(total) = expected_size {
        if written != total {
            return Err(Error::Download(format!(
                "expected {total} bytes, received {written}"
            )));
        }
    }

    if written == 0 {
        return Err(Error::Download("image was empty".into()));
    }

    let actual = hasher.finalize_hex_upper();

    if let Some(expected) = update.checksum.as_deref() {
        if !checksum::matches(expected, &actual) {
            return Err(Error::ChecksumMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
    }

    Ok(InstallReport {
        bytes: written,
        checksum: actual,
    })
}

/// Open the image's URL, trying again if it couldn't be opened for a reason
/// that may pass.
///
/// Only opening is retried. Once bytes have reached the slot, starting again
/// means downloading the image from the top (see "Resumable downloads" in the
/// README), and whether that is worth it is NervesHub's call: the failure is
/// reported, and the deployment offers the update again.
///
/// The error returned is the last attempt's, so what NervesHub records is
/// what was still wrong when the device gave up.
fn open<H, P>(url: &str, http: &mut H, on_progress: &mut P) -> Result<Option<u64>, Error>
where
    H: HttpStream,
    P: Progress,
{
    let mut waits = RETRY_WAITS.iter();

    loop {
        let err = match http.open(url) {
            Ok(content_length) => return Ok(content_length),
            Err(err) => err,
        };

        let Some(&backoff) = waits.next().filter(|_| worth_retrying(&err)) else {
            return Err(err);
        };

        // The server's word as a minimum, not instead of the backoff: a
        // `Retry-After: 0` from storage that is still failing would otherwise
        // spend every retry in a second.
        let wait = match err {
            Error::DownloadStatus {
                retry_after_secs: Some(secs),
                ..
            } => backoff.max(Duration::from_secs(secs).min(RETRY_AFTER_MAX)),
            _ => backoff,
        };

        log::warn!("{err}; trying again in {} s", wait.as_secs());
        on_progress.wait(wait)?;
    }
}

/// Whether a download that couldn't start may start if tried again.
fn worth_retrying(err: &Error) -> bool {
    match err {
        // No connection, no address, a handshake or a response that didn't
        // arrive: the network, which comes and goes.
        Error::Download(_) => true,
        // Timed out, rate-limited, or the server failing. Not a `403` (the
        // pre-signed URL expired, and a retry asks with the same one) or a
        // `404`, which no amount of asking will change.
        Error::DownloadStatus { status, .. } => matches!(status, 408 | 429 | 500..=599),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Serves a fixed body, optionally failing to open or partway through.
    struct FakeHttp {
        body: Vec<u8>,
        position: usize,
        content_length: Option<u64>,
        fail_after: Option<usize>,
        /// What the next opens fail with, in order, before one succeeds.
        open_failures: Vec<Error>,
        opened: Vec<String>,
    }

    impl FakeHttp {
        fn new(body: &[u8]) -> Self {
            Self {
                body: body.to_vec(),
                position: 0,
                content_length: Some(body.len() as u64),
                fail_after: None,
                open_failures: vec![],
                opened: vec![],
            }
        }

        fn failing_to_open(mut self, errors: Vec<Error>) -> Self {
            self.open_failures = errors;
            self
        }

        fn without_content_length(mut self) -> Self {
            self.content_length = None;
            self
        }

        fn failing_after(mut self, bytes: usize) -> Self {
            self.fail_after = Some(bytes);
            self
        }
    }

    impl HttpStream for FakeHttp {
        fn open(&mut self, url: &str) -> Result<Option<u64>, Error> {
            self.opened.push(url.to_string());

            if !self.open_failures.is_empty() {
                return Err(self.open_failures.remove(0));
            }

            Ok(self.content_length)
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            if let Some(limit) = self.fail_after {
                if self.position >= limit {
                    return Err(Error::Download("connection reset".into()));
                }
            }

            // Deliberately small reads, so multi-chunk paths are exercised.
            let remaining = self.body.len() - self.position;
            let take = remaining.min(buf.len()).min(64);

            buf[..take].copy_from_slice(&self.body[self.position..self.position + take]);
            self.position += take;

            Ok(take)
        }
    }

    #[derive(Default)]
    struct FakeSink {
        written: Vec<u8>,
        committed: bool,
        aborted: bool,
        fail_on_write: bool,
    }

    impl ImageSink for FakeSink {
        fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
            if self.fail_on_write {
                return Err(Error::Ota("flash write failed".into()));
            }
            self.written.extend_from_slice(chunk);
            Ok(())
        }

        fn commit(&mut self) -> Result<(), Error> {
            self.committed = true;
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
        }
    }

    fn image() -> Vec<u8> {
        (0..5000u32).map(|i| (i % 251) as u8).collect()
    }

    fn sha256_upper(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize_hex_upper()
    }

    fn update_for(body: &[u8], checksum: Option<String>) -> UpdatePayload {
        let mut value = json!({
            "update_available": true,
            "firmware_url": "https://example.test/fw.bin",
            "firmware_meta": {"uuid": "uuid-1"},
            "size": body.len(),
        });

        if let Some(checksum) = checksum {
            value["checksum"] = json!(checksum);
        }

        UpdatePayload::parse(&value).unwrap()
    }

    fn run(
        update: &UpdatePayload,
        http: &mut FakeHttp,
        sink: &mut FakeSink,
    ) -> (Result<InstallReport, Error>, Vec<(Stage, u8)>) {
        let mut seen = vec![];

        let result = install(update, http, sink, 5, &mut |stage, percent| {
            seen.push((stage, percent));
            Ok(())
        });

        (result, seen)
    }

    /// Notes each wait between attempts, and takes no time over it.
    #[derive(Default)]
    struct Watcher {
        waits: Vec<Duration>,
        /// The connection to NervesHub has gone, as a heartbeat would find.
        gone: bool,
    }

    impl Progress for Watcher {
        fn report(&mut self, _stage: Stage, _percent: u8) -> Result<(), Error> {
            Ok(())
        }

        fn wait(&mut self, duration: Duration) -> Result<(), Error> {
            self.waits.push(duration);

            if self.gone {
                return Err(Error::Transport("link dropped".into()));
            }

            Ok(())
        }
    }

    fn status(status: u16, retry_after_secs: Option<u64>) -> Error {
        Error::DownloadStatus {
            status,
            retry_after_secs,
        }
    }

    fn secs(waits: &[u64]) -> Vec<Duration> {
        waits.iter().map(|&s| Duration::from_secs(s)).collect()
    }

    #[test]
    fn writes_the_whole_image_and_commits() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());

        let (result, _) = run(&update, &mut http, &mut sink);
        let report = result.unwrap();

        assert_eq!(report.bytes, body.len() as u64);
        assert_eq!(sink.written, body);
        assert!(sink.committed);
        assert!(!sink.aborted);
        assert_eq!(http.opened, vec!["https://example.test/fw.bin"]);
    }

    // The whole point of verifying before committing: a corrupt download must
    // not become the boot partition.
    #[test]
    fn a_bad_checksum_aborts_without_committing() {
        let body = image();
        let update = update_for(&body, Some("00".repeat(32)));
        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());

        let (result, _) = run(&update, &mut http, &mut sink);

        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
        assert!(!sink.committed);
        assert!(sink.aborted);
    }

    #[test]
    fn a_truncated_download_aborts_without_committing() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let (mut http, mut sink) = (
            FakeHttp::new(&body).failing_after(1000),
            FakeSink::default(),
        );

        let (result, _) = run(&update, &mut http, &mut sink);

        assert!(matches!(result, Err(Error::Download(_))));
        assert!(!sink.committed);
        assert!(sink.aborted);
    }

    #[test]
    fn a_short_image_is_rejected_even_with_a_clean_stream() {
        let body = image();
        // Server closes early but reports success.
        let mut update = update_for(&body, None);
        update.size = Some(body.len() as u64 + 100);

        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());
        let (result, _) = run(&update, &mut http, &mut sink);

        match result {
            Err(Error::Download(msg)) => assert!(msg.contains("received"), "{msg}"),
            other => panic!("expected a size error, got {other:?}"),
        }
        assert!(sink.aborted);
    }

    #[test]
    fn an_overlong_image_is_rejected() {
        let body = image();
        let mut update = update_for(&body, None);
        update.size = Some(100);

        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());
        let (result, _) = run(&update, &mut http, &mut sink);

        match result {
            Err(Error::Download(msg)) => assert!(msg.contains("longer than"), "{msg}"),
            other => panic!("expected a size error, got {other:?}"),
        }
        assert!(sink.aborted);
    }

    #[test]
    fn a_flash_failure_aborts() {
        let body = image();
        let update = update_for(&body, None);
        let mut sink = FakeSink {
            fail_on_write: true,
            ..Default::default()
        };

        let (result, _) = run(&update, &mut FakeHttp::new(&body), &mut sink);

        assert!(matches!(result, Err(Error::Ota(_))));
        assert!(sink.aborted);
        assert!(!sink.committed);
    }

    #[test]
    fn progress_is_reported_and_ends_at_100() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());

        let (result, seen) = run(&update, &mut http, &mut sink);
        assert!(result.is_ok());

        assert!(seen.iter().all(|(stage, _)| *stage == Stage::Downloading));
        assert_eq!(seen.last().map(|(_, percent)| *percent), Some(100));

        // Throttled, not one message per chunk.
        assert!(
            seen.len() < body.len() / CHUNK_SIZE + 30,
            "{} reports",
            seen.len()
        );
    }

    // NervesHub always sends `size`, but a device should not fall over if a
    // future payload omits it and the CDN declines to say either.
    #[test]
    fn works_without_any_size_information() {
        let body = image();
        let mut update = update_for(&body, Some(sha256_upper(&body)));
        update.size = None;

        let mut http = FakeHttp::new(&body).without_content_length();
        let mut sink = FakeSink::default();

        let (result, seen) = run(&update, &mut http, &mut sink);

        assert!(result.is_ok());
        assert!(sink.committed);
        // Nothing to compute a percentage from.
        assert!(seen.is_empty());
    }

    #[test]
    fn an_empty_image_is_rejected() {
        let update = update_for(&[], None);
        let (mut http, mut sink) = (FakeHttp::new(&[]), FakeSink::default());

        let (result, _) = run(&update, &mut http, &mut sink);

        assert!(matches!(result, Err(Error::Download(_))));
        assert!(!sink.committed);
    }

    #[test]
    fn a_payload_with_nothing_to_download_is_an_error_not_a_commit() {
        let update = UpdatePayload::parse(&json!({"update_available": false})).unwrap();
        let (mut http, mut sink) = (FakeHttp::new(b"x"), FakeSink::default());

        let (result, _) = run(&update, &mut http, &mut sink);

        assert!(matches!(result, Err(Error::Download(_))));
        assert!(!sink.committed);
        assert!(!sink.aborted);
    }

    // Storage that is busy for a moment shouldn't cost an update.
    #[test]
    fn a_busy_server_is_asked_again_after_a_wait() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let mut http =
            FakeHttp::new(&body).failing_to_open(vec![status(503, None), status(503, None)]);
        let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(http.opened.len(), 3);
        assert_eq!(watcher.waits, secs(&[5, 15]));
        assert_eq!(sink.written, body);
        assert!(sink.committed);
    }

    #[test]
    fn a_connection_that_fails_is_tried_again() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let mut http = FakeHttp::new(&body)
            .failing_to_open(vec![Error::Download("ESP_ERR_HTTP_CONNECT".into())]);
        let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(watcher.waits, secs(&[5]));
        assert!(sink.committed);
    }

    // Longer than the backoff when the server asks for longer; never past the
    // cap; and never shorter than the backoff, even when it asks for nothing.
    #[test]
    fn retry_after_is_waited_for_within_limits() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let mut http = FakeHttp::new(&body).failing_to_open(vec![
            status(429, Some(30)),
            status(503, Some(3_600)),
            status(503, Some(0)),
        ]);
        let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(watcher.waits, secs(&[30, 120, 45]));
    }

    // An expired pre-signed URL is asked for again with the same URL, so it
    // fails the same way; a missing image stays missing.
    #[test]
    fn a_refusal_is_not_asked_again() {
        for refused in [403, 404] {
            let body = image();
            let update = update_for(&body, None);
            let mut http = FakeHttp::new(&body).failing_to_open(vec![status(refused, None)]);
            let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

            let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

            assert!(
                matches!(result, Err(Error::DownloadStatus { status, .. }) if status == refused),
                "{result:?}"
            );
            assert_eq!(http.opened.len(), 1);
            assert!(watcher.waits.is_empty());
            assert!(sink.aborted);
        }
    }

    // What NervesHub hears about is what was still wrong at the end.
    #[test]
    fn retries_run_out_with_the_last_error() {
        let body = image();
        let update = update_for(&body, None);
        let mut http = FakeHttp::new(&body).failing_to_open(vec![
            Error::Download("ESP_ERR_HTTP_CONNECT".into()),
            status(503, None),
            status(503, None),
            status(502, None),
            status(503, None),
        ]);
        let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(
            matches!(result, Err(Error::DownloadStatus { status: 502, .. })),
            "{result:?}"
        );
        assert_eq!(http.opened.len(), 4);
        assert_eq!(watcher.waits, secs(&[5, 15, 45]));
        assert!(sink.aborted);
        assert!(!sink.committed);
    }

    // Once bytes are in the slot, another try starts the image from the top:
    // NervesHub's call, not this one's.
    #[test]
    fn a_failure_partway_is_not_retried() {
        let body = image();
        let update = update_for(&body, None);
        let mut http = FakeHttp::new(&body).failing_after(1000);
        let (mut sink, mut watcher) = (FakeSink::default(), Watcher::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(matches!(result, Err(Error::Download(_))), "{result:?}");
        assert_eq!(http.opened.len(), 1);
        assert!(watcher.waits.is_empty());
        assert!(sink.aborted);
    }

    #[test]
    fn losing_the_connection_while_waiting_ends_the_download() {
        let body = image();
        let update = update_for(&body, None);
        let mut http = FakeHttp::new(&body).failing_to_open(vec![status(503, None)]);
        let mut sink = FakeSink::default();
        let mut watcher = Watcher {
            gone: true,
            ..Default::default()
        };

        let result = install(&update, &mut http, &mut sink, 5, &mut watcher);

        assert!(matches!(result, Err(Error::Transport(_))), "{result:?}");
        assert_eq!(http.opened.len(), 1);
        assert!(sink.aborted);
    }

    // A failure to report progress (the link dropped) should stop the install
    // rather than continue writing to a device nobody is watching.
    #[test]
    fn a_progress_failure_aborts() {
        let body = image();
        let update = update_for(&body, Some(sha256_upper(&body)));
        let (mut http, mut sink) = (FakeHttp::new(&body), FakeSink::default());

        let result = install(&update, &mut http, &mut sink, 5, &mut |_, _| {
            Err(Error::Transport("link dropped".into()))
        });

        assert!(matches!(result, Err(Error::Transport(_))));
        assert!(sink.aborted);
        assert!(!sink.committed);
    }
}
