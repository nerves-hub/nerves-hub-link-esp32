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

use crate::checksum::{self, Sha256};
use crate::error::Error;
use crate::update::{ProgressThrottle, Stage, UpdatePayload};

/// Read size. Large enough that flash writes are not dominated by per-call
/// overhead, small enough to sit comfortably in RAM alongside TLS buffers.
pub const CHUNK_SIZE: usize = 4096;

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
    P: FnMut(Stage, u8) -> Result<(), Error>,
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
    P: FnMut(Stage, u8) -> Result<(), Error>,
{
    let content_length = http.open(url)?;

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

        if let Some(total) = expected_size {
            // A server that sends more than it promised is not something to
            // keep writing into a flash partition.
            if written > total {
                return Err(Error::Download(format!(
                    "image is longer than the expected {total} bytes"
                )));
            }

            if let Some(percent) = throttle.take(written, total) {
                on_progress(Stage::Downloading, percent)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Serves a fixed body, optionally failing partway through.
    struct FakeHttp {
        body: Vec<u8>,
        position: usize,
        content_length: Option<u64>,
        fail_after: Option<usize>,
        opened: Vec<String>,
    }

    impl FakeHttp {
        fn new(body: &[u8]) -> Self {
            Self {
                body: body.to_vec(),
                position: 0,
                content_length: Some(body.len() as u64),
                fail_after: None,
                opened: vec![],
            }
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
