//! `HttpStream` over ESP-IDF's HTTP client.
//!
//! **Not yet built or run.** The `esp-idf-svc` API surface needs checking
//! against the version you build with.
//!
//! # Redirects are mandatory
//!
//! NervesHub does not serve firmware itself. `firmware_url` is a pre-signed URL
//! that redirects to object storage (S3, Tigris, or whatever the instance is
//! configured with), and an organization can additionally route it through a
//! `firmware_proxy_url`. A client that does not follow redirects downloads a
//! redirect body, writes it to flash, and fails the checksum — which reads as
//! corruption rather than as a misconfigured client.
//!
//! # TLS
//!
//! The storage host is a different origin from the device socket, and the
//! client certificate is not wanted there. Server verification uses the IDF's
//! certificate bundle.

#![cfg(target_os = "espidf")]

use esp_idf_svc::http::client::{Configuration, EspHttpConnection};
use esp_idf_svc::http::Method;

use crate::error::Error;
use crate::install::HttpStream;

pub struct EspHttpStream {
    configuration: Configuration,
    /// `None` after a failed open, until the next opens a fresh one.
    connection: Option<EspHttpConnection>,
}

impl EspHttpStream {
    pub fn new() -> Result<Self, Error> {
        let configuration = Configuration {
            // See the module docs — this is not optional.
            follow_redirects_policy: esp_idf_svc::http::client::FollowRedirectsPolicy::FollowAll,
            use_global_ca_store: true,
            crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
            // Firmware images are megabytes over a slow link.
            timeout: Some(core::time::Duration::from_secs(60)),
            ..Default::default()
        };

        let connection =
            EspHttpConnection::new(&configuration).map_err(|e| Error::Download(e.to_string()))?;

        Ok(Self {
            configuration,
            connection: Some(connection),
        })
    }

    fn request(&mut self, url: &str) -> Result<Option<u64>, Error> {
        let connection = match self.connection.take() {
            Some(connection) => connection,
            None => EspHttpConnection::new(&self.configuration)
                .map_err(|e| Error::Download(e.to_string()))?,
        };
        let connection = self.connection.insert(connection);

        connection
            .initiate_request(Method::Get, url, &[])
            .map_err(|e| Error::Download(e.to_string()))?;

        connection
            .initiate_response()
            .map_err(|e| Error::Download(e.to_string()))?;

        let status = connection.status();

        // Redirects are followed by the client, so anything non-2xx here is a
        // real failure — most often an expired pre-signed URL, which no retry
        // will mend, or storage that is busy, which one might.
        if !(200..300).contains(&status) {
            return Err(Error::DownloadStatus {
                status,
                // Only the delta-seconds form. The date form needs a clock
                // the device may not have set, and a retry without it only
                // falls back to the usual backoff.
                retry_after_secs: connection
                    .header("Retry-After")
                    .and_then(|value| value.trim().parse::<u64>().ok()),
            });
        }

        Ok(connection
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok()))
    }
}

impl HttpStream for EspHttpStream {
    fn open(&mut self, url: &str) -> Result<Option<u64>, Error> {
        let opened = self.request(url);

        // A connection that failed is not used again. One that failed between
        // sending the request and reading the response is left mid-request,
        // where esp-idf-svc panics rather than start another; and one that
        // answered with an error may be a keep-alive to the very backend that
        // sent it. The next open starts from a fresh one -- and dropping this
        // one now frees its TLS session's memory for the wait in between.
        if opened.is_err() {
            self.connection = None;
        }

        opened
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(Error::Download("read before a successful open".into()));
        };

        esp_idf_svc::io::Read::read(connection, buf).map_err(|e| Error::Download(e.to_string()))
    }
}
