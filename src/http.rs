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
    connection: EspHttpConnection,
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

        Ok(Self { connection })
    }
}

impl HttpStream for EspHttpStream {
    fn open(&mut self, url: &str) -> Result<Option<u64>, Error> {
        self.connection
            .initiate_request(Method::Get, url, &[])
            .map_err(|e| Error::Download(e.to_string()))?;

        self.connection
            .initiate_response()
            .map_err(|e| Error::Download(e.to_string()))?;

        let status = self.connection.status();

        // Redirects are followed by the client, so anything non-2xx here is a
        // real failure — most often an expired pre-signed URL.
        if !(200..300).contains(&status) {
            return Err(Error::Download(format!(
                "firmware download returned HTTP {status}"
            )));
        }

        Ok(self
            .connection
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok()))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        esp_idf_svc::io::Read::read(&mut self.connection, buf)
            .map_err(|e| Error::Download(e.to_string()))
    }
}
