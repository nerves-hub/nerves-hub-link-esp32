// esp-idf-sys writes the ESP-IDF build's include paths, link flags and cfgs
// into the environment; this forwards them to cargo. It is a no-op for host
// builds, which is what keeps `cargo test` working without a toolchain.
fn main() {
    // esp-idf-sys sets a cfg for each sdkconfig option that is on; these are
    // the ones this crate reads. Declared so cargo doesn't warn about them
    // where the option is off, or on the host where there is no sdkconfig.
    println!("cargo::rustc-check-cfg=cfg(esp_idf_esp_tls_client_session_tickets)");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("espidf") {
        embuild::espidf::sysenv::output();
    }
}
