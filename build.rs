// esp-idf-sys writes the ESP-IDF build's include paths, link flags and cfgs
// into the environment; this forwards them to cargo. It is a no-op for host
// builds, which is what keeps `cargo test` working without a toolchain.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("espidf") {
        embuild::espidf::sysenv::output();
    }
}
