//! What an ESP32 can honestly say about its own health.
//!
//! NervesHub charts every metric it is sent, but only a few known keys drive the
//! health status shown in the UI — `mem_used_percent` and `cpu_usage_percent`
//! among them. So the memory figures are reported under the names the platform
//! understands, and the readings that are particular to this hardware are sent
//! alongside under their own names, where they are charted but do not silently
//! change a device's status.
//!
//! # What is worth sending
//!
//! Free heap on its own says little: it moves constantly and a healthy device
//! sits wherever its workload puts it. The two that earn their place are the
//! **low-water mark**, which only ever falls and so turns a slow leak into a
//! visible slope, and the **largest free block**, which falls while free heap
//! stays flat when the heap is fragmenting — the failure where an allocation of
//! a size that used to succeed starts failing.
//!
//! **RSSI** is included because most field problems with a WiFi device are
//! signal problems, and a fleet map of RSSI answers that at a glance.
//!
//! Uptime is deliberately absent. As a metric it is a line that only rises,
//! which reads the same whether a fleet is stable or restarting hourly — the
//! question it appears to answer is better answered by `reset_reason`.
//!
//! # CPU
//!
//! There is no supported way to measure CPU load on FreeRTOS without run-time
//! statistics, which cost a timer and per-task bookkeeping and are off by
//! default. Rather than report a fabricated number, `cpu_usage_percent` is sent
//! only when the `cpu-metrics` feature is on and the build has:
//!
//! ```text
//! CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS=y
//! CONFIG_FREERTOS_USE_TRACE_FACILITY=y
//! ```

#[cfg(target_os = "espidf")]
use crate::extensions::{HealthProvider, HealthReport};

/// A byte count as whole megabytes, for the metric names NervesHub knows.
///
/// An ESP32's heap is a few hundred kilobytes, so these are small fractions —
/// which is honest. The alternative, rescaling to make the numbers look
/// familiar, would make a device's memory unreadable next to a Nerves device
/// charted on the same axis.
fn as_mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    (used as f64 / total as f64) * 100.0
}

/// The memory part of a report, from raw byte counts.
///
/// Split out from the ESP-IDF calls so the arithmetic — which is where the
/// mistakes are — can be checked on a desktop.
pub fn memory_metrics(
    total_bytes: u64,
    free_bytes: u64,
    min_free_bytes: u64,
    largest_free_block_bytes: u64,
) -> Vec<(String, f64)> {
    let used = total_bytes.saturating_sub(free_bytes);

    vec![
        // Names NervesHub knows, and evaluates for health status.
        ("mem_size_mb".into(), as_mb(total_bytes)),
        ("mem_used_mb".into(), as_mb(used)),
        ("mem_used_percent".into(), percent(used, total_bytes)),
        // Names particular to this hardware: charted, but not read as status.
        ("heap_free_bytes".into(), free_bytes as f64),
        ("heap_min_free_bytes".into(), min_free_bytes as f64),
        ("heap_largest_free_block_bytes".into(), largest_free_block_bytes as f64),
    ]
}

/// Why the device last restarted, as a word rather than a number.
///
/// Worth reporting because it distinguishes the reboots that are fine — a power
/// cycle, an OTA — from the ones that are not: a panic, a watchdog, a brownout.
/// A fleet quietly brownout-resetting looks identical to a healthy one in every
/// other metric.
pub fn reset_reason_name(reason: u32) -> &'static str {
    // esp_reset_reason_t, from esp_system.h.
    match reason {
        0 => "unknown",
        1 => "power_on",
        2 => "external_pin",
        3 => "software",
        4 => "panic",
        5 => "interrupt_watchdog",
        6 => "task_watchdog",
        7 => "other_watchdog",
        8 => "deep_sleep",
        9 => "brownout",
        10 => "sdio",
        _ => "unrecognised",
    }
}

/// Health readings from the running device.
#[cfg(target_os = "espidf")]
pub struct EspHealth;

#[cfg(target_os = "espidf")]
impl EspHealth {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "espidf")]
impl Default for EspHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "espidf")]
impl HealthProvider for EspHealth {
    fn report(&mut self) -> HealthReport {
        use esp_idf_svc::sys;

        let (total, free, min_free, largest) = unsafe {
            (
                sys::heap_caps_get_total_size(sys::MALLOC_CAP_INTERNAL) as u64,
                sys::esp_get_free_heap_size() as u64,
                sys::esp_get_minimum_free_heap_size() as u64,
                sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_INTERNAL) as u64,
            )
        };

        let mut report = HealthReport::default();
        for (name, value) in memory_metrics(total, free, min_free, largest) {
            report = report.metric(name, value);
        }

        if let Some(rssi) = wifi_rssi() {
            report = report.metric("wifi_rssi", rssi as f64);
        }

        if let Some(cpu) = cpu_usage_percent() {
            report = report.metric("cpu_usage_percent", cpu);
        }

        let reason = unsafe { sys::esp_reset_reason() };
        report.meta("reset_reason", reset_reason_name(reason as u32))
    }
}

/// Signal strength to the access point, or `None` when not associated.
#[cfg(target_os = "espidf")]
fn wifi_rssi() -> Option<i8> {
    use esp_idf_svc::sys;

    let mut info: sys::wifi_ap_record_t = unsafe { core::mem::zeroed() };

    // Fails when the interface is down or not associated, which is not an
    // error worth reporting — it just means there is no reading.
    if unsafe { sys::esp_wifi_sta_get_ap_info(&mut info) } == sys::ESP_OK {
        Some(info.rssi)
    } else {
        None
    }
}

#[cfg(all(target_os = "espidf", feature = "cpu-metrics"))]
fn cpu_usage_percent() -> Option<f64> {
    use esp_idf_svc::sys;

    // Run-time statistics count ticks per task. CPU usage is the share not
    // spent in the idle tasks.
    unsafe {
        let count = sys::uxTaskGetNumberOfTasks() as usize;
        let mut tasks: Vec<sys::TaskStatus_t> = vec![core::mem::zeroed(); count];
        let mut total_runtime: u32 = 0;

        let written =
            sys::uxTaskGetSystemState(tasks.as_mut_ptr(), count as u32, &mut total_runtime) as usize;

        if written == 0 || total_runtime == 0 {
            return None;
        }

        let idle: u32 = tasks[..written]
            .iter()
            .filter(|task| {
                let name = core::ffi::CStr::from_ptr(task.pcTaskName);
                name.to_bytes().starts_with(b"IDLE")
            })
            .map(|task| task.ulRunTimeCounter)
            .sum();

        Some(100.0 - percent(idle as u64, total_runtime as u64))
    }
}

#[cfg(all(target_os = "espidf", not(feature = "cpu-metrics")))]
fn cpu_usage_percent() -> Option<f64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(metrics: &[(String, f64)], name: &str) -> f64 {
        metrics.iter().find(|(k, _)| k == name).map(|(_, v)| *v).expect("metric missing")
    }

    #[test]
    fn memory_is_reported_under_the_names_the_platform_evaluates() {
        // 300 KB heap, 100 KB free.
        let metrics = memory_metrics(307_200, 102_400, 81_920, 65_536);

        assert_eq!(metric(&metrics, "mem_used_percent"), 200_f64 / 300.0 * 100.0);
        assert!((metric(&metrics, "mem_size_mb") - 0.29296875).abs() < 1e-9);
        assert!((metric(&metrics, "mem_used_mb") - 0.1953125).abs() < 1e-9);
    }

    #[test]
    fn the_diagnostic_readings_are_passed_through_as_bytes() {
        let metrics = memory_metrics(307_200, 102_400, 81_920, 65_536);

        assert_eq!(metric(&metrics, "heap_free_bytes"), 102_400.0);
        assert_eq!(metric(&metrics, "heap_min_free_bytes"), 81_920.0);
        assert_eq!(metric(&metrics, "heap_largest_free_block_bytes"), 65_536.0);
    }

    // A device reporting before the heap is known should say 0%, not divide by
    // zero and take the connection down with it.
    #[test]
    fn a_zero_total_does_not_panic() {
        let metrics = memory_metrics(0, 0, 0, 0);
        assert_eq!(metric(&metrics, "mem_used_percent"), 0.0);
    }

    // Free heap above total would mean used underflows; saturating keeps the
    // report sane rather than reporting a percentage near u64::MAX.
    #[test]
    fn free_above_total_does_not_underflow() {
        let metrics = memory_metrics(1_000, 2_000, 500, 500);
        assert_eq!(metric(&metrics, "mem_used_mb"), 0.0);
        assert_eq!(metric(&metrics, "mem_used_percent"), 0.0);
    }

    #[test]
    fn reset_reasons_name_the_ones_that_matter() {
        assert_eq!(reset_reason_name(1), "power_on");
        assert_eq!(reset_reason_name(4), "panic");
        assert_eq!(reset_reason_name(6), "task_watchdog");
        assert_eq!(reset_reason_name(9), "brownout");
        assert_eq!(reset_reason_name(255), "unrecognised");
    }
}
