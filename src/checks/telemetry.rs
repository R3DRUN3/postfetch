use crate::types::{CheckResult, Status};
use super::cmd_output;
use std::path::Path;

const TELEMETRY_SERVICES: &[(&str, &str, bool)] = &[
    ("apport",              "Ubuntu crash reporting",             true),
    ("whoopsie",            "Ubuntu error reporting",             true),
    ("popularity-contest",  "Debian/Ubuntu popularity contest",   true),
    ("fwupd",               "Firmware update daemon",             false),
    ("geoclue",             "Geolocation service",                false),
    ("avahi-daemon",        "mDNS/DNS-SD LAN broadcast",          false),
    ("bluetooth",           "Bluetooth daemon",                   false),
    ("colord",              "Color management daemon",            false),
    ("snapd",               "Snap daemon (phones home)",          true),
    ("systemd-coredump",    "systemd core dump handler",          false),
    ("cups-browsed",        "CUPS network printer discovery",     false),
    ("packagekit",          "Package management daemon",          false),
];

fn service_is_active(name: &str) -> bool {
    cmd_output("systemctl", &["is-active", name])
        .map(|o| o.trim() == "active")
        .unwrap_or(false)
}

fn service_is_enabled(name: &str) -> bool {
    cmd_output("systemctl", &["is-enabled", name])
        .map(|o| o.trim() == "enabled" || o.trim() == "static")
        .unwrap_or(false)
}

fn check_firefox_telemetry() -> Option<bool> {
    let home = std::env::var("HOME").ok()?;
    let profiles_dir = format!("{}/.mozilla/firefox", home);
    let entries = std::fs::read_dir(&profiles_dir).ok()?;
    for entry in entries.flatten() {
        let prefs = entry.path().join("prefs.js");
        if prefs.exists() {
            if let Ok(content) = std::fs::read_to_string(&prefs) {
                if content.contains("toolkit.telemetry.enabled\", true") {
                    return Some(true);
                }
            }
        }
    }
    Some(false)
}

fn check_chrome_policies() -> bool {
    let paths = [
        "/etc/chromium/policies/managed",
        "/etc/chromium-browser/policies/managed",
        "/etc/opt/chrome/policies/managed",
    ];
    paths.iter().any(|p| Path::new(p).exists())
}

pub fn check_telemetry() -> Vec<CheckResult> {
    let mut results = Vec::new();
    let mut any_found = false;

    for (svc, desc, is_bad) in TELEMETRY_SERVICES {
        let active  = service_is_active(svc);
        let enabled = service_is_enabled(svc);

        if active || enabled {
            any_found = true;
            let state = match (active, enabled) {
                (true,  true)  => "Active & Enabled",
                (true,  false) => "Active (manual start)",
                (false, true)  => "Enabled (not running)",
                _              => "Unknown",
            };
            results.push(CheckResult::new(
                "telemetry",
                svc,
                state,
                if *is_bad { Status::Bad } else { Status::Warn },
                Some(desc),
            ));
        }
    }

    if !any_found {
        results.push(CheckResult::new(
            "telemetry",
            "Telemetry Services",
            "None detected",
            Status::Good,
            Some("No known telemetry/tracking services found active"),
        ));
    }

    // --- Firefox telemetry ---
    match check_firefox_telemetry() {
        Some(true) => results.push(CheckResult::new(
            "telemetry",
            "Firefox Telemetry",
            "Enabled in prefs.js",
            Status::Bad,
            Some("toolkit.telemetry.enabled=true found in Firefox profile"),
        )),
        Some(false) => results.push(CheckResult::new(
            "telemetry",
            "Firefox Telemetry",
            "Not detected",
            Status::Good,
            Some("No telemetry flag found in Firefox prefs.js"),
        )),
        None => {} // Firefox not installed, skip silently
    }

    // --- Chrome/Chromium managed policies ---
    let chrome_policies = check_chrome_policies();
    results.push(CheckResult::new(
        "telemetry",
        "Chrome/Chromium Policies",
        if chrome_policies { "Managed policies present" } else { "No managed policies" },
        if chrome_policies { Status::Warn } else { Status::Good },
        Some("Managed policy dirs can enforce or restrict browser telemetry"),
    ));

    results
}
