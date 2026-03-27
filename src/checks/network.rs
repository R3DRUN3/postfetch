use crate::types::{CheckResult, Status};
use super::{cmd_output, read_file};

fn vpn_active() -> (bool, String) {
    let dev = read_file("/proc/net/dev").unwrap_or_default();
    let vpn_ifaces = ["tun0", "tun1", "wg0-mullvad", "wg0", "wg1", "proton0", "nordlynx", "mullvad"];
    for iface in &vpn_ifaces {
        if dev.contains(iface) {
            return (true, iface.to_string());
        }
    }
    (false, String::new())
}

fn tor_active() -> bool {
    cmd_output("systemctl", &["is-active", "tor"])
        .map(|o| o.trim() == "active")
        .unwrap_or(false)
}

fn tor_socks_configured() -> bool {
    read_file("/etc/tor/torrc")
        .map(|c| {
            c.lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("SocksPort"))
        })
        .unwrap_or(false)
}

fn mac_randomization() -> (bool, String) {
    let dirs = [
        "/etc/NetworkManager/conf.d",
        "/usr/lib/NetworkManager/conf.d",
    ];
    for dir in &dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("cloned-mac-address=random")
                            || content.contains("wifi.cloned-mac-address=random")
                        {
                            return (
                                true,
                                path.file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }
    }
    (false, String::new())
}

fn ipv6_disabled() -> Option<bool> {
    read_file("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .and_then(|v| v.trim().parse::<u8>().ok())
        .map(|v| v == 1)
}

fn open_ports() -> Vec<String> {
    cmd_output("ss", &["-tlnp"])
        .map(|out| {
            out.lines()
                .skip(1)
                .filter_map(|l| {
                    let cols: Vec<&str> = l.split_whitespace().collect();
                    cols.get(3).map(|addr| addr.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn check_network() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- VPN ---
    let (vpn, iface) = vpn_active();
    let vpn_value = if vpn {
        format!("Active ({})", iface)
    } else {
        "No VPN interface detected".to_string()
    };
    results.push(CheckResult::new(
        "network",
        "VPN",
        &vpn_value,
        if vpn { Status::Good } else { Status::Warn },
        Some("Checks for tun0, wg0, proton0, nordlynx, mullvad interfaces"),
    ));

    // --- Tor ---
    let tor = tor_active();
    let tor_socks = tor_socks_configured();
    results.push(CheckResult::new(
        "network",
        "Tor Service",
        if tor { "Active" } else { "Not running" },
        if tor { Status::Good } else { Status::Warn },
        Some("Tor routes traffic through the anonymity network"),
    ));
    results.push(CheckResult::new(
        "network",
        "Tor SocksPort",
        if tor_socks { "Configured in torrc" } else { "Not configured" },
        if tor_socks { Status::Good } else { Status::Unknown },
        Some("/etc/tor/torrc SocksPort entry"),
    ));

    // --- MAC randomization ---
    let (mac_rand, mac_file) = mac_randomization();
    let mac_value = if mac_rand {
        format!("Enabled ({})", mac_file)
    } else {
        "Not configured".to_string()
    };
    results.push(CheckResult::new(
        "network",
        "WiFi MAC Randomization",
        &mac_value,
        if mac_rand { Status::Good } else { Status::Warn },
        Some("Randomizing MAC address prevents tracking across networks"),
    ));

    // --- IPv6 ---
    let ipv6 = ipv6_disabled();
    results.push(CheckResult::new(
        "network",
        "IPv6",
        match ipv6 {
            Some(true)  => "Disabled",
            Some(false) => "Enabled",
            None        => "Unknown",
        },
        match ipv6 {
            Some(true)  => Status::Good,
            Some(false) => Status::Warn,
            None        => Status::Unknown,
        },
        Some("IPv6 can leak real IP even through a VPN"),
    ));

    // --- Open ports ---
    let ports = open_ports();
    let port_count = ports.len();
    let suspicious_count = ports
        .iter()
        .filter(|p| {
            !p.starts_with("127.") && !p.starts_with("[::1]") && *p != "0.0.0.0:*"
        })
        .count();
    let ports_value = format!("{} open ({} non-loopback)", port_count, suspicious_count);
    results.push(CheckResult::new(
        "network",
        "Listening Ports",
        &ports_value,
        if suspicious_count == 0 {
            Status::Good
        } else if suspicious_count <= 3 {
            Status::Warn
        } else {
            Status::Bad
        },
        Some("Non-loopback listening ports are reachable from the network"),
    ));

    results
}
