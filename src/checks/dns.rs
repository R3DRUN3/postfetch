use crate::types::{CheckResult, Status};
use super::{cmd_output, read_file};

const PRIVATE_DNS: &[(&str, &str)] = &[
    ("1.1.1.1",             "Cloudflare"),
    ("1.0.0.1",             "Cloudflare"),
    ("9.9.9.9",             "Quad9"),
    ("149.112.112.112",     "Quad9"),
    ("8.8.8.8",             "Google (caution)"),
    ("8.8.4.4",             "Google (caution)"),
    ("94.140.14.14",        "AdGuard"),
    ("94.140.15.15",        "AdGuard"),
    ("176.103.130.130",     "AdGuard"),
    ("127.0.0.1",           "Localhost / local resolver"),
    ("127.0.0.53",          "systemd-resolved (local)"),
    ("::1",                 "Localhost IPv6"),
];

fn label_for(ip: &str) -> &'static str {
    for (addr, label) in PRIVATE_DNS {
        if *addr == ip { return label; }
    }
    "Unknown / ISP default"
}

pub fn check_dns() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- Nameservers ---
    let resolv = read_file("/etc/resolv.conf").unwrap_or_default();
    let nameservers: Vec<String> = resolv
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .filter_map(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
        .collect();

    if nameservers.is_empty() {
        results.push(CheckResult::new(
            "dns",
            "Nameserver Config",
            "Not found",
            Status::Unknown,
            Some("/etc/resolv.conf has no nameserver entries"),
        ));
    } else {
        for ns in &nameservers {
            let label = label_for(ns.as_str());
            let is_local   = ns.starts_with("127.") || ns == "::1";
            let is_google  = label.contains("Google");
            let is_unknown = label == "Unknown / ISP default";
            let status = if is_local {
                Status::Good
            } else if is_google {
                Status::Warn
            } else if is_unknown {
                Status::Bad
            } else {
                Status::Good
            };
            results.push(CheckResult::new(
                "dns",
                "Nameserver",
                &format!("{} ({})", ns, label),
                status,
                None,
            ));
        }

        // --- DNS leak risk ---
        let all_non_local = nameservers
            .iter()
            .all(|ns| !ns.starts_with("127.") && ns != "::1");
        let multiple = nameservers.len() > 1;
        if all_non_local && multiple {
            results.push(CheckResult::new(
                "dns",
                "DNS Leak Risk",
                "Multiple non-local nameservers",
                Status::Warn,
                Some("Multiple external DNS servers increase leak risk — consider a single local resolver"),
            ));
        }
    }

    // --- DNS-over-TLS ---
    let resolved_conf = read_file("/etc/systemd/resolved.conf").unwrap_or_default()
        + &read_file("/etc/systemd/resolved.conf.d/dns_over_tls.conf").unwrap_or_default();

    let dot_enabled = resolved_conf
        .lines()
        .any(|l| l.contains("DNSOverTLS=yes") || l.contains("DNSOverTLS=opportunistic"));

    results.push(CheckResult::new(
        "dns",
        "DNS-over-TLS (systemd)",
        if dot_enabled { "Enabled" } else { "Not configured" },
        if dot_enabled { Status::Good } else { Status::Warn },
        Some("DNS-over-TLS encrypts queries and prevents interception"),
    ));

    // --- DNSSEC ---
    let dnssec = resolved_conf
        .lines()
        .any(|l| l.contains("DNSSEC=yes") || l.contains("DNSSEC=allow-downgrade"));

    results.push(CheckResult::new(
        "dns",
        "DNSSEC (systemd)",
        if dnssec { "Enabled" } else { "Not configured" },
        if dnssec { Status::Good } else { Status::Warn },
        Some("DNSSEC validates DNS responses against cryptographic signatures"),
    ));

    // --- Local resolvers ---
    for svc in &["dnsmasq", "unbound", "dnscrypt-proxy"] {
        let running = cmd_output("systemctl", &["is-active", svc])
            .map(|o| o.trim() == "active")
            .unwrap_or(false);
        if running {
            results.push(CheckResult::new(
                "dns",
                &format!("{} (local resolver)", svc),
                "Active",
                Status::Good,
                Some("Local DNS resolver in use — good for privacy"),
            ));
        }
    }

    results
}
