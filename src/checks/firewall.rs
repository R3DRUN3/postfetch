use crate::types::{CheckResult, Status};
use super::cmd_output;

pub fn check_firewall() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- nftables ---
    let nft = cmd_output("nft", &["list", "ruleset"])
        .map(|o| !o.trim().is_empty())
        .unwrap_or(false);

    results.push(CheckResult::new(
        "firewall",
        "nftables",
        if nft { "Active rules present" } else { "No rules / not available" },
        if nft { Status::Good } else { Status::Warn },
        None,
    ));

    // --- iptables ---
    let ipt = cmd_output("iptables", &["-L", "-n", "--line-numbers"])
        .map(|o| o.lines().count() > 3)   // more than default empty chains
        .unwrap_or(false);

    results.push(CheckResult::new(
        "firewall",
        "iptables",
        if ipt { "Rules present" } else { "Empty / not available" },
        if ipt { Status::Good } else { Status::Warn },
        None,
    ));

    // --- ufw ---
    let ufw_status = cmd_output("ufw", &["status"])
        .unwrap_or_default();
    let ufw_active = ufw_status.contains("Status: active");

    results.push(CheckResult::new(
        "firewall",
        "UFW",
        if ufw_active { "Active" } else { "Inactive / not installed" },
        if ufw_active { Status::Good } else { Status::Warn },
        None,
    ));

    // --- firewalld ---
    let fwd = cmd_output("firewall-cmd", &["--state"])
        .map(|o| o.trim() == "running")
        .unwrap_or(false);

    results.push(CheckResult::new(
        "firewall",
        "firewalld",
        if fwd { "Running" } else { "Not running / not installed" },
        if fwd { Status::Good } else { Status::Unknown },
        None,
    ));

    // Overall judgement
    let any_active = nft || ipt || ufw_active || fwd;
    results.push(CheckResult::new(
        "firewall",
        "Firewall Overall",
        if any_active { "At least one firewall active" } else { "No active firewall detected" },
        if any_active { Status::Good } else { Status::Bad },
        if !any_active {
            Some("No firewall detected — your network exposure is uncontrolled")
        } else {
            None
        },
    ));

    results
}
