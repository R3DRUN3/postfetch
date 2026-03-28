use crate::types::{CheckResult, Status};
use super::{cmd_output, read_file};
use std::env;
use std::fs;

fn sysctl_int(path: &str) -> Option<i64> {
    read_file(path)
        .and_then(|v| v.trim().parse::<i64>().ok())
}

fn flag(module: &str, label: &str, path: &str, detail: &str, expect_nonzero: bool) -> CheckResult {
    let val = sysctl_int(path);
    let (display, status) = match val {
        None => ("Not found".to_string(), Status::Unknown),
        Some(v) => {
            let ok = if expect_nonzero { v != 0 } else { v == 0 };
            (v.to_string(), if ok { Status::Good } else { Status::Warn })
        }
    };
    CheckResult::new(module, label, &display, status, Some(detail))
}

/// --- shell history size ---
fn check_shell_history() -> CheckResult {
    let module = "hardening";
    let label = "Shell History Lines";

    // Determine shell
    let shell_path = env::var("SHELL").unwrap_or_default();
    let shell_name = shell_path
        .rsplit('/')
        .next()
        .unwrap_or("unknown");

    // Guess history file based on common shells
    let home = env::var("HOME").unwrap_or_default();
    let history_file = match shell_name {
        "bash" => format!("{}/.bash_history", home),
        "zsh"  => format!("{}/.zsh_history", home),
        "fish" => format!("{}/.config/fish/fish_history", home),
        _      => "".to_string(),
    };

    if history_file.is_empty() {
        return CheckResult::new(module, label, "Unknown shell", Status::Unknown,
            Some("Cannot determine shell history file"));
    }

    // Count lines
    let line_count = fs::read_to_string(&history_file)
        .map(|content| content.lines().count())
        .unwrap_or(0);

    let (status, detail) = if line_count <= 50 {
        (Status::Good, "History lines within safe limit (<=50), check it anyway")
    } else if line_count <= 500 {
        (Status::Warn, "History lines exceed 50; consider trimming")
    } else {
        (Status::Bad, "History lines exceed 500; privacy and security risk")
    };

    CheckResult::new(module, label, &format!("{} lines ({})", line_count, shell_name), status, Some(detail))
}

pub fn check_hardening() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- Kernel ASLR ---
    results.push(flag(
        "hardening",
        "ASLR (randomize_va_space)",
        "/proc/sys/kernel/randomize_va_space",
        "2 = full randomisation — best protection",
        true,
    ));

    // --- kptr_restrict ---
    results.push(flag(
        "hardening",
        "kptr_restrict",
        "/proc/sys/kernel/kptr_restrict",
        "Hides kernel pointer addresses — reduces info-leak",
        true,
    ));

    // --- dmesg_restrict ---
    results.push(flag(
        "hardening",
        "dmesg_restrict",
        "/proc/sys/kernel/dmesg_restrict",
        "Restricts dmesg to root — reduces kernel info leak",
        true,
    ));

    // --- perf_event_paranoid ---
    let perf = sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    let (perf_val, perf_status) = match perf {
        Some(v) if v >= 2 => (v.to_string(), Status::Good),
        Some(v)           => (v.to_string(), Status::Warn),
        None              => ("Not found".to_string(), Status::Unknown),
    };
    results.push(CheckResult::new(
        "hardening",
        "perf_event_paranoid",
        &perf_val,
        perf_status,
        Some(">=2 limits unprivileged access to perf counters"),
    ));

    // --- ptrace scope ---
    let ptrace = sysctl_int("/proc/sys/kernel/yama/ptrace_scope");
    let (ptrace_val, ptrace_status) = match ptrace {
        Some(v) if v >= 1 => (v.to_string(), Status::Good),
        Some(v)           => (v.to_string(), Status::Warn),
        None              => ("Not found / Yama not loaded".to_string(), Status::Unknown),
    };
    results.push(CheckResult::new(
        "hardening",
        "ptrace_scope (Yama)",
        &ptrace_val,
        ptrace_status,
        Some(">=1 prevents unprivileged processes from ptracing each other"),
    ));

    // --- Unprivileged user namespaces ---
    let userns = sysctl_int("/proc/sys/kernel/unprivileged_userns_clone");
    let (userns_val, userns_status) = match userns {
        Some(0) => ("0 (restricted)".to_string(), Status::Good),
        Some(v) => (v.to_string(), Status::Warn),
        None    => ("Not found / always allowed".to_string(), Status::Warn),
    };
    results.push(CheckResult::new(
        "hardening",
        "Unprivileged User NS",
        &userns_val,
        userns_status,
        Some("0 reduces container escape and sandbox bypass surface"),
    ));

    // --- Core dumps ---
    let core = read_file("/proc/sys/kernel/core_pattern")
        .unwrap_or_default();
    let core_disabled = core.trim() == "|/bin/false" || core.trim() == "/dev/null";
    results.push(CheckResult::new(
        "hardening",
        "Core Dumps",
        core.trim(),
        if core_disabled { Status::Good } else { Status::Warn },
        Some("Core dumps can leak sensitive memory — disable or redirect to /dev/null"),
    ));

    // --- SYN cookies ---
    results.push(flag(
        "hardening",
        "TCP SYN Cookies",
        "/proc/sys/net/ipv4/tcp_syncookies",
        "Mitigates SYN-flood DoS attacks",
        true,
    ));

    // --- RP filter ---
    results.push(flag(
        "hardening",
        "RP Filter (IPv4)",
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "Reverse-path filtering prevents IP spoofing",
        true,
    ));

    // --- ICMP redirects ---
    results.push(flag(
        "hardening",
        "ICMP Redirect Accept",
        "/proc/sys/net/ipv4/conf/all/accept_redirects",
        "Should be 0 — accepting redirects enables MITM",
        false,
    ));

    // --- IP forwarding ---
    results.push(flag(
        "hardening",
        "IP Forwarding",
        "/proc/sys/net/ipv4/ip_forward",
        "Should be 0 on non-router hosts",
        false,
    ));

    // --- NX bit ---
    let nx = read_file("/proc/cpuinfo")
        .map(|c| c.contains("nx") || c.contains("xd"))
        .unwrap_or(false);
    results.push(CheckResult::new(
        "hardening",
        "NX/XD (no-execute) bit",
        if nx { "Supported by CPU" } else { "Not detected" },
        if nx { Status::Good } else { Status::Warn },
        Some("Hardware no-execute bit prevents code injection attacks"),
    ));

    // --- Secure boot ---
    let sb = std::fs::read_to_string(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    )
    .ok()
    .map(|v| v.bytes().last().map(|b| b == 1).unwrap_or(false));

    let (sb_val, sb_status) = match sb {
        Some(true)  => ("Enabled",                      Status::Good),
        Some(false) => ("Disabled",                     Status::Warn),
        None        => ("Not readable / legacy BIOS",   Status::Unknown),
    };
    results.push(CheckResult::new(
        "hardening",
        "Secure Boot",
        sb_val,
        sb_status,
        Some("Secure Boot verifies bootloader integrity"),
    ));

    // --- USBGuard ---
    let usbguard = cmd_output("systemctl", &["is-active", "usbguard"])
        .map(|o| o.trim() == "active")
        .unwrap_or(false);
    results.push(CheckResult::new(
        "hardening",
        "USBGuard",
        if usbguard { "Active" } else { "Not running" },
        if usbguard { Status::Good } else { Status::Warn },
        Some("USBGuard blocks unauthorized USB devices"),
    ));

    // --- auditd ---
    let auditd = cmd_output("systemctl", &["is-active", "auditd"])
        .map(|o| o.trim() == "active")
        .unwrap_or(false);
    results.push(CheckResult::new(
        "hardening",
        "auditd",
        if auditd { "Active" } else { "Not running" },
        if auditd { Status::Good } else { Status::Warn },
        Some("auditd logs system calls for security auditing"),
    ));

    // --- Shell history ---
    results.push(check_shell_history());

    results
}