use crate::types::{CheckResult, Status};
use super::{which, cmd_output};

pub fn check_sandboxing() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- Flatpak ---
    let flatpak = which("flatpak");
    let flatpak_apps = if flatpak {
        cmd_output("flatpak", &["list", "--app"])
            .map(|o| o.lines().count())
            .unwrap_or(0)
    } else {
        0
    };
    let flatpak_value = if flatpak {
        format!("Installed ({} apps)", flatpak_apps)
    } else {
        "Not installed".to_string()
    };
    results.push(CheckResult::new(
        "sandboxing",
        "Flatpak",
        &flatpak_value,
        if flatpak { Status::Good } else { Status::Warn },
        Some("Flatpak provides app sandboxing via bubblewrap/portals"),
    ));


    // --- Docker ---
    let docker = which("docker");
    results.push(CheckResult::new(
        "sandboxing",
        "Docker",
        if docker { "Installed" } else { "Not installed" },
        if docker { Status::Good } else { Status::Warn },
        Some("Docker lets you run sandboxed Linux processes, consider using podman for better default security"),
    ));


    // --- Podman ---
    let podman = which("podman");
    results.push(CheckResult::new(
        "sandboxing",
        "Podman",
        if podman { "Installed" } else { "Not installed" },
        if podman { Status::Good } else { Status::Warn },
        Some("Podman supports daemonless and rootless container isolation"),
    ));


    // --- Landlock ---
    let landlock_lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
    .ok()
    .map(|s| s.split(',').any(|x| x.trim() == "landlock"))
    .unwrap_or(false);
    results.push(CheckResult::new(
        "sandboxing",
        "Landlock",
        if landlock_lsm { "Enabled in LSM stack" } else { "Not enabled" },
        if landlock_lsm { Status::Good } else { Status::Unknown },
        Some("Landlock is an unprivileged Linux Security Module for self-imposed sandboxing"),
    ));


    

    // --- Firejail ---
    let firejail = which("firejail");
    results.push(CheckResult::new(
        "sandboxing",
        "Firejail",
        if firejail { "Installed" } else { "Not installed" },
        if firejail { Status::Good } else { Status::Warn },
        Some("Firejail restricts app permissions via Linux namespaces"),
    ));

    // --- bubblewrap ---
    let bwrap = which("bwrap");
    results.push(CheckResult::new(
        "sandboxing",
        "bubblewrap (bwrap)",
        if bwrap { "Available" } else { "Not found" },
        if bwrap { Status::Good } else { Status::Unknown },
        None,
    ));

    // --- AppArmor ---
    let apparmor_active = cmd_output("aa-status", &["--enabled"])
        .map(|_| true)
        .or_else(|| {
            std::fs::read_to_string("/sys/kernel/security/apparmor/profiles")
                .ok()
                .map(|_| true)
        })
        .unwrap_or(false);

    let apparmor_module = std::path::Path::new("/sys/module/apparmor").exists();

    results.push(CheckResult::new(
        "sandboxing",
        "AppArmor",
        if apparmor_active || apparmor_module {
            "Active"
        } else {
            "Not active"
        },
        if apparmor_active || apparmor_module {
            Status::Good
        } else {
            Status::Warn
        },
        Some("AppArmor provides MAC profiles for system services"),
    ));

    // --- SELinux ---
    let selinux = cmd_output("getenforce", &[])
        .map(|o| o.trim().to_lowercase());

    let se_status = match selinux.as_deref() {
        Some("enforcing")  => Status::Good,
        Some("permissive") => Status::Warn,
        Some("disabled")   => Status::Warn,
        _                  => Status::Unknown,
    };

    results.push(CheckResult::new(
        "sandboxing",
        "SELinux",
        selinux.as_deref().unwrap_or("Not found"),
        se_status,
        Some("SELinux enforces mandatory access controls on processes"),
    ));

    // --- seccomp ---
    let seccomp = std::fs::read_to_string("/proc/1/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp"))
                .and_then(|l| l.split_whitespace().nth(1).map(|v| v.to_string()))
        });

    let sc_detail = match seccomp.as_deref() {
        Some("0") => ("Disabled on PID 1", Status::Warn),
        Some("1") => ("Strict mode",       Status::Good),
        Some("2") => ("Filter mode",       Status::Good),
        _         => ("Unknown",           Status::Unknown),
    };

    results.push(CheckResult::new(
        "sandboxing",
        "seccomp (PID 1)",
        sc_detail.0,
        sc_detail.1,
        Some("seccomp reduces attack surface by filtering syscalls"),
    ));

    results
}
