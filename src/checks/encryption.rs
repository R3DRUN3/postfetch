use crate::types::{CheckResult, Status};
use super::{cmd_output, read_file};

pub fn check_encryption() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // --- LUKS ---
    let luks = cmd_output("lsblk", &["-o", "NAME,TYPE,FSTYPE"])
        .map(|out| out.contains("crypto_LUKS"))
        .unwrap_or(false);
    results.push(CheckResult::new(
        "encryption",
        "LUKS Disk Encryption",
        if luks { "Enabled" } else { "Not detected" },
        if luks { Status::Good } else { Status::Warn },
        if luks {
            Some("LUKS encrypted partition found via lsblk")
        } else {
            Some("No LUKS partition found — consider full-disk encryption")
        },
    ));

    // --- dm-crypt active ---
    let dmcrypt_active = cmd_output("dmsetup", &["ls", "--target", "crypt"])
        .map(|o| !o.trim().is_empty() && !o.contains("No devices found"))
        .unwrap_or(false);
    if dmcrypt_active {
        results.push(CheckResult::new(
            "encryption",
            "dm-crypt Active Device",
            "Active",
            Status::Good,
            Some("At least one dm-crypt mapped device is active"),
        ));
    }

    // --- /etc/crypttab ---
    let crypttab = read_file("/etc/crypttab")
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false);
    results.push(CheckResult::new(
        "encryption",
        "/etc/crypttab Configured",
        if crypttab { "Present" } else { "Not present" },
        if crypttab { Status::Good } else { Status::Unknown },
        None,
    ));

    // --- Encrypted swap ---
    let swap_enc = read_file("/proc/swaps")
        .map(|s| {
            s.lines()
                .skip(1)
                .any(|l| l.contains("dm-") || l.contains("crypt"))
        })
        .unwrap_or(false);
    results.push(CheckResult::new(
        "encryption",
        "Encrypted Swap",
        if swap_enc { "Likely encrypted" } else { "Not detected / no swap" },
        if swap_enc { Status::Good } else { Status::Warn },
        Some("Unencrypted swap can leak sensitive data to disk"),
    ));

    // --- TPM chip ---
    let tpm = std::path::Path::new("/sys/class/tpm/tpm0").exists()
        || std::path::Path::new("/sys/class/tpm/tpm1").exists();
    results.push(CheckResult::new(
        "encryption",
        "TPM Chip",
        if tpm { "Present" } else { "Not detected" },
        if tpm { Status::Good } else { Status::Unknown },
        Some("TPM enables hardware-backed key storage and measured boot"),
    ));

    // --- Home directory encryption ---
    let home = std::env::var("HOME").unwrap_or_default();
    let mounts = read_file("/proc/mounts").unwrap_or_default();
    let home_enc = mounts.lines().any(|l| {
        (l.contains("ecryptfs") || l.contains("fscrypt") || l.contains("crypto_LUKS"))
            && l.contains(home.as_str())
    });
    results.push(CheckResult::new(
        "encryption",
        "Home Dir Encryption",
        if home_enc { "Encrypted mount detected" } else { "Not detected" },
        if home_enc { Status::Good } else { Status::Warn },
        Some("ecryptfs or fscrypt home encryption protects user data at rest"),
    ));

    results
}
