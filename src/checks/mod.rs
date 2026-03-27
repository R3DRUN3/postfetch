pub mod encryption;
pub mod firewall;
pub mod dns;
pub mod telemetry;
pub mod sandboxing;
pub mod hardening;
pub mod network;

use std::process::Command;

pub fn cmd_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        })
}

pub fn which(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}
