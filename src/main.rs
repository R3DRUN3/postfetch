mod checks;
mod display;
mod types;

use clap::Parser;
use checks::{
    encryption::check_encryption,
    firewall::check_firewall,
    dns::check_dns,
    telemetry::check_telemetry,
    sandboxing::check_sandboxing,
    network::check_network,
    hardening::check_hardening,
};
use display::render_report;

#[derive(Parser, Debug)]
#[command(
    name = "postfetch",
    version,
    about = "A neofetch-style privacy and security audit tool for Linux",
    long_about = None
)]
struct Args {
    /// Show only failed/warning checks
    #[arg(short, long)]
    warnings_only: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Run only a specific module
    /// (encryption, firewall, dns, telemetry, sandboxing, hardening, network)
    #[arg(short, long)]
    module: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    let modules: Vec<&str> = match &args.module {
        Some(m) => vec![m.as_str()],
        None => vec![
            "encryption",
            "network",
            "firewall",
            "dns",
            "sandboxing",
            "telemetry",
            "hardening",
        ],
    };

    let mut results = Vec::new();

    for module in &modules {
        match *module {
            "encryption" => results.extend(check_encryption()),
            "network"    => results.extend(check_network()),
            "firewall"   => results.extend(check_firewall()),
            "dns"        => results.extend(check_dns()),
            "sandboxing" => results.extend(check_sandboxing()),
            "telemetry"  => results.extend(check_telemetry()),
            "hardening"  => results.extend(check_hardening()),
            other        => eprintln!("Unknown module: {}", other),
        }
    }

    render_report(&results, args.warnings_only);
}
