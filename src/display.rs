use colored::Colorize;
use crate::types::{CheckResult, Status};

const LOGO_RAW: &str = r#"
__________               __   
\______   \____  _______/  |_ 
 |     ___/  _ \/  ___/\   __\
 |    |  (  <_> )___ \  |  |  
 |____|   \____/____  > |__|  
    ___________     __         .__     
    \_   _____/____/  |_  ____ |  |__  
    |    __)/ __ \   __\/ ___\|  |  \ 
    |     \\  ___/|  | \  \___|   Y  \
    \___  / \___  >__|  \___  >___|  /
        \/      \/          \/     \/ 

   privacy & security audit
"#;

fn logo_lines() -> Vec<&'static str> {
    LOGO_RAW.lines().collect()
}

fn status_icon(status: &Status) -> &'static str {
    match status {
        Status::Good    => "✔",
        Status::Warn    => "⚠",
        Status::Bad     => "✘",
        Status::Unknown => "?",
    }
}

fn colorize_icon(icon: &'static str, status: &Status) -> colored::ColoredString {
    match status {
        Status::Good    => icon.green().bold(),
        Status::Warn    => icon.yellow().bold(),
        Status::Bad     => icon.red().bold(),
        Status::Unknown => icon.dimmed(),
    }
}

fn colorize_value(s: &str, status: &Status) -> colored::ColoredString {
    match status {
        Status::Good    => s.green(),
        Status::Warn    => s.yellow(),
        Status::Bad     => s.red(),
        Status::Unknown => s.dimmed(),
    }
}

fn build_right_lines(results: &[CheckResult], warnings_only: bool) -> Vec<(String, Option<Status>)> {
    let mut lines: Vec<(String, Option<Status>)> = Vec::new();

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string());
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    let hostname = if hostname.is_empty() {
        "localhost".to_string()
    } else {
        hostname
    };

    lines.push((format!("{}@{}", username, hostname), None));
    lines.push(("─".repeat(42), None));

    let mut current_module = String::new();
    let mut good = 0usize;
    let mut warn = 0usize;
    let mut bad  = 0usize;
    let mut unk  = 0usize;

    for r in results {
        match r.status {
            Status::Good    => good += 1,
            Status::Warn    => warn += 1,
            Status::Bad     => bad  += 1,
            Status::Unknown => unk  += 1,
        }

        if warnings_only && r.status == Status::Good {
            continue;
        }

        if r.module != current_module {
            current_module = r.module.clone();
            lines.push(("".to_string(), None));
            lines.push((format!("  {}", r.module.to_uppercase()), None));
        }

        let icon  = status_icon(&r.status);
        let label = format!("{:<26}", r.label);
        let line  = format!("  {} {}  {}", icon, label, r.value);
        lines.push((line, Some(r.status.clone())));

        if let Some(detail) = &r.detail {
            lines.push((format!("      ↳ {}", detail), Some(Status::Unknown)));
        }
    }

    lines.push(("".to_string(), None));
    lines.push(("─".repeat(42), None));
    lines.push((
        format!(
            "  {} good  {} warn  {} bad  {} unknown",
            good, warn, bad, unk
        ),
        None,
    ));

    lines
}

pub fn render_report(results: &[CheckResult], warnings_only: bool) {
    let logo = logo_lines();
    let right = build_right_lines(results, warnings_only);

    let logo_width = logo.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let total = logo.len().max(right.len());

    for i in 0..total {
        let logo_line = logo.get(i).copied().unwrap_or("");
        let padded_logo = format!("{:<width$}", logo_line, width = logo_width);
        let colored_logo = padded_logo.cyan().bold();

        if let Some((text, status_opt)) = right.get(i) {
            match status_opt {
                None => {
                    print!("{}  ", colored_logo);
                    if i == 0 {
                        println!("{}", text.bold().white());
                    } else if text.starts_with('─') {
                        println!("{}", text.dimmed());
                    } else if !text.trim().is_empty()
                        && text.trim().chars().all(|c| c.is_uppercase() || c == ' ')
                    {
                        println!("{}", text.bold().white());
                    } else {
                        println!("{}", text.dimmed());
                    }
                }
                Some(status) => {
                    print!("{}  ", colored_logo);
                    let icon_str = status_icon(status);
                    let rest = text.trim_start_matches(|c: char| c == ' ');
                    let after_icon = rest.trim_start_matches(icon_str);
                    if let Some(sep) = after_icon.find("  ") {
                        let label = after_icon[..sep].trim();
                        let value = after_icon[sep..].trim();
                        println!(
                            "  {}  {:<26}  {}",
                            colorize_icon(icon_str, status),
                            label.white(),
                            colorize_value(value, status),
                        );
                    } else {
                        println!("{}", colorize_value(text, status));
                    }
                }
            }
        } else {
            println!("{}", colored_logo);
        }
    }

    println!();
}
