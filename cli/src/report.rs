use crate::findings::{AuditReport, Severity};
use colored::Colorize;

const DIVIDER: &str = "═══════════════════════════════════════════════════════════";

// ─────────────────────────────────────────────────────────────
// Text report
// ─────────────────────────────────────────────────────────────

pub fn print_text(report: &AuditReport) {
    println!("{}", DIVIDER.cyan());
    println!("{}", "  solana-auditor · Solana Program Health Scanner".cyan().bold());
    println!("{}", DIVIDER.cyan());
    println!("  Program  : {}", report.program_id.yellow());
    println!("  Cluster  : {}", report.cluster.yellow());
    println!(
        "  Accounts : {}  |  Transactions : {}",
        report.accounts_scanned, report.transactions_scanned
    );
    println!("{}", DIVIDER.cyan());

    if report.findings.is_empty() {
        println!("{}", "  ✓ No findings detected.".green().bold());
    } else {
        for f in &report.findings {
            let severity_label = match f.severity {
                Severity::High => format!("[{}]", f.severity).red().bold().to_string(),
                Severity::Medium => format!("[{}]", f.severity).yellow().bold().to_string(),
                Severity::Low => format!("[{}]", f.severity).blue().bold().to_string(),
            };

            println!();
            println!("  {} {}", severity_label, f.category.to_string().bold());
            println!("  Subject     : {}", f.subject.dimmed());
            println!("  Evidence    : {}", f.evidence);
            println!("  Remediation : {}", f.remediation.italic());
        }
    }

    println!();
    println!("{}", DIVIDER.cyan());
    println!(
        "  Summary: {} finding(s)  {}  {}  {}",
        report.findings.len(),
        format!("HIGH: {}", report.high_count()).red().bold(),
        format!("MEDIUM: {}", report.medium_count()).yellow().bold(),
        format!("LOW: {}", report.low_count()).blue().bold(),
    );
    println!("{}", DIVIDER.cyan());
}

// ─────────────────────────────────────────────────────────────
// JSON report
// ─────────────────────────────────────────────────────────────

pub fn print_json(report: &AuditReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("[!] Failed to serialize report: {}", e),
    }
}
