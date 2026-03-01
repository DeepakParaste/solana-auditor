mod analyzer;
mod cli;
mod findings;
mod report;
mod rpc;
mod rules;

use analyzer::Analyzer;
use clap::Parser;
use cli::{Cli, OutputFormat, SeverityFilter};
use findings::Severity;
use rpc::SolanaRpc;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

fn main() {
    let args = Cli::parse();

    // ── Validate program ID ──────────────────────────────────
    let program_id = match Pubkey::from_str(&args.program_id) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("[!] Invalid program ID '{}': {}", args.program_id, e);
            std::process::exit(2);
        }
    };

    let cluster_url = args.cluster.rpc_url();
    let cluster_name = format!("{:?}", args.cluster).to_lowercase();

    eprintln!(
        "[*] solana-auditor starting | program={} cluster={}",
        args.program_id, cluster_name
    );

    let rpc = SolanaRpc::new(cluster_url);

    // ── Run analysis ─────────────────────────────────────────
    let mut report = match Analyzer::run(&rpc, &program_id, &cluster_name, args.limit) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Analysis failed: {}", e);
            std::process::exit(2);
        }
    };

    // ── Apply severity filter ────────────────────────────────
    if let Some(filter) = &args.severity {
        let min = match filter {
            SeverityFilter::High => Severity::High,
            SeverityFilter::Medium => Severity::Medium,
            SeverityFilter::Low => Severity::Low,
        };
        Analyzer::filter_by_severity(&mut report, &min);
    }

    // ── Emit report ──────────────────────────────────────────
    match args.output {
        OutputFormat::Json => report::print_json(&report),
        OutputFormat::Text => report::print_text(&report),
    }

    // ── CI/CD exit code ──────────────────────────────────────
    // Exit 1 if any HIGH severity findings are present (enables pipeline gating).
    // Exit 0 otherwise (clean bill of health).
    if report.high_count() > 0 {
        eprintln!(
            "[!] {} HIGH severity finding(s) detected — exiting with code 1",
            report.high_count()
        );
        std::process::exit(1);
    }
}
