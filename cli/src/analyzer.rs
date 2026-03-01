use crate::findings::{AuditReport, Finding, Severity};
use crate::rpc::{SolanaRpc, TransactionInfo};
use crate::rules::{account_access, compute, rent, signer};
use anyhow::Result;
use solana_sdk::pubkey::Pubkey;

/// Orchestrates all heuristic rules and assembles the final audit report.
pub struct Analyzer;

impl Analyzer {
    pub fn run(
        rpc: &SolanaRpc,
        program_id: &Pubkey,
        cluster: &str,
        tx_limit: usize,
    ) -> Result<AuditReport> {
        // ── 1. Fetch on-chain data ────────────────────────────
        eprintln!("[*] Fetching program accounts...");
        let accounts = rpc.get_program_accounts(program_id).unwrap_or_else(|e| {
            eprintln!("[!] Could not fetch accounts: {}", e);
            vec![]
        });
        let accounts_scanned = accounts.len();

        eprintln!("[*] Fetching recent transaction signatures (limit={})...", tx_limit);
        let sigs = rpc.get_recent_signatures(program_id, tx_limit).unwrap_or_else(|e| {
            eprintln!("[!] Could not fetch signatures: {}", e);
            vec![]
        });

        eprintln!("[*] Fetching {} transaction(s)...", sigs.len());
        let mut transactions: Vec<TransactionInfo> = Vec::new();
        for sig in &sigs {
            match rpc.get_transaction(sig) {
                Ok(info) => transactions.push(info),
                Err(e) => eprintln!("[!] Skipping tx {} — {}", &sig[..12], e),
            }
        }
        let transactions_scanned = transactions.len();

        // ── 2. Apply rules ───────────────────────────────────
        eprintln!("[*] Running rule engine...");
        let mut findings: Vec<Finding> = Vec::new();

        // Rule: Rent Safety (needs live RPC for per-account threshold)
        match rent::check(rpc, program_id) {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => eprintln!("[!] Rent rule error: {}", e),
        }

        // Rule: Signer Hygiene (offline, uses transaction data)
        findings.extend(signer::check(&transactions));

        // Rule: Compute Risk (offline, uses transaction data)
        findings.extend(compute::check(&transactions));

        // Rule: Account Access Patterns (offline, uses account data)
        findings.extend(account_access::check(&accounts));

        // ── 3. Sort by severity (High first) ─────────────────
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(AuditReport {
            program_id: program_id.to_string(),
            cluster: cluster.to_string(),
            accounts_scanned,
            transactions_scanned,
            findings,
        })
    }

    /// Apply a severity filter to an existing report.
    pub fn filter_by_severity(report: &mut AuditReport, min: &Severity) {
        report.findings.retain(|f| &f.severity >= min);
    }
}
