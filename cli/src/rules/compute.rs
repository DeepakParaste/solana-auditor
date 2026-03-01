use crate::findings::{Category, Finding, Severity};
use crate::rpc::TransactionInfo;

/// Transactions consuming more CUs than this are flagged MEDIUM.
const HIGH_CU_THRESHOLD: u64 = 400_000;

/// Analyzes compute unit usage and failed transactions.
///
/// HIGH CU usage (> 400K): MEDIUM severity — approaching runtime limits.
/// Failed transactions: MEDIUM severity — repeated failures indicate logic errors.
pub fn check(transactions: &[TransactionInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for tx in transactions {
        // ── Compute unit anomaly ──────────────────────────────
        if let Some(cu) = tx.compute_units {
            if cu > HIGH_CU_THRESHOLD {
                findings.push(Finding::new(
                    Category::ComputeRisk,
                    Severity::Medium,
                    tx.signature.clone(),
                    format!(
                        "Transaction consumed {} compute units (threshold: {}). \
                         High compute usage can cause transaction failures \
                         and increases user cost under priority fees.",
                        cu, HIGH_CU_THRESHOLD
                    ),
                    "Profile the instruction for expensive loops or repeated syscalls. \
                     Consider reducing iteration counts, caching intermediate values, \
                     or splitting the operation across multiple transactions. \
                     Explicitly set compute budget with ComputeBudgetProgram."
                        .to_string(),
                ));
            }
        }

        // ── Failed transaction ────────────────────────────────
        if tx.failed {
            let error_detail = tx
                .error
                .as_deref()
                .unwrap_or("unknown error");

            findings.push(Finding::new(
                Category::ComputeRisk,
                Severity::Medium,
                tx.signature.clone(),
                format!(
                    "Transaction failed at runtime. Error: {}. \
                     Repeated failed transactions may indicate missing \
                     input validation, incorrect account ordering, or \
                     logic errors in instruction handlers.",
                    error_detail
                ),
                "Review the instruction handler for missing require!() guards, \
                 invalid account state assumptions, or incorrect PDA derivation. \
                 Add pre-condition checks to reject invalid inputs early."
                    .to_string(),
            ));
        }
    }

    findings
}
