use crate::findings::{Category, Finding, Severity};
use crate::rpc::TransactionInfo;

/// Thresholds for signer-count anomaly detection.
const HIGH_SIGNER_THRESHOLD: u8 = 3;

/// Analyzes the signer count declared in each transaction's message header.
///
/// Severity: MEDIUM — instructions forcing unnecessary signers add friction
/// for users and can indicate accidental privilege over-requirement.
pub fn check(transactions: &[TransactionInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for tx in transactions {
        if tx.num_required_signers >= HIGH_SIGNER_THRESHOLD {
            findings.push(Finding::new(
                Category::SignerHygiene,
                Severity::Medium,
                tx.signature.clone(),
                format!(
                    "Transaction requires {} signer(s). Instructions with {} or more required \
                     signers may be demanding unnecessary authority over the instruction.",
                    tx.num_required_signers, HIGH_SIGNER_THRESHOLD
                ),
                "Review each signer account in the instruction context. Remove 'Signer' \
                 constraints on accounts that are not mutated or do not need to authorize \
                 the operation. Prefer PDAs with 'invoke_signed' for program-controlled authority."
                    .to_string(),
            ));
        }
    }

    findings
}
