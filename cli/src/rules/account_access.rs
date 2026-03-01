use crate::findings::{Category, Finding, Severity};
use solana_sdk::account::Account;
use solana_sdk::pubkey::Pubkey;

/// Minimum data length for a properly initialized Anchor account (8-byte discriminator).
const ANCHOR_DISCRIMINATOR_LEN: usize = 8;

/// Analyzes account structural patterns for anomalies.
///
/// Ghost accounts (0-byte data, owned by program): LOW — may be uninitialized or leftovers.
/// Empty-discriminator accounts (exactly 0 data bytes): LOW — no meaningful state stored.
pub fn check(accounts: &[(Pubkey, Account)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (pubkey, account) in accounts {
        // Skip executable accounts (they're program code, not state)
        if account.executable {
            continue;
        }

        // ── Ghost accounts (zero data) ────────────────────────
        if account.data.is_empty() {
            findings.push(Finding::new(
                Category::AccountAccess,
                Severity::Low,
                pubkey.to_string(),
                "Program-owned account has zero data bytes. This account holds no state \
                 and may be an uninitialized or abandoned ghost account."
                    .to_string(),
                "Verify this account is intentionally empty. If it is unused, close it \
                 with a 'close' constraint or instruction to reclaim rent lamports."
                    .to_string(),
            ));
        }
        // ── Below minimum Anchor state size ──────────────────
        else if account.data.len() < ANCHOR_DISCRIMINATOR_LEN {
            findings.push(Finding::new(
                Category::AccountAccess,
                Severity::Low,
                pubkey.to_string(),
                format!(
                    "Program-owned account has {} data byte(s), which is below the minimum \
                     of {} bytes needed for an Anchor account discriminator. \
                     This account may be incorrectly initialized or misallocated.",
                    account.data.len(),
                    ANCHOR_DISCRIMINATOR_LEN
                ),
                "Ensure the account was initialized with sufficient space (at least 8 bytes \
                 for the discriminator, plus fields). Use Anchor's 'space' constraint: \
                 #[account(init, space = 8 + YourStruct::SIZE)]"
                    .to_string(),
            ));
        }
    }

    findings
}
