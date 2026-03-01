use crate::findings::{Category, Finding, Severity};
use crate::rpc::SolanaRpc;
use anyhow::Result;
use solana_sdk::pubkey::Pubkey;

/// Checks every program-owned account for rent-exemption violations.
///
/// Severity: HIGH — non-rent-exempt accounts can be garbage-collected by
/// the runtime, causing permanent data loss.
pub fn check(rpc: &SolanaRpc, program_id: &Pubkey) -> Result<Vec<Finding>> {
    let accounts = rpc.get_program_accounts(program_id)?;
    let mut findings = Vec::new();

    for (pubkey, account) in &accounts {
        // Skip executable accounts (program accounts themselves)
        if account.executable {
            continue;
        }

        let data_len = account.data.len();
        let min_rent = rpc.get_min_rent_exempt_balance(data_len)?;

        if account.lamports < min_rent {
            let deficit = min_rent.saturating_sub(account.lamports);
            findings.push(Finding::new(
                Category::RentSafety,
                Severity::High,
                pubkey.to_string(),
                format!(
                    "Account holds {} lamport(s) but requires {} lamports for rent exemption \
                     ({} bytes of data). Deficit: {} lamports.",
                    account.lamports, min_rent, data_len, deficit
                ),
                format!(
                    "Fund this account with at least {} additional lamport(s) to achieve \
                     rent exemption, or close it to reclaim the lamports.",
                    deficit
                ),
            ));
        }
    }

    Ok(findings)
}
