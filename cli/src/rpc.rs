use anyhow::{Context, Result};
use solana_rpc_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_sdk::account::Account;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiMessage,
    UiTransactionEncoding,
};
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────
// Enriched transaction data used by the rule engine
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TransactionInfo {
    /// Signature string
    pub signature: String,
    /// Number of required signers declared in the message header
    pub num_required_signers: u8,
    /// Compute units consumed (None if not reported by RPC)
    pub compute_units: Option<u64>,
    /// True if the transaction ended with a runtime error
    pub failed: bool,
    /// Error description if failed
    pub error: Option<String>,
}

// ─────────────────────────────────────────────────────────────
// RPC client wrapper
// ─────────────────────────────────────────────────────────────

pub struct SolanaRpc {
    pub client: RpcClient,
}

impl SolanaRpc {
    pub fn new(url: &str) -> Self {
        Self {
            client: RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed()),
        }
    }

    /// Fetch all accounts owned by `program_id`.
    pub fn get_program_accounts(&self, program_id: &Pubkey) -> Result<Vec<(Pubkey, Account)>> {
        self.client
            .get_program_accounts(program_id)
            .with_context(|| format!("RPC get_program_accounts failed for {}", program_id))
    }

    /// Minimum lamports for rent exemption given `data_len` bytes.
    pub fn get_min_rent_exempt_balance(&self, data_len: usize) -> Result<u64> {
        self.client
            .get_minimum_balance_for_rent_exemption(data_len)
            .context("RPC get_minimum_balance_for_rent_exemption failed")
    }

    /// Fetch up to `limit` recent transaction signatures for `address`.
    pub fn get_recent_signatures(&self, address: &Pubkey, limit: usize) -> Result<Vec<String>> {
        let config = GetConfirmedSignaturesForAddress2Config {
            limit: Some(limit),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        };
        let sigs = self
            .client
            .get_signatures_for_address_with_config(address, config)
            .with_context(|| format!("RPC get_signatures_for_address failed for {}", address))?;

        Ok(sigs.into_iter().map(|s| s.signature).collect())
    }

    /// Fetch and parse a single transaction into `TransactionInfo`.
    pub fn get_transaction(&self, sig_str: &str) -> Result<TransactionInfo> {
        let sig = Signature::from_str(sig_str)
            .with_context(|| format!("Invalid signature: {}", sig_str))?;

        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };

        let tx = self
            .client
            .get_transaction_with_config(&sig, config)
            .with_context(|| format!("RPC get_transaction failed for {}", sig_str))?;

        Ok(parse_transaction(sig_str, &tx))
    }
}

// ─────────────────────────────────────────────────────────────
// Internal parsing
// ─────────────────────────────────────────────────────────────

fn parse_transaction(
    sig_str: &str,
    tx: &EncodedConfirmedTransactionWithStatusMeta,
) -> TransactionInfo {
    use solana_transaction_status_client_types::option_serializer::OptionSerializer;

    let meta = tx.transaction.meta.as_ref();

    // ── Compute units ────────────────────────────────────────
    let compute_units = meta.and_then(|m| match &m.compute_units_consumed {
        OptionSerializer::Some(cu) => Some(*cu),
        _ => None,
    });

    // ── Failed / error ───────────────────────────────────────
    let (failed, error) = match meta.and_then(|m| m.err.as_ref()) {
        Some(e) => (true, Some(format!("{:?}", e))),
        None => (false, None),
    };

    // ── Signer count from message header ─────────────────────
    let num_required_signers = match &tx.transaction.transaction {
        EncodedTransaction::Json(ui_tx) => match &ui_tx.message {
            UiMessage::Raw(raw) => raw.header.num_required_signatures,
            UiMessage::Parsed(_) => 1,
        },
        _ => 1,
    };

    TransactionInfo {
        signature: sig_str.to_string(),
        num_required_signers,
        compute_units,
        failed,
        error,
    }
}
