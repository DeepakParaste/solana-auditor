use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "solana-auditor",
    version = "0.1.0",
    about = "Automated Solana Program Health Scanner",
    long_about = "Performs read-only security and correctness audits on deployed Solana programs.\nAnalyzes account rent status, signer privilege hygiene, compute usage, and account patterns.\nExits with code 1 if any HIGH severity findings are detected (CI/CD mode)."
)]
pub struct Cli {
    /// Target program ID (base58-encoded public key)
    #[arg(short, long, value_name = "PUBKEY")]
    pub program_id: String,

    /// Solana cluster to query
    #[arg(short, long, value_name = "CLUSTER", default_value = "devnet")]
    pub cluster: ClusterChoice,

    /// Output format
    #[arg(short, long, value_name = "FORMAT", default_value = "text")]
    pub output: OutputFormat,

    /// Show only findings at or above this severity
    #[arg(short, long, value_name = "LEVEL")]
    pub severity: Option<SeverityFilter>,

    /// Maximum number of recent transactions to inspect
    #[arg(long, value_name = "N", default_value = "50")]
    pub limit: usize,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ClusterChoice {
    #[value(name = "devnet")]
    Devnet,
    #[value(name = "mainnet-beta")]
    MainnetBeta,
    #[value(name = "testnet")]
    Testnet,
}

impl ClusterChoice {
    pub fn rpc_url(&self) -> &'static str {
        match self {
            ClusterChoice::Devnet => "https://api.devnet.solana.com",
            ClusterChoice::MainnetBeta => "https://api.mainnet-beta.solana.com",
            ClusterChoice::Testnet => "https://api.testnet.solana.com",
        }
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    #[value(name = "text")]
    Text,
    #[value(name = "json")]
    Json,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum SeverityFilter {
    #[value(name = "high")]
    High,
    #[value(name = "medium")]
    Medium,
    #[value(name = "low")]
    Low,
}
