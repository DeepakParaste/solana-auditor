use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
// Core data types shared across all modules
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    RentSafety,
    SignerHygiene,
    ComputeRisk,
    AccountAccess,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::RentSafety => write!(f, "Rent Safety"),
            Category::SignerHygiene => write!(f, "Signer Hygiene"),
            Category::ComputeRisk => write!(f, "Compute Risk"),
            Category::AccountAccess => write!(f, "Account Access"),
        }
    }
}

/// A single audit finding produced by one of the heuristic rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Vulnerability category
    pub category: Category,
    /// Severity tier
    pub severity: Severity,
    /// The on-chain subject (account pubkey or transaction signature)
    pub subject: String,
    /// Human-readable description of what was observed
    pub evidence: String,
    /// Concrete fix recommendation
    pub remediation: String,
}

impl Finding {
    pub fn new(
        category: Category,
        severity: Severity,
        subject: impl Into<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            subject: subject.into(),
            evidence: evidence.into(),
            remediation: remediation.into(),
        }
    }
}

/// The full report produced after analyzing a program.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub program_id: String,
    pub cluster: String,
    pub accounts_scanned: usize,
    pub transactions_scanned: usize,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn high_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::High).count()
    }
    pub fn medium_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::Medium).count()
    }
    pub fn low_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::Low).count()
    }
}
