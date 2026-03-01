# solana-auditor

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A read-only Rust CLI tool for auditing deployed Solana programs by analyzing on-chain account data and transaction history via RPC. No source code access or private keys are required.

`solana-auditor` fetches program-owned accounts, analyzes transaction metadata for anomalies, and identifies potential security risks such as rent-exemption violations, signer hygiene issues, and compute resource exhaustion.

------------------------------------------------------------------------

## Motivation
Traditional Solana audits often focus on the source code level. However, once a program is deployed, it's critical to monitor its "live health."

Today, developers rely on manual log inspection or custom indexers to detect if their program is behaving unexpectedly (e.g., creating non-rent-exempt accounts or hitting compute limits).

`solana-auditor` provides:
- **Zero-knowledge auditing**: No need for IDLs or source code.
- **On-chain snapshotting**: Directly analyzes live account state.
- **Historical transaction analysis**: Heuristic-based detection of recurring failures or inefficiencies.
- **CI/CD integration**: Structured output for automated security pipelines.

------------------------------------------------------------------------

## Core Features
- **Rent Safety Analysis**: Identifies accounts that are not rent-exempt, preventing garbage collection by the runtime.
- **Signer Hygiene**: Flags transactions with excessive or suspicious signer requirements.
- **Compute Risk Detection**: Identifies transactions that are hitting compute limits or consistently failing.
- **Account Access Heuristics**: Detects ghost accounts or misallocated state structures.
- **Flexible Output**: Supports both human-readable text and machine-parsable JSON.
- **Fast Execution**: Purely RPC-based, lightweight, and asynchronous.

------------------------------------------------------------------------

## Quick Install

### Build from source
```bash
git clone https://github.com/DeepakParaste/solana-auditor
cd solana-auditor
cargo build --release
```

------------------------------------------------------------------------

## Usage

### Basic Scan
```bash
./target/release/solana-auditor --program-id <PROGRAM_ID> --cluster devnet
```

### With Transaction Limit
```bash
./target/release/solana-auditor --program-id <PROGRAM_ID> --cluster mainnet-beta --limit 100
```

### JSON Output (CI / Automation)
```bash
./target/release/solana-auditor --program-id <PROGRAM_ID> --output json --severity medium
```

Exit codes:
- `0`: No HIGH severity findings.
- `1`: High severity findings detected.
- `2`: Fatal scanner error.

------------------------------------------------------------------------

## Architecture Overview
CLI Input (Program ID, Cluster)
       ↓
    RPC Fetch (Program Accounts)
       ↓
    RPC Fetch (Recent Signatures)
       ↓
    RPC Fetch (Transaction Metadata)
       ↓
    Rule Engine (Heuristics)
       ↓
    Finding Aggregation
       ↓
    Report Generation (Text/JSON)

------------------------------------------------------------------------

## Integration with Anchor
While `solana-auditor` is zero-knowledge, it works seamlessly with Anchor workflows to verify that instructions don't leak signer authority or waste compute units.

Example workflow:
1. Deploy your Anchor program to devnet.
2. Run your integration tests to populate on-chain data.
3. Run `solana-auditor` to verify the "live" health of your program accounts.

------------------------------------------------------------------------

## Project Structure
`cli/src/`
- `main.rs`: CLI orchestration and exit code handling.
- `rpc.rs`: Agave 2.3.x RPC client wrapper.
- `analyzer.rs`: Rule engine orchestrator.
- `rules/`: Individual heuristic modules (Rent, Signer, Compute, Access).
- `findings.rs`: Data models for security findings.

`programs/test-target/`
- `src/lib.rs`: Intentionally vulnerable program used for verification.

------------------------------------------------------------------------

## License
MIT
