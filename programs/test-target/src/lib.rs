use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::system_instruction;

declare_id!("4tHdcogDvudDsy6QoDkaMGXq1H2fGxL7fUT5EniBwyz5");

// ─────────────────────────────────────────────────────────────
// Account state definitions
// ─────────────────────────────────────────────────────────────

/// A healthy, properly initialized PDA account.
#[account]
pub struct HealthyState {
    /// The authority that initialized this account
    pub authority: Pubkey,
    /// Some stored value
    pub data: u64,
    /// PDA bump
    pub bump: u8,
}

impl HealthyState {
    pub const SIZE: usize = 8 + 32 + 8 + 1; // discriminator + fields
}

/// Stores the result of a compute-heavy operation.
#[account]
pub struct HeavyState {
    /// The authority that created this account
    pub authority: Pubkey,
    /// Result of the last heavy computation (SHA-256 chain)
    pub last_hash: [u8; 32],
    /// PDA bump
    pub bump: u8,
}

impl HeavyState {
    pub const SIZE: usize = 8 + 32 + 32 + 1;
}

// ─────────────────────────────────────────────────────────────
// Instruction contexts
// ─────────────────────────────────────────────────────────────

/// HEALTHY: Creates a properly-funded, rent-exempt PDA account.
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = HealthyState::SIZE,
        seeds = [b"healthy", authority.key().as_ref()],
        bump
    )]
    pub state: Account<'info, HealthyState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// VULNERABILITY 1: Creates a raw program-owned account with only 1 lamport (non-rent-exempt).
/// The underfunded_account keypair must be generated off-chain and passed in.
#[derive(Accounts)]
pub struct CreateUnderfunded<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Intentionally underfunded — used to demonstrate rent-exemption violations.
    #[account(mut)]
    pub underfunded_account: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// VULNERABILITY 2: Requires 3 signers when only authority is ever used.
#[derive(Accounts)]
pub struct ExcessiveSigner<'info> {
    #[account(
        mut,
        seeds = [b"healthy", authority.key().as_ref()],
        bump = state.bump
    )]
    pub state: Account<'info, HealthyState>,

    /// Only this signer is actually needed.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Unnecessary signer 1 — never read or written in instruction logic.
    pub extra_signer_one: Signer<'info>,

    /// Unnecessary signer 2 — never read or written in instruction logic.
    pub extra_signer_two: Signer<'info>,
}

/// VULNERABILITY 3: Performs a SHA-256 hash chain, consuming hundreds of thousands of CUs.
#[derive(Accounts)]
pub struct ComputeHeavy<'info> {
    #[account(
        init,
        payer = payer,
        space = HeavyState::SIZE,
        seeds = [b"heavy", payer.key().as_ref()],
        bump
    )]
    pub state: Account<'info, HeavyState>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// VULNERABILITY 4: Always fails — populates transaction history with failed txs.
#[derive(Accounts)]
pub struct FailTrigger<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
}

// ─────────────────────────────────────────────────────────────
// Custom errors
// ─────────────────────────────────────────────────────────────

#[error_code]
pub enum ProgramError {
    #[msg("This instruction always fails — used for failed-transaction detection testing.")]
    AlwaysFails,
}

// ─────────────────────────────────────────────────────────────
// Program instructions
// ─────────────────────────────────────────────────────────────

#[program]
pub mod test_target {
    use super::*;

    /// HEALTHY: Creates a properly rent-exempt PDA. The scanner should NOT flag this.
    pub fn initialize(ctx: Context<Initialize>, data: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.data = data;
        state.bump = ctx.bumps.state;
        msg!("Initialized healthy state with data={}", data);
        Ok(())
    }

    /// VULNERABILITY 1 — RentSafety/HIGH:
    /// Creates a program-owned account with only 1 lamport.
    /// Minimum rent-exempt balance for 16 bytes is ~1,920,000 lamports.
    /// solana-auditor rent rule must flag this as HIGH.
    pub fn create_underfunded(ctx: Context<CreateUnderfunded>) -> Result<()> {
        let ix = system_instruction::create_account(
            &ctx.accounts.payer.key(),
            &ctx.accounts.underfunded_account.key(),
            1,           // 1 lamport — severely below rent exemption threshold
            16,          // 16 bytes of data space
            ctx.program_id,
        );

        invoke(
            &ix,
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.underfunded_account.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        msg!("Created underfunded account: {}", ctx.accounts.underfunded_account.key());
        Ok(())
    }

    /// VULNERABILITY 2 — SignerHygiene/MEDIUM:
    /// Requires extra_signer_one and extra_signer_two as signers even though
    /// only authority is needed to mutate the state.
    pub fn excessive_signer(ctx: Context<ExcessiveSigner>, value: u64) -> Result<()> {
        ctx.accounts.state.data = value;
        msg!(
            "excessive_signer called with {} signers; only authority needed. value={}",
            3,
            value
        );
        Ok(())
    }

    /// VULNERABILITY 3 — ComputeRisk/MEDIUM:
    /// Burns CUs with a tight arithmetic loop, exceeding the
    /// 400,000 CU scanner threshold. Caller must set compute budget >= 500,000 CU.
    pub fn compute_heavy(ctx: Context<ComputeHeavy>) -> Result<()> {
        let mut acc: u64 = ctx.accounts.payer.key().to_bytes()[0] as u64;
        for i in 0u64..200_000 {
            // wrapping_mul + wrapping_add to avoid panics; this burns CUs in a loop
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i ^ 1442695040888963407);
        }
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.payer.key();
        state.last_hash = [acc as u8; 32];
        state.bump = ctx.bumps.state;
        msg!("compute_heavy completed 200k arithmetic rounds, acc={}", acc);
        Ok(())
    }

    /// VULNERABILITY 4 — ComputeRisk/MEDIUM:
    /// Always returns an error. Demonstrates failed-transaction detection.
    pub fn fail_trigger(_ctx: Context<FailTrigger>) -> Result<()> {
        msg!("fail_trigger: about to fail intentionally");
        err!(ProgramError::AlwaysFails)
    }
}
