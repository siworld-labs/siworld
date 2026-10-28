//! Verified-work fork selection and bounded local candidate admission.
//!
//! The canonical store reconstructs the common ancestor from its own history.
//! Every candidate block then uses the same atomic transition as production and
//! replay. Local capacity exhaustion never establishes consensus invalidity.
use crate::state::{BlockVerifier, MAX_REORG_DEPTH, State};
use crate::wire::{BLOCK_FIXED_BYTES, Block, Hash, TX_PREFIX_BYTES};
use siworld_core::pow::Work;
use std::fmt;

/// Logical owned-buffer limits, not an allocator or whole-process RSS bound.
/// Replay work is bounded separately because older stores have no trusted state
/// checkpoints. Raising a local budget never changes block validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidatePolicy {
    pub max_blocks: usize,
    pub max_bytes: usize,
    pub max_replay_blocks: u64,
    pub max_retained_bytes: usize,
}
impl Default for CandidatePolicy {
    fn default() -> Self {
        Self {
            max_blocks: 32,
            max_bytes: 640 * 1024 * 1024,
            max_replay_blocks: 4096,
            max_retained_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    Invalid(String),
    ResourceExhausted(&'static str),
    /// The retained finalized prefix cannot be replaced automatically.
    ReorganizationLimit,
    Local(String),
}
impl ChainError {
    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }
}
impl fmt::Display for ChainError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(output, "invalid candidate: {reason}"),
            Self::ResourceExhausted(reason) => {
                write!(output, "candidate resource unavailable: {reason}")
            }
            Self::ReorganizationLimit => {
                output.write_str("candidate diverges before retained finality boundary")
            }
            Self::Local(reason) => write!(output, "local chain unavailable: {reason}"),
        }
    }
}
impl std::error::Error for ChainError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BranchOutcome {
    Unchanged {
        candidate_height: u64,
        candidate_work: Work,
    },
    Adopted {
        detached: u64,
        attached: usize,
        height: u64,
        tip: Hash,
    },
}

pub fn finalized_height(tip_height: u64) -> u64 {
    tip_height.saturating_sub(MAX_REORG_DEPTH)
}

pub(crate) fn check_ancestor(tip_height: u64, ancestor_height: u64) -> Result<(), ChainError> {
    if ancestor_height > tip_height {
        return Err(ChainError::Invalid(
            "ancestor is beyond canonical tip".into(),
        ));
    }
    if ancestor_height < finalized_height(tip_height) {
        return Err(ChainError::ReorganizationLimit);
    }
    Ok(())
}

pub(crate) fn prefer_work(current: Work, candidate: Work) -> bool {
    candidate > current
}

pub(crate) struct ValidatedBranch {
    pub accepted: State,
    pub records: Vec<(u64, Vec<u8>)>,
}

/// Preflight owned proof/vector capacities before allocating encoded copies.
/// Per-entry accounting includes fixed metadata and a conservative allowance
/// for set nodes; it does not claim allocator/page accounting.
pub(crate) fn candidate_budget(
    blocks: &[Block],
    policy: CandidatePolicy,
) -> Result<usize, ChainError> {
    if blocks.is_empty() {
        return Err(ChainError::Invalid("empty branch".into()));
    }
    if blocks.len() > policy.max_blocks {
        return Err(ChainError::ResourceExhausted("candidate block count"));
    }
    let mut bytes = 0usize;
    for block in blocks {
        block.validate_shape().map_err(ChainError::Invalid)?;
        let encoded = block.transactions.iter().fold(
            BLOCK_FIXED_BYTES.checked_add(block.settlement_proof.len()),
            |total, tx| {
                total
                    .and_then(|n| n.checked_add(4 + TX_PREFIX_BYTES))
                    .and_then(|n| n.checked_add(tx.proof.len()))
            },
        );
        let owned = block.transactions.iter().fold(
            block
                .transactions
                .capacity()
                .checked_mul(std::mem::size_of::<crate::wire::Transaction>())
                .and_then(|n| n.checked_add(block.settlement_proof.capacity()))
                .and_then(|n| n.checked_add(std::mem::size_of::<Block>())),
            |total, tx| total.and_then(|n| n.checked_add(tx.proof.capacity())),
        );
        bytes = encoded
            .and_then(|n| n.checked_add(32 + 64))
            .and_then(|n| owned.and_then(|owned| n.checked_add(owned)))
            .and_then(|n| bytes.checked_add(n))
            .ok_or(ChainError::ResourceExhausted("candidate byte accounting"))?;
        if bytes > policy.max_bytes {
            return Err(ChainError::ResourceExhausted("candidate bytes"));
        }
    }
    Ok(bytes)
}

fn state_budget(state: &State) -> Option<usize> {
    // BTreeSet entries include an explicit metadata allowance. This estimate is
    // local policy only; an external process guard remains necessary for RSS.
    state
        .spent
        .len()
        .checked_add(state.commitments.len())?
        .checked_mul(128)?
        .checked_add(
            state
                .leaves
                .capacity()
                .checked_mul(std::mem::size_of::<native::multi_asset::Digest>())?,
        )?
        .checked_add(
            state
                .snapshots
                .capacity()
                .checked_mul(std::mem::size_of::<crate::state::CanonicalSnapshot>())?,
        )?
        .checked_add(state.timestamps.capacity().checked_mul(8)?)?
        .checked_add(8192)
}

pub(crate) fn check_state_budget(
    state: &State,
    other_bytes: usize,
    policy: CandidatePolicy,
) -> Result<(), ChainError> {
    if state_budget(state)
        .and_then(|n| n.checked_add(other_bytes))
        .is_none_or(|n| n > policy.max_bytes)
    {
        return Err(ChainError::ResourceExhausted("candidate state bytes"));
    }
    Ok(())
}

pub(crate) fn validate_candidate(
    canonical: &State,
    ancestor: State,
    blocks: &[Block],
    policy: CandidatePolicy,
    verifier: &impl BlockVerifier,
) -> Result<ValidatedBranch, ChainError> {
    check_ancestor(canonical.height, ancestor.height)?;
    if ancestor.config != canonical.config
        || !canonical.snapshots.iter().any(|snapshot| {
            snapshot.selector.height == ancestor.height
                && snapshot.selector.block_id == ancestor.tip
        })
    {
        return Err(ChainError::Local(
            "reconstructed ancestor is not canonical".into(),
        ));
    }
    let candidate_bytes = candidate_budget(blocks, policy)?;
    let mut accepted = ancestor;
    let mut records = Vec::new();
    records
        .try_reserve(blocks.len())
        .map_err(|_| ChainError::ResourceExhausted("candidate record allocation"))?;
    for block in blocks {
        check_state_budget(&accepted, candidate_bytes, policy)?;
        accepted
            .apply(block, verifier)
            .map_err(ChainError::Invalid)?;
        check_state_budget(&accepted, candidate_bytes, policy)?;
        let mut encoded = block.encode().map_err(ChainError::Invalid)?;
        encoded
            .try_reserve_exact(32)
            .map_err(|_| ChainError::ResourceExhausted("candidate fingerprint allocation"))?;
        encoded.extend_from_slice(&accepted.fingerprint());
        records.push((block.height, encoded));
    }
    Ok(ValidatedBranch { accepted, records })
}

#[cfg(test)]
mod tests;
