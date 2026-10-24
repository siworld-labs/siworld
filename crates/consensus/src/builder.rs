//! Block production: fill with empty packages, sort, aggregate proofs, fill in
//! the coinbase, then run the same [`transition`] and [`check_proof`] as the
//! validator.

use siworld_circuits::dummy::dummy_slot;
use siworld_circuits::{AggregateError, FeeOpening, Leaf, ProofSystem, RelationContext, SlotProof};
use siworld_core::issuance::{block_reward, epoch_of, reward_split};
use siworld_core::params::{ChainParams, COINBASE_MATURITY};
use siworld_core::{
    Block, BlockBody, Coinbase, Condition, ContainerProof, Digest, Header, Height, Note, Payout,
    Slot,
};
use siworld_crypto::{encrypt_note, miner_rho, note_commitment, Address, SecretSeed};
use siworld_state::{ChainState, RecentRoots};

use crate::pow::{check_timestamp, mine, next_target};
use crate::transition::{check_proof, transition, BlockError};
use crate::BLOCK_VERSION;

/// A mempool transaction: slot, leaf proof, the fee opening handed to the
/// block producer, and the anti-spam nonce relays require (docs/protocol.md, Mempool
/// and relay). The nonce is relay policy: it is not part of the slot, the
/// proof or the block.
#[derive(Clone, Debug)]
pub struct PendingTx {
    pub slot: Slot,
    pub proof: SlotProof,
    pub fee: FeeOpening,
    pub nonce: u64,
}

/// Who a block pays: the address its miner package is encrypted to, which
/// never appears on chain, and the hash of the miner's pre-confirmation key,
/// which the coinbase carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Miner {
    pub address: Address,
    pub committee_key: Digest,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BuildError {
    TooManyTxs,
    NoAnchor,
    Aggregate(AggregateError),
    Invalid(BlockError),
    /// No nonce meets the target.
    NonceExhausted,
}

struct PreparedBody {
    body: BlockBody,
    entries: Vec<PendingTx>,
    miner_note: Note,
    miner_share: u64,
}

impl PreparedBody {
    fn prove(
        &self,
        system: &dyn ProofSystem,
        acc: &RecentRoots,
        height: Height,
    ) -> Result<ContainerProof, BuildError> {
        let leaves: Vec<_> = self
            .entries
            .iter()
            .map(|t| Leaf {
                slot: &t.slot,
                proof: &t.proof,
                fee: &t.fee,
            })
            .collect();
        system
            .prove_container(acc, height, &leaves, &self.miner_note, self.miner_share)
            .map_err(BuildError::Aggregate)
    }
}

/// Assembles a block body and its container proof with `system` on `acc`, the
/// 𝒜 as of the parent or the grandparent block (the producer's choice). Every
/// slot's anchor must lie in `acc`'s window; empty packages anchor to its
/// latest root. The miner package (reward share plus fees) is encrypted to
/// `miner`. `payouts` are included as given; [`transition`] checks them. `seed`
/// derives the randomness of empty packages and the miner package; it must be
/// fresh per block (or a fresh [`SecretSeed::child`]) so that nobody else can
/// recompute either.
#[allow(clippy::too_many_arguments)]
pub fn assemble_body(
    system: &dyn ProofSystem,
    acc: &RecentRoots,
    params: &ChainParams,
    height: Height,
    miner: &Miner,
    txs: &[PendingTx],
    payouts: &[Payout],
    seed: &SecretSeed,
) -> Result<(BlockBody, ContainerProof), BuildError> {
    let prepared = prepare_body(system, acc, params, height, miner, txs, payouts, seed)?;
    let proof = prepared.prove(system, acc, height)?;
    Ok((prepared.body, proof))
}

#[allow(clippy::too_many_arguments)]
fn prepare_body(
    system: &dyn ProofSystem,
    acc: &RecentRoots,
    params: &ChainParams,
    height: Height,
    miner: &Miner,
    txs: &[PendingTx],
    payouts: &[Payout],
    seed: &SecretSeed,
) -> Result<PreparedBody, BuildError> {
    let n = params.container_size as usize;
    if txs.len() > n {
        return Err(BuildError::TooManyTxs);
    }
    let (anchor, _) = acc.latest().ok_or(BuildError::NoAnchor)?;
    let ctx = RelationContext {
        anchors: acc,
        tree_depth: params.commitment_tree_depth,
    };

    let mut entries: Vec<PendingTx> = txs.to_vec();
    let padding = seed.derive("block padding", height);
    for i in 0..(n - txs.len()) as u64 {
        let (slot, proof, fee) = dummy_slot(system, &ctx, anchor, &padding, i);
        // Never relayed, so no anti-spam work.
        entries.push(PendingTx {
            slot,
            proof,
            fee,
            nonce: 0,
        });
    }
    entries.sort_by_key(|t| t.slot.id());

    let (miner_amount, dev_direct_amount, dev_lock_amount) =
        reward_split(block_reward(epoch_of(height)));
    let total_fee = entries
        .iter()
        .try_fold(0u64, |acc, t| acc.checked_add(t.fee.fee))
        .and_then(|fees| fees.checked_add(miner_amount))
        .ok_or(BuildError::Aggregate(AggregateError::FeeOverflow))?;
    let miner_note = Note {
        owner: miner.address.owner(),
        value: total_fee,
        cond: Condition {
            unlock_height: height + COINBASE_MATURITY,
        },
        rho: miner_rho(height),
        rseed: seed.derive("miner note rseed", height),
    };

    let (miner_note_ct, miner_note_tag) = encrypt_note(
        &miner.address,
        &miner_note,
        &seed.derive("miner note encryption", height),
    );
    let body = BlockBody {
        coinbase: Coinbase {
            committee_key: miner.committee_key,
            miner_amount,
            dev_direct_amount,
            dev_lock_amount,
            miner_note_cm: note_commitment(&miner_note),
            miner_note_ct,
            miner_note_tag,
        },
        payouts: payouts.to_vec(),
        slots: entries.iter().map(|t| t.slot).collect(),
    };
    Ok(PreparedBody {
        body,
        entries,
        miner_note,
        miner_share: miner_amount,
    })
}

/// Builds a complete block with its proof on `acc` (see [`assemble_body`]). The
/// roots are computed by [`transition`] and the proof is checked by
/// [`check_proof`] against the same `system`, the path the validator uses. The
/// header carries ASERT's target and is sealed by [`mine`]; `timestamp` must
/// exceed [`crate::median_time_past`].
#[allow(clippy::too_many_arguments)]
pub fn build_block(
    state: &ChainState,
    acc: &RecentRoots,
    params: &ChainParams,
    system: &dyn ProofSystem,
    miner: &Miner,
    txs: &[PendingTx],
    payouts: &[Payout],
    seed: &SecretSeed,
    timestamp: u64,
) -> Result<Block, BuildError> {
    let mut block = build_unsealed(
        state, acc, params, system, miner, txs, payouts, seed, timestamp,
    )?;
    if !mine(&mut block.header, params.pow_iterations) {
        return Err(BuildError::NonceExhausted);
    }
    Ok(block)
}

/// [`build_block`] up to the PoW: the header's nonce is 0 and still has to be
/// searched (see [`crate::mine_some`]).
#[allow(clippy::too_many_arguments)]
pub fn build_unsealed(
    state: &ChainState,
    acc: &RecentRoots,
    params: &ChainParams,
    system: &dyn ProofSystem,
    miner: &Miner,
    txs: &[PendingTx],
    payouts: &[Payout],
    seed: &SecretSeed,
    timestamp: u64,
) -> Result<Block, BuildError> {
    build_unsealed_with_header(
        state,
        acc,
        params,
        system,
        miner,
        txs,
        payouts,
        seed,
        timestamp,
        |_| {},
    )
}

/// Exposes the fixed PoW header after the shared native transition succeeds,
/// before aggregation. The callback may start nonce search; it receives no
/// unproved `Block`. Only the returned, checked block may be published.
#[allow(clippy::too_many_arguments)]
pub fn build_unsealed_with_header(
    state: &ChainState,
    acc: &RecentRoots,
    params: &ChainParams,
    system: &dyn ProofSystem,
    miner: &Miner,
    txs: &[PendingTx],
    payouts: &[Payout],
    seed: &SecretSeed,
    timestamp: u64,
    on_header: impl FnOnce(Header),
) -> Result<Block, BuildError> {
    let height = state.height + 1;
    check_timestamp(state, timestamp).map_err(BuildError::Invalid)?;
    let prepared = prepare_body(system, acc, params, height, miner, txs, payouts, seed)?;
    let body = &prepared.body;
    let (_, roots) = transition(state, body, height, params).map_err(BuildError::Invalid)?;
    let header = Header {
        version: BLOCK_VERSION,
        height,
        parent: state.tip,
        timestamp,
        target: next_target(state, params),
        nonce: 0,
        state_root: roots.state_root,
        commitment_root: roots.commitment_root,
        nullifier_root: roots.nullifier_root,
        body_root: body.hash(),
        container_size: params.container_size,
    };
    // The header does not commit to the proof, so a real producer runs PoW and
    // proving in parallel and broadcasts once both are done.
    on_header(header);
    let proof = prepared.prove(system, acc, height)?;
    check_proof(&proof, state, body, height, system).map_err(BuildError::Invalid)?;
    Ok(Block {
        header,
        body: prepared.body,
        proof,
    })
}
