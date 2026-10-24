//! The single state transition function and the single proof check.

use siworld_circuits::{ContainerPublic, ContainerVerifier};
use siworld_core::issuance::{block_reward, epoch_of, reward_split};
use siworld_core::params::{ChainParams, MAX_PAYOUTS_PER_BLOCK, MIN_PACKAGE_DEPOSIT};
use siworld_core::{BlockBody, ContainerProof, DevAccount, Height, Nullifier, Roots};
use siworld_crypto::{
    is_canonical, note_commitment, payout_note, verify_payout, SetSum, VerifyingKey,
};
use siworld_state::{BlockDelta, ChainState, DeltaError, PayoutDelta};

/// Why a development-fund payout is invalid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayoutError {
    /// The chain has no development-fund keys, so no payout is valid.
    NoKeys,
    /// The amount is below MIN_PACKAGE_DEPOSIT.
    BelowMinimum,
    /// The counter is not the account's next payout number.
    Counter,
    /// The signature is not the account key's over the payout.
    Signature,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    BadVersion,
    /// The parent is not a block this node has accepted.
    BadParent,
    /// This node has already accepted the block.
    AlreadyKnown,
    /// The block's branch leaves the main chain below the final block, more
    /// than [`MAX_REORG_DEPTH`](siworld_core::params::MAX_REORG_DEPTH) blocks
    /// below the highest tip this node has had.
    ReorgTooDeep,
    BadHeight,
    BadContainerSize,
    /// The timestamp does not exceed the median of the recent timestamps.
    BadTimestamp,
    /// The header's target is not ASERT's value for the parent.
    BadTarget,
    /// The sequential work is not below the target.
    BadPow,
    BadBodyRoot,
    WrongSlotCount,
    /// A nullifier or commitment is not the canonical encoding of its field
    /// elements.
    NonCanonical,
    NotSorted,
    /// The container proof does not verify. Only this copy of the block is
    /// rejected: the header is not invalid, and the same header and body with a
    /// valid proof are still accepted.
    BadProof,
    BadCoinbase,
    /// More than MAX_PAYOUTS_PER_BLOCK payouts.
    TooManyPayouts,
    BadPayout {
        index: usize,
        error: PayoutError,
    },
    /// The block's payouts from this account exceed its spendable balance.
    Overdraft(DevAccount),
    NullifierReused(Nullifier),
    TreeFull,
    RootMismatch,
}

/// Checks a block body against `state` and returns its state changes and the
/// roots after them; the caller applies the changes with [`ChainState::apply`].
///
/// Takes no container proof: the header does not commit to it, and
/// [`check_proof`] checks it separately.
///
/// Does not modify `state` and copies none of it: the roots are computed from
/// the changes alone, so a failing block costs no allocation proportional to
/// the chain.
pub fn transition(
    state: &ChainState,
    body: &BlockBody,
    height: Height,
    params: &ChainParams,
) -> Result<(BlockDelta, Roots), BlockError> {
    if Some(height) != state.height.checked_add(1) {
        return Err(BlockError::BadHeight);
    }
    if body.slots.len() != params.container_size as usize {
        return Err(BlockError::WrongSlotCount);
    }

    // Before anything hashes them: the nullifier set is keyed by the encoding,
    // so a second spelling of a spent nullifier would otherwise pass.
    let coinbase = &body.coinbase;
    let field_digests = body
        .slots
        .iter()
        .flat_map(|s| {
            s.nf.iter()
                .map(|nf| &nf.0)
                .chain(s.cm.iter().map(|cm| &cm.0))
        })
        .chain([&coinbase.miner_note_cm.0])
        .chain(body.payouts.iter().flat_map(|p| [&p.owner, &p.rseed]));
    if !field_digests.into_iter().all(is_canonical) {
        return Err(BlockError::NonCanonical);
    }

    let slot_ids: Vec<_> = body.slots.iter().map(|s| s.id()).collect();
    if !slot_ids.windows(2).all(|w| w[0] < w[1]) {
        return Err(BlockError::NotSorted);
    }

    // Each of the three amounts, not just their sum: the development fund's
    // shares are ⌊reward/20⌋ each and the miner gets the remainder (docs/protocol.md).
    let (miner, dev_direct, dev_lock) = reward_split(block_reward(epoch_of(height)));
    if (
        body.coinbase.miner_amount,
        body.coinbase.dev_direct_amount,
        body.coinbase.dev_lock_amount,
    ) != (miner, dev_direct, dev_lock)
    {
        return Err(BlockError::BadCoinbase);
    }

    // Development-fund payouts (docs/protocol.md, Economics): each carries its
    // account's next counter and the account key's signature; the amounts are
    // checked against the balances by the state. Cheap checks come first;
    // the signature is the expensive one.
    if body.payouts.len() > MAX_PAYOUTS_PER_BLOCK {
        return Err(BlockError::TooManyPayouts);
    }
    let mut counters = [DevAccount::Direct, DevAccount::Lock].map(|a| state.dev_fund.payouts(a));
    let mut payouts = Vec::with_capacity(body.payouts.len());
    for (index, p) in body.payouts.iter().enumerate() {
        let bad = |error| BlockError::BadPayout { index, error };
        let keys = params
            .dev_fund_keys
            .as_ref()
            .ok_or(bad(PayoutError::NoKeys))?;
        if p.amount < MIN_PACKAGE_DEPOSIT {
            return Err(bad(PayoutError::BelowMinimum));
        }
        let counter = &mut counters[usize::from(p.account.to_byte())];
        if p.counter != *counter {
            return Err(bad(PayoutError::Counter));
        }
        *counter += 1;
        if !verify_payout(&VerifyingKey(*keys.key(p.account)), &params.chain_id, p) {
            return Err(bad(PayoutError::Signature));
        }
        payouts.push(PayoutDelta {
            account: p.account,
            amount: p.amount,
            cm: note_commitment(&payout_note(p, height, index as u32)),
        });
    }

    // Every nullifier of every slot. A duplicate of history, of another slot in
    // the same block, or of the other input in the same slot is rejected.
    let nullifiers = body.slots.iter().flat_map(|s| s.nf).collect();
    // Tree order: the slots' outputs in slot order; the state then appends the
    // miner package that matured from COINBASE_MATURITY blocks ago, then the
    // payouts' packages, and queues this block's miner package.
    let commitments = body.slots.iter().flat_map(|s| s.cm).collect();
    state
        .prepare(
            height,
            nullifiers,
            commitments,
            body.coinbase.miner_note_cm,
            &payouts,
        )
        .map_err(|e| match e {
            DeltaError::AlreadySpent(nf) => BlockError::NullifierReused(nf),
            DeltaError::TreeFull => BlockError::TreeFull,
            DeltaError::Overdraft(account) => BlockError::Overdraft(account),
        })
}

/// Checks the container proof of the block at `height` built on `state`.
///
/// The proof may use the 𝒜 root as of the parent or as of the grandparent
/// (ACC_ROOT_LAG = 1 or 2, docs/protocol.md); no other root is accepted. The miner's
/// reward share is recomputed from the issuance schedule, not read from the
/// block. The producer and the validator both call this after [`transition`],
/// which has checked that every nullifier and commitment is canonical before
/// ΣE hashes them.
pub fn check_proof<V: ContainerVerifier + ?Sized>(
    proof: &ContainerProof,
    state: &ChainState,
    body: &BlockBody,
    height: Height,
    verifier: &V,
) -> Result<(), BlockError> {
    let mut public = ContainerPublic {
        set_sum: SetSum::of(&body.slots),
        anchors_root: state.anchors.accumulator_root(),
        height,
        miner_note_cm: body.coinbase.miner_note_cm,
        miner_share: reward_split(block_reward(epoch_of(height))).0,
        count: u32::try_from(body.slots.len()).map_err(|_| BlockError::BadProof)?,
    };
    if verifier.verify(&public, proof) {
        return Ok(());
    }
    if let Some(root) = state.prev_anchors_root {
        public.anchors_root = root;
        if verifier.verify(&public, proof) {
            return Ok(());
        }
    }
    Err(BlockError::BadProof)
}
