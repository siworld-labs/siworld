//! Bounded mempool ordered by fee tier, first come first served within a tier.
//! On admission it checks the encodings, the anti-spam work, the leaf proof,
//! the fee opening, the anchor, every nullifier, and rejects zero-fee
//! (all-dummy) slots. Each peer may have a bounded number of transactions in
//! the pool at a time.
//!
//! All of this is relay policy (docs/protocol.md, Mempool and relay), not consensus:
//! the values below can change without a fork.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use siworld_circuits::{MockProver, ProofSystem};
use siworld_consensus::{meets_target, pow_hash, PendingTx};
use siworld_core::issuance::{epoch_of, fee_priority};
use siworld_core::params::ChainParams;
use siworld_core::{Digest, Nullifier};
use siworld_crypto::is_canonical;
use siworld_state::ChainState;

/// Default pool capacity, in transactions (`MEMPOOL_CAPACITY`, docs/protocol.md).
pub const DEFAULT_CAPACITY: usize = 4_096;
/// Transactions one peer may have in the pool at a time (`MEMPOOL_PER_PEER`).
pub const DEFAULT_PER_PEER: usize = 256;
/// Sequential BLAKE3 hashes per transaction nonce (`TX_POW_ITERATIONS`).
pub const TX_POW_ITERATIONS: u64 = 10_000;
/// One nonce in 256 meets this target (`TX_POW_TARGET`): about 2.5 million
/// sequential hashes per transaction, an engineering default until the
/// half-second-per-phone calibration of docs/protocol.md.
pub const TX_POW_TARGET: [u8; 32] = {
    let mut t = [0xff; 32];
    t[0] = 0;
    t
};

/// The anti-spam work a relay requires of a transaction: a nonce such that
/// the sequential BLAKE3 chain over (slot id ‖ nonce) is below the target.
/// Checked before the leaf proof, since it costs microseconds against
/// milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxPow {
    pub iterations: u64,
    pub target: [u8; 32],
}

impl Default for TxPow {
    fn default() -> Self {
        Self {
            iterations: TX_POW_ITERATIONS,
            target: TX_POW_TARGET,
        }
    }
}

impl TxPow {
    /// The policy for a network: the default, except that a network whose
    /// blocks take fewer hashes per nonce (the devnet, tests) asks no more of
    /// a transaction than of a block nonce.
    pub fn for_params(params: &ChainParams) -> Self {
        Self {
            iterations: params.pow_iterations.min(TX_POW_ITERATIONS),
            ..Self::default()
        }
    }

    pub fn check(&self, slot_id: &Digest, nonce: u64) -> bool {
        meets_target(&pow_hash(slot_id, nonce, self.iterations), &self.target)
    }

    /// The first nonce that meets the target. The wallet does this once per
    /// transaction before relaying it.
    pub fn solve(&self, slot_id: &Digest) -> u64 {
        (0..u64::MAX)
            .find(|&nonce| self.check(slot_id, nonce))
            .expect("a nonce below the target exists")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MempoolError {
    /// A nullifier or commitment is not a canonical field encoding.
    NonCanonical,
    /// The anti-spam nonce does not meet the target.
    BadPow,
    BadProof,
    FeeOpeningMismatch,
    AnchorExpired,
    /// Zero fee: only an all-dummy slot (an empty package) pays nothing, and the
    /// block producer makes its own.
    ZeroFee,
    DuplicateInSlot,
    /// The nullifier is already on chain.
    AlreadySpent(Nullifier),
    /// The nullifier conflicts with another transaction in the pool.
    Conflict(Nullifier),
    /// The pool is full and holds nothing of a lower tier to evict.
    Full,
    /// The sending peer already has as many transactions in the pool as it may.
    PeerLimit,
}

/// Fee tier, used only for ordering. The leaf proof guarantees that a non-zero
/// fee is exactly the base or the priority fee of the anchor's epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    Base,
    Priority,
}

/// Higher tier first, then arrival order.
type Key = (Reverse<Tier>, u64);

/// A pooled transaction and the peer it came from (`None` for this node's own).
struct Entry {
    tx: PendingTx,
    source: Option<Digest>,
}

pub struct Mempool {
    txs: BTreeMap<Key, Entry>,
    /// Nullifiers of all pooled transactions, used to reject double spends within the pool.
    nullifiers: BTreeSet<Nullifier>,
    /// How many pooled transactions each peer contributed.
    sources: BTreeMap<Digest, usize>,
    capacity: usize,
    per_peer: usize,
    pow: TxPow,
    system: Arc<dyn ProofSystem>,
    arrivals: u64,
}

impl Default for Mempool {
    /// The mock proof system: tests and the devnet.
    fn default() -> Self {
        Self::new(
            DEFAULT_CAPACITY,
            DEFAULT_PER_PEER,
            TxPow::default(),
            Arc::new(MockProver),
        )
    }
}

/// The checks that depend on neither the chain state nor the proof system,
/// cheapest first: the encodings, the anti-spam work (bound to the slot's own
/// id, so one solved nonce serves one slot), the fee opening, the fee and the
/// two inputs being distinct. Run once, on admission.
pub fn well_formed(pow: &TxPow, tx: &PendingTx) -> Result<(), MempoolError> {
    let slot = &tx.slot;
    if !slot
        .nf
        .iter()
        .map(|nf| &nf.0)
        .chain(slot.cm.iter().map(|cm| &cm.0))
        .all(is_canonical)
    {
        return Err(MempoolError::NonCanonical);
    }
    if !pow.check(&slot.id(), tx.nonce) {
        return Err(MempoolError::BadPow);
    }
    if tx.fee.commit() != tx.proof.fee_commit {
        return Err(MempoolError::FeeOpeningMismatch);
    }
    if tx.fee.fee == 0 {
        return Err(MempoolError::ZeroFee);
    }
    if slot.nf[0] == slot.nf[1] {
        return Err(MempoolError::DuplicateInSlot);
    }
    Ok(())
}

/// Whether a well-formed transaction can still be included on `state`, and
/// its fee tier: its anchor is in the window and no input is spent. Run on
/// admission and again whenever the tip moves.
pub fn still_admissible(state: &ChainState, tx: &PendingTx) -> Result<Tier, MempoolError> {
    let anchor_height = state
        .anchors
        .height_of(&tx.proof.anchor)
        .ok_or(MempoolError::AnchorExpired)?;
    for nf in &tx.slot.nf {
        if state.nullifiers.contains(nf) {
            return Err(MempoolError::AlreadySpent(*nf));
        }
    }
    Ok(if tx.fee.fee >= fee_priority(epoch_of(anchor_height)) {
        Tier::Priority
    } else {
        Tier::Base
    })
}

/// [`well_formed`] then [`still_admissible`]: everything a transaction must
/// pass to enter the pool.
pub fn admissible(
    state: &ChainState,
    pow: &TxPow,
    system: &dyn ProofSystem,
    tx: &PendingTx,
) -> Result<Tier, MempoolError> {
    well_formed(pow, tx)?;
    let tier = still_admissible(state, tx)?;
    // Last, since it costs the most: the leaf proof, bound to this slot, this
    // fee opening and an anchor in the window.
    if !system.verify_slot(&state.anchors, &tx.slot, &tx.proof, &tx.fee) {
        return Err(MempoolError::BadProof);
    }
    Ok(tier)
}

impl Mempool {
    /// An empty pool holding at most `capacity` transactions, at most
    /// `per_peer` of them from any one peer, requiring the work `pow`, with
    /// slot proofs checked by `system`.
    pub fn new(capacity: usize, per_peer: usize, pow: TxPow, system: Arc<dyn ProofSystem>) -> Self {
        Self {
            txs: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            sources: BTreeMap::new(),
            capacity,
            per_peer,
            pow,
            system,
            arrivals: 0,
        }
    }

    /// An empty pool holding at most `capacity` transactions, with the default
    /// per-peer limit and work and the mock proof system.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(
            capacity,
            DEFAULT_PER_PEER,
            TxPow::default(),
            Arc::new(MockProver),
        )
    }

    /// The anti-spam work this pool requires; wallets solve it before relaying.
    pub fn tx_pow(&self) -> TxPow {
        self.pow
    }

    /// The proof system this pool checks slot proofs with.
    pub fn system(&self) -> &Arc<dyn ProofSystem> {
        &self.system
    }

    /// Admits `tx` from `source` (a peer's opaque identifier, or `None` for
    /// this node's own transactions, which no per-peer limit applies to). A
    /// peer at its limit is turned away before anything of its transaction
    /// is checked. When the pool is full, the newest transaction of the
    /// lowest tier is evicted if that tier is below `tx`'s, and returned so
    /// its sender can release the inputs; otherwise `tx` is rejected with
    /// [`MempoolError::Full`]. A rejected `tx` leaves the pool unchanged.
    pub fn submit(
        &mut self,
        state: &ChainState,
        tx: PendingTx,
        source: Option<Digest>,
    ) -> Result<Option<PendingTx>, MempoolError> {
        if let Some(peer) = &source {
            if self.sources.get(peer).copied().unwrap_or(0) >= self.per_peer {
                return Err(MempoolError::PeerLimit);
            }
        }
        let tier = admissible(state, &self.pow, self.system.as_ref(), &tx)?;
        for nf in &tx.slot.nf {
            if self.nullifiers.contains(nf) {
                return Err(MempoolError::Conflict(*nf));
            }
        }
        let evicted = if self.txs.len() < self.capacity {
            None
        } else {
            match self.txs.keys().next_back().copied() {
                Some(lowest) if lowest.0 .0 < tier => Some(self.remove(lowest)),
                _ => return Err(MempoolError::Full),
            }
        };
        self.nullifiers.extend(tx.slot.nf);
        if let Some(peer) = source {
            *self.sources.entry(peer).or_insert(0) += 1;
        }
        self.txs
            .insert((Reverse(tier), self.arrivals), Entry { tx, source });
        self.arrivals += 1;
        Ok(evicted)
    }

    fn remove(&mut self, key: Key) -> PendingTx {
        let entry = self.txs.remove(&key).expect("key is in the pool");
        for nf in &entry.tx.slot.nf {
            self.nullifiers.remove(nf);
        }
        if let Some(peer) = entry.source {
            let count = self.sources.get_mut(&peer).expect("counted on insert");
            *count -= 1;
            if *count == 0 {
                self.sources.remove(&peer);
            }
        }
        entry.tx
    }

    /// Takes up to `n` transactions: higher tier first, arrival order within a tier.
    pub fn take(&mut self, n: usize) -> Vec<PendingTx> {
        let keys: Vec<Key> = self.txs.keys().take(n).copied().collect();
        keys.into_iter().map(|k| self.remove(k)).collect()
    }

    /// Copies of the transactions [`Self::take`] would take, left in the pool.
    pub fn peek(&self, n: usize) -> Vec<PendingTx> {
        self.txs.values().take(n).map(|e| e.tx.clone()).collect()
    }

    /// Removes and returns the transactions `state` no longer admits: spent
    /// inputs, an anchor that left the window. Called after the tip moves;
    /// re-runs only the state-dependent checks, not the work or the proof.
    pub fn prune(&mut self, state: &ChainState) -> Vec<PendingTx> {
        let stale: Vec<Key> = self
            .txs
            .iter()
            .filter(|(_, e)| still_admissible(state, &e.tx).is_err())
            .map(|(k, _)| *k)
            .collect();
        stale.into_iter().map(|k| self.remove(k)).collect()
    }

    /// Removes the transaction whose slot has this id.
    pub fn remove_slot(&mut self, id: &Digest) -> Option<PendingTx> {
        let key = self
            .txs
            .iter()
            .find(|(_, e)| e.tx.slot.id() == *id)
            .map(|(k, _)| *k)?;
        Some(self.remove(key))
    }

    pub fn contains_slot(&self, id: &Digest) -> bool {
        self.txs.values().any(|e| e.tx.slot.id() == *id)
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}
