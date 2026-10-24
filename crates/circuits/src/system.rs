//! The proof system behind a chain: how slot proofs and container proofs are
//! made and checked. Consensus, the mempool and the wallet speak to it through
//! this trait only, so a chain runs on the mock (devnet, tests) or on Plonky3
//! (`siworld-prover`) without any other code knowing which.

use std::sync::Arc;

use siworld_core::{ContainerProof, Digest, Height, Note, Slot};
use siworld_state::RecentRoots;

use crate::mock::{AggregateError, FeeOpening, Leaf, MockProver, MockVerifier, SlotProof};
use crate::relation::{RelationContext, RelationError, SlotWitness};
use crate::statement::{ContainerPublic, ContainerVerifier};

/// Why a slot proof could not be made.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProveError {
    /// The witness does not satisfy the relation.
    Relation(RelationError),
    /// The prover failed for a reason of its own (a shape or encoding error).
    Prover(String),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relation(e) => write!(f, "{e:?}"),
            Self::Prover(e) => f.write_str(e),
        }
    }
}

pub trait ProofSystem: Send + Sync {
    /// Wallet side: builds and proves a slot. Fails if the relation does not hold.
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError>;

    /// Relay side: whether `proof` is a valid leaf proof of `slot` whose fee
    /// opening is `fee`, anchored at a root `anchors` holds. Everything a
    /// leaf proof binds is checked here, so a transaction that passes cannot
    /// make the producer's aggregation fail later.
    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool;

    /// Producer side: aggregates N leaves into the container proof of the block
    /// at `height`, whose miner package `miner_note` holds the fee total plus
    /// `miner_share`. The order of `leaves` is the slot order within the block.
    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError>;

    /// Validator side: whether `proof` proves the root statement `public`.
    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool;
}

/// Every proof system is a container verifier.
impl<T: ProofSystem + ?Sized> ContainerVerifier for T {
    fn verify(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        self.verify_container(public, proof)
    }
}

impl<T: ProofSystem + ?Sized> ProofSystem for Arc<T> {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        (**self).prove_slot(ctx, w, blind)
    }

    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        (**self).verify_slot(anchors, slot, proof, fee)
    }

    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        (**self).prove_container(anchors, height, leaves, miner_note, miner_share)
    }

    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        (**self).verify_container(public, proof)
    }
}

impl ProofSystem for MockProver {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        MockProver::prove_slot(ctx, w, blind).map_err(ProveError::Relation)
    }

    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        MockProver::verify_slot(anchors, slot, proof, fee)
    }

    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        MockProver::prove_container(anchors, height, leaves, miner_note, miner_share)
    }

    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        MockVerifier.verify(public, proof)
    }
}
