//! Mock prover: checks the relation and uses a binding hash over the public
//! inputs as the "proof".
//!
//! It hides nothing and is not sound (anyone can compute the binding hash). The
//! interface follows the real proof system: leaf proofs → binary aggregation →
//! one container proof, whose public inputs are the root statement
//! ([`ContainerPublic`]); the binding hash covers exactly its public values.

use siworld_core::params::COINBASE_MATURITY;
use siworld_core::{ContainerProof, Digest, Height, Note, Slot};
use siworld_crypto::{domain_hash, miner_rho, note_commitment, SetSum};
use siworld_poseidon2::PrimeField32;
use siworld_state::RecentRoots;

use crate::relation::{check_slot, slot_for, RelationContext, RelationError, SlotWitness};
use crate::statement::{ContainerPublic, ContainerVerifier};

/// Hiding commitment to a fee and its opening. The wallet hands the opening to
/// the block producer; it never appears on chain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FeeOpening {
    pub fee: u64,
    pub blind: Digest,
}

impl core::fmt::Debug for FeeOpening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FeeOpening(REDACTED)")
    }
}

impl FeeOpening {
    pub fn commit(&self) -> Digest {
        domain_hash(
            "siworld v0 mock fee commit",
            &[&self.fee.to_le_bytes(), self.blind.as_bytes()],
        )
    }
}

/// A leaf proof as it travels with a transaction. The four digests are what
/// every proof system exposes: the slot's id, the fee commitment the opening
/// must match, the anchor root (so the aggregator can find its 𝒜 path; the
/// leaf statement shows the aggregator only the 𝒜 entry anyway), and the
/// mock's binding hash. `body` is the real proof system's proof and leaf
/// statement, empty for the mock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotProof {
    pub slot_id: Digest,
    pub fee_commit: Digest,
    pub anchor: Digest,
    pub binding: Digest,
    pub body: Vec<u8>,
}

fn slot_binding(slot_id: &Digest, fee_commit: &Digest, anchor: &Digest) -> Digest {
    domain_hash(
        "siworld v0 mock slot proof",
        &[slot_id.as_bytes(), fee_commit.as_bytes(), anchor.as_bytes()],
    )
}

/// The mock "proof" of a statement: a hash of its public values, as the
/// canonical u32 little-endian bytes of each field element.
fn statement_binding(public: &ContainerPublic) -> Option<Digest> {
    let values = public.public_values()?;
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|x| x.as_canonical_u32().to_le_bytes())
        .collect();
    Some(domain_hash("siworld v0 mock container proof", &[&bytes]))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AggregateError {
    BadSlotProof {
        index: usize,
    },
    AnchorExpired {
        index: usize,
    },
    FeeOpeningMismatch {
        index: usize,
    },
    FeeOverflow,
    /// The miner package does not hold the fee total plus the miner share.
    MinerNoteValue,
    MinerNoteUnlock,
    MinerNoteRho,
    /// The statement has no circuit representation ([`ContainerPublic::public_values`]).
    StatementOutOfRange,
    /// The prover failed for a reason of its own (a shape or encoding error).
    Prover(String),
}

/// A leaf to aggregate: slot, leaf proof, fee opening.
pub struct Leaf<'a> {
    pub slot: &'a Slot,
    pub proof: &'a SlotProof,
    pub fee: &'a FeeOpening,
}

pub struct MockProver;

impl MockProver {
    /// Wallet side: builds and proves a slot. Rejects if the relation does not hold.
    pub fn prove_slot(
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), RelationError> {
        let slot = slot_for(w);
        check_slot(ctx, &slot, w)?;
        let fee = FeeOpening { fee: w.fee, blind };
        let slot_id = slot.id();
        let fee_commit = fee.commit();
        let proof = SlotProof {
            slot_id,
            fee_commit,
            anchor: w.anchor,
            binding: slot_binding(&slot_id, &fee_commit, &w.anchor),
            body: Vec::new(),
        };
        Ok((slot, proof, fee))
    }

    /// Whether `proof` is a mock proof of `slot` with the fee opening `fee`,
    /// anchored in `anchors`' window.
    pub fn verify_slot(
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        proof.slot_id == slot.id()
            && proof.binding == slot_binding(&proof.slot_id, &proof.fee_commit, &proof.anchor)
            && proof.body.is_empty()
            && fee.commit() == proof.fee_commit
            && anchors.height_of(&proof.anchor).is_some()
    }

    /// Block producer: aggregates N leaves into a container proof and proves that
    /// the miner package holds exactly the fee total plus the public
    /// `miner_share`. The order of `leaves` is the slot order within the block.
    pub fn prove_container(
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        let mut total: u64 = 0;
        for (index, leaf) in leaves.iter().enumerate() {
            if anchors.height_of(&leaf.proof.anchor).is_none() {
                return Err(AggregateError::AnchorExpired { index });
            }
            if leaf.fee.commit() != leaf.proof.fee_commit {
                return Err(AggregateError::FeeOpeningMismatch { index });
            }
            if !Self::verify_slot(anchors, leaf.slot, leaf.proof, leaf.fee) {
                return Err(AggregateError::BadSlotProof { index });
            }
            total = total
                .checked_add(leaf.fee.fee)
                .ok_or(AggregateError::FeeOverflow)?;
        }
        let value = total
            .checked_add(miner_share)
            .ok_or(AggregateError::FeeOverflow)?;
        if miner_note.value != value {
            return Err(AggregateError::MinerNoteValue);
        }
        if Some(miner_note.cond.unlock_height) != height.checked_add(COINBASE_MATURITY) {
            return Err(AggregateError::MinerNoteUnlock);
        }
        if miner_note.rho != miner_rho(height) {
            return Err(AggregateError::MinerNoteRho);
        }
        let public = ContainerPublic {
            set_sum: SetSum::of(leaves.iter().map(|l| l.slot)),
            anchors_root: anchors.accumulator_root(),
            height,
            miner_note_cm: note_commitment(miner_note),
            miner_share,
            count: u32::try_from(leaves.len()).map_err(|_| AggregateError::StatementOutOfRange)?,
        };
        Self::prove_statement(&public).ok_or(AggregateError::StatementOutOfRange)
    }

    /// The last step of [`Self::prove_container`]: the mock proof of a
    /// statement, or `None` if it has no circuit representation.
    pub fn prove_statement(public: &ContainerPublic) -> Option<ContainerProof> {
        statement_binding(public).map(|d| ContainerProof(d.0.to_vec()))
    }
}

pub struct MockVerifier;

impl ContainerVerifier for MockVerifier {
    fn verify(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        statement_binding(public).is_some_and(|d| proof.0.as_slice() == d.as_bytes())
    }
}
