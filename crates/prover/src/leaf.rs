//! A leaf proof as it travels with a transaction: the STARK and its
//! statement `[E, fee limbs, 1, 𝒜 entry]`, postcard-encoded in
//! `SlotProof::body`, plus the native checks that bind the statement to the
//! slot and to its anchor.

use p3_uni_stark::Proof;
use serde::{Deserialize, Serialize};
use siworld_bench_plonky3::agg::fee_of;
use siworld_bench_plonky3::air::{ACC_COUNT, ACC_ENTRY, ACC_FEE, ACC_SET, NUM_ACC_PUBLIC};
use siworld_bench_plonky3::Cfg;
use siworld_core::{Digest, Height, Slot};
use siworld_crypto::{anchor_entry, domain_hash, is_canonical, set_element, to_field};
use siworld_poseidon2::{PrimeCharacteristicRing, F};

#[derive(Serialize)]
struct BodyRef<'a> {
    proof: &'a Proof<Cfg>,
    statement: &'a [F],
}

#[derive(Deserialize)]
struct Body {
    proof: Proof<Cfg>,
    statement: Vec<F>,
}

pub fn encode(proof: &Proof<Cfg>, statement: &[F]) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(&BodyRef { proof, statement }).map_err(|e| e.to_string())
}

/// The proof and its statement, if the body decodes to a statement of the
/// right length.
pub fn decode(body: &[u8]) -> Option<(Proof<Cfg>, Vec<F>)> {
    let b: Body = postcard::from_bytes(body).ok()?;
    (b.statement.len() == NUM_ACC_PUBLIC).then_some((b.proof, b.statement))
}

/// The proof's identity in the slot proof: a hash of its bytes.
pub fn binding(body: &[u8]) -> Digest {
    domain_hash("siworld v0 plonky3 leaf proof", &[body])
}

/// The fee the statement's limbs spell.
pub fn fee(statement: &[F]) -> u64 {
    fee_of(statement)
}

/// Whether the statement is a leaf statement of `slot`: its E is the slot's
/// (so it binds both nullifiers, both commitments and every ciphertext byte)
/// and its count is 1.
pub fn statement_matches(statement: &[F], slot: &Slot) -> bool {
    let canonical = slot
        .nf
        .iter()
        .map(|nf| &nf.0)
        .chain(slot.cm.iter().map(|cm| &cm.0))
        .all(is_canonical);
    canonical && statement[ACC_SET..ACC_FEE] == set_element(slot) && statement[ACC_COUNT] == F::ONE
}

/// Whether the statement's 𝒜 entry is block `height`'s entry for the root
/// `anchor`.
pub fn entry_matches(statement: &[F], anchor: &Digest, height: Height, base_fee: u64) -> bool {
    to_field(&anchor_entry(anchor, height, base_fee)).is_some_and(|e| statement[ACC_ENTRY..] == e)
}
