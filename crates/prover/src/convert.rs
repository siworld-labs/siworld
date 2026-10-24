//! From siworld's witnesses to the circuit's: canonical digests become field
//! digests, Merkle paths become (sibling, is-right-child) pairs, and the
//! anchor's 𝒜 data (height, base fee, membership path) is looked up.

use siworld_bench_common::{
    AccWitness, Digest as FieldDigest, InputWitness as LeafInput, OutputWitness,
    SlotWitness as LeafWitness, ANCHOR_DEPTH, TREE_DEPTH,
};
use siworld_circuits::{InputWitness, ProveError, RelationContext, SlotWitness};
use siworld_core::params::FEE_PRIORITY_MULT;
use siworld_core::{Digest, Height, Note, Slot};
use siworld_crypto::to_field;
use siworld_poseidon2::{PrimeCharacteristicRing, DIGEST, F};
use siworld_state::{base_fee, MerklePath, RecentRoots};

/// The field elements of a canonical digest.
pub fn field_digest(d: &Digest) -> Option<FieldDigest> {
    to_field(d)
}

fn digest(d: &Digest, what: &str) -> Result<FieldDigest, ProveError> {
    field_digest(d).ok_or_else(|| ProveError::Prover(format!("{what} is not canonical")))
}

/// A commitment-tree path as the circuit reads it: from the leaf up, each
/// sibling with whether the node on the path is the right child.
fn merkle_path(path: &MerklePath) -> Result<Vec<(FieldDigest, bool)>, ProveError> {
    path.siblings
        .iter()
        .enumerate()
        .map(|(k, s)| Ok((digest(s, "path sibling")?, (path.index >> k) & 1 == 1)))
        .collect()
}

fn input(w: &InputWitness) -> Result<LeafInput, ProveError> {
    Ok(match w {
        InputWitness::Real { note, sk, path } => LeafInput {
            nk: digest(&sk.nullifier_key(), "nullifier key")?,
            rho: digest(&note.rho, "input ρ")?,
            rseed: digest(&note.rseed, "input rseed")?,
            value: note.value,
            unlock_height: note.cond.unlock_height,
            dummy: false,
            path: merkle_path(path)?,
        },
        // A dummy input has no package: zero value, no condition and a path
        // the circuit does not read.
        InputWitness::Dummy { nk, rho } => LeafInput {
            nk: digest(nk, "dummy nullifier key")?,
            rho: digest(rho, "dummy ρ")?,
            rseed: [F::ZERO; DIGEST],
            value: 0,
            unlock_height: 0,
            dummy: true,
            path: vec![([F::ZERO; DIGEST], false); TREE_DEPTH],
        },
    })
}

fn output(n: &Note) -> Result<OutputWitness, ProveError> {
    Ok(OutputWitness {
        owner: digest(&n.owner, "output owner")?,
        value: n.value,
        unlock_height: n.cond.unlock_height,
        rseed: digest(&n.rseed, "output rseed")?,
    })
}

/// The 𝒜 membership path of block `height`'s entry, in circuit order.
pub fn anchor_path(
    anchors: &RecentRoots,
    height: Height,
) -> Result<Vec<(FieldDigest, bool)>, ProveError> {
    if anchors.depth() as usize != ANCHOR_DEPTH {
        return Err(ProveError::Prover(format!(
            "𝒜 depth {}, the circuits need {ANCHOR_DEPTH}",
            anchors.depth()
        )));
    }
    let siblings = anchors
        .path(height)
        .ok_or_else(|| ProveError::Prover("anchor left the window".into()))?;
    let pos = height % (1 << ANCHOR_DEPTH);
    siblings
        .iter()
        .enumerate()
        .map(|(k, s)| Ok((digest(s, "𝒜 sibling")?, (pos >> k) & 1 == 1)))
        .collect()
}

/// The accumulator-mode witness of `w`, whose slot is `slot`, after
/// `check_slot` accepted it against `ctx`.
pub fn acc_witness(
    ctx: &RelationContext,
    slot: &Slot,
    w: &SlotWitness,
    blind: &Digest,
) -> Result<AccWitness, ProveError> {
    if usize::from(ctx.tree_depth) != TREE_DEPTH {
        return Err(ProveError::Prover(format!(
            "commitment-tree depth {}, the circuits need {TREE_DEPTH}",
            ctx.tree_depth
        )));
    }
    let anchor_height = ctx
        .anchors
        .height_of(&w.anchor)
        .ok_or_else(|| ProveError::Prover("anchor left the window".into()))?;
    let base_fee = base_fee(anchor_height);
    let all_dummy = w.inputs.iter().all(InputWitness::is_dummy);
    // The circuit multiplies the base fee by 0, 1 or 4; `check_slot` has
    // already held the fee to one of those tiers.
    let fee_is_priority = !all_dummy && base_fee != 0 && w.fee == base_fee * FEE_PRIORITY_MULT;
    let blind = digest(blind, "fee blind")?;
    Ok(AccWitness {
        slot: LeafWitness {
            anchor: digest(&w.anchor, "anchor")?,
            inputs: [input(&w.inputs[0])?, input(&w.inputs[1])?],
            outputs: [output(&w.outputs[0])?, output(&w.outputs[1])?],
            fee: w.fee,
            fee_blind: [blind[0], blind[1], blind[2], blind[3]],
            fee_is_priority,
        },
        d_ct: slot.ct_digest().0,
        anchor_height,
        base_fee,
        anchor_path: anchor_path(ctx.anchors, anchor_height)?,
    })
}
