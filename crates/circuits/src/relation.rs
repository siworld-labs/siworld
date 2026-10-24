//! Proof relation for a single slot (2 inputs, 2 outputs).

use zeroize::{Zeroize, ZeroizeOnDrop};

use siworld_core::issuance::{epoch_of, fee_base, fee_priority};
use siworld_core::params::{MIN_PACKAGE_DEPOSIT, SLOT_INPUTS, SLOT_OUTPUTS};
use siworld_core::{Ciphertext, Digest, Note, Nullifier, Slot};
use siworld_crypto::{encrypt_note, note_commitment, nullifier, output_rho, Address, SpendKey};
use siworld_state::{MerklePath, RecentRoots};

#[derive(Clone)]
pub enum InputWitness {
    /// Spends a real package from the commitment tree.
    Real {
        note: Note,
        sk: SpendKey,
        path: MerklePath,
    },
    /// Zero-value dummy input: membership is not checked, but its nullifier is
    /// computed as usual and inserted into the set.
    Dummy { nk: Digest, rho: Digest },
}

impl InputWitness {
    pub fn is_dummy(&self) -> bool {
        matches!(self, InputWitness::Dummy { .. })
    }

    pub fn nullifier(&self) -> Nullifier {
        match self {
            InputWitness::Real { note, sk, .. } => nullifier(&sk.nullifier_key(), &note.rho),
            InputWitness::Dummy { nk, rho } => nullifier(nk, rho),
        }
    }

    fn value(&self) -> u64 {
        match self {
            InputWitness::Real { note, .. } => note.value,
            InputWitness::Dummy { .. } => 0,
        }
    }
}

/// The prover's private inputs.
#[derive(Clone)]
pub struct SlotWitness {
    /// The recent root that membership is proven against; not public.
    pub anchor: Digest,
    pub inputs: [InputWitness; SLOT_INPUTS],
    pub outputs: [Note; SLOT_OUTPUTS],
    /// The outputs encrypted to their recipients, with view tags (see
    /// [`encrypt_outputs`]). The relation does not check them (docs/security-model.md).
    pub ct: [Ciphertext; SLOT_OUTPUTS],
    pub tag: [u8; SLOT_OUTPUTS],
    pub fee: u64,
}

// Native witness ownership is erased here. Prover traces, third-party working
// buffers and copies made by field conversion require a separate lifecycle audit.
fn erase_note(note: &mut Note) {
    note.owner.0.zeroize();
    note.value.zeroize();
    note.cond.unlock_height.zeroize();
    note.rho.0.zeroize();
    note.rseed.0.zeroize();
}

impl Zeroize for InputWitness {
    fn zeroize(&mut self) {
        match self {
            Self::Real { note, sk, path } => {
                erase_note(note);
                sk.zeroize();
                for sibling in &mut path.siblings {
                    sibling.0.zeroize();
                }
                path.index.zeroize();
            }
            Self::Dummy { nk, rho } => {
                nk.0.zeroize();
                rho.0.zeroize();
            }
        }
    }
}
impl Drop for InputWitness {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for InputWitness {}
impl core::fmt::Debug for InputWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InputWitness(REDACTED)")
    }
}

impl Zeroize for SlotWitness {
    fn zeroize(&mut self) {
        self.anchor.0.zeroize();
        for input in &mut self.inputs {
            input.zeroize();
        }
        for note in &mut self.outputs {
            erase_note(note);
        }
        self.fee.zeroize();
    }
}
impl Drop for SlotWitness {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SlotWitness {}
impl core::fmt::Debug for SlotWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SlotWitness(REDACTED)")
    }
}

pub struct RelationContext<'a> {
    pub anchors: &'a RecentRoots,
    pub tree_depth: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelationError {
    UnknownAnchor,
    BadPathLength { input: usize },
    NotInTree { input: usize },
    WrongSpendKey { input: usize },
    NullifierMismatch { input: usize },
    DuplicateNullifier,
    ConditionNotMet { input: usize },
    CommitmentMismatch { output: usize },
    RhoMismatch { output: usize },
    BelowMinimumDeposit { output: usize },
    BadFee,
    Unbalanced,
}

/// Wallet side: the ρ values the two outputs must use.
pub fn output_rhos(inputs: &[InputWitness; SLOT_INPUTS]) -> [Digest; SLOT_OUTPUTS] {
    let (nf0, nf1) = (inputs[0].nullifier(), inputs[1].nullifier());
    [output_rho(&nf0, &nf1, 0), output_rho(&nf0, &nf1, 1)]
}

/// Wallet side: encrypts each output to its recipient. `randomness` must be
/// fresh and secret.
pub fn encrypt_outputs(
    outputs: &[Note; SLOT_OUTPUTS],
    to: [&Address; SLOT_OUTPUTS],
    mut randomness: [Digest; SLOT_OUTPUTS],
) -> ([Ciphertext; SLOT_OUTPUTS], [u8; SLOT_OUTPUTS]) {
    let (ct0, tag0) = encrypt_note(to[0], &outputs[0], &randomness[0]);
    let (ct1, tag1) = encrypt_note(to[1], &outputs[1], &randomness[1]);
    for draw in &mut randomness {
        draw.0.zeroize();
    }
    ([ct0, ct1], [tag0, tag1])
}

/// Wallet side: builds the slot's public data from the witness.
pub fn slot_for(w: &SlotWitness) -> Slot {
    Slot {
        nf: [w.inputs[0].nullifier(), w.inputs[1].nullifier()],
        cm: [
            note_commitment(&w.outputs[0]),
            note_commitment(&w.outputs[1]),
        ],
        ct: w.ct,
        tag: w.tag,
    }
}

/// Checks the slot relation. Every input and every output is checked; none is
/// skipped before the first error.
///
/// Conditions and fee tiers are evaluated at the anchor root's height, which
/// never exceeds the actual inclusion height and is therefore conservative.
/// Using the anchor height to select the fee epoch is provisional; see docs/security-model.md.
/// Ciphertext correctness is not proven by the relation; ciphertexts are bound
/// to the proof through the slot hash.
pub fn check_slot(
    ctx: &RelationContext,
    slot: &Slot,
    w: &SlotWitness,
) -> Result<(), RelationError> {
    let anchor_height = ctx
        .anchors
        .height_of(&w.anchor)
        .ok_or(RelationError::UnknownAnchor)?;

    let mut value_in: u128 = 0;
    for (i, input) in w.inputs.iter().enumerate() {
        if let InputWitness::Real { note, sk, path } = input {
            if path.siblings.len() != usize::from(ctx.tree_depth) {
                return Err(RelationError::BadPathLength { input: i });
            }
            if path.root(&note_commitment(note)) != w.anchor {
                return Err(RelationError::NotInTree { input: i });
            }
            if note.owner != sk.owner() {
                return Err(RelationError::WrongSpendKey { input: i });
            }
            if note.cond.unlock_height > anchor_height {
                return Err(RelationError::ConditionNotMet { input: i });
            }
        }
        if slot.nf[i] != input.nullifier() {
            return Err(RelationError::NullifierMismatch { input: i });
        }
        value_in += u128::from(input.value());
    }
    if slot.nf[0] == slot.nf[1] {
        return Err(RelationError::DuplicateNullifier);
    }

    let mut value_out: u128 = 0;
    for (j, out) in w.outputs.iter().enumerate() {
        if out.value != 0 && out.value < MIN_PACKAGE_DEPOSIT {
            return Err(RelationError::BelowMinimumDeposit { output: j });
        }
        if slot.cm[j] != note_commitment(out) {
            return Err(RelationError::CommitmentMismatch { output: j });
        }
        if out.rho != output_rho(&slot.nf[0], &slot.nf[1], j) {
            return Err(RelationError::RhoMismatch { output: j });
        }
        value_out += u128::from(out.value);
    }

    let all_dummy = w.inputs.iter().all(InputWitness::is_dummy);
    let e = epoch_of(anchor_height);
    let fee_ok = if all_dummy {
        w.fee == 0
    } else {
        w.fee == fee_base(e) || w.fee == fee_priority(e)
    };
    if !fee_ok {
        return Err(RelationError::BadFee);
    }

    if value_in != value_out + u128::from(w.fee) {
        return Err(RelationError::Unbalanced);
    }
    Ok(())
}
