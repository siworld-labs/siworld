//! Empty packages: 2 dummy inputs + 2 dummy outputs with zero fee. The block
//! producer uses them to fill the container.

use siworld_core::{Condition, Digest, Note, Slot};
use siworld_crypto::{expand, Address, SpendKey};

use crate::mock::{FeeOpening, SlotProof};
use crate::relation::{encrypt_outputs, output_rhos, InputWitness, RelationContext, SlotWitness};
use crate::system::ProofSystem;

/// A throwaway recipient: nobody keeps its key, so the output is unspendable,
/// but its ciphertext is a real encryption like any other.
fn throwaway(seed: &Digest, index: u64, j: u64) -> Address {
    SpendKey::from_digest(expand(seed, "dummy key", index * 2 + j)).address()
}

fn zero_note(seed: &Digest, index: u64, j: u64, to: &Address, rho: Digest) -> Note {
    Note {
        owner: to.owner(),
        value: 0,
        cond: Condition::default(),
        rho,
        rseed: expand(seed, "dummy rseed", index * 2 + j),
    }
}

/// Derives all randomness of an empty package from `seed` and proves it with
/// `system`. `seed` must be unpredictable to outsiders (real randomness in
/// production); otherwise they could tell which slots are padding.
pub fn dummy_slot(
    system: &dyn ProofSystem,
    ctx: &RelationContext,
    anchor: Digest,
    seed: &Digest,
    index: u64,
) -> (Slot, SlotProof, FeeOpening) {
    let input = |k: u64| InputWitness::Dummy {
        nk: expand(seed, "dummy nk", index * 2 + k),
        rho: expand(seed, "dummy in rho", index * 2 + k),
    };
    let inputs = [input(0), input(1)];
    let rho = output_rhos(&inputs);
    let to = [throwaway(seed, index, 0), throwaway(seed, index, 1)];
    let outputs = [
        zero_note(seed, index, 0, &to[0], rho[0]),
        zero_note(seed, index, 1, &to[1], rho[1]),
    ];
    let (ct, tag) = encrypt_outputs(
        &outputs,
        [&to[0], &to[1]],
        [
            expand(seed, "dummy encryption", index * 2),
            expand(seed, "dummy encryption", index * 2 + 1),
        ],
    );
    let w = SlotWitness {
        anchor,
        inputs,
        outputs,
        ct,
        tag,
        fee: 0,
    };
    system
        .prove_slot(ctx, &w, expand(seed, "dummy blind", index))
        .expect("dummy slot always satisfies the relation")
}
