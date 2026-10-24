//! The producer's seed: empty packages and the miner package must not be
//! recomputable by anyone else, or filler slots and the real-transaction count
//! leak (privacy invariants in CONTRIBUTING.md).

mod common;

use std::collections::BTreeSet;

use common::*;
use siworld_circuits::MockProver;
use siworld_consensus::{build_block, PendingTx};
use siworld_core::{Block, Slot};
use siworld_crypto::SecretSeed;
use siworld_state::ChainState;

const SI: u64 = 100_000_000;

fn one_payment() -> (ChainState, PendingTx) {
    let p = params();
    let (state, owned) = genesis(&p, &[(key(1), SI, 0)]);
    let fee = fee_now(&state);
    let tx = pay(
        &state,
        &p,
        [real(&state, &owned[0]), dummy(1)],
        &key(2),
        [SI / 2, SI / 2 - fee],
        fee,
        7,
    )
    .unwrap();
    (state, tx)
}

fn build_with(state: &ChainState, txs: &[PendingTx], seed: &SecretSeed) -> Block {
    let p = params();
    build_block(
        state,
        &state.anchors,
        &p,
        &MockProver,
        &miner(),
        txs,
        &[],
        seed,
        next_timestamp(state, &p),
    )
    .unwrap()
}

fn slot_ids(block: &Block) -> BTreeSet<siworld_core::Digest> {
    block.body.slots.iter().map(Slot::id).collect()
}

/// Two producers holding independent OS seeds build the same block contents:
/// apart from the real transaction, no slot and no miner package coincide, so
/// neither can be recomputed from public data.
#[test]
fn os_seeds_give_unrelated_padding_and_miner_package() {
    let (state, tx) = one_payment();
    let a = build_with(
        &state,
        std::slice::from_ref(&tx),
        &SecretSeed::from_os_rng().unwrap(),
    );
    let b = build_with(
        &state,
        std::slice::from_ref(&tx),
        &SecretSeed::from_os_rng().unwrap(),
    );

    let shared: BTreeSet<_> = slot_ids(&a).intersection(&slot_ids(&b)).copied().collect();
    assert_eq!(shared, BTreeSet::from([tx.slot.id()]));
    assert_ne!(a.body.coinbase.miner_note_cm, b.body.coinbase.miner_note_cm);
    assert_ne!(a.body.coinbase.miner_note_ct, b.body.coinbase.miner_note_ct);

    for block in [&a, &b] {
        chain(&params(), state.clone()).apply_block(block).unwrap();
    }
}

/// The deterministic constructor exists for tests and the devnet: the same
/// seed reproduces the same block.
#[test]
fn insecure_deterministic_seed_reproduces_the_block() {
    let (state, tx) = one_payment();
    let det = || SecretSeed::insecure_deterministic(seed(42));
    let a = build_with(&state, std::slice::from_ref(&tx), &det());
    let b = build_with(&state, &[tx], &det());
    assert_eq!(a.body.hash(), b.body.hash());
}
