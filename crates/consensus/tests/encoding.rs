//! Every field element on chain uses its canonical encoding (docs/protocol.md):
//! a block carrying the second spelling x + p of any nullifier, commitment or
//! owner element is invalid, and the node is left unchanged.

mod common;

use common::*;
use siworld_consensus::BlockError;
use siworld_core::{Block, Digest};

/// The other encoding of the same element at byte offset `at`: x + p, which
/// still fits in a u32 because 2p < 2^32.
fn alias(d: &mut Digest, at: usize) {
    let x = u32::from_le_bytes(d.0[at..at + 4].try_into().unwrap());
    assert!(x < 0x7f00_0001, "start from a canonical element");
    d.0[at..at + 4].copy_from_slice(&(x + 0x7f00_0001).to_le_bytes());
}

fn rejects(edit: impl Fn(&mut Block)) {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let block = build(&state, &p, &[], 1).unwrap();
    let mut bad = block.clone();
    edit(&mut bad);
    bad.header.body_root = bad.body.hash();
    reseal(&mut bad.header, &p);

    let mut node = chain(&p, state);
    let before = (node.state.roots(), node.state.tip, node.tip_work());
    assert_eq!(node.apply_block(&bad), Err(BlockError::NonCanonical));
    assert_eq!(
        (node.state.roots(), node.state.tip, node.tip_work()),
        before
    );
    node.apply_block(&block).unwrap();
}

#[test]
fn non_canonical_nullifier_is_rejected() {
    rejects(|b| alias(&mut b.body.slots[0].nf[1].0, 28));
}

#[test]
fn non_canonical_output_commitment_is_rejected() {
    rejects(|b| alias(&mut b.body.slots[1].cm[0].0, 0));
}

#[test]
fn non_canonical_miner_package_commitment_is_rejected() {
    rejects(|b| alias(&mut b.body.coinbase.miner_note_cm.0, 12));
}
