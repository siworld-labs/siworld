//! Package ciphertexts in produced blocks: recipients find their packages by
//! trial decryption, and nobody else can read them.

mod common;

use std::collections::BTreeSet;

use common::*;
use siworld_core::params::COINBASE_MATURITY;
use siworld_core::Block;
use siworld_crypto::{SpendKey, ViewKey};

const SIP: u64 = 100_000_000;

/// alice pays bob (both outputs to bob) in block 1.
fn paid_block() -> (siworld_state::ChainState, Block, u64) {
    let p = params();
    let (state, owned) = genesis(&p, &[(key(1), SIP, 0)]);
    let fee = fee_now(&state);
    let tx = pay(
        &state,
        &p,
        [real(&state, &owned[0]), dummy(1)],
        &key(2),
        [SIP / 2, SIP / 2 - fee],
        fee,
        7,
    )
    .unwrap();
    let block = build(&state, &p, &[tx], 1).unwrap();
    let mut node = chain(&p, state);
    node.apply_block(&block).unwrap();
    (node.state, block, fee)
}

/// Positions (within the block's new packages) that `vk` can decrypt.
fn found(vk: &ViewKey, block: &Block) -> Vec<(usize, u64)> {
    block
        .body
        .outputs()
        .enumerate()
        .filter_map(|(i, (cm, tag, ct))| vk.decrypt(cm, tag, ct).map(|n| (i, n.value)))
        .collect()
}

#[test]
fn recipient_finds_payment_at_its_tree_position() {
    let (state, block, fee) = paid_block();
    let bob = found(&key(2).view_key(), &block);
    let mut values: Vec<u64> = bob.iter().map(|&(_, v)| v).collect();
    values.sort_unstable();
    assert_eq!(values, [SIP / 2 - fee, SIP / 2]);

    // The block appended its slot outputs and then one matured miner package
    // (the zero digest this early in the chain).
    let outputs: Vec<_> = block.body.outputs().collect();
    let base = state.commitments.len() - outputs.len() as u64 - 1;
    for (i, _) in bob {
        assert_eq!(state.commitments.leaf(base + i as u64), Some(*outputs[i].0));
    }
}

#[test]
fn miner_decrypts_the_miner_package() {
    let (state, block, fee) = paid_block();
    let (cm, tag, ct) = block.body.miner_package();
    let note = miner_key()
        .view_key()
        .decrypt(cm, tag, ct)
        .expect("the miner package is encrypted to the miner");
    assert_eq!(note.value, fee + block.body.coinbase.miner_amount);
    assert_eq!(note.owner, miner_key().owner());
    assert_eq!(note.cond.unlock_height, state.height + COINBASE_MATURITY);
}

#[test]
fn others_decrypt_nothing() {
    let (_, block, _) = paid_block();
    for k in [key(1), key(3), SpendKey::from_digest(seed(1))] {
        assert!(found(&k.view_key(), &block).is_empty());
    }
    // The miner reads only the miner package, which is no slot output.
    assert!(found(&miner_key().view_key(), &block).is_empty());
    let (cm, tag, ct) = block.body.miner_package();
    for k in [key(1), key(2), key(3)] {
        assert_eq!(k.view_key().decrypt(cm, tag, ct), None);
    }
}

#[test]
fn every_ciphertext_and_kem_part_is_distinct() {
    // Empty packages carry real encryptions, not a recognisable filler.
    let (_, block, _) = paid_block();
    let cts: BTreeSet<Vec<u8>> = block
        .body
        .outputs()
        .map(|(_, _, ct)| ct.0.to_vec())
        .collect();
    let kems: BTreeSet<Vec<u8>> = block
        .body
        .outputs()
        .map(|(_, _, ct)| ct.0[..1088].to_vec())
        .collect();
    let n = block.body.outputs().count();
    assert_eq!(cts.len(), n);
    assert_eq!(kems.len(), n);
}
