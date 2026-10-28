//! The miner package (docs/protocol.md, Economics): one shielded package per block
//! holding the miner's reward share plus the block's fees, appended to the
//! commitment tree only `COINBASE_MATURITY` blocks later through the
//! pending-reward queue, after which the miner can spend it.

mod common;

use common::*;
use siworld_core::issuance::{block_reward, epoch_of, reward_split};
use siworld_core::params::COINBASE_MATURITY;
use siworld_core::{Commitment, Digest, Note};
use siworld_crypto::{miner_rho, note_commitment};

const SIP: u64 = 100_000_000;

/// Decrypts the miner package of a block body with the test miner's view key.
fn miner_note(body: &siworld_core::BlockBody) -> Note {
    let (cm, tag, ct) = body.miner_package();
    miner_key()
        .view_key()
        .decrypt(cm, tag, ct)
        .expect("the miner package is encrypted to the miner")
}

#[test]
fn miner_package_holds_the_reward_share_plus_the_fees() {
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
    let share = reward_split(block_reward(epoch_of(1))).0;
    let note = miner_note(&block.body);
    assert_eq!(note.value, share + fee);
    assert_eq!(note.owner, miner_key().owner());
    assert_eq!(note.cond.unlock_height, 1 + COINBASE_MATURITY);
    assert_eq!(note.rho, miner_rho(1));
    assert_eq!(note_commitment(&note), block.body.coinbase.miner_note_cm);
    // The coinbase carries the public share and the committee key, never the
    // miner's address.
    assert_eq!(block.body.coinbase.miner_amount, share);
    assert_eq!(block.body.coinbase.committee_key, miner().committee_key);
    assert_ne!(block.body.coinbase.committee_key, miner_key().owner());
}

#[test]
fn miner_package_enters_the_tree_one_hundred_blocks_later_and_is_then_spendable() {
    let p = params();
    let n = u64::from(p.container_size);
    let (state, _) = genesis(&p, &[(key(1), SIP, 0)]);
    let mut node = chain(&p, state);
    let first = build(&node.state, &p, &[], 1).unwrap();
    let cm_first = first.body.coinbase.miner_note_cm;
    let note_first = miner_note(&first.body);
    node.apply_block(&first).unwrap();

    // Block h appends its 2N outputs and then the matured package of block
    // h − 100, which is the zero digest while there is none.
    let zero = Commitment(Digest::ZERO);
    let per_block = 2 * n + 1;
    assert_eq!(node.state.commitments.len(), 1 + per_block);
    assert_eq!(node.state.commitments.leaf(per_block), Some(zero));
    assert!(
        (0..node.state.commitments.len()).all(|i| node.state.commitments.leaf(i) != Some(cm_first))
    );

    for h in 2..=COINBASE_MATURITY {
        let block = build(&node.state, &p, &[], h).unwrap();
        node.apply_block(&block).unwrap();
        assert_eq!(node.state.commitments.leaf(h * per_block), Some(zero));
    }
    assert_eq!(node.state.height, COINBASE_MATURITY);
    assert!(
        (0..node.state.commitments.len()).all(|i| node.state.commitments.leaf(i) != Some(cm_first))
    );

    // Block 101 appends block 1's package as its last commitment.
    let block = build(&node.state, &p, &[], COINBASE_MATURITY + 1).unwrap();
    node.apply_block(&block).unwrap();
    let index = (COINBASE_MATURITY + 1) * per_block;
    assert_eq!(node.state.commitments.leaf(index), Some(cm_first));
    assert_eq!(node.state.commitments.len(), index + 1);

    // The miner spends it in block 102, anchored at block 101's root.
    let fee = fee_now(&node.state);
    let owned = Owned {
        sk: miner_key(),
        note: note_first,
        index,
    };
    let tx = pay(
        &node.state,
        &p,
        [real(&node.state, &owned), dummy(2)],
        &key(2),
        [note_first.value - fee, 0],
        fee,
        9,
    )
    .expect("the matured package is spendable");
    let block = build(&node.state, &p, &[tx], COINBASE_MATURITY + 2).unwrap();
    node.apply_block(&block).unwrap();
    assert_eq!(node.state.height, COINBASE_MATURITY + 2);
}

#[test]
fn a_block_whose_miner_package_does_not_match_its_proof_is_rejected() {
    use siworld_circuits::MockVerifier;
    use siworld_consensus::{check_proof, BlockError};

    let p = params();
    let (state, _) = genesis(&p, &[(key(1), SIP, 0)]);
    let block = build(&state, &p, &[], 1).unwrap();
    // Another package in place of the one the proof derived.
    let mut body = block.body.clone();
    body.coinbase.miner_note_cm = body.slots[0].cm[0];
    assert_eq!(
        check_proof(&block.proof, &state, &body, 1, &MockVerifier),
        Err(BlockError::BadProof)
    );
}
