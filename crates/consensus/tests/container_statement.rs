//! The container proof binds the root statement of docs/protocol.md: ΣE over
//! the block's slots, the 𝒜 root, the height, the miner package commitment,
//! the miner's reward share and the slot count.

mod common;

use common::*;
use siworld_circuits::{ContainerPublic, MockProver, MockVerifier};
use siworld_consensus::{check_proof, BlockError};
use siworld_core::issuance::{block_reward, epoch_of, reward_split};
use siworld_core::Block;
use siworld_crypto::SetSum;
use siworld_state::ChainState;

fn block() -> (ChainState, Block) {
    let p = params();
    let (state, _) = genesis(&p, &[(key(1), 100_000_000, 0)]);
    let block = build(&state, &p, &[], 1).expect("empty block");
    (state, block)
}

#[test]
fn the_proof_binds_the_slots_as_a_multiset() {
    let (state, b) = block();
    let mut body = b.body.clone();
    assert_eq!(
        check_proof(&b.proof, &state, &body, 1, &MockVerifier),
        Ok(())
    );

    // ΣE ignores order; the sorted order is a separate native rule.
    body.slots.reverse();
    assert_eq!(
        check_proof(&b.proof, &state, &body, 1, &MockVerifier),
        Ok(())
    );

    // A repeated slot counts twice.
    let mut body = b.body.clone();
    body.slots[1] = body.slots[0];
    assert_eq!(
        check_proof(&b.proof, &state, &body, 1, &MockVerifier),
        Err(BlockError::BadProof)
    );
}

#[test]
fn the_proof_binds_every_public_slot_byte() {
    let (state, b) = block();
    let edits: [fn(&mut siworld_core::Slot); 3] = [
        |s| s.ct[0].0[0] ^= 1,
        |s| s.ct[1].0[siworld_core::CIPHERTEXT_LEN - 1] ^= 1,
        |s| s.tag[1] ^= 1,
    ];
    for edit in edits {
        let mut body = b.body.clone();
        edit(&mut body.slots[0]);
        assert_eq!(
            check_proof(&b.proof, &state, &body, 1, &MockVerifier),
            Err(BlockError::BadProof)
        );
    }
}

#[test]
fn the_proof_binds_height_miner_package_share_and_count() {
    let (state, b) = block();
    assert_eq!(
        check_proof(&b.proof, &state, &b.body, 2, &MockVerifier),
        Err(BlockError::BadProof)
    );

    // A proof made for one atom more of reward share is not this block's: the
    // verifier takes the share from the issuance schedule.
    let share = reward_split(block_reward(epoch_of(1))).0;
    let mut public = ContainerPublic {
        set_sum: SetSum::of(&b.body.slots),
        anchors_root: state.anchors.accumulator_root(),
        height: 1,
        miner_note_cm: b.body.coinbase.miner_note_cm,
        miner_share: share,
        count: b.body.slots.len() as u32,
    };
    let same = MockProver::prove_statement(&public).unwrap();
    assert_eq!(
        check_proof(&same, &state, &b.body, 1, &MockVerifier),
        Ok(())
    );
    public.miner_share = share + 1;
    let other = MockProver::prove_statement(&public).unwrap();
    assert_eq!(
        check_proof(&other, &state, &b.body, 1, &MockVerifier),
        Err(BlockError::BadProof)
    );

    let mut body = b.body.clone();
    body.coinbase.miner_note_cm = body.slots[0].cm[0];
    assert_eq!(
        check_proof(&b.proof, &state, &body, 1, &MockVerifier),
        Err(BlockError::BadProof)
    );

    let mut body = b.body.clone();
    body.slots.pop();
    assert_eq!(
        check_proof(&b.proof, &state, &body, 1, &MockVerifier),
        Err(BlockError::BadProof)
    );
}
