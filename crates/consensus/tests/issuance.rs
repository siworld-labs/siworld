//! Issuance test vectors (docs/protocol.md, "Issuance"). Every implementation must
//! reproduce each one exactly.

use siworld_core::issuance::{block_reward, decayed_reward, epoch_of, fee_base, fee_priority};
use siworld_core::params::{EPOCH_BLOCKS, TAIL_REWARD};

#[test]
fn decayed_reward_vectors() {
    let vectors = [
        (0, 678_904_903),
        (1, 674_674_488),
        (26, 577_069_155),
        (52, 490_508_770),
        (260, 133_658_931),
        (499, 30_005_031),
        (500, 29_818_062),
    ];
    for (e, r) in vectors {
        assert_eq!(decayed_reward(e), r, "r[{e}]");
    }
}

#[test]
fn tail_starts_at_epoch_500() {
    let first_below = (0..).find(|&e| decayed_reward(e) < TAIL_REWARD).unwrap();
    assert_eq!(first_below, 500);
    assert_eq!(block_reward(499), 30_005_031);
    assert_eq!(block_reward(500), TAIL_REWARD);
    assert_eq!(block_reward(10_000), TAIL_REWARD);
}

#[test]
fn main_issuance_total() {
    let total: u128 = (0..500)
        .map(|e| u128::from(decayed_reward(e)) * u128::from(EPOCH_BLOCKS))
        .sum();
    assert_eq!(total, 2_099_999_420_225_280);
}

#[test]
fn reward_never_increases() {
    let mut prev = block_reward(0);
    for e in 1..600 {
        let r = block_reward(e);
        assert!(r <= prev, "epoch {e}");
        prev = r;
    }
}

#[test]
fn epoch_boundaries() {
    assert_eq!(epoch_of(0), 0);
    assert_eq!(epoch_of(EPOCH_BLOCKS - 1), 0);
    assert_eq!(epoch_of(EPOCH_BLOCKS), 1);
}

#[test]
fn fee_tiers() {
    assert_eq!(fee_base(0), 678_904);
    assert_eq!(fee_priority(0), 2_715_616);
    assert_eq!(fee_base(500), 30_000);
    assert_eq!(fee_priority(500), 120_000);
}
