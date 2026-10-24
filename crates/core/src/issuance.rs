//! Issuance and fee tiers; see "Issuance" in docs/protocol.md.

use crate::params::{
    DECAY_Q32, EPOCH_BLOCKS, FEE_BASE_DIVISOR, FEE_PRIORITY_MULT, INITIAL_REWARD, TAIL_REWARD,
};
use crate::types::Height;

pub type Epoch = u64;

pub fn epoch_of(height: Height) -> Epoch {
    height / EPOCH_BLOCKS
}

fn decay(r: u64) -> u64 {
    // r < 2^30 and DECAY_Q32 < 2^32, so the product fits in u128; after the shift it is at most r.
    ((u128::from(r) * u128::from(DECAY_Q32)) >> 32) as u64
}

/// `r[e]`: the decayed reward without the tail floor. For analysis and tests only;
/// consensus uses [`block_reward`].
pub fn decayed_reward(e: Epoch) -> u64 {
    let mut r = INITIAL_REWARD;
    for _ in 0..e {
        if r == 0 {
            break;
        }
        r = decay(r);
    }
    r
}

/// `reward(e) = max(r[e], TAIL_REWARD)`.
pub fn block_reward(e: Epoch) -> u64 {
    let mut r = INITIAL_REWARD;
    for _ in 0..e {
        // r is monotonically decreasing: once below the tail it stays at the tail.
        if r < TAIL_REWARD {
            break;
        }
        r = decay(r);
    }
    r.max(TAIL_REWARD)
}

pub fn fee_base(e: Epoch) -> u64 {
    block_reward(e) / FEE_BASE_DIVISOR
}

pub fn fee_priority(e: Epoch) -> u64 {
    fee_base(e) * FEE_PRIORITY_MULT
}

/// The 90/5/5 split of a block reward as `(miner, dev_direct, dev_lock)`: the
/// two development-fund shares are ⌊reward/20⌋ each and the miner takes the
/// remainder, so the three always sum to the reward.
pub fn reward_split(reward: u64) -> (u64, u64, u64) {
    let dev = reward / 20;
    (reward - 2 * dev, dev, dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_sums_to_reward_and_rounds_down_the_fund() {
        for r in [0, 1, 19, 20, 39, 678_904_903, 30_000_000, u64::MAX] {
            let (m, d, l) = reward_split(r);
            assert_eq!(m as u128 + d as u128 + l as u128, r as u128);
            assert_eq!(d, l);
            assert_eq!(d, r / 20);
            assert!(m >= d + l);
        }
        assert_eq!(
            reward_split(INITIAL_REWARD),
            (611_014_413, 33_945_245, 33_945_245)
        );
        assert_eq!(
            reward_split(TAIL_REWARD),
            (27_000_000, 1_500_000, 1_500_000)
        );
    }
}
