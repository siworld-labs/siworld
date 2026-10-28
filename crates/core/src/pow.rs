// Adapted from midstate v5.0.0 (https://github.com/ciphernom/midstate),
// core/extension.rs and core/state.rs. Copyright (C) the midstate authors,
// licensed under GPL-3.0. Integer arithmetic matches the existing consensus
// vectors; network rules and header encodings remain outside this module.
use crate::params::{ASERT_HALF_LIFE, MAX_FUTURE_BLOCK_TIME, MEDIAN_TIME_PAST_WINDOW};

/// Integer cumulative-work representation shared by independent runtimes.
pub type Work = primitive_types::U512;

/// Sequential BLAKE3 work over a fixed header seed and little-endian nonce.
pub fn pow_hash(seed: &[u8; 32], nonce: u64, iterations: u64) -> [u8; 32] {
    let mut first = [0u8; 40];
    first[..32].copy_from_slice(seed);
    first[32..].copy_from_slice(&nonce.to_le_bytes());
    let mut x = *blake3::hash(&first).as_bytes();
    for _ in 0..iterations {
        x = *blake3::hash(&x).as_bytes();
    }
    x
}

/// Compare 256-bit big-endian work strictly below the declared target.
pub fn meets_target(work: &[u8; 32], target: &[u8; 32]) -> bool {
    work < target
}

/// ASERT anchored at the immutable genesis target/time and network interval.
pub fn asert_target(
    genesis_target: &[u8; 32],
    genesis_timestamp: u64,
    target_interval: u64,
    parent_height: u64,
    parent_timestamp: u64,
) -> [u8; 32] {
    if parent_height == 0 {
        return *genesis_target;
    }
    let ideal = i128::from(parent_height) * i128::from(target_interval);
    let actual = i128::from(parent_timestamp) - i128::from(genesis_timestamp);
    let exponent = (actual - ideal) * 65536 / i128::from(ASERT_HALF_LIFE);
    let shifts = exponent >> 16;
    let frac = exponent & 0xFFFF;
    let factor = 65536
        + ((frac * 45426) >> 16)
        + ((frac * frac * 15746) >> 32)
        + ((frac * frac * frac * 3643) >> 48);
    let factor = Work::from(u64::try_from(factor).expect("factor is in [2^16, 2^17)"));
    let mut target = (Work::from_big_endian(genesis_target) * factor) >> 16;
    let shift = usize::try_from(shifts.unsigned_abs().min(255)).expect("at most 255");
    if shifts > 0 {
        target <<= shift;
    } else {
        target >>= shift;
    }
    let ceiling = Work::from_big_endian(&[0xff; 32]);
    if target > ceiling {
        target = ceiling;
    } else if target.is_zero() {
        target = Work::one();
    }
    let bytes = target.to_big_endian();
    bytes[32..].try_into().expect("below the ceiling")
}

/// Branch work, using the existing integer ledger floor(2^256 / (target + 1)).
pub fn block_work(target: &[u8; 32]) -> Work {
    (Work::one() << 256usize) / (Work::from_big_endian(target) + Work::one())
}

/// Parent's timestamp before the full window, then median of its last eleven.
/// An empty history is invalid and must be rejected by its owning runtime.
pub fn median_time_past(timestamps: &[u64]) -> Option<u64> {
    if timestamps.len() < MEDIAN_TIME_PAST_WINDOW {
        return timestamps.last().copied();
    }
    let mut recent = timestamps[timestamps.len() - MEDIAN_TIME_PAST_WINDOW..].to_vec();
    recent.sort_unstable();
    Some(recent[MEDIAN_TIME_PAST_WINDOW / 2])
}

/// Local future-time admission policy; historical validity never reads a clock.
pub fn beyond_future_limit(timestamp: u64, now: u64) -> bool {
    timestamp.saturating_sub(now) > MAX_FUTURE_BLOCK_TIME
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_interval_and_half_life_vectors() {
        let mut initial = [0xff; 32];
        initial[0] = 0;
        initial[1] = 0x11;
        let genesis = 1_700_000_000;
        assert_eq!(asert_target(&initial, genesis, 300, 0, u64::MAX), initial);
        assert_eq!(
            asert_target(&initial, genesis, 300, 48, genesis + 14_400),
            initial
        );
        let base = Work::from_big_endian(&initial);
        assert_eq!(
            Work::from_big_endian(&asert_target(&initial, genesis, 300, 48, genesis)),
            base >> 1
        );
        assert_eq!(
            Work::from_big_endian(&asert_target(
                &initial,
                genesis,
                300,
                1,
                genesis + 300 + 14_400
            )),
            base << 1
        );
        assert_ne!(
            asert_target(&initial, genesis, 60, 48, genesis + 14_400),
            initial
        );
        assert_eq!(
            asert_target(&initial, genesis, 300, 1, u64::MAX),
            [0xff; 32]
        );
        let mut floor = [0; 32];
        floor[31] = 1;
        assert_eq!(asert_target(&initial, genesis, 300, u64::MAX, 0), floor);
    }
    #[test]
    fn sequential_work_and_strict_big_endian_comparison() {
        let seed = [9; 32];
        let mut input = [0; 40];
        input[..32].copy_from_slice(&seed);
        input[32..].copy_from_slice(&7u64.to_le_bytes());
        let first = *blake3::hash(&input).as_bytes();
        assert_eq!(pow_hash(&seed, 7, 0), first);
        assert_eq!(pow_hash(&seed, 7, 1), *blake3::hash(&first).as_bytes());
        assert_ne!(pow_hash(&seed, 7, 1), pow_hash(&seed, 8, 1));
        assert!(!meets_target(&first, &first));
        assert!(meets_target(&[0; 32], &[1; 32]));
        assert_eq!(block_work(&[0xff; 32]), Work::one());
    }
    #[test]
    fn median_and_local_future_admission_boundaries() {
        assert_eq!(median_time_past(&[]), None);
        assert_eq!(median_time_past(&[100, 200, 150]), Some(150));
        assert_eq!(
            median_time_past(&[1000, 30, 120, 20, 110, 40, 100, 50, 90, 60, 80, 70]),
            Some(70)
        );
        assert!(!beyond_future_limit(1900, 1000));
        assert!(beyond_future_limit(1901, 1000));
        assert!(!beyond_future_limit(u64::MAX, u64::MAX));
    }
}
