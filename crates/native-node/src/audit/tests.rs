use super::*;
use crate::state::{BlockVerifier, State};
use crate::wire::{DigestBytes, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord, Transaction};
use native::codec::{ProofContext, PublicTransaction, encode_digest};
use native::multi_asset::{Digest, F};
use p3_field::PrimeCharacteristicRing;

pub(crate) struct TestVerifier;
impl BlockVerifier for TestVerifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("fixture transaction rejection".into())
        }
    }
    fn settlement(
        &self,
        _: &[Digest],
        _: u64,
        _: u64,
        _: Hash,
        _: Hash,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("fixture settlement rejection".into())
        }
    }
}
pub(crate) fn felt(value: u32) -> DigestBytes {
    let mut digest = [F::ZERO; 12];
    digest[0] = F::from_u32(value);
    encode_digest(&digest)
}
pub(crate) fn candidate(state: &State, seed: u32) -> Block {
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0; crate::wire::PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(state.tip_snapshot().selector, body, felt(seed + 10_000 + i))
                .unwrap(),
            proof: vec![1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&state.config.network));
    Block {
        network: state.config.network,
        height: state.height + 1,
        parent: state.tip,
        timestamp: state.timestamp() + state.config.target_interval,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward: RewardRecord {
            commitment: felt(seed + 20_000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        },
        settlement_proof: vec![1],
    }
}

#[test]
fn every_height_matches_integer_curve_and_accepted_state() {
    let config = Config::development([31; 32], 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut blocks = Vec::new();
    for seed in [100, 100_000, 200_000] {
        let block = candidate(&state, seed);
        state.apply(&block, &TestVerifier).unwrap();
        blocks.push(block);
    }
    let (replayed, report) = replay_chain(config, &blocks, &TestVerifier).unwrap();
    assert_eq!(replayed.fingerprint(), state.fingerprint());
    assert_eq!(report.fingerprint, state.fingerprint());
    assert_eq!(report.total_subsidy, state.total_subsidy);
    assert_eq!(report.fund_direct, state.fund_direct);
    assert_eq!(report.fund_locked, state.fund_locked);
    assert_eq!(report.heights.len(), 3);
    for row in &report.heights {
        assert_eq!(
            row.subsidy,
            siworld_core::issuance::block_reward(siworld_core::issuance::epoch_of(row.height))
        );
        assert_eq!(
            u128::from(row.subsidy),
            u128::from(row.miner_subsidy)
                + u128::from(row.fund_direct)
                + u128::from(row.fund_locked)
        );
    }
    report
        .check_head(state.height, state.tip, state.fingerprint())
        .unwrap();
    assert!(
        report
            .check_head(state.height, [0; 32], state.fingerprint())
            .is_err()
    );
    assert!(!report.asset_issuance_supported);
    assert!(!report.fund_spending_supported);
}

#[test]
fn invalid_proofs_order_or_parent_never_produce_an_audit_report() {
    let config = Config::development([32; 32], 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let valid = candidate(&state, 500);
    for change in 0..4 {
        let mut invalid = valid.clone();
        match change {
            0 => invalid.transactions[0].proof = vec![0],
            1 => invalid.settlement_proof = vec![0],
            2 => invalid.transactions.swap(0, 1),
            _ => invalid.parent[0] ^= 1,
        }
        assert!(replay_chain(config.clone(), &[invalid], &TestVerifier).is_err());
    }
}

#[test]
fn fresh_canonical_replay_discards_orphan_subsidy_and_fund_credits() {
    let config = Config::development([33; 32], 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let first = candidate(&state, 800);
    state.apply(&first, &TestVerifier).unwrap();
    let orphan = candidate(&state, 100_000);
    let replacement = candidate(&state, 200_000);
    let (_, old) = replay_chain(config.clone(), &[first.clone(), orphan], &TestVerifier).unwrap();
    let (_, new) =
        replay_chain(config.clone(), &[first.clone(), replacement], &TestVerifier).unwrap();
    assert_ne!(old.tip, new.tip);
    assert_eq!(old.total_subsidy, new.total_subsidy);
    let (_, shorter) = replay_chain(config, &[first], &TestVerifier).unwrap();
    assert_eq!(shorter.heights.len(), 1);
    assert_eq!(old.total_subsidy, shorter.total_subsidy * 2);
    assert_eq!(old.fund_direct, shorter.fund_direct * 2);
}
