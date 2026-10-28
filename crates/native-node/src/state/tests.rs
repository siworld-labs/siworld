use super::*;
use crate::wire::{PUBLIC_BYTES, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord, Transaction};
use native::codec::encode_digest;
use p3_field::PrimeCharacteristicRing;

struct TestVerifier;
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
            Err("test transaction rejection".into())
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
            Err("test settlement rejection".into())
        }
    }
}
fn felt(value: u32) -> DigestBytes {
    let mut d = [F::ZERO; 12];
    d[0] = F::from_u32(value);
    encode_digest(&d)
}
fn candidate(state: &State, seed: u32) -> Block {
    let snapshot = state.tip_snapshot().selector;
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0u8; PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(snapshot, body, felt(seed + 10000 + i)).unwrap(),
            proof: vec![1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&state.config.network));
    let mut block = Block {
        network: state.config.network,
        height: state.height + 1,
        parent: state.tip,
        timestamp: state.timestamp() + state.config.target_interval,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward: RewardRecord {
            commitment: felt(seed + 20000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        },
        settlement_proof: vec![1],
    };
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
    block
}
#[test]
fn producer_and_validator_apply_the_same_transition() {
    let initial = State::new(Config::development([1; 32], 0).unwrap()).unwrap();
    let block = candidate(&initial, 1);
    let mut producer = initial.clone();
    let mut validator = initial;
    producer.apply(&block, &TestVerifier).unwrap();
    validator.apply(&block, &TestVerifier).unwrap();
    assert_eq!(producer.fingerprint(), validator.fingerprint());
    assert_eq!(producer.height, 1);
    assert_eq!(producer.spent.len(), 128);
    assert_eq!(producer.tree.count, 193);
    assert_eq!(
        producer.total_subsidy,
        siworld_core::issuance::block_reward(0) as u128
    );
}
#[test]
fn every_public_mutation_failure_is_atomic() {
    let initial = State::new(Config::development([2; 32], 0).unwrap()).unwrap();
    let base = candidate(&initial, 2);
    for kind in 0..8 {
        let mut block = base.clone();
        match kind {
            0 => block.parent[0] ^= 1,
            1 => block.network[0] ^= 1,
            2 => block.height += 1,
            3 => block.transactions.swap(0, 1),
            4 => block.transactions[63].proof = vec![0],
            5 => block.settlement_proof = vec![0],
            6 => block.transactions[0].record.snapshot.block_id[0] ^= 1,
            _ => {
                block.transactions[1].record.body[..48]
                    .copy_from_slice(&base.transactions[0].record.body[..48]);
                block
                    .transactions
                    .sort_by_key(|tx| tx.record.statement_id(&block.network));
            }
        }
        let mut state = initial.clone();
        let before = state.fingerprint();
        assert!(state.apply(&block, &TestVerifier).is_err(), "case {kind}");
        assert_eq!(state.fingerprint(), before);
    }
}
#[test]
fn rejects_second_input_reuse_across_blocks() {
    let mut state = State::new(Config::development([3; 32], 0).unwrap()).unwrap();
    let first = candidate(&state, 3);
    state.apply(&first, &TestVerifier).unwrap();
    let mut next = candidate(&state, 100000);
    next.transactions[63].record.body[48..96]
        .copy_from_slice(&first.transactions[0].record.body[48..96]);
    next.transactions
        .sort_by_key(|tx| tx.record.statement_id(&next.network));
    let before = state.fingerprint();
    assert!(state.apply(&next, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
}
#[test]
fn rejects_reused_output_and_reward_commitments() {
    let mut state = State::new(Config::development([4; 32], 0).unwrap()).unwrap();
    let first = candidate(&state, 4);
    state.apply(&first, &TestVerifier).unwrap();
    for reward in [false, true] {
        let mut next = candidate(&state, 200000);
        if reward {
            next.reward.commitment = first.reward.commitment;
        } else {
            next.transactions[63].record.body[96..144]
                .copy_from_slice(&first.transactions[0].record.body[96..144]);
            next.transactions
                .sort_by_key(|tx| tx.record.statement_id(&next.network));
        }
        let before = state.fingerprint();
        assert!(state.apply(&next, &TestVerifier).is_err());
        assert_eq!(state.fingerprint(), before);
    }
}
#[test]
fn snapshot_window_accepts_4096th_rejects_4097th_and_removed_identity() {
    let mut state = State::new(Config::development([5; 32], 0).unwrap()).unwrap();
    let root = state.tip_snapshot().recent_root;
    state.snapshots.clear();
    state.height = 4096;
    for height in 1..=4096 {
        state.snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height,
                block_id: blake3::hash(&height.to_le_bytes()).into(),
            },
            commitment_root: root,
            recent_root: root,
        });
    }
    let oldest = state.snapshots[0].selector;
    assert!(state.snapshot(oldest).is_ok());
    assert!(
        state
            .snapshot(Snapshot {
                height: 0,
                block_id: [0; 32]
            })
            .is_err()
    );
    let mut orphan = oldest;
    orphan.block_id[0] ^= 1;
    assert!(state.snapshot(orphan).is_err());
    state.snapshots.pop_front();
    assert!(state.snapshot(oldest).is_err());
}
#[test]
fn settlement_tail_is_multi_asset_context_bound_and_canonical() {
    let a = tail_slots([1; 32], 1, 64).unwrap();
    let b = tail_slots([1; 32], 1, 80).unwrap();
    assert_eq!(a.len(), 512);
    assert_ne!(a[0].commitment, b[0].commitment);
    let c = tail_slots([1; 32], 2, 64).unwrap();
    assert_ne!(a[0].commitment, c[0].commitment);
    let mut seen = BTreeSet::new();
    for row in a {
        assert_eq!(row.opening.fee, 0);
        assert!(seen.insert(encode_digest(&row.commitment)));
        assert_eq!(
            Hasher::new().fee_commit(0, &row.opening.blind),
            row.commitment
        );
    }
    assert!(tail_slots([1; 32], 1, 63).is_err());
    assert!(tail_slots([1; 32], 1, 577).is_err());
}
#[test]
fn incremental_tree_matches_native_merkle_paths() {
    let hasher = Hasher::new();
    let mut tree = CommitmentTree::new();
    let mut leaves = Vec::new();
    for i in 1..=9u32 {
        let leaf = decode_digest(&felt(i)).unwrap();
        leaves.push(leaf);
        tree.append(leaf).unwrap();
        for (index, value) in leaves.iter().enumerate() {
            assert_eq!(
                hasher.merkle_root(value, &tree.path(&leaves, index).unwrap()),
                tree.root()
            );
        }
    }
}

#[test]
fn asert_configuration_is_genesis_bound_and_fixture_mode_is_explicit() {
    let config = Config::asert_development([6; 32], 1_700_000_000, [0x7f; 32], 100).unwrap();
    assert_eq!(config.target_interval, 300);
    assert!(!config.fixture);
    let id = config.genesis_id();
    for change in 0..5 {
        let mut changed = config.clone();
        match change {
            0 => changed.genesis_timestamp += 1,
            1 => changed.genesis_target[31] ^= 1,
            2 => changed.pow_iterations += 1,
            3 => changed.target_interval += 1,
            _ => changed.fixture = true,
        }
        assert_ne!(changed.genesis_id(), id);
    }
    assert!(Config::asert_development([6; 32], 0, [0x7f; 32], 100).is_err());
    assert!(Config::asert_development([6; 32], 1, [0; 32], 100).is_err());
    assert!(Config::asert_development([6; 32], 1, [0x7f; 32], 0).is_err());
    assert!(Config::asert_development([6; 32], 1, [0x7f; 32], 1_000_001).is_err());
    assert!(Config::development([6; 32], 0).unwrap().fixture);
}
#[test]
fn timestamp_window_and_cumulative_work_survive_shared_transitions() {
    let mut state = State::new(Config::development([8; 32], 0).unwrap()).unwrap();
    let initial = state.config.genesis_timestamp;
    let mut expected_work = siworld_core::pow::Work::zero();
    for height in 1..=12u32 {
        let block = candidate(&state, 400000 + height * 100000);
        expected_work += siworld_core::pow::block_work(&block.target);
        state.apply(&block, &TestVerifier).unwrap();
    }
    assert_eq!(state.timestamps.len(), 11);
    assert_eq!(state.timestamp(), initial + 12 * 300);
    assert_eq!(state.median_time_past(), initial + 7 * 300);
    assert_eq!(state.cumulative_work, expected_work);
    let before = state.fingerprint();
    state.timestamps[0] += 1;
    assert_ne!(state.fingerprint(), before);
    state.timestamps[0] -= 1;
    state.cumulative_work += siworld_core::pow::Work::one();
    assert_ne!(state.fingerprint(), before);
}
#[test]
fn asert_header_failures_precede_proof_checks_and_are_atomic() {
    struct NoProofCalls;
    impl BlockVerifier for NoProofCalls {
        fn transaction(
            &self,
            _: &PublicTransaction,
            _: &ProofContext,
            _: &Digest,
            _: &Digest,
            _: &[u8],
        ) -> Result<(), String> {
            panic!("header failure reached transaction verifier")
        }
        fn settlement(
            &self,
            _: &[Digest],
            _: u64,
            _: u64,
            _: Hash,
            _: Hash,
            _: &Digest,
            _: &[u8],
        ) -> Result<(), String> {
            panic!("header failure reached settlement verifier")
        }
    }
    let state = State::new(Config::development([7; 32], 1).unwrap()).unwrap();
    let valid = candidate(&state, 300000);
    for kind in 0..3 {
        let mut invalid = valid.clone();
        match kind {
            0 => invalid.timestamp = state.median_time_past(),
            1 => invalid.target[31] ^= 1,
            _ => {
                let seed = invalid.pow_seed().unwrap();
                while siworld_core::pow::meets_target(
                    &siworld_core::pow::pow_hash(&seed, invalid.nonce, state.config.pow_iterations),
                    &invalid.target,
                ) {
                    invalid.nonce += 1;
                }
            }
        }
        let mut next = state.clone();
        let before = next.fingerprint();
        assert!(next.apply(&invalid, &NoProofCalls).is_err());
        assert_eq!(next.fingerprint(), before);
    }
}

#[test]
fn early_parent_changes_the_next_asert_target_and_old_target_is_rejected() {
    let mut state = State::new(Config::development([10; 32], 0).unwrap()).unwrap();
    let mut early = candidate(&state, 2000000);
    early.timestamp = state.timestamp() + 1;
    let seed = early.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, early.nonce, state.config.pow_iterations),
        &early.target,
    ) {
        early.nonce += 1;
    }
    state.apply(&early, &TestVerifier).unwrap();
    assert!(state.next_target() < state.config.genesis_target);
    let mut stale = candidate(&state, 2100000);
    stale.target = state.config.genesis_target;
    let before = state.fingerprint();
    assert!(
        state
            .apply(&stale, &TestVerifier)
            .unwrap_err()
            .contains("ASERT")
    );
    assert_eq!(state.fingerprint(), before);
}

#[test]
fn future_time_is_local_admission_only_not_a_replay_clock_rule() {
    let mut state = State::new(Config::development([11; 32], 0).unwrap()).unwrap();
    let mut block = candidate(&state, 2200000);
    block.timestamp = u64::MAX;
    assert!(siworld_core::pow::beyond_future_limit(
        block.timestamp,
        1_700_000_000
    ));
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
    state.apply(&block, &TestVerifier).unwrap();
    assert_eq!(state.timestamp(), u64::MAX);
}

#[test]
fn configuration_codec_rejects_noncanonical_modes_and_rule_changes() {
    let config = Config::asert_development([12; 32], 1_700_000_000, [0xff; 32], 64).unwrap();
    let encoded = config.encode_rules();
    assert_eq!(Config::decode_rules(&encoded).unwrap(), config);
    for index in [32, 33, 74] {
        let mut invalid = encoded;
        invalid[index] = 2;
        assert!(Config::decode_rules(&invalid).is_err());
    }
    assert!(Config::decode_rules(&encoded[..89]).is_err());
}
