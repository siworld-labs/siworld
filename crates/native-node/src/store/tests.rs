use super::*;
use crate::state::BlockVerifier;
use crate::wire::{
    DigestBytes, Hash, PUBLIC_BYTES, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, encode_digest};
use native::multi_asset::{Digest, F};
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        loop {
            let path = base.join(format!(
                "siworld-native-store-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create synthetic test directory: {error}"),
            }
        }
    }
    fn db(&self) -> PathBuf {
        self.0.join("chain.redb")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct TestVerifier {
    transactions: Cell<usize>,
    settlements: Cell<usize>,
    reject: bool,
}
impl BlockVerifier for TestVerifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.transactions.set(self.transactions.get() + 1);
        if !self.reject && proof == [1] {
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
        self.settlements.set(self.settlements.get() + 1);
        if !self.reject && proof == [1] {
            Ok(())
        } else {
            Err("test settlement rejection".into())
        }
    }
}
fn config() -> Config {
    Config::development([91; 32], 0).unwrap()
}
fn felt(value: u32) -> DigestBytes {
    let mut digest = [F::ZERO; 12];
    digest[0] = F::from_u32(value);
    encode_digest(&digest)
}
fn candidate(state: &State, seed: u32) -> Block {
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0; PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(state.tip_snapshot().selector, body, felt(seed + 10000 + i))
                .unwrap(),
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
fn populated(path: &Path) -> (Block, Hash) {
    let mut store = Store::open(path, config(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    (block, store.state().fingerprint())
}
fn tamper(path: &Path, operation: impl FnOnce(&redb::WriteTransaction)) {
    let db = Database::open(path).unwrap();
    let txn = db.begin_write().unwrap();
    operation(&txn);
    txn.commit().unwrap();
}

#[test]
fn initializes_once_and_reopens_genesis() {
    let dir = TestDir::new();
    let store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let initial = store.state().fingerprint();
    assert_eq!(store.state().height, 0);
    drop(store);
    let reopened = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), initial);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn existing_only_open_never_reinitializes_missing_history() {
    let dir = TestDir::new();
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    assert!(!dir.db().exists());
    populated(&dir.db());
    let moved = dir.0.join("preserved.redb");
    std::fs::rename(dir.db(), &moved).unwrap();
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    assert!(!dir.db().exists());
    assert_eq!(
        Store::open_existing(moved, config(), &TestVerifier::default())
            .unwrap()
            .state()
            .height,
        1
    );
}

#[test]
fn replays_every_transaction_and_settlement_in_every_block() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    for seed in [1, 100000] {
        let block = candidate(store.state(), seed);
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let expected = store.state().fingerprint();
    drop(store);
    let verifier = TestVerifier::default();
    let reopened = Store::open(dir.db(), config(), &verifier).unwrap();
    assert_eq!(reopened.state().height, 2);
    assert_eq!(reopened.state().fingerprint(), expected);
    assert_eq!(verifier.transactions.get(), 128);
    assert_eq!(verifier.settlements.get(), 2);
    let block = reopened.block(1).unwrap();
    assert_eq!(block.height, 1);
    assert_eq!(block.transactions.len(), 64);
    assert!(reopened.block(0).is_err());
    assert!(reopened.block(3).is_err());
}

#[test]
fn replay_does_not_trust_the_saved_fingerprint_in_place_of_proofs() {
    let dir = TestDir::new();
    populated(&dir.db());
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    assert!(Store::open(dir.db(), config(), &verifier).is_err());
    assert_eq!(verifier.transactions.get(), 1);
}

#[test]
fn rejected_append_changes_neither_memory_nor_durable_state() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let mut block = candidate(store.state(), 1);
    block.transactions[63].proof = vec![0];
    assert!(store.append(&block, &TestVerifier::default()).is_err());
    assert_eq!(store.state().fingerprint(), before);
    drop(store);
    let reopened = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), before);
}

#[test]
fn a_conflicting_durable_head_is_not_exposed_as_accepted_memory() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let block = candidate(store.state(), 1);
    {
        let txn = store.database.begin_write().unwrap();
        {
            let mut meta = txn.open_table(META).unwrap();
            let _ = meta.insert("head", [0u8; 72].as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    assert!(store.append(&block, &TestVerifier::default()).is_err());
    assert_eq!(store.state().fingerprint(), before);
}

#[test]
fn wrong_configuration_is_rejected_and_the_original_stays_readable() {
    let dir = TestDir::new();
    let (_, expected) = populated(&dir.db());
    for wrong in [
        Config::development([92; 32], 0).unwrap(),
        Config::development([91; 32], 1).unwrap(),
    ] {
        assert!(Store::open(dir.db(), wrong, &TestVerifier::default()).is_err());
    }
    assert_eq!(
        Store::open(dir.db(), config(), &TestVerifier::default())
            .unwrap()
            .state()
            .fingerprint(),
        expected
    );
}

#[test]
fn missing_or_unrecognized_metadata_and_tables_are_never_reinitialized() {
    for kind in 0..6 {
        let dir = TestDir::new();
        drop(Store::open(dir.db(), config(), &TestVerifier::default()).unwrap());
        tamper(&dir.db(), |txn| match kind {
            0 | 1 => {
                let mut table = txn.open_table(META).unwrap();
                let _ = table
                    .remove(if kind == 0 { "config" } else { "head" })
                    .unwrap();
            }
            2 => {
                let _ = txn.delete_table(BLOCKS).unwrap();
            }
            3 => {
                let _ = txn.delete_table(META).unwrap();
            }
            4 => {
                let mut table = txn.open_table(META).unwrap();
                let _ = table.insert("unknown", &[0u8][..]).unwrap();
            }
            _ => {
                drop(
                    txn.open_table(TableDefinition::<u64, u64>::new("unexpected"))
                        .unwrap(),
                );
            }
        });
        assert!(
            Store::open(dir.db(), config(), &TestVerifier::default()).is_err(),
            "case {kind}"
        );
    }
}

#[test]
fn rejects_missing_and_gapped_blocks_and_changed_state_fingerprints() {
    for kind in 0..4 {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let value = blocks.get(1).unwrap().unwrap().value().to_vec();
            match kind {
                0 => {
                    let _ = blocks.remove(1).unwrap();
                }
                1 => {
                    let _ = blocks.remove(1).unwrap();
                    let _ = blocks.insert(2, value.as_slice()).unwrap();
                }
                2 => {
                    let mut bad = value;
                    *bad.last_mut().unwrap() ^= 1;
                    let _ = blocks.insert(1, bad.as_slice()).unwrap();
                }
                _ => {
                    let mut bad = value;
                    bad.truncate(31);
                    let _ = blocks.insert(1, bad.as_slice()).unwrap();
                }
            }
        });
        assert!(
            Store::open(dir.db(), config(), &TestVerifier::default()).is_err(),
            "case {kind}"
        );
    }
}

#[test]
fn rejects_noncanonical_or_trailing_stored_block_data() {
    for trailing in [false, true] {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let mut bad = blocks.get(1).unwrap().unwrap().value().to_vec();
            if trailing {
                bad.insert(bad.len() - 32, 0);
            } else {
                bad[0] ^= 1;
            }
            let _ = blocks.insert(1, bad.as_slice()).unwrap();
        });
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    }
}

#[test]
fn rejects_changed_committed_height_tip_or_head_fingerprint() {
    for offset in [0, 8, 40] {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut meta = txn.open_table(META).unwrap();
            let mut bad = meta.get("head").unwrap().unwrap().value().to_vec();
            bad[offset] ^= 1;
            let _ = meta.insert("head", bad.as_slice()).unwrap();
        });
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    }
}

#[test]
fn existing_empty_random_and_truncated_files_fail_closed() {
    for data in [vec![], vec![17; 23], vec![0; 4096]] {
        let dir = TestDir::new();
        std::fs::write(dir.db(), &data).unwrap();
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
        assert_eq!(std::fs::read(dir.db()).unwrap(), data);
    }
    let dir = TestDir::new();
    populated(&dir.db());
    let file = OpenOptions::new().write(true).open(dir.db()).unwrap();
    file.set_len(32).unwrap();
    drop(file);
    assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    assert_eq!(std::fs::metadata(dir.db()).unwrap().len(), 32);
}

#[test]
fn invalid_public_config_is_not_persisted() {
    let dir = TestDir::new();
    assert!(
        Store::open(
            dir.db(),
            Config {
                network: [0; 32],
                ..config()
            },
            &TestVerifier::default()
        )
        .is_err()
    );
    assert!(!dir.db().exists());
}

#[cfg(unix)]
#[test]
fn symlinks_and_nonregular_paths_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;
    let dir = TestDir::new();
    let target = dir.0.join("target");
    std::fs::write(&target, b"original evidence").unwrap();
    symlink(&target, dir.db()).unwrap();
    assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"original evidence");
    assert!(Store::open(&dir.0, config(), &TestVerifier::default()).is_err());
}

#[test]
fn asert_rules_and_replayed_work_are_durable_and_wrong_rules_fail_closed() {
    let dir = TestDir::new();
    let base = Config::asert_development([93; 32], 1_700_000_000, [0xff; 32], 1).unwrap();
    let mut store = Store::open(dir.db(), base.clone(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    let work = store.state().cumulative_work;
    let timestamps = store.state().timestamps.clone();
    drop(store);
    for field in 0..4 {
        let mut changed = base.clone();
        match field {
            0 => changed.genesis_timestamp += 1,
            1 => changed.genesis_target[31] ^= 1,
            2 => changed.pow_iterations += 1,
            _ => changed.target_interval += 1,
        }
        assert!(Store::open_existing(dir.db(), changed, &TestVerifier::default()).is_err());
    }
    let reopened = Store::open_existing(dir.db(), base, &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().cumulative_work, work);
    assert_eq!(reopened.state().timestamps, timestamps);
    assert_eq!(reopened.block(1).unwrap().target, block.target);
    assert_eq!(reopened.block(1).unwrap().timestamp, block.timestamp);
}
#[test]
fn old_store_configuration_is_rejected_without_reinitialization() {
    let dir = TestDir::new();
    populated(&dir.db());
    let mut legacy = b"SWNS\x01\0".to_vec();
    legacy.extend_from_slice(native::codec::SUITE_ID);
    legacy.extend_from_slice(&config().network);
    legacy.push(0);
    legacy.extend_from_slice(&[0; 32]);
    tamper(&dir.db(), |txn| {
        txn.open_table(META)
            .unwrap()
            .insert("config", legacy.as_slice())
            .unwrap();
    });
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    let db = Database::open(dir.db()).unwrap();
    let txn = db.begin_read().unwrap();
    let meta = txn.open_table(META).unwrap();
    assert_eq!(meta.get("config").unwrap().unwrap().value(), legacy);
    assert_eq!(txn.open_table(BLOCKS).unwrap().len().unwrap(), 1);
}
