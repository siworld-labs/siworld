//! Consistent encrypted wallet snapshots and explicit restored-order reconciliation.
use siworld_circuits::MockProver;
use siworld_consensus::mine;
use siworld_core::{Block, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::backup::{
    create_full_backup, inspect_full_backup, merge_full_backup, restore_full_backup,
};
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::keystore::{Keystore, WalletFileLock};
use siworld_node::node::Node;
use siworld_node::payments::{PaymentId, PaymentOrder, PaymentState};
use siworld_node::wire::encode_tx;
use siworld_storage::BlockStore;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
const PASSWORD: &str = "full wallet backup test password";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "siworld-backup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn key(i: u8) -> SpendKey {
    SpendKey::from_digest(Digest([i; 32]))
}
fn id(i: u8) -> PaymentId {
    PaymentId::parse(&format!("{i:02x}").repeat(32)).unwrap()
}
fn genesis() -> Genesis {
    Genesis::from_file(&GenesisFile {
        network: "full-backup-test".into(),
        timestamp: 1000,
        block_time: 1,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: siworld_node::hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap()
}
fn source(dir: &Path) {
    Keystore::seal(&key(1), PASSWORD)
        .unwrap()
        .save_new(&dir.join("key"))
        .unwrap();
}
fn open(dir: &Path) -> Node {
    let g = genesis();
    let store = BlockStore::open(&dir.join("blocks.redb"), &g.id).unwrap();
    let mut n = Node::open(
        g,
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        Some(store),
        Arc::new(MockProver),
    )
    .unwrap();
    n.enable_payment_journal(&dir.join("payments.redb"))
        .unwrap();
    n
}
fn order(i: u8) -> PaymentOrder {
    PaymentOrder::new(id(i), &key(2).address(), 10_000_000, false)
}
fn mine_one(n: &mut Node) -> Block {
    let mut b = n.template(1001 + n.height()).unwrap();
    assert!(mine(&mut b.header, 1));
    n.accept(&b).unwrap();
    b
}
fn backup(dir: &Path, out: &Path) {
    create_full_backup(dir, out, PASSWORD, &genesis(), Arc::new(MockProver)).unwrap();
}
#[test]
fn missing_cancelled_order_is_atomically_retired_and_survives_snapshot_and_drill() {
    let src = Temp::new();
    source(&src.0);
    drop(open(&src.0));
    let files = Temp::new();
    let old = files.0.join("old");
    backup(&src.0, &old);
    let l = Temp::new();
    let w = Temp::new();
    let mut ledger = siworld_node::orders::OrderLedger::create(
        &l.0,
        &w.0,
        PASSWORD,
        genesis().id,
        key(1).owner(),
    )
    .unwrap();
    let cp = ledger.record(&order(1)).unwrap();
    let restored = files.0.join("restored");
    restore_full_backup(&old, &restored, PASSWORD).unwrap();
    let mut n = open(&restored);
    let v = ledger.verify(&cp).unwrap();
    let preview = n.reconcile_payments(&v, 0, n.tip(), false).unwrap();
    assert!(!preview.committable);
    assert_eq!(
        preview.missing_orders[0].state,
        siworld_node::orders::OrderState::Unsubmitted
    );
    assert!(n.reconcile_payments(&v, 0, n.tip(), true).is_err());
    assert!(n.payment_recovery_required());
    let cp = ledger.cancel_unsubmitted(id(1), &cp).unwrap();
    let v = ledger.verify(&cp).unwrap();
    let preview = n.reconcile_payments(&v, 0, n.tip(), false).unwrap();
    assert!(preview.committable);
    assert_eq!(preview.cancelled_tombstones, 1);
    assert!(n.payment(id(1)).is_err());
    n.reconcile_payments(&v, 0, n.tip(), true).unwrap();
    let outcome = n
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap();
    assert_eq!(outcome.receipt.state, PaymentState::Cancelled);
    assert!(outcome.relay.is_none());
    assert!(n
        .pay_with_id(id(1), &key(2).address(), 20_000_000, false)
        .is_err());
    drop(n);
    let mut n = open(&restored);
    assert!(!n.payment_recovery_required());
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Cancelled);
    drop(n);
    let snapshot = files.0.join("cancelled");
    backup(&restored, &snapshot);
    let second = files.0.join("second");
    restore_full_backup(&snapshot, &second, PASSWORD).unwrap();
    let mut n = open(&second);
    n.reconcile_payments(&v, 0, n.tip(), true).unwrap();
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Cancelled);
    drop(n);
    let work = Temp::new();
    let report = siworld_node::backup::drill_full_backup(
        &siworld_node::backup::DrillRequest {
            backup: &old,
            chain_dir: &src.0,
            work_dir: &work.0,
            password: PASSWORD,
            expected_height: 0,
            expected_tip: genesis().id,
        },
        Arc::new(MockProver),
        &v,
    )
    .unwrap();
    assert_eq!(report.cancelled_tombstones, 1);
    assert_eq!(report.retry_count, 1);
    // An actual journal record is contradictory evidence, never erased by a cancellation.
    let mut n = open(&src.0);
    n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap();
    drop(n);
    let actual = files.0.join("actual");
    backup(&src.0, &actual);
    let conflict = files.0.join("conflict");
    restore_full_backup(&actual, &conflict, PASSWORD).unwrap();
    let mut n = open(&conflict);
    assert!(n.reconcile_payments(&v, 0, n.tip(), true).is_err());
    assert!(n.payment_recovery_required());
    let cancelled_merge = files.0.join("cancelled-merge");
    restore_full_backup(&snapshot, &cancelled_merge, PASSWORD).unwrap();
    let mut n = open(&cancelled_merge);
    assert_eq!(
        merge_full_backup(&mut n, &actual, PASSWORD).unwrap_err(),
        "payment_id_conflict"
    );
    assert!(n.payment_recovery_required());
    n.reconcile_payments(&v, 0, n.tip(), true).unwrap();
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Cancelled);
}
#[test]
fn dispatched_missing_order_remains_ambiguous_until_exact_newer_snapshot_is_imported() {
    let src = Temp::new();
    source(&src.0);
    drop(open(&src.0));
    let files = Temp::new();
    let old = files.0.join("old");
    backup(&src.0, &old);
    let l = Temp::new();
    let w = Temp::new();
    let mut ledger = siworld_node::orders::OrderLedger::create(
        &l.0,
        &w.0,
        PASSWORD,
        genesis().id,
        key(1).owner(),
    )
    .unwrap();
    let recorded = ledger.record(&order(1)).unwrap();
    ledger.begin_dispatch(&order(1)).unwrap();
    assert!(ledger.cancel_unsubmitted(id(1), &recorded).is_err());
    let cp = ledger.record(&order(2)).unwrap();
    let cp = ledger.cancel_unsubmitted(id(2), &cp).unwrap();
    let v = ledger.verify(&cp).unwrap();
    let dest = files.0.join("restore");
    restore_full_backup(&old, &dest, PASSWORD).unwrap();
    let mut n = open(&dest);
    let preview = n.reconcile_payments(&v, 0, n.tip(), false).unwrap();
    assert!(!preview.committable);
    assert_eq!(preview.cancelled_tombstones, 1);
    assert_eq!(
        preview.missing_orders[0].state,
        siworld_node::orders::OrderState::Dispatched
    );
    assert!(n.reconcile_payments(&v, 0, n.tip(), true).is_err());
    assert!(n.payment(id(2)).is_err()); // No partial tombstone installation.
    assert!(n.payment_recovery_required());
    let mut original = open(&src.0);
    let bytes = encode_tx(
        &original
            .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap()
            .relay
            .unwrap(),
    );
    drop(original);
    let newer = files.0.join("newer");
    backup(&src.0, &newer);
    merge_full_backup(&mut n, &newer, PASSWORD).unwrap();
    n.reconcile_payments(&v, 0, n.tip(), true).unwrap();
    assert_eq!(
        encode_tx(
            &n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        bytes
    );
    assert_eq!(n.payment(id(2)).unwrap().state, PaymentState::Cancelled);
}
#[test]
fn complete_snapshot_restores_exact_artifact_and_reservations_but_requires_order_reconciliation() {
    let dir = Temp::new();
    source(&dir.0);
    let out = Temp::new();
    let path = out.0.join("full.backup");
    let original = {
        let mut n = open(&dir.0);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap()
            .relay
            .unwrap()
    };
    backup(&dir.0, &path);
    let info = inspect_full_backup(&path, PASSWORD).unwrap();
    assert_eq!(info.payment_count, 1);
    assert_eq!(info.genesis, genesis());
    let destination = out.0.join("recovered");
    restore_full_backup(&path, &destination, PASSWORD).unwrap();
    assert_eq!(
        Keystore::load(&destination.join("key"))
            .unwrap()
            .open(PASSWORD)
            .unwrap(),
        key(1)
    );
    assert!(destination.join("genesis.json").is_file());
    for token in ["rpc-read.token", "rpc-spend.token", "rpc-devfund.token"] {
        assert!(destination.join(token).is_file());
    }
    let mut n = open(&destination);
    assert!(n.payment_recovery_required());
    assert_eq!(n.balance().unwrap().spendable, 0);
    assert_eq!(
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .err()
            .unwrap()
            .code(),
        "payment_reconciliation_required"
    );
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Unreconciled);
    let tip = n.tip();
    let review = n.reconcile_test_orders(&[order(1)], 0, tip, false).unwrap();
    assert!(!review.committed);
    assert!(n.payment_recovery_required());
    assert!(n
        .reconcile_test_orders(&[order(1)], 0, Digest([9; 32]), true)
        .is_err());
    n.reconcile_test_orders(&[order(1)], 0, tip, true).unwrap();
    assert!(!n.payment_recovery_required());
    assert_eq!(
        encode_tx(
            &n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        encode_tx(&original)
    );
    drop(n);
    let mut n = open(&destination);
    assert!(!n.payment_recovery_required());
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Pending);
}
#[test]
fn old_backup_cannot_forget_later_orders_and_a_newer_backup_merges_them_without_repayment() {
    let dir = Temp::new();
    source(&dir.0);
    let temp = Temp::new();
    let old = temp.0.join("old");
    let newer = temp.0.join("newer");
    {
        let mut n = open(&dir.0);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap();
    }
    backup(&dir.0, &old);
    let (block, later) = {
        let mut n = open(&dir.0);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap();
        let b = mine_one(&mut n);
        let t = n
            .pay_with_id(id(2), &key(2).address(), 10_000_000, false)
            .unwrap()
            .relay
            .unwrap();
        (b, t)
    };
    backup(&dir.0, &newer);
    let destination = temp.0.join("recovered");
    restore_full_backup(&old, &destination, PASSWORD).unwrap();
    let mut n = open(&destination);
    n.accept(&block).unwrap();
    let tip = n.tip();
    assert_eq!(
        n.reconcile_test_orders(&[order(1), order(2)], 1, tip, true)
            .err()
            .unwrap()
            .code(),
        "payment_history_incomplete"
    );
    assert!(n.payment_recovery_required());
    merge_full_backup(&mut n, &newer, PASSWORD).unwrap();
    n.reconcile_test_orders(&[order(1), order(2)], 1, tip, true)
        .unwrap();
    assert_eq!(n.payment(id(1)).unwrap().state, PaymentState::Confirmed);
    assert!(n
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .is_none());
    assert_eq!(
        encode_tx(
            &n.pay_with_id(id(2), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        encode_tx(&later)
    );
}
#[test]
fn restored_wallet_can_sync_from_genesis_to_backup_checkpoint_before_reconciling() {
    let dir = Temp::new();
    source(&dir.0);
    let temp = Temp::new();
    let path = temp.0.join("backup");
    let blocks = {
        let mut n = open(&dir.0);
        (0..102).map(|_| mine_one(&mut n)).collect::<Vec<_>>()
    };
    backup(&dir.0, &path);
    let destination = temp.0.join("restore");
    restore_full_backup(&path, &destination, PASSWORD).unwrap();
    let mut n = open(&destination);
    assert!(n.payment_recovery_required());
    assert!(n.reconcile_test_orders(&[], 0, n.tip(), true).is_err());
    for b in &blocks {
        n.accept(b).unwrap();
    }
    n.reconcile_test_orders(&[], n.height(), n.tip(), true)
        .unwrap();
    assert!(!n.payment_recovery_required());
}
#[test]
fn wrong_password_tampering_ownership_and_existing_destinations_fail_without_partial_publication() {
    let dir = Temp::new();
    source(&dir.0);
    let temp = Temp::new();
    let path = temp.0.join("backup");
    let lock = WalletFileLock::acquire(&dir.0).unwrap();
    assert!(create_full_backup(&dir.0, &path, PASSWORD, &genesis(), Arc::new(MockProver)).is_err());
    assert!(!path.exists());
    drop(lock);
    assert!(
        create_full_backup(&dir.0, &path, "incorrect", &genesis(), Arc::new(MockProver)).is_err()
    );
    assert!(!path.exists());
    backup(&dir.0, &path);
    let bytes = std::fs::read(&path).unwrap();
    assert!(create_full_backup(&dir.0, &path, PASSWORD, &genesis(), Arc::new(MockProver)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let dest = temp.0.join("restored");
    assert!(restore_full_backup(&path, &dest, "incorrect").is_err());
    assert!(!dest.exists());
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    std::fs::write(&path, tampered).unwrap();
    assert!(restore_full_backup(&path, &dest, PASSWORD).is_err());
    assert!(!dest.exists());
    std::fs::write(&path, bytes).unwrap();
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("marker"), "preserve").unwrap();
    assert!(restore_full_backup(&path, &dest, PASSWORD).is_err());
    assert_eq!(
        std::fs::read_to_string(dest.join("marker")).unwrap(),
        "preserve"
    );
}

#[test]
fn restored_directory_cannot_silently_initialize_missing_recovery_data() {
    use redb::{Database, TableDefinition};
    for fault in [0, 1, 2] {
        let dir = Temp::new();
        source(&dir.0);
        let temp = Temp::new();
        let path = temp.0.join("backup");
        backup(&dir.0, &path);
        let dest = temp.0.join("restore");
        restore_full_backup(&path, &dest, PASSWORD).unwrap();
        match fault {
            0 => {
                std::fs::remove_file(dest.join("payments.redb")).unwrap();
            }
            1 => {
                std::fs::remove_file(dest.join("payments.required")).unwrap();
            }
            _ => {
                let db = Database::create(dest.join("payments.redb")).unwrap();
                let tx = db.begin_write().unwrap();
                {
                    let mut t = tx
                        .open_table(TableDefinition::<&str, &[u8]>::new("context-v1"))
                        .unwrap();
                    t.remove("recovery").unwrap();
                }
                tx.commit().unwrap();
            }
        }
        let g = genesis();
        let mut n = Node::open(
            g,
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        assert!(
            n.enable_payment_journal(&dest.join("payments.redb"))
                .is_err(),
            "fault {fault}"
        );
    }
}
#[test]
fn reconciliation_rejects_omissions_duplicates_extra_and_changed_requests_and_retains_gate_when_locked(
) {
    let dir = Temp::new();
    source(&dir.0);
    let temp = Temp::new();
    let path = temp.0.join("backup");
    {
        let mut n = open(&dir.0);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap();
    }
    backup(&dir.0, &path);
    let dest = temp.0.join("restore");
    restore_full_backup(&path, &dest, PASSWORD).unwrap();
    let mut n = open(&dest);
    let mut changed = order(1);
    changed.amount = "0.2".into();
    for orders in [
        vec![],
        vec![order(1), order(1)],
        vec![order(1), order(2)],
        vec![changed],
    ] {
        assert!(n.reconcile_test_orders(&orders, 0, n.tip(), true).is_err());
        assert!(n.payment_recovery_required());
    }
    n.protect_wallet(Keystore::load(&dest.join("key")).unwrap())
        .unwrap();
    assert!(n.payment_recovery_required());
    assert!(n
        .reconcile_test_orders(&[order(1)], 0, n.tip(), true)
        .is_err());
    n.unlock_wallet(PASSWORD, 30).unwrap();
    assert!(n.payment_recovery_required());
    n.reconcile_test_orders(&[order(1)], 0, n.tip(), true)
        .unwrap();
    n.lock_wallet();
    assert!(!n.payment_recovery_required());
    n.unlock_wallet(PASSWORD, 30).unwrap();
    assert!(!n.payment_recovery_required());
}

#[cfg(feature = "development")]
#[test]
fn offline_full_backup_cli_and_explicit_dry_run_commit_roundtrip() {
    use siworld_node::secrets::write_secret;
    use std::process::Command;
    let temp = Temp::new();
    let source_dir = temp.0.join("source");
    std::fs::create_dir(&source_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&source_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    source(&source_dir);
    let original = {
        let mut n = open(&source_dir);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap()
            .relay
            .unwrap()
    };
    write_secret(&temp.0.join("password"), PASSWORD).unwrap();
    let g = temp.0.join("genesis.json");
    std::fs::write(&g, genesis().to_json()).unwrap();
    let orders = temp.0.join("orders.json");
    write_secret(&orders, &serde_json::to_string(&[order(1)]).unwrap()).unwrap();
    let run = |args: Vec<&str>| {
        let out = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .arg("--password-file")
            .arg(temp.0.join("password"))
            .current_dir(&temp.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let s = String::from_utf8(out.stdout).unwrap();
        assert!(!s.contains(PASSWORD));
        s
    };
    run(vec![
        "wallet-backup-full",
        "--datadir",
        "source",
        "--genesis",
        "genesis.json",
        "--out",
        "full",
    ]);
    assert!(run(vec!["wallet-check-full", "--backup", "full"]).contains("payments: 1"));
    run(vec![
        "wallet-restore-full",
        "--backup",
        "full",
        "--datadir",
        "recovered",
    ]);
    let tip = siworld_node::hex(&genesis().id);
    let base = vec![
        "wallet-reconcile",
        "--datadir",
        "recovered",
        "--genesis",
        "genesis.json",
        "--orders",
        "orders.json",
        "--expected-height",
        "0",
        "--expected-tip",
        &tip,
    ];
    assert!(run(base.clone()).contains("\"committed\": false"));
    assert!(open(&temp.0.join("recovered")).payment_recovery_required());
    let mut raw_commit = base;
    raw_commit.push("--commit");
    let rejected = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
        .args(raw_commit)
        .args(["--password-file", "password"])
        .current_dir(&temp.0)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("order_ledger_freshness_required"));
    let ledger_dir = Temp::new();
    let witness_dir = Temp::new();
    let mut ledger = siworld_node::orders::OrderLedger::create(
        &ledger_dir.0,
        &witness_dir.0,
        PASSWORD,
        genesis().id,
        key(1).owner(),
    )
    .unwrap();
    let cp = ledger.record(&order(1)).unwrap();
    cp.save_new(&temp.0.join("pin.json")).unwrap();
    drop(ledger);
    let mut commit = vec![
        "wallet-reconcile",
        "--datadir",
        "recovered",
        "--genesis",
        "genesis.json",
        "--expected-height",
        "0",
        "--expected-tip",
        &tip,
        "--order-ledger",
        ledger_dir.0.to_str().unwrap(),
        "--order-witness",
        witness_dir.0.to_str().unwrap(),
        "--ledger-password-file",
        "password",
        "--expected-ledger-checkpoint",
        "pin.json",
        "--commit",
    ];
    cp.save_new(&temp.0.join("recovered/pin.json")).unwrap();
    cp.save_new(&ledger_dir.0.join("pin.json")).unwrap();
    for bad_pin in [
        temp.0.join("recovered/pin.json"),
        ledger_dir.0.join("pin.json"),
        witness_dir
            .0
            .join(siworld_node::orders::Checkpoint::filename(cp.sequence)),
    ] {
        let mut args = commit.clone();
        let pos = args
            .iter()
            .position(|a| *a == "--expected-ledger-checkpoint")
            .unwrap();
        args[pos + 1] = bad_pin.to_str().unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .args(["--password-file", "password"])
            .current_dir(&temp.0)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("checkpoint must be outside"));
        assert!(open(&temp.0.join("recovered")).payment_recovery_required());
    }
    assert!(run(commit.clone()).contains("\"committed\": true"));
    commit.clear();
    let work = Temp::new();
    let drill = vec![
        "wallet-recovery-drill",
        "--backup",
        "full",
        "--chain-datadir",
        "source",
        "--work-dir",
        work.0.to_str().unwrap(),
        "--out",
        "drill.json",
        "--expected-height",
        "0",
        "--expected-tip",
        &tip,
        "--order-ledger",
        ledger_dir.0.to_str().unwrap(),
        "--order-witness",
        witness_dir.0.to_str().unwrap(),
        "--ledger-password-file",
        "password",
        "--expected-ledger-checkpoint",
        "pin.json",
    ];
    for dir in [&source_dir, &work.0] {
        let inside = dir.join("pin.json");
        cp.save_new(&inside).unwrap();
        let mut args = drill.clone();
        let pos = args
            .iter()
            .position(|a| *a == "--expected-ledger-checkpoint")
            .unwrap();
        args[pos + 1] = inside.to_str().unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .args(["--password-file", "password"])
            .current_dir(&temp.0)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("checkpoint must be outside"));
        assert!(!temp.0.join("drill.json").exists());
    }
    run(drill);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.0.join("drill.json")).unwrap()).unwrap();
    assert_eq!(report["reopened"], true);
    assert_eq!(report["retry_count"], 1);
    let mut n = open(&temp.0.join("recovered"));
    assert!(!n.payment_recovery_required());
    assert_eq!(
        encode_tx(
            &n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        encode_tx(&original)
    );
}

#[test]
fn imports_reject_other_wallets_and_networks_without_changing_recovered_history() {
    let dir = Temp::new();
    source(&dir.0);
    let temp = Temp::new();
    let path = temp.0.join("backup");
    backup(&dir.0, &path);
    let dest = temp.0.join("restore");
    restore_full_backup(&path, &dest, PASSWORD).unwrap();
    let mut n = open(&dest);
    for other_wallet in [true, false] {
        let other = Temp::new();
        let other_key = if other_wallet { key(3) } else { key(1) };
        Keystore::seal(&other_key, PASSWORD)
            .unwrap()
            .save_new(&other.0.join("key"))
            .unwrap();
        let g = if other_wallet {
            genesis()
        } else {
            let mut file: GenesisFile = serde_json::from_str(&genesis().to_json()).unwrap();
            file.network = "other-network".into();
            Genesis::from_file(&file).unwrap()
        };
        let snapshot = other.0.join("backup");
        create_full_backup(&other.0, &snapshot, PASSWORD, &g, Arc::new(MockProver)).unwrap();
        assert!(merge_full_backup(&mut n, &snapshot, PASSWORD).is_err());
        assert!(n.payment_recovery_required());
    }
    n.reconcile_test_orders(&[], 0, n.tip(), true).unwrap();
}

trait TestReconciliation {
    fn reconcile_test_orders(
        &mut self,
        orders: &[PaymentOrder],
        h: u64,
        t: Digest,
        commit: bool,
    ) -> Result<siworld_node::payments::Reconciliation, siworld_node::payments::PaymentError>;
}
impl TestReconciliation for Node {
    fn reconcile_test_orders(
        &mut self,
        orders: &[PaymentOrder],
        h: u64,
        t: Digest,
        commit: bool,
    ) -> Result<siworld_node::payments::Reconciliation, siworld_node::payments::PaymentError> {
        use siworld_node::payments::PaymentError;
        let tmp = Temp::new();
        let l = tmp.0.join("ledger");
        let w = tmp.0.join("witness");
        for p in [&l, &w] {
            std::fs::create_dir(p).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let mut ledger = siworld_node::orders::OrderLedger::create(
            &l,
            &w,
            PASSWORD,
            self.genesis.id,
            self.address().owner(),
        )
        .unwrap();
        let mut ids = std::collections::BTreeSet::new();
        for order in orders {
            if !ids.insert(&order.payment_id) {
                return Err(PaymentError::Conflict);
            }
            ledger.record(order).map_err(|_| PaymentError::Conflict)?;
        }
        let cp = ledger.checkpoint().unwrap();
        let verified = ledger.verify(&cp).unwrap();
        self.reconcile_payments(&verified, h, t, commit)
    }
}

#[test]
fn offline_drill_replays_reconciles_retries_and_reopens_without_changing_source() {
    let source_dir = Temp::new();
    source(&source_dir.0);
    {
        let mut n = open(&source_dir.0);
        n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
            .unwrap();
        mine_one(&mut n);
        n.pay_with_id(id(2), &key(2).address(), 10_000_000, false)
            .unwrap();
    }
    let temp = Temp::new();
    let path = temp.0.join("backup");
    backup(&source_dir.0, &path);
    let l = Temp::new();
    let w = Temp::new();
    let work = Temp::new();
    let mut ledger = siworld_node::orders::OrderLedger::create(
        &l.0,
        &w.0,
        PASSWORD,
        genesis().id,
        key(1).owner(),
    )
    .unwrap();
    for i in [1, 2] {
        ledger.record(&order(i)).unwrap();
    }
    let cp = ledger.checkpoint().unwrap();
    let verified = ledger.verify(&cp).unwrap();
    let (height, tip) = {
        let n = open(&source_dir.0);
        (n.height(), n.tip())
    };
    let before: Vec<_> = ["key", "payments.redb", "blocks.redb"]
        .iter()
        .map(|f| std::fs::read(source_dir.0.join(f)).unwrap())
        .collect();
    let request = siworld_node::backup::DrillRequest {
        backup: &path,
        chain_dir: &source_dir.0,
        work_dir: &work.0,
        password: PASSWORD,
        expected_height: height,
        expected_tip: tip,
    };
    let report =
        siworld_node::backup::drill_full_backup(&request, Arc::new(MockProver), &verified).unwrap();
    assert_eq!(report.payment_count, 2);
    assert_eq!(report.retry_count, 2);
    assert!(report.reopened);
    assert_eq!(report.order_checkpoint, cp);
    for (i, f) in ["key", "payments.redb", "blocks.redb"].iter().enumerate() {
        assert_eq!(std::fs::read(source_dir.0.join(f)).unwrap(), before[i]);
    }
    assert!(!std::fs::read_dir(&work.0).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".wallet-drill-")));
    let bad = siworld_node::backup::DrillRequest {
        expected_tip: Digest([8; 32]),
        ..request
    };
    assert!(
        siworld_node::backup::drill_full_backup(&bad, Arc::new(MockProver), &verified).is_err()
    );
    let corrupt_chain = Temp::new();
    std::fs::copy(
        source_dir.0.join("blocks.redb"),
        corrupt_chain.0.join("blocks.redb"),
    )
    .unwrap();
    {
        let mut store =
            BlockStore::open(&corrupt_chain.0.join("blocks.redb"), &genesis().id).unwrap();
        let mut bad = store.blocks().unwrap()[0].clone();
        bad.header.nonce = bad.header.nonce.wrapping_add(1);
        bad.proof.0.clear();
        store.append(&bad).unwrap();
    }
    let corrupt = siworld_node::backup::DrillRequest {
        chain_dir: &corrupt_chain.0,
        ..request
    };
    assert!(
        siworld_node::backup::drill_full_backup(&corrupt, Arc::new(MockProver), &verified).is_err()
    );
    report.save_new(&temp.0.join("report.json")).unwrap();
    assert!(report.save_new(&temp.0.join("report.json")).is_err());

    ledger.record(&order(3)).unwrap();
    assert!(ledger.verify(&cp).is_err());
    let pin = ledger.checkpoint().unwrap();
    let v = ledger.verify(&pin).unwrap();
    let request = siworld_node::backup::DrillRequest {
        expected_tip: tip,
        ..bad
    };
    assert!(
        siworld_node::backup::drill_full_backup(&request, Arc::new(MockProver), &v)
            .unwrap_err()
            .contains("payment_history_incomplete")
    );
    assert!(!std::fs::read_dir(&work.0).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".wallet-drill-")));
}
#[test]
fn copied_backup_domains_reject_mixed_generations_and_recover_from_a_current_retained_pin() {
    use siworld_node::orders::{Checkpoint, OrderLedger};
    // Separate directories simulate separately restored domains; they do not
    // establish physical disk, administrator or snapshot-policy independence.
    let src = Temp::new();
    source(&src.0);
    let l = Temp::new();
    let w = Temp::new();
    let retained = Temp::new();
    let archives = Temp::new();
    let mut ledger =
        OrderLedger::create(&l.0, &w.0, PASSWORD, genesis().id, key(1).owner()).unwrap();
    ledger.record(&order(1)).unwrap();
    ledger.begin_dispatch(&order(1)).unwrap();
    let old_pin = retained.0.join("old.json");
    let old_cp = ledger.export_checkpoint(&old_pin, None).unwrap();
    let old_ledger = std::fs::read(l.0.join("orders.enc")).unwrap();
    let original = {
        let mut n = open(&src.0);
        encode_tx(
            &n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap(),
        )
    };
    let snapshot = archives.0.join("wallet.full");
    backup(&src.0, &snapshot);
    let cp = ledger.record(&order(2)).unwrap();
    let cp = ledger.cancel_unsubmitted(id(2), &cp).unwrap();
    let pin = retained.0.join("current.json");
    assert_eq!(ledger.export_checkpoint(&pin, Some(&old_pin)).unwrap(), cp);
    let latest_ledger = std::fs::read(l.0.join("orders.enc")).unwrap();
    // A checkpoint is an identity/hash reference, not an order payload backup.
    let copied_ledger = Temp::new();
    let copied_witness = Temp::new();
    let recovered_pin = Temp::new();
    std::fs::copy(&pin, recovered_pin.0.join("current.json")).unwrap();
    let copy_prefix = |last: u64| {
        for seq in 0..=last {
            let name = Checkpoint::filename(seq);
            std::fs::copy(w.0.join(&name), copied_witness.0.join(name)).unwrap();
        }
    };
    copy_prefix(old_cp.sequence);
    std::fs::write(copied_ledger.0.join("orders.enc"), &latest_ledger).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            copied_ledger.0.join("orders.enc"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    // Two unwitnessed events cannot be repaired as a single interrupted append.
    assert!(OrderLedger::open(&copied_ledger.0, &copied_witness.0, PASSWORD).is_err());
    std::fs::write(copied_ledger.0.join("orders.enc"), &old_ledger).unwrap();
    let restored = archives.0.join("restored");
    restore_full_backup(&snapshot, &restored, PASSWORD).unwrap();
    let mut n = open(&restored);
    let pin_path = recovered_pin.0.join("current.json");
    let old = OrderLedger::open(&copied_ledger.0, &copied_witness.0, PASSWORD).unwrap();
    assert!(old.verify_file(&pin_path).is_err());
    assert!(old
        .export_checkpoint(&recovered_pin.0.join("rollback.json"), Some(&pin_path))
        .is_err());
    assert!(!recovered_pin.0.join("rollback.json").exists());
    assert!(n.payment_recovery_required());
    // Document the unavoidable coordinated-rollback control: an old ledger,
    // old witness AND old expected pin agree. Do not use that as freshness.
    assert!(old.verify_file(&old_pin).is_ok());
    drop(old);
    copy_prefix(cp.sequence);
    assert!(OrderLedger::open(&copied_ledger.0, &copied_witness.0, PASSWORD).is_err());
    std::fs::write(copied_ledger.0.join("orders.enc"), &latest_ledger).unwrap();
    let recovered = OrderLedger::open(&copied_ledger.0, &copied_witness.0, PASSWORD).unwrap();
    let verified = recovered.verify_file(&pin_path).unwrap();
    let preview = n.reconcile_payments(&verified, 0, n.tip(), false).unwrap();
    assert!(preview.committable);
    assert!(n.payment_recovery_required());
    assert_eq!(preview.cancelled_tombstones, 1);
    n.reconcile_payments(&verified, 0, n.tip(), true).unwrap();
    assert_eq!(
        encode_tx(
            &n.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        original
    );
    assert_eq!(n.payment(id(2)).unwrap().state, PaymentState::Cancelled);
    drop(n);
    let mut reopened = open(&restored);
    assert!(!reopened.payment_recovery_required());
    assert_eq!(
        reopened.payment(id(2)).unwrap().state,
        PaymentState::Cancelled
    );
    drop(reopened);
    let work = Temp::new();
    let report = siworld_node::backup::drill_full_backup(
        &siworld_node::backup::DrillRequest {
            backup: &snapshot,
            chain_dir: &src.0,
            work_dir: &work.0,
            password: PASSWORD,
            expected_height: 0,
            expected_tip: genesis().id,
        },
        Arc::new(MockProver),
        &verified,
    )
    .unwrap();
    assert_eq!(report.order_checkpoint, cp);
    assert_eq!(report.cancelled_tombstones, 1);
    assert!(report.reopened);
    assert_eq!(Checkpoint::read(&pin_path).unwrap(), cp);
    assert_eq!(Checkpoint::read(&old_pin).unwrap(), old_cp);
    assert_eq!(
        std::fs::read(copied_ledger.0.join("orders.enc")).unwrap(),
        latest_ledger
    );
}

#[test]
fn verified_orders_reject_wrong_wallet_network_and_co_located_journal() {
    let source_dir = Temp::new();
    source(&source_dir.0);
    let temp = Temp::new();
    let path = temp.0.join("backup");
    backup(&source_dir.0, &path);
    let dest = temp.0.join("restore");
    restore_full_backup(&path, &dest, PASSWORD).unwrap();
    let mut node = open(&dest);
    for (network, owner) in [
        (Digest([9; 32]), key(1).owner()),
        (genesis().id, key(3).owner()),
    ] {
        let l = Temp::new();
        let w = Temp::new();
        let ledger =
            siworld_node::orders::OrderLedger::create(&l.0, &w.0, PASSWORD, network, owner)
                .unwrap();
        let cp = ledger.checkpoint().unwrap();
        let verified = ledger.verify(&cp).unwrap();
        assert_eq!(
            node.reconcile_payments(&verified, 0, node.tip(), true)
                .err()
                .unwrap()
                .code(),
            "order_ledger_freshness_required"
        );
        assert!(node.payment_recovery_required());
    }
    let l = Temp::new();
    let w = Temp::new();
    let ledger = siworld_node::orders::OrderLedger::create(
        &l.0,
        &w.0,
        PASSWORD,
        genesis().id,
        key(1).owner(),
    )
    .unwrap();
    let cp = ledger.checkpoint().unwrap();
    let verified = ledger.verify(&cp).unwrap();
    let mut n = Node::open(
        genesis(),
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    n.enable_payment_journal(&l.0.join("payments.redb"))
        .unwrap();
    assert_eq!(
        n.reconcile_payments(&verified, 0, n.tip(), true)
            .err()
            .unwrap()
            .code(),
        "order_ledger_freshness_required"
    );
}

#[test]
fn signed_archive_generation_feeds_exact_wallet_retry_and_offline_recovery_drill() {
    use siworld_node::orders::{archive, OrderLedger};
    use siworld_node::retention::{ReceiptSigner, Request, Retainer};
    // One-host simulated domains only; physical independence is a deployment gate.
    let src = Temp::new();
    source(&src.0);
    let l = Temp::new();
    let w = Temp::new();
    let files = Temp::new();
    let receiving = Temp::new();
    let mut ledger =
        OrderLedger::create(&l.0, &w.0, PASSWORD, genesis().id, key(1).owner()).unwrap();
    ledger.record(&order(1)).unwrap();
    ledger.begin_dispatch(&order(1)).unwrap();
    let original = {
        let mut node = open(&src.0);
        encode_tx(
            &node
                .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap(),
        )
    };
    let snapshot = files.0.join("wallet.full");
    backup(&src.0, &snapshot);
    let cp = ledger.record(&order(2)).unwrap();
    ledger.cancel_unsubmitted(id(2), &cp).unwrap();
    let generation = files.0.join("archive");
    let manifest = ledger.archive(&generation, None).unwrap();
    let signer = ReceiptSigner::generate_file(&receiving.0.join("receiver.key"), PASSWORD).unwrap();
    let root = receiving.0.join("retained");
    let mut retainer = Retainer::create(&root, &signer, &manifest.checkpoint).unwrap();
    let receipt = retainer
        .accept(&generation, &Request::fresh(None).unwrap())
        .unwrap();
    let query = Request::fresh(Some(receipt.id().unwrap())).unwrap();
    let current = retainer
        .status(&query)
        .unwrap()
        .verify(signer.verifying_key(), &query)
        .unwrap();
    let pin = files.0.join("independent-current.json");
    current.body.manifest.checkpoint.save_new(&pin).unwrap();
    let restored_orders = files.0.join("restored-orders");
    archive::restore_file(
        &root.join("entry-0000000000000001/archive"),
        &restored_orders,
        PASSWORD,
        &pin,
    )
    .unwrap();
    let restored = OrderLedger::open(
        &restored_orders.join("ledger"),
        &restored_orders.join("witness"),
        PASSWORD,
    )
    .unwrap();
    let verified = restored.verify_file(&pin).unwrap();
    let recovered_wallet = files.0.join("recovered-wallet");
    restore_full_backup(&snapshot, &recovered_wallet, PASSWORD).unwrap();
    let mut node = open(&recovered_wallet);
    node.reconcile_payments(&verified, 0, node.tip(), true)
        .unwrap();
    assert!(!node.payment_recovery_required());
    assert_eq!(node.payment(id(2)).unwrap().state, PaymentState::Cancelled);
    assert_eq!(
        encode_tx(
            &node
                .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .unwrap()
        ),
        original
    );
    drop(node);
    let work = Temp::new();
    let drill = siworld_node::backup::drill_full_backup(
        &siworld_node::backup::DrillRequest {
            backup: &snapshot,
            chain_dir: &src.0,
            work_dir: &work.0,
            password: PASSWORD,
            expected_height: 0,
            expected_tip: genesis().id,
        },
        Arc::new(MockProver),
        &verified,
    )
    .unwrap();
    assert!(drill.reopened);
    assert_eq!(drill.cancelled_tombstones, 1);
    assert_eq!(drill.order_checkpoint, manifest.checkpoint);
}
