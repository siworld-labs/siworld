//! Independent ledger rollback, freshness and write-ahead submission boundaries.
use siworld_core::Digest;
use siworld_crypto::SpendKey;
use siworld_node::orders::{Checkpoint, OrderLedger};
use siworld_node::payments::{PaymentId, PaymentOrder};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
const PASSWORD: &str = "independent ledger test password";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "siworld-orders-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
    fn dir(&self, n: &str) -> PathBuf {
        let p = self.0.join(n);
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        p
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn order(i: u8) -> PaymentOrder {
    PaymentOrder::new(
        PaymentId::parse(&format!("{i:02x}").repeat(32)).unwrap(),
        &SpendKey::from_digest(Digest([2; 32])).address(),
        10_000_000,
        false,
    )
}
fn create(t: &Temp) -> OrderLedger {
    OrderLedger::create(
        &t.dir("ledger"),
        &t.dir("witness"),
        PASSWORD,
        Digest([3; 32]),
        SpendKey::from_digest(Digest([1; 32])).owner(),
    )
    .unwrap()
}
#[test]
fn retained_checkpoints_advance_only_from_a_verified_prefix_and_never_overwrite() {
    let t = Temp::new();
    let retained = t.dir("retained");
    let mut ledger = create(&t);
    let zero = retained.join("zero.json");
    let initial = ledger.export_checkpoint(&zero, None).unwrap();
    let one = ledger.record(&order(1)).unwrap();
    let next = retained.join("one.json");
    assert_eq!(ledger.export_checkpoint(&next, Some(&zero)).unwrap(), one);
    assert_eq!(Checkpoint::read(&zero).unwrap(), initial);
    assert!(ledger.export_checkpoint(&next, Some(&zero)).is_err());
    let current = ledger.begin_dispatch(&order(1)).unwrap();
    let mut fork = one.clone();
    fork.head = "ff".repeat(32);
    let invalid = retained.join("fork.json");
    fork.save_new(&invalid).unwrap();
    let output = retained.join("rejected.json");
    assert!(ledger.export_checkpoint(&output, Some(&invalid)).is_err());
    assert!(!output.exists());
    let mut ahead = current.clone();
    ahead.sequence += 1;
    let future = retained.join("ahead.json");
    ahead.save_new(&future).unwrap();
    assert!(ledger.export_checkpoint(&output, Some(&future)).is_err());
    assert!(!output.exists());
    let mut foreign = current.clone();
    foreign.ledger_id = "ee".repeat(32);
    let other = retained.join("foreign.json");
    foreign.save_new(&other).unwrap();
    assert!(ledger.export_checkpoint(&output, Some(&other)).is_err());
    let updated = retained.join("current.json");
    assert_eq!(
        ledger.export_checkpoint(&updated, Some(&next)).unwrap(),
        current
    );
    assert_eq!(ledger.verify_file(&updated).unwrap().checkpoint(), &current);
    assert!(ledger.verify_file(&next).is_err());
}
#[test]
fn checkpoint_files_must_be_outside_managed_directories_and_aliases() {
    let t = Temp::new();
    let ledger = create(&t);
    for dir in ["ledger", "witness"] {
        let output = t.0.join(dir).join("retained.json");
        assert!(ledger.export_checkpoint(&output, None).is_err());
        assert!(!output.exists());
    }
    let witness = t.0.join("witness").join(Checkpoint::filename(0));
    assert!(ledger.verify_file(&witness).is_err());
    let wallet = t.dir("wallet");
    let colocated = wallet.join("pin.json");
    ledger.checkpoint().unwrap().save_new(&colocated).unwrap();
    assert!(ledger
        .verify_file(&colocated)
        .unwrap()
        .ensure_outside(&wallet)
        .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = t.0.join("alias");
        symlink(t.0.join("witness"), &alias).unwrap();
        assert!(ledger
            .export_checkpoint(&alias.join("retained.json"), None)
            .is_err());
        assert!(ledger
            .verify_file(&alias.join(Checkpoint::filename(0)))
            .is_err());
    }
    drop(ledger);
    // A rejected export must not add unexpected witness files or damage reopening.
    OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).unwrap();
}
#[test]
fn same_id_retry_is_stable_and_pinned_witness_rejects_stale_exports_and_rollbacks() {
    let t = Temp::new();
    let mut l = create(&t);
    let empty = l.checkpoint().unwrap();
    let one = l.record(&order(1)).unwrap();
    assert_eq!(one.sequence, 1);
    assert_eq!(l.record(&order(1)).unwrap(), one);
    let saved = std::fs::read(t.0.join("ledger/orders.enc")).unwrap();
    let two = l.record(&order(2)).unwrap();
    assert_ne!(one.head, two.head);
    assert!(l.verify(&one).is_err());
    assert_eq!(l.verify(&two).unwrap().orders().len(), 2);
    let mut altered = order(1);
    altered.amount = "1".into();
    assert!(l.record(&altered).is_err());
    drop(l);
    std::fs::write(t.0.join("ledger/orders.enc"), &saved).unwrap();
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).is_err());
    // Even if the witness is also rolled back, a retained newer pin rejects it.
    std::fs::remove_file(t.0.join("witness").join(Checkpoint::filename(2))).unwrap();
    let l = OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).unwrap();
    assert!(l.verify(&two).is_err());
    assert!(l.verify(&empty).is_err());
}
#[test]
fn independent_ownership_wrong_password_tampering_and_missing_witness_fail_closed() {
    let t = Temp::new();
    let mut l = create(&t);
    let cp = l.record(&order(1)).unwrap();
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).is_err());
    drop(l);
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), "incorrect").is_err());
    let p = t.0.join("ledger/orders.enc");
    let bytes = std::fs::read(&p).unwrap();
    let mut bad = bytes.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    std::fs::write(&p, bad).unwrap();
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).is_err());
    std::fs::write(&p, bytes).unwrap();
    std::fs::remove_file(t.0.join("witness").join(Checkpoint::filename(0))).unwrap();
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).is_err());
    assert_eq!(cp.sequence, 1);
}

#[test]
fn offline_ledger_cli_roundtrip_and_exclusive_checkpoint_export() {
    use siworld_node::genesis::{Genesis, GenesisFile, ProofsFile};
    use siworld_node::secrets::write_secret;
    let t = Temp::new();
    write_secret(&t.0.join("password"), PASSWORD).unwrap();
    let g = Genesis::from_file(&GenesisFile {
        network: "ledger-cli".into(),
        timestamp: 1000,
        block_time: 1,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![],
    })
    .unwrap();
    std::fs::write(t.0.join("genesis.json"), g.to_json()).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .args([
                "--order-ledger",
                "ledger",
                "--order-witness",
                "witness",
                "--ledger-password-file",
                "password",
            ])
            .current_dir(&t.0)
            .output()
            .unwrap()
    };
    let owner = siworld_node::hex(&SpendKey::from_digest(Digest([1; 32])).owner());
    let out = run(&[
        "orders-init",
        "--genesis",
        "genesis.json",
        "--owner",
        &owner,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let one = order(1);
    let out = run(&[
        "orders-record",
        "--payment-id",
        &one.payment_id,
        "--to",
        &one.to,
        "--amount",
        &one.amount,
    ]);
    assert!(out.status.success());
    let cp: Checkpoint = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(cp.sequence, 1);
    let out = run(&["orders-checkpoint", "--out", "pin.json"]);
    assert!(out.status.success());
    assert_eq!(Checkpoint::read(&t.0.join("pin.json")).unwrap(), cp);
    for managed in ["ledger/retained.json", "witness/retained.json"] {
        let out = run(&["orders-checkpoint", "--out", managed]);
        assert!(!out.status.success());
        assert!(!t.0.join(managed).exists());
    }
    let inside = format!("witness/{}", Checkpoint::filename(1));
    let out = run(&[
        "orders-cancel",
        "--payment-id",
        &one.payment_id,
        "--expected-ledger-checkpoint",
        &inside,
        "--commit",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checkpoint must be outside"));
    let cancel_args = [
        "orders-cancel",
        "--payment-id",
        &one.payment_id,
        "--expected-ledger-checkpoint",
        "pin.json",
    ];
    let preview = run(&cancel_args);
    assert!(preview.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&preview.stdout).unwrap()["committed"],
        false
    );
    assert!(!t.0.join("witness").join(Checkpoint::filename(2)).exists());
    let mut commit = cancel_args.to_vec();
    commit.push("--commit");
    let cancelled = run(&commit);
    assert!(
        cancelled.status.success(),
        "{}",
        String::from_utf8_lossy(&cancelled.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Checkpoint>(&cancelled.stdout)
            .unwrap()
            .sequence,
        2
    );
    assert!(run(&commit).status.success()); // Exact lost-reply retry.
    let updated = run(&[
        "orders-checkpoint",
        "--out",
        "pin-2.json",
        "--previous-ledger-checkpoint",
        "pin.json",
    ]);
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    assert_eq!(
        Checkpoint::read(&t.0.join("pin-2.json")).unwrap().sequence,
        2
    );
    assert_eq!(Checkpoint::read(&t.0.join("pin.json")).unwrap(), cp);
    assert!(!run(&cancel_args).status.success()); // A stale preview cannot start a new action.
    assert!(!run(&[
        "orders-dispatch",
        "--payment-id",
        &one.payment_id,
        "--to",
        &one.to,
        "--amount",
        &one.amount
    ])
    .status
    .success());
    assert!(!run(&["orders-checkpoint", "--out", "pin.json"])
        .status
        .success());
    assert!(!run(&[
        "orders-record",
        "--payment-id",
        &one.payment_id,
        "--to",
        &one.to,
        "--amount",
        "0.2"
    ])
    .status
    .success());
    assert!(!run(&[
        "orders-init",
        "--genesis",
        "genesis.json",
        "--owner",
        &owner
    ])
    .status
    .success());
}
