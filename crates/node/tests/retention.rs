//! Consistent archives and independently keyed retention protocol regressions.
use siworld_core::Digest;
use siworld_crypto::SpendKey;
use siworld_node::orders::{archive, OrderLedger};
use siworld_node::payments::{PaymentId, PaymentOrder};
use siworld_node::retention::{Receipt, ReceiptSigner, Request, Retainer, Status};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
const PASSWORD: &str = "temporary retention exercise password";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "si-retention-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        private_dir(&p);
        Self(p)
    }
    fn dir(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        private_dir(&p);
        p
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn private_dir(p: &Path) {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p).unwrap();
}
fn order(i: u8) -> PaymentOrder {
    PaymentOrder::new(
        PaymentId::parse(&format!("{i:02x}").repeat(32)).unwrap(),
        &SpendKey::from_digest(Digest([2; 32])).address(),
        10_000_000,
        false,
    )
}
fn ledger(t: &Temp) -> OrderLedger {
    OrderLedger::create(
        &t.dir("ledger"),
        &t.dir("witness"),
        PASSWORD,
        Digest([3; 32]),
        SpendKey::from_digest(Digest([1; 32])).owner(),
    )
    .unwrap()
}
fn signer(t: &Temp) -> ReceiptSigner {
    ReceiptSigner::generate_file(&t.0.join("receiver.key"), PASSWORD).unwrap()
}
#[test]
fn archive_holds_both_locks_preserves_exact_bytes_and_restores_only_a_matching_generation() {
    let t = Temp::new();
    let mut l = ledger(&t);
    l.record(&order(1)).unwrap();
    l.begin_dispatch(&order(1)).unwrap();
    let cp = l.checkpoint().unwrap();
    let original = std::fs::read(t.0.join("ledger/orders.enc")).unwrap();
    let path = t.0.join("archive");
    let m = l.archive(&path, None).unwrap();
    assert_eq!(m.checkpoint, cp);
    assert_eq!(archive::inspect(&path).unwrap(), m);
    assert_eq!(
        std::fs::read(path.join("ledger/orders.enc")).unwrap(),
        original
    );
    assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASSWORD).is_err());
    assert!(l.archive(&path, None).is_err());
    assert!(l.archive(&t.0.join("witness/bad"), None).is_err());
    let restore = t.0.join("restored");
    let mut wrong = cp.clone();
    wrong.head = "ff".repeat(32);
    assert!(archive::restore(&path, &restore, PASSWORD, &wrong).is_err());
    assert!(!restore.exists());
    assert!(archive::restore(&path, &restore, "incorrect", &cp).is_err());
    assert!(!restore.exists());
    archive::restore(&path, &restore, PASSWORD, &cp).unwrap();
    assert!(archive::restore(&path, &restore, PASSWORD, &cp).is_err());
    let restored =
        OrderLedger::open(&restore.join("ledger"), &restore.join("witness"), PASSWORD).unwrap();
    assert_eq!(restored.checkpoint().unwrap(), cp);
    assert_eq!(
        std::fs::read(t.0.join("ledger/orders.enc")).unwrap(),
        original
    );
}
#[test]
fn archive_rejects_missing_extra_tampered_and_aliased_files() {
    let t = Temp::new();
    let l = ledger(&t);
    let path = t.0.join("archive");
    l.archive(&path, None).unwrap();
    let file = path.join("ledger/orders.enc");
    let original = std::fs::read(&file).unwrap();
    std::fs::write(&file, b"corrupt").unwrap();
    assert!(archive::inspect(&path).is_err());
    std::fs::write(&file, &original).unwrap();
    std::fs::write(path.join("witness/unexpected"), b"bad").unwrap();
    assert!(archive::inspect(&path).is_err());
    std::fs::remove_file(path.join("witness/unexpected")).unwrap();
    let witness = path
        .join("witness")
        .join(siworld_node::orders::Checkpoint::filename(0));
    let bytes = std::fs::read(&witness).unwrap();
    std::fs::remove_file(&witness).unwrap();
    assert!(archive::inspect(&path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let outside = t.0.join("outside");
        std::fs::write(&outside, &bytes).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, &witness).unwrap();
        assert!(archive::inspect(&path).is_err());
    }
}
#[test]
fn signed_receipts_bind_bytes_identity_challenge_previous_and_pinned_key() {
    let t = Temp::new();
    let mut l = ledger(&t);
    let key = signer(&t);
    let vk = *key.verifying_key();
    let path = t.0.join("a1");
    let m = l.archive(&path, None).unwrap();
    let receiver = t.0.join("receiver");
    let mut r = Retainer::create(&receiver, &key, &m.checkpoint).unwrap();
    let q = Request::fresh(None).unwrap();
    let receipt = r.accept(&path, &q).unwrap();
    receipt.verify(&vk, &m, &q).unwrap();
    assert_eq!(r.accept(&path, &q).unwrap(), receipt); // Lost acknowledgement, no duplicate generation.
    let unrelated = Request::fresh(None).unwrap();
    assert!(receipt.verify(&vk, &m, &unrelated).is_err());
    let other = Temp::new();
    let wrong = signer(&other);
    assert!(receipt.verify(wrong.verifying_key(), &m, &q).is_err());
    let mut changed = serde_json::to_value(&receipt).unwrap();
    changed["body"]["archive_id"] = "ff".repeat(32).into();
    let changed: Receipt = serde_json::from_value(changed).unwrap();
    assert!(changed.verify(&vk, &m, &q).is_err());
    l.record(&order(1)).unwrap();
    let path2 = t.0.join("a2");
    let m2 = l.archive(&path2, None).unwrap();
    assert!(r.accept(&path2, &q).is_err());
    let q2 = Request::fresh(Some(receipt.id().unwrap())).unwrap();
    let receipt2 = r.accept(&path2, &q2).unwrap();
    receipt2.verify(&vk, &m2, &q2).unwrap();
    assert!(r.accept(&path, &q).is_err());
    let rollback = Request::fresh(Some(receipt2.id().unwrap())).unwrap();
    assert!(r.accept(&path, &rollback).is_err());
    let status_query = Request::fresh(Some(receipt.id().unwrap())).unwrap();
    let status = r.status(&status_query).unwrap();
    assert_eq!(status.verify(&vk, &status_query).unwrap(), receipt2);
    assert!(status.verify(&vk, &Request::fresh(None).unwrap()).is_err());
    let bad = Request::fresh(Some("ff".repeat(32))).unwrap();
    assert!(r.status(&bad).is_err());
    drop(r);
    assert!(Retainer::open(&receiver, &wrong).is_err());
    let mut reopened = Retainer::open(&receiver, &key).unwrap();
    assert_eq!(
        reopened
            .status(&status_query)
            .unwrap()
            .verify(&vk, &status_query)
            .unwrap(),
        receipt2
    );
    let stored = receiver.join("entry-0000000000000001/archive/ledger/orders.enc");
    std::fs::write(stored, b"damaged").unwrap();
    assert!(reopened.status(&status_query).is_err());
}
#[test]
fn archive_previous_prefix_and_receiver_fork_checks_fail_without_publication() {
    let t = Temp::new();
    let mut l = ledger(&t);
    let path = t.0.join("a");
    let m = l.archive(&path, None).unwrap();
    let pin = t.0.join("pin.json");
    m.checkpoint.save_new(&pin).unwrap();
    l.record(&order(1)).unwrap();
    let good = t.0.join("good");
    l.archive(&good, Some(&pin)).unwrap();
    let mut bad = m.checkpoint.clone();
    bad.head = "ee".repeat(32);
    let badpin = t.0.join("badpin");
    bad.save_new(&badpin).unwrap();
    let rejected = t.0.join("rejected");
    assert!(l.archive(&rejected, Some(&badpin)).is_err());
    assert!(!rejected.exists());
    let key = signer(&t);
    let mut r = Retainer::create(&t.0.join("receiver"), &key, &m.checkpoint).unwrap();
    let foreign = Temp::new();
    let other = ledger(&foreign);
    let otherpath = foreign.0.join("archive");
    other.archive(&otherpath, None).unwrap();
    assert!(r
        .accept(&otherpath, &Request::fresh(None).unwrap())
        .is_err());
    assert!(!t.0.join("receiver/entry-0000000000000001").exists());
}
#[test]
fn offline_cli_archive_retention_status_and_restore_roundtrip() {
    use std::process::Command;
    let t = Temp::new();
    let l = ledger(&t);
    let cp = l.checkpoint().unwrap();
    drop(l);
    siworld_node::secrets::write_secret(&t.0.join("password"), PASSWORD).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .current_dir(&t.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    run(&[
        "orders-archive",
        "--order-ledger",
        "ledger",
        "--order-witness",
        "witness",
        "--ledger-password-file",
        "password",
        "--out",
        "archive",
    ]);
    run(&[
        "retention-keygen",
        "--out",
        "receiver.key",
        "--public-out",
        "receiver.pub",
        "--password-file",
        "password",
    ]);
    cp.save_new(&t.0.join("initial.json")).unwrap();
    run(&[
        "retention-init",
        "--root",
        "receiver",
        "--signer",
        "receiver.key",
        "--password-file",
        "password",
        "--checkpoint",
        "initial.json",
    ]);
    run(&["retention-request", "--out", "request.json"]);
    run(&[
        "retention-accept",
        "--root",
        "receiver",
        "--signer",
        "receiver.key",
        "--password-file",
        "password",
        "--archive",
        "archive",
        "--request",
        "request.json",
        "--out",
        "receipt.json",
    ]);
    let receipt = Receipt::read(&t.0.join("receipt.json")).unwrap();
    run(&[
        "retention-request",
        "--previous-receipt",
        "receipt.json",
        "--trusted-key",
        "receiver.pub",
        "--out",
        "query.json",
    ]);
    run(&[
        "retention-status",
        "--root",
        "receiver",
        "--signer",
        "receiver.key",
        "--password-file",
        "password",
        "--request",
        "query.json",
        "--out",
        "status.json",
    ]);
    let status = Status::read(&t.0.join("status.json")).unwrap();
    let query = Request::read(&t.0.join("query.json")).unwrap();
    assert_eq!(
        status
            .verify(
                &ReceiptSigner::load(&t.0.join("receiver.key"), PASSWORD)
                    .unwrap()
                    .verifying_key()
                    .to_owned(),
                &query
            )
            .unwrap(),
        receipt
    );
    run(&[
        "retention-verify",
        "--trusted-key",
        "receiver.pub",
        "--request",
        "query.json",
        "--status",
        "status.json",
        "--archive",
        "archive",
        "--out-checkpoint",
        "verified.json",
    ]);
    run(&[
        "orders-restore",
        "--archive",
        "archive",
        "--out",
        "restored",
        "--expected-ledger-checkpoint",
        "verified.json",
        "--ledger-password-file",
        "password",
    ]);
    assert_eq!(
        OrderLedger::open(
            &t.0.join("restored/ledger"),
            &t.0.join("restored/witness"),
            PASSWORD
        )
        .unwrap()
        .checkpoint()
        .unwrap(),
        cp
    );
}

#[test]
fn encrypted_signer_request_and_receiver_history_reject_damage_and_missing_prefixes() {
    let t = Temp::new();
    let key = signer(&t);
    let keypath = t.0.join("receiver.key");
    assert!(ReceiptSigner::load(&keypath, "incorrect").is_err());
    assert!(ReceiptSigner::generate_file(&keypath, PASSWORD).is_err());
    assert!(ReceiptSigner::generate_file(&t.0.join("short"), "short").is_err());
    assert!(!t.0.join("short").exists());
    let bytes = std::fs::read(&keypath).unwrap();
    assert_eq!(bytes.len(), 96);
    let mut damaged = bytes.clone();
    damaged[70] ^= 1;
    std::fs::write(&keypath, damaged).unwrap();
    assert!(ReceiptSigner::load(&keypath, PASSWORD).is_err());
    std::fs::write(&keypath, &bytes).unwrap();
    assert_eq!(
        ReceiptSigner::load(&keypath, PASSWORD)
            .unwrap()
            .verifying_key(),
        key.verifying_key()
    );
    let mut l = ledger(&t);
    let source = t.0.join("archive");
    let manifest = l.archive(&source, None).unwrap();
    let root = t.0.join("receiver");
    let mut r = Retainer::create(&root, &key, &manifest.checkpoint).unwrap();
    assert!(Retainer::open(&root, &key).is_err());
    let q = Request::fresh(None).unwrap();
    let a = r.accept(&source, &q).unwrap();
    l.record(&order(1)).unwrap();
    let newer = t.0.join("newer");
    l.archive(&newer, None).unwrap();
    let q2 = Request::fresh(Some(a.id().unwrap())).unwrap();
    r.accept(&newer, &q2).unwrap();
    drop(r);
    let entry = root.join("entry-0000000000000001");
    let hidden = t.0.join("preserved-first");
    std::fs::rename(&entry, &hidden).unwrap();
    assert!(Retainer::open(&root, &key).is_err());
    std::fs::rename(&hidden, &entry).unwrap();
    let receipt = entry.join("receipt.json");
    let original = std::fs::read(&receipt).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["signature"] = "00".repeat(siworld_core::params::SIGNATURE_LEN).into();
    std::fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(Retainer::open(&root, &key).is_err());
    std::fs::write(&receipt, &original).unwrap();
    let request = t.0.join("request.json");
    siworld_node::secrets::write_secret(
        &request,
        &format!(
            "{{\"version\":1,\"challenge\":\"{}\",\"previous_receipt\":null,\"extra\":true}}",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    assert!(Request::read(&request).is_err());
    std::fs::write(&request, "x".repeat(32769)).unwrap();
    assert!(Request::read(&request).is_err());
    // A newer separately held receipt detects rollback at the receiver too.
    let mut r = Retainer::open(&root, &key).unwrap();
    let query = Request::fresh(Some(a.id().unwrap())).unwrap();
    let b = r
        .status(&query)
        .unwrap()
        .verify(key.verifying_key(), &query)
        .unwrap();
    drop(r);
    let latest = root.join("entry-0000000000000002");
    let hold = t.0.join("preserved-second");
    std::fs::rename(&latest, &hold).unwrap();
    let mut rolled = Retainer::open(&root, &key).unwrap();
    assert!(rolled
        .status(&Request::fresh(Some(b.id().unwrap())).unwrap())
        .is_err());
    // Coordinated rollback remains a negative control when only an old pin survives.
    assert_eq!(
        rolled
            .status(&query)
            .unwrap()
            .verify(key.verifying_key(), &query)
            .unwrap(),
        a
    );
}

#[test]
fn receiver_configuration_is_authenticated_before_any_archive_is_accepted() {
    let t = Temp::new();
    let l = ledger(&t);
    let key = signer(&t);
    let root = t.0.join("receiver");
    Retainer::create(&root, &key, &l.checkpoint().unwrap()).unwrap();
    let config = root.join("config.json");
    let original = std::fs::read(&config).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    // Preserve every other field and alter the identity even with no receipts.
    value["body"]["initial"]["head"] = "ff".repeat(32).into();
    std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(Retainer::open(&root, &key).is_err());
    std::fs::write(&config, &original).unwrap();
    assert!(Retainer::open(&root, &key).is_ok());
}
