//! Durable intent/transaction ordering and retry/reorganization regressions.
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use siworld_circuits::MockProver;
use siworld_consensus::{mine, PendingTx};
use siworld_core::Digest;
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::keystore::Keystore;
use siworld_node::node::Node;
use siworld_node::payments::{PaymentId, PaymentState};
use siworld_node::wire::encode_tx;
use siworld_node::{hex, PayError};
use siworld_storage::BlockStore;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-payments-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
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
    let mut genesis = Genesis::from_file(&GenesisFile {
        network: "payments-test".into(),
        timestamp: 1000,
        block_time: 1,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap();
    // A small window exercises reversible anchor loss and conservative release.
    genesis.params.anchor_window = 4;
    genesis
}
fn open(dir: &Path) -> Node {
    let genesis = genesis();
    let store = BlockStore::open(&dir.join("blocks.redb"), &genesis.id).unwrap();
    let mut node = Node::open(
        genesis,
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        Some(store),
        Arc::new(MockProver),
    )
    .unwrap();
    node.enable_payment_journal(&dir.join("payments.redb"))
        .unwrap();
    node
}
fn mine_one(node: &mut Node) -> siworld_core::Block {
    let mut block = node.template(1001 + node.height()).unwrap();
    assert!(mine(&mut block.header, 1));
    node.accept(&block).unwrap();
    block
}
fn send(node: &mut Node, i: u8) -> PendingTx {
    node.pay_with_id(id(i), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .unwrap()
}
#[test]
fn retry_after_lost_reply_or_restart_uses_identical_transaction_and_reservation() {
    let dir = Temp::new();
    let original = {
        let mut node = open(&dir.0);
        let first = send(&mut node, 1);
        let retry = send(&mut node, 1);
        assert_eq!(encode_tx(&first), encode_tx(&retry));
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.balance().unwrap().spendable, 0);
        assert!(node
            .pay_with_id(id(2), &key(2).address(), 10_000_000, false)
            .is_err());
        first
    };
    let mut node = open(&dir.0);
    assert_eq!(node.balance().unwrap().spendable, 0);
    let retry = send(&mut node, 1);
    assert_eq!(encode_tx(&original), encode_tx(&retry));
    assert_eq!(node.mempool.len(), 1);
    assert_eq!(node.payment(id(1)).unwrap().state, PaymentState::Pending);
    assert!(matches!(
        node.pay(&key(2).address(), 10_000_000, false),
        Err(PayError::DurablePaymentRequired)
    ));
}
#[test]
fn payment_id_conflicts_bind_amount_recipient_and_priority() {
    let dir = Temp::new();
    let mut node = open(&dir.0);
    let tx = send(&mut node, 1);
    for (to, amount, priority) in [
        (key(3).address(), 10_000_000, false),
        (key(2).address(), 20_000_000, false),
        (key(2).address(), 10_000_000, true),
    ] {
        let error = node
            .pay_with_id(id(1), &to, amount, priority)
            .err()
            .unwrap();
        assert_eq!(error.code(), "payment_id_conflict");
    }
    assert_eq!(encode_tx(&send(&mut node, 1)), encode_tx(&tx));
    assert_eq!(node.mempool.len(), 1);
}
#[test]
fn eviction_cannot_release_a_durable_input_and_confirmed_retry_cannot_repay() {
    let dir = Temp::new();
    let mut node = open(&dir.0);
    let tx = send(&mut node, 1);
    node.mempool.remove_slot(&tx.slot.id()).unwrap();
    node.wallets.release(&tx.slot);
    assert_eq!(node.balance().unwrap().spendable, 0);
    assert!(node
        .pay_with_id(id(2), &key(2).address(), 10_000_000, false)
        .is_err());
    send(&mut node, 1);
    mine_one(&mut node);
    let receipt = node.payment(id(1)).unwrap();
    assert_eq!(receipt.state, PaymentState::Confirmed);
    assert_eq!(receipt.confirmed_height, Some(1));
    assert!(node
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .is_none());
    assert!(node.mempool.is_empty());
    drop(node);
    assert_eq!(open(&dir.0).payment(id(1)).unwrap(), receipt);
}
#[test]
fn confirmed_payment_reorgs_to_original_pending_bytes_and_survives_locking() {
    let dir = Temp::new();
    let mut node = open(&dir.0);
    let tx = send(&mut node, 1);
    mine_one(&mut node);
    let mut peer = Node::open(
        genesis(),
        key(3),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    let password = "durable wallet test password";
    node.protect_wallet(Keystore::seal(&key(1), password).unwrap())
        .unwrap();
    for _ in 0..3 {
        let block = mine_one(&mut peer);
        node.accept(&block).unwrap();
    }
    assert!(node.payment(id(1)).is_err());
    node.unlock_wallet(password, 60).unwrap();
    assert_eq!(node.payment(id(1)).unwrap().state, PaymentState::Pending);
    assert_eq!(node.balance().unwrap().spendable, 0);
    assert_eq!(encode_tx(&send(&mut node, 1)), encode_tx(&tx));
    drop(node);
    assert_eq!(encode_tx(&send(&mut open(&dir.0), 1)), encode_tx(&tx));
}
#[test]
fn expired_anchor_keeps_inputs_until_it_cannot_return_within_reorg_bound() {
    let dir = Temp::new();
    let mut node = open(&dir.0);
    let tx = send(&mut node, 1);
    node.mempool.remove_slot(&tx.slot.id()).unwrap();
    for _ in 0..4 {
        mine_one(&mut node);
    }
    assert_eq!(
        node.payment(id(1)).unwrap().state,
        PaymentState::AnchorUnavailable
    );
    assert_eq!(node.balance().unwrap().spendable, 0);
    assert!(node
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .is_none());
    for _ in 0..101 {
        mine_one(&mut node);
    }
    assert_eq!(node.payment(id(1)).unwrap().state, PaymentState::Expired);
    assert!(node.balance().unwrap().spendable >= 100 * 100_000_000);
    assert!(node
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .is_none());
    send(&mut node, 2);
}
#[test]
fn journal_refuses_wrong_wallet_network_and_symlink_alias() {
    let dir = Temp::new();
    {
        let mut node = open(&dir.0);
        send(&mut node, 1);
    }
    let mut wrong = Node::open(
        genesis(),
        key(3),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    assert!(wrong
        .enable_payment_journal(&dir.0.join("payments.redb"))
        .is_err());
    let mut other = genesis();
    other.id = Digest([8; 32]);
    let mut wrong = Node::open(
        other,
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    assert!(wrong
        .enable_payment_journal(&dir.0.join("payments.redb"))
        .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = dir.0.join("alias.redb");
        symlink(dir.0.join("payments.redb"), &alias).unwrap();
        let mut node = Node::open(
            genesis(),
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        assert!(node.enable_payment_journal(&alias).is_err());
    }
}
#[test]
fn ids_are_fixed_length_client_values_with_canonical_display() {
    assert!(PaymentId::parse("").is_err());
    assert!(PaymentId::parse("invoice-1").is_err());
    assert!(PaymentId::parse(&"1".repeat(63)).is_err());
    let text = "AB".repeat(32);
    assert_eq!(
        PaymentId::parse(&text).unwrap().to_string(),
        text.to_lowercase()
    );
}

#[test]
fn missing_or_empty_initialized_journal_cannot_silently_forget_payments() {
    for empty in [false, true] {
        let dir = Temp::new();
        {
            let mut node = open(&dir.0);
            send(&mut node, 1);
        }
        let path = dir.0.join("payments.redb");
        if empty {
            std::fs::write(&path, []).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        let mut node = Node::open(
            genesis(),
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        assert!(node.enable_payment_journal(&path).is_err());
    }
}

struct ExitProver {
    mode: u8,
    calls: Arc<AtomicU64>,
}
impl siworld_circuits::ProofSystem for ExitProver {
    fn prove_slot(
        &self,
        ctx: &siworld_circuits::RelationContext,
        w: &siworld_circuits::SlotWitness,
        b: Digest,
    ) -> Result<
        (
            siworld_core::Slot,
            siworld_circuits::SlotProof,
            siworld_circuits::FeeOpening,
        ),
        siworld_circuits::ProveError,
    > {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            0 => std::process::exit(71),
            1 => Err(siworld_circuits::ProveError::Prover("test failure".into())),
            _ => siworld_circuits::ProofSystem::prove_slot(&MockProver, ctx, w, b),
        }
    }
    fn verify_slot(
        &self,
        a: &siworld_state::RecentRoots,
        s: &siworld_core::Slot,
        p: &siworld_circuits::SlotProof,
        f: &siworld_circuits::FeeOpening,
    ) -> bool {
        siworld_circuits::ProofSystem::verify_slot(&MockProver, a, s, p, f)
    }
    fn prove_container(
        &self,
        a: &siworld_state::RecentRoots,
        h: u64,
        l: &[siworld_circuits::Leaf],
        n: &siworld_core::Note,
        s: u64,
    ) -> Result<siworld_core::ContainerProof, siworld_circuits::AggregateError> {
        siworld_circuits::ProofSystem::prove_container(&MockProver, a, h, l, n, s)
    }
    fn verify_container(
        &self,
        p: &siworld_circuits::ContainerPublic,
        b: &siworld_core::ContainerProof,
    ) -> bool {
        siworld_circuits::ProofSystem::verify_container(&MockProver, p, b)
    }
}
#[test]
fn crash_child() {
    // Faults exist only in the integration-test executable, never in the node.
    let Ok(dir) = std::env::var("SIWORLD_PAYMENT_CRASH_DIR") else {
        return;
    };
    let dir = Path::new(&dir);
    if std::env::var("SIWORLD_PAYMENT_CRASH_PHASE").unwrap() == "preparing" {
        let mut node = Node::open(
            genesis(),
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(ExitProver {
                mode: 0,
                calls: Arc::new(AtomicU64::new(0)),
            }),
        )
        .unwrap();
        node.enable_payment_journal(&dir.join("payments.redb"))
            .unwrap();
        send(&mut node, 1);
        panic!("prover should exit");
    }
    let mut node = open(dir);
    let tx = send(&mut node, 1);
    std::fs::write(dir.join("expected.bin"), encode_tx(&tx)).unwrap();
    std::process::exit(72);
}
#[test]
fn abrupt_exit_during_proof_or_after_durable_artifact_is_recoverable() {
    for (phase, exit) in [("preparing", 71), ("ready", 72)] {
        let dir = Temp::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--nocapture"])
            .env("SIWORLD_PAYMENT_CRASH_DIR", &dir.0)
            .env("SIWORLD_PAYMENT_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(exit));
        let mut node = open(&dir.0);
        if phase == "preparing" {
            assert_eq!(
                node.payment(id(1)).unwrap().state,
                PaymentState::Interrupted
            );
            assert_eq!(node.balance().unwrap().spendable, 100 * 100_000_000);
            assert!(node
                .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap()
                .relay
                .is_none());
            send(&mut node, 2);
        } else {
            assert_eq!(node.balance().unwrap().spendable, 0);
            assert_eq!(
                encode_tx(&send(&mut node, 1)),
                std::fs::read(dir.0.join("expected.bin")).unwrap()
            );
        }
    }
}

#[test]
fn successful_retries_prove_once_and_failed_builds_are_terminal_without_reservations() {
    for mode in [1, 2] {
        let dir = Temp::new();
        let calls = Arc::new(AtomicU64::new(0));
        let mut node = Node::open(
            genesis(),
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(ExitProver {
                mode,
                calls: calls.clone(),
            }),
        )
        .unwrap();
        node.enable_payment_journal(&dir.0.join("payments.redb"))
            .unwrap();
        let result = node.pay_with_id(id(1), &key(2).address(), 10_000_000, false);
        if mode == 1 {
            assert!(result.is_err());
            assert_eq!(node.payment(id(1)).unwrap().state, PaymentState::Failed);
            assert_eq!(node.balance().unwrap().spendable, 100 * 100_000_000);
        } else {
            assert!(result.unwrap().relay.is_some());
        }
        for _ in 0..4 {
            node.pay_with_id(id(1), &key(2).address(), 10_000_000, false)
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn rejected_admission_keeps_the_original_artifact_and_inputs() {
    let dir = Temp::new();
    let mut node = open(&dir.0);
    node.mempool = siworld_node::Mempool::new(0, 0, node.mempool.tx_pow(), Arc::new(MockProver));
    let result = node
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap();
    assert!(result.relay.is_none());
    assert!(result.relay_error.is_some());
    assert_eq!(node.balance().unwrap().spendable, 0);
    node.mempool = siworld_node::Mempool::new(10, 10, node.mempool.tx_pow(), Arc::new(MockProver));
    assert_eq!(
        send(&mut node, 1).slot.id(),
        result.receipt.slot_id.unwrap()
    );
}
#[test]
fn both_real_inputs_are_reserved_atomically_and_reconstructed() {
    let dir = Temp::new();
    let g = Genesis::from_file(&GenesisFile {
        network: "two-inputs".into(),
        timestamp: 1000,
        block_time: 1,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![
            AllocationFile {
                owner: hex(&key(1).owner()),
                amount: "1".into(),
            },
            AllocationFile {
                owner: hex(&key(1).owner()),
                amount: "1".into(),
            },
        ],
    })
    .unwrap();
    for restart in [false, true] {
        let mut node = Node::open(
            g.clone(),
            key(1),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        node.enable_payment_journal(&dir.0.join("payments.redb"))
            .unwrap();
        if !restart {
            node.pay_with_id(id(1), &key(2).address(), 150_000_000, false)
                .unwrap();
        }
        assert_eq!(node.balance().unwrap().spendable, 0);
        assert!(node
            .pay_with_id(id(2), &key(3).address(), 10_000_000, false)
            .is_err());
    }
}
#[test]
fn newer_journal_refuses_a_chain_rollback_beyond_local_finality() {
    let dir = Temp::new();
    {
        let mut node = open(&dir.0);
        send(&mut node, 1);
        for _ in 0..101 {
            mine_one(&mut node);
        }
    }
    let mut node = Node::open(
        genesis(),
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    assert_eq!(
        node.enable_payment_journal(&dir.0.join("payments.redb"))
            .unwrap_err()
            .code(),
        "payment_chain_rollback"
    );
    assert!(node
        .pay_with_id(id(2), &key(2).address(), 10_000_000, false)
        .is_err());
}

#[test]
fn another_slot_spending_the_same_input_is_conflict_not_confirmation() {
    let dir = Temp::new();
    let mut n = open(&dir.0);
    let tx = send(&mut n, 1);
    n.mempool.remove_slot(&tx.slot.id()).unwrap();
    let mut other = Node::open(
        genesis(),
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    other.pay(&key(3).address(), 20_000_000, false).unwrap();
    n.accept(&mine_one(&mut other)).unwrap();
    let receipt = n.payment(id(1)).unwrap();
    assert_eq!(receipt.state, PaymentState::Conflicted);
    assert_eq!(receipt.confirmed_height, None);
    assert!(n
        .pay_with_id(id(1), &key(2).address(), 10_000_000, false)
        .unwrap()
        .relay
        .is_none());
}
#[cfg(unix)]
#[test]
fn exclusive_journal_ownership_and_owner_only_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Temp::new();
    let n = open(&dir.0);
    let mut other = Node::open(
        genesis(),
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    assert!(other
        .enable_payment_journal(&dir.0.join("payments.redb"))
        .is_err());
    drop(n);
    std::fs::set_permissions(
        dir.0.join("payments.redb"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(other
        .enable_payment_journal(&dir.0.join("payments.redb"))
        .is_err());
}
