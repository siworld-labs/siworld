//! Durable fund requests use temporary keys and genuinely validated mock blocks.
use siworld_circuits::MockProver;
use siworld_consensus::mine;
use siworld_core::{Block, DevAccount, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::{
    address::encode_address,
    devfund::DevFundSigner,
    fund_keys::{FundGrant, FundKeystore},
    fund_payments::{initialize, PayoutId},
    genesis::{Genesis, GenesisFile, ProofsFile},
    node::Node,
    PayoutRefused,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
const PASSWORD: &str = "temporary durable fund test password";
struct Fixture {
    dir: PathBuf,
    genesis: Genesis,
    blocks: Vec<Block>,
    store: FundKeystore,
}
impl Fixture {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "si-fund-payments-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut genesis = Genesis::from_file(&GenesisFile {
            network: "fund-payments-test".into(),
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
        let store = FundKeystore::seal(&Digest([8; 32]), PASSWORD).unwrap();
        genesis.params.dev_fund_keys = Some(store.open(PASSWORD).unwrap().verifying_keys());
        initialize(&dir, &store, PASSWORD, &genesis).unwrap();
        let mut f = Self {
            dir,
            genesis,
            blocks: vec![],
            store,
        };
        let mut n = f.open(false);
        for h in 1..=101 {
            f.blocks.push(mine_one(&mut n, 1000 + h));
        }
        f
    }
    fn open(&self, protected: bool) -> Node {
        let mut n = Node::open(
            self.genesis.clone(),
            SpendKey::from_digest(Digest([1; 32])),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        for b in &self.blocks {
            n.accept(b).unwrap();
        }
        if protected {
            n.protect_dev_fund(self.store.clone(), PASSWORD, &self.dir)
                .unwrap();
        }
        n
    }
    fn unlock(&self, n: &mut Node) {
        n.unlock_fund(
            PASSWORD,
            &FundGrant {
                version: 2,
                approval_id: siworld_node::fund_payments::PayoutId::random()
                    .unwrap()
                    .to_string(),
                budget: siworld_node::fund_keys::FundBudget {
                    version: 1,
                    id: "ab".repeat(32),
                    direct_sip: "1000000000".into(),
                    lock_sip: "1000000000".into(),
                    total_sip: "2000000000".into(),
                    max_payout_sip: "1000000".into(),
                },
                genesis: siworld_node::hex(&n.genesis.id),
                seconds: 3600,
                direct_sip: "0.0004".into(),
                lock_sip: "0".into(),
                max_payout_sip: "0.0002".into(),
                recipients: vec![encode_address(&recipient(3)), encode_address(&recipient(4))],
                approval: None,
            },
        )
        .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn recipient(i: u8) -> siworld_crypto::Address {
    SpendKey::from_digest(Digest([i; 32])).address()
}
fn id(i: u8) -> PayoutId {
    PayoutId::parse(&format!("{i:02x}").repeat(32)).unwrap()
}
fn mine_one(n: &mut Node, t: u64) -> Block {
    let mut b = n.template(t).unwrap();
    assert!(mine(&mut b.header, 1));
    n.accept(&b).unwrap();
    b
}

fn cumulative_grant(n: &Node, approval: u8) -> FundGrant {
    serde_json::from_value(serde_json::json!({
        "version": 2, "genesis": siworld_node::hex(&n.genesis.id),
        "approval_id": format!("{approval:02x}").repeat(32), "seconds": 3600,
        "direct_si": "0.0004", "lock_si": "0", "max_payout_si": "0.0002",
        "recipients": [encode_address(&recipient(3)), encode_address(&recipient(4))],
        "budget": {"version": 1, "id": "ab".repeat(32), "direct_si": "0.0003",
            "lock_si": "0.0002", "total_si": "0.0003", "max_payout_si": "0.0002"}
    }))
    .unwrap()
}

#[test]
fn cumulative_budget_survives_sessions_restart_and_approval_replay() {
    let f = Fixture::new();
    let mut n = f.open(true);
    let first = cumulative_grant(&n, 1);
    n.unlock_fund(PASSWORD, &first).unwrap();
    let original = n
        .payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
        .unwrap();
    n.lock_fund();
    assert!(n.unlock_fund(PASSWORD, &first).is_err());
    let mut changed = serde_json::to_value(&first).unwrap();
    changed["direct_si"] = "0.0005".into();
    assert!(n
        .unlock_fund(PASSWORD, &serde_json::from_value(changed).unwrap())
        .is_err());
    drop(n);
    let mut n = f.open(true);
    assert!(n.unlock_fund(PASSWORD, &first).is_err());
    n.unlock_fund(PASSWORD, &cumulative_grant(&n, 2)).unwrap();
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
            .unwrap(),
        original
    );
    assert_eq!(
        n.payout(id(2), DevAccount::Direct, &recipient(3), 20_000),
        Err(PayoutRefused::Authorization)
    );
    n.payout(id(2), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    n.lock_fund();
    n.unlock_fund(PASSWORD, &cumulative_grant(&n, 3)).unwrap();
    assert_eq!(
        n.payout(id(3), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::Authorization)
    );
    let audit = n.fund_approvals(0, 2).unwrap();
    assert_eq!(audit.reserved_atoms, [30_000, 0]);
    assert_eq!(audit.total_remaining_atoms, Some(0));
    assert_eq!(audit.approval_count, 3);
    assert_eq!(audit.next_offset, Some(2));
    assert_eq!(audit.approvals[0].authorized_atoms, [20_000, 0]);
    assert_eq!(audit.approvals[1].authorized_atoms, [10_000, 0]);
    assert_eq!(n.fund_approvals(2, 2).unwrap().approvals.len(), 1);
    assert!(n.fund_approvals(4, 2).is_err());
    assert!(n.fund_approvals(0, 17).is_err());
    assert_eq!(
        n.fund_payout_status(id(1)).unwrap().approval_ids,
        vec![first.approval_id]
    );
}

#[test]
fn enrolled_budget_cannot_be_replaced_or_raised_by_a_new_approval() {
    let f = Fixture::new();
    let mut n = f.open(true);
    n.unlock_fund(PASSWORD, &cumulative_grant(&n, 1)).unwrap();
    n.lock_fund();
    for field in ["id", "direct_si", "total_si", "max_payout_si"] {
        let mut changed = serde_json::to_value(cumulative_grant(&n, 2)).unwrap();
        changed["budget"][field] = if field == "id" {
            "cd".repeat(32).into()
        } else {
            "10".into()
        };
        assert!(n
            .unlock_fund(PASSWORD, &serde_json::from_value(changed).unwrap())
            .is_err());
        assert!(n.fund_status().locked);
    }
    let mut old = serde_json::to_value(cumulative_grant(&n, 2)).unwrap();
    old["version"] = 1.into();
    assert!(n
        .unlock_fund(PASSWORD, &serde_json::from_value(old).unwrap())
        .is_err());
}

#[test]
fn combined_cumulative_limit_covers_both_accounts_and_reorg_does_not_refund() {
    let mut f = Fixture::new();
    let mut miner = f.open(false);
    for h in 102..=401 {
        f.blocks.push(mine_one(&mut miner, 1000 + h));
    }
    let mut n = f.open(true);
    let mut grant = cumulative_grant(&n, 1);
    grant.lock_sip = "0.0002".into();
    n.unlock_fund(PASSWORD, &grant).unwrap();
    n.payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
        .unwrap();
    n.payout(id(2), DevAccount::Lock, &recipient(3), 10_000)
        .unwrap();
    let before = n.fund_approvals(0, 16).unwrap();
    assert_eq!(before.reserved_atoms, [20_000, 10_000]);
    assert_eq!(
        n.payout(id(3), DevAccount::Lock, &recipient(3), 10_000),
        Err(PayoutRefused::Authorization)
    );
    mine_one(&mut n, 1402);
    let mut fork = f.open(false);
    for t in [1403, 1404] {
        n.accept(&mine_one(&mut fork, t)).unwrap();
    }
    assert_eq!(
        n.fund_approvals(0, 16).unwrap().reserved_atoms,
        before.reserved_atoms
    );
    assert_eq!(
        n.payout(id(3), DevAccount::Lock, &recipient(3), 10_000),
        Err(PayoutRefused::Authorization)
    );
}
#[test]
fn lost_reply_retry_and_locked_restart_preserve_exact_artifact_and_budget() {
    let f = Fixture::new();
    let mut n = f.open(true);
    f.unlock(&mut n);
    let a = n
        .payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
        .unwrap();
    for _ in 0..3 {
        assert_eq!(
            n.payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
                .unwrap(),
            a
        );
    }
    assert_eq!(n.fund_status().direct_remaining, 20_000);
    assert_eq!(n.template(1102).unwrap().body.payouts, vec![a]);
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(4), 20_000),
        Err(PayoutRefused::IdConflict)
    );
    assert_eq!(
        n.payout(id(1), DevAccount::Lock, &recipient(3), 20_000),
        Err(PayoutRefused::IdConflict)
    );
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::IdConflict)
    );
    drop(n);
    let mut n = f.open(true);
    assert!(n.fund_status().locked);
    assert_eq!(n.template(1102).unwrap().body.payouts, vec![a]);
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
            .unwrap(),
        a
    );
    assert_eq!(
        n.payout(id(2), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::Locked)
    );
    f.unlock(&mut n);
    let b = n
        .payout(id(2), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    assert_eq!((a.counter, b.counter), (0, 1));
    assert_eq!(n.fund_status().direct_remaining, 30_000);
    mine_one(&mut n, 1102);
    assert_eq!(n.fund_payout_status(id(1)).unwrap().state, "included");
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 20_000)
            .unwrap(),
        a
    );
    assert!(n.template(1103).unwrap().body.payouts.is_empty());
}
#[test]
fn reorg_restores_originals_and_competing_counter_never_resigns() {
    let f = Fixture::new();
    let mut n = f.open(true);
    f.unlock(&mut n);
    let a = n
        .payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    mine_one(&mut n, 1102);
    let mut fork = f.open(false);
    let b = mine_one(&mut fork, 1103);
    n.accept(&b).unwrap();
    let b = mine_one(&mut fork, 1104);
    n.accept(&b).unwrap();
    assert_eq!(n.fund_payout_status(id(1)).unwrap().state, "pending");
    assert_eq!(n.template(1105).unwrap().body.payouts, vec![a]);
    // A distinct valid signature at the same account counter wins on the fork.
    let signer = DevFundSigner::from_seed(&Digest([8; 32]));
    let mut q = siworld_node::devfund::PayoutQueue::default();
    let competing = q
        .queue(
            &signer,
            &fork.chain.params.chain_id,
            fork.dev_fund(),
            DevAccount::Direct,
            recipient(4).owner(),
            10_000,
            Digest([1; 32]),
            &Digest([2; 32]),
        )
        .unwrap();
    let mut b = fork.template(1105).unwrap();
    // Build a real block carrying the alternate payout through the shared builder.
    b = siworld_consensus::build_unsealed(
        &fork.chain.state,
        &fork.chain.state.anchors,
        &fork.chain.params,
        &MockProver,
        &siworld_consensus::Miner {
            address: fork.address(),
            committee_key: Digest([7; 32]),
        },
        &[],
        &[competing],
        &SecretSeed::from_os_rng().unwrap(),
        b.header.timestamp,
    )
    .unwrap();
    assert!(mine(&mut b.header, 1));
    n.accept(&b).unwrap();
    assert_eq!(n.fund_payout_status(id(1)).unwrap().state, "conflicted");
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
            .unwrap(),
        a
    );
    assert_eq!(
        n.payout(id(2), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::RecoveryRequired)
    );
    assert!(n.template(1106).unwrap().body.payouts.is_empty());
}
#[test]
fn journal_ownership_missing_files_corruption_and_chain_rollback_fail_closed() {
    let f = Fixture::new();
    let mut n = f.open(true);
    f.unlock(&mut n);
    n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    let mut other = f.open(false);
    assert!(other
        .protect_dev_fund(f.store.clone(), PASSWORD, &f.dir)
        .is_err());
    drop(n);
    let original = std::fs::read(f.dir.join("state")).unwrap();
    assert!(!original
        .windows(64)
        .any(|w| w == id(1).to_string().as_bytes()));
    std::fs::remove_file(f.dir.join("state")).unwrap();
    assert!(other
        .protect_dev_fund(f.store.clone(), PASSWORD, &f.dir)
        .is_err());
    siworld_node::secrets::write_secret_bytes(&f.dir.join("state"), &original).unwrap();
    let mut bad = original.clone();
    bad[40] ^= 1;
    std::fs::write(f.dir.join("state"), bad).unwrap();
    assert!(other
        .protect_dev_fund(f.store.clone(), PASSWORD, &f.dir)
        .is_err());
    std::fs::write(f.dir.join("state"), original).unwrap();
    let mut behind = Node::open(
        f.genesis.clone(),
        SpendKey::from_digest(Digest([1; 32])),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    behind
        .protect_dev_fund(f.store.clone(), PASSWORD, &f.dir)
        .unwrap();
    assert!(behind
        .unlock_fund(
            PASSWORD,
            &FundGrant {
                version: 2,
                approval_id: siworld_node::fund_payments::PayoutId::random()
                    .unwrap()
                    .to_string(),
                budget: siworld_node::fund_keys::FundBudget {
                    version: 1,
                    id: "ab".repeat(32),
                    direct_sip: "1000000000".into(),
                    lock_sip: "1000000000".into(),
                    total_sip: "2000000000".into(),
                    max_payout_sip: "1000000".into(),
                },
                genesis: siworld_node::hex(&f.genesis.id),
                seconds: 60,
                direct_sip: "1".into(),
                lock_sip: "0".into(),
                max_payout_sip: "1".into(),
                recipients: vec![encode_address(&recipient(3))],
                approval: None,
            }
        )
        .is_err());
    assert!(behind.template(1001).unwrap().body.payouts.is_empty());
}

#[test]
fn live_journal_replacement_locks_signer_and_password_rotation_preserves_history() {
    let f = Fixture::new();
    let mut n = f.open(true);
    f.unlock(&mut n);
    let original = n
        .payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    n.lock_fund();
    drop(n);
    let rotated_password = "new durable fund encryption password";
    let rotated = FundKeystore::seal(&Digest([8; 32]), rotated_password).unwrap();
    let mut n = f.open(false);
    n.protect_dev_fund(rotated, rotated_password, &f.dir)
        .unwrap();
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
            .unwrap(),
        original
    );
    let original_file = std::fs::read(f.dir.join("state")).unwrap();
    std::fs::remove_file(f.dir.join("state")).unwrap();
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::Journal)
    );
    assert!(n.fund_status().locked);
    siworld_node::secrets::write_secret_bytes(&f.dir.join("state"), &original_file).unwrap();
    assert_eq!(
        n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::Journal)
    );
}

#[test]
fn finalized_checkpoint_mismatch_prevents_requeue_and_new_signing() {
    let f = Fixture::new();
    let mut n = f.open(true);
    f.unlock(&mut n);
    n.payout(id(1), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    drop(n);
    let mut different = Node::open(
        f.genesis.clone(),
        SpendKey::from_digest(Digest([9; 32])),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    for h in 1..=101 {
        mine_one(&mut different, 2000 + h);
    }
    different
        .protect_dev_fund(f.store.clone(), PASSWORD, &f.dir)
        .unwrap();
    assert_eq!(
        different.fund_payout_status(id(1)).unwrap().state,
        "chain_sync_required"
    );
    assert!(different.template(2102).unwrap().body.payouts.is_empty());
}
