//! Offline fund snapshots, independent freshness and real verified-chain recovery.
use siworld_circuits::MockProver;
use siworld_core::{Block, DevAccount, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::{
    address::encode_address,
    fund_keys::{FundGrant, FundKeystore},
    fund_payments::{backup, initialize, PayoutId},
    genesis::{DevFundFile, Genesis, GenesisFile, ProofsFile},
    node::Node,
    PayoutRefused,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
const PASSWORD: &str = "temporary fund full recovery password";
struct Fixture {
    root: PathBuf,
    key: PathBuf,
    witness: PathBuf,
    genesis: Genesis,
    blocks: Vec<Block>,
}
impl Fixture {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "si-fund-full-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let fund = root.join("fund");
        std::fs::create_dir(&fund).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fund, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = fund.join("key");
        let store = FundKeystore::seal(&Digest([8; 32]), PASSWORD).unwrap();
        store.save_new(&key).unwrap();
        let keys = store.open(PASSWORD).unwrap().verifying_keys();
        let genesis = Genesis::from_file(&GenesisFile {
            network: "fund-full-test".into(),
            timestamp: 1000,
            block_time: 1,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: ProofsFile::Mock,
            dev_fund: Some(DevFundFile {
                direct: siworld_node::genesis::hex_bytes(&keys.direct),
                lock: siworld_node::genesis::hex_bytes(&keys.lock),
            }),
            allocations: vec![],
        })
        .unwrap();
        initialize(&fund.join("payouts"), &store, PASSWORD, &genesis).unwrap();
        let witness = root.join("witness");
        backup::enable_witness(&key, &witness, PASSWORD, &genesis).unwrap();
        let mut f = Self {
            root,
            key,
            witness,
            genesis,
            blocks: vec![],
        };
        let mut n = f.chain();
        for h in 1..=101 {
            let mut b = n.template(1000 + h).unwrap();
            assert!(siworld_consensus::mine(&mut b.header, 1));
            n.accept(&b).unwrap();
            f.blocks.push(b);
        }
        f
    }
    fn chain(&self) -> Node {
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
        n
    }
    fn open(&self, key: &Path) -> Node {
        let mut n = self.chain();
        n.protect_dev_fund_witnessed(
            FundKeystore::load(key).unwrap(),
            PASSWORD,
            &key.parent().unwrap().join("payouts"),
            &self.witness,
        )
        .unwrap();
        n
    }
    fn grant(&self, n: &mut Node) {
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
                genesis: siworld_node::hex(&self.genesis.id),
                seconds: 3600,
                direct_sip: "0.0004".into(),
                lock_sip: "0".into(),
                max_payout_sip: "0.0002".into(),
                recipients: vec![encode_address(&recipient())],
                approval: None,
            },
        )
        .unwrap();
    }
    fn pin(&self, name: &str) -> PathBuf {
        let p = self.root.join(name);
        backup::export_checkpoint(&self.key, &self.witness, PASSWORD, &self.genesis, &p, None)
            .unwrap();
        p
    }
    fn snapshot(&self, name: &str) -> PathBuf {
        let p = self.root.join(name);
        backup::create(&self.key, &self.witness, PASSWORD, &self.genesis, &p).unwrap();
        p
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn recipient() -> siworld_crypto::Address {
    SpendKey::from_digest(Digest([3; 32])).address()
}
fn id(i: u8) -> PayoutId {
    PayoutId::parse(&format!("{i:02x}").repeat(32)).unwrap()
}

#[test]
fn independent_approval_and_budget_revision_preserve_spending_and_reject_stale_authority() {
    use siworld_node::{fund_approval::ApprovalSigner, fund_payments::governance::GovernanceFiles};
    let f = Fixture::new();
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    let audit = n.fund_approvals(0, 16).unwrap();
    let mut grant = audit.approvals[0].grant.clone();
    let policy = audit.policy.unwrap();
    n.payout(id(1), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    drop(n);
    let before = f.snapshot("unsigned.full");
    let approver = f.root.join("approver");
    std::fs::create_dir(&approver).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&approver, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let signer = ApprovalSigner::generate_file(&approver.join("approval.key"), PASSWORD).unwrap();
    let trusted = signer.verifying_key();
    let pin = f.pin("enroll.json");
    let files = GovernanceFiles {
        key: &f.key,
        witness: &f.witness,
        checkpoint: &pin,
    };
    let request = files
        .propose(
            PASSWORD,
            &f.genesis,
            &policy,
            Some(&trusted),
            "Separate approval custody",
        )
        .unwrap();
    let signed = signer.approve_change(&request).unwrap();
    assert!(
        !files
            .apply(PASSWORD, &f.genesis, &signed, Some(&trusted), false)
            .unwrap()
            .committed
    );
    assert!(
        files
            .apply(PASSWORD, &f.genesis, &signed, Some(&trusted), true)
            .unwrap()
            .committed
    );
    let mut n = f.open(&f.key);
    grant.approval_id = id(20).to_string();
    assert!(n.unlock_fund(PASSWORD, &grant).is_err());
    let context = n.fund_approvals(0, 16).unwrap().signing_context.unwrap();
    let approved = signer.approve_grant(&grant, &context).unwrap();
    n.unlock_fund(PASSWORD, &approved).unwrap();
    n.payout(id(2), DevAccount::Direct, &recipient(), 10_000)
        .unwrap();
    assert_eq!(n.fund_approvals(0, 16).unwrap().reserved_atoms, [30_000, 0]);
    drop(n);
    let pin = f.pin("revision.json");
    let files = GovernanceFiles {
        key: &f.key,
        witness: &f.witness,
        checkpoint: &pin,
    };
    let mut revised = policy.clone();
    revised.direct_sip = "0.0004".into();
    revised.lock_sip = "0".into();
    revised.total_sip = "0.0004".into();
    revised.max_payout_sip = "0.0002".into();
    let proposal = files
        .propose(
            PASSWORD,
            &f.genesis,
            &revised,
            None,
            "Bound remaining authorized expenditure",
        )
        .unwrap();
    let signed = signer.approve_change(&proposal).unwrap();
    assert!(
        files
            .apply(PASSWORD, &f.genesis, &signed, None, true)
            .unwrap()
            .committed
    );
    let mut n = f.open(&f.key);
    let audit = n.fund_approvals(0, 16).unwrap();
    assert_eq!(audit.reserved_atoms, [30_000, 0]);
    assert_eq!(audit.total_remaining_atoms, Some(10_000));
    let context = audit.signing_context.unwrap();
    let mut stale = approved.clone();
    stale.approval_id = id(21).to_string();
    assert!(n.unlock_fund(PASSWORD, &stale).is_err());
    grant.approval_id = id(21).to_string();
    grant.budget = revised;
    n.unlock_fund(PASSWORD, &signer.approve_grant(&grant, &context).unwrap())
        .unwrap();
    n.payout(id(3), DevAccount::Direct, &recipient(), 10_000)
        .unwrap();
    assert_eq!(
        n.payout(id(4), DevAccount::Direct, &recipient(), 10_000),
        Err(PayoutRefused::Authorization)
    );
    drop(n);
    let pin = f.pin("restore-signed.json");
    let out = f.root.join("restored-signed");
    backup::restore(&before, &out, PASSWORD, &f.witness, &pin).unwrap();
    let mut n = f.open(&out.join("key"));
    let audit = n.fund_approvals(0, 16).unwrap();
    assert_eq!(audit.reserved_atoms, [40_000, 0]);
    assert_eq!(audit.signing_context.unwrap().revision, 1);
    assert!(n.fund_recovery_required());
}
#[test]
fn stale_snapshot_recovers_latest_original_artifacts_but_never_signs_before_review() {
    let f = Fixture::new();
    let old = f.snapshot("old.full");
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    let p = n
        .payout(id(1), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    let before = n.fund_approvals(0, 16).unwrap();
    drop(n);
    let pin = f.pin("current.json");
    let dest = f.root.join("restored");
    let info = backup::restore(&old, &dest, PASSWORD, &f.witness, &pin).unwrap();
    assert_eq!(info.records, 1);
    let mut r = f.open(&dest.join("key"));
    let recovered = r.fund_approvals(0, 16).unwrap();
    assert_eq!(recovered.reserved_atoms, before.reserved_atoms);
    assert_eq!(recovered.approval_count, before.approval_count);
    assert_eq!(
        recovered.approvals[0].grant_hash,
        before.approvals[0].grant_hash
    );
    assert!(recovered.active_approval_id.is_none());
    assert!(r.fund_recovery_required());
    assert!(r.template(1102).unwrap().body.payouts.is_empty());
    assert_eq!(
        r.payout(id(1), DevAccount::Direct, &recipient(), 20_000),
        Err(PayoutRefused::RecoveryRequired)
    );
    assert!(r
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
                seconds: 3600,
                direct_sip: "0.0004".into(),
                lock_sip: "0".into(),
                max_payout_sip: "0.0002".into(),
                recipients: vec![encode_address(&recipient())],
                approval: None,
            }
        )
        .is_err());
    let tip = r.tip();
    let height = r.height();
    assert!(r
        .reconcile_fund(PASSWORD, height + 1, tip, &pin, true)
        .is_err());
    assert!(
        !r.reconcile_fund(PASSWORD, height, tip, &pin, false)
            .unwrap()
            .committed
    );
    assert!(r.fund_recovery_required());
    assert!(
        r.reconcile_fund(PASSWORD, height, tip, &pin, true)
            .unwrap()
            .committed
    );
    assert!(r.fund_status().locked);
    assert!(!r.fund_recovery_required());
    assert!(r.unlock_fund(PASSWORD, &before.approvals[0].grant).is_err());
    assert_eq!(
        r.payout(id(1), DevAccount::Direct, &recipient(), 20_000)
            .unwrap(),
        p
    );
    assert_eq!(r.template(1102).unwrap().body.payouts, vec![p]);
    drop(r);
    let mut r = f.open(&dest.join("key"));
    assert!(!r.fund_recovery_required());
    assert_eq!(
        r.payout(id(1), DevAccount::Direct, &recipient(), 20_000)
            .unwrap(),
        p
    );
    // The original source is now behind the independently advanced witness.
    let mut old = f.chain();
    assert!(old
        .protect_dev_fund_witnessed(
            FundKeystore::load(&f.key).unwrap(),
            PASSWORD,
            &f.key.parent().unwrap().join("payouts"),
            &f.witness
        )
        .is_err());
}
#[test]
fn stale_pin_wrong_password_corruption_and_nested_checkpoint_never_publish_restore() {
    let f = Fixture::new();
    let snap = f.snapshot("saved.full");
    let oldpin = f.pin("old.json");
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    n.payout(id(2), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    drop(n);
    let pin = f.pin("latest.json");
    let dest = f.root.join("restore");
    assert!(backup::restore(&snap, &dest, PASSWORD, &f.witness, &oldpin).is_err());
    assert!(!dest.exists());
    assert!(backup::restore(&snap, &dest, "incorrect password", &f.witness, &pin).is_err());
    assert!(!dest.exists());
    let nested = f.witness.join("copied-pin.json");
    std::fs::copy(&pin, &nested).unwrap();
    assert!(backup::restore(&snap, &dest, PASSWORD, &f.witness, &nested).is_err());
    assert!(!dest.exists());
    let mut bytes = std::fs::read(&snap).unwrap();
    let k = bytes.len() - 1;
    bytes[k] ^= 1;
    std::fs::write(&snap, bytes).unwrap();
    assert!(backup::restore(&snap, &dest, PASSWORD, &f.witness, &pin).is_err());
    assert!(!dest.exists());
}
#[test]
fn missing_or_rolled_back_witness_cannot_be_omitted_on_startup() {
    let f = Fixture::new();
    let mut n = f.chain();
    assert!(n
        .protect_dev_fund(
            FundKeystore::load(&f.key).unwrap(),
            PASSWORD,
            &f.key.parent().unwrap().join("payouts")
        )
        .is_err());
    let pin = f.pin("before.json");
    let cp: backup::Checkpoint = serde_json::from_slice(&std::fs::read(pin).unwrap()).unwrap();
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    n.payout(id(3), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    drop(n);
    for e in std::fs::read_dir(&f.witness).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("generation-") {
            let sequence = u64::from_str_radix(
                name.split('-').nth(1).unwrap().split('.').next().unwrap(),
                16,
            )
            .unwrap();
            if sequence > cp.sequence {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
    }
    let mut n = f.chain();
    assert!(n
        .protect_dev_fund_witnessed(
            FundKeystore::load(&f.key).unwrap(),
            PASSWORD,
            &f.key.parent().unwrap().join("payouts"),
            &f.witness
        )
        .is_err());
}
#[test]
fn live_ownership_and_backup_outputs_are_exclusive_and_checkpoint_pins_are_immutable() {
    let f = Fixture::new();
    let n = f.open(&f.key);
    let output = f.root.join("busy.full");
    assert!(backup::create(&f.key, &f.witness, PASSWORD, &f.genesis, &output).is_err());
    assert!(!output.exists());
    drop(n);
    let snap = f.snapshot("good.full");
    assert!(backup::create(&f.key, &f.witness, PASSWORD, &f.genesis, &snap).is_err());
    let pin = f.pin("pin.json");
    assert!(
        backup::export_checkpoint(&f.key, &f.witness, PASSWORD, &f.genesis, &pin, None).is_err()
    );
    let nested = f.key.parent().unwrap().join("pin.json");
    assert!(
        backup::export_checkpoint(&f.key, &f.witness, PASSWORD, &f.genesis, &nested, None).is_err()
    );
    let dest = f.root.join("exists");
    std::fs::create_dir(&dest).unwrap();
    assert!(backup::restore(&snap, &dest, PASSWORD, &f.witness, &pin).is_err());
}

#[test]
fn included_original_payouts_are_reconciled_without_requeue_and_conflicting_counters_stay_gated() {
    let mut f = Fixture::new();
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    let p = n
        .payout(id(4), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    let mut block = n.template(1102).unwrap();
    assert!(siworld_consensus::mine(&mut block.header, 1));
    n.accept(&block).unwrap();
    drop(n);
    let snapshot = f.snapshot("included.full");
    let pin = f.pin("included-pin.json");
    f.blocks.push(block);
    let dest = f.root.join("included-restore");
    backup::restore(&snapshot, &dest, PASSWORD, &f.witness, &pin).unwrap();
    let mut n = f.open(&dest.join("key"));
    let h = n.height();
    let tip = n.tip();
    n.reconcile_fund(PASSWORD, h, tip, &pin, true).unwrap();
    assert_eq!(n.fund_payout_status(id(4)).unwrap().state, "included");
    assert!(n.template(1103).unwrap().body.payouts.is_empty());
    assert_eq!(
        n.payout(id(4), DevAccount::Direct, &recipient(), 20_000)
            .unwrap(),
        p
    );
    drop(n);
    // A competing, valid same-counter signature must never release recovery.
    f.blocks.pop();
    let mut fork = f.chain();
    let signer = FundKeystore::load(&f.key).unwrap().open(PASSWORD).unwrap();
    let mut q = siworld_node::devfund::PayoutQueue::default();
    let competing = q
        .queue(
            &signer,
            &fork.chain.params.chain_id,
            fork.dev_fund(),
            DevAccount::Direct,
            recipient().owner(),
            10_000,
            Digest([1; 32]),
            &Digest([2; 32]),
        )
        .unwrap();
    let mut block = siworld_consensus::build_unsealed(
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
        1102,
    )
    .unwrap();
    assert!(siworld_consensus::mine(&mut block.header, 1));
    fork.accept(&block).unwrap();
    f.blocks.push(block);
    // The first successful reconciliation advanced the witness; export its current pin.
    let pin = f.root.join("advanced.json");
    backup::export_checkpoint(
        &dest.join("key"),
        &f.witness,
        PASSWORD,
        &f.genesis,
        &pin,
        None,
    )
    .unwrap();
    let other = f.root.join("conflict-restore");
    backup::restore(&snapshot, &other, PASSWORD, &f.witness, &pin).unwrap();
    let mut n = f.open(&other.join("key"));
    let h = n.height();
    let tip = n.tip();
    assert!(n.reconcile_fund(PASSWORD, h, tip, &pin, true).is_err());
    assert!(n.fund_recovery_required());
    assert!(n.template(1103).unwrap().body.payouts.is_empty());
}

#[test]
fn cli_full_snapshot_checkpoint_and_atomic_restore_roundtrip() {
    let f = Fixture::new();
    let genesis = f.root.join("genesis.json");
    std::fs::write(&genesis, f.genesis.to_json()).unwrap();
    let password = f.root.join("password");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(&password)
        .unwrap()
        .write_all(PASSWORD.as_bytes())
        .unwrap();
    let binary = env!("CARGO_BIN_EXE_siworld-node");
    let invoke = |command: &str, args: &[&Path]| {
        let mut cmd = std::process::Command::new(binary);
        cmd.arg(command).arg("--password-file").arg(&password);
        for pair in args.as_chunks::<2>().0 {
            cmd.arg(pair[0]).arg(pair[1]);
        }
        cmd.output().unwrap()
    };
    let snap = f.root.join("cli.full");
    let out = invoke(
        "devfund-backup-full",
        &[
            Path::new("--key"),
            &f.key,
            Path::new("--genesis"),
            &genesis,
            Path::new("--fund-witness"),
            &f.witness,
            Path::new("--out"),
            &snap,
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = invoke("devfund-check-full", &[Path::new("--backup"), &snap]);
    assert!(out.status.success());
    let pin = f.root.join("cli-pin.json");
    let out = invoke(
        "devfund-checkpoint",
        &[
            Path::new("--key"),
            &f.key,
            Path::new("--genesis"),
            &genesis,
            Path::new("--fund-witness"),
            &f.witness,
            Path::new("--out"),
            &pin,
        ],
    );
    assert!(out.status.success());
    let dest = f.root.join("cli-restore");
    let out = invoke(
        "devfund-restore-full",
        &[
            Path::new("--backup"),
            &snap,
            Path::new("--fund-witness"),
            &f.witness,
            Path::new("--expected-fund-checkpoint"),
            &pin,
            Path::new("--out"),
            &dest,
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(f.open(&dest.join("key")).fund_recovery_required());
    #[cfg(feature = "development")]
    {
        let node_dir = f.root.join("node");
        std::fs::create_dir(&node_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&node_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut blocks =
            siworld_storage::BlockStore::open(&node_dir.join("blocks.redb"), &f.genesis.id)
                .unwrap();
        for b in &f.blocks {
            blocks.append(b).unwrap();
        }
        drop(blocks);
        let chain = f.chain();
        let tip = siworld_node::hex(&chain.tip());
        let height = chain.height().to_string();
        let args = [
            Path::new("--key"),
            &dest.join("key"),
            Path::new("--genesis"),
            &genesis,
            Path::new("--fund-witness"),
            &f.witness,
            Path::new("--expected-fund-checkpoint"),
            &pin,
            Path::new("--datadir"),
            &node_dir,
            Path::new("--expected-height"),
            Path::new(&height),
            Path::new("--expected-tip"),
            Path::new(&tip),
        ];
        let out = invoke("devfund-reconcile", &args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(f.open(&dest.join("key")).fund_recovery_required());
        let mut cmd = std::process::Command::new(binary);
        cmd.arg("devfund-reconcile")
            .arg("--password-file")
            .arg(&password)
            .arg("--commit");
        for pair in args.as_chunks::<2>().0 {
            cmd.arg(pair[0]).arg(pair[1]);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!f.open(&dest.join("key")).fund_recovery_required());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = f.root.join("witness-alias");
        symlink(&f.witness, &alias).unwrap();
        let nested = alias.join("pin.json");
        assert!(
            backup::export_checkpoint(&f.key, &f.witness, PASSWORD, &f.genesis, &nested, None)
                .is_err()
        );
    }
}

#[test]
fn copied_independent_witness_restores_after_original_custody_and_witness_are_lost() {
    let f = Fixture::new();
    let mut n = f.open(&f.key);
    f.grant(&mut n);
    let original = n
        .payout(id(7), DevAccount::Direct, &recipient(), 20_000)
        .unwrap();
    drop(n);
    let snapshot = f.snapshot("portable.full");
    let pin = f.pin("independent-pin.json");
    let copy = f.root.join("copied-witness");
    std::fs::create_dir(&copy).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for entry in std::fs::read_dir(&f.witness).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() != ".wallet.lock" {
            std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
        }
    }
    std::fs::remove_dir_all(f.key.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&f.witness).unwrap();
    let dest = f.root.join("from-copied-domain");
    backup::restore(&snapshot, &dest, PASSWORD, &copy, &pin).unwrap();
    let mut n = f.chain();
    n.protect_dev_fund_witnessed(
        FundKeystore::load(&dest.join("key")).unwrap(),
        PASSWORD,
        &dest.join("payouts"),
        &copy,
    )
    .unwrap();
    let h = n.height();
    let tip = n.tip();
    n.reconcile_fund(PASSWORD, h, tip, &pin, true).unwrap();
    assert_eq!(
        n.payout(id(7), DevAccount::Direct, &recipient(), 20_000)
            .unwrap(),
        original
    );
    assert!(n.fund_status().locked);
}
