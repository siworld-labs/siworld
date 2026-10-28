//! Fund custody, bounded authorization and secret-lifetime regressions.
mod common;
use siworld_circuits::MockProver;
use siworld_consensus::mine;
use siworld_core::{DevAccount, Digest};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::address::encode_address;
use siworld_node::devfund::DevFundSigner;
use siworld_node::fund_keys::{self, FundGrant, FundKeystore};
use siworld_node::genesis::{Genesis, GenesisFile, ProofsFile};
use siworld_node::keystore::WalletFileLock;
use siworld_node::node::Node;
use siworld_node::secrets::write_secret_bytes;
use siworld_node::{hex, PayoutRefused};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
const PASSWORD: &str = "temporary fund custody password";
const NEW_PASSWORD: &str = "different temporary custody password";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "si-fund-{}-{}",
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
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn request_id() -> siworld_node::fund_payments::PayoutId {
    siworld_node::fund_payments::PayoutId::random().unwrap()
}
fn seed() -> Digest {
    Digest([8; 32])
}
fn recipient(i: u8) -> siworld_crypto::Address {
    SpendKey::from_digest(Digest([i; 32])).address()
}
fn node() -> Node {
    let mut genesis = Genesis::from_file(&GenesisFile {
        network: "fund-security-test".into(),
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
    genesis.params.dev_fund_keys = Some(DevFundSigner::from_seed(&seed()).verifying_keys());
    let mut n = Node::open(
        genesis,
        SpendKey::from_digest(Digest([1; 32])),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    for h in 1..=101 {
        let mut b = n.template(1000 + h).unwrap();
        assert!(mine(&mut b.header, 1));
        n.accept(&b).unwrap();
    }
    n
}
fn grant(n: &Node) -> FundGrant {
    FundGrant {
        version: 2,
        approval_id: siworld_node::fund_payments::PayoutId::random()
            .unwrap()
            .to_string(),
        budget: siworld_node::fund_keys::FundBudget {
            version: 1,
            id: "ab".repeat(32),
            direct_si: "1000000000".into(),
            lock_si: "1000000000".into(),
            total_si: "2000000000".into(),
            max_payout_si: "1000000".into(),
        },
        genesis: hex(&n.genesis.id),
        seconds: 60,
        direct_si: "0.0003".into(),
        lock_si: "0".into(),
        max_payout_si: "0.0002".into(),
        recipients: vec![encode_address(&recipient(3))],
        approval: None,
    }
}
#[test]
fn encrypted_fund_seed_authenticates_every_field_and_never_loads_plaintext_implicitly() {
    let t = Temp::new();
    let p = t.0.join("key");
    let a = FundKeystore::seal(&seed(), PASSWORD).unwrap();
    let b = FundKeystore::seal(&seed(), PASSWORD).unwrap();
    a.save_new(&p).unwrap();
    let original = std::fs::read(&p).unwrap();
    assert_eq!(original.len(), 96);
    assert!(!original.windows(32).any(|w| w == seed().as_bytes()));
    assert_eq!(
        a.open(PASSWORD).unwrap().verifying_keys(),
        b.open(PASSWORD).unwrap().verifying_keys()
    );
    assert_eq!(format!("{a:?}"), "FundKeystore(REDACTED)");
    assert!(a.open("incorrect").is_err());
    assert!(FundKeystore::seal(&seed(), "short").is_err());
    assert!(a.open(&"x".repeat(1025)).is_err());
    assert!(a.save_new(&p).is_err());
    for offset in [0, 8, 24, 48, 80] {
        let mut bad = original.clone();
        bad[offset] ^= 1;
        std::fs::write(&p, bad).unwrap();
        assert!(FundKeystore::load(&p)
            .and_then(|s| s.open(PASSWORD))
            .is_err());
    }
    std::fs::write(&p, hex(&seed())).unwrap();
    assert!(FundKeystore::load(&p).is_err());
}
#[test]
fn explicit_migration_rotation_and_authenticated_copies_preserve_identity_and_ownership() {
    let t = Temp::new();
    let p = t.0.join("key");
    let copy = t.0.join("backup");
    write_secret_bytes(&p, seed().as_bytes()).unwrap();
    let before = std::fs::read(&p).unwrap();
    assert!(fund_keys::migrate_file(&p, "short").is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    let lock = WalletFileLock::acquire(&t.0).unwrap();
    assert!(fund_keys::migrate_file(&p, PASSWORD).is_err());
    drop(lock);
    fund_keys::migrate_file(&p, PASSWORD).unwrap();
    assert!(fund_keys::migrate_file(&p, PASSWORD).is_err());
    assert!(fund_keys::copy_file(&p, &copy, "incorrect").is_err());
    assert!(!copy.exists());
    fund_keys::copy_file(&p, &copy, PASSWORD).unwrap();
    assert!(fund_keys::copy_file(&p, &copy, PASSWORD).is_err());
    let encrypted = std::fs::read(&p).unwrap();
    assert!(fund_keys::rotate_file(&p, "incorrect", NEW_PASSWORD).is_err());
    assert!(fund_keys::rotate_file(&p, PASSWORD, "short").is_err());
    assert_eq!(std::fs::read(&p).unwrap(), encrypted);
    fund_keys::rotate_file(&p, PASSWORD, NEW_PASSWORD).unwrap();
    let loaded = FundKeystore::load(&p).unwrap();
    assert!(loaded.open(PASSWORD).is_err());
    assert_eq!(
        loaded.open(NEW_PASSWORD).unwrap().verifying_keys(),
        DevFundSigner::from_seed(&seed()).verifying_keys()
    );
    assert!(FundKeystore::load(&copy).unwrap().open(PASSWORD).is_ok());
    let restored = t.0.join("restored");
    fund_keys::copy_file(&copy, &restored, PASSWORD).unwrap();
    assert_eq!(
        FundKeystore::load(&restored)
            .unwrap()
            .open(PASSWORD)
            .unwrap()
            .verifying_keys(),
        loaded.open(NEW_PASSWORD).unwrap().verifying_keys()
    );
}
#[test]
fn authorization_binds_chain_recipients_amounts_accounts_and_expiry_without_refills() {
    let mut n = node();
    let g = grant(&n);
    let store = FundKeystore::seal(&seed(), PASSWORD).unwrap();
    let journal = common::FundDir::attach(&mut n, store.clone(), PASSWORD);
    assert!(n.fund_status().locked);
    assert_eq!(
        n.payout(request_id(), DevAccount::Direct, &recipient(3), 10_000),
        Err(PayoutRefused::Locked)
    );
    assert!(n.unlock_fund("incorrect", &g).is_err());
    let mut bad = g.clone();
    bad.genesis = "ff".repeat(32);
    assert!(n.unlock_fund(PASSWORD, &bad).is_err());
    for change in 0..19 {
        let mut bad = g.clone();
        match change {
            0 => bad.seconds = 0,
            1 => bad.seconds = 3601,
            2 => bad.recipients.clear(),
            3 => bad.direct_si = "-1".into(),
            4 => bad.max_payout_si = "0".into(),
            5 => bad.recipients.push(bad.recipients[0].clone()),
            6 => bad.direct_si = "184467440738".into(),
            7 => bad.max_payout_si = "1e3".into(),
            8 => bad.recipients = vec![bad.recipients[0].clone(); 33],
            9 => bad.version = 3,
            10 => bad.budget.version = 2,
            11 => bad.budget.id = "AB".repeat(32),
            12 => bad.approval_id.clear(),
            13 => bad.approval_id = "AB".repeat(32),
            14 => bad.budget.total_si = "0".into(),
            15 => bad.budget.total_si = "184467440738".into(),
            16 => bad.budget.direct_si = "0.000000001".into(),
            17 => bad.budget.max_payout_si = "0.0001".into(),
            _ => {
                bad.budget.direct_si = "0".into();
                bad.budget.lock_si = "0".into();
            }
        }
        assert!(n.unlock_fund(PASSWORD, &bad).is_err());
    }
    n.unlock_fund(PASSWORD, &g).unwrap();
    assert!(n.unlock_fund(PASSWORD, &g).is_err());
    assert!(n
        .protect_dev_fund(store.clone(), PASSWORD, &journal.0)
        .is_err());
    for (account, to, amount) in [
        (DevAccount::Direct, recipient(4), 10_000),
        (DevAccount::Lock, recipient(3), 10_000),
        (DevAccount::Direct, recipient(3), 30_000),
    ] {
        assert_eq!(
            n.payout(request_id(), account, &to, amount),
            Err(PayoutRefused::Authorization)
        );
    }
    assert_eq!(n.fund_status().direct_remaining, 30_000);
    assert_eq!(
        n.payout(request_id(), DevAccount::Direct, &recipient(3), 1),
        Err(PayoutRefused::BelowMinimum)
    );
    assert_eq!(n.fund_status().direct_remaining, 30_000);
    n.payout(request_id(), DevAccount::Direct, &recipient(3), 20_000)
        .unwrap();
    assert_eq!(n.fund_status().direct_remaining, 10_000);
    assert_eq!(
        n.payout(request_id(), DevAccount::Direct, &recipient(3), 20_000),
        Err(PayoutRefused::Authorization)
    );
    n.payout(request_id(), DevAccount::Direct, &recipient(3), 10_000)
        .unwrap();
    assert_eq!(n.fund_status().direct_remaining, 0);
    n.expire_fund(n.fund_unlock_deadline().unwrap() + Duration::from_nanos(1));
    assert!(n.fund_status().locked);
    assert!(n.fund_unlock_deadline().is_none());
    // Locking cannot revoke signatures already issued: the next block still carries them.
    assert_eq!(n.template(1102).unwrap().body.payouts.len(), 2);
    n.unlock_fund(PASSWORD, &grant(&n)).unwrap();
    n.lock_fund();
    assert!(n.fund_status().locked);
    drop(n);
    let mut restarted = node();
    restarted
        .protect_dev_fund(store, PASSWORD, &journal.0)
        .unwrap();
    assert!(restarted.fund_status().locked);
    assert_eq!(restarted.fund_status().direct_remaining, 0);
}
#[test]
fn wrong_genesis_keys_fail_before_installation_and_failed_payouts_keep_budget() {
    let mut n = node();
    assert!(n
        .protect_dev_fund(
            FundKeystore::seal(&Digest([9; 32]), PASSWORD).unwrap(),
            PASSWORD,
            &std::env::temp_dir().join("unused-fund-journal")
        )
        .is_err());
    assert!(!n.fund_status().configured);
    let _journal = common::FundDir::attach(
        &mut n,
        FundKeystore::seal(&seed(), PASSWORD).unwrap(),
        PASSWORD,
    );
    let mut g = grant(&n);
    g.lock_si = "100".into();
    n.unlock_fund(PASSWORD, &g).unwrap();
    assert!(matches!(
        n.payout(request_id(), DevAccount::Lock, &recipient(3), 10_000),
        Err(PayoutRefused::Insufficient { .. })
    ));
    assert_eq!(n.fund_status().lock_remaining, 10_000_000_000);
}

#[test]
fn rpc_fund_capability_needs_password_and_grant_and_expires_without_activity() {
    use serde_json::json;
    use siworld_node::rpc_auth::{RpcAuth, RpcToken};
    use siworld_node::service::{call_authenticated, run, Config, RpcConfig};
    use std::net::TcpListener;
    use std::time::Instant;
    let mut n = node();
    let g = grant(&n);
    let _journal = common::FundDir::attach(
        &mut n,
        FundKeystore::seal(&seed(), PASSWORD).unwrap(),
        PASSWORD,
    );
    let socket = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let rpc = socket.to_string();
    let token = |b: u8| RpcToken::from_hex(&format!("{b:02x}").repeat(32)).unwrap();
    let config = Config {
        worker: None,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        peers: vec![],
        mine: false,
        rpc: Some(RpcConfig {
            address: socket,
            auth: RpcAuth::new(token(1), Some(token(2)), Some(token(3))).unwrap(),
        }),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run(n, config, async {
                let _ = rx.await;
            }))
            .unwrap()
    });
    // Always join the service, including after an assertion failure.
    struct Stop(
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<std::thread::JoinHandle<()>>,
    );
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
            let _ = self.1.take().unwrap().join();
        }
    }
    let _stop = Stop(Some(tx), Some(thread));
    let deadline = Instant::now() + Duration::from_secs(30);
    while call_authenticated(&rpc, &json!({"method":"info"}), &token(1)).is_err() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let call = |b, request| call_authenticated(&rpc, &request, &token(b)).unwrap();
    for method in [
        "fundstatus",
        "fundunlock",
        "fundlock",
        "devfund",
        "fundpayoutstatus",
        "fundapprovals",
    ] {
        for b in [1, 2] {
            assert_eq!(
                call(b, json!({"method":method})),
                json!({"error":"forbidden"})
            );
        }
    }
    assert_eq!(call(3, json!({"method":"fundstatus"}))["locked"], true);
    assert!(call(3, json!({"method":"fundunlock","grant":g}))
        .get("error")
        .is_some());
    assert!(call(
        3,
        json!({"method":"fundunlock","grant":g,"password":"incorrect"})
    )
    .get("error")
    .is_some());
    assert_eq!(
        call(
            3,
            json!({"method":"fundunlock","grant":g,"password":PASSWORD})
        )["locked"],
        false
    );
    assert!(call(
        3,
        json!({"method":"fundunlock","grant":g,"password":PASSWORD})
    )
    .get("error")
    .is_some());
    let payout = json!({"method":"devfund","payout_id":"01".repeat(32),"account":"direct","to":encode_address(&recipient(3)),"amount":"0.0002"});
    let receipt = call(3, payout.clone());
    assert_eq!(receipt["counter"], 0);
    assert_eq!(call(3, payout.clone()), receipt);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| call(3, payout.clone())))
            .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), receipt);
        }
    });
    assert_eq!(
        call(
            3,
            json!({"method":"fundpayoutstatus","payout_id":"01".repeat(32)})
        ),
        receipt
    );
    let mut unkeyed = payout.clone();
    unkeyed.as_object_mut().unwrap().remove("payout_id");
    assert!(call(3, unkeyed).get("error").is_some());
    let mut changed = payout;
    changed["amount"] = json!("0.0001");
    assert!(call(3, changed).get("error").is_some());
    assert_eq!(
        call(3, json!({"method":"fundstatus"}))["direct_remaining"],
        "0.0001"
    );
    assert_eq!(call(3, json!({"method":"fundlock"}))["locked"], true);
    let audit = call(3, json!({"method":"fundapprovals"}));
    assert_eq!(audit["approval_count"], 1);
    assert_eq!(audit["reserved_atoms"], json!([20_000, 0]));
    assert_eq!(audit["approvals"][0]["grant"]["approval_id"], g.approval_id);
    assert!(call(3, json!({"method":"fundapprovals", "limit":17}))
        .get("error")
        .is_some());
    let mut short = g.clone();
    short.seconds = 1;
    short.approval_id = request_id().to_string();
    let files = Temp::new();
    let auth = files.0.join("auth");
    let pw = files.0.join("password");
    let grant_file = files.0.join("grant.json");
    siworld_node::secrets::write_secret(&auth, &"03".repeat(32)).unwrap();
    siworld_node::secrets::write_secret(&pw, PASSWORD).unwrap();
    siworld_node::secrets::write_secret(&grant_file, &serde_json::to_string(&short).unwrap())
        .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_siworld-cli"))
        .args([
            "--rpc",
            &rpc,
            "--auth-file",
            auth.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
            "fundunlock",
            grant_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["locked"],
        false
    );
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(call(3, json!({"method":"fundstatus"}))["locked"], true);
    let listed = std::process::Command::new(env!("CARGO_BIN_EXE_siworld-cli"))
        .args([
            "--rpc",
            &rpc,
            "--auth-file",
            auth.to_str().unwrap(),
            "fundapprovals",
            "0",
            "1",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["approval_count"], 2);
    assert_eq!(listed["next_offset"], 1);
    assert_eq!(
        call(3, json!({"method":"fundstatus"}))["direct_remaining"],
        "0"
    );
    assert!(call(3, json!({"method":"balance"})).get("error").is_some());
    let order = files.0.join("fund-order.json");
    let id = "01".repeat(32);
    let address = encode_address(&recipient(3));
    for _ in 0..2 {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_siworld-cli"))
            .args([
                "--rpc",
                &rpc,
                "--auth-file",
                auth.to_str().unwrap(),
                "--fund-order",
                order.to_str().unwrap(),
                "devfund",
                &id,
                "direct",
                &address,
                "0.0002",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
            receipt
        );
    }
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(order).unwrap()).unwrap();
    assert_eq!(retained["payout_id"], id);
    assert_eq!(retained["genesis"], g.genesis);
}

#[test]
fn cli_key_lifecycle_uses_encrypted_files_and_preserves_public_identity() {
    use std::process::Command;
    let t = Temp::new();
    let p = t.0.join("fund.key");
    let pw = t.0.join("password");
    let next = t.0.join("new-password");
    siworld_node::secrets::write_secret(&pw, PASSWORD).unwrap();
    siworld_node::secrets::write_secret(&next, NEW_PASSWORD).unwrap();
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .output()
            .unwrap()
    };
    let p = p.to_str().unwrap();
    let pw = pw.to_str().unwrap();
    let next = next.to_str().unwrap();
    let keygen = call(&["devfund-keygen", "--out", p, "--password-file", pw]);
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let original = call(&["devfund-public", "--key", p, "--password-file", pw]);
    assert!(original.status.success());
    assert_eq!(original.stdout, keygen.stdout);
    assert!(
        !call(&["devfund-keygen", "--out", p, "--password-file", pw])
            .status
            .success()
    );
    let keys = FundKeystore::load(std::path::Path::new(p))
        .unwrap()
        .open(PASSWORD)
        .unwrap()
        .verifying_keys();
    let genesis = t.0.join("genesis.json");
    let file = GenesisFile {
        network: "fund-init-cli-test".into(),
        timestamp: 1000,
        block_time: 1,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: Some(siworld_node::genesis::DevFundFile {
            direct: siworld_node::genesis::hex_bytes(&keys.direct),
            lock: siworld_node::genesis::hex_bytes(&keys.lock),
        }),
        allocations: vec![],
    };
    std::fs::write(&genesis, serde_json::to_vec(&file).unwrap()).unwrap();
    let init_args = [
        "devfund-journal-init",
        "--key",
        p,
        "--genesis",
        genesis.to_str().unwrap(),
        "--password-file",
        pw,
    ];
    assert!(!call(&init_args).status.success());
    assert!(!t.0.join("payouts").exists());
    let mut confirmed = init_args.to_vec();
    confirmed.push("--confirm-no-prior-requests");
    let initialized = call(&confirmed);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let state = std::fs::read(t.0.join("payouts/state")).unwrap();
    assert!(!call(&confirmed).status.success());
    assert_eq!(std::fs::read(t.0.join("payouts/state")).unwrap(), state);
    let backup = t.0.join("backup");
    let backup = backup.to_str().unwrap();
    assert!(call(&[
        "devfund-backup",
        "--key",
        p,
        "--out",
        backup,
        "--password-file",
        pw
    ])
    .status
    .success());
    assert!(call(&[
        "devfund-rotate",
        "--key",
        p,
        "--password-file",
        pw,
        "--new-password-file",
        next
    ])
    .status
    .success());
    assert!(
        !call(&["devfund-public", "--key", p, "--password-file", pw])
            .status
            .success()
    );
    assert_eq!(
        call(&["devfund-public", "--key", p, "--password-file", next]).stdout,
        original.stdout
    );
    let restored = t.0.join("restored");
    let restored = restored.to_str().unwrap();
    assert!(call(&[
        "devfund-restore",
        "--key",
        backup,
        "--out",
        restored,
        "--password-file",
        pw
    ])
    .status
    .success());
    assert_eq!(
        call(&["devfund-public", "--key", restored, "--password-file", pw]).stdout,
        original.stdout
    );
    assert!(!call(&[
        "devfund-public",
        "--key",
        p,
        "--password-file",
        next,
        "--password-file",
        pw
    ])
    .status
    .success());
}
