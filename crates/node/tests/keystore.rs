//! Keystore authentication, recovery and live spending boundaries.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use siworld_circuits::MockProver;
use siworld_core::Digest;
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::keystore::{
    backup_wallet, migrate_wallet, restore_wallet, Keystore, WalletFileLock,
};
use siworld_node::node::Node;
use siworld_node::secrets::{read_secret, write_secret_bytes};
use siworld_node::{hex, PayError};

const PASSWORD: &str = "correct horse test battery";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-keystore-{}-{}",
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
fn key() -> SpendKey {
    SpendKey::from_digest(Digest([1; 32]))
}

#[test]
fn authenticated_roundtrip_and_fresh_salt_nonce() {
    let a = Keystore::seal(&key(), PASSWORD).unwrap();
    let b = Keystore::seal(&key(), PASSWORD).unwrap();
    assert_ne!(a.encode(), b.encode());
    assert!(!a.encode().contains(&hex(&Digest(*key().expose_secret()))));
    assert_eq!(a.open(PASSWORD).unwrap().address(), key().address());
    assert_eq!(
        Keystore::decode(&a.encode())
            .unwrap()
            .open(PASSWORD)
            .unwrap(),
        key()
    );
    assert!(a.open("a different password").is_err());
    assert!(Keystore::seal(&key(), "short").is_err());
    assert!(a.open(&"x".repeat(1025)).is_err());
    assert_eq!(format!("{a:?}"), "Keystore(REDACTED)");
}

#[test]
fn malformed_versions_lengths_and_authenticated_bytes_fail_closed() {
    let encoded = Keystore::seal(&key(), PASSWORD).unwrap().encode();
    for bad in [
        String::new(),
        "00".repeat(32),
        encoded[..encoded.len() - 3].into(),
        encoded.replace("SIWALLET1", "SIWALLET2"),
        format!("{encoded}00"),
    ] {
        assert!(Keystore::decode(&bad).is_err());
    }
    // Salt, nonce, encrypted key and tag are all authenticated by the fixed format.
    for offset in [0, 16, 40, 72, 87] {
        let mut bad = encoded.as_bytes().to_vec();
        let index = "SIWALLET1:".len() + offset * 2;
        bad[index] = if bad[index] == b'0' { b'1' } else { b'0' };
        let bad = Keystore::decode(std::str::from_utf8(&bad).unwrap()).unwrap();
        assert!(bad.open(PASSWORD).is_err(), "tamper offset {offset}");
    }
}

#[cfg(unix)]
#[test]
fn migration_backup_restore_and_exclusive_ownership_preserve_identity() {
    let source = Temp::new();
    let backup_dir = Temp::new();
    let restore_dir = Temp::new();
    let path = source.0.join("key");
    write_secret_bytes(&path, key().expose_secret()).unwrap();
    let before = read_secret(&path).unwrap();
    assert!(migrate_wallet(&source.0, "short").is_err());
    assert_eq!(*before, *read_secret(&path).unwrap());
    let lock = WalletFileLock::acquire(&source.0).unwrap();
    assert!(migrate_wallet(&source.0, PASSWORD).is_err());
    assert!(WalletFileLock::acquire(&source.0).is_err());
    drop(lock);
    migrate_wallet(&source.0, PASSWORD).unwrap();
    let store = Keystore::load(&path).unwrap();
    assert_eq!(store.open(PASSWORD).unwrap().address(), key().address());
    assert!(!read_secret(&path).unwrap().contains(before.trim()));
    assert!(migrate_wallet(&source.0, PASSWORD).is_err());
    let backup = backup_dir.0.join("wallet.backup");
    assert!(backup_wallet(&source.0, &backup, "incorrect password").is_err());
    assert!(!backup.exists());
    backup_wallet(&source.0, &backup, PASSWORD).unwrap();
    assert!(backup_wallet(&source.0, &backup, PASSWORD).is_err());
    assert!(restore_wallet(&backup, &restore_dir.0, "incorrect password").is_err());
    assert!(!restore_dir.0.join("key").exists());
    let marker = restore_dir.0.join("rpc-read.token");
    siworld_node::secrets::write_secret(&marker, "existing credential").unwrap();
    assert!(restore_wallet(&backup, &restore_dir.0, PASSWORD).is_err());
    assert!(!restore_dir.0.join("key").exists());
    assert_eq!(&*read_secret(&marker).unwrap(), "existing credential");
    std::fs::remove_file(marker).unwrap();
    restore_wallet(&backup, &restore_dir.0, PASSWORD).unwrap();
    let recovered = Keystore::load(&restore_dir.0.join("key")).unwrap();
    assert_eq!(recovered.open(PASSWORD).unwrap().address(), key().address());
    assert!(restore_wallet(&backup, &restore_dir.0, PASSWORD).is_err());
    assert!(source.0.read_dir().unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn wallet_lock_rejects_aliases_and_unsafe_directory_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = Temp::new();
    let other = Temp::new();
    let file = other.0.join("file");
    siworld_node::secrets::write_secret(&file, "test lock").unwrap();
    let lock = dir.0.join(".wallet.lock");
    symlink(&file, &lock).unwrap();
    assert!(WalletFileLock::acquire(&dir.0).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::hard_link(&file, &lock).unwrap();
    assert!(WalletFileLock::acquire(&dir.0).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(WalletFileLock::acquire(&dir.0).is_err());
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = other.0.join("directory");
    symlink(&dir.0, &alias).unwrap();
    assert!(WalletFileLock::acquire(&alias).is_err());
    assert!(WalletFileLock::acquire(&dir.0).is_ok());
}

fn node() -> Node {
    let genesis = Genesis::from_file(&GenesisFile {
        network: "keystore-test".into(),
        timestamp: 1000,
        block_time: 60,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: hex(&key().owner()),
            amount: "100".into(),
        }],
    })
    .unwrap();
    Node::open(
        genesis,
        key(),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap()
}

#[test]
fn lock_evicts_keys_and_rescan_preserves_pending_reservations_and_deadline() {
    let mut node = node();
    let store = Keystore::seal(&key(), PASSWORD).unwrap();
    let recipient = SpendKey::from_digest(Digest([2; 32])).address();
    let tx = node.pay(&recipient, 10_000_000, false).unwrap();
    let before = node.balance().unwrap();
    node.protect_wallet(store).unwrap();
    assert!(node.wallet_is_locked());
    assert_eq!(node.balance(), Err(PayError::Locked));
    assert!(node.wallets.iter().all(|w| w.notes().is_empty()));
    assert!(matches!(
        node.pay(&recipient, 10_000_000, false),
        Err(PayError::Locked)
    ));
    assert!(node.unlock_wallet("incorrect", 30).is_err());
    assert!(node.wallet_is_locked());
    assert!(node.unlock_wallet(PASSWORD, 0).is_err());
    assert!(node.unlock_wallet(PASSWORD, 3601).is_err());
    node.unlock_wallet(PASSWORD, 30).unwrap();
    assert!(!node.wallet_is_locked());
    assert_eq!(node.balance().unwrap(), before);
    assert!(
        node.pay(&recipient, 10_000_000, false).is_err(),
        "pending inputs remain reserved"
    );
    let deadline = node.wallet_unlock_deadline().unwrap();
    node.expire_wallet(deadline + Duration::from_nanos(1));
    assert!(node.wallet_is_locked());
    assert!(node.wallets.iter().all(|w| w.notes().is_empty()));
    // Blocks accepted while locked are recovered by replay when unlocked.
    let mut block = node.template(1001).unwrap();
    assert!(siworld_consensus::mine(&mut block.header, 1));
    node.accept(&block).unwrap();
    node.unlock_wallet(PASSWORD, 30).unwrap();
    assert_eq!(node.balance().unwrap().spendable, before.pending);
    assert!(node.chain.state.nullifiers.contains(&tx.slot.nf[0]));
    node.expire_wallet(Instant::now());
    assert!(!node.wallet_is_locked());
}

#[cfg(unix)]
#[test]
fn offline_cli_encrypts_new_wallet_and_recovers_identical_address() {
    use siworld_node::secrets::write_secret;
    use std::process::Command;
    let temp = Temp::new();
    let password_file = temp.0.join("password");
    write_secret(&password_file, PASSWORD).unwrap();
    let source = temp.0.join("source");
    let backup = temp.0.join("backup");
    let recovered = temp.0.join("recovered");
    let run = |args: Vec<&str>| {
        let output = Command::new(env!("CARGO_BIN_EXE_siworld-node"))
            .args(args)
            .current_dir(&temp.0)
            .arg("--password-file")
            .arg(&password_file)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(PASSWORD));
        text
    };
    let source = source.to_str().unwrap();
    let backup = backup.to_str().unwrap();
    let recovered = recovered.to_str().unwrap();
    run(vec!["init", "--datadir", source]);
    let identity = run(vec!["address", "--datadir", source]);
    assert!(Keystore::load(&PathBuf::from(source).join("key")).is_ok());
    run(vec!["wallet-backup", "--datadir", source, "--out", backup]);
    run(vec![
        "wallet-backup",
        "--datadir",
        source,
        "--out",
        "relative.backup",
    ]);
    run(vec!["wallet-check", "--backup", "relative.backup"]);
    assert!(run(vec!["wallet-check", "--backup", backup]).starts_with(&identity));
    run(vec![
        "wallet-restore",
        "--datadir",
        recovered,
        "--backup",
        backup,
    ]);
    assert_eq!(run(vec!["address", "--datadir", recovered]), identity);
    for name in ["rpc-read.token", "rpc-spend.token", "rpc-devfund.token"] {
        assert_ne!(
            *read_secret(&PathBuf::from(source).join(name)).unwrap(),
            *read_secret(&PathBuf::from(recovered).join(name)).unwrap()
        );
    }
}

#[test]
fn locked_reorg_rescans_only_the_surviving_branch() {
    let mut wallet = node();
    let mut peer = node();
    let recipient = SpendKey::from_digest(Digest([2; 32])).address();
    wallet.pay(&recipient, 10_000_000, false).unwrap();
    let mut orphan = wallet.template(1001).unwrap();
    assert!(siworld_consensus::mine(&mut orphan.header, 1));
    wallet.accept(&orphan).unwrap();
    wallet
        .protect_wallet(Keystore::seal(&key(), PASSWORD).unwrap())
        .unwrap();
    for height in 1..=3 {
        let mut block = peer.template(1000 + height).unwrap();
        assert!(siworld_consensus::mine(&mut block.header, 1));
        peer.accept(&block).unwrap();
        wallet.accept(&block).unwrap();
    }
    assert_eq!(wallet.tip(), peer.tip());
    assert!(wallet.wallets.iter().all(|w| w.notes().is_empty()));
    wallet.unlock_wallet(PASSWORD, 30).unwrap();
    assert_eq!(wallet.balance().unwrap(), peer.balance().unwrap());
    assert_eq!(wallet.balance().unwrap().spendable, 100 * 100_000_000);
    wallet.pay(&recipient, 10_000_000, false).unwrap();
}

#[test]
fn mismatched_keystore_cannot_change_wallet_identity() {
    let mut wallet = node();
    let identity = wallet.address();
    let other = SpendKey::from_digest(Digest([2; 32]));
    wallet
        .protect_wallet(Keystore::seal(&other, PASSWORD).unwrap())
        .unwrap();
    assert!(wallet.unlock_wallet(PASSWORD, 30).is_err());
    assert!(wallet.wallet_is_locked());
    assert_eq!(wallet.address(), identity);
}
