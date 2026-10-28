//! Password-authenticated wallet snapshots and atomic offline restoration.
//! Blocks, fund keys and live proving randomness are deliberately not archived.
use crate::genesis::Genesis;
use crate::keystore::{Keystore, WalletFileLock};
use crate::node::Node;
use crate::payments::{JournalSnapshot, RecoveryCheckpoint};
use crate::secrets::{read_private_bytes, write_private_bytes};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use siworld_circuits::ProofSystem;
use siworld_core::{
    codec::{decode_all, DecodeError},
    Digest,
};
use siworld_crypto::SecretSeed;
use siworld_storage::BlockStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SIWFULL1";
const AAD: &[u8] = b"siworld full wallet snapshot v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
const MAX_BACKUP: usize = 260 << 20;
const MAX_GENESIS: usize = 2 << 20;
const MAX_JOURNAL: usize = 256 << 20;

pub struct BackupInfo {
    pub snapshot_id: Digest,
    pub genesis: Genesis,
    pub owner: Digest,
    pub height: u64,
    pub tip: Digest,
    pub final_height: u64,
    pub final_hash: Digest,
    pub payment_count: usize,
}
struct Snapshot {
    info: BackupInfo,
    key_store: Keystore,
    journal: JournalSnapshot,
}
impl Snapshot {
    fn checkpoint(&self) -> RecoveryCheckpoint {
        RecoveryCheckpoint {
            snapshot_id: self.info.snapshot_id,
            height: self.info.height,
            tip: self.info.tip,
            final_height: self.info.final_height,
            final_hash: self.info.final_hash,
            reviewed_at: None,
        }
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(Vec::new());
        b.extend_from_slice(self.info.snapshot_id.as_bytes());
        b.extend_from_slice(self.info.owner.as_bytes());
        for bytes in [
            self.info.genesis.to_json().into_bytes(),
            self.key_store.encode().into_bytes(),
        ] {
            b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            b.extend_from_slice(&bytes);
        }
        b.extend_from_slice(&self.info.height.to_le_bytes());
        b.extend_from_slice(self.info.tip.as_bytes());
        b.extend_from_slice(&self.info.final_height.to_le_bytes());
        b.extend_from_slice(self.info.final_hash.as_bytes());
        let journal = self.journal.encode();
        b.extend_from_slice(&(journal.len() as u32).to_le_bytes());
        b.extend_from_slice(&journal);
        b
    }
    fn decode(bytes: &[u8], password: &str) -> Result<Self, String> {
        let snapshot = decode_all(bytes, |r| {
            let snapshot_id = r.digest()?;
            let owner = r.digest()?;
            let n = r.length(MAX_GENESIS)?;
            let genesis = Genesis::from_json(
                std::str::from_utf8(r.take(n)?).map_err(|_| DecodeError::BadValue)?,
            )
            .map_err(|_| DecodeError::BadValue)?;
            let n = r.length(256)?;
            let key_store = Keystore::decode(
                std::str::from_utf8(r.take(n)?).map_err(|_| DecodeError::BadValue)?,
            )
            .map_err(|_| DecodeError::BadValue)?;
            let height = r.u64()?;
            let tip = r.digest()?;
            let final_height = r.u64()?;
            let final_hash = r.digest()?;
            let n = r.length(MAX_JOURNAL)?;
            let journal = JournalSnapshot::decode(r.take(n)?).map_err(|_| DecodeError::BadValue)?;
            if final_height > height
                || journal.high_water < height
                || (height == 0 && tip != genesis.id)
                || (final_height == 0 && final_hash != genesis.id)
            {
                return Err(DecodeError::BadValue);
            }
            let payment_count = journal.len();
            Ok(Self {
                info: BackupInfo {
                    snapshot_id,
                    genesis,
                    owner,
                    height,
                    tip,
                    final_height,
                    final_hash,
                    payment_count,
                },
                key_store,
                journal,
            })
        })
        .map_err(|_| "invalid wallet snapshot")?;
        if snapshot.key_store.open(password)?.owner() != snapshot.info.owner {
            return Err("snapshot wallet identity mismatch".into());
        }
        Ok(snapshot)
    }
}
fn envelope_aad(header: &[u8]) -> Vec<u8> {
    let mut aad = AAD.to_vec();
    aad.extend_from_slice(header);
    aad
}
fn encrypt(plain: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if plain.len() > MAX_BACKUP - 64 {
        return Err("wallet snapshot exceeds limit".into());
    }
    let mut header = [0u8; 48];
    header[..8].copy_from_slice(MAGIC);
    getrandom::fill(&mut header[8..]).map_err(|_| "OS randomness unavailable")?;
    let key = crate::keystore::derived_key(password, &header[8..24])?;
    let mut b = Zeroizing::new(plain.to_vec());
    let tag = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .encrypt_inout_detached(
            <&XNonce>::try_from(&header[24..48]).expect("nonce length"),
            &envelope_aad(&header),
            b.as_mut_slice().into(),
        )
        .map_err(|_| "snapshot encryption failed")?;
    let mut out = Vec::with_capacity(64 + b.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&b);
    out.extend_from_slice(&tag);
    Ok(out)
}
fn decrypt(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.len() < 64 || bytes.len() > MAX_BACKUP || &bytes[..8] != MAGIC {
        return Err("unsupported or malformed wallet snapshot".into());
    }
    let key = crate::keystore::derived_key(password, &bytes[8..24])?;
    let mut plain = Zeroizing::new(bytes[48..bytes.len() - 16].to_vec());
    XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..48]).expect("nonce length"),
            &envelope_aad(&bytes[..48]),
            plain.as_mut_slice().into(),
            &Tag::try_from(&bytes[bytes.len() - 16..]).expect("tag length"),
        )
        .map_err(|_| "incorrect snapshot password or damaged snapshot")?;
    Ok(plain)
}
fn load(path: &Path, password: &str) -> Result<Snapshot, String> {
    let bytes = read_private_bytes(path, MAX_BACKUP)?;
    Snapshot::decode(&decrypt(&bytes, password)?, password)
}
pub fn inspect_full_backup(path: &Path, password: &str) -> Result<BackupInfo, String> {
    Ok(load(path, password)?.info)
}

pub fn create_full_backup(
    dir: &Path,
    output: &Path,
    password: &str,
    genesis: &Genesis,
    system: Arc<dyn ProofSystem>,
) -> Result<(), String> {
    let _lock = WalletFileLock::acquire(dir)?;
    if Genesis::from_json(&genesis.to_json()).map_err(|e| e.to_string())? != *genesis {
        return Err("genesis contains unsupported non-file parameters".into());
    }
    let key = Keystore::load(&dir.join("key"))?.open(password)?;
    let owner = key.owner();
    let key_store = Keystore::seal(&key, password)?;
    let block_path = dir.join("blocks.redb");
    if let Ok(m) = std::fs::symlink_metadata(&block_path) {
        if !m.is_file() {
            return Err("block store must be a regular file".into());
        }
    }
    let store = BlockStore::open(&block_path, &genesis.id).map_err(|e| e.to_string())?;
    let mut node = Node::open(
        genesis.clone(),
        key,
        SecretSeed::from_os_rng().map_err(|_| "OS randomness unavailable")?,
        Some(store),
        system,
    )
    .map_err(|e| e.to_string())?;
    node.enable_payment_journal(&dir.join("payments.redb"))
        .map_err(|e| e.to_string())?;
    if node.payment_recovery_required() {
        return Err("reconcile restored orders before creating a new full backup".into());
    }
    let journal = node.payment_snapshot().map_err(|e| e.to_string())?;
    let final_height = node.chain.final_height();
    let final_hash = node
        .chain
        .main_hash(final_height)
        .ok_or("missing final checkpoint")?;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "OS randomness unavailable")?;
    let snapshot = Snapshot {
        info: BackupInfo {
            snapshot_id: Digest(bytes),
            genesis: genesis.clone(),
            owner,
            height: node.height(),
            tip: node.tip(),
            final_height,
            final_hash,
            payment_count: journal.len(),
        },
        key_store,
        journal,
    };
    let plain = snapshot.encode();
    let encrypted = encrypt(&plain, password)?;
    let decoded = decrypt(&encrypted, password)?;
    if blake3::hash(&decoded) != blake3::hash(&plain) {
        return Err("snapshot verification failed".into());
    }
    // Apply the restoration decoder and its bounds before publishing a backup.
    let _verified = Snapshot::decode(&decoded, password)?;
    crate::keystore::atomic_write_bytes(output, &encrypted, false, || Ok(()))
}

pub(crate) struct Staging(pub(crate) Option<PathBuf>);
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn publish_directory(stage: &Path, destination: &Path) -> Result<(), String> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    renameat_with(CWD, stage, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|_| "cannot publish restore directory (destination must not exist)".to_owned())
}
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
pub(crate) fn publish_directory(_stage: &Path, _destination: &Path) -> Result<(), String> {
    Err("atomic restore publication unavailable".into())
}

pub fn restore_full_backup(path: &Path, dir: &Path, password: &str) -> Result<BackupInfo, String> {
    restore_with_hook(path, dir, password, || Ok(()))
}
fn restore_with_hook(
    path: &Path,
    dir: &Path,
    password: &str,
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<BackupInfo, String> {
    // Authenticate and decode everything before creating any destination files.
    let snapshot = load(path, password)?;
    if std::fs::symlink_metadata(dir).is_ok() {
        return Err("full restore requires a new destination directory".into());
    }
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let staging_path = parent.join(format!(".wallet-restore-{name}.tmp"));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&staging_path)
        .map_err(|_| "cannot create restore staging directory")?;
    let mut staging = Staging(Some(staging_path.clone()));
    let _lock = WalletFileLock::acquire(&staging_path)?;
    let key = snapshot.key_store.open(password)?;
    Keystore::seal(&key, password)?.save_new(&staging_path.join("key"))?;
    write_private_bytes(
        &staging_path.join("genesis.json"),
        snapshot.info.genesis.to_json().as_bytes(),
    )?;
    let checkpoint = snapshot.checkpoint();
    crate::payments::restore_journal(
        &staging_path.join("payments.redb"),
        &key,
        &snapshot.info.genesis.id,
        snapshot.journal,
        checkpoint,
    )
    .map_err(|e| e.to_string())?;
    for name in [
        crate::rpc_auth::READ_TOKEN_FILE,
        crate::rpc_auth::SPEND_TOKEN_FILE,
        crate::rpc_auth::FUND_TOKEN_FILE,
    ] {
        crate::rpc_auth::RpcToken::generate_file(&staging_path.join(name))?;
    }
    write_private_bytes(
        &staging_path.join("recovery.required"),
        b"siworld full wallet recovery v1\n",
    )?;
    std::fs::File::open(&staging_path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "cannot sync restored wallet")?;
    before_publish()?;
    publish_directory(&staging_path, dir)?;
    staging.0 = None;
    std::fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| "restore published; parent directory sync failed")?;
    Ok(snapshot.info)
}

pub fn merge_full_backup(node: &mut Node, path: &Path, password: &str) -> Result<(), String> {
    let snapshot = load(path, password)?;
    if snapshot.info.genesis != node.genesis || snapshot.info.owner != node.address().owner() {
        return Err("snapshot wallet or network mismatch".into());
    }
    let checkpoint = snapshot.checkpoint();
    node.merge_payment_snapshot(snapshot.journal, &checkpoint)
        .map_err(|e| e.to_string())
}

/// Private evidence from a sandbox exercise, never a public-chain attestation.
#[derive(Debug, serde::Serialize)]
pub struct RecoveryDrill {
    pub version: u32,
    pub snapshot_id: String,
    pub order_checkpoint: crate::orders::Checkpoint,
    pub height: u64,
    pub tip: String,
    pub orders_hash: String,
    pub payment_count: usize,
    pub retry_count: usize,
    pub cancelled_tombstones: usize,
    pub reopened: bool,
}
impl RecoveryDrill {
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        crate::keystore::atomic_write_bytes(
            path,
            &serde_json::to_vec_pretty(self).map_err(|_| "cannot encode drill report")?,
            false,
            || Ok(()),
        )
    }
}
pub struct DrillRequest<'a> {
    pub backup: &'a Path,
    pub chain_dir: &'a Path,
    pub work_dir: &'a Path,
    pub password: &'a str,
    pub expected_height: u64,
    pub expected_tip: Digest,
}
/// Offline only: replay a private copy of the source store, reconcile a restored
/// journal, retry known IDs without new proving, then reopen it before cleanup.
pub fn drill_full_backup(
    request: &DrillRequest<'_>,
    system: Arc<dyn ProofSystem>,
    orders: &crate::orders::VerifiedOrders<'_>,
) -> Result<RecoveryDrill, String> {
    let _source_lock = WalletFileLock::acquire(request.chain_dir)?;
    let _work_lock = WalletFileLock::acquire(request.work_dir)?;
    orders.ensure_outside(request.chain_dir)?;
    orders.ensure_outside(request.work_dir)?;
    let source =
        std::fs::canonicalize(request.chain_dir).map_err(|_| "cannot inspect chain directory")?;
    let work =
        std::fs::canonicalize(request.work_dir).map_err(|_| "cannot inspect drill directory")?;
    if source.starts_with(&work) || work.starts_with(&source) {
        return Err("drill work and source directories must be separate".into());
    }
    let block_path = source.join("blocks.redb");
    if !std::fs::symlink_metadata(&block_path)
        .map_err(|_| "source block store missing")?
        .is_file()
    {
        return Err("source block store must be a regular file".into());
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
    let stage = work.join(format!(
        ".wallet-drill-{}",
        crate::genesis::hex_bytes(&nonce)
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&stage)
        .map_err(|_| "cannot create drill sandbox")?;
    let mut cleanup = Staging(Some(stage.clone()));
    let wallet = stage.join("wallet");
    let info = restore_full_backup(request.backup, &wallet, request.password)?;
    let _wallet_lock = WalletFileLock::acquire(&wallet)?;
    // BlockStore::open uses a write transaction even when merely opening. Copy
    // while holding source ownership so replay cannot change the source database.
    std::fs::copy(&block_path, wallet.join("blocks.redb"))
        .map_err(|_| "cannot copy source block store")?;
    let open = || -> Result<Node, String> {
        let key = Keystore::load(&wallet.join("key"))?.open(request.password)?;
        let store = BlockStore::open(&wallet.join("blocks.redb"), &info.genesis.id)
            .map_err(|e| e.to_string())?;
        let mut node = Node::open(
            info.genesis.clone(),
            key,
            SecretSeed::from_os_rng().map_err(|_| "OS randomness unavailable")?,
            Some(store),
            system.clone(),
        )
        .map_err(|e| e.to_string())?;
        node.enable_payment_journal(&wallet.join("payments.redb"))
            .map_err(|e| e.to_string())?;
        Ok(node)
    };
    let mut node = open()?;
    if !node.payment_recovery_required() {
        return Err("drill restore did not set recovery gate".into());
    }
    let before = node.payment_snapshot().map_err(|e| e.to_string())?;
    let preview = node
        .reconcile_payments(orders, request.expected_height, request.expected_tip, false)
        .map_err(|e| e.to_string())?;
    if !node.payment_recovery_required() {
        return Err("drill preview cleared recovery gate".into());
    }
    let review = node
        .reconcile_payments(orders, request.expected_height, request.expected_tip, true)
        .map_err(|e| e.to_string())?;
    if preview.orders_hash != review.orders_hash || node.payment_recovery_required() {
        return Err("drill reconciliation mismatch".into());
    }
    let reconciled = node.payment_snapshot().map_err(|e| e.to_string())?;
    if !reconciled.preserves(&before) {
        return Err("drill reconciliation changed original records".into());
    }
    let mut retry_count = 0;
    for order in orders.orders() {
        let id = crate::payments::PaymentId::parse(&order.payment_id).map_err(|e| e.to_string())?;
        let to = crate::address::parse_address(&order.to).ok_or("invalid drill order")?;
        let amount = crate::amount::parse_sip(&order.amount).ok_or("invalid drill amount")?;
        let outcome = node
            .pay_with_id(id, &to, amount, order.priority)
            .map_err(|e| e.to_string())?;
        if let Some(tx) = outcome.relay {
            if reconciled.artifact(id) != Some(crate::wire::encode_tx(&tx).as_slice()) {
                return Err("drill retry changed artifact".into());
            }
        }
        retry_count += 1;
    }
    let after = node.payment_snapshot().map_err(|e| e.to_string())?.encode();
    if *reconciled.encode() != *after {
        return Err("drill retry changed durable payment records".into());
    }
    drop(node);
    let mut reopened = open()?;
    if reopened.payment_recovery_required()
        || *reopened
            .payment_snapshot()
            .map_err(|e| e.to_string())?
            .encode()
            != *after
    {
        return Err("drill reopen changed recovery state or payment records".into());
    }
    drop(reopened);
    drop(_wallet_lock);
    std::fs::remove_dir_all(&stage).map_err(|_| {
        "drill complete but sandbox cleanup failed; preserve and inspect work directory"
    })?;
    cleanup.0 = None;
    Ok(RecoveryDrill {
        version: 1,
        snapshot_id: crate::hex(&info.snapshot_id),
        order_checkpoint: orders.checkpoint().clone(),
        height: review.height,
        tip: crate::hex(&review.tip),
        orders_hash: crate::hex(&review.orders_hash),
        payment_count: info.payment_count,
        retry_count,
        cancelled_tombstones: review.cancelled_tombstones,
        reopened: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{GenesisFile, ProofsFile};
    use siworld_circuits::MockProver;
    use siworld_crypto::SpendKey;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut b = [0; 16];
            getrandom::fill(&mut b).unwrap();
            let p = std::env::temp_dir().join(format!(
                "siworld-full-unit-{}",
                crate::genesis::hex_bytes(&b)
            ));
            let mut d = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                d.mode(0o700);
            }
            d.create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    const PASSWORD: &str = "snapshot crash test password";
    #[test]
    fn restore_process_child() {
        let Ok(root) = std::env::var("SIWORLD_RESTORE_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let mode = std::env::var("SIWORLD_RESTORE_TEST_MODE").unwrap();
        let dest = root.join(&mode);
        if mode == "before" {
            let _ = restore_with_hook(&root.join("backup"), &dest, PASSWORD, || {
                std::process::exit(89)
            });
        } else {
            restore_full_backup(&root.join("backup"), &dest, PASSWORD).unwrap();
            std::process::exit(90);
        }
        panic!("child did not exit");
    }
    #[test]
    fn interrupted_restore_publishes_no_partial_wallet_and_completed_publication_survives_exit() {
        let dir = Temp::new();
        let source = dir.0.join("source");
        std::fs::create_dir(&source).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SpendKey::from_digest(Digest([1; 32]));
        Keystore::seal(&key, PASSWORD)
            .unwrap()
            .save_new(&source.join("key"))
            .unwrap();
        let genesis = Genesis::from_file(&GenesisFile {
            network: "backup-unit".into(),
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
        let path = dir.0.join("backup");
        create_full_backup(&source, &path, PASSWORD, &genesis, Arc::new(MockProver)).unwrap();
        assert!(
            restore_with_hook(&path, &dir.0.join("ordinary-failure"), PASSWORD, || Err(
                "injected write failure".into()
            ))
            .is_err()
        );
        assert!(!dir.0.join("ordinary-failure").exists());
        assert!(!std::fs::read_dir(&dir.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".wallet-restore-")));
        for (mode, code) in [("before", 89), ("after", 90)] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backup::tests::restore_process_child",
                    "--nocapture",
                ])
                .env("SIWORLD_RESTORE_TEST_ROOT", &dir.0)
                .env("SIWORLD_RESTORE_TEST_MODE", mode)
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(!dir.0.join("before").exists());
        let dest = dir.0.join("after");
        assert_eq!(
            Keystore::load(&dest.join("key"))
                .unwrap()
                .open(PASSWORD)
                .unwrap(),
            key
        );
        let mut n = Node::open(
            genesis,
            key,
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        n.enable_payment_journal(&dest.join("payments.redb"))
            .unwrap();
        assert!(n.payment_recovery_required());
        // Header, salt, nonce, ciphertext and tag alterations cannot be accepted.
        let bytes = read_private_bytes(&path, MAX_BACKUP).unwrap();
        for offset in [0, 8, 24, 48, bytes.len() - 1] {
            let mut bad = bytes.to_vec();
            bad[offset] ^= 1;
            assert!(decrypt(&bad, PASSWORD).is_err());
        }
        assert!(decrypt(&bytes[..63], PASSWORD).is_err());
        let plain = decrypt(&bytes, PASSWORD).unwrap();
        let mut bad = plain.to_vec();
        bad.extend_from_slice(&[0]);
        assert!(Snapshot::decode(&bad, PASSWORD).is_err());
        bad[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Snapshot::decode(&bad, PASSWORD).is_err());
    }
}
