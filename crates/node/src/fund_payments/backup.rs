//! Authenticated fund key+journal snapshots and explicitly gated restoration.
pub use super::witness::Checkpoint;
use super::*;
use crate::orders::archive::{external_path, json, publish, stage_for};
const MAGIC: &[u8; 8] = b"SIFULL01";
const AAD: &[u8] = b"siworld complete fund snapshot v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
const MAX_BACKUP: usize = 260 << 20;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovery {
    snapshot_id: String,
    pub(super) checkpoint: Checkpoint,
    prior_final_height: u64,
    prior_final_hash: String,
}
impl Recovery {
    pub(super) fn validate(&self, data: &Data) -> Result<(), String> {
        if self.prior_final_height > data.final_height
            || crate::parse_hex32(&self.prior_final_hash).is_none()
            || self.prior_final_hash.to_lowercase() != self.prior_final_hash
            || crate::parse_hex32(&self.snapshot_id).is_none()
            || self.snapshot_id.to_lowercase() != self.snapshot_id
            || data.witness.as_deref() != Some(self.checkpoint.witness.as_str())
            || data.sequence != self.checkpoint.sequence
        {
            return Err("invalid fund recovery gate".into());
        }
        self.checkpoint.id()?;
        Ok(())
    }
}
#[derive(Serialize)]
pub struct BackupInfo {
    pub snapshot_id: String,
    pub genesis: String,
    pub checkpoint: Checkpoint,
    pub records: usize,
    pub height: u64,
    pub final_height: u64,
    pub final_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    id: String,
    genesis: String,
    key: Vec<u8>,
    checkpoint: Checkpoint,
    state: Vec<u8>,
}
impl Snapshot {
    fn decode(bytes: &[u8], password: &str) -> Result<(Self, Genesis, FundKeystore, Data), String> {
        let snapshot: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid full fund snapshot")?;
        let g = Genesis::from_json(&snapshot.genesis).map_err(|e| e.to_string())?;
        let store = FundKeystore::decode(&snapshot.key)?;
        if snapshot.version != 1
            || crate::parse_hex32(&snapshot.id).is_none()
            || snapshot.id.to_lowercase() != snapshot.id
            || g.params.dev_fund_keys != Some(store.open(password)?.verifying_keys())
        {
            return Err("fund snapshot identity mismatch".into());
        }
        let data = decrypt(
            &*store.journal_key(password, &g.id)?,
            &context(&g),
            &snapshot.state,
        )
        .map_err(|e| e.to_string())?;
        validate(&data, &g).map_err(|e| e.to_string())?;
        snapshot.checkpoint.id()?;
        if snapshot.checkpoint.identity != blake3::hash(&context(&g)).to_hex().as_str()
            || snapshot.checkpoint.state_hash != blake3::hash(&snapshot.state).to_hex().as_str()
            || snapshot.checkpoint.sequence != data.sequence
            || data.witness.as_deref() != Some(snapshot.checkpoint.witness.as_str())
            || data.recovery.is_some()
        {
            return Err("fund snapshot journal mismatch".into());
        }
        Ok((snapshot, g, store, data))
    }
    fn info(&self, g: &Genesis, data: &Data, checkpoint: Checkpoint) -> BackupInfo {
        BackupInfo {
            snapshot_id: self.id.clone(),
            genesis: crate::hex(&g.id),
            checkpoint,
            records: data.records.len(),
            height: data.height,
            final_height: data.final_height,
            final_hash: data.final_hash.clone(),
        }
    }
}
fn seal(plain: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if plain.len() > MAX_BACKUP - 64 {
        return Err("fund snapshot exceeds limit".into());
    }
    let mut head = [0; 48];
    head[..8].copy_from_slice(MAGIC);
    getrandom::fill(&mut head[8..]).map_err(|_| "OS randomness unavailable")?;
    let key = crate::keystore::derived_key(password, &head[8..24])?;
    let mut aad = AAD.to_vec();
    aad.extend_from_slice(&head);
    let mut bytes = Zeroizing::new(plain.to_vec());
    let tag = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .encrypt_inout_detached(
            <&XNonce>::try_from(&head[24..]).expect("nonce length"),
            &aad,
            bytes.as_mut_slice().into(),
        )
        .map_err(|_| "cannot encrypt fund snapshot")?;
    let mut out = head.to_vec();
    out.extend_from_slice(&bytes);
    out.extend_from_slice(&tag);
    Ok(out)
}
fn unseal(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if !(64..=MAX_BACKUP).contains(&bytes.len()) || &bytes[..8] != MAGIC {
        return Err("invalid fund snapshot envelope".into());
    }
    let key = crate::keystore::derived_key(password, &bytes[8..24])?;
    let mut aad = AAD.to_vec();
    aad.extend_from_slice(&bytes[..48]);
    let mut out = Zeroizing::new(bytes[48..bytes.len() - 16].to_vec());
    XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..48]).expect("nonce length"),
            &aad,
            out.as_mut_slice().into(),
            &Tag::try_from(&bytes[bytes.len() - 16..]).expect("tag length"),
        )
        .map_err(|_| "incorrect fund snapshot password or damaged snapshot")?;
    Ok(out)
}
fn load(path: &Path, password: &str) -> Result<(Snapshot, Genesis, FundKeystore, Data), String> {
    Snapshot::decode(
        &unseal(&read_private_bytes(path, MAX_BACKUP)?, password)?,
        password,
    )
}
pub(super) fn fund_dir(key: &Path) -> &Path {
    key.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
pub(super) fn open(
    key: &Path,
    witness: &Path,
    password: &str,
    g: &Genesis,
) -> Result<(FundKeystore, FundJournal), String> {
    let store = FundKeystore::load(key)?;
    if g.params.dev_fund_keys != Some(store.open(password)?.verifying_keys()) {
        return Err("fund key does not match genesis".into());
    }
    let j = FundJournal::open_with_witness(
        &fund_dir(key).join("payouts"),
        store.journal_key(password, &g.id)?,
        g,
        Some(witness),
    )
    .map_err(|e| e.to_string())?;
    Ok((store, j))
}
/// Explicit upgrade under exclusive ownership. A partial upgrade fails closed;
/// never delete the witness-required marker to return to unwitnessed signing.
pub fn enable_witness(
    key: &Path,
    witness: &Path,
    password: &str,
    g: &Genesis,
) -> Result<Checkpoint, String> {
    let _lock = crate::fund_keys::lock_file(key)?;
    let store = FundKeystore::load(key)?;
    if g.params.dev_fund_keys != Some(store.open(password)?.verifying_keys()) {
        return Err("fund key does not match genesis".into());
    }
    let dir = fund_dir(key).join("payouts");
    let mut j = FundJournal::open(&dir, store.journal_key(password, &g.id)?, g)
        .map_err(|e| e.to_string())?;
    let resolved = external_path(witness, &[fund_dir(key)])?;
    if std::fs::symlink_metadata(&resolved).is_ok()
        || std::fs::canonicalize(fund_dir(key))
            .map_err(|_| "cannot resolve fund directory")?
            .starts_with(&resolved)
    {
        return Err("new separate witness directory required".into());
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
    let id = crate::genesis::hex_bytes(&nonce);
    j.data.witness = Some(id.clone());
    j.data.sequence = j
        .data
        .sequence
        .checked_add(1)
        .ok_or("fund sequence overflow")?;
    let bytes = encrypt(j.key.as_ref().expect("unlocked"), &j.context, &j.data)
        .map_err(|e| e.to_string())?;
    // Mark locally BEFORE creating the other domain. Failure requires recovering
    // these retained files; neither live startup nor a new empty witness can sign.
    atomic_write_bytes(&dir.join("witness.required"), id.as_bytes(), false, || {
        Ok(())
    })?;
    let w = witness::Witness::create(&resolved, g, &id, &bytes, &j.data)?;
    w.ensure_outside(fund_dir(key))?;
    atomic_write_bytes(&dir.join("state"), &bytes, true, || Ok(()))?;
    Ok(w.checkpoint().clone())
}
pub fn export_checkpoint(
    key: &Path,
    witness: &Path,
    password: &str,
    g: &Genesis,
    output: &Path,
    previous: Option<&Path>,
) -> Result<Checkpoint, String> {
    let _lock = crate::fund_keys::lock_file(key)?;
    let dir = fund_dir(key).join("payouts");
    let _journal_lock = WalletFileLock::acquire(&dir)?;
    let store = FundKeystore::load(key)?;
    if g.params.dev_fund_keys != Some(store.open(password)?.verifying_keys()) {
        return Err("fund key does not match genesis".into());
    }
    let k = store.journal_key(password, &g.id)?;
    if read_private_bytes(&dir.join("required"), 128)?.as_slice() != REQUIRED.as_bytes() {
        return Err("fund journal sentinel missing".into());
    }
    let mut before = decrypt(
        &k,
        &context(g),
        &read_private_bytes(&dir.join("state"), MAX_BYTES)?,
    )
    .map_err(|e| e.to_string())?;
    validate(&before, g).map_err(|e| e.to_string())?;
    let w = witness::Witness::open(witness, g)?;
    w.ensure_outside(fund_dir(key))?;
    if read_private_bytes(&dir.join("witness.required"), 64)?.as_slice()
        != w.checkpoint().witness.as_bytes()
    {
        return Err("fund witness marker mismatch".into());
    }
    let current = decrypt(&k, &context(g), &w.bytes).map_err(|e| e.to_string())?;
    validate(&current, g).map_err(|e| e.to_string())?;
    w.check_data(&w.bytes, &current, &k, g)?;
    if before.witness.is_none() {
        before.witness = Some(w.checkpoint().witness.clone());
    }
    if current.recovery.is_some() || !preserves(&current, &before) {
        return Err("fund witness does not preserve local records".into());
    }
    let out = w.external(output, fund_dir(key))?;
    if let Some(p) = previous {
        let cp = Checkpoint::read(&w.external(p, fund_dir(key))?)?;
        if !w.contains(&cp) {
            return Err("fund checkpoint is not an ancestor".into());
        }
    }
    let cp = w.checkpoint().clone();
    cp.save_new(&out)?;
    if Checkpoint::read(&out)? != cp {
        return Err("fund checkpoint read-back mismatch".into());
    }
    Ok(cp)
}
pub fn create(
    key: &Path,
    witness: &Path,
    password: &str,
    g: &Genesis,
    output: &Path,
) -> Result<BackupInfo, String> {
    let _lock = crate::fund_keys::lock_file(key)?;
    let (store, j) = open(key, witness, password, g)?;
    if Genesis::from_json(&g.to_json()).map_err(|e| e.to_string())? != *g {
        return Err("genesis contains unsupported non-file parameters".into());
    }
    if j.data.recovery.is_some() {
        return Err("fund recovery required".into());
    }
    j.healthy().map_err(|e| e.to_string())?;
    let w = j.witness.as_ref().expect("witness");
    let output = w.external(output, fund_dir(key))?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
    let snapshot = Snapshot {
        version: 1,
        id: crate::genesis::hex_bytes(&nonce),
        genesis: g.to_json(),
        key: store.bytes().to_vec(),
        checkpoint: w.checkpoint().clone(),
        state: read_private_bytes(&j.directory.join("state"), MAX_BYTES)?.to_vec(),
    };
    let plain = Zeroizing::new(json(&snapshot)?);
    let encrypted = seal(&plain, password)?;
    let _ = Snapshot::decode(&unseal(&encrypted, password)?, password)?;
    atomic_write_bytes(&output, &encrypted, false, || Ok(()))?;
    Ok(snapshot.info(g, &j.data, w.checkpoint().clone()))
}
pub fn inspect(path: &Path, password: &str) -> Result<BackupInfo, String> {
    let (s, g, _, d) = load(path, password)?;
    Ok(s.info(&g, &d, s.checkpoint.clone()))
}
pub(super) fn preserves(new: &Data, old: &Data) -> bool {
    new.witness == old.witness
        && super::budget::preserves(new, old)
        && new.sequence >= old.sequence
        && new.height >= old.height
        && new.final_height >= old.final_height
        && old.records.iter().all(|r| {
            new.records.iter().any(|n| {
                n.id == r.id
                    && n.to == r.to
                    && n.account == r.account
                    && n.counter == r.counter
                    && n.amount == r.amount
                    && n.rseed == r.rseed
                    && n.approvals.starts_with(&r.approvals)
                    && (r.artifact.is_none() || n.approvals == r.approvals)
                    && (r.artifact.is_none() || n.artifact == r.artifact)
            })
        })
}
pub fn restore(
    path: &Path,
    output: &Path,
    password: &str,
    witness: &Path,
    pin: &Path,
) -> Result<BackupInfo, String> {
    restore_with_hook(path, output, password, witness, pin, || Ok(()))
}
fn restore_with_hook(
    path: &Path,
    output: &Path,
    password: &str,
    witness: &Path,
    pin: &Path,
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<BackupInfo, String> {
    let (snapshot, g, store, before) = load(path, password)?;
    let w = witness::Witness::open(witness, &g)?;
    // Resolve the destination parent to reject aliases before creating staging.
    let destination = external_path(output, &[&w.directory])?;
    let pin = external_path(pin, &[&w.directory])?;
    if pin.starts_with(&destination)
        || std::fs::canonicalize(path)
            .map_err(|_| "cannot resolve backup")?
            .starts_with(&destination)
    {
        return Err("fund recovery references must be outside destination".into());
    }
    let expected = Checkpoint::read(&pin)?;
    if &expected != w.checkpoint() || !w.contains(&snapshot.checkpoint) {
        return Err("fund_checkpoint_freshness_mismatch".into());
    }
    let key = store.journal_key(password, &g.id)?;
    let mut data = decrypt(&key, &context(&g), &w.bytes).map_err(|e| e.to_string())?;
    validate(&data, &g).map_err(|e| e.to_string())?;
    if data.recovery.is_some() || !preserves(&data, &before) {
        return Err("fund witness does not preserve snapshot records".into());
    }
    w.check_data(&w.bytes, &data, &key, &g)?;
    let info = snapshot.info(&g, &data, expected.clone());
    data.recovery = Some(Recovery {
        snapshot_id: snapshot.id,
        checkpoint: expected,
        prior_final_height: before.final_height,
        prior_final_hash: before.final_hash,
    });
    let mut stage = stage_for(&destination)?;
    let dir = stage.0.as_ref().expect("stage");
    // Key rewrap changes only password encryption; seed and signature bytes stay.
    store
        .rewrap(password, password)?
        .save_new(&dir.join("key"))?;
    atomic_write_bytes(
        &dir.join("genesis.json"),
        g.to_json().as_bytes(),
        false,
        || Ok(()),
    )?;
    let journal = dir.join("payouts");
    crate::orders::archive::make_dir(&journal)?;
    atomic_write_bytes(
        &journal.join("required"),
        REQUIRED.as_bytes(),
        false,
        || Ok(()),
    )?;
    atomic_write_bytes(
        &journal.join("witness.required"),
        data.witness.as_ref().expect("witness").as_bytes(),
        false,
        || Ok(()),
    )?;
    let bytes = encrypt(&key, &context(&g), &data).map_err(|e| e.to_string())?;
    atomic_write_bytes(&journal.join("state"), &bytes, false, || Ok(()))?;
    // Witness is deliberately still locked here; validate the staged bytes directly.
    let verified = decrypt(
        &*store.journal_key(password, &g.id)?,
        &context(&g),
        &read_private_bytes(&journal.join("state"), MAX_BYTES)?,
    )
    .map_err(|e| e.to_string())?;
    if verified != data {
        return Err("restored fund read-back mismatch".into());
    }
    w.healthy()?;
    before_publish()?;
    publish(&mut stage, &destination)?;
    Ok(info)
}
/// Repair a cross-domain partial write using the independently pinned latest
/// encrypted generation. No records are fabricated and recovery remains gated.
pub fn recover_journal(
    key: &Path,
    witness: &Path,
    password: &str,
    g: &Genesis,
    pin: &Path,
) -> Result<BackupInfo, String> {
    let _lock = crate::fund_keys::lock_file(key)?;
    let dir = fund_dir(key).join("payouts");
    let _journal_lock = WalletFileLock::acquire(&dir)?;
    let store = FundKeystore::load(key)?;
    if g.params.dev_fund_keys != Some(store.open(password)?.verifying_keys()) {
        return Err("fund key does not match genesis".into());
    }
    let k = store.journal_key(password, &g.id)?;
    if read_private_bytes(&dir.join("required"), 128)?.as_slice() != REQUIRED.as_bytes() {
        return Err("fund journal sentinel missing".into());
    }
    let mut before = decrypt(
        &k,
        &context(g),
        &read_private_bytes(&dir.join("state"), MAX_BYTES)?,
    )
    .map_err(|e| e.to_string())?;
    validate(&before, g).map_err(|e| e.to_string())?;
    let w = witness::Witness::open(witness, g)?;
    w.ensure_outside(fund_dir(key))?;
    let cp = w.verify_pin(pin, fund_dir(key))?;
    if read_private_bytes(&dir.join("witness.required"), 64)?.as_slice() != cp.witness.as_bytes() {
        return Err("fund witness marker mismatch".into());
    }
    let mut data = decrypt(&k, &context(g), &w.bytes).map_err(|e| e.to_string())?;
    validate(&data, g).map_err(|e| e.to_string())?;
    w.check_data(&w.bytes, &data, &k, g)?;
    // The only permitted unwitnessed prefix is an interrupted explicit upgrade.
    if before.witness.is_none() {
        before.witness = Some(cp.witness.clone());
    }
    if data.recovery.is_some() || !preserves(&data, &before) {
        return Err("fund witness does not preserve local records".into());
    }
    let mut random = [0; 32];
    getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
    let id = crate::genesis::hex_bytes(&random);
    let info = BackupInfo {
        snapshot_id: id.clone(),
        genesis: crate::hex(&g.id),
        checkpoint: cp.clone(),
        records: data.records.len(),
        height: data.height,
        final_height: data.final_height,
        final_hash: data.final_hash.clone(),
    };
    data.recovery = Some(Recovery {
        snapshot_id: id,
        checkpoint: cp,
        prior_final_height: before
            .recovery
            .as_ref()
            .map_or(before.final_height, |r| r.prior_final_height),
        prior_final_hash: before
            .recovery
            .as_ref()
            .map_or_else(|| before.final_hash.clone(), |r| r.prior_final_hash.clone()),
    });
    let bytes = encrypt(&k, &context(g), &data).map_err(|e| e.to_string())?;
    atomic_write_bytes(&dir.join("state"), &bytes, true, || Ok(()))?;
    Ok(info)
}
#[derive(Serialize)]
pub struct RecoveryReview {
    pub committed: bool,
    pub height: u64,
    pub tip: String,
    pub checkpoint: Checkpoint,
    pub records: usize,
    pub snapshot_id: String,
}
impl Node {
    pub fn fund_recovery_required(&self) -> bool {
        self.fund_journal
            .as_ref()
            .is_some_and(|j| j.data.recovery.is_some() || j.poisoned)
    }
    pub fn reconcile_fund(
        &mut self,
        password: &str,
        height: u64,
        tip: Digest,
        pin: &Path,
        commit: bool,
    ) -> Result<RecoveryReview, String> {
        if self.height() != height || self.tip() != tip {
            return Err("fund recovery chain checkpoint mismatch".into());
        }
        let canonical = self.canonical_fund_payouts();
        let j = self.fund_journal.as_ref().ok_or("fund journal required")?;
        j.healthy().map_err(|e| e.to_string())?;
        let recovery = j
            .data
            .recovery
            .as_ref()
            .ok_or("fund recovery is not pending")?;
        let w = j.witness.as_ref().ok_or("fund witness required")?;
        let cp = w.verify_pin(pin, j.directory.parent().unwrap_or(&j.directory))?;
        if self
            .chain
            .main_hash(recovery.prior_final_height)
            .map(|h| crate::hex(&h))
            != Some(recovery.prior_final_hash.clone())
            || self.height() < j.data.height
            || self
                .chain
                .main_hash(j.data.final_height)
                .map(|h| crate::hex(&h))
                != Some(j.data.final_hash.clone())
        {
            return Err("fund recovery chain synchronization required".into());
        }
        // Every on-chain payout and retained counter must agree byte for byte.
        for ((account, counter), (p, _)) in &canonical {
            if !j.data.records.iter().any(|r| {
                r.account == *account
                    && r.counter == *counter
                    && r.payout().ok().flatten() == Some(*p)
            }) {
                return Err("fund recovery has unknown or conflicting canonical payouts".into());
            }
        }
        let mut pending: Vec<_> = j
            .data
            .records
            .iter()
            .filter(|r| !canonical.contains_key(&(r.account, r.counter)))
            .collect();
        pending.sort_by_key(|r| (r.account, r.counter));
        let mut next = [DevAccount::Direct, DevAccount::Lock].map(|a| self.dev_fund().payouts(a));
        let mut left = [DevAccount::Direct, DevAccount::Lock].map(|a| self.dev_fund().spendable(a));
        for r in pending {
            let i = r.account as usize;
            if r.counter != next[i] || r.amount > left[i] {
                return Err("fund recovery counter or balance mismatch".into());
            }
            next[i] = next[i].checked_add(1).ok_or("fund counter overflow")?;
            left[i] -= r.amount;
        }
        let mut review = RecoveryReview {
            committed: false,
            height,
            tip: crate::hex(&tip),
            checkpoint: cp,
            records: j.data.records.len(),
            snapshot_id: recovery.snapshot_id.clone(),
        };
        // Authenticate even previews; never restore a grant or signer.
        let key = self
            .fund_protection
            .as_ref()
            .ok_or("fund protection required")?
            .store
            .journal_key(password, &self.genesis.id)?;
        let j = self.fund_journal.as_mut().expect("journal");
        j.unlock(key, &self.genesis).map_err(|e| e.to_string())?;
        if commit {
            j.data.recovery = None;
            let result = j.persist().map_err(|e| e.to_string());
            j.lock();
            result?;
            review.committed = true;
            review.checkpoint = j.witness.as_ref().expect("witness").checkpoint().clone();
            self.refresh_fund_payouts();
        } else {
            j.lock();
        }
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fund_payments::tests::{
        id, open as chain, recipient, setup, unlock, Temp, PASSWORD,
    };
    fn fixture() -> (Temp, PathBuf, PathBuf, Genesis, FundKeystore) {
        let t = Temp::new();
        crate::orders::archive::make_dir(&t.0).unwrap();
        let dir = t.0.join("fund");
        crate::orders::archive::make_dir(&dir).unwrap();
        let (g, store) = setup();
        let g = Genesis::from_json(&g.to_json()).unwrap();
        let key = dir.join("key");
        store.save_new(&key).unwrap();
        initialize(&dir.join("payouts"), &store, PASSWORD, &g).unwrap();
        let w = t.0.join("witness");
        enable_witness(&key, &w, PASSWORD, &g).unwrap();
        (t, key, w, g, store)
    }
    #[test]
    fn witness_ahead_approval_is_recovered_without_reusing_its_unlock_id() {
        let (t, key, w, g, store) = fixture();
        let dir = key.parent().unwrap().join("payouts");
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .unwrap();
        unlock(&mut n);
        let mut grant = n.fund_approvals(0, 16).unwrap().approvals.remove(0).grant;
        grant.approval_id = "fe".repeat(32);
        n.lock_fund();
        n.fund_journal.as_mut().unwrap().fault = Some(6);
        assert!(n.unlock_fund(PASSWORD, &grant).is_err());
        assert!(n.fund_status().locked);
        assert!(n.dev_fund.is_none());
        drop(n);
        let mut n = chain(&g, &dir);
        assert!(n
            .protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .is_err());
        let pin = t.0.join("approval-current.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        recover_journal(&key, &w, PASSWORD, &g, &pin).unwrap();
        n.protect_dev_fund_witnessed(store, PASSWORD, &dir, &w)
            .unwrap();
        let audit = n.fund_approvals(0, 16).unwrap();
        assert_eq!(audit.approval_count, 2);
        assert_eq!(audit.approvals[1].grant.approval_id, grant.approval_id);
        assert!(audit.active_approval_id.is_none());
        assert_eq!(audit.reserved_atoms, [0, 0]);
        let height = n.height();
        let tip = n.tip();
        n.reconcile_fund(PASSWORD, height, tip, &pin, true).unwrap();
        assert!(n.unlock_fund(PASSWORD, &grant).is_err());
        assert!(n.fund_status().locked);
    }
    #[test]
    fn witness_ahead_of_local_intent_is_repaired_under_a_persistent_recovery_gate() {
        let (t, key, w, g, store) = fixture();
        let dir = key.parent().unwrap().join("payouts");
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .unwrap();
        unlock(&mut n);
        n.fund_journal.as_mut().unwrap().fault = Some(6);
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 20_000),
            Err(PayoutRefused::Journal)
        );
        assert!(n.fund_status().locked);
        drop(n);
        let mut n = chain(&g, &dir);
        assert!(n
            .protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .is_err());
        let pin = t.0.join("pin.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        recover_journal(&key, &w, PASSWORD, &g, &pin).unwrap();
        n.protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .unwrap();
        assert!(n.fund_recovery_required());
        assert_eq!(
            n.fund_payout_status(id()).unwrap().state,
            "recovery_required"
        );
        let height = n.height();
        let tip = n.tip();
        n.reconcile_fund(PASSWORD, height, tip, &pin, true).unwrap();
        unlock(&mut n);
        let p = n
            .payout(id(), DevAccount::Direct, &recipient(), 20_000)
            .unwrap();
        assert_eq!(p.counter, 0);
        drop(n);
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store, PASSWORD, &dir, &w)
            .unwrap();
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 20_000)
                .unwrap(),
            p
        );
    }
    #[test]
    fn interrupted_recovery_commit_preserves_the_latest_witness_and_can_be_repaired() {
        let (t, key, w, g, store) = fixture();
        let pin = t.0.join("before.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        recover_journal(&key, &w, PASSWORD, &g, &pin).unwrap();
        let dir = key.parent().unwrap().join("payouts");
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .unwrap();
        n.fund_journal.as_mut().unwrap().fault = Some(6);
        let h = n.height();
        let tip = n.tip();
        assert!(n.reconcile_fund(PASSWORD, h, tip, &pin, true).is_err());
        assert!(n.fund_recovery_required());
        drop(n);
        let pin = t.0.join("after.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        recover_journal(&key, &w, PASSWORD, &g, &pin).unwrap();
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store, PASSWORD, &dir, &w)
            .unwrap();
        let h = n.height();
        let tip = n.tip();
        n.reconcile_fund(PASSWORD, h, tip, &pin, true).unwrap();
        assert!(!n.fund_recovery_required());
        assert!(n.fund_status().locked);
    }
    #[test]
    fn mixed_authenticated_snapshots_and_failed_publication_leave_no_destination() {
        let (t, key, w, g, store) = fixture();
        let saved = t.0.join("saved.full");
        create(&key, &w, PASSWORD, &g, &saved).unwrap();
        let pin = t.0.join("pin.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        let destination = t.0.join("restored");
        for case in 0..3 {
            let (mut snapshot, _, _, _) = load(&saved, PASSWORD).unwrap();
            match case {
                0 => {
                    snapshot.key = FundKeystore::seal(&Digest([9; 32]), PASSWORD)
                        .unwrap()
                        .bytes()
                        .to_vec()
                }
                1 => snapshot.state[32] ^= 1,
                _ => snapshot.checkpoint.sequence += 1,
            }
            let path = t.0.join(format!("bad-{case}.full"));
            atomic_write_bytes(
                &path,
                &seal(&json(&snapshot).unwrap(), PASSWORD).unwrap(),
                false,
                || Ok(()),
            )
            .unwrap();
            assert!(restore(&path, &destination, PASSWORD, &w, &pin).is_err());
            assert!(!destination.exists());
        }
        assert!(
            restore_with_hook(&saved, &destination, PASSWORD, &w, &pin, || Err(
                "injected publication interruption".into()
            ))
            .is_err()
        );
        assert!(!destination.exists());
        assert!(!std::fs::read_dir(&t.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".si-archive-")));
        restore(&saved, &destination, PASSWORD, &w, &pin).unwrap();
        let mut n = chain(&g, &destination.join("payouts"));
        n.protect_dev_fund_witnessed(store, PASSWORD, &destination.join("payouts"), &w)
            .unwrap();
        assert!(n.fund_recovery_required());
    }
    #[test]
    fn process_exit_before_restore_publication_never_exposes_partial_custody() {
        let (t, key, w, g, _) = fixture();
        let saved = t.0.join("saved.full");
        create(&key, &w, PASSWORD, &g, &saved).unwrap();
        let pin = t.0.join("pin.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fund_payments::backup::tests::restore_crash_child",
                "--nocapture",
            ])
            .env("SI_FUND_SNAPSHOT_CRASH_ROOT", &t.0)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(73),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let dest = t.0.join("crash-restored");
        assert!(!dest.exists());
        assert!(std::fs::read_dir(&t.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".si-archive-")));
        restore(&saved, &dest, PASSWORD, &w, &pin).unwrap();
        assert!(FundKeystore::load(&dest.join("key"))
            .unwrap()
            .open(PASSWORD)
            .is_ok());
    }
    #[test]
    fn restore_crash_child() {
        let Some(root) = std::env::var_os("SI_FUND_SNAPSHOT_CRASH_ROOT").map(PathBuf::from) else {
            return;
        };
        let _ = restore_with_hook(
            &root.join("saved.full"),
            &root.join("crash-restored"),
            PASSWORD,
            &root.join("witness"),
            &root.join("pin.json"),
            || std::process::exit(73),
        );
        panic!("crash hook was not reached");
    }
    #[test]
    fn signed_witness_generation_survives_failed_local_artifact_publication() {
        let (t, key, w, g, store) = fixture();
        let dir = key.parent().unwrap().join("payouts");
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store.clone(), PASSWORD, &dir, &w)
            .unwrap();
        unlock(&mut n);
        n.fund_journal.as_mut().unwrap().fault = Some(7);
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 20_000),
            Err(PayoutRefused::Journal)
        );
        drop(n);
        let remote = witness::Witness::open(&w, &g).unwrap();
        let data = decrypt(
            &store.journal_key(PASSWORD, &g.id).unwrap(),
            &context(&g),
            &remote.bytes,
        )
        .unwrap();
        let original = data.records[0].payout().unwrap().unwrap();
        drop(remote);
        let pin = t.0.join("signed.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        recover_journal(&key, &w, PASSWORD, &g, &pin).unwrap();
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store, PASSWORD, &dir, &w)
            .unwrap();
        let h = n.height();
        let tip = n.tip();
        n.reconcile_fund(PASSWORD, h, tip, &pin, true).unwrap();
        assert!(n.fund_status().locked);
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 20_000)
                .unwrap(),
            original
        );
    }
    #[test]
    fn process_exit_between_witness_and_local_commit_recovers_without_fabricating_an_order() {
        let (t, key, w, g, store) = fixture();
        let snapshot = t.0.join("saved.full");
        create(&key, &w, PASSWORD, &g, &snapshot).unwrap();
        atomic_write_bytes(
            &t.0.join("genesis.json"),
            g.to_json().as_bytes(),
            false,
            || Ok(()),
        )
        .unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fund_payments::backup::tests::witness_crash_child",
                "--nocapture",
            ])
            .env("SI_FUND_WITNESS_CRASH_ROOT", &t.0)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(74),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let pin = t.0.join("current.json");
        export_checkpoint(&key, &w, PASSWORD, &g, &pin, None).unwrap();
        let restored = t.0.join("restored");
        let info = restore(&snapshot, &restored, PASSWORD, &w, &pin).unwrap();
        assert_eq!(info.records, 1);
        let dir = restored.join("payouts");
        // Replay the source's actual validated branch; a newly generated mock
        // chain at the same height must fail the retained finalized checkpoint.
        std::fs::copy(
            key.parent().unwrap().join("payouts/test-history"),
            dir.join("test-history"),
        )
        .unwrap();
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(store, PASSWORD, &dir, &w)
            .unwrap();
        assert!(n.fund_recovery_required());
        let h = n.height();
        let tip = n.tip();
        n.reconcile_fund(PASSWORD, h, tip, &pin, true).unwrap();
        assert_eq!(n.fund_payout_status(id()).unwrap().state, "prepared");
        unlock(&mut n);
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 20_000)
                .unwrap()
                .counter,
            0
        );
    }
    #[test]
    fn witness_crash_child() {
        let Some(root) = std::env::var_os("SI_FUND_WITNESS_CRASH_ROOT").map(PathBuf::from) else {
            return;
        };
        let g = Genesis::from_json(&std::fs::read_to_string(root.join("genesis.json")).unwrap())
            .unwrap();
        let dir = root.join("fund/payouts");
        let mut n = chain(&g, &dir);
        n.protect_dev_fund_witnessed(
            FundKeystore::load(&root.join("fund/key")).unwrap(),
            PASSWORD,
            &dir,
            &root.join("witness"),
        )
        .unwrap();
        unlock(&mut n);
        n.fund_journal.as_mut().unwrap().fault = Some(8);
        let _ = n.payout(id(), DevAccount::Direct, &recipient(), 20_000);
        panic!("witness crash hook not reached");
    }
}
