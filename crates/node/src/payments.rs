//! Encrypted, durable local payment intents. IDs never enter consensus or relay data.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use siworld_consensus::{Chain, PendingTx};
use siworld_core::codec::{decode_all, DecodeError};
use siworld_core::params::MAX_REORG_DEPTH;
use siworld_core::{Digest, Nullifier};
use siworld_crypto::Address;
use zeroize::{Zeroize, Zeroizing};

use crate::address::encode_address;
use crate::node::Node;
use crate::wallet::PayError;
use crate::wire::{decode_tx, encode_tx, TX_MAX_LEN};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("payments-v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("context-v1");
const MAX_RECORDS: usize = 65_536;
const MAX_BYTES: usize = 256 << 20;
const MAX_RECORD: usize = TX_MAX_LEN + 8192;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PaymentId([u8; 32]);
impl PaymentId {
    pub fn parse(text: &str) -> Result<Self, PaymentError> {
        crate::parse_hex(text)
            .map(Self)
            .ok_or(PaymentError::InvalidId)
    }
    pub fn random() -> Result<Self, PaymentError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PaymentError::Storage)?;
        Ok(Self(bytes))
    }
}
impl std::fmt::Display for PaymentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
impl std::fmt::Debug for PaymentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaymentId(REDACTED)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PaymentState {
    Preparing,
    Unreconciled,
    Pending,
    Confirmed,
    AnchorUnavailable,
    Conflicted,
    Expired,
    Interrupted,
    Failed,
    Cancelled,
}
impl PaymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Unreconciled => "unreconciled",
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::AnchorUnavailable => "anchor_unavailable",
            Self::Conflicted => "conflicted",
            Self::Expired => "expired",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PaymentReceipt {
    pub id: PaymentId,
    pub state: PaymentState,
    pub slot_id: Option<Digest>,
    pub confirmed_height: Option<u64>,
}
pub struct PaymentOutcome {
    pub receipt: PaymentReceipt,
    pub relay: Option<PendingTx>,
    pub relay_error: Option<crate::mempool::MempoolError>,
}
#[derive(Debug)]
pub enum PaymentError {
    InvalidId,
    Conflict,
    NotFound,
    Unavailable,
    Locked,
    Storage,
    Corrupt,
    Capacity,
    Rollback,
    Build(PayError),
    ReconciliationRequired,
    HistoryIncomplete,
    CheckpointMismatch,
    ChainBehind,
    LedgerFreshness,
}
impl PaymentError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_payment_id",
            Self::Conflict => "payment_id_conflict",
            Self::NotFound => "payment_not_found",
            Self::Unavailable => "payment_journal_required",
            Self::Locked => "wallet_locked",
            Self::Storage => "payment_storage_unavailable",
            Self::Corrupt => "payment_journal_invalid",
            Self::Capacity => "payment_journal_full",
            Self::Rollback => "payment_chain_rollback",
            Self::Build(_) => "payment_build_failed",
            Self::ReconciliationRequired => "payment_reconciliation_required",
            Self::HistoryIncomplete => "payment_history_incomplete",
            Self::CheckpointMismatch => "payment_checkpoint_mismatch",
            Self::ChainBehind => "payment_chain_sync_required",
            Self::LedgerFreshness => "order_ledger_freshness_required",
        }
    }
}
impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build(e) => e.fmt(f),
            _ => f.write_str(self.code()),
        }
    }
}
impl std::error::Error for PaymentError {}
impl From<PayError> for PaymentError {
    fn from(e: PayError) -> Self {
        if e == PayError::Locked {
            Self::Locked
        } else {
            Self::Build(e)
        }
    }
}

// Only persisted phases; confirmations are derived from the verified current chain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Preparing,
    Ready,
    Interrupted,
    Failed,
    Cancelled,
}
#[derive(Clone)]
struct Record {
    id: PaymentId,
    to: String,
    amount: u64,
    priority: bool,
    nfs: Vec<Nullifier>,
    change: u64,
    anchor_height: u64,
    phase: Phase,
    tx: Vec<u8>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.id.0.zeroize();
        self.to.zeroize();
        self.amount.zeroize();
        self.change.zeroize();
        for nf in &mut self.nfs {
            nf.0 .0.zeroize();
        }
        self.tx.zeroize();
    }
}
impl Record {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(Vec::new());
        b.extend_from_slice(&self.id.0);
        b.extend_from_slice(&(self.to.len() as u32).to_le_bytes());
        b.extend_from_slice(self.to.as_bytes());
        b.extend_from_slice(&self.amount.to_le_bytes());
        b.push(u8::from(self.priority));
        b.push(self.nfs.len() as u8);
        for nf in &self.nfs {
            b.extend_from_slice(nf.0.as_bytes());
        }
        b.extend_from_slice(&self.change.to_le_bytes());
        b.extend_from_slice(&self.anchor_height.to_le_bytes());
        b.push(match self.phase {
            Phase::Preparing => 0,
            Phase::Ready => 1,
            Phase::Interrupted => 2,
            Phase::Failed => 3,
            Phase::Cancelled => 4,
        });
        b.extend_from_slice(&(self.tx.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.tx);
        b
    }
    fn decode(b: &[u8]) -> Result<Self, PaymentError> {
        decode_all(b, |r| {
            let id = PaymentId(r.array()?);
            let n = r.length(4096)?;
            let to = std::str::from_utf8(r.take(n)?)
                .map_err(|_| DecodeError::BadValue)?
                .to_owned();
            let amount = r.u64()?;
            let priority = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::BadValue),
            };
            let count = r.u8()?;
            if count > 2 {
                return Err(DecodeError::BadValue);
            }
            let mut nfs = Vec::new();
            for _ in 0..count {
                nfs.push(Nullifier(r.digest()?));
            }
            let change = r.u64()?;
            let anchor_height = r.u64()?;
            let phase = match r.u8()? {
                0 => Phase::Preparing,
                1 => Phase::Ready,
                2 => Phase::Interrupted,
                3 => Phase::Failed,
                4 => Phase::Cancelled,
                _ => return Err(DecodeError::BadValue),
            };
            let n = r.length(TX_MAX_LEN)?;
            let tx = r.take(n)?.to_vec();
            if (phase == Phase::Cancelled && (count != 0 || change != 0 || anchor_height != 0))
                || (phase != Phase::Cancelled && count == 0)
            {
                return Err(DecodeError::BadValue);
            }
            if phase == Phase::Cancelled {
                let address = crate::address::parse_address(&to).ok_or(DecodeError::BadValue)?;
                if encode_address(&address) != to || amount == 0 {
                    return Err(DecodeError::BadValue);
                }
            }
            if (phase == Phase::Ready) == tx.is_empty() {
                return Err(DecodeError::BadValue);
            }
            if phase == Phase::Ready {
                let t = decode_tx(&tx)?;
                if nfs.iter().any(|nf| !t.slot.nf.contains(nf)) || t.slot.id() != t.proof.slot_id {
                    return Err(DecodeError::BadValue);
                }
            }
            Ok(Self {
                id,
                to,
                amount,
                priority,
                nfs,
                change,
                anchor_height,
                phase,
                tx,
            })
        })
        .map_err(|_| PaymentError::Corrupt)
    }
}
struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    records: BTreeMap<PaymentId, Record>,
    bytes: usize,
    high_water: u64,
    confirmations: BTreeMap<Digest, u64>,
    scanned: Option<u64>,
    recovery: Option<RecoveryCheckpoint>,
}
pub(crate) struct PaymentJournal {
    db: Database,
    directory: std::path::PathBuf,
    context: Vec<u8>,
    unlocked: Option<Unlocked>,
    poisoned: bool,
    recovery_pending: bool,
    recovery_marker: bool,
    #[cfg(test)]
    ready_commit_fault: Option<bool>,
    #[cfg(test)]
    install_commit_fault: Option<bool>,
}

fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, PaymentError> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| PaymentError::Storage)?;
    let mut b = plain.to_vec();
    let tag = XChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("key length"))
        .encrypt_inout_detached(
            <&XNonce>::try_from(nonce.as_slice()).expect("nonce length"),
            aad,
            b.as_mut_slice().into(),
        )
        .map_err(|_| PaymentError::Storage)?;
    let mut out = Vec::with_capacity(40 + b.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&b);
    out.extend_from_slice(&tag);
    b.zeroize();
    Ok(out)
}
fn unseal(key: &[u8; 32], aad: &[u8], b: &[u8]) -> Result<Zeroizing<Vec<u8>>, PaymentError> {
    if b.len() < 40 || b.len() > MAX_RECORD {
        return Err(PaymentError::Corrupt);
    }
    let mut plain = Zeroizing::new(b[24..b.len() - 16].to_vec());
    XChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("key length"))
        .decrypt_inout_detached(
            <&XNonce>::try_from(&b[..24]).expect("nonce length"),
            aad,
            plain.as_mut_slice().into(),
            &Tag::try_from(&b[b.len() - 16..]).expect("tag length"),
        )
        .map_err(|_| PaymentError::Corrupt)?;
    Ok(plain)
}
#[cfg(unix)]
fn journal_file(path: &Path) -> Result<std::fs::File, PaymentError> {
    use rustix::fs::{open, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let parent = path.parent().ok_or(PaymentError::Storage)?;
    let m = std::fs::symlink_metadata(parent).map_err(|_| PaymentError::Storage)?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(PaymentError::Storage);
    }
    let fd = open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| PaymentError::Storage)?;
    let file = std::fs::File::from(fd);
    let m = file.metadata().map_err(|_| PaymentError::Storage)?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(PaymentError::Storage);
    }
    std::fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| PaymentError::Storage)?;
    Ok(file)
}
#[cfg(not(unix))]
fn journal_file(_: &Path) -> Result<std::fs::File, PaymentError> {
    Err(PaymentError::Storage)
}
impl PaymentJournal {
    fn open(
        path: &Path,
        network: &Digest,
        owner: &Digest,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, PaymentError> {
        let mut context = b"siworld payment journal v1:xchacha20poly1305".to_vec();
        context.extend_from_slice(network.as_bytes());
        context.extend_from_slice(owner.as_bytes());
        // A separate durable sentinel detects accidental loss/truncation of an
        // initialized journal. It is not protection against coordinated rollback.
        let marker = path.with_extension("required");
        let required = std::fs::symlink_metadata(&marker).is_ok();
        let recovery_path = path
            .parent()
            .ok_or(PaymentError::Storage)?
            .join("recovery.required");
        let recovery_marker = std::fs::symlink_metadata(&recovery_path).is_ok();
        if recovery_marker
            && (*crate::secrets::read_secret(&recovery_path).map_err(|_| PaymentError::Storage)?
                != "siworld full wallet recovery v1\n"
                || !required)
        {
            return Err(PaymentError::Corrupt);
        }
        if required {
            if *crate::secrets::read_secret(&marker).map_err(|_| PaymentError::Storage)?
                != "siworld payment journal required v1\n"
            {
                return Err(PaymentError::Corrupt);
            }
            if std::fs::symlink_metadata(path)
                .map_err(|_| PaymentError::Storage)?
                .len()
                == 0
            {
                return Err(PaymentError::Corrupt);
            }
        }
        let file = journal_file(path)?;
        let new = file.metadata().map_err(|_| PaymentError::Storage)?.len() == 0;
        let db = Database::builder()
            .set_cache_size(8 << 20)
            .create_file(file)
            .map_err(|_| PaymentError::Storage)?;
        let mut journal = Self {
            directory: std::fs::canonicalize(path.parent().ok_or(PaymentError::Storage)?)
                .map_err(|_| PaymentError::Storage)?,
            db,
            context,
            unlocked: None,
            poisoned: false,
            recovery_pending: false,
            recovery_marker,
            #[cfg(test)]
            ready_commit_fault: None,
            #[cfg(test)]
            install_commit_fault: None,
        };
        if new {
            journal.write(None, Some((key.as_ref(), 0)))?;
        }
        journal.unlock(key)?;
        if !required {
            crate::secrets::write_secret(&marker, "siworld payment journal required v1\n")
                .map_err(|_| PaymentError::Storage)?;
            std::fs::File::open(path.parent().ok_or(PaymentError::Storage)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| PaymentError::Storage)?;
        }
        Ok(journal)
    }
    pub(crate) fn check(&self) -> Result<(), PaymentError> {
        if self.poisoned {
            Err(PaymentError::Storage)
        } else if self.unlocked.is_none() {
            Err(PaymentError::Locked)
        } else {
            Ok(())
        }
    }
    pub(crate) fn lock(&mut self) {
        self.unlocked = None;
    }
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }
    pub(crate) fn unlock(&mut self, key: Zeroizing<[u8; 32]>) -> Result<(), PaymentError> {
        if self.poisoned {
            return Err(PaymentError::Storage);
        }
        let read = self.db.begin_read().map_err(|_| PaymentError::Storage)?;
        let meta = read.open_table(META).map_err(|_| PaymentError::Corrupt)?;
        let b = meta
            .get("height")
            .map_err(|_| PaymentError::Storage)?
            .ok_or(PaymentError::Corrupt)?;
        let plain = unseal(&key, &self.context, b.value())?;
        let high_water = u64::from_le_bytes(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| PaymentError::Corrupt)?,
        );
        let recovery = meta
            .get("recovery")
            .map_err(|_| PaymentError::Storage)?
            .map(|v| {
                unseal(&key, &self.aad(b"recovery"), v.value())
                    .and_then(|b| RecoveryCheckpoint::decode(&b))
            })
            .transpose()?;
        if self.recovery_marker && recovery.is_none() {
            return Err(PaymentError::Corrupt);
        }
        self.recovery_pending = recovery.as_ref().is_some_and(|r| r.reviewed_at.is_none());
        let table = read
            .open_table(RECORDS)
            .map_err(|_| PaymentError::Corrupt)?;
        let mut records = BTreeMap::new();
        let mut bytes = 0;
        for entry in table.iter().map_err(|_| PaymentError::Storage)? {
            let (index, b) = entry.map_err(|_| PaymentError::Storage)?;
            if records.len() >= MAX_RECORDS || b.value().len() > MAX_RECORD {
                return Err(PaymentError::Capacity);
            }
            bytes += b.value().len();
            if bytes > MAX_BYTES {
                return Err(PaymentError::Capacity);
            }
            let aad = self.aad(index.value());
            let plain = unseal(&key, &aad, b.value())?;
            let record = Record::decode(&plain)?;
            if index.value() != blake3::keyed_hash(&key, &record.id.0).as_bytes() {
                return Err(PaymentError::Corrupt);
            }
            records.insert(record.id, record);
        }
        self.unlocked = Some(Unlocked {
            key,
            records,
            bytes,
            high_water,
            confirmations: BTreeMap::new(),
            scanned: None,
            recovery,
        });
        let drafts: Vec<_> = self
            .unlocked
            .as_ref()
            .expect("unlocked")
            .records
            .values()
            .filter(|r| r.phase == Phase::Preparing)
            .cloned()
            .collect();
        for mut r in drafts {
            r.phase = Phase::Interrupted;
            self.persist(r)?;
        }
        Ok(())
    }
    fn aad(&self, index: &[u8]) -> Vec<u8> {
        let mut aad = self.context.clone();
        aad.extend_from_slice(index);
        aad
    }
    fn write(
        &mut self,
        record: Option<(&[u8], &[u8])>,
        meta: Option<(&[u8], u64)>,
    ) -> Result<(), PaymentError> {
        let result = (|| {
            let mut tx = self.db.begin_write().map_err(|_| PaymentError::Storage)?;
            tx.set_durability(Durability::Immediate)
                .map_err(|_| PaymentError::Storage)?;
            {
                let mut table = tx.open_table(RECORDS).map_err(|_| PaymentError::Storage)?;
                if let Some((i, b)) = record {
                    table.insert(i, b).map_err(|_| PaymentError::Storage)?;
                }
            }
            {
                let mut table = tx.open_table(META).map_err(|_| PaymentError::Storage)?;
                if let Some((key, height)) = meta {
                    let b = seal(
                        key.try_into().map_err(|_| PaymentError::Storage)?,
                        &self.context,
                        &height.to_le_bytes(),
                    )?;
                    table
                        .insert("height", b.as_slice())
                        .map_err(|_| PaymentError::Storage)?;
                }
            }
            tx.commit().map_err(|_| PaymentError::Storage)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn persist(&mut self, r: Record) -> Result<(), PaymentError> {
        self.check()?;
        let u = self.unlocked.as_ref().expect("unlocked");
        let index = blake3::keyed_hash(&u.key, &r.id.0);
        let b = seal(&u.key, &self.aad(index.as_bytes()), &r.encode())?;
        let old = u.records.get(&r.id).map_or(0, |r| r.encode().len() + 40);
        if (old == 0 && u.records.len() >= MAX_RECORDS)
            || b.len() > MAX_RECORD
            || u.bytes - old + b.len() > MAX_BYTES
        {
            return Err(PaymentError::Capacity);
        }
        #[cfg(test)]
        let fault = if r.phase == Phase::Ready {
            self.ready_commit_fault.take()
        } else {
            None
        };
        #[cfg(test)]
        if fault == Some(false) {
            self.poisoned = true;
            return Err(PaymentError::Storage);
        }
        self.write(Some((index.as_bytes(), &b)), None)?;
        #[cfg(test)]
        if fault == Some(true) {
            self.poisoned = true;
            return Err(PaymentError::Storage);
        }
        let u = self.unlocked.as_mut().expect("unlocked");
        u.bytes = u.bytes - old + b.len();
        u.records.insert(r.id, r);
        Ok(())
    }
    fn get(&self, id: PaymentId) -> Result<&Record, PaymentError> {
        self.check()?;
        self.unlocked
            .as_ref()
            .expect("unlocked")
            .records
            .get(&id)
            .ok_or(PaymentError::NotFound)
    }
    fn sync(
        &mut self,
        chain: &Chain<std::sync::Arc<dyn siworld_circuits::ProofSystem>>,
        reset: bool,
    ) -> Result<(), PaymentError> {
        self.check()?;
        let height = chain.state.height;
        let u = self.unlocked.as_ref().expect("unlocked");
        if !self.recovery_pending && height.saturating_add(MAX_REORG_DEPTH) < u.high_water {
            return Err(PaymentError::Rollback);
        }
        if height > u.high_water {
            let key = Zeroizing::new(*u.key);
            self.write(None, Some((key.as_ref(), height)))?;
            self.unlocked.as_mut().expect("unlocked").high_water = height;
        }
        let u = self.unlocked.as_mut().expect("unlocked");
        if reset {
            u.scanned = None;
            u.confirmations.clear();
        }
        let ids: BTreeSet<_> = u
            .records
            .values()
            .filter(|r| r.phase == Phase::Ready)
            .map(|r| decode_tx(&r.tx).expect("validated record").slot.id())
            .collect();
        for h in u.scanned.map_or(1, |h| h + 1)..=height {
            let hash = chain.main_hash(h).ok_or(PaymentError::Corrupt)?;
            let block = chain.block(&hash).ok_or(PaymentError::Corrupt)?;
            for slot in &block.body.slots {
                let id = slot.id();
                if ids.contains(&id) {
                    u.confirmations.insert(id, h);
                }
            }
        }
        u.scanned = Some(height);
        Ok(())
    }
    fn receipt_unchecked(
        &self,
        r: &Record,
        state: &siworld_state::ChainState,
        window: u64,
    ) -> PaymentReceipt {
        let (mut slot_id, mut confirmed_height) = (None, None);
        let status = match r.phase {
            Phase::Preparing => PaymentState::Preparing,
            Phase::Interrupted => PaymentState::Interrupted,
            Phase::Failed => PaymentState::Failed,
            Phase::Cancelled => PaymentState::Cancelled,
            Phase::Ready => {
                let tx = decode_tx(&r.tx).expect("validated record");
                let id = tx.slot.id();
                slot_id = Some(id);
                confirmed_height = self
                    .unlocked
                    .as_ref()
                    .expect("unlocked")
                    .confirmations
                    .get(&id)
                    .copied();
                if confirmed_height.is_some() {
                    PaymentState::Confirmed
                } else if state.height
                    > r.anchor_height
                        .saturating_add(window)
                        .saturating_add(MAX_REORG_DEPTH)
                {
                    PaymentState::Expired
                } else if tx.slot.nf.iter().any(|nf| state.nullifiers.contains(nf)) {
                    PaymentState::Conflicted
                } else if state.anchors.height_of(&tx.proof.anchor).is_none() {
                    PaymentState::AnchorUnavailable
                } else {
                    PaymentState::Pending
                }
            }
        };
        PaymentReceipt {
            id: r.id,
            state: status,
            slot_id,
            confirmed_height,
        }
    }
    fn receipt(
        &self,
        r: &Record,
        state: &siworld_state::ChainState,
        window: u64,
    ) -> PaymentReceipt {
        if self.recovery_pending {
            PaymentReceipt {
                id: r.id,
                state: PaymentState::Unreconciled,
                slot_id: if r.phase == Phase::Ready {
                    Some(decode_tx(&r.tx).expect("validated record").slot.id())
                } else {
                    None
                },
                confirmed_height: None,
            }
        } else {
            self.receipt_unchecked(r, state, window)
        }
    }
    fn reservations(
        &self,
        state: &siworld_state::ChainState,
        window: u64,
    ) -> (BTreeSet<Nullifier>, BTreeMap<Nullifier, u64>) {
        let mut reserved = BTreeSet::new();
        let mut change = BTreeMap::new();
        for r in self.unlocked.as_ref().expect("unlocked").records.values() {
            let receipt = self.receipt(r, state, window);
            if matches!(
                receipt.state,
                PaymentState::Preparing
                    | PaymentState::Unreconciled
                    | PaymentState::Pending
                    | PaymentState::AnchorUnavailable
                    | PaymentState::Conflicted
                    | PaymentState::Confirmed
            ) {
                reserved.extend(r.nfs.iter().copied());
                if receipt.state == PaymentState::Pending && r.change != 0 {
                    change.insert(r.nfs[0], r.change);
                }
            }
        }
        (reserved, change)
    }
}
impl Node {
    pub fn enable_payment_journal(&mut self, path: &Path) -> Result<(), PaymentError> {
        if self.payments.is_some() {
            return Err(PaymentError::Unavailable);
        }
        let key = self.wallets.journal_key(&self.genesis.id)?;
        self.payments = Some(PaymentJournal::open(
            path,
            &self.genesis.id,
            &self.address().owner(),
            key,
        )?);
        self.refresh_payments(true)
    }
    pub(crate) fn refresh_payments(&mut self, reset: bool) -> Result<(), PaymentError> {
        if self.wallet_is_locked() {
            return Ok(());
        }
        if let Some(j) = &mut self.payments {
            if let Err(e) = j.sync(&self.chain, reset) {
                j.poison();
                return Err(e);
            }
            let (reserved, change) =
                j.reservations(&self.chain.state, self.chain.params.anchor_window as u64);
            self.wallets.durable_reservations(reserved, change);
        }
        Ok(())
    }
    pub fn payment(&mut self, id: PaymentId) -> Result<PaymentReceipt, PaymentError> {
        self.expire_wallet(Instant::now());
        if self.wallet_is_locked() {
            return Err(PaymentError::Locked);
        }
        self.refresh_payments(false)?;
        let j = self.payments.as_ref().ok_or(PaymentError::Unavailable)?;
        let r = j.get(id)?;
        Ok(j.receipt(r, &self.chain.state, self.chain.params.anchor_window as u64))
    }
    pub fn pay_with_id(
        &mut self,
        id: PaymentId,
        to: &Address,
        amount: u64,
        priority: bool,
    ) -> Result<PaymentOutcome, PaymentError> {
        self.expire_wallet(Instant::now());
        if self.wallet_is_locked() {
            return Err(PaymentError::Locked);
        }
        self.refresh_payments(false)?;
        let j = self.payments.as_ref().ok_or(PaymentError::Unavailable)?;
        j.check()?;
        if j.recovery_pending {
            return Err(PaymentError::ReconciliationRequired);
        }
        let recipient = encode_address(to);
        match j.get(id) {
            Ok(r) => {
                if r.to != recipient || r.amount != amount || r.priority != priority {
                    return Err(PaymentError::Conflict);
                }
            }
            Err(PaymentError::NotFound) => {
                let plan = self
                    .wallets
                    .prepare_payment(&self.chain.state, 0, amount, priority)?;
                // Serial node dispatch + one immediate database transaction commits the
                // complete selection before any proof or externally visible artifact.
                let record = Record {
                    id,
                    to: recipient,
                    amount,
                    priority,
                    nfs: plan.nfs.clone(),
                    change: plan.change,
                    anchor_height: plan.anchor_height,
                    phase: Phase::Preparing,
                    tx: Vec::new(),
                };
                self.payments
                    .as_mut()
                    .expect("journal")
                    .persist(record.clone())?;
                self.refresh_payments(false)?;
                let built = self.wallets.prove_payment(
                    &self.chain.state,
                    &self.chain.params,
                    &self.mempool.tx_pow(),
                    self.system.as_ref(),
                    to,
                    amount,
                    &plan,
                );
                let mut record = record;
                match built {
                    Ok(tx) => {
                        self.wallets.release(&tx.slot); // only remove the legacy live overlay
                        record.phase = Phase::Ready;
                        record.tx = encode_tx(&tx);
                        self.payments.as_mut().expect("journal").persist(record)?;
                    }
                    Err(e) => {
                        record.phase = Phase::Failed;
                        self.payments.as_mut().expect("journal").persist(record)?;
                        self.refresh_payments(false)?;
                        return Err(e.into());
                    }
                }
            }
            Err(e) => return Err(e),
        }
        self.refresh_payments(false)?;
        let j = self.payments.as_ref().expect("journal");
        let r = j.get(id)?;
        let receipt = j.receipt(r, &self.chain.state, self.chain.params.anchor_window as u64);
        let (mut relay, mut relay_error) = (None, None);
        if receipt.state == PaymentState::Pending {
            let tx = decode_tx(&r.tx).map_err(|_| PaymentError::Corrupt)?;
            if self.mempool.contains_slot(&tx.slot.id()) {
                relay = Some(tx);
            } else {
                match self.submit_tx(tx.clone(), None) {
                    Ok(()) => relay = Some(tx),
                    Err(e) => relay_error = Some(e),
                }
            }
        }
        Ok(PaymentOutcome {
            receipt,
            relay,
            relay_error,
        })
    }
}

/// The application's separately retained, accepted payment intents. These
/// records are deliberately not inferred from a restored snapshot.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentOrder {
    pub payment_id: String,
    pub to: String,
    pub amount: String,
    pub priority: bool,
}
impl PaymentOrder {
    pub fn new(id: PaymentId, to: &Address, amount: u64, priority: bool) -> Self {
        Self {
            payment_id: id.to_string(),
            to: encode_address(to),
            amount: crate::amount::format_sip(amount),
            priority,
        }
    }
}

/// Read an independently retained order ledger, with private-file and parser
/// bounds. This does not establish that the application supplied its latest copy.
pub fn load_payment_orders(path: &Path) -> Result<Vec<PaymentOrder>, String> {
    use serde::Deserialize;
    let bytes = Zeroizing::new(crate::secrets::read_private_bytes(path, MAX_BYTES)?);
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    let orders =
        BoundedOrders::deserialize(&mut decoder).map_err(|_| "invalid payment order ledger")?;
    decoder
        .end()
        .map_err(|_| "trailing data in payment order ledger")?;
    Ok(orders.0)
}

pub(crate) struct BoundedOrders(pub Vec<PaymentOrder>);
impl<'de> serde::Deserialize<'de> for BoundedOrders {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct Orders;
        impl<'de> Visitor<'de> for Orders {
            type Value = Vec<PaymentOrder>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded array of payment orders")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut orders = Vec::new();
                while let Some(order) = seq.next_element::<PaymentOrder>()? {
                    if orders.len() >= MAX_RECORDS
                        || order.payment_id.len() != 64
                        || order.to.len() > 4096
                        || order.amount.len() > 64
                    {
                        return Err(A::Error::custom("order ledger exceeds limits"));
                    }
                    orders.push(order);
                }
                Ok(orders)
            }
        }
        decoder.deserialize_seq(Orders).map(Self)
    }
}
impl Drop for PaymentOrder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.payment_id.zeroize();
        self.to.zeroize();
        self.amount.zeroize();
    }
}

#[derive(serde::Serialize)]
pub struct MissingOrder {
    pub payment_id: String,
    pub state: crate::orders::OrderState,
}
pub struct Reconciliation {
    pub committable: bool,
    pub missing_orders: Vec<MissingOrder>,
    pub cancelled_tombstones: usize,
    pub receipts: Vec<PaymentReceipt>,
    pub committed: bool,
    pub height: u64,
    pub tip: Digest,
    pub orders_hash: Digest,
    pub order_checkpoint: Option<crate::orders::Checkpoint>,
}

#[derive(Clone)]
pub(crate) struct RecoveryCheckpoint {
    pub snapshot_id: Digest,
    pub height: u64,
    pub tip: Digest,
    pub final_height: u64,
    pub final_hash: Digest,
    pub reviewed_at: Option<(u64, Digest, Digest)>,
}
impl RecoveryCheckpoint {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(self.snapshot_id.as_bytes());
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(self.tip.as_bytes());
        b.extend_from_slice(&self.final_height.to_le_bytes());
        b.extend_from_slice(self.final_hash.as_bytes());
        if let Some((h, t, o)) = self.reviewed_at {
            b.push(1);
            b.extend_from_slice(&h.to_le_bytes());
            b.extend_from_slice(t.as_bytes());
            b.extend_from_slice(o.as_bytes());
        } else {
            b.push(0);
        }
        b
    }
    fn decode(b: &[u8]) -> Result<Self, PaymentError> {
        decode_all(b, |r| {
            let snapshot_id = r.digest()?;
            let height = r.u64()?;
            let tip = r.digest()?;
            let final_height = r.u64()?;
            let final_hash = r.digest()?;
            let reviewed_at = match r.u8()? {
                0 => None,
                1 => Some((r.u64()?, r.digest()?, r.digest()?)),
                _ => return Err(DecodeError::BadValue),
            };
            if final_height > height {
                return Err(DecodeError::BadValue);
            }
            Ok(Self {
                snapshot_id,
                height,
                tip,
                final_height,
                final_hash,
                reviewed_at,
            })
        })
        .map_err(|_| PaymentError::Corrupt)
    }
}
pub(crate) struct JournalSnapshot {
    pub high_water: u64,
    records: BTreeMap<PaymentId, Record>,
}
impl JournalSnapshot {
    pub(crate) fn artifact(&self, id: PaymentId) -> Option<&[u8]> {
        self.records.get(&id).map(|r| r.tx.as_slice())
    }
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(Vec::new());
        b.extend_from_slice(&self.high_water.to_le_bytes());
        b.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for r in self.records.values() {
            let bytes = r.encode();
            b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            b.extend_from_slice(&bytes);
        }
        b
    }
    pub(crate) fn preserves(&self, original: &Self) -> bool {
        original.records.iter().all(|(id, record)| {
            self.records
                .get(id)
                .is_some_and(|r| r.encode() == record.encode())
        })
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PaymentError> {
        if bytes.len() > MAX_BYTES {
            return Err(PaymentError::Capacity);
        }
        decode_all(bytes, |r| {
            let high_water = r.u64()?;
            let count = r.length(MAX_RECORDS)?;
            let mut records = BTreeMap::new();
            let mut total = 0;
            for _ in 0..count {
                let n = r.length(MAX_RECORD - 40)?;
                total += n + 40;
                if total > MAX_BYTES {
                    return Err(DecodeError::TooLong);
                }
                let record = Record::decode(r.take(n)?).map_err(|_| DecodeError::BadValue)?;
                if record.anchor_height > high_water || records.insert(record.id, record).is_some()
                {
                    return Err(DecodeError::BadValue);
                }
            }
            Ok(Self {
                high_water,
                records,
            })
        })
        .map_err(|_| PaymentError::Corrupt)
    }
}
impl PaymentJournal {
    fn snapshot(&self) -> Result<JournalSnapshot, PaymentError> {
        self.check()?;
        let u = self.unlocked.as_ref().expect("unlocked");
        Ok(JournalSnapshot {
            high_water: u.high_water,
            records: u.records.clone(),
        })
    }
    // Re-encrypt and publish every record plus high-water/recovery metadata in
    // one transaction. Used for restore, merge and reconciliation commits.
    fn install(
        &mut self,
        snapshot: JournalSnapshot,
        recovery: RecoveryCheckpoint,
    ) -> Result<(), PaymentError> {
        self.check()?;
        let u = self.unlocked.as_ref().expect("unlocked");
        let key = Zeroizing::new(*u.key);
        let mut rows = Vec::new();
        let mut bytes = 0;
        if snapshot.records.len() > MAX_RECORDS {
            return Err(PaymentError::Capacity);
        }
        for r in snapshot.records.values() {
            let index = *blake3::keyed_hash(&key, &r.id.0).as_bytes();
            let b = seal(&key, &self.aad(&index), &r.encode())?;
            bytes += b.len();
            if b.len() > MAX_RECORD || bytes > MAX_BYTES {
                return Err(PaymentError::Capacity);
            }
            rows.push((index, b));
        }
        let height = seal(&key, &self.context, &snapshot.high_water.to_le_bytes())?;
        let gate = seal(&key, &self.aad(b"recovery"), &recovery.encode())?;
        #[cfg(test)]
        let fault = self.install_commit_fault.take();
        let result = (|| {
            let mut tx = self.db.begin_write().map_err(|_| PaymentError::Storage)?;
            tx.set_durability(Durability::Immediate)
                .map_err(|_| PaymentError::Storage)?;
            {
                let mut table = tx.open_table(RECORDS).map_err(|_| PaymentError::Storage)?;
                table
                    .retain(|_, _| false)
                    .map_err(|_| PaymentError::Storage)?;
                for (i, b) in &rows {
                    table
                        .insert(i.as_slice(), b.as_slice())
                        .map_err(|_| PaymentError::Storage)?;
                }
            }
            {
                let mut table = tx.open_table(META).map_err(|_| PaymentError::Storage)?;
                table
                    .insert("height", height.as_slice())
                    .map_err(|_| PaymentError::Storage)?;
                table
                    .insert("recovery", gate.as_slice())
                    .map_err(|_| PaymentError::Storage)?;
            }
            #[cfg(test)]
            if fault == Some(false) {
                return Err(PaymentError::Storage);
            }
            tx.commit().map_err(|_| PaymentError::Storage)?;
            #[cfg(test)]
            if fault == Some(true) {
                return Err(PaymentError::Storage);
            }
            Ok(())
        })();
        if result.is_err() {
            self.poison();
            return result;
        }
        self.recovery_pending = recovery.reviewed_at.is_none();
        self.unlocked = Some(Unlocked {
            key,
            records: snapshot.records,
            bytes,
            high_water: snapshot.high_water,
            confirmations: BTreeMap::new(),
            scanned: None,
            recovery: Some(recovery),
        });
        Ok(())
    }
}
impl Node {
    pub fn payment_recovery_required(&self) -> bool {
        self.payments.as_ref().is_some_and(|j| j.recovery_pending)
    }
    pub(crate) fn payment_snapshot(&mut self) -> Result<JournalSnapshot, PaymentError> {
        self.refresh_payments(false)?;
        self.payments
            .as_ref()
            .ok_or(PaymentError::Unavailable)?
            .snapshot()
    }
    pub(crate) fn restore_payment_snapshot(
        &mut self,
        snapshot: JournalSnapshot,
        recovery: RecoveryCheckpoint,
    ) -> Result<(), PaymentError> {
        self.payments
            .as_mut()
            .ok_or(PaymentError::Unavailable)?
            .install(snapshot, recovery)?;
        self.refresh_payments(true)
    }
    fn check_recovery_checkpoint(
        &self,
        r: &RecoveryCheckpoint,
        high_water: u64,
    ) -> Result<(), PaymentError> {
        if self.height() < r.height.max(high_water) {
            return Err(PaymentError::ChainBehind);
        }
        if self.chain.main_hash(r.final_height) != Some(r.final_hash) {
            return Err(PaymentError::CheckpointMismatch);
        }
        Ok(())
    }
    pub(crate) fn merge_payment_snapshot(
        &mut self,
        other: JournalSnapshot,
        checkpoint: &RecoveryCheckpoint,
    ) -> Result<(), PaymentError> {
        if !self.payment_recovery_required() {
            return Err(PaymentError::ReconciliationRequired);
        }
        self.check_recovery_checkpoint(checkpoint, other.high_water)?;
        let j = self.payments.as_ref().ok_or(PaymentError::Unavailable)?;
        let recovery = j
            .unlocked
            .as_ref()
            .ok_or(PaymentError::Locked)?
            .recovery
            .clone()
            .ok_or(PaymentError::Corrupt)?;
        self.check_recovery_checkpoint(
            &recovery,
            j.unlocked.as_ref().expect("unlocked").high_water,
        )?;
        let mut snapshot = j.snapshot()?;
        snapshot.high_water = snapshot.high_water.max(other.high_water);
        for (id, incoming) in other.records {
            if let Some(current) = snapshot.records.get(&id) {
                if current.to != incoming.to
                    || current.amount != incoming.amount
                    || current.priority != incoming.priority
                    || current.nfs != incoming.nfs
                    || current.change != incoming.change
                    || current.anchor_height != incoming.anchor_height
                    || (current.phase == Phase::Ready
                        && incoming.phase == Phase::Ready
                        && current.tx != incoming.tx)
                {
                    return Err(PaymentError::Conflict);
                }
                if current.phase == Phase::Ready || incoming.phase == Phase::Preparing {
                    continue;
                }
            }
            snapshot.records.insert(id, incoming);
        }
        // Imported drafts could never have been exposed without a ready commit.
        for r in snapshot.records.values_mut() {
            if r.phase == Phase::Preparing {
                r.phase = Phase::Interrupted;
            }
        }
        self.restore_payment_snapshot(snapshot, recovery)
    }
    pub fn reconcile_payments(
        &mut self,
        verified: &crate::orders::VerifiedOrders<'_>,
        expected_height: u64,
        expected_tip: Digest,
        commit: bool,
    ) -> Result<Reconciliation, PaymentError> {
        let directory = &self
            .payments
            .as_ref()
            .ok_or(PaymentError::Unavailable)?
            .directory;
        verified
            .ensure_outside(directory)
            .map_err(|_| PaymentError::LedgerFreshness)?;
        let cp = verified.checkpoint();
        if cp.genesis != crate::hex(&self.genesis.id)
            || cp.owner != crate::hex(&self.address().owner())
        {
            return Err(PaymentError::LedgerFreshness);
        }
        self.reconcile_records(
            verified.orders(),
            expected_height,
            expected_tip,
            commit,
            Some((cp, verified.states())),
        )
    }
    /// Unversioned order arrays are useful only for an initial private preview.
    pub fn preview_payment_orders(
        &mut self,
        orders: &[PaymentOrder],
        expected_height: u64,
        expected_tip: Digest,
    ) -> Result<Reconciliation, PaymentError> {
        self.reconcile_records(orders, expected_height, expected_tip, false, None)
    }
    fn reconcile_records(
        &mut self,
        orders: &[PaymentOrder],
        expected_height: u64,
        expected_tip: Digest,
        commit: bool,
        ledger: Option<(
            &crate::orders::Checkpoint,
            BTreeMap<PaymentId, crate::orders::OrderState>,
        )>,
    ) -> Result<Reconciliation, PaymentError> {
        let checkpoint = ledger.as_ref().map(|(cp, _)| *cp);
        if commit && checkpoint.is_none() {
            return Err(PaymentError::LedgerFreshness);
        }
        self.expire_wallet(Instant::now());
        if self.wallet_is_locked() {
            return Err(PaymentError::Locked);
        }
        self.refresh_payments(false)?;
        if self.height() != expected_height || self.tip() != expected_tip {
            return Err(PaymentError::CheckpointMismatch);
        }
        let j = self.payments.as_ref().ok_or(PaymentError::Unavailable)?;
        j.check()?;
        let u = j.unlocked.as_ref().expect("unlocked");
        let mut recovery = u
            .recovery
            .clone()
            .ok_or(PaymentError::ReconciliationRequired)?;
        self.check_recovery_checkpoint(&recovery, u.high_water)?;
        if orders.len() > MAX_RECORDS {
            return Err(PaymentError::Capacity);
        }
        let mut canonical = BTreeMap::new();
        for order in orders {
            let id = PaymentId::parse(&order.payment_id)?;
            let to = crate::address::parse_address(&order.to).ok_or(PaymentError::Conflict)?;
            let amount = crate::amount::parse_sip(&order.amount).ok_or(PaymentError::Conflict)?;
            if canonical
                .insert(id, (encode_address(&to), amount, order.priority))
                .is_some()
            {
                return Err(PaymentError::Conflict);
            }
        }
        // Journal evidence must never disappear, even when an external order was cancelled.
        if u.records.keys().any(|id| !canonical.contains_key(id)) {
            return Err(PaymentError::HistoryIncomplete);
        }
        let states = ledger.as_ref().map(|(_, states)| states);
        let mut snapshot = j.snapshot()?;
        let mut missing_orders = Vec::new();
        let mut cancelled_tombstones = 0;
        let mut committable = checkpoint.is_some();
        for (id, (to, amount, priority)) in &canonical {
            let state = states
                .and_then(|s| s.get(id))
                .copied()
                .unwrap_or(crate::orders::OrderState::LegacyUnknown);
            if let Some(record) = snapshot.records.get(id) {
                if states.is_some()
                    && (state == crate::orders::OrderState::CancelledUnsubmitted)
                        != (record.phase == Phase::Cancelled)
                {
                    return Err(PaymentError::Conflict);
                }
            } else {
                missing_orders.push(MissingOrder {
                    payment_id: id.to_string(),
                    state,
                });
                if state == crate::orders::OrderState::CancelledUnsubmitted {
                    snapshot.records.insert(
                        *id,
                        Record {
                            id: *id,
                            to: to.clone(),
                            amount: *amount,
                            priority: *priority,
                            nfs: Vec::new(),
                            change: 0,
                            anchor_height: 0,
                            phase: Phase::Cancelled,
                            tx: Vec::new(),
                        },
                    );
                    cancelled_tombstones += 1;
                } else {
                    committable = false;
                }
            }
        }
        if commit && !committable {
            return Err(PaymentError::HistoryIncomplete);
        }
        let mut hash =
            blake3::Hasher::new_derive_key("siworld restored payment order reconciliation v1");
        hash.update(self.genesis.id.as_bytes());
        // Bind the externally reviewed ledger identity/revision/head into the
        // persisted reconciliation digest in the same gate-clearing transaction.
        if let Some(cp) = checkpoint {
            hash.update(b"independent-order-checkpoint-v1");
            hash.update(&serde_json::to_vec(cp).map_err(|_| PaymentError::Corrupt)?);
        }
        let mut receipts = Vec::new();
        for (id, (to, amount, priority)) in canonical {
            if let Some(r) = snapshot.records.get(&id) {
                if r.to != to || r.amount != amount || r.priority != priority {
                    return Err(PaymentError::Conflict);
                }
            }
            hash.update(&id.0);
            hash.update(&(to.len() as u32).to_le_bytes());
            hash.update(to.as_bytes());
            hash.update(&amount.to_le_bytes());
            hash.update(&[u8::from(priority)]);
            let Some(r) = snapshot.records.get(&id) else {
                continue;
            };
            receipts.push(j.receipt_unchecked(
                r,
                &self.chain.state,
                self.chain.params.anchor_window as u64,
            ));
        }
        let orders_hash = Digest(*hash.finalize().as_bytes());
        if commit {
            recovery.reviewed_at = Some((self.height(), self.tip(), orders_hash));
            self.restore_payment_snapshot(snapshot, recovery)?;
        }
        Ok(Reconciliation {
            committable,
            missing_orders,
            cancelled_tombstones,
            receipts,
            committed: commit,
            height: self.height(),
            tip: self.tip(),
            orders_hash,
            order_checkpoint: checkpoint.cloned(),
        })
    }
}

pub(crate) fn restore_journal(
    path: &Path,
    key: &siworld_crypto::SpendKey,
    network: &Digest,
    snapshot: JournalSnapshot,
    recovery: RecoveryCheckpoint,
) -> Result<(), PaymentError> {
    let derived = crate::wallet::journal_key_from_spend_key(key, network);
    let mut journal = PaymentJournal::open(path, network, &key.owner(), derived)?;
    journal.install(snapshot, recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
    use siworld_circuits::MockProver;
    use siworld_crypto::{SecretSeed, SpendKey};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    pub(super) struct Temp(pub(super) std::path::PathBuf);
    impl Temp {
        pub(super) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "siworld-payment-unit-{}-{}",
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
    pub(super) fn node() -> Node {
        let key = SpendKey::from_digest(Digest([1; 32]));
        let g = Genesis::from_file(&GenesisFile {
            network: "journal-unit".into(),
            timestamp: 1000,
            block_time: 1,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![AllocationFile {
                owner: crate::hex(&key.owner()),
                amount: "100".into(),
            }],
        })
        .unwrap();
        Node::open(
            g,
            key,
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap()
    }
    pub(super) fn id() -> PaymentId {
        PaymentId([1; 32])
    }
    pub(super) fn recipient() -> Address {
        SpendKey::from_digest(Digest([2; 32])).address()
    }
    #[test]
    fn artifact_commit_errors_disable_spending_and_recovery_resolves_ambiguous_commit() {
        for after in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("payments.redb");
            let mut n = node();
            n.enable_payment_journal(&path).unwrap();
            n.payments.as_mut().unwrap().ready_commit_fault = Some(after);
            assert_eq!(
                n.pay_with_id(id(), &recipient(), 10_000_000, false)
                    .err()
                    .unwrap()
                    .code(),
                "payment_storage_unavailable"
            );
            assert!(n.mempool.is_empty());
            assert!(n
                .pay_with_id(PaymentId([2; 32]), &recipient(), 10_000_000, false)
                .is_err());
            drop(n);
            let mut n = node();
            n.enable_payment_journal(&path).unwrap();
            let receipt = n.payment(id()).unwrap();
            if after {
                assert_eq!(receipt.state, PaymentState::Pending);
                assert!(n
                    .pay_with_id(id(), &recipient(), 10_000_000, false)
                    .unwrap()
                    .relay
                    .is_some());
            } else {
                assert_eq!(receipt.state, PaymentState::Interrupted);
                assert_eq!(n.balance().unwrap().spendable, 10_000_000_000);
            }
        }
    }
    #[test]
    fn damaged_ciphertext_and_entry_swapping_are_rejected() {
        for swap in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("payments.redb");
            {
                let mut n = node();
                n.enable_payment_journal(&path).unwrap();
                n.pay_with_id(id(), &recipient(), 10_000_000, false)
                    .unwrap();
            }
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut table = tx.open_table(RECORDS).unwrap();
                let (index, mut bytes) = {
                    let (i, b) = table.iter().unwrap().next().unwrap().unwrap();
                    (i.value().to_vec(), b.value().to_vec())
                };
                if swap {
                    table.remove(index.as_slice()).unwrap();
                    table
                        .insert([8u8; 32].as_slice(), bytes.as_slice())
                        .unwrap();
                } else {
                    bytes[30] ^= 1;
                    table.insert(index.as_slice(), bytes.as_slice()).unwrap();
                }
            }
            tx.commit().unwrap();
            drop(db);
            assert!(node().enable_payment_journal(&path).is_err());
        }
    }
    #[test]
    fn bounded_record_decoder_rejects_truncation_trailing_bytes_and_oversized_fields() {
        let r = Record {
            id: id(),
            to: encode_address(&recipient()),
            amount: 10_000_000,
            priority: false,
            nfs: vec![Nullifier(Digest::ZERO)],
            change: 1,
            anchor_height: 0,
            phase: Phase::Preparing,
            tx: vec![],
        };
        let bytes = r.encode();
        for len in 0..bytes.len() {
            assert!(Record::decode(&bytes[..len]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Record::decode(&extra).is_err());
        extra[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Record::decode(&extra).is_err());
    }
    pub(super) fn checkpoint(n: &Node) -> RecoveryCheckpoint {
        RecoveryCheckpoint {
            snapshot_id: Digest([3; 32]),
            height: n.height(),
            tip: n.tip(),
            final_height: 0,
            final_hash: n.genesis.id,
            reviewed_at: None,
        }
    }
    #[test]
    fn merge_conflicts_are_atomic_and_terminal_ids_survive_snapshot_roundtrip() {
        let dir = Temp::new();
        let mut n = node();
        n.enable_payment_journal(&dir.0.join("payments.redb"))
            .unwrap();
        n.pay_with_id(id(), &recipient(), 10_000_000, false)
            .unwrap();
        let mut baseline = n.payment_snapshot().unwrap();
        let original = baseline.encode();
        let recovery = checkpoint(&n);
        n.restore_payment_snapshot(
            JournalSnapshot::decode(&original).unwrap(),
            recovery.clone(),
        )
        .unwrap();
        // A new record sorted first must not leak through a later conflict.
        let mut extra = baseline.records[&id()].clone();
        extra.id = PaymentId([0; 32]);
        extra.phase = Phase::Interrupted;
        extra.tx.clear();
        baseline.records.insert(extra.id, extra);
        baseline.records.get_mut(&id()).unwrap().amount += 1;
        assert!(matches!(
            n.merge_payment_snapshot(baseline, &recovery),
            Err(PaymentError::Conflict)
        ));
        assert_eq!(*n.payment_snapshot().unwrap().encode(), *original);
        let mut baseline = JournalSnapshot::decode(&original).unwrap();
        let r = baseline.records.get_mut(&id()).unwrap();
        r.phase = Phase::Failed;
        r.tx.clear();
        let failed = baseline.encode();
        n.restore_payment_snapshot(JournalSnapshot::decode(&failed).unwrap(), recovery)
            .unwrap();
        let orders = [PaymentOrder::new(id(), &recipient(), 10_000_000, false)];
        n.reconcile_test_orders(&orders, 0, n.tip(), true).unwrap();
        assert_eq!(
            n.pay_with_id(id(), &recipient(), 10_000_000, false)
                .unwrap()
                .receipt
                .state,
            PaymentState::Failed
        );
        assert!(n.mempool.len() == 1); // Restoring did not submit another artifact.
        for len in 0..failed.len() {
            assert!(JournalSnapshot::decode(&failed[..len]).is_err());
        }
        let mut bad = failed.to_vec();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(JournalSnapshot::decode(&bad).is_err());
    }
    #[test]
    fn recovery_checks_finalized_ancestry_but_allows_nonfinal_tip_reorganization() {
        let dir = Temp::new();
        let mut n = node();
        n.enable_payment_journal(&dir.0.join("payments.redb"))
            .unwrap();
        let mut b = n.template(1001).unwrap();
        assert!(siworld_consensus::mine(&mut b.header, 1));
        n.accept(&b).unwrap();
        let snapshot = n.payment_snapshot().unwrap();
        let mut recovery = checkpoint(&n);
        n.restore_payment_snapshot(snapshot, recovery.clone())
            .unwrap();
        let mut peer = node();
        for h in 1..=2 {
            let mut alternate = peer.template(1001 + h).unwrap();
            assert!(siworld_consensus::mine(&mut alternate.header, 1));
            peer.accept(&alternate).unwrap();
            n.accept(&alternate).unwrap();
        }
        assert_ne!(recovery.tip, n.tip());
        assert_eq!(n.tip(), peer.tip());
        assert!(n.reconcile_test_orders(&[], 2, n.tip(), false).is_ok());
        recovery.final_hash = Digest([9; 32]);
        let snapshot = n.payment_snapshot().unwrap();
        n.restore_payment_snapshot(snapshot, recovery).unwrap();
        assert!(matches!(
            n.reconcile_test_orders(&[], 2, n.tip(), true),
            Err(PaymentError::CheckpointMismatch)
        ));
        assert!(n.payment_recovery_required());
    }
}

#[cfg(test)]
mod recovery_commit_tests {
    use super::*;
    #[test]
    fn cancellation_tombstones_and_gate_commit_together_even_with_lost_commit_reply() {
        for after in [false, true] {
            let dir = super::tests::Temp::new();
            let path = dir.0.join("payments.redb");
            let mut n = super::tests::node();
            n.enable_payment_journal(&path).unwrap();
            let snapshot = n.payment_snapshot().unwrap();
            let recovery = super::tests::checkpoint(&n);
            n.restore_payment_snapshot(snapshot, recovery).unwrap();
            let root = super::tests::Temp::new();
            for name in ["ledger", "witness"] {
                std::fs::create_dir(root.0.join(name)).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        root.0.join(name),
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
            }
            let mut ledger = crate::orders::OrderLedger::create(
                &root.0.join("ledger"),
                &root.0.join("witness"),
                "cancellation commit test password",
                n.genesis.id,
                n.address().owner(),
            )
            .unwrap();
            let order = PaymentOrder::new(
                super::tests::id(),
                &super::tests::recipient(),
                10_000_000,
                false,
            );
            let cp = ledger.record(&order).unwrap();
            let cp = ledger.cancel_unsubmitted(super::tests::id(), &cp).unwrap();
            let v = ledger.verify(&cp).unwrap();
            n.payments.as_mut().unwrap().install_commit_fault = Some(after);
            assert!(matches!(
                n.reconcile_payments(&v, 0, n.tip(), true),
                Err(PaymentError::Storage)
            ));
            assert!(n
                .pay_with_id(
                    super::tests::id(),
                    &super::tests::recipient(),
                    10_000_000,
                    false
                )
                .is_err());
            drop(n);
            let mut n = super::tests::node();
            n.enable_payment_journal(&path).unwrap();
            assert_eq!(n.payment_recovery_required(), !after);
            if after {
                let retry = n
                    .pay_with_id(
                        super::tests::id(),
                        &super::tests::recipient(),
                        10_000_000,
                        false,
                    )
                    .unwrap();
                assert_eq!(retry.receipt.state, PaymentState::Cancelled);
                assert!(retry.relay.is_none());
            } else {
                assert!(matches!(
                    n.payment(super::tests::id()),
                    Err(PaymentError::NotFound)
                ));
            }
        }
    }
    #[test]
    fn cancellation_encoding_cannot_carry_inputs_change_anchor_or_artifact() {
        let record = Record {
            id: super::tests::id(),
            to: encode_address(&super::tests::recipient()),
            amount: 10_000_000,
            priority: false,
            nfs: vec![],
            change: 0,
            anchor_height: 0,
            phase: Phase::Cancelled,
            tx: vec![],
        };
        assert!(Record::decode(&record.encode()).is_ok());
        for fault in 0..6 {
            let mut bad = record.clone();
            match fault {
                0 => bad.nfs.push(Nullifier(Digest([1; 32]))),
                1 => bad.change = 1,
                2 => bad.anchor_height = 1,
                3 => bad.tx.push(1),
                4 => bad.phase = Phase::Failed,
                _ => bad.amount = 0,
            }
            assert!(Record::decode(&bad.encode()).is_err());
        }
    }
    #[test]
    fn reconciliation_commit_errors_never_enable_uncommitted_spending() {
        for after in [false, true] {
            let dir = super::tests::Temp::new();
            let path = dir.0.join("payments.redb");
            let mut n = super::tests::node();
            n.enable_payment_journal(&path).unwrap();
            let snapshot = n.payment_snapshot().unwrap();
            let cp = super::tests::checkpoint(&n);
            n.restore_payment_snapshot(snapshot, cp).unwrap();
            n.payments.as_mut().unwrap().install_commit_fault = Some(after);
            assert!(matches!(
                n.reconcile_test_orders(&[], 0, n.tip(), true),
                Err(PaymentError::Storage)
            ));
            assert!(n
                .pay_with_id(
                    super::tests::id(),
                    &super::tests::recipient(),
                    10_000_000,
                    false
                )
                .is_err());
            drop(n);
            let mut n = super::tests::node();
            n.enable_payment_journal(&path).unwrap();
            assert_eq!(n.payment_recovery_required(), !after);
        }
    }
    #[test]
    fn order_file_rejects_unknown_fields_trailing_data_permissions_and_count_overflow() {
        let dir = super::tests::Temp::new();
        let path = dir.0.join("orders");
        crate::secrets::write_secret(&path, "[]").unwrap();
        assert!(load_payment_orders(&path).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_payment_orders(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.0.join("linked-orders");
            symlink(&path, &link).unwrap();
            assert!(load_payment_orders(&link).is_err());
        }
        for bad in ["[{}]","[] []","{\"orders\":[]}","[{\"payment_id\":\"00\",\"to\":\"\",\"amount\":\"1\",\"priority\":false,\"ignore\":true}]"] {
            std::fs::write(&path,bad).unwrap();assert!(load_payment_orders(&path).is_err());
        }
        let order = PaymentOrder::new(super::tests::id(), &super::tests::recipient(), 1, false);
        let mut encoded = serde_json::to_value(&order).unwrap();
        encoded["to"] = serde_json::json!("");
        let element = serde_json::to_string(&encoded).unwrap();
        std::fs::write(
            &path,
            format!("[{}]", vec![element; MAX_RECORDS + 1].join(",")),
        )
        .unwrap();
        assert!(load_payment_orders(&path).is_err());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_BYTES as u64 + 1)
            .unwrap();
        assert!(load_payment_orders(&path).is_err());
    }
}

#[cfg(test)]
impl Node {
    fn reconcile_test_orders(
        &mut self,
        orders: &[PaymentOrder],
        height: u64,
        tip: Digest,
        commit: bool,
    ) -> Result<Reconciliation, PaymentError> {
        let t = tests::Temp::new();
        let l = t.0.join("ledger");
        let w = t.0.join("witness");
        for p in [&l, &w] {
            std::fs::create_dir(p).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let mut ledger = crate::orders::OrderLedger::create(
            &l,
            &w,
            "test order ledger password",
            self.genesis.id,
            self.address().owner(),
        )
        .unwrap();
        for order in orders {
            ledger.record(order).map_err(|_| PaymentError::Conflict)?;
        }
        let cp = ledger.checkpoint().unwrap();
        let verified = ledger.verify(&cp).unwrap();
        self.reconcile_payments(&verified, height, tip, commit)
    }
}
