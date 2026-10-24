//! Local, encrypted write-ahead fund payout journal. Not a consensus format.
pub use crate::payments::PaymentId as PayoutId;
pub mod backup;
mod budget;
pub mod governance;
pub use budget::{ApprovalAudit, BudgetAudit};
mod witness;
use crate::{
    address::{encode_address, parse_address},
    fund_keys::FundKeystore,
    genesis::Genesis,
    keystore::{atomic_write_bytes, WalletFileLock},
    node::Node,
    secrets::read_private_bytes,
    PayoutRefused,
};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use siworld_core::{
    codec::decode_all,
    params::{MAX_PAYOUTS_PER_BLOCK, MIN_PACKAGE_DEPOSIT},
    DevAccount, Digest, Payout,
};
use siworld_crypto::{verify_payout, Address, SecretSeed, VerifyingKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};
const MAGIC: &[u8; 8] = b"SIFPAY01";
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 64 << 20;
const REQUIRED: &str = "siworld fund payout journal required v1\n";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    to: String,
    account: u8,
    counter: u64,
    amount: u64,
    rseed: String,
    artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    approvals: Vec<String>,
}
impl Record {
    fn payout(&self) -> Result<Option<Payout>, PayoutRefused> {
        self.artifact
            .as_ref()
            .map(|s| {
                if s.len() != 2 * Payout::ENCODED_LEN {
                    return Err(PayoutRefused::Journal);
                }
                let mut b = Vec::with_capacity(Payout::ENCODED_LEN);
                for pair in s.as_bytes().as_chunks::<2>().0 {
                    let s = std::str::from_utf8(pair).map_err(|_| PayoutRefused::Journal)?;
                    b.push(u8::from_str_radix(s, 16).map_err(|_| PayoutRefused::Journal)?);
                }
                decode_all(&b, Payout::read).map_err(|_| PayoutRefused::Journal)
            })
            .transpose()
    }
    fn account(&self) -> DevAccount {
        DevAccount::from_byte(self.account).expect("validated account")
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u32,
    sequence: u64,
    height: u64,
    final_height: u64,
    final_hash: String,
    records: Vec<Record>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<backup::Recovery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody: Option<budget::Custody>,
}
pub(crate) struct FundJournal {
    directory: PathBuf,
    _lock: WalletFileLock,
    context: Vec<u8>,
    data: Data,
    key: Option<Zeroizing<[u8; 32]>>,
    poisoned: bool,
    head: [u8; 32],
    witness: Option<witness::Witness>,
    #[cfg(test)]
    fault: Option<u8>,
}
#[derive(Serialize)]
pub struct PayoutReceipt {
    pub payout_id: String,
    pub state: &'static str,
    pub counter: u64,
    pub artifact_hash: Option<String>,
    pub included_height: Option<u64>,
    pub approval_ids: Vec<String>,
}
fn context(genesis: &Genesis) -> Vec<u8> {
    let mut b = b"siworld fund payout journal v1:xchacha20poly1305".to_vec();
    b.extend_from_slice(genesis.id.as_bytes());
    b.extend_from_slice(genesis.params.chain_id.as_bytes());
    if let Some(keys) = &genesis.params.dev_fund_keys {
        b.extend_from_slice(&keys.direct);
        b.extend_from_slice(&keys.lock);
    }
    b
}
fn encrypt(key: &[u8; 32], aad: &[u8], data: &Data) -> Result<Vec<u8>, PayoutRefused> {
    let mut b = Zeroizing::new(serde_json::to_vec(data).map_err(|_| PayoutRefused::Journal)?);
    if b.len() > MAX_BYTES - 48 {
        return Err(PayoutRefused::Journal);
    }
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| PayoutRefused::Randomness)?;
    let tag = XChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("key length"))
        .encrypt_inout_detached(
            <&XNonce>::try_from(nonce.as_slice()).expect("nonce length"),
            aad,
            b.as_mut_slice().into(),
        )
        .map_err(|_| PayoutRefused::Journal)?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&b);
    out.extend_from_slice(&tag);
    Ok(out)
}
fn decrypt(key: &[u8; 32], aad: &[u8], b: &[u8]) -> Result<Data, PayoutRefused> {
    if b.len() < 48 || b.len() > MAX_BYTES || &b[..8] != MAGIC {
        return Err(PayoutRefused::Journal);
    }
    let mut plain = Zeroizing::new(b[32..b.len() - 16].to_vec());
    XChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("key length"))
        .decrypt_inout_detached(
            <&XNonce>::try_from(&b[8..32]).expect("nonce length"),
            aad,
            plain.as_mut_slice().into(),
            &Tag::try_from(&b[b.len() - 16..]).expect("tag length"),
        )
        .map_err(|_| PayoutRefused::Journal)?;
    serde_json::from_slice(&plain).map_err(|_| PayoutRefused::Journal)
}
fn validate(data: &Data, genesis: &Genesis) -> Result<(), PayoutRefused> {
    if !matches!(
        (
            data.version,
            data.custody.is_some(),
            data.custody
                .as_ref()
                .is_some_and(|c| c.governance.is_some())
        ),
        (1, false, false) | (2, true, false) | (3, true, true)
    ) || data.records.len() > MAX_RECORDS
        || data.final_height > data.height
        || crate::parse_hex32(&data.final_hash).is_none()
    {
        return Err(PayoutRefused::Journal);
    }
    if data
        .witness
        .as_ref()
        .is_some_and(|s| crate::parse_hex32(s).is_none() || s.to_lowercase() != *s)
        || data
            .recovery
            .as_ref()
            .is_some_and(|r| r.validate(data).is_err())
    {
        return Err(PayoutRefused::Journal);
    }
    let keys = genesis
        .params
        .dev_fund_keys
        .as_ref()
        .ok_or(PayoutRefused::NoKeys)?;
    let mut ids = BTreeSet::new();
    let mut counters = BTreeSet::new();
    for r in &data.records {
        let id = PayoutId::parse(&r.id).map_err(|_| PayoutRefused::Journal)?;
        let to = parse_address(&r.to).ok_or(PayoutRefused::Journal)?;
        let account = DevAccount::from_byte(r.account).ok_or(PayoutRefused::Journal)?;
        let rseed = crate::parse_hex32(&r.rseed).ok_or(PayoutRefused::Journal)?;
        if id.to_string() != r.id
            || crate::hex(&rseed) != r.rseed
            || !siworld_crypto::is_canonical(&rseed)
            || encode_address(&to) != r.to
            || r.amount < MIN_PACKAGE_DEPOSIT
            || !ids.insert(id)
            || !counters.insert((r.account, r.counter))
        {
            return Err(PayoutRefused::Journal);
        }
        if let Some(p) = r.payout()? {
            let key = VerifyingKey(match account {
                DevAccount::Direct => keys.direct,
                DevAccount::Lock => keys.lock,
            });
            if p.account != account
                || p.counter != r.counter
                || p.amount != r.amount
                || p.owner != to.owner()
                || p.rseed != rseed
                || !verify_payout(&key, &genesis.params.chain_id, &p)
            {
                return Err(PayoutRefused::Journal);
            }
        }
    }
    budget::validate(data, genesis)
}
/// Explicitly provision a NEW journal only after ruling out prior unknown
/// requests/signatures. Missing history is never automatically initialized.
pub fn initialize(
    directory: &Path,
    store: &FundKeystore,
    password: &str,
    genesis: &Genesis,
) -> Result<(), String> {
    if genesis.params.dev_fund_keys != Some(store.open(password)?.verifying_keys()) {
        return Err("fund key does not match genesis".into());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| "new fund journal directory required")?;
    let _lock = WalletFileLock::acquire(directory)?;
    // Publish the sentinel first. A crash here leaves an unusable, never empty,
    // journal, rather than making startup guess that history can be discarded.
    atomic_write_bytes(
        &directory.join("required"),
        REQUIRED.as_bytes(),
        false,
        || Ok(()),
    )?;
    let key = store.journal_key(password, &genesis.id)?;
    let data = Data {
        version: 1,
        sequence: 0,
        height: 0,
        final_height: 0,
        final_hash: crate::hex(&genesis.id),
        records: vec![],
        witness: None,
        recovery: None,
        custody: None,
    };
    let bytes = encrypt(&key, &context(genesis), &data).map_err(|e| e.to_string())?;
    atomic_write_bytes(&directory.join("state"), &bytes, false, || Ok(()))?;
    std::fs::File::open(
        directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|_| "cannot sync fund journal parent")?;
    Ok(())
}
impl FundJournal {
    pub(crate) fn open(
        directory: &Path,
        key: Zeroizing<[u8; 32]>,
        genesis: &Genesis,
    ) -> Result<Self, PayoutRefused> {
        Self::open_with_witness(directory, key, genesis, None)
    }
    pub(crate) fn open_with_witness(
        directory: &Path,
        key: Zeroizing<[u8; 32]>,
        genesis: &Genesis,
        witness_path: Option<&Path>,
    ) -> Result<Self, PayoutRefused> {
        let lock = WalletFileLock::acquire(directory).map_err(|_| PayoutRefused::Journal)?;
        let context = context(genesis);
        if read_private_bytes(&directory.join("required"), 128)
            .map_err(|_| PayoutRefused::Journal)?
            .as_slice()
            != REQUIRED.as_bytes()
        {
            return Err(PayoutRefused::Journal);
        }
        let bytes = read_private_bytes(&directory.join("state"), MAX_BYTES)
            .map_err(|_| PayoutRefused::Journal)?;
        let data = decrypt(&key, &context, &bytes)?;
        validate(&data, genesis)?;
        let required = directory.join("witness.required");
        let witness = match (&data.witness, witness_path) {
            (Some(id), Some(path)) => {
                let marker =
                    read_private_bytes(&required, 64).map_err(|_| PayoutRefused::Journal)?;
                if marker.as_slice() != id.as_bytes() {
                    return Err(PayoutRefused::Journal);
                }
                let w =
                    witness::Witness::open(path, genesis).map_err(|_| PayoutRefused::Journal)?;
                w.ensure_outside(directory.parent().unwrap_or(directory))
                    .map_err(|_| PayoutRefused::Journal)?;
                w.check_data(&bytes, &data, &key, genesis)
                    .map_err(|_| PayoutRefused::Journal)?;
                Some(w)
            }
            (None, None)
                if std::fs::symlink_metadata(&required)
                    .err()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            _ => return Err(PayoutRefused::Journal),
        };
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
            context,
            data,
            key: Some(key),
            poisoned: false,
            head: blake3::hash(&bytes).into(),
            witness,
            #[cfg(test)]
            fault: None,
        })
    }
    pub(crate) fn lock(&mut self) {
        self.key = None;
    }
    pub(crate) fn unlock(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        genesis: &Genesis,
    ) -> Result<(), PayoutRefused> {
        self.healthy()?;
        let bytes = read_private_bytes(&self.directory.join("state"), MAX_BYTES)
            .map_err(|_| PayoutRefused::Journal)?;
        let data = decrypt(&key, &self.context, &bytes)?;
        validate(&data, genesis)?;
        // No external replacement or rollback during this process's ownership.
        if serde_json::to_vec(&data).ok() != serde_json::to_vec(&self.data).ok() {
            self.poisoned = true;
            return Err(PayoutRefused::Journal);
        }
        self.key = Some(key);
        Ok(())
    }
    fn persist(&mut self) -> Result<(), PayoutRefused> {
        let result = (|| {
            self.healthy()?;
            self.data.sequence = self
                .data
                .sequence
                .checked_add(1)
                .ok_or(PayoutRefused::Journal)?;
            let key = self.key.as_ref().ok_or(PayoutRefused::Locked)?;
            let b = encrypt(key, &self.context, &self.data)?;
            #[cfg(test)]
            if self.fault == Some(1) {
                self.fault = None;
                return Err(PayoutRefused::Journal);
            }
            if let Some(w) = &mut self.witness {
                w.append(&b, &self.data)
                    .map_err(|_| PayoutRefused::Journal)?;
            }
            #[cfg(test)]
            if self.fault == Some(8) {
                std::process::exit(74);
            }
            #[cfg(test)]
            if self.fault == Some(6) {
                self.fault = None;
                return Err(PayoutRefused::Journal);
            }
            atomic_write_bytes(&self.directory.join("state"), &b, true, || Ok(()))
                .map_err(|_| PayoutRefused::Journal)?;
            self.head = blake3::hash(&b).into();
            #[cfg(test)]
            if self.fault == Some(2) {
                self.fault = None;
                return Err(PayoutRefused::Journal);
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            self.lock();
        }
        result
    }
    fn healthy(&self) -> Result<(), PayoutRefused> {
        if self.poisoned {
            return Err(PayoutRefused::Journal);
        }
        if read_private_bytes(&self.directory.join("required"), 128)
            .map_err(|_| PayoutRefused::Journal)?
            .as_slice()
            != REQUIRED.as_bytes()
        {
            return Err(PayoutRefused::Journal);
        }
        let bytes = read_private_bytes(&self.directory.join("state"), MAX_BYTES)
            .map_err(|_| PayoutRefused::Journal)?;
        if blake3::hash(&bytes).as_bytes() != &self.head {
            return Err(PayoutRefused::Journal);
        }
        if let Some(w) = &self.witness {
            w.healthy().map_err(|_| PayoutRefused::Journal)?;
            if read_private_bytes(&self.directory.join("witness.required"), 64)
                .map_err(|_| PayoutRefused::Journal)?
                .as_slice()
                != self
                    .data
                    .witness
                    .as_ref()
                    .ok_or(PayoutRefused::Journal)?
                    .as_bytes()
            {
                return Err(PayoutRefused::Journal);
            }
        }
        Ok(())
    }
}
impl Node {
    pub(crate) fn fund_chain_ready(&self) -> bool {
        self.fund_journal.as_ref().is_some_and(|j| {
            !j.poisoned
                && j.data.recovery.is_none()
                && self.height() >= j.data.height
                && self
                    .chain
                    .main_hash(j.data.final_height)
                    .map(|h| crate::hex(&h))
                    == Some(j.data.final_hash.clone())
        })
    }
    fn canonical_fund_payouts(&self) -> BTreeMap<(u8, u64), (Payout, u64)> {
        let mut out = BTreeMap::new();
        for h in 1..=self.height() {
            if let Some(block) = self
                .chain
                .main_hash(h)
                .and_then(|hash| self.chain.block(&hash))
            {
                for p in &block.body.payouts {
                    out.insert((p.account.to_byte(), p.counter), (*p, h));
                }
            }
        }
        out
    }
    /// Reconstruct only exact already-issued artifacts, including after reorgs.
    /// Locked restart can requeue signatures but never signs an unfinished intent.
    pub(crate) fn refresh_fund_payouts(&mut self) {
        if self.fund_journal.is_none() {
            return;
        }
        self.payouts.clear();
        if self
            .fund_journal
            .as_ref()
            .expect("journal")
            .healthy()
            .is_err()
        {
            self.fund_journal.as_mut().expect("journal").poisoned = true;
            self.lock_fund();
            return;
        }
        if !self.fund_chain_ready() {
            return;
        }
        let canonical = self.canonical_fund_payouts();
        let j = self.fund_journal.as_ref().expect("journal");
        let mut records: Vec<_> = j.data.records.iter().collect();
        records.sort_by_key(|r| (r.account, r.counter));
        let mut next = [DevAccount::Direct, DevAccount::Lock].map(|a| self.dev_fund().payouts(a));
        let mut left = [DevAccount::Direct, DevAccount::Lock].map(|a| self.dev_fund().spendable(a));
        for r in records {
            let i = r.account as usize;
            if canonical.contains_key(&(r.account, r.counter)) {
                continue;
            }
            if r.counter != next[i] || r.amount > left[i] {
                continue;
            }
            if let Ok(Some(p)) = r.payout() {
                if self.payouts.len() < MAX_PAYOUTS_PER_BLOCK {
                    self.payouts.push_signed(p);
                    next[i] += 1;
                    left[i] -= p.amount;
                }
            }
        }
    }
    pub fn fund_payout_status(&self, id: PayoutId) -> Result<PayoutReceipt, PayoutRefused> {
        let j = self
            .fund_journal
            .as_ref()
            .ok_or(PayoutRefused::JournalRequired)?;
        j.healthy()?;
        let r = j
            .data
            .records
            .iter()
            .find(|r| r.id == id.to_string())
            .ok_or(PayoutRefused::UnknownId)?;
        let p = r.payout()?;
        let canonical = self.canonical_fund_payouts();
        let inclusion = canonical.get(&(r.account, r.counter));
        let state = if j.data.recovery.is_some() {
            "recovery_required"
        } else if !self.fund_chain_ready() {
            "chain_sync_required"
        } else if let Some((found, _)) = inclusion {
            if Some(*found) == p {
                "included"
            } else {
                "conflicted"
            }
        } else if p.is_none() {
            "prepared"
        } else if self
            .payouts
            .pending()
            .iter()
            .any(|queued| Some(*queued) == p)
        {
            "pending"
        } else {
            "blocked"
        };
        Ok(PayoutReceipt {
            payout_id: id.to_string(),
            state,
            counter: r.counter,
            artifact_hash: p.map(|p| blake3::hash(&p.encode()).to_hex().to_string()),
            included_height: inclusion
                .filter(|(found, _)| Some(*found) == p)
                .map(|(_, h)| *h),
            approval_ids: r.approvals.clone(),
        })
    }
    /// A client MUST retain this ID and full order before the first request.
    /// Reusing it never allocates a new account counter or changes signed bytes.
    pub fn payout(
        &mut self,
        id: PayoutId,
        account: DevAccount,
        to: &Address,
        amount: u64,
    ) -> Result<Payout, PayoutRefused> {
        self.expire_fund(Instant::now());
        if self.fund_protection.is_none() {
            return Err(PayoutRefused::NoKeys);
        }
        let result = self.payout_durable(id, account, to, amount);
        if result == Err(PayoutRefused::Journal)
            || self.fund_journal.as_ref().is_some_and(|j| j.poisoned)
        {
            if let Some(j) = self.fund_journal.as_mut() {
                j.poisoned = true;
            }
            self.payouts.clear();
            self.lock_fund();
        }
        result
    }
    fn payout_durable(
        &mut self,
        id: PayoutId,
        account: DevAccount,
        to: &Address,
        amount: u64,
    ) -> Result<Payout, PayoutRefused> {
        let j = self
            .fund_journal
            .as_ref()
            .ok_or(PayoutRefused::JournalRequired)?;
        j.healthy()?;
        if j.data.recovery.is_some() {
            return Err(PayoutRefused::RecoveryRequired);
        }
        let existing = j.data.records.iter().position(|r| r.id == id.to_string());
        if let Some(index) = existing {
            let r = &j.data.records[index];
            if r.account != account.to_byte() || r.to != encode_address(to) || r.amount != amount {
                return Err(PayoutRefused::IdConflict);
            }
            if let Some(p) = r.payout()? {
                self.refresh_fund_payouts();
                return Ok(p);
            }
        }
        let a = self
            .fund_protection
            .as_ref()
            .and_then(|p| p.authorization.as_ref())
            .ok_or(PayoutRefused::Locked)?;
        if !a.allows(account, &to.owner(), amount) {
            return Err(PayoutRefused::Authorization);
        }
        budget::allows(&j.data, account, amount, existing.is_none())?;
        if amount < MIN_PACKAGE_DEPOSIT {
            return Err(PayoutRefused::BelowMinimum);
        }
        if !self.fund_chain_ready() {
            return Err(PayoutRefused::RecoveryRequired);
        }
        let canonical = self.canonical_fund_payouts();
        let j = self.fund_journal.as_ref().expect("journal");
        if j.data.records.iter().any(|r| {
            canonical
                .get(&(r.account, r.counter))
                .is_some_and(|(p, _)| r.payout().ok().flatten() != Some(*p))
        }) {
            return Err(PayoutRefused::RecoveryRequired);
        }
        let pending: Vec<_> = j
            .data
            .records
            .iter()
            .filter(|r| !canonical.contains_key(&(r.account, r.counter)))
            .collect();
        if existing.is_none() && pending.len() >= MAX_PAYOUTS_PER_BLOCK {
            return Err(PayoutRefused::BlockFull);
        }
        let mut same: Vec<_> = pending
            .iter()
            .filter(|r| r.account == account.to_byte())
            .copied()
            .collect();
        same.sort_by_key(|r| r.counter);
        let mut next = self.dev_fund().payouts(account);
        let mut left = self.dev_fund().spendable(account);
        for r in same {
            if r.counter != next {
                return Err(PayoutRefused::RecoveryRequired);
            }
            next = next.checked_add(1).ok_or(PayoutRefused::RecoveryRequired)?;
            if r.amount > left {
                return Err(PayoutRefused::Insufficient { spendable: left });
            }
            left -= r.amount;
        }
        if existing.is_none() && amount > left {
            return Err(PayoutRefused::Insufficient { spendable: left });
        }
        let height = self.height();
        let final_height = self.chain.final_height();
        let final_hash = crate::hex(
            &self
                .chain
                .main_hash(final_height)
                .ok_or(PayoutRefused::RecoveryRequired)?,
        );
        if existing.is_none() && j.data.records.len() >= MAX_RECORDS {
            return Err(PayoutRefused::Capacity);
        }
        if next == u64::MAX {
            return Err(PayoutRefused::RecoveryRequired);
        }
        let record = if let Some(i) = existing {
            j.data.records[i].clone()
        } else {
            let seed = SecretSeed::from_os_rng().map_err(|_| PayoutRefused::Randomness)?;
            Record {
                id: id.to_string(),
                to: encode_address(to),
                account: account.to_byte(),
                counter: next,
                amount,
                rseed: crate::hex(&seed.derive("fund durable payout rseed", 0)),
                artifact: None,
                approvals: vec![a.id.clone()],
            }
        };
        // Conservative reservation: charge before either durable write can have
        // an uncertain result. No refund, including a pre-sign interruption.
        let approval = self
            .fund_protection
            .as_ref()
            .expect("protected")
            .authorization
            .as_ref()
            .expect("authorized")
            .id
            .clone();
        self.fund_protection
            .as_mut()
            .expect("protected")
            .authorization
            .as_mut()
            .expect("authorized")
            .charge(account, amount);
        let j = self.fund_journal.as_mut().expect("journal");
        j.data.height = j.data.height.max(height);
        j.data.final_height = final_height;
        j.data.final_hash = final_hash;
        let index = if let Some(i) = existing {
            j.data.records[i].approvals.push(approval);
            i
        } else {
            j.data.records.push(record.clone());
            j.data.records.len() - 1
        };
        j.persist()?; // Intent/counter/randomness durable BEFORE signing.
        #[cfg(test)]
        if j.fault == Some(3) {
            j.fault = None;
            j.poisoned = true;
            j.lock();
            return Err(PayoutRefused::Journal);
        }
        let key = j.key.as_ref().ok_or(PayoutRefused::Locked)?;
        let mut hedge =
            Digest(blake3::keyed_hash(key, b"siworld fund payout signature hedge v1").into());
        let mut material = Zeroizing::new(Vec::new());
        material.extend_from_slice(hedge.as_bytes());
        material.extend_from_slice(id.to_string().as_bytes());
        material.extend_from_slice(record.rseed.as_bytes());
        hedge.0 = blake3::keyed_hash(key, &material).into();
        let signer = self.dev_fund.as_ref().ok_or(PayoutRefused::Locked)?;
        let p = signer.sign(
            &self.chain.params.chain_id,
            record.account(),
            record.counter,
            amount,
            to.owner(),
            crate::parse_hex32(&record.rseed).expect("validated randomness"),
            &hedge,
        );
        hedge.0.zeroize();
        j.data.records[index].artifact =
            Some(p.encode().iter().map(|b| format!("{b:02x}")).collect());
        #[cfg(test)]
        if j.fault == Some(4) {
            j.fault = Some(1);
        }
        #[cfg(test)]
        if j.fault == Some(5) {
            j.fault = Some(2);
        }
        #[cfg(test)]
        if j.fault == Some(7) {
            j.fault = Some(6);
        }
        j.persist()?; // Exact signature durable BEFORE enqueue/response.
        self.refresh_fund_payouts();
        Ok(p)
    }
}

/// Owner-only client write-ahead order. Retain outside node snapshots. This is
/// not an independently witnessed or encrypted order ledger.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientOrder {
    version: u32,
    payout_id: String,
    account: u8,
    to: String,
    amount: u64,
    genesis: Option<String>,
}
pub struct RetainedOrder {
    path: PathBuf,
    order: ClientOrder,
    _lock: WalletFileLock,
}
impl RetainedOrder {
    /// Must complete before any RPC. A directory lock serializes CLI retries.
    pub fn retain(
        path: &Path,
        id: PayoutId,
        account: DevAccount,
        to: &Address,
        amount: u64,
    ) -> Result<Self, String> {
        if amount < MIN_PACKAGE_DEPOSIT {
            return Err("payout below minimum".into());
        }
        let lock = WalletFileLock::acquire(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let mut order = ClientOrder {
            version: 1,
            payout_id: id.to_string(),
            account: account.to_byte(),
            to: encode_address(to),
            amount,
            genesis: None,
        };
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let old: ClientOrder = serde_json::from_slice(&read_private_bytes(path, 32 << 10)?)
                    .map_err(|_| "invalid fund order file")?;
                order.genesis = old.genesis.clone();
                if old != order
                    || old.genesis.as_ref().is_some_and(|s| {
                        crate::parse_hex32(s).map(|d| crate::hex(&d)) != Some(s.clone())
                    })
                {
                    return Err("fund order file binds different parameters".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => atomic_write_bytes(
                path,
                &serde_json::to_vec(&order).map_err(|_| "cannot encode fund order")?,
                false,
                || Ok(()),
            )?,
            Err(_) => return Err("cannot inspect fund order file".into()),
        }
        Ok(Self {
            path: path.into(),
            order,
            _lock: lock,
        })
    }
    /// Pin the authenticated node's genesis durably before dispatching payment.
    pub fn bind_genesis(&mut self, genesis: &str) -> Result<(), String> {
        let g = crate::parse_hex32(genesis)
            .map(|g| crate::hex(&g))
            .ok_or("invalid node genesis")?;
        if let Some(old) = &self.order.genesis {
            if old != &g {
                return Err("fund order network mismatch; payout not sent".into());
            }
            return Ok(());
        }
        self.order.genesis = Some(g);
        atomic_write_bytes(
            &self.path,
            &serde_json::to_vec(&self.order).map_err(|_| "cannot encode fund order")?,
            true,
            || Ok(()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_circuits::MockProver;
    use siworld_crypto::SpendKey;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    pub(super) const PASSWORD: &str = "temporary durable fund custody password";
    pub(super) struct Temp(pub(super) PathBuf);
    impl Temp {
        pub(super) fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "si-fund-fault-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    pub(super) fn setup() -> (Genesis, FundKeystore) {
        let mut g = Genesis::from_file(&crate::genesis::GenesisFile {
            network: "fund-fault-test".into(),
            timestamp: 1000,
            block_time: 1,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: crate::genesis::ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![],
        })
        .unwrap();
        let store = FundKeystore::seal(&Digest([8; 32]), PASSWORD).unwrap();
        g.params.dev_fund_keys = Some(store.open(PASSWORD).unwrap().verifying_keys());
        (g, store)
    }
    pub(super) fn recipient() -> Address {
        SpendKey::from_digest(Digest([3; 32])).address()
    }
    pub(super) fn id() -> PayoutId {
        PayoutId::parse(&"01".repeat(32)).unwrap()
    }
    pub(super) fn open(g: &Genesis, directory: &Path) -> Node {
        let mut n = Node::open(
            g.clone(),
            SpendKey::from_digest(Digest([1; 32])),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        let path = directory.join("test-history");
        if path.exists() {
            let blocks: Vec<Vec<u8>> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for bytes in blocks {
                n.accept(&siworld_core::Block::decode(&bytes).unwrap())
                    .unwrap();
            }
        } else {
            let mut blocks = Vec::new();
            for h in 1..=101 {
                let mut b = n.template(1000 + h).unwrap();
                assert!(siworld_consensus::mine(&mut b.header, 1));
                n.accept(&b).unwrap();
                blocks.push(b.encode());
            }
            std::fs::write(path, serde_json::to_vec(&blocks).unwrap()).unwrap();
        }
        n
    }
    pub(super) fn unlock(n: &mut Node) {
        n.unlock_fund(
            PASSWORD,
            &crate::fund_keys::FundGrant {
                version: 2,
                approval_id: crate::fund_payments::PayoutId::random()
                    .unwrap()
                    .to_string(),
                budget: crate::fund_keys::FundBudget {
                    version: 1,
                    id: "ab".repeat(32),
                    direct_si: "1000000000".into(),
                    lock_si: "1000000000".into(),
                    total_si: "2000000000".into(),
                    max_payout_si: "1000000".into(),
                },
                genesis: crate::hex(&n.genesis.id),
                seconds: 3600,
                direct_si: "0.0002".into(),
                lock_si: "0".into(),
                max_payout_si: "0.0002".into(),
                recipients: vec![encode_address(&recipient())],
                approval: None,
            },
        )
        .unwrap();
    }
    #[test]
    fn uncertain_intent_and_artifact_writes_poison_live_signer_and_recover_without_new_counter() {
        for fault in 1..=5 {
            let t = Temp::new();
            let (g, store) = setup();
            initialize(&t.0, &store, PASSWORD, &g).unwrap();
            let mut n = open(&g, &t.0);
            n.protect_dev_fund(store.clone(), PASSWORD, &t.0).unwrap();
            unlock(&mut n);
            n.fund_journal.as_mut().unwrap().fault = Some(fault);
            assert_eq!(
                n.payout(id(), DevAccount::Direct, &recipient(), 10_000),
                Err(PayoutRefused::Journal)
            );
            assert!(n.fund_status().locked);
            assert!(n.payouts.is_empty());
            assert!(n
                .unlock_fund(
                    PASSWORD,
                    &crate::fund_keys::FundGrant {
                        version: 2,
                        approval_id: crate::fund_payments::PayoutId::random()
                            .unwrap()
                            .to_string(),
                        budget: crate::fund_keys::FundBudget {
                            version: 1,
                            id: "ab".repeat(32),
                            direct_si: "1000000000".into(),
                            lock_si: "1000000000".into(),
                            total_si: "2000000000".into(),
                            max_payout_si: "1000000".into(),
                        },
                        genesis: crate::hex(&g.id),
                        seconds: 60,
                        direct_si: "1".into(),
                        lock_si: "0".into(),
                        max_payout_si: "1".into(),
                        recipients: vec![encode_address(&recipient())],
                        approval: None,
                    }
                )
                .is_err());
            assert!(n.dev_fund.is_none());
            assert!(n.fund_journal.as_ref().unwrap().key.is_none());
            let originally_signed = n
                .fund_journal
                .as_ref()
                .unwrap()
                .data
                .records
                .first()
                .and_then(|r| r.payout().unwrap());
            drop(n);
            let mut n = open(&g, &t.0);
            n.protect_dev_fund(store.clone(), PASSWORD, &t.0).unwrap();
            if fault == 1 {
                assert!(n.fund_journal.as_ref().unwrap().data.records.is_empty());
            } else {
                assert_eq!(
                    n.fund_payout_status(id()).unwrap().state,
                    if fault == 5 { "pending" } else { "prepared" }
                );
            }
            let durable = n
                .fund_journal
                .as_ref()
                .unwrap()
                .data
                .records
                .first()
                .cloned();
            unlock(&mut n);
            let a = n
                .payout(id(), DevAccount::Direct, &recipient(), 10_000)
                .unwrap();
            assert_eq!(a.counter, 0);
            if let Some(original) = originally_signed {
                assert_eq!(a, original);
            }
            if let Some(r) = durable {
                assert_eq!(crate::hex(&a.rseed), r.rseed);
                if let Some(p) = r.payout().unwrap() {
                    assert_eq!(a, p);
                }
            }
            assert_eq!(
                n.fund_status().direct_remaining,
                if fault == 5 { 20_000 } else { 10_000 }
            );
            assert_eq!(
                n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
                    .unwrap(),
                a
            );
            assert_eq!(n.payouts.pending(), &[a]);
            assert_eq!(n.fund_approvals(0, 16).unwrap().reserved_atoms, [10_000, 0]);
        }
    }
    #[test]
    fn unfinished_intent_holds_counter_and_blocks_later_artifacts_until_explicit_recovery() {
        let t = Temp::new();
        let (g, store) = setup();
        initialize(&t.0, &store, PASSWORD, &g).unwrap();
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store.clone(), PASSWORD, &t.0).unwrap();
        unlock(&mut n);
        n.fund_journal.as_mut().unwrap().fault = Some(3);
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 10_000),
            Err(PayoutRefused::Journal)
        );
        drop(n);
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store, PASSWORD, &t.0).unwrap();
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 10_000),
            Err(PayoutRefused::Locked)
        );
        unlock(&mut n);
        let later = PayoutId::parse(&"02".repeat(32)).unwrap();
        let b = n
            .payout(later, DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        assert_eq!(b.counter, 1);
        assert!(n.payouts.is_empty());
        assert_eq!(n.fund_payout_status(later).unwrap().state, "blocked");
        let a = n
            .payout(id(), DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        assert_eq!(a.counter, 0);
        assert_eq!(n.payouts.pending(), &[a, b]);
        assert_eq!(n.fund_status().direct_remaining, 0);
        let audit = n.fund_approvals(0, 16).unwrap();
        assert_eq!(audit.reserved_atoms, [20_000, 0]);
        assert_eq!(audit.approvals[0].authorized_atoms, [10_000, 0]);
        assert_eq!(audit.approvals[1].authorized_atoms, [20_000, 0]);
        assert_eq!(n.fund_payout_status(id()).unwrap().approval_ids.len(), 2);
    }
    #[test]
    fn authenticated_journal_records_reject_duplicate_ids_counters_and_invalid_artifact_associations(
    ) {
        let t = Temp::new();
        let (g, store) = setup();
        initialize(&t.0, &store, PASSWORD, &g).unwrap();
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store, PASSWORD, &t.0).unwrap();
        unlock(&mut n);
        n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        let data = n.fund_journal.as_ref().unwrap().data.clone();
        for case in 0..8 {
            let mut bad = data.clone();
            match case {
                0 => bad.records.push(bad.records[0].clone()),
                1 => {
                    let mut r = bad.records[0].clone();
                    r.id = "02".repeat(32);
                    bad.records.push(r);
                }
                2 => bad.records[0].amount += 1,
                3 => {
                    let artifact = bad.records[0].artifact.as_mut().unwrap();
                    let replacement = if artifact.as_bytes()[200] == b'0' {
                        "1"
                    } else {
                        "0"
                    };
                    artifact.replace_range(200..201, replacement);
                }
                4 => bad.records[0].rseed = "ff".repeat(32),
                5 => bad.records[0].account = 9,
                6 => bad.records[0].to = "invalid".into(),
                _ => bad.version = 3,
            }
            assert_eq!(validate(&bad, &g), Err(PayoutRefused::Journal));
        }
        let mut wrong = g.clone();
        wrong.params.chain_id = Digest([9; 32]);
        assert_eq!(validate(&data, &wrong), Err(PayoutRefused::Journal));
        let j = n.fund_journal.as_ref().unwrap();
        let key = j.key.as_ref().unwrap();
        let b = read_private_bytes(&t.0.join("state"), MAX_BYTES).unwrap();
        assert!(decrypt(&[0; 32], &j.context, &b).is_err());
        assert!(decrypt(key, b"wrong-domain", &b).is_err());
        assert!(initialize(
            &t.0,
            &n.fund_protection.as_ref().unwrap().store,
            PASSWORD,
            &g
        )
        .is_err());
    }
    #[test]
    fn process_exit_child() {
        let Ok(path) = std::env::var("SI_FUND_CRASH_CHILD_DIRECTORY") else {
            return;
        };
        let (g, store) = setup();
        let mut n = open(&g, Path::new(&path));
        n.protect_dev_fund(store, PASSWORD, Path::new(&path))
            .unwrap();
        unlock(&mut n);
        n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
            .unwrap();
        // Bypass all Rust destructors, including service/journal/file-lock drops.
        std::process::exit(0);
    }
    #[test]
    fn process_exit_after_durable_enqueue_recovers_with_no_response_or_destructors() {
        let t = Temp::new();
        let (g, store) = setup();
        initialize(&t.0, &store, PASSWORD, &g).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fund_payments::tests::process_exit_child"])
            .env("SI_FUND_CRASH_CHILD_DIRECTORY", &t.0)
            .status()
            .unwrap();
        assert!(status.success());
        let mut n = open(&g, &t.0);
        n.protect_dev_fund(store, PASSWORD, &t.0).unwrap();
        assert!(n.fund_status().locked);
        let before = n.payouts.pending()[0];
        assert_eq!(
            n.payout(id(), DevAccount::Direct, &recipient(), 10_000)
                .unwrap(),
            before
        );
        assert_eq!(n.payouts.len(), 1);
    }
    #[test]
    fn client_order_precedes_network_and_rejects_parameter_network_and_concurrent_retries() {
        let t = Temp::new();
        std::fs::create_dir(&t.0).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = t.0.join("order");
        let mut r =
            RetainedOrder::retain(&path, id(), DevAccount::Direct, &recipient(), 10_000).unwrap();
        assert!(path.exists());
        assert!(
            RetainedOrder::retain(&path, id(), DevAccount::Direct, &recipient(), 10_000).is_err()
        );
        r.bind_genesis(&"01".repeat(32)).unwrap();
        assert!(r.bind_genesis(&"02".repeat(32)).is_err());
        drop(r);
        assert!(
            RetainedOrder::retain(&path, id(), DevAccount::Direct, &recipient(), 20_000).is_err()
        );
        let mut r =
            RetainedOrder::retain(&path, id(), DevAccount::Direct, &recipient(), 10_000).unwrap();
        r.bind_genesis(&"01".repeat(32)).unwrap();
    }
}
