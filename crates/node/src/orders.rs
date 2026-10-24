//! Independently retained, encrypted write-ahead orders and monotonic witnesses.
//! A checkpoint must be obtained from a trusted current source. No local file
//! can establish freshness if every independently retained copy is rolled back.
use crate::keystore::{atomic_write_bytes, derived_key, WalletFileLock};
use crate::payments::{PaymentId, PaymentOrder};
use crate::secrets::read_private_bytes;
use crate::{hex, parse_hex32};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use siworld_core::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
pub mod archive;
const MAX_ORDERS: usize = 65_536;
const MAX_EVENTS: usize = 2 * MAX_ORDERS;
const MAX_FILE: usize = 256 << 20;
const MAGIC: &[u8; 8] = b"SIORDER1";
const CONTEXT: &[u8] =
    b"siworld independent order ledger v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub ledger_id: String,
    pub genesis: String,
    pub owner: String,
    pub sequence: u64,
    pub head: String,
}
impl Checkpoint {
    pub fn filename(sequence: u64) -> String {
        format!("checkpoint-{sequence:016x}.json")
    }
    pub fn read(path: &Path) -> Result<Self, String> {
        let c: Self = serde_json::from_slice(&read_private_bytes(path, 2048)?)
            .map_err(|_| "invalid order checkpoint")?;
        c.validate()?;
        Ok(c)
    }
    pub fn save_new(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        atomic_write_bytes(
            path,
            &serde_json::to_vec(self).map_err(|_| "cannot encode checkpoint")?,
            false,
            || Ok(()),
        )
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.sequence > MAX_EVENTS as u64
            || [&self.ledger_id, &self.genesis, &self.owner, &self.head]
                .iter()
                .any(|s| parse_hex32(s).is_none() || s.to_lowercase() != **s)
        {
            return Err("invalid order checkpoint".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    identity: Checkpoint,
    #[serde(deserialize_with = "bounded_orders")]
    orders: Vec<PaymentOrder>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "bounded_events"
    )]
    events: Option<Vec<Event>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderState {
    LegacyUnknown,
    Unsubmitted,
    Dispatched,
    CancelledUnsubmitted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
enum Event {
    LegacyRecorded { index: u32 },
    Recorded { index: u32 },
    DispatchStarted { index: u32 },
    CancelledUnsubmitted { index: u32 },
}
fn bounded_events<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<Event>>, D::Error> {
    struct Events;
    impl<'de> serde::de::Visitor<'de> for Events {
        type Value = Vec<Event>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded lifecycle event array")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
            let mut events = Vec::new();
            while let Some(e) = a.next_element::<Event>()? {
                if events.len() == MAX_EVENTS {
                    return Err(serde::de::Error::custom("too many order events"));
                }
                events.push(e);
            }
            Ok(events)
        }
    }
    d.deserialize_seq(Events).map(Some)
}
impl Ledger {
    fn events(&self) -> Vec<Event> {
        self.events.clone().unwrap_or_else(|| {
            (0..self.orders.len())
                .map(|i| Event::LegacyRecorded { index: i as u32 })
                .collect()
        })
    }
    fn states(&self) -> Result<BTreeMap<PaymentId, OrderState>, String> {
        let (_, states) = replay(self)?;
        Ok(self
            .orders
            .iter()
            .zip(states)
            .map(|(o, s)| (PaymentId::parse(&o.payment_id).expect("validated order"), s))
            .collect())
    }
}
fn bounded_orders<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<PaymentOrder>, D::Error> {
    <crate::payments::BoundedOrders as serde::Deserialize>::deserialize(d).map(|o| o.0)
}
fn canonical(order: &PaymentOrder) -> Result<PaymentOrder, String> {
    let id = PaymentId::parse(&order.payment_id).map_err(|e| e.to_string())?;
    let to = crate::address::parse_address(&order.to).ok_or("invalid order address")?;
    let amount = crate::amount::parse_si(&order.amount)
        .filter(|a| *a > 0)
        .ok_or("invalid order amount")?;
    Ok(PaymentOrder::new(id, &to, amount, order.priority))
}
fn canonical_bytes(order: &PaymentOrder) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(Vec::new());
    b.extend_from_slice(
        parse_hex32(&order.payment_id)
            .expect("validated ID")
            .as_bytes(),
    );
    b.extend_from_slice(&(order.to.len() as u32).to_le_bytes());
    b.extend_from_slice(order.to.as_bytes());
    b.extend_from_slice(
        &crate::amount::parse_si(&order.amount)
            .expect("validated amount")
            .to_le_bytes(),
    );
    b.push(u8::from(order.priority));
    b
}
fn checkpoints(data: &Ledger) -> Result<Vec<Checkpoint>, String> {
    replay(data).map(|(cps, _)| cps)
}
fn replay(data: &Ledger) -> Result<(Vec<Checkpoint>, Vec<OrderState>), String> {
    data.identity.validate()?;
    if data.identity.sequence != 0 || data.orders.len() > MAX_ORDERS {
        return Err("invalid order ledger limits".into());
    }
    let mut hash = blake3::Hasher::new_derive_key("siworld independent order ledger identity v1");
    for s in [
        &data.identity.ledger_id,
        &data.identity.genesis,
        &data.identity.owner,
    ] {
        hash.update(parse_hex32(s).expect("validated identity").as_bytes());
    }
    let mut head = Digest(*hash.finalize().as_bytes());
    if hex(&head) != data.identity.head {
        return Err("invalid order ledger identity".into());
    }
    let mut cps = vec![data.identity.clone()];
    let mut ids = BTreeSet::new();
    for order in &data.orders {
        let c = canonical(order)?;
        if canonical_bytes(&c) != canonical_bytes(order)
            || c.payment_id != order.payment_id
            || c.to != order.to
            || c.amount != order.amount
            || !ids.insert(c.payment_id.clone())
        {
            return Err("noncanonical or repeated order".into());
        }
    }
    let events = data.events();
    if events.len() > MAX_EVENTS {
        return Err("too many order events".into());
    }
    let mut states = Vec::new();
    let mut tracked_seen = false;
    for (i, event) in events.iter().enumerate() {
        let (index, domain, tag) = match *event {
            Event::LegacyRecorded { index } => {
                (index, "siworld independent order ledger append v1", 0)
            }
            Event::Recorded { index } => (
                index,
                "siworld independent order ledger tracked append v1",
                0,
            ),
            Event::DispatchStarted { index } => {
                (index, "siworld independent order ledger lifecycle v1", 1)
            }
            Event::CancelledUnsubmitted { index } => {
                (index, "siworld independent order ledger lifecycle v1", 2)
            }
        };
        let order = data
            .orders
            .get(index as usize)
            .ok_or("invalid order event index")?;
        match *event {
            Event::LegacyRecorded { .. } | Event::Recorded { .. } => {
                if index as usize != states.len()
                    || (matches!(event, Event::LegacyRecorded { .. }) && tracked_seen)
                {
                    return Err("invalid order record sequence".into());
                }
                let tracked = matches!(event, Event::Recorded { .. });
                tracked_seen |= tracked;
                states.push(if tracked {
                    OrderState::Unsubmitted
                } else {
                    OrderState::LegacyUnknown
                });
            }
            Event::DispatchStarted { .. } | Event::CancelledUnsubmitted { .. } => {
                let state = states
                    .get_mut(index as usize)
                    .ok_or("order event before record")?;
                if *state != OrderState::Unsubmitted {
                    return Err("invalid order lifecycle transition".into());
                }
                *state = if tag == 1 {
                    OrderState::Dispatched
                } else {
                    OrderState::CancelledUnsubmitted
                };
            }
        }
        let mut h = blake3::Hasher::new_derive_key(domain);
        h.update(head.as_bytes());
        h.update(&(i as u64 + 1).to_le_bytes());
        if tag == 0 {
            h.update(&canonical_bytes(order));
        } else {
            h.update(&[tag]);
            h.update(
                parse_hex32(&order.payment_id)
                    .expect("validated ID")
                    .as_bytes(),
            );
        }
        head = Digest(*h.finalize().as_bytes());
        let mut cp = data.identity.clone();
        cp.sequence = i as u64 + 1;
        cp.head = hex(&head);
        cps.push(cp);
    }
    if states.len() != data.orders.len() {
        return Err("unrecorded order in ledger".into());
    }
    Ok((cps, states))
}
fn aad(header: &[u8]) -> Vec<u8> {
    let mut b = CONTEXT.to_vec();
    b.extend_from_slice(header);
    b
}
fn encrypt(data: &Ledger, password: &str) -> Result<Vec<u8>, String> {
    let mut plain =
        Zeroizing::new(serde_json::to_vec(data).map_err(|_| "cannot encode order ledger")?);
    if plain.len() > MAX_FILE - 64 {
        return Err("order ledger exceeds limit".into());
    }
    let mut header = [0; 48];
    header[..8].copy_from_slice(MAGIC);
    getrandom::fill(&mut header[8..]).map_err(|_| "OS randomness unavailable")?;
    let key = derived_key(password, &header[8..24])?;
    let tag = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .encrypt_inout_detached(
            <&XNonce>::try_from(&header[24..]).expect("nonce length"),
            &aad(&header),
            plain.as_mut_slice().into(),
        )
        .map_err(|_| "order encryption failed")?;
    let mut out = header.to_vec();
    out.extend_from_slice(&plain);
    out.extend_from_slice(&tag);
    Ok(out)
}
fn decrypt(bytes: &[u8], password: &str) -> Result<Ledger, String> {
    if bytes.len() < 64 || bytes.len() > MAX_FILE || &bytes[..8] != MAGIC {
        return Err("unsupported order ledger".into());
    }
    let key = derived_key(password, &bytes[8..24])?;
    let mut plain = Zeroizing::new(bytes[48..bytes.len() - 16].to_vec());
    XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key length"))
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..48]).expect("nonce length"),
            &aad(&bytes[..48]),
            plain.as_mut_slice().into(),
            &Tag::try_from(&bytes[bytes.len() - 16..]).expect("tag length"),
        )
        .map_err(|_| "incorrect ledger password or damaged ledger")?;
    serde_json::from_slice(&plain).map_err(|_| "invalid order ledger".into())
}
fn separate(a: &Path, b: &Path) -> Result<(), String> {
    if a.starts_with(b) || b.starts_with(a) {
        return Err("wallet, ledger and witness directories must be separate".into());
    }
    Ok(())
}
// Resolve parent aliases without following the final file: private-file I/O must
// still reject a final symlink/hard link. Parent ownership remains an operator
// assumption, as in secrets.rs; this does not identify physical backup domains.
fn external_file(path: &Path, excluded: &[&Path]) -> Result<PathBuf, String> {
    let name = path.file_name().ok_or("checkpoint file name required")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = std::fs::canonicalize(parent)
        .map_err(|_| "cannot inspect checkpoint parent directory")?
        .join(name);
    for dir in excluded {
        let dir = std::fs::canonicalize(dir).map_err(|_| "cannot inspect excluded directory")?;
        if resolved.starts_with(dir) {
            return Err(
                "checkpoint must be outside wallet, ledger, witness and drill directories".into(),
            );
        }
    }
    Ok(resolved)
}
pub struct OrderLedger {
    dir: PathBuf,
    witness: PathBuf,
    _locks: (WalletFileLock, WalletFileLock),
    data: Ledger,
    cps: Vec<Checkpoint>,
    witness_sequence: usize,
    password: Zeroizing<String>,
    poisoned: bool,
}
/// The borrow retains exclusive ledger/witness ownership through reconciliation.
pub struct VerifiedOrders<'a> {
    ledger: &'a OrderLedger,
    checkpoint_source: Option<PathBuf>,
}
impl VerifiedOrders<'_> {
    pub fn orders(&self) -> &[PaymentOrder] {
        &self.ledger.data.orders
    }
    pub fn states(&self) -> BTreeMap<PaymentId, OrderState> {
        self.ledger.data.states().expect("verified lifecycle")
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        self.ledger.cps.last().expect("identity")
    }
    pub fn ensure_outside(&self, wallet: &Path) -> Result<(), String> {
        let w = std::fs::canonicalize(wallet).map_err(|_| "cannot inspect wallet directory")?;
        separate(&w, &self.ledger.dir)?;
        separate(&w, &self.ledger.witness)?;
        if let Some(path) = &self.checkpoint_source {
            external_file(path, &[&w])?;
        }
        Ok(())
    }
}
impl OrderLedger {
    fn locks(
        dir: &Path,
        witness: &Path,
    ) -> Result<(PathBuf, PathBuf, (WalletFileLock, WalletFileLock)), String> {
        let a = WalletFileLock::acquire(dir)?;
        let b = WalletFileLock::acquire(witness)?;
        let d = std::fs::canonicalize(dir).map_err(|_| "cannot inspect ledger directory")?;
        let w = std::fs::canonicalize(witness).map_err(|_| "cannot inspect witness directory")?;
        separate(&d, &w)?;
        Ok((d, w, (a, b)))
    }
    pub fn create(
        dir: &Path,
        witness: &Path,
        password: &str,
        genesis: Digest,
        owner: Digest,
    ) -> Result<Self, String> {
        if password.len() < 12 {
            return Err("new ledger passwords require at least 12 UTF-8 bytes".into());
        }
        let (dir, witness, locks) = Self::locks(dir, witness)?;
        for p in [&dir, &witness] {
            for entry in std::fs::read_dir(p).map_err(|_| "cannot inspect new order directory")? {
                if entry
                    .map_err(|_| "cannot inspect new order directory")?
                    .file_name()
                    != ".wallet.lock"
                {
                    return Err("new order directories must be empty".into());
                }
            }
        }
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| "OS randomness unavailable")?;
        let mut identity = Checkpoint {
            version: 1,
            ledger_id: hex(&Digest(id)),
            genesis: hex(&genesis),
            owner: hex(&owner),
            sequence: 0,
            head: String::new(),
        };
        let mut hash =
            blake3::Hasher::new_derive_key("siworld independent order ledger identity v1");
        for s in [&identity.ledger_id, &identity.genesis, &identity.owner] {
            hash.update(parse_hex32(s).expect("identity").as_bytes());
        }
        identity.head = hex(&Digest(*hash.finalize().as_bytes()));
        let data = Ledger {
            identity: identity.clone(),
            orders: Vec::new(),
            events: Some(Vec::new()),
        };
        let bytes = encrypt(&data, password)?;
        atomic_write_bytes(&dir.join("orders.enc"), &bytes, false, || Ok(()))?;
        identity.save_new(&witness.join(Checkpoint::filename(0)))?;
        Ok(Self {
            dir,
            witness,
            _locks: locks,
            data,
            cps: vec![identity],
            witness_sequence: 0,
            password: Zeroizing::new(password.to_owned()),
            poisoned: false,
        })
    }
    pub fn open(dir: &Path, witness: &Path, password: &str) -> Result<Self, String> {
        let (dir, witness, locks) = Self::locks(dir, witness)?;
        let data = decrypt(
            &read_private_bytes(&dir.join("orders.enc"), MAX_FILE)?,
            password,
        )?;
        let cps = checkpoints(&data)?;
        let mut seen = BTreeSet::new();
        for entry in std::fs::read_dir(&witness).map_err(|_| "cannot read order witness")? {
            let entry = entry.map_err(|_| "cannot read order witness")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err("invalid witness file".into());
            };
            if name == ".wallet.lock" {
                continue;
            }
            if seen.len() > MAX_EVENTS {
                return Err("too many witness records".into());
            }
            let seq = name
                .strip_prefix("checkpoint-")
                .and_then(|s| s.strip_suffix(".json"))
                .filter(|s| s.len() == 16)
                .and_then(|s| usize::from_str_radix(s, 16).ok())
                .ok_or("unexpected witness file")?;
            if name != Checkpoint::filename(seq as u64)
                || !seen.insert(seq)
                || cps.get(seq) != Some(&Checkpoint::read(&entry.path())?)
            {
                return Err("order ledger rollback or witness mismatch".into());
            }
        }
        let count = seen.len();
        if count == 0
            || count > cps.len()
            || (0..count).any(|i| !seen.contains(&i))
            || cps.len() - count > 1
        {
            return Err("order witness missing, truncated or inconsistent".into());
        }
        Ok(Self {
            dir,
            witness,
            _locks: locks,
            data,
            cps,
            witness_sequence: count - 1,
            password: Zeroizing::new(password.to_owned()),
            poisoned: false,
        })
    }
    pub fn checkpoint(&self) -> Result<Checkpoint, String> {
        if self.poisoned || self.witness_sequence + 1 != self.cps.len() {
            return Err("order witness incomplete; retry only the last recorded request".into());
        }
        Ok(self.cps.last().expect("identity").clone())
    }
    pub fn verify(&self, expected: &Checkpoint) -> Result<VerifiedOrders<'_>, String> {
        expected.validate()?;
        if self.checkpoint()? != *expected {
            return Err("order_ledger_freshness_mismatch".into());
        }
        Ok(VerifiedOrders {
            ledger: self,
            checkpoint_source: None,
        })
    }
    /// Read a reference outside the managed ledger/witness trees. This checks
    /// known path separation, not independently current provenance.
    pub fn read_external_checkpoint(&self, path: &Path) -> Result<Checkpoint, String> {
        Checkpoint::read(&external_file(path, &[&self.dir, &self.witness])?)
    }
    /// Retain the file origin so wallet/drill separation can be checked before
    /// any restore reconciliation or snapshot import modifies wallet records.
    pub fn verify_file(&self, path: &Path) -> Result<VerifiedOrders<'_>, String> {
        let source = external_file(path, &[&self.dir, &self.witness])?;
        let cp = Checkpoint::read(&source)?;
        let mut verified = self.verify(&cp)?;
        verified.checkpoint_source = Some(source);
        Ok(verified)
    }
    /// Publish a new immutable reference after checking any previous retained
    /// checkpoint is an exact prefix of this ledger. Never replace the old pin.
    pub fn export_checkpoint(
        &self,
        output: &Path,
        previous: Option<&Path>,
    ) -> Result<Checkpoint, String> {
        let cp = self.checkpoint()?;
        let output = external_file(output, &[&self.dir, &self.witness])?;
        if let Some(path) = previous {
            let previous = self.read_external_checkpoint(path)?;
            if self.cps.get(previous.sequence as usize) != Some(&previous) {
                return Err("order_checkpoint_not_ancestor".into());
            }
        }
        cp.save_new(&output)?;
        if Checkpoint::read(&output)? != cp {
            return Err("checkpoint publication read-back mismatch".into());
        }
        Ok(cp)
    }
    pub fn state(&self, id: PaymentId) -> Result<Option<OrderState>, String> {
        if self.poisoned {
            return Err("order ledger storage unavailable; reopen before retry".into());
        }
        Ok(self.data.states()?.get(&id).copied())
    }
    fn index(&self, order: &PaymentOrder) -> Result<usize, String> {
        let c = canonical(order)?;
        let i = self
            .data
            .orders
            .iter()
            .position(|o| o.payment_id == c.payment_id)
            .ok_or("order not found")?;
        if canonical_bytes(&self.data.orders[i]) != canonical_bytes(&c) {
            return Err("payment_id_conflict".into());
        }
        Ok(i)
    }
    pub fn record(&mut self, order: &PaymentOrder) -> Result<Checkpoint, String> {
        self.record_with_hook(order, || Ok(()))
    }
    fn record_with_hook(
        &mut self,
        order: &PaymentOrder,
        hook: impl FnOnce() -> Result<(), String>,
    ) -> Result<Checkpoint, String> {
        let c = canonical(order)?;
        let id = PaymentId::parse(&c.payment_id).expect("canonical ID");
        if let Some(state) = self.state(id)? {
            let index = self.index(&c)? as u32;
            if state == OrderState::CancelledUnsubmitted {
                return Err("order_cancelled_unsubmitted".into());
            }
            if self.witness_sequence + 1 == self.cps.len() {
                return self.checkpoint();
            }
            let event = self.data.events().last().copied().ok_or("missing event")?;
            if !matches!(event, Event::Recorded { index: i } | Event::LegacyRecorded { index: i } if i == index)
            {
                return Err("order witness incomplete; retry the exact pending operation".into());
            }
            return self.publish(event, hook);
        }
        self.checkpoint()?;
        if self.data.orders.len() >= MAX_ORDERS {
            return Err("order ledger full".into());
        }
        let index = self.data.orders.len() as u32;
        // Freeze the complete legacy prefix before adding a newly tracked record.
        if self.data.events.is_none() {
            self.data.events = Some(self.data.events());
        }
        self.data.orders.push(c);
        self.publish(Event::Recorded { index }, hook)
    }
    /// Must finish durably before a send RPC can start. A lost reply is ambiguous.
    pub fn begin_dispatch(&mut self, order: &PaymentOrder) -> Result<Checkpoint, String> {
        let index = self.index(order)? as u32;
        let id = PaymentId::parse(&order.payment_id).map_err(|e| e.to_string())?;
        match self.state(id)? {
            Some(OrderState::Unsubmitted) => {
                self.checkpoint()?;
                self.publish(Event::DispatchStarted { index }, || Ok(()))
            }
            Some(OrderState::Dispatched) => {
                self.publish(Event::DispatchStarted { index }, || Ok(()))
            }
            Some(OrderState::LegacyUnknown) => self.checkpoint(),
            _ => Err("order_cancelled_unsubmitted".into()),
        }
    }
    /// Read-only eligibility check against an independently current checkpoint.
    pub fn preview_cancel(&self, id: PaymentId, expected: &Checkpoint) -> Result<(), String> {
        self.verify(expected)?;
        if self.state(id)? != Some(OrderState::Unsubmitted) {
            return Err("order_not_proven_unsubmitted".into());
        }
        Ok(())
    }
    pub fn cancel_unsubmitted(
        &mut self,
        id: PaymentId,
        expected: &Checkpoint,
    ) -> Result<Checkpoint, String> {
        expected.validate()?;
        let index = self
            .data
            .orders
            .iter()
            .position(|o| o.payment_id == id.to_string())
            .ok_or("order not found")? as u32;
        let event = Event::CancelledUnsubmitted { index };
        if self.state(id)? == Some(OrderState::CancelledUnsubmitted) {
            // Exact lost-reply retry only; no unrelated stale checkpoint is accepted.
            if self.data.events().last() == Some(&event)
                && self.cps.get(self.cps.len() - 2) == Some(expected)
            {
                return self.publish(event, || Ok(()));
            }
            if self.checkpoint().as_ref() == Ok(expected) {
                return self.checkpoint();
            }
            return Err("order_ledger_freshness_mismatch".into());
        }
        self.preview_cancel(id, expected)?;
        self.publish(event, || Ok(()))
    }
    fn publish(
        &mut self,
        event: Event,
        hook: impl FnOnce() -> Result<(), String>,
    ) -> Result<Checkpoint, String> {
        if self.poisoned {
            return Err("order ledger storage unavailable; reopen before retry".into());
        }
        let pending = self.witness_sequence + 1 != self.cps.len();
        if pending {
            if self.data.events().last() != Some(&event) {
                return Err("retry the exact pending operation".into());
            }
        } else {
            let terminal = match event {
                Event::DispatchStarted { index } => Some((index, OrderState::Dispatched)),
                Event::CancelledUnsubmitted { index } => {
                    Some((index, OrderState::CancelledUnsubmitted))
                }
                _ => None,
            };
            if let Some((index, terminal)) = terminal {
                let order = self
                    .data
                    .orders
                    .get(index as usize)
                    .ok_or("invalid order event index")?;
                let id = PaymentId::parse(&order.payment_id).expect("validated ID");
                if self.state(id)? == Some(terminal) {
                    return self.checkpoint();
                }
            }
            self.data.events.get_or_insert_with(Vec::new).push(event);
            let result = (|| {
                let cps = checkpoints(&self.data)?;
                let bytes = encrypt(&self.data, &self.password)?;
                atomic_write_bytes(&self.dir.join("orders.enc"), &bytes, true, || Ok(()))?;
                self.cps = cps;
                Ok::<_, String>(())
            })();
            if let Err(e) = result {
                self.poisoned = true;
                return Err(e);
            }
        }
        let cp = self.cps.last().expect("identity").clone();
        if let Err(e) =
            hook().and_then(|()| cp.save_new(&self.witness.join(Checkpoint::filename(cp.sequence))))
        {
            self.poisoned = true;
            return Err(e);
        }
        self.witness_sequence = cp.sequence as usize;
        self.checkpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_prefix_is_preserved_and_cannot_be_reclassified_as_unsubmitted() {
        let t = Temp::new();
        let mut l = create(&t);
        // Encode exactly the pre-lifecycle schema, with no events field.
        l.data.orders.push(order(1));
        l.data.events = None;
        l.cps = checkpoints(&l.data).unwrap();
        let old = l.cps[1].clone();
        let mut hash = blake3::Hasher::new_derive_key("siworld independent order ledger append v1");
        hash.update(parse_hex32(&l.data.identity.head).unwrap().as_bytes());
        hash.update(&1u64.to_le_bytes());
        hash.update(&canonical_bytes(&order(1)));
        assert_eq!(old.head, hex(&Digest(*hash.finalize().as_bytes())));
        atomic_write_bytes(
            &l.dir.join("orders.enc"),
            &encrypt(&l.data, PASS).unwrap(),
            true,
            || Ok(()),
        )
        .unwrap();
        old.save_new(&l.witness.join(Checkpoint::filename(1)))
            .unwrap();
        drop(l);
        let mut l = open(&t);
        let id = PaymentId::parse(&order(1).payment_id).unwrap();
        assert_eq!(l.state(id).unwrap(), Some(OrderState::LegacyUnknown));
        assert!(l.cancel_unsubmitted(id, &old).is_err());
        let current = l.record(&order(2)).unwrap();
        assert_eq!(l.cps[1], old);
        assert_eq!(l.state(id).unwrap(), Some(OrderState::LegacyUnknown));
        assert_eq!(l.checkpoint().unwrap(), current);
        // Changing the classification cannot preserve the independently pinned head.
        l.data.events.as_mut().unwrap()[0] = Event::Recorded { index: 0 };
        atomic_write_bytes(
            &l.dir.join("orders.enc"),
            &encrypt(&l.data, PASS).unwrap(),
            true,
            || Ok(()),
        )
        .unwrap();
        drop(l);
        assert!(OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASS).is_err());
    }
    #[test]
    fn malformed_event_sequences_fail_closed() {
        let t = Temp::new();
        let l = create(&t);
        let mut data = Ledger {
            identity: l.data.identity.clone(),
            orders: vec![order(1)],
            events: None,
        };
        for events in [
            vec![],
            vec![Event::Recorded { index: 1 }],
            vec![Event::DispatchStarted { index: 0 }],
            vec![Event::Recorded { index: 0 }, Event::Recorded { index: 0 }],
            vec![
                Event::LegacyRecorded { index: 0 },
                Event::CancelledUnsubmitted { index: 0 },
            ],
            vec![
                Event::Recorded { index: 0 },
                Event::DispatchStarted { index: 0 },
                Event::CancelledUnsubmitted { index: 0 },
            ],
            vec![
                Event::Recorded { index: 0 },
                Event::CancelledUnsubmitted { index: 0 },
                Event::DispatchStarted { index: 0 },
            ],
        ] {
            data.events = Some(events);
            assert!(checkpoints(&data).is_err());
        }
        let json = serde_json::json!({"identity":data.identity,"orders":[],"events":null});
        assert!(serde_json::from_value::<Ledger>(json).is_err());
        let entries = std::iter::repeat_n("{\"kind\":\"recorded\",\"index\":0}", MAX_EVENTS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            "{{\"identity\":{},\"orders\":[],\"events\":[{entries}]}}",
            serde_json::to_string(&l.data.identity).unwrap()
        );
        assert!(serde_json::from_str::<Ledger>(&json).is_err());
    }
    #[test]
    fn lifecycle_process_child() {
        let Ok(root) = std::env::var("SIWORLD_LIFECYCLE_CRASH_ROOT") else {
            return;
        };
        let mut l = OrderLedger::open(
            &PathBuf::from(&root).join("ledger"),
            &PathBuf::from(root).join("witness"),
            PASS,
        )
        .unwrap();
        let event = if std::env::var("SIWORLD_LIFECYCLE_CANCEL").unwrap() == "yes" {
            Event::CancelledUnsubmitted { index: 0 }
        } else {
            Event::DispatchStarted { index: 0 }
        };
        let _ = l.publish(event, || std::process::exit(88));
        panic!("child did not exit");
    }
    #[test]
    fn lifecycle_crash_only_repairs_the_exact_dispatch_or_cancellation() {
        for cancel in [false, true] {
            let t = Temp::new();
            let mut l = create(&t);
            let cp = l.record(&order(1)).unwrap();
            drop(l);
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "orders::tests::lifecycle_process_child",
                    "--nocapture",
                ])
                .env("SIWORLD_LIFECYCLE_CRASH_ROOT", &t.0)
                .env(
                    "SIWORLD_LIFECYCLE_CANCEL",
                    if cancel { "yes" } else { "no" },
                )
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(88));
            let mut l = open(&t);
            assert!(l.verify(&cp).is_err());
            assert!(l.record(&order(1)).is_err());
            assert!(l.record(&order(2)).is_err());
            let id = PaymentId::parse(&order(1).payment_id).unwrap();
            if cancel {
                assert!(l.begin_dispatch(&order(1)).is_err());
                let mut wrong = cp.clone();
                wrong.head = "ff".repeat(32);
                assert!(l.cancel_unsubmitted(id, &wrong).is_err());
                assert_eq!(l.cancel_unsubmitted(id, &cp).unwrap().sequence, 2);
            } else {
                assert!(l.cancel_unsubmitted(id, &cp).is_err());
                let mut changed = order(1);
                changed.priority = true;
                assert!(l.begin_dispatch(&changed).is_err());
                assert_eq!(l.begin_dispatch(&order(1)).unwrap().sequence, 2);
            }
            let current = l.checkpoint().unwrap();
            drop(l);
            assert_eq!(open(&t).checkpoint().unwrap(), current);
        }
    }
    #[test]
    fn only_tracked_unsubmitted_orders_can_be_cancelled_and_ids_remain_retired() {
        let t = Temp::new();
        let mut l = create(&t);
        let old = l.checkpoint().unwrap();
        let cp = l.record(&order(1)).unwrap();
        let id = PaymentId::parse(&order(1).payment_id).unwrap();
        assert_eq!(l.state(id).unwrap(), Some(OrderState::Unsubmitted));
        assert!(l.cancel_unsubmitted(id, &old).is_err());
        let cancelled = l.cancel_unsubmitted(id, &cp).unwrap();
        assert_eq!(l.cancel_unsubmitted(id, &cp).unwrap(), cancelled);
        assert!(l.begin_dispatch(&order(1)).is_err());
        assert!(l.record(&order(1)).is_err());
        drop(l);
        let mut l = open(&t);
        assert_eq!(l.state(id).unwrap(), Some(OrderState::CancelledUnsubmitted));
        let cp = l.record(&order(2)).unwrap();
        l.begin_dispatch(&order(2)).unwrap();
        assert!(l
            .cancel_unsubmitted(PaymentId::parse(&order(2).payment_id).unwrap(), &cp)
            .is_err());
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut b = [0; 16];
            getrandom::fill(&mut b).unwrap();
            let p = std::env::temp_dir().join(format!(
                "siworld-order-unit-{}",
                crate::genesis::hex_bytes(&b)
            ));
            std::fs::create_dir(&p).unwrap();
            for n in ["ledger", "witness"] {
                std::fs::create_dir(p.join(n)).unwrap();
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for n in [p.clone(), p.join("ledger"), p.join("witness")] {
                    std::fs::set_permissions(n, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    const PASS: &str = "ledger fault test password";
    fn order(i: u8) -> PaymentOrder {
        PaymentOrder::new(
            PaymentId::parse(&format!("{i:02x}").repeat(32)).unwrap(),
            &siworld_crypto::SpendKey::from_digest(Digest([2; 32])).address(),
            10_000_000,
            false,
        )
    }
    fn create(t: &Temp) -> OrderLedger {
        OrderLedger::create(
            &t.0.join("ledger"),
            &t.0.join("witness"),
            PASS,
            Digest([3; 32]),
            Digest([4; 32]),
        )
        .unwrap()
    }
    fn open(t: &Temp) -> OrderLedger {
        OrderLedger::open(&t.0.join("ledger"), &t.0.join("witness"), PASS).unwrap()
    }
    #[test]
    fn interrupted_append_only_repairs_the_identical_last_request() {
        let t = Temp::new();
        let mut l = create(&t);
        let old = l.record(&order(1)).unwrap();
        assert!(l
            .record_with_hook(&order(2), || Err("injected after ledger commit".into()))
            .is_err());
        assert!(l.checkpoint().is_err());
        assert!(l.record(&order(2)).is_err());
        drop(l);
        let mut l = open(&t);
        assert!(l.verify(&old).is_err());
        let exported = t.0.join("interrupted-pin.json");
        assert!(l.export_checkpoint(&exported, None).is_err());
        assert!(!exported.exists());
        let archive = t.0.join("interrupted-archive");
        assert!(l.archive(&archive, None).is_err());
        assert!(!archive.exists());
        assert!(l.record(&order(1)).is_err());
        assert!(l.record(&order(3)).is_err());
        let mut changed = order(2);
        changed.priority = true;
        assert!(l.record(&changed).is_err());
        let cp = l.record(&order(2)).unwrap();
        assert_eq!(cp.sequence, 2);
        assert_eq!(l.record(&order(2)).unwrap(), cp);
        drop(l);
        assert_eq!(open(&t).checkpoint().unwrap(), cp);
    }
    #[test]
    fn append_process_child() {
        let Ok(root) = std::env::var("SIWORLD_ORDER_CRASH_ROOT") else {
            return;
        };
        let mut l = OrderLedger::open(
            &PathBuf::from(&root).join("ledger"),
            &PathBuf::from(root).join("witness"),
            PASS,
        )
        .unwrap();
        let _ = l.record_with_hook(&order(1), || std::process::exit(87));
        panic!("child did not exit");
    }
    #[test]
    fn abrupt_exit_preserves_order_and_blocks_recovery_until_exact_retry() {
        let t = Temp::new();
        drop(create(&t));
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "orders::tests::append_process_child",
                "--nocapture",
            ])
            .env("SIWORLD_ORDER_CRASH_ROOT", &t.0)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(87));
        let mut l = open(&t);
        assert!(l.checkpoint().is_err());
        assert_eq!(l.record(&order(1)).unwrap().sequence, 1);
    }
    #[test]
    fn identities_canonical_requests_and_bounded_decoder_are_checked() {
        let t = Temp::new();
        let mut l = create(&t);
        let cp = l.record(&order(1)).unwrap();
        let mut equivalent = order(1);
        equivalent.payment_id = equivalent.payment_id.to_uppercase();
        equivalent.amount = "0.10000000".into();
        assert_eq!(l.record(&equivalent).unwrap(), cp);
        for field in ["ledger_id", "genesis", "owner", "head"] {
            let mut pin = serde_json::to_value(&cp).unwrap();
            pin[field] = serde_json::Value::String("ff".repeat(32));
            let pin: Checkpoint = serde_json::from_value(pin).unwrap();
            assert!(l.verify(&pin).is_err());
        }
        let data = Ledger {
            identity: l.data.identity.clone(),
            orders: vec![order(1), order(1)],
            events: None,
        };
        assert!(checkpoints(&data).is_err());
        let invalid = serde_json::json!({"identity":l.data.identity,"orders":[{"payment_id":"00","to":"x","amount":"1","priority":false}]});
        assert!(serde_json::from_value::<Ledger>(invalid).is_err());
        let tiny=serde_json::json!({"payment_id":"ab".repeat(32),"to":"x","amount":"1","priority":false}).to_string();
        let orders = std::iter::repeat_n(tiny.as_str(), MAX_ORDERS + 1)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            serde_json::from_str::<crate::payments::BoundedOrders>(&format!("[{orders}]")).is_err()
        );
        assert!(l.verify(&cp).unwrap().ensure_outside(&t.0).is_err());
    }
}
