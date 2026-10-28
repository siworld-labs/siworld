//! Native admission, verified-work synchronization and production composition.
//! This module never starts a listener or supplies an authentication provider.
use crate::admission::{AdmissionError, Mempool, PeerId};
use crate::chain::{BranchOutcome, CandidatePolicy, ChainError};
use crate::p2p::{self, Budget, Packet, Reservation, Session};
use crate::pool::Pool;
use crate::producer::{self, ProducedBlock};
use crate::proofs::NativeProver;
use crate::state::{BlockVerifier, State};
use crate::store::Store;
use crate::sync::{self, Batch, CompactBlock, Locator, Reference, Staging};
use crate::wire::{
    Block, GROUP, Hash, MAX_ENVELOPE_BYTES, MAX_SLOTS, MIN_SLOTS, SIDECAR_BYTES, Sidecar, Snapshot,
    Transaction,
};
use std::io::{Read, Write};

#[derive(Debug)]
pub enum Error {
    Transport(p2p::Error),
    Admission(AdmissionError),
    Chain(ChainError),
    Local(String),
}
impl From<p2p::Error> for Error {
    fn from(e: p2p::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<AdmissionError> for Error {
    fn from(e: AdmissionError) -> Self {
        Self::Admission(e)
    }
}
impl From<ChainError> for Error {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}
impl From<String> for Error {
    fn from(e: String) -> Self {
        Self::Local(e)
    }
}
fn invalid() -> Error {
    Error::Transport(p2p::Error::InvalidProtocol)
}

pub struct Node<V> {
    store: Store,
    verifier: V,
    mempool: Mempool,
    padding: Pool,
    budget: Budget,
}
impl<V: BlockVerifier> Node<V> {
    pub fn new(store: Store, verifier: V) -> Self {
        let network = store.state().config.network;
        Self {
            store,
            verifier,
            mempool: Mempool::new(network),
            padding: Pool::new(network),
            budget: Budget::default(),
        }
    }
    pub fn state(&self) -> &State {
        self.store.state()
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }
    /// Supply clones of this one budget to every node session.
    pub fn transport_budget(&self) -> Budget {
        self.budget.clone()
    }
    pub fn binding(&self) -> p2p::Binding {
        p2p::Binding::new(&self.state().config)
    }
    /// Trusted local wallet ingress has the same verification and bounded quota
    /// as one remote identity. It does not infer a local bypass for proofs.
    pub fn submit_local(
        &mut self,
        envelope: &[u8],
        sidecar: Option<&[u8]>,
    ) -> Result<Hash, AdmissionError> {
        let peer = PeerId(blake3::derive_key(
            "siworld native local admission identity v1",
            &self.state().config.network,
        ));
        self.mempool
            .submit_encoded(self.store.state(), peer, envelope, sidecar, &self.verifier)
    }
    fn reconcile_pools(&mut self) -> Result<(), Error> {
        self.mempool.prune(self.store.state())?;
        self.padding.prune(self.store.state())?;
        Ok(())
    }
    pub fn import_branch(
        &mut self,
        ancestor: u64,
        blocks: &[Block],
        policy: CandidatePolicy,
    ) -> Result<BranchOutcome, Error> {
        let result = self
            .store
            .consider_branch(ancestor, blocks, policy, &self.verifier)?;
        if matches!(result, BranchOutcome::Adopted { .. }) {
            self.reconcile_pools()?;
        }
        Ok(result)
    }
    pub fn precompute_one(&mut self, prover: &NativeProver) -> Result<(), Error> {
        self.padding.prune(self.store.state())?;
        if !self.padding.can_grow() {
            return Err(Error::Transport(p2p::Error::ResourceExhausted));
        }
        let value = producer::prepare_padding(self.store.state(), prover)?;
        self.padding
            .insert(self.store.state(), value, &self.verifier)?;
        Ok(())
    }
    /// Real pending entries remain reserved until canonical inclusion. A failed
    /// candidate can consume padding reservations but never deletes wallet work.
    /// The caller must durably save reward_secret before appending the block.
    pub fn prepare_block(
        &mut self,
        prover: &NativeProver,
        slots: usize,
        timestamp: u64,
    ) -> Result<ProducedBlock, Error> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots) || !slots.is_multiple_of(GROUP) {
            return Err(invalid());
        }
        self.reconcile_pools()?;
        let mut values = self.mempool.select(self.store.state(), slots)?;
        let remaining = slots - values.len();
        values.extend(self.padding.take_for_fill(self.store.state(), remaining)?);
        Ok(producer::assemble(
            self.store.state(),
            prover,
            values,
            timestamp,
        )?)
    }
    fn session<S>(&self, session: &Session<S>) -> Result<(), Error>
    where
        S: Read + Write,
    {
        if !session.shares_budget(&self.budget) || session.binding() != self.binding() {
            return Err(invalid());
        }
        Ok(())
    }
    /// Serve one authenticated request. Framing or I/O errors require dropping
    /// the session. Branch announcements are fully verified or request retry.
    pub fn serve_once<S: Read + Write>(&mut self, session: &mut Session<S>) -> Result<(), Error> {
        self.session(session)?;
        match session.receive()? {
            Packet::Control {
                kind,
                request,
                body,
                reservation,
            } => {
                let _guard = reservation;
                match kind {
                    p2p::GET_BLOCKS => {
                        let (ancestor, after) = decode_request(&body, &self.store)?;
                        // Reserve the batch before reading/copying any stored proof.
                        // Leave bounded control-frame space while streaming replies.
                        let allowance = self
                            .budget
                            .available()?
                            .saturating_sub(p2p::MAX_CONTROL_BYTES + 65536);
                        let batch_reservation = self.budget.reserve(allowance)?;
                        let batch = match sync::serve_batch(
                            &self.store,
                            ancestor,
                            after,
                            sync::MAX_BATCH_BLOCKS,
                            allowance.saturating_sub(65536),
                        ) {
                            Ok(b) => b,
                            Err(_) => {
                                session.send_control(p2p::UNAVAILABLE, request, &[])?;
                                return Ok(());
                            }
                        };
                        let meta = BatchMeta {
                            ancestor,
                            after,
                            count: batch.blocks.len() as u16,
                            more: batch.more,
                        };
                        session.send_control(p2p::SYNC_META, request, &meta.encode())?;
                        for block in &batch.blocks {
                            session.send_reserved_block(request, block, &batch_reservation)?;
                        }
                        session.send_control(p2p::END_BATCH, request, &[])?;
                    }
                    p2p::TRANSACTION => {
                        let (envelope, sidecar) = decode_gossip(&body)?;
                        self.mempool.submit_encoded(
                            self.store.state(),
                            PeerId(session.peer()),
                            envelope,
                            Some(sidecar),
                            &self.verifier,
                        )?;
                    }
                    p2p::GET_TRANSACTIONS => {
                        let references = decode_references(&body)?;
                        for r in references {
                            let Some(tx) = self.mempool.transaction(&r.statement).filter(|tx| {
                                sync::reference(tx, &self.state().config.network) == r
                            }) else {
                                session.send_control(p2p::UNAVAILABLE, request, &[])?;
                                return Ok(());
                            };
                            let _copy_guard = self.budget.reserve(MAX_ENVELOPE_BYTES + 64)?;
                            let envelope = tx.encode_envelope(&self.state().config.network)?;
                            session.send_control(p2p::TRANSACTION, request, &envelope)?;
                        }
                        session.send_control(p2p::END_BATCH, request, &[])?;
                    }
                    p2p::COMPACT_BLOCK => {
                        let _compact_copy = self.budget.reserve(
                            body.len()
                                .checked_add(65536)
                                .ok_or(p2p::Error::ResourceExhausted)?,
                        )?;
                        let compact = CompactBlock::decode(&body, &self.state().config.network)
                            .map_err(|_| invalid())?;
                        let _reconstruction = self
                            .budget
                            .reserve(crate::wire::MAX_BLOCK_BYTES + MAX_ENVELOPE_BYTES + 65536)?;
                        match compact
                            .reconstruct(|r| self.mempool.transaction(&r.statement).cloned())
                        {
                            Ok(block) => {
                                self.import_extension(&block)?;
                            }
                            Err(_) => {
                                session.send_control(p2p::UNAVAILABLE, request, &[])?;
                            }
                        }
                    }
                    _ => return Err(invalid()),
                }
                Ok(())
            }
            Packet::Block {
                block, reservation, ..
            } => {
                let _guard = reservation;
                self.import_extension(&block)
            }
        }
    }
    fn import_extension(&mut self, block: &Block) -> Result<(), Error> {
        if block.parent != self.state().tip {
            return Err(Error::Transport(p2p::Error::Unavailable));
        }
        self.import_branch(
            self.state().height,
            std::slice::from_ref(block),
            CandidatePolicy::default(),
        )?;
        Ok(())
    }
    /// Pull one bounded batch. Advertised work never enters fork choice.
    /// Failure discards this attempt's uncommitted branch and reservations.
    /// A false result exhausts this peer's response; it does not establish that
    /// the local node has the globally strongest chain or a trusted checkpoint.
    pub fn synchronize<S: Read + Write>(
        &mut self,
        session: &mut Session<S>,
        request: u64,
        attempt: &mut SyncAttempt,
    ) -> Result<bool, Error> {
        let result = self.synchronize_inner(session, request, attempt);
        if result.is_err() {
            attempt.clear();
        }
        result
    }
    fn synchronize_inner<S: Read + Write>(
        &mut self,
        session: &mut Session<S>,
        request: u64,
        attempt: &mut SyncAttempt,
    ) -> Result<bool, Error> {
        self.session(session)?;
        if attempt.peer.is_some_and(|peer| peer != session.peer()) {
            return Err(invalid());
        }
        attempt.peer = Some(session.peer());
        let body = if let Some(staging) = &attempt.staging {
            encode_continue(staging.base(), staging.continuation()?)
        } else {
            let mut b = vec![0];
            b.extend(Locator::from_store(&self.store)?.encode()?);
            b
        };
        session.send_control(p2p::GET_BLOCKS, request, &body)?;
        let meta = match session.receive()? {
            Packet::Control {
                kind: p2p::SYNC_META,
                request: r,
                body,
                ..
            } if r == request => BatchMeta::decode(&body)?,
            Packet::Control {
                kind: p2p::UNAVAILABLE,
                request: r,
                ..
            } if r == request => return Err(p2p::Error::Unavailable.into()),
            _ => return Err(invalid()),
        };
        if attempt.staging.is_none() {
            if meta.after != meta.ancestor {
                return Err(invalid());
            }
            attempt.staging = Some(Staging::new(
                &self.store,
                meta.ancestor,
                CandidatePolicy::default(),
            )?);
        }
        let staging = attempt.staging.as_ref().expect("initialized staging");
        if (meta.ancestor, meta.after) != (staging.base(), staging.continuation()?) {
            return Err(invalid());
        }
        let mut blocks = Vec::with_capacity(usize::from(meta.count));
        let mut guards = Vec::with_capacity(usize::from(meta.count));
        for _ in 0..meta.count {
            match session.receive()? {
                Packet::Block {
                    request: r,
                    block,
                    reservation,
                } if r == request => {
                    blocks.push(*block);
                    guards.push(reservation);
                }
                _ => return Err(invalid()),
            }
        }
        match session.receive()? {
            Packet::Control {
                kind: p2p::END_BATCH,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => {}
            _ => return Err(invalid()),
        }
        if blocks.is_empty() {
            if meta.more {
                return Err(invalid());
            }
            attempt.clear();
            return Ok(false);
        }
        let result = attempt
            .staging
            .as_mut()
            .expect("initialized staging")
            .accept(
                &mut self.store,
                Batch {
                    ancestor: meta.ancestor,
                    after: meta.after,
                    blocks,
                    more: meta.more,
                },
                &self.verifier,
            )?;
        if matches!(result, BranchOutcome::Adopted { .. }) {
            attempt.reservations.clear();
            self.reconcile_pools()?;
        } else {
            attempt.reservations.extend(guards);
        }
        if !meta.more {
            attempt.clear();
        }
        Ok(meta.more)
    }
    /// Exact-proof compact recovery; returned envelopes omit private fee openings
    /// and must never be admitted as gossip without a separately checked sidecar.
    pub fn fetch_missing<S: Read + Write>(
        &self,
        session: &mut Session<S>,
        request: u64,
        references: &[Reference],
    ) -> Result<Recovered, Error> {
        self.session(session)?;
        let body = encode_references(references)?;
        session.send_control(p2p::GET_TRANSACTIONS, request, &body)?;
        let mut transactions = Vec::with_capacity(references.len());
        let mut reservations = Vec::with_capacity(references.len());
        for expected in references {
            match session.receive()? {
                Packet::Control {
                    kind: p2p::TRANSACTION,
                    request: r,
                    body,
                    reservation,
                } if r == request => {
                    // The original packet guard covers body. Reserve the decoded
                    // proof copy before it coexists with that original buffer.
                    let _body_guard = reservation;
                    let retained = self.budget.reserve(
                        body.len()
                            .checked_add(64)
                            .ok_or(p2p::Error::ResourceExhausted)?,
                    )?;
                    let tx = Transaction::decode_envelope(&body, &self.state().config.network)
                        .map_err(|_| invalid())?;
                    if sync::reference(&tx, &self.state().config.network) != *expected {
                        return Err(invalid());
                    }
                    drop(body);
                    transactions.push(tx);
                    reservations.push(retained);
                }
                Packet::Control {
                    kind: p2p::UNAVAILABLE,
                    request: r,
                    ..
                } if r == request => return Err(p2p::Error::Unavailable.into()),
                _ => return Err(invalid()),
            }
        }
        match session.receive()? {
            Packet::Control {
                kind: p2p::END_BATCH,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => {}
            _ => return Err(invalid()),
        }
        Ok(Recovered {
            transactions,
            _reservations: reservations,
        })
    }
}
#[derive(Default)]
pub struct SyncAttempt {
    peer: Option<Hash>,
    staging: Option<Staging>,
    reservations: Vec<Reservation>,
}
impl SyncAttempt {
    pub fn clear(&mut self) {
        self.peer = None;
        self.staging = None;
        self.reservations.clear();
    }
}
pub struct Recovered {
    transactions: Vec<Transaction>,
    _reservations: Vec<Reservation>,
}
impl Recovered {
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BatchMeta {
    ancestor: Snapshot,
    after: Snapshot,
    count: u16,
    more: bool,
}
fn put_snapshot(out: &mut Vec<u8>, s: Snapshot) {
    out.extend_from_slice(&s.height.to_le_bytes());
    out.extend_from_slice(&s.block_id);
}
fn snapshot(bytes: &[u8]) -> Snapshot {
    Snapshot {
        height: u64::from_le_bytes(bytes[..8].try_into().expect("bounded snapshot")),
        block_id: bytes[8..40].try_into().expect("bounded ID"),
    }
}
impl BatchMeta {
    fn encode(self) -> [u8; 83] {
        let mut out = Vec::with_capacity(83);
        put_snapshot(&mut out, self.ancestor);
        put_snapshot(&mut out, self.after);
        out.extend_from_slice(&self.count.to_le_bytes());
        out.push(u8::from(self.more));
        out.try_into().expect("fixed metadata")
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 83 || bytes[82] > 1 {
            return Err(invalid());
        }
        let count = u16::from_le_bytes(bytes[80..82].try_into().expect("fixed count"));
        if usize::from(count) > sync::MAX_BATCH_BLOCKS {
            return Err(invalid());
        }
        Ok(Self {
            ancestor: snapshot(&bytes[..40]),
            after: snapshot(&bytes[40..80]),
            count,
            more: bytes[82] == 1,
        })
    }
}
fn encode_continue(base: Snapshot, after: Snapshot) -> Vec<u8> {
    let mut out = vec![1];
    put_snapshot(&mut out, base);
    put_snapshot(&mut out, after);
    out
}
fn decode_request(bytes: &[u8], store: &Store) -> Result<(Snapshot, Snapshot), Error> {
    match bytes.first() {
        Some(0) => {
            let locator = Locator::decode(&bytes[1..]).map_err(|_| invalid())?;
            let base = locator.common_ancestor(store).map_err(|_| invalid())?;
            Ok((base, base))
        }
        Some(1) if bytes.len() == 81 => Ok((snapshot(&bytes[1..41]), snapshot(&bytes[41..81]))),
        _ => Err(invalid()),
    }
}
pub fn encode_gossip(
    tx: &Transaction,
    sidecar: &Sidecar,
    network: &Hash,
) -> Result<Vec<u8>, String> {
    if sidecar.transaction_id != tx.record.statement_id(network) {
        return Err("gossip sidecar identity mismatch".into());
    }
    let envelope = tx.encode_envelope(network)?;
    let mut out = Vec::with_capacity(4 + envelope.len() + SIDECAR_BYTES);
    out.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
    out.extend(envelope);
    out.extend(sidecar.encode()?);
    Ok(out)
}
fn decode_gossip(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < 4 + SIDECAR_BYTES {
        return Err(invalid());
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().expect("fixed length")) as usize;
    if n > MAX_ENVELOPE_BYTES || bytes.len() != 4 + n + SIDECAR_BYTES {
        return Err(invalid());
    }
    Ok((&bytes[4..4 + n], &bytes[4 + n..]))
}
fn encode_references(values: &[Reference]) -> Result<Vec<u8>, Error> {
    if values.is_empty()
        || values.len() > sync::MAX_MISSING
        || values
            .iter()
            .map(|r| r.statement)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(2 + 64 * values.len());
    bytes.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for r in values {
        bytes.extend_from_slice(&r.statement);
        bytes.extend_from_slice(&r.proof);
    }
    Ok(bytes)
}
fn decode_references(bytes: &[u8]) -> Result<Vec<Reference>, Error> {
    if bytes.len() < 2 {
        return Err(invalid());
    }
    let n = u16::from_le_bytes(bytes[..2].try_into().expect("fixed count")) as usize;
    if n == 0 || n > sync::MAX_MISSING || bytes.len() != 2 + 64 * n {
        return Err(invalid());
    }
    let values: Vec<_> = bytes[2..]
        .chunks_exact(64)
        .map(|r| Reference {
            statement: r[..32].try_into().expect("fixed statement"),
            proof: r[32..].try_into().expect("fixed proof"),
        })
        .collect();
    encode_references(&values)?;
    Ok(values)
}
#[cfg(test)]
mod tests;
