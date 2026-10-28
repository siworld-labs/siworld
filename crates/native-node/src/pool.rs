//! Bounded private queue of independently verified pre-generated positions.
//! Entries move into one candidate only; no queue metadata is exported.
use crate::state::{BlockVerifier, State};
use crate::wire::{
    DigestBytes, GROUP, Hash, MAX_SLOTS, MAX_TX_PROOF, MIN_SLOTS, SIDECAR_BYTES, TX_PREFIX_BYTES,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::FeeOpening;
use native::multi_asset::{Digest, Hasher};
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_READY: usize = 64;
pub const MAX_ENTRIES: usize = 128;
pub const MAX_BYTES: usize = 65 * 1024 * 1024;
const MAX_CONSUMED: usize = 1024;
const RESERVATION_BYTES: usize = 32 + 5 * 48 + 256;

/// Move-only private proof and its settlement opening.
pub struct Padding {
    pub(crate) transaction: Transaction,
    pub(crate) opening: FeeOpening,
}
struct Reserved {
    value: Padding,
    inputs: [DigestBytes; 2],
    outputs: [DigestBytes; 3],
    bytes: usize,
}
struct Consumed {
    inputs: [DigestBytes; 2],
    outputs: [DigestBytes; 3],
}
pub struct Pool {
    network: Hash,
    entries: BTreeMap<Hash, Reserved>,
    inputs: BTreeSet<DigestBytes>,
    outputs: BTreeSet<DigestBytes>,
    consumed: BTreeMap<Hash, Consumed>,
    bytes: usize,
}
impl Pool {
    pub fn new(network: Hash) -> Self {
        Self {
            network,
            entries: BTreeMap::new(),
            inputs: BTreeSet::new(),
            outputs: BTreeSet::new(),
            consumed: BTreeMap::new(),
            bytes: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn ready(&self) -> bool {
        self.len() >= MIN_READY
    }
    /// Reserve enough room for a maximum-sized next proof before starting work.
    pub fn can_grow(&self) -> bool {
        let maximum = TX_PREFIX_BYTES
            + MAX_TX_PROOF
            + SIDECAR_BYTES
            + RESERVATION_BYTES
            + std::mem::size_of::<Reserved>();
        self.len() < MAX_ENTRIES
            && self
                .bytes
                .checked_add(maximum)
                .is_some_and(|n| n <= MAX_BYTES)
    }
    fn network(&self, state: &State) -> Result<(), String> {
        if self.network != state.config.network {
            return Err("private queue network mismatch".into());
        }
        Ok(())
    }
    fn public(state: &State, value: &Padding) -> Result<(PublicTransaction, Digest), String> {
        let tx = &value.transaction;
        tx.record.validate()?;
        if tx.proof.is_empty() || tx.proof.len() > MAX_TX_PROOF {
            return Err("private queue proof byte limit".into());
        }
        let snapshot = state.snapshot(tx.record.snapshot)?;
        let root =
            decode_digest(&snapshot.recent_root).map_err(|_| "invalid canonical recent root")?;
        let public = PublicTransaction::decode(&tx.record.body)
            .map_err(|_| "invalid private queue public fields")?;
        let inputs = public.nf.map(|nf| encode_digest(&nf));
        let outputs = public.cm.map(|cm| encode_digest(&cm));
        if inputs[0] == inputs[1]
            || outputs.iter().collect::<BTreeSet<_>>().len() != outputs.len()
            || inputs.iter().any(|nf| state.spent.contains(nf))
            || outputs.iter().any(|cm| state.commitments.contains(cm))
        {
            return Err("private queue canonical-state conflict".into());
        }
        if value.opening.fee != 0
            || !value.opening.dummy
            || value.opening.priority
            || encode_digest(&Hasher::new().fee_commit(value.opening.fee, &value.opening.blind))
                != tx.record.fee_commit
        {
            return Err("private queue fee opening mismatch".into());
        }
        Ok((public, root))
    }
    /// Verify through the independent block verifier before reserving any input,
    /// output, identity or byte budget. A rejected insertion leaves the queue unchanged.
    pub fn insert(
        &mut self,
        state: &State,
        mut value: Padding,
        verifier: &impl BlockVerifier,
    ) -> Result<(), String> {
        self.network(state)?;
        let (public, root) = Self::public(state, &value)?;
        // Serialization may leave a growing Vec with capacity above its wire
        // length. Normalize before retention so reserved capacity is bounded.
        value.transaction.proof = value.transaction.proof.into_boxed_slice().into_vec();
        let id = value.transaction.record.statement_id(&self.network);
        let inputs = public.nf.map(|nf| encode_digest(&nf));
        let outputs = public.cm.map(|cm| encode_digest(&cm));
        let bytes = TX_PREFIX_BYTES
            .checked_add(value.transaction.proof.capacity())
            .and_then(|n| {
                n.checked_add(SIDECAR_BYTES + RESERVATION_BYTES + std::mem::size_of::<Reserved>())
            })
            .ok_or("private queue byte accounting overflow")?;
        if self.entries.len() >= MAX_ENTRIES
            || self.bytes.checked_add(bytes).is_none_or(|n| n > MAX_BYTES)
        {
            return Err("private queue capacity limit".into());
        }
        if self.entries.contains_key(&id)
            || self.consumed.contains_key(&id)
            || inputs.iter().any(|nf| {
                self.inputs.contains(nf) || self.consumed.values().any(|c| c.inputs.contains(nf))
            })
            || outputs.iter().any(|cm| {
                self.outputs.contains(cm) || self.consumed.values().any(|c| c.outputs.contains(cm))
            })
        {
            return Err("private queue reservation conflict".into());
        }
        let selector = value.transaction.record.snapshot;
        let context = ProofContext::for_snapshot(self.network, selector.height, selector.block_id);
        let fee = decode_digest(&value.transaction.record.fee_commit)
            .map_err(|_| "invalid private fee commitment")?;
        verifier.transaction(&public, &context, &fee, &root, &value.transaction.proof)?;
        self.inputs.extend(inputs);
        self.outputs.extend(outputs);
        self.bytes += bytes;
        self.entries.insert(
            id,
            Reserved {
                value,
                inputs,
                outputs,
                bytes,
            },
        );
        Ok(())
    }
    pub fn prune(&mut self, state: &State) -> Result<usize, String> {
        self.network(state)?;
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| Self::public(state, &entry.value).is_err().then_some(*id))
            .collect();
        for id in &removed {
            let entry = self
                .entries
                .remove(id)
                .expect("selected private queue entry");
            for nf in entry.inputs {
                self.inputs.remove(&nf);
            }
            for cm in entry.outputs {
                self.outputs.remove(&cm);
            }
            self.bytes -= entry.bytes;
        }
        // Accepted canonical spends absorb their tombstones. Uncommitted entries
        // stay reserved even if a candidate failed or a snapshot later expires.
        self.consumed
            .retain(|_, entry| !entry.inputs.iter().all(|nf| state.spent.contains(nf)));
        Ok(removed.len())
    }
    pub fn take(&mut self, state: &State, count: usize) -> Result<Vec<Padding>, String> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
            return Err("candidate positions must be 64 through 576 in groups of 16".into());
        }
        self.prune(state)?;
        if self.entries.len() < count
            || self
                .consumed
                .len()
                .checked_add(count)
                .is_none_or(|n| n > MAX_CONSUMED)
        {
            return Err("private queue not ready or consumed reservation limit reached".into());
        }
        let ids: Vec<_> = self.entries.keys().take(count).copied().collect();
        let mut selected = Vec::with_capacity(count);
        for id in ids {
            let entry = self
                .entries
                .remove(&id)
                .expect("selected private queue entry");
            for nf in entry.inputs {
                self.inputs.remove(&nf);
            }
            for cm in entry.outputs {
                self.outputs.remove(&cm);
            }
            self.bytes -= entry.bytes;
            self.consumed.insert(
                id,
                Consumed {
                    inputs: entry.inputs,
                    outputs: entry.outputs,
                },
            );
            selected.push(entry.value);
        }
        Ok(selected)
    }
}
#[cfg(test)]
mod tests;
