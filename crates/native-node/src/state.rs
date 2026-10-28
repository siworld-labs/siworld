//! Deterministic native engineering-chain transition shared by production and replay.
//! No peer-supplied verifier key, private fee opening, or local clock enters this transition.
use crate::proofs::NativeVerifier;
use crate::wire::{Block, DigestBytes, GROUP, Hash, MAX_SLOTS, MIN_SLOTS, Snapshot};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::{FeeOpening, SettlementSlot};
use native::multi_asset::{Digest, F, Hasher, RecentRoots, TREE_DEPTH};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_core::pow::{self, Work};
use std::collections::{BTreeSet, VecDeque};

pub const SNAPSHOT_WINDOW: usize = 4096;
pub const MAX_REORG_DEPTH: u64 = 24;

pub const TARGET_INTERVAL: u64 = 300;
pub const MAX_POW_ITERATIONS: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub network: Hash,
    /// Fixture selector only; an ASERT service uses its immutable target.
    pub work_bits: u8,
    pub genesis_timestamp: u64,
    pub genesis_target: Hash,
    pub target_interval: u64,
    pub pow_iterations: u64,
    pub fixture: bool,
}
impl Config {
    /// Deterministic cheap development fixture, never service qualification.
    pub fn development(network: Hash, work_bits: u8) -> Result<Self, String> {
        if network == [0; 32] || work_bits > 24 {
            return Err("invalid engineering network configuration".into());
        }
        let target = (Work::from_big_endian(&[0xff; 32]) >> usize::from(work_bits)).to_big_endian();
        Ok(Self {
            network,
            work_bits,
            genesis_timestamp: 1,
            genesis_target: target[32..].try_into().expect("256-bit target"),
            target_interval: TARGET_INTERVAL,
            pow_iterations: 0,
            fixture: true,
        })
    }
    /// Explicit disposable ASERT engineering network, not a public genesis.
    pub fn asert_development(
        network: Hash,
        genesis_timestamp: u64,
        genesis_target: Hash,
        pow_iterations: u64,
    ) -> Result<Self, String> {
        if network == [0; 32]
            || genesis_timestamp == 0
            || genesis_target == [0; 32]
            || !(1..=MAX_POW_ITERATIONS).contains(&pow_iterations)
        {
            return Err("invalid ASERT engineering network configuration".into());
        }
        Ok(Self {
            network,
            work_bits: 0,
            genesis_timestamp,
            genesis_target,
            target_interval: TARGET_INTERVAL,
            pow_iterations,
            fixture: false,
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        let expected = if self.fixture {
            Self::development(self.network, self.work_bits)?
        } else {
            Self::asert_development(
                self.network,
                self.genesis_timestamp,
                self.genesis_target,
                self.pow_iterations,
            )?
        };
        if &expected != self {
            return Err("noncanonical engineering network rules".into());
        }
        Ok(())
    }
    /// Fixed-width canonical engineering rules, also used by local and DB metadata.
    pub fn encode_rules(&self) -> [u8; 90] {
        let mut bytes = [0; 90];
        bytes[..32].copy_from_slice(&self.network);
        bytes[32] = self.work_bits;
        bytes[33] = u8::from(self.fixture);
        bytes[34..42].copy_from_slice(&self.genesis_timestamp.to_le_bytes());
        bytes[42..74].copy_from_slice(&self.genesis_target);
        bytes[74..82].copy_from_slice(&self.target_interval.to_le_bytes());
        bytes[82..90].copy_from_slice(&self.pow_iterations.to_le_bytes());
        bytes
    }
    pub fn decode_rules(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 90 || bytes[33] > 1 {
            return Err("invalid engineering rule encoding".into());
        }
        let config = Self {
            network: bytes[..32].try_into().expect("fixed network width"),
            work_bits: bytes[32],
            fixture: bytes[33] == 1,
            genesis_timestamp: u64::from_le_bytes(
                bytes[34..42].try_into().expect("fixed timestamp"),
            ),
            genesis_target: bytes[42..74].try_into().expect("fixed target"),
            target_interval: u64::from_le_bytes(bytes[74..82].try_into().expect("fixed interval")),
            pow_iterations: u64::from_le_bytes(bytes[82..90].try_into().expect("fixed iterations")),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn genesis_id(&self) -> Hash {
        let mut h = blake3::Hasher::new_derive_key("siworld native engineering genesis v2");
        h.update(&self.encode_rules());
        h.update(b"asert:14400;mtp:11;sequential-blake3");
        h.update(native::codec::SUITE_ID);
        h.update(b"transaction:b7:q41:g20;settlement:576:b8:q36:g20");
        *h.finalize().as_bytes()
    }
}

pub trait BlockVerifier {
    fn transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn settlement(
        &self,
        fees: &[Digest],
        subsidy: u64,
        height: u64,
        network: Hash,
        list_hash: Hash,
        reward: &Digest,
        proof: &[u8],
    ) -> Result<(), String>;
}
impl BlockVerifier for NativeVerifier {
    fn transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_transaction(public, context, fee, root, proof)
    }
    fn settlement(
        &self,
        fees: &[Digest],
        subsidy: u64,
        height: u64,
        network: Hash,
        list_hash: Hash,
        reward: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_settlement(fees, subsidy, height, network, list_hash, reward, proof)
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentTree {
    pub count: u64,
    frontier: Vec<Digest>,
    zeros: Vec<Digest>,
    root: Digest,
}
impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}
impl CommitmentTree {
    pub fn new() -> Self {
        let h = Hasher::new();
        let mut zeros = vec![[F::ZERO; 12]];
        for i in 0..TREE_DEPTH {
            zeros.push(h.compress(&zeros[i], &zeros[i]));
        }
        Self {
            count: 0,
            frontier: vec![[F::ZERO; 12]; TREE_DEPTH],
            root: zeros[TREE_DEPTH],
            zeros,
        }
    }
    pub fn root(&self) -> Digest {
        self.root
    }
    pub fn append(&mut self, leaf: Digest) -> Result<(), String> {
        if self.count >= (1u64 << TREE_DEPTH) {
            return Err("commitment tree capacity".into());
        }
        let h = Hasher::new();
        let mut node = leaf;
        let mut index = self.count;
        for level in 0..TREE_DEPTH {
            if index & 1 == 0 {
                self.frontier[level] = node;
                node = h.compress(&node, &self.zeros[level]);
            } else {
                node = h.compress(&self.frontier[level], &node);
            }
            index >>= 1;
        }
        self.count += 1;
        self.root = node;
        Ok(())
    }
    /// Local wallet witness construction; all public commitments must be supplied.
    pub fn path(&self, leaves: &[Digest], index: usize) -> Result<Vec<(Digest, bool)>, String> {
        if leaves.len() as u64 != self.count || index >= leaves.len() {
            return Err("invalid commitment path request".into());
        }
        let h = Hasher::new();
        let mut nodes = leaves.to_vec();
        let mut position = index;
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            let sibling = nodes
                .get(position ^ 1)
                .copied()
                .unwrap_or(self.zeros[level]);
            path.push((sibling, position & 1 == 1));
            nodes = nodes
                .chunks(2)
                .map(|pair| h.compress(&pair[0], pair.get(1).unwrap_or(&self.zeros[level])))
                .collect();
            position >>= 1;
        }
        Ok(path)
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalSnapshot {
    pub selector: Snapshot,
    pub commitment_root: DigestBytes,
    pub recent_root: DigestBytes,
}
#[derive(Clone, Debug)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub tip: Hash,
    pub timestamps: VecDeque<u64>,
    pub cumulative_work: Work,
    pub tree: CommitmentTree,
    pub spent: BTreeSet<DigestBytes>,
    pub commitments: BTreeSet<DigestBytes>,
    pub leaves: Vec<Digest>,
    pub snapshots: VecDeque<CanonicalSnapshot>,
    pub total_subsidy: u128,
    pub fund_direct: u128,
    pub fund_locked: u128,
}
impl State {
    pub fn new(config: Config) -> Result<Self, String> {
        config.validate()?;
        let genesis_timestamp = config.genesis_timestamp;
        let tree = CommitmentTree::new();
        let root = tree.root();
        let h = Hasher::new();
        let mut roots = RecentRoots::new();
        roots.insert(&h, 0, &root, base_fee(0));
        let selector = Snapshot {
            height: 0,
            block_id: config.genesis_id(),
        };
        let recent_root = encode_digest(&roots.tree(&h).root());
        Ok(Self {
            config,
            height: 0,
            tip: selector.block_id,
            timestamps: VecDeque::from([genesis_timestamp]),
            cumulative_work: Work::zero(),
            tree,
            spent: BTreeSet::new(),
            commitments: BTreeSet::new(),
            leaves: Vec::new(),
            snapshots: VecDeque::from([CanonicalSnapshot {
                selector,
                commitment_root: encode_digest(&root),
                recent_root,
            }]),
            total_subsidy: 0,
            fund_direct: 0,
            fund_locked: 0,
        })
    }
    pub fn timestamp(&self) -> u64 {
        *self.timestamps.back().expect("genesis timestamp retained")
    }
    pub fn median_time_past(&self) -> u64 {
        let timestamps: Vec<_> = self.timestamps.iter().copied().collect();
        pow::median_time_past(&timestamps).expect("genesis timestamp retained")
    }
    pub fn next_target(&self) -> Hash {
        pow::asert_target(
            &self.config.genesis_target,
            self.config.genesis_timestamp,
            self.config.target_interval,
            self.height,
            self.timestamp(),
        )
    }
    pub fn tip_snapshot(&self) -> &CanonicalSnapshot {
        self.snapshots.back().expect("genesis snapshot retained")
    }
    pub fn snapshot(&self, selector: Snapshot) -> Result<&CanonicalSnapshot, String> {
        if selector.height > self.height || self.height - selector.height >= SNAPSHOT_WINDOW as u64
        {
            return Err("expired or future canonical snapshot".into());
        }
        self.snapshots
            .iter()
            .find(|s| s.selector == selector)
            .ok_or_else(|| "unknown or removed canonical snapshot".into())
    }
    pub fn recent_roots(&self) -> Result<RecentRoots, String> {
        let h = Hasher::new();
        let mut roots = RecentRoots::new();
        for s in &self.snapshots {
            roots.insert(
                &h,
                s.selector.height,
                &decode_digest(&s.commitment_root).map_err(|_| "invalid stored root")?,
                base_fee(s.selector.height),
            );
        }
        Ok(roots)
    }
    /// All structural, snapshot, spend, output and independent proof checks finish
    /// before any accepted-state field changes. Durable callers commit the block
    /// and resulting fingerprint together before exposing this state.
    pub fn apply(&mut self, block: &Block, verifier: &impl BlockVerifier) -> Result<(), String> {
        block.validate_shape()?;
        if block.network != self.config.network {
            return Err("block network mismatch".into());
        }
        if self.height.checked_add(1) != Some(block.height) {
            return Err("nonconsecutive block height".into());
        }
        if block.parent != self.tip {
            return Err("block parent mismatch".into());
        }
        if block.timestamp <= self.median_time_past() {
            return Err("block timestamp does not exceed median time past".into());
        }
        if block.target != self.next_target() {
            return Err("block target does not match ASERT".into());
        }
        let seed = block.pow_seed()?;
        let work = pow::pow_hash(&seed, block.nonce, self.config.pow_iterations);
        if !pow::meets_target(&work, &block.target) {
            return Err("insufficient engineering proof of work".into());
        }
        let cumulative_work = self
            .cumulative_work
            .checked_add(pow::block_work(&block.target))
            .ok_or("cumulative engineering work overflow")?;
        let id = block.id()?;
        let mut spends = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        let mut leaves = Vec::new();
        let mut fees = Vec::with_capacity(MAX_SLOTS);
        let mut trial_tree = self.tree.clone();
        for tx in &block.transactions {
            let snapshot = self.snapshot(tx.record.snapshot)?;
            let root =
                decode_digest(&snapshot.recent_root).map_err(|_| "invalid stored snapshot root")?;
            let public = PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "noncanonical transaction public values")?;
            let fee =
                decode_digest(&tx.record.fee_commit).map_err(|_| "noncanonical fee commitment")?;
            for nf in public.nf {
                let nf = encode_digest(&nf);
                if self.spent.contains(&nf) || !spends.insert(nf) {
                    return Err("nullifier already used".into());
                }
            }
            for cm in public.cm {
                let bytes = encode_digest(&cm);
                if self.commitments.contains(&bytes) || !outputs.insert(bytes) {
                    return Err("output commitment already used".into());
                }
                trial_tree.append(cm)?;
                leaves.push(cm);
            }
            let context = ProofContext::for_snapshot(
                self.config.network,
                tx.record.snapshot.height,
                tx.record.snapshot.block_id,
            );
            verifier.transaction(&public, &context, &fee, &root, &tx.proof)?;
            fees.push(fee);
        }
        let reward =
            decode_digest(&block.reward.commitment).map_err(|_| "noncanonical miner reward")?;
        if self.commitments.contains(&block.reward.commitment)
            || !outputs.insert(block.reward.commitment)
        {
            return Err("reward commitment already used".into());
        }
        trial_tree.append(reward)?;
        leaves.push(reward);
        fees.extend(
            tail_slots(self.config.network, block.height, block.transactions.len())?
                .iter()
                .map(|s| s.commitment),
        );
        let (miner, direct, locked) = subsidy_split(block.height);
        verifier.settlement(
            &fees,
            miner,
            block.height,
            self.config.network,
            block.list_digest(),
            &reward,
            &block.settlement_proof,
        )?;
        let total = self
            .total_subsidy
            .checked_add(u128::from(miner) + u128::from(direct) + u128::from(locked))
            .ok_or("issuance counter overflow")?;
        let direct = self
            .fund_direct
            .checked_add(u128::from(direct))
            .ok_or("fund counter overflow")?;
        let locked = self
            .fund_locked
            .checked_add(u128::from(locked))
            .ok_or("fund counter overflow")?;
        let mut roots = RecentRoots::new();
        let h = Hasher::new();
        for s in &self.snapshots {
            if block.height - s.selector.height < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &h,
                    s.selector.height,
                    &decode_digest(&s.commitment_root).map_err(|_| "invalid stored root")?,
                    base_fee(s.selector.height),
                );
            }
        }
        roots.insert(&h, block.height, &trial_tree.root(), base_fee(block.height));
        let snapshot = CanonicalSnapshot {
            selector: Snapshot {
                height: block.height,
                block_id: id,
            },
            commitment_root: encode_digest(&trial_tree.root()),
            recent_root: encode_digest(&roots.tree(&h).root()),
        };
        self.tree = trial_tree;
        self.height = block.height;
        self.tip = id;
        self.timestamps.push_back(block.timestamp);
        while self.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
            self.timestamps.pop_front();
        }
        self.cumulative_work = cumulative_work;
        self.total_subsidy = total;
        self.fund_direct = direct;
        self.fund_locked = locked;
        self.spent.extend(spends);
        self.commitments.extend(outputs);
        self.leaves.extend(leaves);
        self.snapshots.push_back(snapshot);
        while self.snapshots.len() > SNAPSHOT_WINDOW {
            self.snapshots.pop_front();
        }
        Ok(())
    }
    /// Public deterministic state checksum for replay and storage corruption checks.
    pub fn fingerprint(&self) -> Hash {
        let mut h = blake3::Hasher::new_derive_key("siworld native engineering state v2");
        h.update(&self.config.genesis_id());
        h.update(&self.height.to_le_bytes());
        h.update(&self.tip);
        h.update(&self.cumulative_work.to_big_endian());
        h.update(&(self.timestamps.len() as u64).to_le_bytes());
        for timestamp in &self.timestamps {
            h.update(&timestamp.to_le_bytes());
        }
        h.update(&encode_digest(&self.tree.root()));
        h.update(&self.tree.count.to_le_bytes());
        for n in &self.spent {
            h.update(n);
        }
        for c in &self.commitments {
            h.update(c);
        }
        h.update(&self.total_subsidy.to_le_bytes());
        h.update(&self.fund_direct.to_le_bytes());
        h.update(&self.fund_locked.to_le_bytes());
        for s in &self.snapshots {
            h.update(&s.selector.height.to_le_bytes());
            h.update(&s.selector.block_id);
            h.update(&s.commitment_root);
            h.update(&s.recent_root);
        }
        *h.finalize().as_bytes()
    }
}

pub fn base_fee(height: u64) -> u64 {
    siworld_core::issuance::fee_base(siworld_core::issuance::epoch_of(height))
}
pub fn subsidy_split(height: u64) -> (u64, u64, u64) {
    siworld_core::issuance::reward_split(siworld_core::issuance::block_reward(
        siworld_core::issuance::epoch_of(height),
    ))
}
pub fn satisfies_work(id: &Hash, bits: u8) -> bool {
    if bits > 24 {
        return false;
    }
    let mut remaining = bits;
    for byte in id {
        if remaining == 0 {
            return true;
        }
        let take = remaining.min(8);
        if byte.leading_zeros() < u32::from(take) {
            return false;
        }
        remaining -= take;
    }
    remaining == 0
}

/// Public, deterministic zero-fee rows of the fixed-576 relation. These are
/// internal settlement rows, never additional transactions or chain flags.
pub fn tail_slots(network: Hash, height: u64, count: usize) -> Result<Vec<SettlementSlot>, String> {
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
        return Err("invalid settlement position count".into());
    }
    let h = Hasher::new();
    let mut slots = Vec::with_capacity(MAX_SLOTS - count);
    for index in count..MAX_SLOTS {
        let mut hash = blake3::Hasher::new_derive_key("siworld native zero fee settlement tail v1");
        hash.update(&network);
        hash.update(&height.to_le_bytes());
        hash.update(&(count as u16).to_le_bytes());
        hash.update(&(index as u16).to_le_bytes());
        let raw = hash.finalize();
        let blind = core::array::from_fn(|i| {
            F::from_u32(
                u32::from_le_bytes(
                    raw.as_bytes()[i * 4..i * 4 + 4]
                        .try_into()
                        .expect("fixed word"),
                ) % F::ORDER_U32,
            )
        });
        slots.push(SettlementSlot::from_opening(&h, FeeOpening::dummy(blind)));
    }
    Ok(slots)
}

#[cfg(test)]
mod tests;
