//! The Plonky3 proof system: STARK leaf proofs for slots and their recursive
//! aggregation into one container proof per block, behind the
//! [`ProofSystem`] interface consensus, the mempool and the wallet use.
//!
//! The circuits are the ones measured in docs/benchmarks.md
//! (`crates/bench-stark/plonky3`): the accumulator-mode leaf AIR and the
//! binary aggregation whose root proves the statement of
//! [`ContainerPublic`]. This crate maps siworld's witnesses, slots and
//! anchors onto them and checks, natively, everything the aggregation
//! assumes about a leaf before it proves a node over it.
//!
//! A container proof travels in Plonky3-recursion's canonical artifact
//! format and is verified against the root verifying key of the chain's
//! container size: the relation, the preprocessed commitments and the FRI
//! parameters, 458 bytes. Key setup is deterministic, so the keys of the
//! decided parameters are pinned in `keys/` and a verifying node starts at
//! once. A mining node also prepares one aggregation layer per level of the
//! container tree, which proves one sample node per internal level, and
//! refuses to start if the key it rebuilds differs from the pinned one.

mod cache;
mod convert;
mod leaf;
mod schedule;

use std::sync::{Arc, Mutex};

use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, TablePacking};
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableArtifactImport, TypedArtifactVerifier,
};
use p3_recursion::builtin_config::koala_bear_d4_poseidon2_random_codeword;
use p3_recursion::{ProveNextLayerParams, VerifierLimits};
use rand::rngs::StdRng;
use rand::SeedableRng;
pub use schedule::{FixedAggregationSchedule, PRIVATE_WORKER_BATCHES};
use siworld_bench_common::{acc_witnesses, sample_empty_slot, ANCHOR_DEPTH, FEE_BASE, TREE_DEPTH};
use siworld_bench_plonky3::agg::{
    anchor_leaf, compose_acc, AccAggregation, Child, Input, MinerNote, NUM_ROOT_PUBLIC,
};
pub use siworld_bench_plonky3::FriParams;
use siworld_bench_plonky3::{Cfg, SlotProver};
use siworld_circuits::{
    check_slot, slot_for, AggregateError, ContainerPublic, FeeOpening, Leaf, ProofSystem,
    ProveError, RelationContext, SlotProof, SlotWitness,
};
use siworld_core::codec::MAX_PROOF_LEN;
use siworld_core::params::{ChainParams, COINBASE_MATURITY};
use siworld_core::{ContainerProof, Digest, Height, Note, Slot};
use siworld_crypto::miner_rho;
use siworld_poseidon2::{PrimeField32, F};
use siworld_state::{base_fee, RecentRoots};

use crate::convert::{anchor_path, field_digest};

/// Most slots a container may hold: the aggregation range-checks the count
/// to 8 bits, and docs/protocol.md goes no further than 128.
pub const MAX_CONTAINER_SIZE: u32 = 128;

/// The root verifying key of each container size at the decided FRI
/// parameters, by slot count (`keys/root-n{N}.bin`, written by
/// `siworld-bench-plonky3 --acc --leaves N --export DIR`).
pub const ROOT_KEYS: [(u32, &[u8]); 7] = [
    (2, include_bytes!("../keys/root-n2.bin")),
    (4, include_bytes!("../keys/root-n4.bin")),
    (8, include_bytes!("../keys/root-n8.bin")),
    (16, include_bytes!("../keys/root-n16.bin")),
    (32, include_bytes!("../keys/root-n32.bin")),
    (64, include_bytes!("../keys/root-n64.bin")),
    (128, include_bytes!("../keys/root-n128.bin")),
];

/// The pinned key of container size `n` at the decided parameters.
pub fn pinned_root_key(n: u32) -> Option<&'static [u8]> {
    ROOT_KEYS.iter().find(|(k, _)| *k == n).map(|(_, key)| *key)
}

/// Why a [`Plonky3System`] could not be prepared.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SetupError {
    /// The container size is not a power of two between 2 and
    /// [`MAX_CONTAINER_SIZE`].
    ContainerSize(u32),
    /// The circuits fix the 𝒜 depth at 12 (a window of 4096 blocks).
    AnchorWindow(u32),
    /// The circuits fix the commitment-tree depth at 40.
    TreeDepth(u8),
    /// A circuit could not be built or its sample proof failed.
    Circuit(String),
    /// The root verifying key does not decode.
    Key(String),
    /// The circuits built here have another root verifying key than the one
    /// this system was given (or the pinned one): the circuit changed, or the
    /// key is from another parameter set. Proofs made here would not verify.
    KeyMismatch,
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContainerSize(n) => write!(
                f,
                "container size {n}: the Plonky3 system needs a power of two from 2 to {MAX_CONTAINER_SIZE}"
            ),
            Self::AnchorWindow(w) => {
                write!(f, "anchor window {w}: the circuits need {}", 1u32 << ANCHOR_DEPTH)
            }
            Self::TreeDepth(d) => {
                write!(f, "commitment-tree depth {d}: the circuits need {TREE_DEPTH}")
            }
            Self::Circuit(e) => write!(f, "circuit setup: {e}"),
            Self::Key(e) => write!(f, "root verifying key: {e}"),
            Self::KeyMismatch => f.write_str(
                "the aggregation circuits built here do not match the root verifying key",
            ),
        }
    }
}

impl std::error::Error for SetupError {}

/// A node proof with the full statement it proves (its public values are the
/// statement's digest).
type NodeProof = (BatchStarkProof<Cfg>, Vec<F>);

/// The prepared Plonky3 proof system of one chain: the leaf prover every
/// wallet needs, the root verifier, and, on a miner, one aggregation layer
/// per level of the container tree.
pub struct Plonky3System {
    container_size: u32,
    fri: FriParams,
    leaf: Arc<SlotProver>,
    key: Vec<u8>,
    verifier: TypedArtifactVerifier<Cfg>,
    /// `layers[k]` proves level k + 1; the last one is the root. `None` on a
    /// node that does not aggregate.
    layers: Option<Vec<AccAggregation>>,
    parallel: usize,
    /// One completed tree, scoped to this immutable suite/key/size. No disk
    /// import and no retention of miner witnesses or root proofs.
    cache: Mutex<cache::TreeCache<NodeProof>>,
    #[cfg(test)]
    node_proofs: std::sync::atomic::AtomicUsize,
}

impl Plonky3System {
    /// A verifying node and wallet for `params` at the decided FRI parameters:
    /// instant with a pinned key; otherwise it builds the circuits to derive
    /// the key, which takes as long as [`Self::for_miner`].
    pub fn new(params: &ChainParams) -> Result<Self, SetupError> {
        let fri = FriParams::secure();
        match pinned_root_key(params.container_size) {
            Some(key) => Self::build(params, fri, Some(key), false),
            None => Self::build(params, fri, None, false),
        }
    }

    /// A mining node for `params`: [`Self::new`] plus the aggregation layers,
    /// one sample node proof per internal level, checked against the pinned
    /// key when there is one.
    pub fn for_miner(params: &ChainParams) -> Result<Self, SetupError> {
        Self::build(
            params,
            FriParams::secure(),
            pinned_root_key(params.container_size),
            true,
        )
    }

    /// [`Self::new`] or [`Self::for_miner`] at `FriParams::fast()`: a few
    /// queries and no grinding, so proofs take a fraction of the time and
    /// prove nothing. No key is pinned for it, so the circuits are built
    /// either way. Tests only.
    pub fn insecure_fast(params: &ChainParams, aggregate: bool) -> Result<Self, SetupError> {
        Self::build(params, FriParams::fast(), None, aggregate)
    }

    /// A verifying node at `FriParams::fast()` trusting `key`, as exported by
    /// [`Self::root_key`] of a system built with the same parameters. Tests
    /// only.
    pub fn insecure_fast_with_key(params: &ChainParams, key: &[u8]) -> Result<Self, SetupError> {
        Self::build(params, FriParams::fast(), Some(key), false)
    }

    /// `key` is the root verifying key to trust; without one it is derived
    /// from the circuits, which are then built even without `aggregate`.
    fn build(
        params: &ChainParams,
        fri: FriParams,
        key: Option<&[u8]>,
        aggregate: bool,
    ) -> Result<Self, SetupError> {
        let n = params.container_size;
        if !n.is_power_of_two() || !(2..=MAX_CONTAINER_SIZE).contains(&n) {
            return Err(SetupError::ContainerSize(n));
        }
        if params.anchor_window != 1 << ANCHOR_DEPTH {
            return Err(SetupError::AnchorWindow(params.anchor_window));
        }
        if usize::from(params.commitment_tree_depth) != TREE_DEPTH {
            return Err(SetupError::TreeDepth(params.commitment_tree_depth));
        }
        let leaf = Arc::new(SlotProver::new_acc(fri));
        let layers = if aggregate || key.is_none() {
            Some(build_layers(n, fri, &leaf)?)
        } else {
            None
        };
        let built = match &layers {
            Some(layers) => Some(
                layers
                    .last()
                    .expect("at least one layer")
                    .verifier()
                    .encode_verifier_artifact(limits())
                    .map_err(|e| SetupError::Key(format!("{e:?}")))?,
            ),
            None => None,
        };
        let key = match (key, built) {
            (Some(key), Some(built)) if key != built => return Err(SetupError::KeyMismatch),
            (Some(key), _) => key.to_vec(),
            (None, Some(built)) => built,
            (None, None) => unreachable!("the layers are built without a key"),
        };
        // The hiding RNG serves only the prover; verification draws no
        // randomness, so a fixed seed is fine.
        let config = koala_bear_d4_poseidon2_random_codeword(
            &fri.descriptor(),
            &VerifierLimits::default(),
            StdRng::seed_from_u64(0),
        )
        .map_err(|e| SetupError::Key(format!("{e:?}")))?;
        let verifier = TypedArtifactVerifier::decode_with_config(
            config,
            &key,
            ExpectedVerifierArtifact::from_trusted_bytes(&key),
            limits(),
        )
        .map_err(|e| SetupError::Key(format!("{e:?}")))?;
        Ok(Self {
            container_size: n,
            fri,
            leaf,
            key,
            verifier,
            layers,
            // Default to serial until a matched speed/memory comparison
            // justifies an explicit opt-in to the two-proof envelope.
            parallel: 1,
            cache: Mutex::new(cache::TreeCache::default()),
            #[cfg(test)]
            node_proofs: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn container_size(&self) -> u32 {
        self.container_size
    }

    pub fn fri(&self) -> FriParams {
        self.fri
    }

    /// The root verifying key container proofs are checked against, in the
    /// canonical artifact format.
    pub fn root_key(&self) -> &[u8] {
        &self.key
    }

    /// Whether this system can prove container proofs.
    pub fn aggregates(&self) -> bool {
        self.layers.is_some()
    }

    /// How many node proofs of one level are made at once. Each uses about
    /// one core; memory grows with it. Defaults to serial and caps at two.
    pub fn set_parallelism(&mut self, nodes: usize) {
        self.parallel = nodes.clamp(1, PRIVATE_WORKER_BATCHES);
    }

    /// Proves every pair of one level, `self.parallel` nodes at a time.
    fn prove_level(
        &self,
        layer: &AccAggregation,
        pairs: &[(Input<'_>, Input<'_>)],
        note: Option<&MinerNote>,
    ) -> Result<Vec<BatchStarkProof<Cfg>>, String> {
        let mut out = Vec::with_capacity(pairs.len());
        #[cfg(test)]
        self.node_proofs
            .fetch_add(pairs.len(), std::sync::atomic::Ordering::Relaxed);
        for chunk in pairs.chunks(self.parallel) {
            let proofs: Vec<Result<BatchStarkProof<Cfg>, String>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&(l, r)| s.spawn(move || layer.prove(l, r, note)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err("a prover thread panicked".into()))
                    })
                    .collect()
            });
            for p in proofs {
                out.push(p?);
            }
        }
        Ok(out)
    }
}

/// Artifact limits: a container proof is bounded by the block codec's
/// `MAX_PROOF_LEN`.
fn limits() -> ArtifactLimits {
    ArtifactLimits {
        max_proof_bytes: MAX_PROOF_LEN,
        ..ArtifactLimits::default()
    }
}

/// Hiding FRI needs mask height (trace height / 2) ≥ 2·(4·opening points +
/// queries); recursive layers take the minimum trace height for 2 opening
/// points.
fn layer_params(fri: FriParams) -> ProveNextLayerParams {
    let min_height = (4 * (8 + fri.num_queries as usize)).next_power_of_two();
    ProveNextLayerParams {
        table_packing: TablePacking::new(4, 4).with_min_trace_height(min_height),
        ..ProveNextLayerParams::default()
    }
}

/// One aggregation layer per level of a tree over `n` leaves. Every layer's
/// circuit is built from a sample proof of the layer below, so each internal
/// level proves one sample node.
fn build_layers(
    n: u32,
    fri: FriParams,
    leaf: &Arc<SlotProver>,
) -> Result<Vec<AccAggregation>, SetupError> {
    let depth = n.trailing_zeros();
    let layer_params = layer_params(fri);
    // Any valid leaf fixes the leaf proof's shape: an empty package anchored
    // at height 0 of an 𝒜 holding only it.
    let (mut sample, _) = acc_witnesses(vec![sample_empty_slot(0)], 0, FEE_BASE, 0);
    let sample = sample.remove(0);
    let (sample_proof, sample_stmt) = leaf.prove_acc(&sample);
    let sample_full = {
        let a = anchor_leaf(&sample_stmt, &sample.anchor_path);
        compose_acc(&a, &a)
    };
    let mut node: Option<(NodeProof, CircuitVerifier<Cfg>)> = None;
    let mut layers = Vec::with_capacity(depth as usize);
    for level in 1..=depth {
        let is_root = level == depth;
        let (child, input) = match &node {
            None => (
                Child::Uni(leaf.clone()),
                Input::Uni(&sample_proof, &sample_stmt, &sample.anchor_path),
            ),
            Some(((proof, full), verifier)) => {
                (Child::Batch(verifier.clone()), Input::Batch(proof, full))
            }
        };
        let layer = AccAggregation::new(child, input, &fri.config(), &layer_params, is_root)
            .map_err(SetupError::Circuit)?;
        let next = if is_root {
            None
        } else {
            let proof = layer
                .prove(input, input, None)
                .map_err(SetupError::Circuit)?;
            let full = match &node {
                None => sample_full.clone(),
                Some(((_, full), _)) => compose_acc(full, full),
            };
            Some(((proof, full), layer.verifier()))
        };
        layers.push(layer);
        node = next;
    }
    Ok(layers)
}

fn prover_error(e: impl std::fmt::Display) -> AggregateError {
    AggregateError::Prover(e.to_string())
}

impl ProofSystem for Plonky3System {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        let slot = slot_for(w);
        check_slot(ctx, &slot, w).map_err(ProveError::Relation)?;
        let witness = convert::acc_witness(ctx, &slot, w, &blind)?;
        let (proof, statement) = self.leaf.prove_acc(&witness);
        debug_assert!(leaf::statement_matches(&statement, &slot) && leaf::fee(&statement) == w.fee);
        let body = leaf::encode(&proof, &statement).map_err(ProveError::Prover)?;
        let fee = FeeOpening { fee: w.fee, blind };
        let proof = SlotProof {
            slot_id: slot.id(),
            fee_commit: fee.commit(),
            anchor: w.anchor,
            binding: leaf::binding(&body),
            body,
        };
        Ok((slot, proof, fee))
    }

    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        self.check_leaf(anchors, slot, proof, fee).is_ok()
    }

    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        let layers = self.layers.as_ref().ok_or_else(|| {
            prover_error("this node was not prepared to aggregate (Plonky3System::for_miner)")
        })?;
        let schedule = FixedAggregationSchedule::for_container(self.container_size)
            .expect("container size was validated during setup");
        if !schedule.validate_leaf_count(leaves.len()) {
            return Err(prover_error(
                "fixed aggregation schedule requires dummy-filled leaves",
            ));
        }
        if leaves.len() != self.container_size as usize {
            return Err(prover_error(format!(
                "{} leaves for a container of {}",
                leaves.len(),
                self.container_size
            )));
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| prover_error("aggregation cache poisoned"))?;
        // Revalidate every leaf before consulting a completed subtree. Identity
        // includes the actual proof bytes and all opaque/opening fields.
        let ids: Vec<_> = leaves
            .iter()
            .map(|l| {
                siworld_crypto::domain_hash(
                    "siworld local aggregate cache leaf v1",
                    &[
                        l.slot.id().as_bytes(),
                        l.proof.slot_id.as_bytes(),
                        l.proof.anchor.as_bytes(),
                        l.proof.fee_commit.as_bytes(),
                        l.proof.binding.as_bytes(),
                        leaf::binding(&l.proof.body).as_bytes(),
                        &l.fee.fee.to_le_bytes(),
                        l.fee.blind.as_bytes(),
                    ],
                )
            })
            .collect();
        let plan = cache
            .plan(&ids, anchors.accumulator_root())
            .ok_or_else(|| prover_error("duplicate leaves or unsupported tree shape"))?;
        let mut decoded = Vec::with_capacity(leaves.len());
        let mut total: u64 = 0;
        for &index in &plan.order {
            let leaf = &leaves[index];
            let (proof, statement, h) = self
                .check_leaf(anchors, leaf.slot, leaf.proof, leaf.fee)
                .map_err(|e| e.at(index))?;
            let path = anchor_path(anchors, h).map_err(prover_error)?;
            total = total
                .checked_add(leaf.fee.fee)
                .ok_or(AggregateError::FeeOverflow)?;
            decoded.push((proof, statement, path));
        }
        let value = total
            .checked_add(miner_share)
            .ok_or(AggregateError::FeeOverflow)?;
        if miner_note.value != value {
            return Err(AggregateError::MinerNoteValue);
        }
        if Some(miner_note.cond.unlock_height) != height.checked_add(COINBASE_MATURITY) {
            return Err(AggregateError::MinerNoteUnlock);
        }
        if miner_note.rho != miner_rho(height) {
            return Err(AggregateError::MinerNoteRho);
        }
        let note = MinerNote {
            height,
            share: miner_share,
            owner: field_digest(&miner_note.owner).ok_or(AggregateError::StatementOutOfRange)?,
            rseed: field_digest(&miner_note.rseed).ok_or(AggregateError::StatementOutOfRange)?,
        };

        // Level 1 merges leaves; every later level merges node proofs, whose
        // full statements the parent takes as private inputs.
        let anchored: Vec<Vec<F>> = decoded
            .iter()
            .map(|(_, s, path)| anchor_leaf(s, path))
            .collect();
        let mut inputs: Vec<Input<'_>> = decoded
            .iter()
            .map(|(p, s, path)| Input::Uni(p, s, path))
            .collect();
        let mut fulls: Vec<&[F]> = anchored.iter().map(Vec::as_slice).collect();
        let mut nodes: Vec<Arc<NodeProof>>;
        let mut retained = Vec::with_capacity(plan.keys.len());
        for (k, layer) in layers.iter().enumerate() {
            let is_root = k + 1 == layers.len();
            let pairs: Vec<(Input<'_>, Input<'_>)> =
                inputs.chunks(2).map(|c| (c[0], c[1])).collect();
            if is_root {
                let proofs = self
                    .prove_level(layer, &pairs, Some(&note))
                    .map_err(prover_error)?;
                let root = proofs.into_iter().next().expect("one root");
                let bytes = layer
                    .verifier()
                    .encode_proof_artifact(&root, limits())
                    .map_err(|e| prover_error(format!("{e:?}")))?;
                cache.commit(plan, retained);
                return Ok(ContainerProof(bytes));
            }
            let mut next: Vec<_> = plan.keys[k]
                .iter()
                .enumerate()
                .map(|(i, key)| cache.get(k, i, *key))
                .collect();
            let missing: Vec<_> = next
                .iter()
                .enumerate()
                .filter_map(|(i, n)| n.is_none().then_some(i))
                .collect();
            let work: Vec<_> = missing.iter().map(|&i| pairs[i]).collect();
            let proofs = self.prove_level(layer, &work, None).map_err(prover_error)?;
            for (i, proof) in missing.into_iter().zip(proofs) {
                next[i] = Some(Arc::new((
                    proof,
                    compose_acc(fulls[2 * i], fulls[2 * i + 1]),
                )));
            }
            nodes = next
                .into_iter()
                .map(|n| n.expect("cached or proved"))
                .collect();
            retained.push(nodes.clone());
            // The borrows of `decoded` and `anchored` end here; the next
            // level reads `nodes`.
            inputs = Vec::new();
            fulls = Vec::new();
            for node in &nodes {
                let (p, full) = node.as_ref();
                inputs.push(Input::Batch(p, full));
                fulls.push(full);
            }
        }
        unreachable!("the last layer is the root")
    }

    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        if public.count != self.container_size {
            return false;
        }
        let Some(values) = public.public_values() else {
            return false;
        };
        let statement: Vec<u8> = values
            .iter()
            .flat_map(|v| v.as_canonical_u32().to_le_bytes())
            .collect();
        self.verifier
            .import_proof(
                &proof.0,
                CanonicalStatement::new(&statement, NUM_ROOT_PUBLIC),
            )
            .is_ok()
    }
}

/// What is wrong with a leaf, before any aggregation.
enum LeafError {
    Expired,
    Proof,
    Fee,
}

impl LeafError {
    fn at(self, index: usize) -> AggregateError {
        match self {
            Self::Expired => AggregateError::AnchorExpired { index },
            Self::Proof => AggregateError::BadSlotProof { index },
            Self::Fee => AggregateError::FeeOpeningMismatch { index },
        }
    }
}

impl Plonky3System {
    /// Every check of a leaf: the opaque fields, the fee opening, the
    /// statement's binding to the slot and to the anchor's 𝒜 entry, and the
    /// STARK itself. Returns the proof, its statement and the anchor height.
    fn check_leaf(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> Result<(p3_uni_stark::Proof<Cfg>, Vec<F>, Height), LeafError> {
        let h = anchors.height_of(&proof.anchor).ok_or(LeafError::Expired)?;
        if fee.commit() != proof.fee_commit {
            return Err(LeafError::Fee);
        }
        if proof.slot_id != slot.id() || proof.binding != leaf::binding(&proof.body) {
            return Err(LeafError::Proof);
        }
        let (stark, statement) = leaf::decode(&proof.body).ok_or(LeafError::Proof)?;
        if !leaf::statement_matches(&statement, slot) {
            return Err(LeafError::Proof);
        }
        if leaf::fee(&statement) != fee.fee {
            return Err(LeafError::Fee);
        }
        if !leaf::entry_matches(&statement, &proof.anchor, h, base_fee(h)) {
            return Err(LeafError::Proof);
        }
        self.leaf
            .verify(&stark, &statement)
            .map_err(|_| LeafError::Proof)?;
        Ok((stark, statement, h))
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::*;
    use siworld_circuits::dummy::dummy_slot;
    use siworld_core::{params::ChainParams, Condition};
    use siworld_crypto::{note_commitment, SecretSeed, SetSum, SpendKey};
    use siworld_state::ChainState;
    use std::sync::atomic::Ordering;

    #[test]
    fn real_n32_tree_reuses_thirty_nodes_and_rebuilds_only_five_for_one_replacement() {
        let params = ChainParams {
            container_size: 32,
            ..ChainParams::devnet()
        };
        let mut system = Plonky3System::insecure_fast(&params, true).unwrap();
        assert_eq!(system.parallel, 1);
        system.set_parallelism(usize::MAX);
        assert_eq!(system.parallel, 2);
        system.set_parallelism(0);
        assert_eq!(system.parallel, 1);
        system.set_parallelism(2);
        let state = ChainState::genesis(&params);
        let entropy = SecretSeed::from_os_rng().unwrap();
        let anchor = state.anchors.latest().unwrap().0;
        let ctx = RelationContext {
            anchors: &state.anchors,
            tree_depth: params.commitment_tree_depth,
        };
        let mut entries: Vec<_> = (0..32)
            .map(|i| dummy_slot(&system, &ctx, anchor, &entropy.derive("cache n32", 0), i))
            .collect();
        let key = SpendKey::from_digest(Digest([87; 32]));
        let note = Note {
            owner: key.owner(),
            value: 1_000_000,
            cond: Condition { unlock_height: 101 },
            rho: miner_rho(1),
            rseed: entropy.derive("miner", 0),
        };
        let prove = |entries: &[(Slot, SlotProof, FeeOpening)], anchors: &RecentRoots| {
            let leaves: Vec<_> = entries
                .iter()
                .map(|(slot, proof, fee)| Leaf { slot, proof, fee })
                .collect();
            let proof = system
                .prove_container(anchors, 1, &leaves, &note, note.value)
                .unwrap();
            let public = ContainerPublic {
                set_sum: SetSum::of(entries.iter().map(|t| &t.0)),
                anchors_root: anchors.accumulator_root(),
                height: 1,
                miner_note_cm: note_commitment(&note),
                miner_share: note.value,
                count: 32,
            };
            assert!(system.verify_container(&public, &proof));
        };
        prove(&entries, &state.anchors);
        assert_eq!(system.node_proofs.load(Ordering::Relaxed), 31);
        entries.reverse();
        prove(&entries, &state.anchors);
        assert_eq!(
            system.node_proofs.load(Ordering::Relaxed),
            32,
            "unchanged tree needs only a fresh root"
        );
        entries[9] = dummy_slot(&system, &ctx, anchor, &entropy.derive("replacement", 0), 0);
        prove(&entries, &state.anchors);
        assert_eq!(
            system.node_proofs.load(Ordering::Relaxed),
            37,
            "one leaf dirties five binary ancestors"
        );
        let mut anchors = state.anchors.clone();
        anchors.push(key.owner(), 1);
        prove(&entries, &anchors);
        assert_eq!(
            system.node_proofs.load(Ordering::Relaxed),
            68,
            "new accumulator root invalidates all 31 nodes"
        );
    }
}
