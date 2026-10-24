//! Plonky3 benchmark: single-slot proving / verification / size, and binary recursive
//! aggregation of N leaves (default 32).
//!
//! Usage:
//!   cargo run --release -p siworld-bench-plonky3 -- [--fast] [--chain | --acc] [--leaves 32] [--reps 5]
//!     [--log-blowup B] [--queries Q] [--pow G] [--dump-root root.json] [--export DIR]
//!
//! `--fast` uses small, insecure parameters (2 queries) and is only for debugging the pipeline.
//! `--log-blowup`, `--queries` and `--pow` override single FRI parameters, for measuring how size
//! and time scale. `--dump-root` (with `--acc`) writes the root proof as JSON for
//! `scripts/proof_breakdown.py`. `--export DIR` (with `--acc`) writes the root verifying key, the
//! root proof and its statement in the library's canonical artifact format, for
//! `crates/stark-verifier` in the main workspace.
//! By default the aggregation statement is the concatenation of the child statements
//! (48 field elements per leaf, growing linearly with the number of leaves). `--chain` uses
//! chained leaves with state-transition aggregation instead; the statement is always
//! [s_0, s_N, N], 17 field elements in total. `--acc` uses set-hash leaves with the custom
//! aggregation in `agg` (docs/protocol.md): nodes carry [ΣE, fee, count, 𝒜 root], and the root
//! publishes [ΣE, 𝒜 root, height, cm_miner, miner share, N], 70 field elements in total.

use std::sync::Arc;
use std::time::{Duration, Instant};

use p3_field::PrimeCharacteristicRing;

use p3_circuit::StateTransitionLayout;
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, TablePacking};
use p3_recursion::artifact::{ArtifactLimits, PortableArtifactExport};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, Poseidon2Config, ProveNextLayerParams,
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedSource,
};
use siworld_bench_common::{
    AccWitness, DIGEST, F, FEE_BASE, Hasher, Rng, SlotWitness, acc_witnesses, sample_empty_slot,
    sample_priority_slot, sample_slot,
};
use siworld_bench_plonky3::agg::{self, AccAggregation, Child, Input};
use siworld_bench_plonky3::air::{STMT_COUNT, STMT_IN, STMT_OUT};
use siworld_bench_plonky3::{Cfg, FriParams, SlotProver, proof_size};

macro_rules! backend {
    () => {
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>()
    };
}

/// Hiding FRI requires mask height (trace height / 2) ≥ 2·(4·opening points + queries);
/// recursive layers take the minimum trace height for 2 opening points.
fn layer_params(p: FriParams) -> ProveNextLayerParams {
    let min_height = (4 * (8 + p.num_queries as usize)).next_power_of_two();
    ProveNextLayerParams {
        table_packing: TablePacking::new(4, 4).with_min_trace_height(min_height),
        ..ProveNextLayerParams::default()
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

struct Args {
    params: FriParams,
    leaves: usize,
    reps: usize,
    chain: bool,
    acc: bool,
    dump_root: Option<String>,
    export: Option<String>,
}

fn args() -> Args {
    let mut a = Args {
        params: FriParams::secure(),
        leaves: 32,
        reps: 5,
        chain: false,
        acc: false,
        dump_root: None,
        export: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(s) = it.next() {
        match s.as_str() {
            "--fast" => a.params = FriParams::fast(),
            "--chain" => a.chain = true,
            "--acc" => a.acc = true,
            "--leaves" => a.leaves = it.next().and_then(|v| v.parse().ok()).expect("--leaves N"),
            "--reps" => a.reps = it.next().and_then(|v| v.parse().ok()).expect("--reps N"),
            "--log-blowup" => {
                a.params.log_blowup = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--log-blowup B")
            }
            "--queries" => {
                a.params.num_queries = it.next().and_then(|v| v.parse().ok()).expect("--queries Q")
            }
            "--pow" => {
                a.params.query_pow_bits = it.next().and_then(|v| v.parse().ok()).expect("--pow G")
            }
            "--dump-root" => a.dump_root = Some(it.next().expect("--dump-root PATH")),
            "--export" => a.export = Some(it.next().expect("--export DIR")),
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(
        a.leaves.is_power_of_two() && a.leaves >= 2,
        "the number of leaves must be a power of two ≥ 2"
    );
    assert!(!(a.chain && a.acc), "--chain and --acc are exclusive");
    assert!(
        a.acc || (a.dump_root.is_none() && a.export.is_none()),
        "--dump-root and --export need --acc"
    );
    a
}

type Node = (BatchStarkProof<Cfg>, Vec<F>);

/// Parent statement: concatenation, or chained [left.s_in, right.s_out, left.count + right.count].
fn compose(l: &[F], r: &[F], chain: bool) -> Vec<F> {
    if chain {
        assert_eq!(
            l[STMT_OUT..STMT_COUNT],
            r[STMT_IN..STMT_OUT],
            "chain is not contiguous"
        );
        let mut v = l[STMT_IN..STMT_OUT].to_vec();
        v.extend_from_slice(&r[STMT_OUT..STMT_COUNT]);
        v.push(l[STMT_COUNT] + r[STMT_COUNT]);
        v
    } else {
        let mut v = l.to_vec();
        v.extend_from_slice(r);
        v
    }
}

macro_rules! aggregation {
    ($ty:ty, $chain:expr, $l:expr, $r:expr, $cfg:expr, $params:expr) => {
        if $chain {
            <$ty>::new_state_transition($l, $r, $cfg, backend!(), $params, layout())
        } else {
            <$ty>::new($l, $r, $cfg, backend!(), $params)
        }
    };
}

/// State is 8 base-field elements; count is 8 bits (≤ 255 leaves).
fn layout() -> StateTransitionLayout {
    StateTransitionLayout::base(DIGEST, 8).expect("layout")
}

fn main() {
    let a = args();
    let p = a.params;
    println!(
        "# Plonky3 (KoalaBear D4, Poseidon2 W16, hiding FRI) log_blowup={} queries={} query_pow={} ≈{} bits conjectured security; aggregation statement: {}",
        p.log_blowup,
        p.num_queries,
        p.query_pow_bits,
        p.conjectured_bits(),
        if a.acc {
            "set-hash accumulator (E 48 with d_ct, 𝒜 entry checked at level 1, fee limbs, root cm_miner and share)"
        } else if a.chain {
            "chained fixed-width"
        } else {
            "concatenated"
        }
    );
    println!(
        "threads: {}",
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );

    if a.acc {
        return run_acc(&a);
    }

    // ---- Single slot ----
    let t = Instant::now();
    let prover = if a.chain {
        SlotProver::new_chain(p)
    } else {
        SlotProver::new(p)
    };
    let s0 = [F::ZERO; DIGEST];
    let mut s = s0;
    println!("preprocessed commitment: {:.1} ms", ms(t.elapsed()));

    let mut leaves = Vec::with_capacity(a.leaves);
    let mut prove_times = Vec::new();
    for i in 0..a.leaves.max(a.reps) {
        let w = sample_slot(100 + i as u64, i % 4 == 3);
        let t = Instant::now();
        let leaf = if a.chain {
            prover.prove_chain(&w, &s)
        } else {
            prover.prove(&w)
        };
        prove_times.push(t.elapsed());
        if a.chain {
            s.copy_from_slice(&leaf.1[STMT_OUT..STMT_COUNT]);
        }
        if leaves.len() < a.leaves {
            leaves.push(leaf);
        }
    }
    let mut verify_times = Vec::new();
    for (proof, pis) in leaves.iter().take(a.reps.max(1)) {
        let t = Instant::now();
        prover.verify(proof, pis).expect("leaf verification");
        verify_times.push(t.elapsed());
    }
    let leaf_total: Duration = prove_times[..a.leaves].iter().sum();
    let leaf_size = proof_size(&leaves[0].0);
    println!(
        "single slot: prove {:.1} ms (median of {}), verify {:.2} ms, proof size {} B ({:.1} KiB), public inputs {} field elements",
        ms(median(prove_times.clone())),
        prove_times.len(),
        ms(median(verify_times)),
        leaf_size,
        leaf_size as f64 / 1024.0,
        leaves[0].1.len()
    );

    // ---- Aggregation level 1: two uni-STARK leaves → one batch proof ----
    let limits = ArtifactLimits::default();
    let mut total_setup = Duration::ZERO;
    let mut total_prove = Duration::ZERO;
    let mut critical = median(prove_times);
    println!(
        "| Level | Nodes | Setup (ms) | Per-node proof (ms) | Level total (ms) | Proof size (KiB) | Statement length |"
    );
    println!("|---|---|---|---|---|---|---|");

    let (mut level, mut verifier): (Vec<Node>, CircuitVerifier<Cfg>) = {
        let t = Instant::now();
        let owner = aggregation!(
            TrustedPreparedAggregation::<
                Cfg,
                Cfg,
                siworld_bench_plonky3::SlotAir,
                siworld_bench_plonky3::SlotAir,
                _,
                4,
            >,
            a.chain,
            uni_src(&prover, p, &leaves[0]),
            uni_src(&prover, p, &leaves[1]),
            p.config(),
            layer_params(p)
        )
        .expect("level 1 setup");
        let setup = t.elapsed();
        let mut out = Vec::new();
        let mut times = Vec::new();
        for pair in leaves.chunks(2) {
            let t = Instant::now();
            let r = owner
                .prove(
                    TrustedPreparedInput::UniStark {
                        proof: &pair[0].0,
                        public_inputs: &pair[0].1,
                    },
                    TrustedPreparedInput::UniStark {
                        proof: &pair[1].0,
                        public_inputs: &pair[1].1,
                    },
                )
                .expect("level 1 proof");
            times.push(t.elapsed());
            out.push((r.0, compose(&pair[0].1, &pair[1].1, a.chain)));
        }
        let v = owner.verifier();
        report(1, &v, &out, setup, &times, limits);
        total_setup += setup;
        total_prove += times.iter().sum::<Duration>();
        critical += median(times);
        (out, v)
    };

    // ---- Level 2 onward: two batch proofs → one batch proof ----
    let mut depth = 1;
    while level.len() > 1 {
        depth += 1;
        let t = Instant::now();
        let owner = aggregation!(
            TrustedPreparedAggregation::<Cfg, Cfg, BatchOnly, BatchOnly, _, 4>,
            a.chain,
            batch_src(&verifier, &level[0]),
            batch_src(&verifier, &level[1]),
            p.config(),
            layer_params(p)
        )
        .unwrap_or_else(|e| panic!("level {depth} setup: {e:?}"));
        let setup = t.elapsed();
        let mut out = Vec::new();
        let mut times = Vec::new();
        for pair in level.chunks(2) {
            let t = Instant::now();
            let r = owner
                .prove(
                    TrustedPreparedInput::BatchStark {
                        proof: &pair[0].0,
                        statement: &pair[0].1,
                    },
                    TrustedPreparedInput::BatchStark {
                        proof: &pair[1].0,
                        statement: &pair[1].1,
                    },
                )
                .unwrap_or_else(|e| panic!("level {depth} proof: {e:?}"));
            times.push(t.elapsed());
            out.push((r.0, compose(&pair[0].1, &pair[1].1, a.chain)));
        }
        let v = owner.verifier();
        report(depth, &v, &out, setup, &times, limits);
        total_setup += setup;
        total_prove += times.iter().sum::<Duration>();
        critical += median(times);
        level = out;
        verifier = v;
    }

    // ---- Root proof ----
    let (root, statement) = &level[0];
    if a.chain {
        // The verifier recomputes the chain end from the slot data published in the block and only
        // needs to compare 17 elements.
        let mut want = s0.to_vec();
        want.extend_from_slice(&s);
        want.push(F::from_u32(a.leaves as u32));
        assert_eq!(statement, &want, "root statement should be [s_0, s_N, N]");
    }
    let mut vt = Vec::new();
    for _ in 0..a.reps.max(1) {
        let t = Instant::now();
        verifier
            .verify(root, statement)
            .expect("root proof verification");
        vt.push(t.elapsed());
    }
    let mut bad = statement.clone();
    bad[0] += F::from_u32(1);
    assert!(
        verifier.verify(root, &bad).is_err(),
        "a tampered statement should fail verification"
    );
    let root_size = verifier
        .encode_proof_artifact(root, limits)
        .expect("root proof encoding")
        .len();
    let stmt_bytes = statement.len() * 4;
    println!();
    println!(
        "{} leaves → 1 container proof: depth {depth}; leaf proofs total {:.0} ms; aggregation setup total {:.0} ms; aggregation proofs total {:.0} ms (nodes proven sequentially, each proof internally multithreaded)",
        a.leaves,
        ms(leaf_total),
        ms(total_setup),
        ms(total_prove),
    );
    println!(
        "critical path (with intra-level parallelism = leaf + one proof per level) ≈ {:.0} ms",
        ms(critical)
    );
    println!(
        "root proof {} B ({:.1} KiB), plus a statement of {} field elements ({} B); root verification {:.2} ms",
        root_size,
        root_size as f64 / 1024.0,
        statement.len(),
        stmt_bytes,
        ms(median(vt))
    );
}

fn uni_src<'a>(
    prover: &'a SlotProver,
    p: FriParams,
    n: &'a (p3_uni_stark::Proof<Cfg>, Vec<F>),
) -> TrustedPreparedSource<'a, 'a, Cfg, siworld_bench_plonky3::SlotAir> {
    TrustedPreparedSource::UniStark {
        config: p.config(),
        air: &prover.air,
        preprocessed_commit: Some(prover.vk.commitment.clone()),
        proof: &n.0,
        public_inputs: &n.1,
    }
}

fn batch_src<'a>(
    v: &CircuitVerifier<Cfg>,
    n: &'a Node,
) -> TrustedPreparedSource<'static, 'a, Cfg, BatchOnly> {
    TrustedPreparedSource::BatchStark {
        verifier: v.clone(),
        proof: &n.0,
        statement: &n.1,
    }
}

fn report(
    depth: usize,
    v: &CircuitVerifier<Cfg>,
    out: &[Node],
    setup: Duration,
    times: &[Duration],
    limits: ArtifactLimits,
) {
    v.verify(&out[0].0, &out[0].1)
        .unwrap_or_else(|e| panic!("level {depth} verification: {e:?}"));
    let size = v
        .encode_proof_artifact(&out[0].0, limits)
        .expect("proof encoding")
        .len();
    let sum: Duration = times.iter().sum();
    println!(
        "| {depth} | {} | {:.0} | {:.0} | {:.0} | {:.1} | {} |",
        out.len(),
        ms(setup),
        ms(median(times.to_vec())),
        ms(sum),
        size as f64 / 1024.0,
        out[0].1.len()
    );
}

/// Writes `root-verifier-n{N}.bin` (the verifying key: relation, preprocessed commitments and FRI
/// parameters), `root-proof-n{N}.bin` and `root-statement-n{N}.bin` (the 70 public values as
/// canonical u32 little-endian words).
fn export(
    dir: &str,
    leaves: usize,
    verifier: &CircuitVerifier<Cfg>,
    root: &BatchStarkProof<Cfg>,
    statement: &[F],
    limits: ArtifactLimits,
) {
    use p3_field::PrimeField32;
    let dir = std::path::Path::new(dir);
    std::fs::create_dir_all(dir).expect("create export directory");
    let key = verifier
        .encode_verifier_artifact(limits)
        .expect("verifier encoding");
    let proof = verifier
        .encode_proof_artifact(root, limits)
        .expect("root proof encoding");
    let words: Vec<u8> = statement
        .iter()
        .flat_map(|e| e.as_canonical_u32().to_le_bytes())
        .collect();
    for (name, bytes) in [("verifier", &key), ("proof", &proof), ("statement", &words)] {
        std::fs::write(dir.join(format!("root-{name}-n{leaves}.bin")), bytes)
            .expect("write export");
    }
    println!(
        "exported to {}: verifying key {} B, root proof {} B",
        dir.display(),
        key.len(),
        proof.len()
    );
}

/// Leaf kinds cycle through standard, priority, empty (miner-filled), and one dummy input.
fn acc_leaf(i: usize) -> SlotWitness {
    let seed = 100 + i as u64;
    match i % 4 {
        0 => sample_slot(seed, false),
        1 => sample_priority_slot(seed),
        2 => sample_empty_slot(seed),
        _ => sample_slot(seed, true),
    }
}

/// One block's leaves: slot i anchors at height ANCHOR_BASE + i, all in one 𝒜.
const ANCHOR_BASE: u64 = 5000;

fn acc_block(n: usize) -> (Vec<AccWitness>, siworld_bench_common::Digest) {
    acc_witnesses((0..n).map(acc_leaf).collect(), ANCHOR_BASE, FEE_BASE, 7)
}

fn run_acc(a: &Args) {
    let p = a.params;
    let prover = Arc::new(SlotProver::new_acc(p));
    let (witnesses, anchors) = acc_block(a.leaves.max(a.reps));
    let mut leaves = Vec::with_capacity(a.leaves);
    let mut prove_times = Vec::new();
    for w in &witnesses {
        let t = Instant::now();
        let leaf = prover.prove_acc(w);
        prove_times.push(t.elapsed());
        if leaves.len() < a.leaves {
            leaves.push(leaf);
        }
    }
    let mut verify_times = Vec::new();
    for (proof, pis) in leaves.iter().take(a.reps.max(1)) {
        let t = Instant::now();
        prover.verify(proof, pis).expect("leaf verification");
        verify_times.push(t.elapsed());
    }
    let leaf_total: Duration = prove_times[..a.leaves].iter().sum();
    let leaf_size = proof_size(&leaves[0].0);
    println!(
        "single slot: prove {:.1} ms (median of {}), verify {:.2} ms, proof size {} B ({:.1} KiB), public inputs {} field elements",
        ms(median(prove_times.clone())),
        prove_times.len(),
        ms(median(verify_times)),
        leaf_size,
        leaf_size as f64 / 1024.0,
        leaves[0].1.len()
    );

    let limits = ArtifactLimits::default();
    let lp = layer_params(p);
    let note = agg::MinerNote {
        height: ANCHOR_BASE + 4096,
        share: siworld_bench_common::MINER_SHARE,
        owner: Rng::new(31).digest(),
        rseed: Rng::new(41).digest(),
    };
    let mut total_setup = Duration::ZERO;
    let mut total_prove = Duration::ZERO;
    let mut critical = median(prove_times);
    println!(
        "| Level | Nodes | Setup (ms) | Per-node proof (ms) | Level total (ms) | Proof size (KiB) | Statement length |"
    );
    println!("|---|---|---|---|---|---|---|");

    let root_level = a.leaves.trailing_zeros() as usize;
    // Leaf statements as level 1 sees them: each 𝒜 entry replaced by the 𝒜 root of its path.
    let anchored: Vec<Vec<F>> = leaves
        .iter()
        .zip(&witnesses)
        .map(|((_, s), w)| agg::anchor_leaf(s, &w.anchor_path))
        .collect();
    // Internal nodes publish a digest; the full statements go to the parent as private inputs.
    let mut level: Vec<Node> = Vec::new();
    let mut fulls: Vec<Vec<F>> = Vec::new();
    let mut verifier: Option<CircuitVerifier<Cfg>> = None;
    for depth in 1..=root_level {
        let is_root = depth == root_level;
        let t = Instant::now();
        let (child, sample) = match &verifier {
            None => (
                Child::Uni(prover.clone()),
                Input::Uni(&leaves[0].0, &leaves[0].1, &witnesses[0].anchor_path),
            ),
            Some(v) => (
                Child::Batch(v.clone()),
                Input::Batch(&level[0].0, &fulls[0]),
            ),
        };
        let owner = AccAggregation::new(child, sample, &p.config(), &lp, is_root)
            .unwrap_or_else(|e| panic!("level {depth} setup: {e}"));
        let setup = t.elapsed();
        let mut out = Vec::new();
        let mut out_fulls = Vec::new();
        let mut times = Vec::new();
        let n = if depth == 1 {
            leaves.len()
        } else {
            level.len()
        };
        for j in (0..n).step_by(2) {
            let (l, r, ls, rs) = if depth == 1 {
                (
                    Input::Uni(&leaves[j].0, &leaves[j].1, &witnesses[j].anchor_path),
                    Input::Uni(
                        &leaves[j + 1].0,
                        &leaves[j + 1].1,
                        &witnesses[j + 1].anchor_path,
                    ),
                    &anchored[j],
                    &anchored[j + 1],
                )
            } else {
                (
                    Input::Batch(&level[j].0, &fulls[j]),
                    Input::Batch(&level[j + 1].0, &fulls[j + 1]),
                    &fulls[j],
                    &fulls[j + 1],
                )
            };
            let t = Instant::now();
            let proof = owner
                .prove(l, r, is_root.then_some(&note))
                .unwrap_or_else(|e| panic!("level {depth} proof: {e}"));
            times.push(t.elapsed());
            if is_root {
                out.push((proof, agg::root_statement(ls, rs, &note)));
            } else {
                let full = agg::compose_acc(ls, rs);
                out.push((proof, agg::node_digest(&full)));
                out_fulls.push(full);
            }
        }
        let v = owner.verifier();
        report(depth, &v, &out, setup, &times, limits);
        total_setup += setup;
        total_prove += times.iter().sum::<Duration>();
        critical += median(times);
        level = out;
        fulls = out_fulls;
        verifier = Some(v);
    }

    // ---- Root proof ----
    let verifier = verifier.expect("at least one level");
    let (root, statement) = &level[0];
    // The verifier recomputes ΣE from the slot data published in the block (nf, cm, d_ct); the
    // fee total is visible only to the holder of the miner package.
    let h = Hasher::new();
    let mut set = vec![F::ZERO; siworld_bench_common::SET_LEN];
    let mut fee = 0u64;
    for w in &witnesses[..a.leaves] {
        let leaf = w.check(&h, &anchors).expect("valid leaf");
        for (s, e) in set.iter_mut().zip(leaf.set) {
            *s += e;
        }
        fee += leaf.fee;
    }
    let mut want = set;
    want.extend_from_slice(&anchors);
    want.push(F::from_u64(note.height));
    want.extend_from_slice(&h.miner_note_cm(
        fee + note.share,
        note.height,
        &note.owner,
        &note.rseed,
    ));
    want.extend_from_slice(&siworld_bench_common::limbs(note.share));
    want.push(F::from_u32(a.leaves as u32));
    assert_eq!(
        statement, &want,
        "root statement should be [ΣE, 𝒜 root, height, cm_miner, share, N]"
    );
    let mut vt = Vec::new();
    for _ in 0..a.reps.max(1) {
        let t = Instant::now();
        verifier
            .verify(root, statement)
            .expect("root proof verification");
        vt.push(t.elapsed());
    }
    for i in [
        agg::ROOT_SET,
        agg::ROOT_ANCHORS,
        agg::ROOT_HEIGHT,
        agg::ROOT_CM_MINER,
        agg::ROOT_SHARE,
        agg::ROOT_COUNT,
    ] {
        let mut bad = statement.clone();
        bad[i] += F::from_u32(1);
        assert!(
            verifier.verify(root, &bad).is_err(),
            "a tampered statement should fail verification"
        );
    }
    let mut bad = statement.clone();
    bad[agg::ROOT_CM_MINER..agg::ROOT_SHARE].copy_from_slice(&h.miner_note_cm(
        fee + note.share + 1,
        note.height,
        &note.owner,
        &note.rseed,
    ));
    assert!(
        verifier.verify(root, &bad).is_err(),
        "a commitment to another fee total should fail verification"
    );
    let root_size = verifier
        .encode_proof_artifact(root, limits)
        .expect("root proof encoding")
        .len();
    if let Some(path) = &a.dump_root {
        std::fs::write(path, serde_json::to_vec(root).expect("root proof JSON"))
            .expect("write root proof");
    }
    if let Some(dir) = &a.export {
        export(dir, a.leaves, &verifier, root, statement, limits);
    }
    println!();
    println!(
        "{} leaves → 1 container proof: depth {root_level}; fee total {fee} atoms (committed only); leaf proofs total {:.0} ms; aggregation setup total {:.0} ms; aggregation proofs total {:.0} ms (nodes proven sequentially, each proof internally multithreaded)",
        a.leaves,
        ms(leaf_total),
        ms(total_setup),
        ms(total_prove),
    );
    println!(
        "critical path (with intra-level parallelism = leaf + one proof per level) ≈ {:.0} ms",
        ms(critical)
    );
    println!(
        "root proof {} B ({:.1} KiB), plus a statement of {} field elements ({} B); root verification {:.2} ms",
        root_size,
        root_size as f64 / 1024.0,
        statement.len(),
        statement.len() * 4,
        ms(median(vt))
    );
}
