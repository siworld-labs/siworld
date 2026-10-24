//! Accumulator leaf proof under hash and extension choices the recursion library does not offer
//! yet: wider Merkle digests (Poseidon2 width 24, 12-element digests) and the degree-8 extension.
//! Proves the same leaf AIR under each configuration with plain Plonky3 (no recursion) so the
//! cost of each factor can be separated (docs/benchmarks.md, quantum target).
//!
//! Usage: cargo run --release -p siworld-bench-plonky3 --bin leaf_params -- [--reps 16]

use std::time::{Duration, Instant};

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_koala_bear::{
    Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};
use rand::rngs::StdRng;
use siworld_bench_common::{
    F, FEE_BASE, acc_witnesses, sample_empty_slot, sample_priority_slot, sample_slot,
};
use siworld_bench_plonky3::{SlotAir, trace};

type P = <F as Field>::Packing;

fn median(mut v: Vec<Duration>) -> f64 {
    v.sort();
    v[v.len() / 2].as_secs_f64() * 1e3
}

macro_rules! measure {
    ($label:expr, $w:literal, $rate:literal, $digest:literal, $d:literal, $perm:expr,
     $blowup:expr, $queries:expr, $reps:expr) => {{
        type Perm = Poseidon2KoalaBear<$w>;
        type Mmcs = MerkleTreeMmcs<
            P,
            P,
            PaddingFreeSponge<Perm, $w, $rate, $digest>,
            TruncatedPermutation<Perm, 2, $digest, $w>,
            2,
            $digest,
        >;
        type EF = BinomialExtensionField<F, $d>;
        type Pcs = HidingFriPcs<F, Radix2DitParallel<F>, Mmcs, ExtensionMmcs<F, EF, Mmcs>, StdRng>;
        type Cfg = StarkConfig<Pcs, EF, DuplexChallenger<F, Perm, $w, $rate>>;
        let perm: Perm = $perm;
        let mmcs = || Mmcs::new(PaddingFreeSponge::new(perm.clone()), TruncatedPermutation::new(perm.clone()), 1);
        let params = FriParameters {
            log_blowup: $blowup,
            log_final_poly_len: 0,
            max_log_arity: 2,
            num_queries: $queries,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            mmcs: ExtensionMmcs::new(mmcs()),
        };
        let pcs = Pcs::new(Radix2DitParallel::default(), mmcs(), params, $d, rand::make_rng::<StdRng>());
        let cfg = Cfg::new(pcs, DuplexChallenger::new(perm.clone()));
        // Hiding FRI needs 2·(D·opening points + queries) mask rows; pad the leaf when 128 rows are too few.
        let air = SlotAir::new_acc().with_min_height((2 * ($d * 2 + $queries) as usize).next_power_of_two());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("preprocessed commitment")
            .expect("AIR has preprocessed columns");
        let (ws, _) = acc_witnesses((0..$reps).map(leaf).collect(), 5000, FEE_BASE, 7);
        let mut pt = Vec::new();
        let mut vt = Vec::new();
        let mut size = 0;
        for w in &ws {
            let (tr, pis) = trace::generate_acc(&air, w);
            let t = Instant::now();
            let proof = prove_with_preprocessed(&cfg, &air, tr, &pis, Some(&pdata)).expect("proof");
            pt.push(t.elapsed());
            let t = Instant::now();
            verify_with_preprocessed(&cfg, &air, &proof, &pis, Some(&vk)).expect("verify");
            vt.push(t.elapsed());
            size = postcard::to_allocvec(&proof).expect("serialize").len();
        }
        println!(
            "| {} | W{} / {}-element digest | D{} | {} × {} | {:.1} | {:.2} | {:.1} |",
            $label, $w, $digest, $d, $blowup, $queries, median(pt), median(vt), size as f64 / 1024.0
        );
    }};
}

fn leaf(i: usize) -> siworld_bench_common::SlotWitness {
    let seed = 100 + i as u64;
    match i % 4 {
        0 => sample_slot(seed, false),
        1 => sample_priority_slot(seed),
        2 => sample_empty_slot(seed),
        _ => sample_slot(seed, true),
    }
}

fn main() {
    let mut reps = 16usize;
    let mut it = std::env::args().skip(1);
    while let Some(s) = it.next() {
        match s.as_str() {
            "--reps" => reps = it.next().and_then(|v| v.parse().ok()).expect("--reps N"),
            other => panic!("unknown argument {other}"),
        }
    }
    println!("# accumulator leaf, plain Plonky3, 16 bits of query grinding, median of {reps}");
    println!(
        "| Configuration | Hash | Extension | log_blowup × queries | Prove (ms) | Verify (ms) | Proof (KiB) |"
    );
    println!("|---|---|---|---|---|---|---|");
    measure!(
        "current",
        16,
        8,
        8,
        4,
        default_koalabear_poseidon2_16(),
        2,
        42,
        reps
    );
    measure!(
        "queries only",
        16,
        8,
        8,
        4,
        default_koalabear_poseidon2_16(),
        2,
        92,
        reps
    );
    measure!(
        "digest only",
        24,
        12,
        12,
        4,
        default_koalabear_poseidon2_24(),
        2,
        42,
        reps
    );
    measure!(
        "extension only",
        16,
        8,
        8,
        8,
        default_koalabear_poseidon2_16(),
        2,
        42,
        reps
    );
    measure!(
        "quantum, blowup 2",
        24,
        12,
        12,
        8,
        default_koalabear_poseidon2_24(),
        2,
        92,
        reps
    );
    measure!(
        "quantum, blowup 4",
        24,
        12,
        12,
        8,
        default_koalabear_poseidon2_24(),
        4,
        46,
        reps
    );
}
