//! SP1 baseline: single-slot proving / verification / size, and binary aggregation of N leaves
//! (default 32), verifying child proofs inside the zkVM.
//!
//! Usage (from crates/bench-stark/sp1):
//!   SP1_PROVER=cpu cargo run --release -p siworld-bench-sp1 -- [--leaves 32] [--reps 3]
//!
//! Proofs are compressed (STARK, constant size, recursively verifiable). SP1 STARK proofs are
//! not zero-knowledge.

use std::time::{Duration, Instant};

use siworld_bench_common::{Hasher, sample_slot};
use sp1_sdk::prelude::*;
use sp1_sdk::{ProverClient, SP1Proof, SP1VerifyingKey};

const SLOT_ELF: Elf = include_elf!("siworld-slot-program");
const AGG_ELF: Elf = include_elf!("siworld-aggregate-program");

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn size(p: &SP1ProofWithPublicValues) -> usize {
    bincode::serialize(&p.proof).expect("serialize").len()
}

fn slot_stdin(seed: u64, dummy: bool) -> (SP1Stdin, Vec<u8>) {
    let w = sample_slot(seed, dummy);
    let pi = w.check(&Hasher::new()).expect("sample is valid");
    let expect: Vec<u8> = pi.to_u32s().iter().flat_map(|x| x.to_le_bytes()).collect();
    let mut s = SP1Stdin::new();
    s.write(&w.to_words());
    (s, expect)
}

fn agg_stdin(
    vk: &SP1VerifyingKey,
    agg_vk: &SP1VerifyingKey,
    leaves: bool,
    l: &SP1ProofWithPublicValues,
    r: &SP1ProofWithPublicValues,
) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write(&vk.hash_u32());
    s.write(&leaves);
    s.write(&agg_vk.hash_u32());
    s.write(&l.public_values.to_vec());
    s.write(&r.public_values.to_vec());
    for p in [l, r] {
        let SP1Proof::Compressed(c) = &p.proof else {
            panic!("child proofs must be compressed")
        };
        s.write_proof((**c).clone(), vk.vk.clone());
    }
    s
}

#[tokio::main]
async fn main() {
    let mut leaves_n = 32usize;
    let mut reps = 3usize;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--leaves" => leaves_n = it.next().and_then(|v| v.parse().ok()).expect("--leaves N"),
            "--reps" => reps = it.next().and_then(|v| v.parse().ok()).expect("--reps N"),
            o => panic!("unknown argument {o}"),
        }
    }
    assert!(leaves_n.is_power_of_two() && leaves_n >= 2);
    println!(
        "# SP1 sdk 6.9.0, circuits {} (CPU prover, compressed STARK)",
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
    println!(
        "threads: {}",
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );

    let client = ProverClient::builder().cpu().build().await;
    let t = Instant::now();
    let pk = client.setup(SLOT_ELF).await.expect("slot setup");
    let agg_pk = client.setup(AGG_ELF).await.expect("aggregation setup");
    println!("setup (both programs): {:.0} ms", ms(t.elapsed()));

    // ---- Single slot ----
    let (stdin, expect) = slot_stdin(100, false);
    let (pv, report) = client
        .execute(SLOT_ELF, stdin.clone())
        .await
        .expect("execute");
    assert_eq!(
        pv.to_vec(),
        expect,
        "guest public values differ from the native check"
    );
    println!(
        "single-slot guest: {} RISC-V instructions, {} syscalls",
        report.total_instruction_count(),
        report.total_syscall_count()
    );

    // An invalid witness must fail to execute: changing an output value breaks conservation.
    let mut bad = sample_slot(100, false);
    bad.outputs[0].value += 1;
    let mut bs = SP1Stdin::new();
    bs.write(&bad.to_words());
    let rejected = match client.execute(SLOT_ELF, bs).await {
        Err(_) => true,
        Ok((_, r)) => r.exit_code != 0,
    };
    assert!(
        rejected,
        "a value-conservation violation should fail to execute"
    );

    let mut core_t = Vec::new();
    let mut comp_t = Vec::new();
    let mut ver_t = Vec::new();
    let mut core_size = 0;
    let mut leaves = Vec::with_capacity(leaves_n);
    for i in 0..leaves_n.max(reps) {
        let (stdin, expect) = slot_stdin(100 + i as u64, i % 4 == 3);
        if i < reps {
            let t = Instant::now();
            let p = client
                .prove(&pk, stdin.clone())
                .core()
                .await
                .expect("core proof");
            core_t.push(t.elapsed());
            core_size = size(&p);
        }
        let t = Instant::now();
        let p = client
            .prove(&pk, stdin)
            .compressed()
            .await
            .expect("compressed proof");
        comp_t.push(t.elapsed());
        assert_eq!(p.public_values.to_vec(), expect);
        if i < reps {
            let t = Instant::now();
            client
                .verify(&p, pk.verifying_key(), None)
                .expect("leaf verification");
            ver_t.push(t.elapsed());
        }
        if leaves.len() < leaves_n {
            leaves.push(p);
        }
        eprintln!("leaf {i} done");
    }
    let leaf_size = size(&leaves[0]);
    let leaf_total: Duration = comp_t[..leaves_n].iter().sum();
    println!(
        "single slot: core proof {:.0} ms ({} B), compressed proof {:.0} ms (median of {}), verify {:.1} ms, compressed size {} B ({:.1} KiB), public values {} B",
        ms(median(core_t)),
        core_size,
        ms(median(comp_t.clone())),
        comp_t.len(),
        ms(median(ver_t)),
        leaf_size,
        leaf_size as f64 / 1024.0,
        leaves[0].public_values.to_vec().len()
    );

    // ---- Binary aggregation ----
    println!(
        "| Level | Nodes | Per-node proof (ms) | Level total (ms) | Proof size (KiB) | Public values (B) |"
    );
    println!("|---|---|---|---|---|---|");
    let mut level = leaves;
    let mut child_vk = pk.verifying_key().clone();
    let mut depth = 0;
    let mut total = Duration::ZERO;
    let mut critical = median(comp_t);
    while level.len() > 1 {
        depth += 1;
        let mut out = Vec::new();
        let mut times = Vec::new();
        for pair in level.chunks(2) {
            let stdin = agg_stdin(
                &child_vk,
                agg_pk.verifying_key(),
                depth == 1,
                &pair[0],
                &pair[1],
            );
            let t = Instant::now();
            let p = client
                .prove(&agg_pk, stdin)
                .compressed()
                .await
                .expect("aggregation proof");
            times.push(t.elapsed());
            out.push(p);
            eprintln!("level {depth} node {} done", out.len());
        }
        client
            .verify(&out[0], agg_pk.verifying_key(), None)
            .expect("aggregation verification");
        let sum: Duration = times.iter().sum();
        println!(
            "| {depth} | {} | {:.0} | {:.0} | {:.1} | {} |",
            out.len(),
            ms(median(times.clone())),
            ms(sum),
            size(&out[0]) as f64 / 1024.0,
            out[0].public_values.to_vec().len()
        );
        total += sum;
        critical += median(times);
        level = out;
        child_vk = agg_pk.verifying_key().clone();
    }

    let root = &level[0];
    let mut vt = Vec::new();
    for _ in 0..reps.max(1) {
        let t = Instant::now();
        client
            .verify(root, agg_pk.verifying_key(), None)
            .expect("root verification");
        vt.push(t.elapsed());
    }
    let pv = root.public_values.to_vec();
    let leaf_vk: Vec<u8> = pk
        .verifying_key()
        .hash_u32()
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    assert_eq!(
        pv[..32],
        leaf_vk[..],
        "the root proof's leaf vk should be the slot program"
    );
    let agg_vk: Vec<u8> = agg_pk
        .verifying_key()
        .hash_u32()
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    assert_eq!(
        pv[32..64],
        agg_vk[..],
        "the root proof's child vk should be the aggregation program"
    );
    assert_eq!(
        pv.len(),
        64 + leaves_n * 192,
        "the root payload should contain every leaf's public values"
    );
    let root_size = size(root);
    println!();
    println!(
        "{leaves_n} leaves → 1 container proof: depth {depth}; leaf proofs total {:.0} ms; aggregation proofs total {:.0} ms (nodes proven sequentially)",
        ms(leaf_total),
        ms(total)
    );
    println!(
        "critical path (with intra-level parallelism = leaf + one proof per level) ≈ {:.0} ms",
        ms(critical)
    );
    println!(
        "root proof {} B ({:.1} KiB), public values {} B; root verification {:.1} ms",
        root_size,
        root_size as f64 / 1024.0,
        pv.len(),
        ms(median(vt))
    );
}
