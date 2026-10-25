//! Isolated N=16 composition benchmark. No node, wallet, or network access.
use std::sync::Arc;
use std::time::Instant;

use p3_circuit_prover::{BatchStarkProof, TablePacking};
use p3_maybe_rayon::prelude::join;
use p3_recursion::ProveNextLayerParams;
use serde_json::{Value, json};
use siworld_bench_common::{F, FEE_BASE, MINER_SHARE, Rng, acc_witnesses, sample_slot};
use siworld_bench_plonky3::agg::fanin::EightLeafAggregation;
use siworld_bench_plonky3::agg::{
    AccAggregation, Child, Input, MinerNote, anchor_leaf, compose_acc, node_digest, root_statement,
};
use siworld_bench_plonky3::profile::Span;
use siworld_bench_plonky3::{Cfg, FriParams, SlotProver};

fn measured<T>(name: &'static str, stages: &mut Vec<Value>, f: impl FnOnce() -> T) -> T {
    let phase = Span::new(name);
    let start = Instant::now();
    let result = f();
    stages.push(json!({"phase": name, "wall_ns": start.elapsed().as_nanos()}));
    drop(phase);
    result
}

fn fold(rows: &[Vec<F>]) -> Vec<F> {
    rows[1..]
        .iter()
        .fold(rows[0].clone(), |a, b| compose_acc(&a, b))
}

fn pairs<T: Send>(jobs: usize, count: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let mut out = Vec::with_capacity(count);
    let mut i = 0;
    while i < count {
        if jobs == 2 && i + 1 < count {
            let (a, b) = join(|| f(i), || f(i + 1));
            out.extend([a, b]);
            i += 2;
        } else {
            out.push(f(i));
            i += 1;
        }
    }
    out
}

fn run() -> Result<(), String> {
    let mut topology = String::from("fanin8");
    let mut jobs = 1;
    let mut fri = FriParams::secure();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--topology" => topology = args.next().ok_or("missing topology")?,
            "--jobs" => jobs = args.next().ok_or("missing jobs")?.parse().map_err(|_| "jobs")?,
            "--queries" => {
                fri.num_queries = args.next().ok_or("missing queries")?.parse().map_err(|_| "queries")?;
            }
            "--smoke" => fri = FriParams::fast(),
            _ => return Err("usage: composition-bench --topology binary|fanin8 --jobs 1|2 [--queries 42|92] [--smoke]".into()),
        }
    }
    if ![1, 2].contains(&jobs)
        || !["binary", "fanin8"].contains(&topology.as_str())
        || ![2, 42, 92].contains(&fri.num_queries)
    {
        return Err("unsupported configuration".into());
    }
    println!("{}", json!({"pid": std::process::id(), "event": "ready"}));
    let start = Instant::now();
    let mut stages = Vec::new();
    let layer = ProveNextLayerParams {
        table_packing: TablePacking::new(4, 4)
            .with_min_trace_height((4 * (8 + fri.num_queries as usize)).next_power_of_two()),
        ..ProveNextLayerParams::default()
    };
    let cfg = fri.config();
    let prover = measured("leaf_setup", &mut stages, || {
        Arc::new(SlotProver::new_acc(fri))
    });
    let slots = (0..16).map(|i| sample_slot(100 + i, false)).collect();
    let (witnesses, _) = acc_witnesses(slots, 1000, FEE_BASE, 21);
    let leaves = measured("leaves", &mut stages, || {
        // Serial leaf production isolates recursive proof scheduling.
        witnesses
            .iter()
            .map(|w| prover.prove_acc(w))
            .collect::<Vec<_>>()
    });
    let inputs: Vec<_> = (0..16)
        .map(|i| Input::Uni(&leaves[i].0, &leaves[i].1, &witnesses[i].anchor_path))
        .collect();
    let full: Vec<_> = (0..16)
        .map(|i| anchor_leaf(&leaves[i].1, &witnesses[i].anchor_path))
        .collect();
    let note = MinerNote {
        height: 1234,
        share: MINER_SHARE,
        owner: Rng::new(9).digest(),
        rseed: Rng::new(10).digest(),
    };
    let (proof, statement, verifier) = if topology == "fanin8" {
        let batch = measured("batch_setup", &mut stages, || {
            EightLeafAggregation::new(prover.clone(), inputs[0], &cfg, &layer)
        })?;
        let statements = [fold(&full[..8]), fold(&full[8..])];
        let proofs = measured("batch_proofs", &mut stages, || {
            pairs(jobs, 2, |i| batch.prove(&inputs[i * 8..(i + 1) * 8]))
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
        })?;
        let v = batch.verifier();
        measured("batch_verify", &mut stages, || -> Result<(), String> {
            for (p, s) in proofs.iter().zip(&statements) {
                v.verify(p, &node_digest(s)).map_err(|e| format!("{e:?}"))?;
            }
            Ok(())
        })?;
        // Keep the prepared batch resident: a warm miner needs both layers.
        let root = measured("root_setup", &mut stages, || {
            AccAggregation::new(
                Child::Batch(v),
                Input::Batch(&proofs[0], &statements[0]),
                &cfg,
                &layer,
                true,
            )
        })?;
        let proof = measured("root_proof", &mut stages, || {
            root.prove(
                Input::Batch(&proofs[0], &statements[0]),
                Input::Batch(&proofs[1], &statements[1]),
                Some(&note),
            )
        })?;
        let statement = root_statement(&statements[0], &statements[1], &note);
        (proof, statement, root.verifier())
    } else {
        let mut child = Child::Uni(prover.clone());
        let mut proofs: Vec<BatchStarkProof<Cfg>> = Vec::new();
        let mut statements = full;
        let mut layers = Vec::new();
        loop {
            let count = statements.len() / 2;
            let root = count == 1;
            let inp = |i: usize| {
                if proofs.is_empty() {
                    inputs[i]
                } else {
                    Input::Batch(&proofs[i], statements[i].as_slice())
                }
            };
            let prepared = measured("binary_setup", &mut stages, || {
                AccAggregation::new(child, inp(0), &cfg, &layer, root)
            })?;
            let next = measured(
                if root { "root_proof" } else { "binary_proofs" },
                &mut stages,
                || {
                    pairs(jobs, count, |i| {
                        prepared.prove(inp(i * 2), inp(i * 2 + 1), root.then_some(&note))
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                },
            )?;
            if root {
                break (
                    next.into_iter().next().ok_or("missing root")?,
                    root_statement(&statements[0], &statements[1], &note),
                    prepared.verifier(),
                );
            }
            let next_statements = statements
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| compose_acc(&p[0], &p[1]))
                .collect();
            child = Child::Batch(prepared.verifier());
            proofs = next;
            statements = next_statements;
            layers.push(prepared);
        }
    };
    measured("root_verify", &mut stages, || {
        verifier.verify(&proof, &statement)
    })
    .map_err(|e| format!("{e:?}"))?;
    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| e.to_string())?
        .len();
    let proof_ns: u64 = stages
        .iter()
        .filter(|s| {
            matches!(
                s["phase"].as_str(),
                Some(
                    "leaves"
                        | "batch_proofs"
                        | "binary_proofs"
                        | "root_proof"
                        | "root_verify"
                        | "batch_verify"
                )
            )
        })
        .map(|s| s["wall_ns"].as_u64().unwrap())
        .sum();
    println!(
        "{}",
        json!({
            "schema": 1, "verified": true, "synthetic_only": true, "slots": 16,
            "topology": topology, "jobs": jobs,
            "parameters": {"suite": "D4-W16", "log_blowup": fri.log_blowup, "queries": fri.num_queries, "grinding": fri.query_pow_bits},
            "rayon_threads": std::env::var("RAYON_NUM_THREADS").unwrap_or_default(),
            "cold_wall_ns": start.elapsed().as_nanos(), "proof_and_verify_ns": proof_ns,
            "root_proof_bytes": proof_bytes, "stages": stages,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
