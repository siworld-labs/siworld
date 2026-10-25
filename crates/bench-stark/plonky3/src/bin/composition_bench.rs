//! Isolated N=16 composition benchmark. No node, wallet, or network access.
#[path = "composition_bench/leaf.rs"]
mod leaf;

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
    let mut leaf_profile = String::from("uniform");
    let mut leaf_pin_path = None;
    let mut export_leaf_pin = None;
    let mut security_output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--topology" => topology = args.next().ok_or("missing topology")?,
            "--jobs" => jobs = args.next().ok_or("missing jobs")?.parse().map_err(|_| "jobs")?,
            "--queries" => {
                fri.num_queries = args.next().ok_or("missing queries")?.parse().map_err(|_| "queries")?;
            }
            "--smoke" => fri = FriParams::fast(),
            "--leaf-profile" => leaf_profile = args.next().ok_or("missing leaf profile")?,
            "--leaf-pin" => leaf_pin_path = Some(args.next().ok_or("missing leaf pin")?),
            "--export-leaf-pin" => export_leaf_pin = Some(args.next().ok_or("missing pin output")?),
            "--security-output" => security_output = Some(args.next().ok_or("missing report output")?),
            _ => return Err("usage: composition-bench --topology binary|fanin8 --jobs 1|2 [--queries 42|92] [--smoke] [--leaf-profile uniform|b|a|c] [--leaf-pin FILE | --export-leaf-pin FILE] [--security-output FILE]".into()),
        }
    }
    if ![1, 2].contains(&jobs)
        || !["binary", "fanin8"].contains(&topology.as_str())
        || ![2, 42, 92].contains(&fri.num_queries)
    {
        return Err("unsupported configuration".into());
    }
    let leaf_fri = leaf::parameters(&leaf_profile, fri)?;
    if security_output.is_some()
        && (!cfg!(feature = "security-report") || topology != "fanin8" || jobs != 1)
    {
        return Err("security output requires security-report, fanin8 and one proof job".into());
    }
    if let Some(path) = &security_output
        && (export_leaf_pin.is_some() || std::path::Path::new(path).exists())
    {
        return Err("security output needs a new path and cannot export a leaf pin".into());
    }
    if leaf_profile != "uniform" && (topology != "fanin8" || jobs != 1) {
        return Err("leaf candidates require fanin8 and one proof at a time".into());
    }
    if export_leaf_pin.is_some() && leaf_pin_path.is_some() {
        return Err("export and verification of a leaf pin are separate operations".into());
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
        Arc::new(SlotProver::new_acc(leaf_fri))
    });
    let leaf_pin = leaf::pin(&leaf_profile, leaf_fri, &prover)?;
    if let Some(path) = export_leaf_pin {
        leaf::export_pin(&path, &leaf_pin)?;
        return Ok(());
    }
    if leaf_profile != "uniform" || leaf_pin_path.is_some() {
        let path =
            leaf_pin_path.ok_or("leaf candidates require a previously exported --leaf-pin")?;
        let expected: Value = serde_json::from_slice(
            &std::fs::read(path).map_err(|e| format!("read leaf pin: {e}"))?,
        )
        .map_err(|e| format!("decode leaf pin: {e}"))?;
        leaf::check_pin(&expected, &leaf_pin)?;
    }
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
    let mut batch_node_wall_ns = Vec::new();
    let (proof, statement, verifier) = if topology == "fanin8" {
        let batch = measured("batch_setup", &mut stages, || {
            EightLeafAggregation::new(prover.clone(), inputs[0], &cfg, &layer)
        })?;
        let statements = [fold(&full[..8]), fold(&full[8..])];
        let proofs = measured("batch_proofs", &mut stages, || {
            pairs(jobs, 2, |i| {
                let start = Instant::now();
                let result = batch.prove(&inputs[i * 8..(i + 1) * 8]);
                (result, start.elapsed().as_nanos())
            })
            .into_iter()
            .map(|(result, elapsed)| {
                batch_node_wall_ns.push(elapsed);
                result
            })
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
        #[cfg(feature = "security-report")]
        if let Some(path) = &security_output {
            use siworld_bench_plonky3::security;
            let report = json!({
                "schema": 1, "status": "internal D4 control; not external review or acceptance",
                "p3_security_version": "0.9.0-rc.2",
                "recursion_revision": "3a69ba61f713c8400b14eb3d8f0e52caa13512c7",
                "suite": "KoalaBear D4 / Poseidon2 W16 / digest8",
                "profile": leaf_profile, "parent_queries": fri.num_queries,
                "topology": [16, 2, 1], "proof_multiplicities": [16, 2, 1],
                "root_evidence": "prepared actual circuit shape; root proof not generated in this analysis run",
                "leaf": security::leaf(&prover, leaf_fri),
                "eight_input": security::recursive(&batch.verifier(), fri)?,
                "root": security::recursive(&root.verifier(), fri)?,
                "acceptance": false,
                "limitations": [
                    "conservative common-domain batch envelope; not an exact multi-instance theorem",
                    "classical p3-security reports do not prove quantum Fiat-Shamir or recursive composition",
                    "D4/W16 fails the selected hash collision targets independently of these terms"
                ],
            });
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| file.write_all(&serde_json::to_vec_pretty(&report)?))
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({"event": "security_report_written", "acceptance": false})
            );
            return Ok(());
        }
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
            "leaf_profile": leaf_profile, "leaf_parameters": leaf_pin["parameters"],
            "leaf_pin": leaf_pin, "batch_node_wall_ns": batch_node_wall_ns,
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
