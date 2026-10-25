//! Isolated cold-tree aggregation timing at pinned classical parameters.
//! Output contains aggregate timings only; no witnesses or transaction data.
use std::time::Instant;

use serde_json::json;
use siworld_circuits::{dummy::dummy_slot, ContainerPublic, Leaf, ProofSystem, RelationContext};
use siworld_core::{
    params::{ChainParams, COINBASE_MATURITY},
    Condition, Digest, Note,
};
use siworld_crypto::{miner_rho, note_commitment, SecretSeed, SetSum, SpendKey};
use siworld_prover::Plonky3System;
use siworld_state::ChainState;

fn measure() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--slots" || args[2] != "--parallel" {
        return Err("usage: siworld-aggregation-bench --slots N --parallel 1|2".into());
    }
    let n: u32 = args[1].parse().map_err(|_| "invalid capacity")?;
    let parallel: usize = args[3].parse().map_err(|_| "invalid parallelism")?;
    if ![1, 2].contains(&parallel) {
        return Err("parallelism must be 1 or 2".into());
    }
    let params = ChainParams {
        container_size: n,
        ..ChainParams::devnet()
    };
    let setup = Instant::now();
    let mut system = Plonky3System::for_miner(&params).map_err(|e| e.to_string())?;
    system.set_parallelism(parallel);
    let setup_ms = setup.elapsed().as_millis();
    let state = ChainState::genesis(&params);
    let entropy = SecretSeed::from_os_rng().map_err(|e| e.to_string())?;
    let anchor = state.anchors.latest().ok_or("missing anchor")?.0;
    let ctx = RelationContext {
        anchors: &state.anchors,
        tree_depth: params.commitment_tree_depth,
    };
    let leaf_start = Instant::now();
    let entries: Vec<_> = (0..u64::from(n))
        .map(|i| {
            dummy_slot(
                &system,
                &ctx,
                anchor,
                &entropy.derive("aggregation measurement", 0),
                i,
            )
        })
        .collect();
    let leaf_ms = leaf_start.elapsed().as_millis();
    let key = SpendKey::from_digest(Digest([87; 32]));
    let note = Note {
        owner: key.owner(),
        value: 1_000_000,
        cond: Condition {
            unlock_height: 1 + COINBASE_MATURITY,
        },
        rho: miner_rho(1),
        rseed: entropy.derive("measurement miner", 0),
    };
    let leaves: Vec<_> = entries
        .iter()
        .map(|(slot, proof, fee)| Leaf { slot, proof, fee })
        .collect();
    let start = Instant::now();
    let proof = system
        .prove_container(&state.anchors, 1, &leaves, &note, note.value)
        .map_err(|e| format!("aggregation failed: {e:?}"))?;
    let aggregation_ms = start.elapsed().as_millis();
    let public = ContainerPublic {
        set_sum: SetSum::of(entries.iter().map(|t| &t.0)),
        anchors_root: state.anchors.accumulator_root(),
        height: 1,
        miner_note_cm: note_commitment(&note),
        miner_share: note.value,
        count: n,
    };
    let verify = Instant::now();
    if !system.verify_container(&public, &proof) {
        return Err("root verification failed".into());
    }
    println!(
        "{}",
        json!({"schema": 2, "synthetic_only": true, "verified": true,
        "container_size": n, "parallel": parallel, "cache": "cold",
        "setup_ms": setup_ms, "leaf_ms": leaf_ms, "aggregation_ms": aggregation_ms,
        "verification_ms": verify.elapsed().as_millis(), "proof_bytes": proof.0.len(),
        "parameters": {"suite": "classical-D4-W16", "log_blowup": 2, "queries": 42, "grinding": 16}})
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    match measure() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
