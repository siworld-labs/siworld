//! Synthetic two-service measurements at the pinned classical proof parameters.
//! No telemetry is added to the production service. Never attach real wallets.
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use siworld_circuits::{
    AggregateError, ContainerPublic, FeeOpening, Leaf, ProofSystem, ProveError, RelationContext,
    SlotProof, SlotWitness,
};
use siworld_core::params::ATOMS_PER_SIP;
use siworld_core::{ContainerProof, Digest, Height, Note, Slot};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::genesis::{hex_bytes, AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::node::Node;
use siworld_node::rpc_auth::{RpcAuth, RpcToken};
use siworld_node::service::{call_authenticated, run, Config, RpcConfig};
use siworld_prover::Plonky3System;
use siworld_state::RecentRoots;
use zeroize::Zeroizing;

#[derive(Default)]
struct Measurements(Mutex<Vec<(&'static str, Duration)>>);

impl Measurements {
    fn record<T>(&self, name: &'static str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = f();
        self.0.lock().unwrap().push((name, start.elapsed()));
        result
    }

    fn report(&self) -> Value {
        let samples = self.0.lock().unwrap();
        let mut report = serde_json::Map::new();
        for stage in [
            "slot_prove",
            "slot_verify",
            "container_prove",
            "container_verify",
        ] {
            let values = samples
                .iter()
                .filter(|(name, _)| *name == stage)
                .map(|(_, elapsed)| *elapsed)
                .collect();
            report.insert(stage.into(), distribution(values));
        }
        Value::Object(report)
    }
}

struct ObservedSystem {
    inner: Plonky3System,
    measurements: Arc<Measurements>,
}

impl ProofSystem for ObservedSystem {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        witness: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        self.measurements
            .record("slot_prove", || self.inner.prove_slot(ctx, witness, blind))
    }

    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        self.measurements.record("slot_verify", || {
            self.inner.verify_slot(anchors, slot, proof, fee)
        })
    }

    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        note: &Note,
        share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        self.measurements.record("container_prove", || {
            self.inner
                .prove_container(anchors, height, leaves, note, share)
        })
    }

    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        self.measurements.record("container_verify", || {
            self.inner.verify_container(public, proof)
        })
    }
}

// Floating point is confined to diagnostic wall-clock presentation, outside
// proof construction and every consensus/state-transition path.
#[allow(clippy::float_arithmetic)]
fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn distribution(mut values: Vec<Duration>) -> Value {
    if values.is_empty() {
        return json!({"samples": 0});
    }
    values.sort();
    let quantile = |percent: usize| {
        let index = (percent * values.len()).div_ceil(100).saturating_sub(1);
        milliseconds(values[index])
    };
    json!({
        "samples": values.len(),
        "total_ms": milliseconds(values.iter().sum()),
        "p50_ms": quantile(50), "p95_ms": quantile(95),
        "max_ms": milliseconds(*values.last().unwrap()),
    })
}

fn socket() -> Result<SocketAddr, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map_err(|e| e.to_string())
}

fn credentials() -> Result<(RpcToken, RpcToken), String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| "OS randomness unavailable")?;
    let text = Zeroizing::new(hex_bytes(bytes.as_ref()));
    Ok((
        RpcToken::from_hex(&text).unwrap(),
        RpcToken::from_hex(&text).unwrap(),
    ))
}

struct Running {
    rpc: SocketAddr,
    token: RpcToken,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl Running {
    fn call(&self, method: &str) -> Result<Value, String> {
        call_authenticated(
            &self.rpc.to_string(),
            &json!({"method": method}),
            &self.token,
        )
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take() {
            Some(thread) => thread.join().map_err(|_| "service thread panicked")?,
            None => Ok(()),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn start(
    node: Node,
    p2p: SocketAddr,
    peers: Vec<SocketAddr>,
    mine: bool,
) -> Result<Running, String> {
    let rpc = socket()?;
    let (server, token) = credentials()?;
    let address = |socket: SocketAddr| {
        format!("/ip4/127.0.0.1/tcp/{}", socket.port())
            .parse()
            .unwrap()
    };
    let config = Config {
        listen: vec![address(p2p)],
        peers: peers.into_iter().map(address).collect(),
        rpc: Some(RpcConfig {
            address: rpc,
            auth: RpcAuth::new(server, None, None)?,
        }),
        mine,
        worker: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(run(node, config, async {
                let _ = stopped.await;
            }))
            .map_err(|e| e.to_string())
    });
    Ok(Running {
        rpc,
        token,
        stop: Some(stop),
        thread: Some(thread),
    })
}

fn node(genesis: &Genesis, key: SpendKey, system: Arc<dyn ProofSystem>) -> Result<Node, String> {
    Node::open(
        genesis.clone(),
        key,
        SecretSeed::from_os_rng().map_err(|e| e.to_string())?,
        None,
        system,
    )
    .map_err(|e| e.to_string())
}

fn number(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match args.as_chunks::<2>().0.iter().find(|pair| pair[0] == name) {
        Some(pair) => pair[1]
            .parse::<u64>()
            .ok()
            .filter(|n| *n != 0)
            .ok_or_else(|| format!("{name} requires a positive integer")),
        None => Ok(default),
    }
}

fn measure() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.len().is_multiple_of(2)
        || args.as_chunks::<2>().0.iter().any(|pair| {
            !["--slots", "--blocks", "--parallel", "--timeout-secs"].contains(&pair[0].as_str())
        })
    {
        return Err("usage: siworld-proof-pipeline [--slots 32] [--blocks 3] [--parallel 1|2] [--timeout-secs 1800]".into());
    }
    let slots = u32::try_from(number(&args, "--slots", 32)?).map_err(|_| "slots overflow")?;
    let blocks = number(&args, "--blocks", 3)?;
    let parallel =
        usize::try_from(number(&args, "--parallel", 1)?).map_err(|_| "parallelism overflow")?;
    if ![1, 2].contains(&parallel) {
        return Err("parallelism must be 1 or 2".into());
    }
    let timeout = Duration::from_secs(number(&args, "--timeout-secs", 1800)?);
    let seed = SecretSeed::from_os_rng().map_err(|e| e.to_string())?;
    let miner_key = SpendKey::from_digest(seed.derive("synthetic miner", 0));
    let receiver_key = SpendKey::from_digest(seed.derive("synthetic receiver", 0));
    let genesis = Genesis::from_file(&GenesisFile {
        network: "synthetic-proof-pipeline".into(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        block_time: 60,
        pow_iterations: 10_000,
        // Deliberately trivial PoW isolates proof latency; this is not calibrated mining.
        target: "ff".repeat(32),
        container_size: slots,
        proofs: ProofsFile::Plonky3,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: siworld_node::hex(&miner_key.owner()),
            amount: "100".into(),
        }],
    })
    .map_err(|e| e.to_string())?;
    let setup = Instant::now();
    eprintln!("preparing pinned classical proof parameters for N={slots}");
    let mut inner = Plonky3System::for_miner(&genesis.params).map_err(|e| e.to_string())?;
    inner.set_parallelism(parallel);
    let setup_ms = milliseconds(setup.elapsed());
    let miner_metrics = Arc::new(Measurements::default());
    let peer_metrics = Arc::new(Measurements::default());
    let mining_system = Arc::new(ObservedSystem {
        inner,
        measurements: miner_metrics.clone(),
    });
    let verifying_system = Arc::new(ObservedSystem {
        inner: Plonky3System::new(&genesis.params).map_err(|e| e.to_string())?,
        measurements: peer_metrics.clone(),
    });
    let receiver = node(&genesis, receiver_key, verifying_system)?;
    let mut miner = node(&genesis, miner_key, mining_system)?;
    let snapshot = Instant::now();
    let snapshot_state = miner.chain.state.clone();
    let snapshot_ms = milliseconds(snapshot.elapsed());
    drop(snapshot_state);
    let wallet = Instant::now();
    miner
        .pay(&receiver.address(), ATOMS_PER_SIP, false)
        .map_err(|e| e.to_string())?;
    let wallet_ms = milliseconds(wallet.elapsed());
    let peer_p2p = socket()?;
    let miner_p2p = socket()?;
    let mut peer = start(receiver, peer_p2p, vec![], false)?;
    let mut producer = start(miner, miner_p2p, vec![peer_p2p], true)?;
    let wall = Instant::now();
    let mut rpc = Vec::new();
    let mut rpc_errors = 0usize;
    let mut startup_rpc_errors = 0usize;
    let mut rpc_ready = false;
    let mut reached = Vec::new();
    let mut last_height = 0u64;
    let converged = loop {
        if wall.elapsed() >= timeout {
            break Err("measurement deadline exceeded".to_string());
        }
        let begin = Instant::now();
        let info = producer.call("info");
        match info {
            Ok(info) => {
                rpc_ready = true;
                rpc.push(begin.elapsed());
                let height = info["height"].as_u64().ok_or("missing miner height")?;
                if height > last_height {
                    reached.push(wall.elapsed());
                    last_height = height;
                    eprintln!("synthetic chain reached height {height}");
                }
                if height >= blocks {
                    if let Ok(other) = peer.call("info") {
                        if other["height"] == info["height"] && other["tip"] == info["tip"] {
                            let balance = peer.call("balance")?;
                            if balance["total"] == "1" {
                                break Ok(());
                            }
                        }
                    }
                }
            }
            Err(_) if rpc_ready => rpc_errors += 1,
            Err(_) => startup_rpc_errors += 1,
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let convergence_ms = milliseconds(wall.elapsed());
    let shutdown = Instant::now();
    let producer_stopped = producer.shutdown();
    let peer_stopped = peer.shutdown();
    let shutdown_ms = milliseconds(shutdown.elapsed());
    let passed =
        converged.is_ok() && rpc_errors == 0 && producer_stopped.is_ok() && peer_stopped.is_ok();
    let intervals: Vec<_> = reached.windows(2).map(|p| p[1] - p[0]).collect();
    println!(
        "{}",
        json!({
            "schema": 1, "synthetic_only": true, "status": if passed { "passed" } else { "failed" },
            "proof_parameters": {"security": "conjectured classical 100 bits", "log_blowup": 2, "queries": 42, "grinding": 16},
        "container_size": slots, "block_time_secs": 60, "aggregation_parallelism": parallel,
        "available_parallelism": std::thread::available_parallelism().map_or(1, |n| n.get()),
        "rayon_num_threads": std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "library default".into()),
            "pow": "10000 iterations, trivial target; proof-latency lower bound only",
            "storage": "in-memory", "services": 2, "payment_received": converged.is_ok(),
            "miner_setup_ms": setup_ms, "initial_state_clone_ms": snapshot_ms,
            "synthetic_wallet_payment_ms": wallet_ms, "convergence_ms": convergence_ms,
            "accepted_height_observations_ms": reached.iter().copied().map(milliseconds).collect::<Vec<_>>(),
        "observed_inter_block": distribution(intervals), "rpc": distribution(rpc), "rpc_errors": rpc_errors,
        "startup_rpc_errors": startup_rpc_errors,
            "miner": miner_metrics.report(), "peer": peer_metrics.report(), "shutdown_ms": shutdown_ms,
            "limits": "small sample; includes a possible in-flight shutdown proof; no realistic PoW, sustained paid load, disk, WAN, orphan-rate or quantum-security evidence"
        })
    );
    converged?;
    if rpc_errors != 0 {
        return Err(format!("{rpc_errors} post-readiness RPC errors"));
    }
    producer_stopped?;
    peer_stopped
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
