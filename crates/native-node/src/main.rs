//! Disposable native engineering CLI. No retained-network adapter or reset.
use siworld_native_node::{
    local, producer,
    proofs::{NativeProver, NativeVerifier},
    service,
    state::Config,
    store::Store,
};
use std::path::Path;
fn help() {
    println!(
        "siworld-native-node: isolated native V1 engineering network\n\ninit DIRECTORY [WORK_BITS]  Create a cheap development fixture\ninit-service DIRECTORY     Create a new ASERT network with initialization-only calibration\nrun DIRECTORY              Run continuous native production; requires four proving workers\nstop DIRECTORY             Request run-bound graceful stop and final verification\nservice-status DIRECTORY   Read the private atomic service export\nstatus DIRECTORY           Show exported service status or independently replay an idle store\ncheck DIRECTORY            Replay every proof and check every local reward receipt\nmine DIRECTORY [SLOTS]     Produce and atomically accept one native block (64..576, groups of 16)\n\nRAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2 are required for run.\nA completed 24-hour observation does not automatically stop the service.\nNo reset, migration, peer networking, issuance admission, or public-network activation is provided."
    );
}
fn cpu_admission() -> Result<(), String> {
    #[cfg(target_arch = "x86_64")]
    if !std::is_x86_feature_detected!("avx2") {
        return Err("AVX2 is required; scalar fallback is disabled".into());
    }
    Ok(())
}
fn config(path: &Path) -> Result<Config, String> {
    local::load(path)
}
fn exact(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        Err("unexpected argument".into())
    } else {
        Ok(())
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        help();
        return Ok(());
    }
    cpu_admission()?;
    if args.len() < 2 || args.len() > 3 {
        return Err("expected command and explicit engineering directory; use --help".into());
    }
    let path = Path::new(&args[1]);
    match args[0].as_str() {
        "run" => {
            exact(&args)?;
            service::run(path)?;
        }
        "stop" => {
            exact(&args)?;
            service::request_stop(path)?;
            println!("graceful stop requested for the exported service run");
        }
        "service-status" => {
            exact(&args)?;
            println!("{}", service::exported_status(path)?);
        }
        "init" | "init-service" => {
            let config = if args[0] == "init-service" {
                exact(&args)?;
                let (timestamp, target, iterations) = service::calibrate()?;
                local::initialize_asert(path, timestamp, target, iterations)?
            } else {
                let bits = args
                    .get(2)
                    .map_or(Ok(0), |x| x.parse::<u8>().map_err(|_| "invalid work bits"))?;
                local::initialize(path, bits)?
            };
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open(path.join("chain.redb"), config, &verifier)?;
            println!(
                "initialized isolated engineering network: height={}, tip={}",
                store.state().height,
                local::hex(&store.state().tip)
            );
        }
        "status" | "check" => {
            exact(&args)?;
            if args[0] == "status" && path.join(service::STATUS_FILE).exists() {
                println!("{}", service::exported_status(path)?);
                return Ok(());
            }
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            if args[0] == "check" {
                for height in 1..=store.state().height {
                    let block = store.block(height)?;
                    let id = block.id()?;
                    let secret = local::read_reward(path, &id)?;
                    producer::validate_reward_secret(&block, &secret)?;
                }
            }
            println!(
                "verified engineering state: height={}, tip={}, state={}",
                store.state().height,
                local::hex(&store.state().tip),
                local::hex(&store.state().fingerprint())
            );
        }
        "mine" => {
            let slots = args.get(2).map_or(Ok(64), |x| {
                x.parse::<usize>().map_err(|_| "invalid slot count")
            })?;
            if !(64..=576).contains(&slots) || !slots.is_multiple_of(16) {
                return Err("slot count must be 64..576 in groups of 16".into());
            }
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            let prover = NativeProver::new()?;
            let produced = producer::produce(store.state(), &prover, slots)?;
            let id = produced.block.id()?;
            producer::validate_reward_secret(&produced.block, &produced.reward_secret)?;
            local::save_reward(path, &id, &produced.reward_secret)?;
            store.append(&produced.block, &verifier)?;
            println!(
                "accepted engineering block: height={}, tip={}",
                store.state().height,
                local::hex(&store.state().tip)
            );
        }
        _ => return Err("unknown command; use --help".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("native engineering operation rejected: {error}");
        std::process::exit(1);
    }
}
