//! Disposable single-node engineering CLI. No peer service or retained network adapter.
use siworld_native_node::{
    local, producer,
    proofs::{NativeProver, NativeVerifier},
    state::Config,
    store::Store,
};
use std::path::Path;
fn help() {
    println!(
        "siworld-native-node: isolated native V1 engineering network\n\ninit DIRECTORY [WORK_BITS]  Create a new network; default work bits 0\nstatus DIRECTORY           Replay and show accepted public state\ncheck DIRECTORY            Replay proofs and check local reward recovery\nmine DIRECTORY [SLOTS]     Produce and atomically accept one native block (64..576, groups of 16)\n\nNo reset, migration, peer networking, issuance admission, or public-network activation is provided."
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
    let verifier = NativeVerifier::new()?;
    match args[0].as_str() {
        "init" => {
            let bits = args
                .get(2)
                .map_or(Ok(0), |x| x.parse::<u8>().map_err(|_| "invalid work bits"))?;
            let config = local::initialize(path, bits)?;
            let store = Store::open(path.join("chain.redb"), config, &verifier)?;
            println!(
                "initialized isolated engineering network: height={}, tip={}",
                store.state().height,
                local::hex(&store.state().tip)
            );
        }
        "status" | "check" => {
            if args.len() != 2 {
                return Err("unexpected argument".into());
            }
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
