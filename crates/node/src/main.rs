//! `siworld-devnet`: single-node development network.
//!
//! ```text
//! siworld-devnet run  [--blocks N] [--interval-ms MS] [--seed HEX64] [--insecure-deterministic]
//! siworld-devnet demo [--blocks N] [--seed HEX64] [--insecure-deterministic]
//! ```
//!
//! `run` produces blocks at a fixed interval while reading commands from
//! standard input (`pay`, `balance`, `help`, `quit`). `demo` does not wait: it
//! sends a few scripted payments along the way and prints balances at the end.

use std::io::BufRead;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use siworld_crypto::{expand, SecretSeed};
use siworld_node::amount::{format_sip, parse_sip};
use siworld_node::devnet::DEFAULT_SEED;
use siworld_node::{hex, parse_hex32, BlockInfo, Config, Devnet, WALLET_NAMES};

const USAGE: &str = "\
Usage:
  siworld-devnet run  [--blocks N] [--interval-ms MS] [--seed HEX64] [--insecure-deterministic]
  siworld-devnet demo [--blocks N] [--seed HEX64] [--insecure-deterministic]

--seed fixes the (public) test wallet and miner keys. Block padding and
payment randomness come from the OS unless --insecure-deterministic derives
them from --seed too, which replays a run exactly but lets anyone who knows
the seed tell padding from payments.

While `run` is running, type on standard input:
  pay <from> <to> <amount in SIP> [priority]   e.g. pay alice dave 12.5
  balance [wallet]                            show test-wallet balances
  help | quit";

struct Opts {
    blocks: Option<u64>,
    interval_ms: u64,
    seed: siworld_core::Digest,
    deterministic: bool,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        blocks: None,
        interval_ms: 1_000,
        seed: DEFAULT_SEED,
        deterministic: false,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "--blocks" => {
                opts.blocks = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--blocks requires an integer")?,
                );
            }
            "--interval-ms" => {
                opts.interval_ms = value()?
                    .parse()
                    .map_err(|_| "--interval-ms requires an integer")?;
            }
            "--seed" => {
                opts.seed = parse_hex32(value()?).ok_or("--seed requires 64 hexadecimal digits")?;
            }
            "--insecure-deterministic" => opts.deterministic = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(opts)
}

fn config(opts: &Opts) -> Config {
    let randomness = if opts.deterministic {
        SecretSeed::insecure_deterministic(expand(&opts.seed, "devnet randomness", 0))
    } else {
        SecretSeed::from_os_rng().expect("OS random number generator")
    };
    Config {
        seed: opts.seed,
        randomness,
        ..Config::default()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn print_block(b: &BlockInfo) {
    println!(
        "height {:>6}  block {}  state_root {}",
        b.height,
        hex(&b.hash),
        hex(&b.state_root)
    );
}

fn print_balances(net: &Devnet, only: Option<&str>) {
    for name in WALLET_NAMES {
        if only.is_some_and(|o| o != name) {
            continue;
        }
        let bal = net.balance(name).unwrap_or(0);
        println!("  {name:<6} {} SIP", format_sip(bal));
    }
}

fn pay(net: &mut Devnet, from: &str, to: &str, amount: &str, priority: bool) {
    let Some(atoms) = parse_sip(amount) else {
        println!("invalid amount: {amount}");
        return;
    };
    match net.pay(from, to, atoms, priority) {
        Ok(()) => println!("submitted: {from} → {to} {} SIP", format_sip(atoms)),
        Err(e) => println!("payment failed: {e:?}"),
    }
}

/// Handles one command line; returns false to exit.
fn handle(net: &mut Devnet, line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        [] => {}
        ["pay", from, to, amount] => pay(net, from, to, amount, false),
        ["pay", from, to, amount, "priority"] => pay(net, from, to, amount, true),
        ["balance"] => print_balances(net, None),
        ["balance", name] => print_balances(net, Some(name)),
        ["help"] => println!("{USAGE}"),
        ["quit"] | ["exit"] => return false,
        _ => println!("unrecognized: {line} (type help for usage)"),
    }
    true
}

fn mine(net: &mut Devnet, timestamp: u64) -> Result<(), String> {
    let info = net
        .mine(timestamp)
        .map_err(|e| format!("block production failed: {e:?}"))?;
    print_block(&info);
    Ok(())
}

fn run(opts: Opts) -> Result<(), String> {
    let mut net = Devnet::new(Config {
        genesis_timestamp: now_secs(),
        ..config(&opts)
    });
    println!("siworld devnet (mock proofs, devnet PoW; not for real funds)");
    println!("Test wallets:");
    print_balances(&net, None);
    println!("Type help for commands.");

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let interval = Duration::from_millis(opts.interval_ms);
    let mut next = Instant::now() + interval;
    let mut stdin_open = true;
    loop {
        let now = Instant::now();
        if now >= next {
            mine(&mut net, now_secs())?;
            if opts.blocks.is_some_and(|b| net.height() >= b) {
                return Ok(());
            }
            next += interval;
            continue;
        }
        let wait = next - now;
        if !stdin_open {
            thread::sleep(wait);
            continue;
        }
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if !handle(&mut net, &line) {
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => stdin_open = false,
        }
    }
}

/// Script: dave first receives a payment, then spends the received package.
fn demo(opts: Opts) -> Result<(), String> {
    let blocks = opts.blocks.unwrap_or(12).max(1);
    let mut net = Devnet::new(config(&opts));
    let script: &[(u64, &str, &str, &str)] = &[
        (2, "alice", "dave", "10"),
        (2, "bob", "carol", "7.5"),
        (5, "dave", "bob", "4"),
        (8, "dave", "alice", "1.25"),
    ];
    for h in 1..=blocks {
        for (at, from, to, amount) in script {
            if *at == h {
                pay(&mut net, from, to, amount, false);
            }
        }
        mine(&mut net, h)?;
    }
    println!("Balances:");
    print_balances(&net, None);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => parse_opts(&args[1..]).and_then(run),
        Some("demo") => parse_opts(&args[1..]).and_then(demo),
        Some("help") | Some("--help") | Some("-h") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand {other}\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
