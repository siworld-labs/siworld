//! `siworld-node`: testnet node.
//!
//! ```text
//! siworld-node init    --datadir DIR
//! siworld-node address --datadir DIR
//! siworld-node devfund-keygen --out FILE
//! siworld-node genesis --network NAME --alloc OWNER:AMOUNT... [--proofs plonky3|mock]
//!                      [--dev-fund FILE] [options] > genesis.json
//! siworld-node run     --datadir DIR --genesis FILE [--listen MULTIADDR]... [--peer MULTIADDR]...
//!                      [--rpc ADDR] [--mine] [--dev-fund FILE]
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "development")]
use siworld_circuits::MockProver;
use siworld_circuits::ProofSystem;
use siworld_consensus::pow_hash;
use siworld_core::params::ProofSystemKind;
use siworld_core::Digest;
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::address::encode_address;
use siworld_node::devfund::DevFundSigner;
use siworld_node::fund_approval::{ApprovalSigner, ChangeRequest, SignedChange};
use siworld_node::fund_keys::{self, FundBudget, FundGrant, FundKeystore};
use siworld_node::fund_payments::governance::GovernanceFiles;
use siworld_node::genesis::{
    calibrated_target, hex_bytes, AllocationFile, DevFundFile, Genesis, GenesisFile, ProofsFile,
};
use siworld_node::keystore::{self, Keystore, WalletFileLock};
use siworld_node::node::Node;
use siworld_node::rpc_auth::{
    RpcAuth, RpcToken, FUND_TOKEN_FILE, READ_TOKEN_FILE, SPEND_TOKEN_FILE,
};
use siworld_node::secrets::read_secret;
use siworld_node::service::{check_rpc_address, run, Config, RpcConfig};
use siworld_node::{hex, parse_hex32};
use siworld_storage::BlockStore;

const USAGE: &str = "\
Usage:
  siworld-node init    --datadir DIR [--password-file FILE]
  siworld-node address --datadir DIR [--password-file FILE] [--allow-plaintext-wallet]
  siworld-node rpc-keygen --datadir DIR
  siworld-node devfund-keygen --out FILE [--password-file FILE]
  siworld-node devfund-approval-keygen --out FILE [--password-file FILE]
  siworld-node devfund-approval-public --key FILE --out FILE [--password-file FILE]
  siworld-node devfund-budget-request --key FILE --genesis FILE --fund-witness DIR --expected-fund-checkpoint FILE --policy FILE --reason TEXT --out FILE [--trusted-key FILE] [--password-file FILE]
  siworld-node devfund-approve --approver-key FILE --request FILE --out FILE [--password-file FILE]
  siworld-node devfund-approve-grant --approver-key FILE --grant FILE --context FILE --out FILE [--password-file FILE]
  siworld-node devfund-budget-apply --key FILE --genesis FILE --fund-witness DIR --expected-fund-checkpoint FILE --signed FILE [--trusted-key FILE] [--commit] [--password-file FILE]
  siworld-node devfund-journal-init --key FILE --genesis FILE --confirm-no-prior-requests [--password-file FILE]
  siworld-node devfund-migrate --key FILE [--password-file FILE]
  siworld-node devfund-public --key FILE [--password-file FILE]
  siworld-node devfund-backup --key FILE --out FILE [--password-file FILE]
  siworld-node devfund-restore --key FILE --out FILE [--password-file FILE]
  siworld-node devfund-witness-init --key FILE --genesis FILE --fund-witness NEW_DIR [--password-file FILE]
  siworld-node devfund-checkpoint --key FILE --genesis FILE --fund-witness DIR --out FILE
                       [--previous-fund-checkpoint FILE] [--password-file FILE]
  siworld-node devfund-backup-full --key FILE --genesis FILE --fund-witness DIR --out FILE [--password-file FILE]
  siworld-node devfund-check-full --backup FILE [--password-file FILE]
  siworld-node devfund-restore-full --backup FILE --out NEW_DIR --fund-witness DIR
                       --expected-fund-checkpoint FILE [--password-file FILE]
  siworld-node devfund-recover-journal --key FILE --genesis FILE --fund-witness DIR
                       --expected-fund-checkpoint FILE [--password-file FILE]
  siworld-node devfund-reconcile --key FILE --genesis FILE --fund-witness DIR --datadir DIR
                       --expected-height N --expected-tip HEX --expected-fund-checkpoint FILE
                       [--commit] [--password-file FILE]
  siworld-node devfund-rotate --key FILE [--password-file FILE] [--new-password-file FILE]
  siworld-node genesis --network NAME --alloc OWNER:AMOUNT [--alloc ...]
                       [--proofs plonky3|mock] [--dev-fund FILE] [--block-time SECS]
                       [--pow-iterations N] [--container-size N] [--miners N]
                       [--timestamp UNIX_SECS]
                       [--fund-password-file FILE]
  siworld-node run     --datadir DIR --genesis FILE [--listen MULTIADDR]...
                       [--peer MULTIADDR]... [--rpc ADDR] [--mine] [--dev-fund FILE]
                       [--enable-wallet-spend] [--password-file FILE]
                       [--allow-plaintext-wallet] [--fund-password-file FILE] [--fund-witness DIR]
                       [--worker-control FILE]
  siworld-node wallet-migrate --datadir DIR [--password-file FILE]
  siworld-node wallet-backup  --datadir DIR --out FILE [--password-file FILE]
  siworld-node wallet-check   --backup FILE [--password-file FILE]
  siworld-node wallet-restore --backup FILE --datadir NEW_DIR [--password-file FILE]
  siworld-node wallet-backup-full --datadir DIR --genesis FILE --out FILE [--password-file FILE]
  siworld-node wallet-check-full --backup FILE [--password-file FILE]
  siworld-node wallet-restore-full --backup FILE --datadir NEW_DIR [--password-file FILE]
  siworld-node orders-init --order-ledger NEW_DIR --order-witness NEW_DIR
                       --genesis FILE --owner HEX [--ledger-password-file FILE]
  siworld-node orders-record --order-ledger DIR --order-witness DIR
                       --payment-id HEX --to ADDRESS --amount SI [--priority]
                       [--ledger-password-file FILE]
  siworld-node orders-dispatch --order-ledger DIR --order-witness DIR
                       --payment-id HEX --to ADDRESS --amount SI [--priority]
                       [--ledger-password-file FILE]
  siworld-node orders-cancel --order-ledger DIR --order-witness DIR
                       --payment-id HEX --expected-ledger-checkpoint FILE [--commit]
                       [--ledger-password-file FILE]
  siworld-node orders-checkpoint --order-ledger DIR --order-witness DIR --out FILE
                       [--previous-ledger-checkpoint FILE] [--ledger-password-file FILE]
  siworld-node orders-archive --order-ledger DIR --order-witness DIR --out NEW_DIR
                       [--previous-ledger-checkpoint FILE] [--ledger-password-file FILE]
  siworld-node orders-check-archive --archive DIR [--ledger-password-file FILE]
  siworld-node orders-restore --archive DIR --out NEW_DIR --expected-ledger-checkpoint FILE
                       [--ledger-password-file FILE]
  siworld-node retention-keygen --out FILE --public-out FILE [--password-file FILE]
  siworld-node retention-key-public --signer FILE --public-out FILE [--password-file FILE]
  siworld-node retention-init --root NEW_DIR --signer FILE --checkpoint FILE [--password-file FILE]
  siworld-node retention-request --out FILE [--previous-receipt FILE --trusted-key FILE]
  siworld-node retention-accept --root DIR --signer FILE --archive DIR --request FILE --out FILE
                       [--password-file FILE]
  siworld-node retention-status --root DIR --signer FILE --request FILE --out FILE
                       [--password-file FILE]
  siworld-node retention-verify --trusted-key FILE --request FILE --status FILE --archive DIR
                       --out-checkpoint FILE
  siworld-node wallet-reconcile --datadir DIR --genesis FILE
                       --order-ledger DIR --order-witness DIR
                       --expected-ledger-checkpoint FILE [--ledger-password-file FILE]
                       --expected-height N --expected-tip HEX [--commit]
                       [--merge-backup FILE]... [--password-file FILE]
  siworld-node wallet-recovery-drill --backup FILE --chain-datadir DIR --work-dir DIR
                       --order-ledger DIR --order-witness DIR
                       --expected-ledger-checkpoint FILE [--ledger-password-file FILE]
                       --expected-height N --expected-tip HEX --out FILE [--password-file FILE]

Wallet passwords use a hidden terminal prompt or an owner-only file, never
command-line password text. Encrypted wallets start locked; use siworld-cli
walletunlock for a bounded spending session. Migration/backup/restore are offline
and never overwrite a backup or another restored wallet. Legacy plaintext wallets
require explicit migration or the testnet-only override.

wallet-backup/check/restore preserve only the spend key. Their -full variants also
preserve payment IDs, exact transactions and reservations. Full restore requires
a new directory and gates payments until offline wallet-reconcile reviews the
verified chain and an independent latest order ledger. Reconciliation is a dry
run unless --commit is supplied; --merge-backup imports records only with --commit.
The expected ledger checkpoint must come from an independently current source.
Legacy --orders FILE permits preview only, never --commit. The offline drill
uses a disposable sandbox and does not relay payments. No command establishes
global freshness or coordinates separate wallet instances.

Fund files use separate encrypted custody in a dedicated owner-only directory.
genesis/run authenticate them with a hidden prompt or --fund-password-file.
Fund signing starts locked; siworld-cli fundunlock requires its password and an
explicit chain/recipient/SI budget file. Locking does not revoke signed payouts.

TESTNET ONLY: the protocol is not final and these coins have no value.

init     creates DIR with an encrypted spend key and prints its owner and address.
address  prints the owner and address of DIR's key.
devfund-keygen
         creates an encrypted FILE and prints its two development-fund
         verifying keys. Pass FILE to genesis, and to run on the fund's node.
genesis  prints a genesis file. The first block's target is calibrated so that
         --miners machines like this one find a block every --block-time
         seconds (default 60 s, 10000 iterations, 32 slots, 1 miner).
         --proofs plonky3 (the default) makes every block carry a real STARK
         container proof; mock proofs check the rules but prove nothing, so
         a mock network's coins can be forged. --dev-fund puts the fund's
         verifying keys in the file; without it the fund accrues but cannot
         pay out.
run      starts the node. Defaults: --listen /ip4/0.0.0.0/tcp/30333,
         --rpc 127.0.0.1:30334. The RPC address must be a loopback
         address. Every call needs a scoped credential file from init or
         rpc-keygen. Wallet spending is disabled unless --enable-wallet-spend
         is set. With --dev-fund (and --mine), the node signs the payouts
         `siworld-cli devfund` asks for and includes them in its blocks.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("address") => address(&args[1..]),
        Some("rpc-keygen") => rpc_keygen(&args[1..]),
        Some(
            "orders-init" | "orders-record" | "orders-checkpoint" | "orders-dispatch"
            | "orders-cancel",
        ) => order_command(args[0].as_str(), &args[1..]),
        Some("wallet-recovery-drill") => recovery_drill_command(&args[1..]),
        Some(
            "orders-archive"
            | "orders-check-archive"
            | "orders-restore"
            | "retention-keygen"
            | "retention-key-public"
            | "retention-init"
            | "retention-request"
            | "retention-accept"
            | "retention-status"
            | "retention-verify",
        ) => retention_command(args[0].as_str(), &args[1..]),
        Some("wallet-migrate" | "wallet-backup" | "wallet-restore" | "wallet-check") => {
            wallet_command(args[0].as_str(), &args[1..])
        }
        Some(
            "wallet-backup-full" | "wallet-check-full" | "wallet-restore-full" | "wallet-reconcile",
        ) => full_wallet_command(args[0].as_str(), &args[1..]),
        Some(
            "devfund-keygen"
            | "devfund-approval-keygen"
            | "devfund-approval-public"
            | "devfund-budget-request"
            | "devfund-approve"
            | "devfund-approve-grant"
            | "devfund-budget-apply"
            | "devfund-migrate"
            | "devfund-public"
            | "devfund-backup"
            | "devfund-restore"
            | "devfund-rotate"
            | "devfund-journal-init",
        ) => {
            if args[0].starts_with("devfund-approval-")
                || args[0].starts_with("devfund-budget-")
                || args[0] == "devfund-approve"
                || args[0] == "devfund-approve-grant"
            {
                approval_command(args[0].as_str(), &args[1..])
            } else {
                devfund_key_command(args[0].as_str(), &args[1..])
            }
        }
        Some(
            "devfund-witness-init"
            | "devfund-checkpoint"
            | "devfund-backup-full"
            | "devfund-check-full"
            | "devfund-restore-full"
            | "devfund-recover-journal"
            | "devfund-reconcile",
        ) => full_fund_command(args[0].as_str(), &args[1..]),
        Some("genesis") => genesis(&args[1..]),
        Some("run") => run_node(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// `--flag value` pairs; a flag may repeat. `switches` take no value.
fn parse_flags(args: &[String], switches: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag}\n\n{USAGE}"));
        }
        if switches.contains(&flag.as_str()) {
            out.push((flag.clone(), String::new()));
        } else {
            let value = it.next().ok_or(format!("{flag} requires a value"))?;
            out.push((flag.clone(), value.clone()));
        }
    }
    Ok(out)
}

fn one<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .rev()
        .find(|(f, _)| f == name)
        .map(|(_, v)| v.as_str())
}

fn all<'a>(flags: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    flags
        .iter()
        .filter(|(f, _)| f == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

fn check_known(flags: &[(String, String)], known: &[&str]) -> Result<(), String> {
    match flags.iter().find(|(f, _)| !known.contains(&f.as_str())) {
        Some((f, _)) => Err(format!("unknown option {f}\n\n{USAGE}")),
        None => Ok(()),
    }
}

fn number(flags: &[(String, String)], name: &str, default: u64) -> Result<u64, String> {
    one(flags, name).map_or(Ok(default), |v| {
        v.parse().map_err(|_| format!("{name} requires an integer"))
    })
}

fn datadir(flags: &[(String, String)]) -> Result<PathBuf, String> {
    one(flags, "--datadir")
        .map(PathBuf::from)
        .ok_or_else(|| "--datadir is required".to_string())
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("key")
}

fn read_key(
    dir: &Path,
    password_file: Option<&Path>,
    allow_plaintext: bool,
) -> Result<(SpendKey, Option<Keystore>), String> {
    let path = key_path(dir);
    let text = read_secret(&path)?;
    if let Ok(store) = Keystore::decode(&text) {
        let password = keystore::read_password(password_file, false)?;
        let key = store.open(&password)?;
        return Ok((key, Some(store)));
    }
    if !allow_plaintext {
        return Err("encrypted wallet required; use wallet-migrate (legacy testnet override: --allow-plaintext-wallet)".into());
    }
    Ok((keystore::legacy_key(&path)?, None))
}

fn wallet_command(command: &str, args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &[])?;
    let known: &[&str] = match command {
        "wallet-migrate" => &["--datadir", "--password-file"],
        "wallet-backup" => &["--datadir", "--out", "--password-file"],
        "wallet-restore" => &["--datadir", "--backup", "--password-file"],
        "wallet-check" => &["--backup", "--password-file"],
        _ => return Err("unknown wallet command".into()),
    };
    check_known(&flags, known)?;
    let password = keystore::read_password(
        one(&flags, "--password-file").map(Path::new),
        command == "wallet-migrate",
    )?;
    match command {
        "wallet-migrate" => keystore::migrate_wallet(&datadir(&flags)?, &password)?,
        "wallet-backup" => keystore::backup_wallet(
            &datadir(&flags)?,
            Path::new(one(&flags, "--out").ok_or("--out is required")?),
            &password,
        )?,
        "wallet-restore" => {
            let dir = datadir(&flags)?;
            keystore::restore_wallet(
                Path::new(one(&flags, "--backup").ok_or("--backup is required")?),
                &dir,
                &password,
            )?;
            create_rpc_tokens(&dir)?;
        }
        "wallet-check" => {
            let store = Keystore::load(Path::new(
                one(&flags, "--backup").ok_or("--backup is required")?,
            ))?;
            print_identity(&store.open(&password)?);
        }
        _ => unreachable!(),
    }
    println!("wallet operation completed");
    Ok(())
}

fn full_wallet_command(command: &str, args: &[String]) -> Result<(), String> {
    use siworld_node::backup::{self, BackupInfo};
    let flags = parse_flags(args, &["--commit"])?;
    let known: &[&str] = match command {
        "wallet-backup-full" => &["--datadir", "--genesis", "--out", "--password-file"],
        "wallet-check-full" => &["--backup", "--password-file"],
        "wallet-restore-full" => &["--backup", "--datadir", "--password-file"],
        "wallet-reconcile" => &[
            "--datadir",
            "--genesis",
            "--orders",
            "--order-ledger",
            "--order-witness",
            "--ledger-password-file",
            "--expected-ledger-checkpoint",
            "--expected-height",
            "--expected-tip",
            "--commit",
            "--merge-backup",
            "--password-file",
        ],
        _ => return Err("unknown wallet command".into()),
    };
    check_known(&flags, known)?;
    for name in known.iter().filter(|n| **n != "--merge-backup") {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let required = |name| one(&flags, name).ok_or_else(|| format!("{name} is required"));
    let password = keystore::read_password(one(&flags, "--password-file").map(Path::new), false)?;
    let info = |i: BackupInfo| {
        println!("snapshot: {}\nnetwork: {}\nowner: {}\nheight: {}\ntip: {}\nfinalized_height: {}\nfinalized_hash: {}\npayments: {}",hex(&i.snapshot_id),i.genesis.network,hex(&i.owner),i.height,hex(&i.tip),i.final_height,hex(&i.final_hash),i.payment_count);
    };
    match command {
        "wallet-check-full" => info(backup::inspect_full_backup(
            Path::new(required("--backup")?),
            &password,
        )?),
        "wallet-restore-full" => info(backup::restore_full_backup(
            Path::new(required("--backup")?),
            &datadir(&flags)?,
            &password,
        )?),
        "wallet-backup-full" => {
            let text = std::fs::read_to_string(required("--genesis")?)
                .map_err(|_| "cannot read genesis")?;
            let genesis = Genesis::from_json(&text).map_err(|e| e.to_string())?;
            let system = proof_system(&genesis, false)?;
            backup::create_full_backup(
                &datadir(&flags)?,
                Path::new(required("--out")?),
                &password,
                &genesis,
                system,
            )?;
            println!("full wallet backup completed");
        }
        "wallet-reconcile" => {
            let expected_height = required("--expected-height")?
                .parse::<u64>()
                .map_err(|_| "invalid expected height")?;
            let expected_tip =
                parse_hex32(required("--expected-tip")?).ok_or("invalid expected tip")?;
            let commit = one(&flags, "--commit").is_some();
            let merges = all(&flags, "--merge-backup");
            if !commit && !merges.is_empty() {
                return Err(
                    "--merge-backup requires --commit; a dry run never imports records".into(),
                );
            }
            let dir = datadir(&flags)?;
            let legacy = one(&flags, "--orders");
            if legacy.is_some()
                && (commit
                    || [
                        "--order-ledger",
                        "--order-witness",
                        "--ledger-password-file",
                        "--expected-ledger-checkpoint",
                    ]
                    .iter()
                    .any(|n| one(&flags, n).is_some()))
            {
                return Err(
                    "order_ledger_freshness_required: raw arrays support preview only".into(),
                );
            }
            let ledger = if legacy.is_none() {
                Some(open_order_ledger(&flags)?)
            } else {
                None
            };
            let verified = ledger
                .as_ref()
                .map(|l| l.verify_file(Path::new(required("--expected-ledger-checkpoint")?)))
                .transpose()?;
            if let Some(v) = &verified {
                v.ensure_outside(&dir)?;
            }
            let orders = legacy
                .map(|p| siworld_node::payments::load_payment_orders(Path::new(p)))
                .transpose()?;
            let _lock = WalletFileLock::acquire(&dir)?;
            let key = Keystore::load(&dir.join("key"))?.open(&password)?;
            let text = std::fs::read_to_string(required("--genesis")?)
                .map_err(|_| "cannot read genesis")?;
            let genesis = Genesis::from_json(&text).map_err(|e| e.to_string())?;
            if let Some(v) = &verified {
                if v.checkpoint().genesis != hex(&genesis.id)
                    || v.checkpoint().owner != hex(&key.owner())
                {
                    return Err("order_ledger_freshness_required".into());
                }
            }
            let system = proof_system(&genesis, false)?;
            let store = BlockStore::open(&dir.join("blocks.redb"), &genesis.id)
                .map_err(|e| e.to_string())?;
            let mut node = Node::open(
                genesis,
                key,
                SecretSeed::from_os_rng().map_err(|_| "OS randomness unavailable")?,
                Some(store),
                system,
            )
            .map_err(|e| e.to_string())?;
            node.enable_payment_journal(&dir.join("payments.redb"))
                .map_err(|e| e.to_string())?;
            // Check the operator-reviewed chain before any optional durable imports.
            if node.height() != expected_height || node.tip() != expected_tip {
                return Err("payment_checkpoint_mismatch".into());
            }
            for path in merges {
                backup::merge_full_backup(&mut node, Path::new(path), &password)?;
            }
            let review = if let Some(v) = verified.as_ref() {
                node.reconcile_payments(v, expected_height, expected_tip, commit)
            } else {
                node.preview_payment_orders(
                    orders.as_ref().expect("legacy orders"),
                    expected_height,
                    expected_tip,
                )
            }
            .map_err(|e| e.to_string())?;
            let receipts:Vec<_>=review.receipts.iter().map(|r|serde_json::json!({"payment_id":r.id.to_string(),"state":r.state.as_str(),"slot_id":r.slot_id.map(|id|hex(&id)),"confirmed_height":r.confirmed_height})).collect();
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"committed":review.committed,"committable":review.committable,"missing_orders":review.missing_orders,"cancelled_tombstones":review.cancelled_tombstones,"height":review.height,"tip":hex(&review.tip),"orders_hash":hex(&review.orders_hash),"order_checkpoint":review.order_checkpoint,"payments":receipts})).map_err(|_|"cannot encode reconciliation report")?);
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn open_order_ledger(
    flags: &[(String, String)],
) -> Result<siworld_node::orders::OrderLedger, String> {
    let p = keystore::read_password(one(flags, "--ledger-password-file").map(Path::new), false)?;
    siworld_node::orders::OrderLedger::open(
        Path::new(one(flags, "--order-ledger").ok_or("--order-ledger is required")?),
        Path::new(one(flags, "--order-witness").ok_or("--order-witness is required")?),
        &p,
    )
}
fn order_command(command: &str, args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &["--priority", "--commit"])?;
    let common = [
        "--order-ledger",
        "--order-witness",
        "--ledger-password-file",
    ];
    let extra: &[&str] = match command {
        "orders-init" => &["--genesis", "--owner"],
        "orders-record" | "orders-dispatch" => &["--payment-id", "--to", "--amount", "--priority"],
        "orders-cancel" => &["--payment-id", "--expected-ledger-checkpoint", "--commit"],
        "orders-checkpoint" => &["--out", "--previous-ledger-checkpoint"],
        _ => unreachable!(),
    };
    let mut known = common.to_vec();
    known.extend_from_slice(extra);
    check_known(&flags, &known)?;
    for name in &known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let required = |n| one(&flags, n).ok_or_else(|| format!("{n} is required"));
    let checkpoint = if command == "orders-init" {
        let text =
            std::fs::read_to_string(required("--genesis")?).map_err(|_| "cannot read genesis")?;
        let g = Genesis::from_json(&text).map_err(|e| e.to_string())?;
        let owner = parse_hex32(required("--owner")?)
            .filter(siworld_crypto::is_canonical)
            .ok_or("invalid owner")?;
        let password =
            keystore::read_password(one(&flags, "--ledger-password-file").map(Path::new), true)?;
        let l = Path::new(required("--order-ledger")?);
        let w = Path::new(required("--order-witness")?);
        for dir in [l, w] {
            let mut d = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                d.mode(0o700);
            }
            d.create(dir).map_err(|_| {
                "orders-init requires two new separate directories with existing parents"
            })?;
        }
        siworld_node::orders::OrderLedger::create(l, w, &password, g.id, owner)?.checkpoint()?
    } else {
        let mut ledger = open_order_ledger(&flags)?;
        if command == "orders-cancel" {
            let id = siworld_node::payments::PaymentId::parse(required("--payment-id")?)
                .map_err(|e| e.to_string())?;
            let expected = ledger
                .read_external_checkpoint(Path::new(required("--expected-ledger-checkpoint")?))?;
            if one(&flags, "--commit").is_some() {
                ledger.cancel_unsubmitted(id, &expected)?
            } else {
                ledger.preview_cancel(id, &expected)?;
                println!(
                    "{}",
                    serde_json::json!({"committed":false,"payment_id":id.to_string(),"eligible":true,"state":"unsubmitted","order_checkpoint":expected})
                );
                return Ok(());
            }
        } else if command == "orders-record" || command == "orders-dispatch" {
            let id = siworld_node::payments::PaymentId::parse(required("--payment-id")?)
                .map_err(|e| e.to_string())?;
            let to =
                siworld_node::address::parse_address(required("--to")?).ok_or("invalid address")?;
            let amount =
                siworld_node::amount::parse_si(required("--amount")?).ok_or("invalid amount")?;
            let order = siworld_node::payments::PaymentOrder::new(
                id,
                &to,
                amount,
                one(&flags, "--priority").is_some(),
            );
            if command == "orders-dispatch" {
                ledger.begin_dispatch(&order)?
            } else {
                ledger.record(&order)?
            }
        } else {
            ledger.export_checkpoint(
                Path::new(required("--out")?),
                one(&flags, "--previous-ledger-checkpoint").map(Path::new),
            )?
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&checkpoint).map_err(|_| "cannot encode checkpoint")?
    );
    Ok(())
}
fn retention_command(command: &str, args: &[String]) -> Result<(), String> {
    use siworld_node::orders::{archive, Checkpoint};
    use siworld_node::retention::{self, Receipt, ReceiptSigner, Request, Retainer, Status};
    let flags = parse_flags(args, &[])?;
    let known: &[&str] = match command {
        "orders-archive" => &[
            "--order-ledger",
            "--order-witness",
            "--ledger-password-file",
            "--out",
            "--previous-ledger-checkpoint",
        ],
        "orders-check-archive" => &["--archive", "--ledger-password-file"],
        "orders-restore" => &[
            "--archive",
            "--out",
            "--expected-ledger-checkpoint",
            "--ledger-password-file",
        ],
        "retention-keygen" => &["--out", "--public-out", "--password-file"],
        "retention-key-public" => &["--signer", "--public-out", "--password-file"],
        "retention-init" => &["--root", "--signer", "--checkpoint", "--password-file"],
        "retention-request" => &["--out", "--previous-receipt", "--trusted-key"],
        "retention-accept" => &[
            "--root",
            "--signer",
            "--archive",
            "--request",
            "--out",
            "--password-file",
        ],
        "retention-status" => &[
            "--root",
            "--signer",
            "--request",
            "--out",
            "--password-file",
        ],
        "retention-verify" => &[
            "--trusted-key",
            "--request",
            "--status",
            "--archive",
            "--out-checkpoint",
        ],
        _ => unreachable!(),
    };
    check_known(&flags, known)?;
    for name in known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let required = |n| one(&flags, n).ok_or_else(|| format!("{n} is required"));
    let path = |n| required(n).map(Path::new);
    match command {
        "orders-archive" => {
            let ledger = open_order_ledger(&flags)?;
            let m = ledger.archive(
                path("--out")?,
                one(&flags, "--previous-ledger-checkpoint").map(Path::new),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&m).map_err(|_| "cannot encode archive manifest")?
            );
        }
        "orders-check-archive" | "orders-restore" => {
            let p = keystore::read_password(
                one(&flags, "--ledger-password-file").map(Path::new),
                false,
            )?;
            let m = if command == "orders-restore" {
                archive::restore_file(
                    path("--archive")?,
                    path("--out")?,
                    &p,
                    path("--expected-ledger-checkpoint")?,
                )?
            } else {
                archive::check(path("--archive")?, &p)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m).map_err(|_| "cannot encode archive manifest")?
            );
        }
        "retention-keygen" | "retention-key-public" => {
            let password = keystore::read_password(
                one(&flags, "--password-file").map(Path::new),
                command == "retention-keygen",
            )?;
            let key = if command == "retention-keygen" {
                ReceiptSigner::generate_file(path("--out")?, &password)?
            } else {
                ReceiptSigner::load(path("--signer")?, &password)?
            };
            retention::save_trusted_key(path("--public-out")?, key.verifying_key())?;
        }
        "retention-init" | "retention-accept" | "retention-status" => {
            let password =
                keystore::read_password(one(&flags, "--password-file").map(Path::new), false)?;
            let signer = ReceiptSigner::load(path("--signer")?, &password)?;
            if command == "retention-init" {
                let cp = Checkpoint::read(path("--checkpoint")?)?;
                Retainer::create(path("--root")?, &signer, &cp)?;
            } else {
                let root = path("--root")?;
                let mut excluded = vec![root];
                if command == "retention-accept" {
                    excluded.push(path("--archive")?);
                }
                let out = archive::external_path(path("--out")?, &excluded)?;
                let request = Request::read(path("--request")?)?;
                let mut receiver = Retainer::open(root, &signer)?;
                if command == "retention-accept" {
                    receiver
                        .accept(path("--archive")?, &request)?
                        .save_new(&out)?;
                } else {
                    receiver.status(&request)?.save_new(&out)?;
                }
            }
        }
        "retention-request" => {
            let previous = if let Some(p) = one(&flags, "--previous-receipt") {
                let key = retention::read_trusted_key(path("--trusted-key")?)?;
                let receipt = Receipt::read(Path::new(p))?;
                receipt.verify_signature(&key)?;
                Some(receipt.id()?)
            } else {
                if one(&flags, "--trusted-key").is_some() {
                    return Err("--trusted-key requires --previous-receipt".into());
                }
                None
            };
            Request::fresh(previous)?.save_new(path("--out")?)?;
        }
        "retention-verify" => {
            let key = retention::read_trusted_key(path("--trusted-key")?)?;
            let request = Request::read(path("--request")?)?;
            let receipt = Status::read(path("--status")?)?.verify(&key, &request)?;
            let source = path("--archive")?;
            let m = archive::inspect(source)?;
            if receipt.body.manifest != m {
                return Err("retention status/archive mismatch".into());
            }
            m.checkpoint.save_new(&archive::external_path(
                path("--out-checkpoint")?,
                &[source],
            )?)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn recovery_drill_command(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &[])?;
    let known = [
        "--backup",
        "--chain-datadir",
        "--work-dir",
        "--out",
        "--password-file",
        "--order-ledger",
        "--order-witness",
        "--ledger-password-file",
        "--expected-ledger-checkpoint",
        "--expected-height",
        "--expected-tip",
    ];
    check_known(&flags, &known)?;
    for name in known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let required = |n| one(&flags, n).ok_or_else(|| format!("{n} is required"));
    let ledger = open_order_ledger(&flags)?;
    let verified = ledger.verify_file(Path::new(required("--expected-ledger-checkpoint")?))?;
    let password = keystore::read_password(one(&flags, "--password-file").map(Path::new), false)?;
    let backup = Path::new(required("--backup")?);
    let info = siworld_node::backup::inspect_full_backup(backup, &password)?;
    let request = siworld_node::backup::DrillRequest {
        backup,
        chain_dir: Path::new(required("--chain-datadir")?),
        work_dir: Path::new(required("--work-dir")?),
        password: &password,
        expected_height: required("--expected-height")?
            .parse()
            .map_err(|_| "invalid expected height")?,
        expected_tip: parse_hex32(required("--expected-tip")?).ok_or("invalid expected tip")?,
    };
    let report = siworld_node::backup::drill_full_backup(
        &request,
        proof_system(&info.genesis, false)?,
        &verified,
    )?;
    report.save_new(Path::new(required("--out")?))?;
    println!("offline recovery drill completed; no network relay performed");
    Ok(())
}

fn print_identity(key: &SpendKey) {
    println!("owner:   {}", hex(&key.owner()));
    println!("address: {}", encode_address(&key.address()));
}

fn init(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &[])?;
    check_known(&flags, &["--datadir", "--password-file"])?;
    let dir = datadir(&flags)?;
    let password = keystore::read_password(one(&flags, "--password-file").map(Path::new), true)?;
    let path = key_path(&dir);
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let _lock = WalletFileLock::acquire(&dir)?;
    let seed = SecretSeed::from_os_rng().map_err(|e| format!("OS random generator: {e}"))?;
    let key = SpendKey::from_digest(seed.derive("spend key", 0));
    Keystore::seal(&key, &password)?.save_new(&path)?;
    create_rpc_tokens(&dir)?;
    println!("created {}", path.display());
    print_identity(&key);
    Ok(())
}

fn create_rpc_tokens(dir: &Path) -> Result<(), String> {
    for name in [READ_TOKEN_FILE, SPEND_TOKEN_FILE, FUND_TOKEN_FILE] {
        let path = dir.join(name);
        if path.exists() {
            RpcToken::read(&path)?;
        } else {
            RpcToken::generate_file(&path)?;
        }
    }
    // Also catch accidental copies across roles before starting a server.
    RpcAuth::new(
        RpcToken::read(&dir.join(READ_TOKEN_FILE))?,
        Some(RpcToken::read(&dir.join(SPEND_TOKEN_FILE))?),
        Some(RpcToken::read(&dir.join(FUND_TOKEN_FILE))?),
    )?;
    Ok(())
}

fn load_rpc_auth(dir: &Path, spend: bool, fund: bool) -> Result<RpcAuth, String> {
    RpcAuth::new(
        RpcToken::read(&dir.join(READ_TOKEN_FILE))
            .map_err(|e| format!("{e}; run rpc-keygen --datadir DIR"))?,
        spend
            .then(|| RpcToken::read(&dir.join(SPEND_TOKEN_FILE)))
            .transpose()?,
        fund.then(|| RpcToken::read(&dir.join(FUND_TOKEN_FILE)))
            .transpose()?,
    )
}

fn rpc_keygen(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &[])?;
    check_known(&flags, &["--datadir"])?;
    let dir = datadir(&flags)?;
    create_rpc_tokens(&dir)?;
    println!("RPC credentials ready in {}", dir.display());
    Ok(())
}

fn address(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &["--allow-plaintext-wallet"])?;
    check_known(
        &flags,
        &["--datadir", "--password-file", "--allow-plaintext-wallet"],
    )?;
    let dir = datadir(&flags)?;
    let _lock = WalletFileLock::acquire(&dir)?;
    print_identity(
        &read_key(
            &dir,
            one(&flags, "--password-file").map(Path::new),
            one(&flags, "--allow-plaintext-wallet").is_some(),
        )?
        .0,
    );
    Ok(())
}

fn approval_command(command: &str, args: &[String]) -> Result<(), String> {
    let switches = ["--commit"];
    let flags = parse_flags(args, &switches)?;
    let known: &[&str] = match command {
        "devfund-approval-keygen" => &["--out", "--password-file"],
        "devfund-approval-public" => &["--key", "--out", "--password-file"],
        "devfund-approve" => &["--approver-key", "--request", "--out", "--password-file"],
        "devfund-approve-grant" => &[
            "--approver-key",
            "--grant",
            "--context",
            "--out",
            "--password-file",
        ],
        "devfund-budget-request" => &[
            "--key",
            "--genesis",
            "--fund-witness",
            "--expected-fund-checkpoint",
            "--policy",
            "--reason",
            "--out",
            "--trusted-key",
            "--password-file",
        ],
        "devfund-budget-apply" => &[
            "--key",
            "--genesis",
            "--fund-witness",
            "--expected-fund-checkpoint",
            "--signed",
            "--trusted-key",
            "--commit",
            "--password-file",
        ],
        _ => return Err("unknown approval command".into()),
    };
    check_known(&flags, known)?;
    for name in known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let path = |name: &str| {
        one(&flags, name)
            .map(Path::new)
            .ok_or_else(|| format!("{name} is required"))
    };
    let password = keystore::read_password_for(
        "Approval key",
        one(&flags, "--password-file").map(Path::new),
        command == "devfund-approval-keygen",
    )?;
    match command {
        "devfund-approval-keygen" => {
            ApprovalSigner::generate_file(path("--out")?, &password)?;
        }
        "devfund-approval-public" => {
            let signer = ApprovalSigner::load(path("--key")?, &password)?;
            ApprovalSigner::save_public(path("--out")?, &signer.verifying_key())?;
        }
        "devfund-approve" => {
            let signer = ApprovalSigner::load(path("--approver-key")?, &password)?;
            let request: ChangeRequest =
                siworld_node::fund_approval::read_json(path("--request")?)?;
            siworld_node::fund_approval::save_new(
                path("--out")?,
                &signer.approve_change(&request)?,
            )?;
        }
        "devfund-approve-grant" => {
            let signer = ApprovalSigner::load(path("--approver-key")?, &password)?;
            let grant: FundGrant = siworld_node::fund_approval::read_json(path("--grant")?)?;
            let context: siworld_node::fund_approval::SigningContext =
                siworld_node::fund_approval::read_json(path("--context")?)?;
            siworld_node::fund_approval::save_new(
                path("--out")?,
                &signer.approve_grant(&grant, &context)?,
            )?;
        }
        "devfund-budget-request" => {
            let g = Genesis::from_json(
                &std::fs::read_to_string(path("--genesis")?).map_err(|_| "cannot read genesis")?,
            )
            .map_err(|e| e.to_string())?;
            let policy: FundBudget = siworld_node::fund_approval::read_json(path("--policy")?)?;
            let trusted = one(&flags, "--trusted-key")
                .map(Path::new)
                .map(siworld_node::fund_approval::read_key)
                .transpose()?;
            let files = GovernanceFiles {
                key: path("--key")?,
                witness: path("--fund-witness")?,
                checkpoint: path("--expected-fund-checkpoint")?,
            };
            let request = files.propose(
                &password,
                &g,
                &policy,
                trusted.as_ref(),
                one(&flags, "--reason").ok_or("--reason is required")?,
            )?;
            siworld_node::fund_approval::save_new(path("--out")?, &request)?;
        }
        "devfund-budget-apply" => {
            let g = Genesis::from_json(
                &std::fs::read_to_string(path("--genesis")?).map_err(|_| "cannot read genesis")?,
            )
            .map_err(|e| e.to_string())?;
            let signed: SignedChange = siworld_node::fund_approval::read_json(path("--signed")?)?;
            let trusted = one(&flags, "--trusted-key")
                .map(Path::new)
                .map(siworld_node::fund_approval::read_key)
                .transpose()?;
            let files = GovernanceFiles {
                key: path("--key")?,
                witness: path("--fund-witness")?,
                checkpoint: path("--expected-fund-checkpoint")?,
            };
            let report = files.apply(
                &password,
                &g,
                &signed,
                trusted.as_ref(),
                one(&flags, "--commit").is_some(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|_| "cannot encode budget change report")?
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn devfund_key_command(command: &str, args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &["--confirm-no-prior-requests"])?;
    let known: &[&str] = match command {
        "devfund-journal-init" => &[
            "--key",
            "--genesis",
            "--password-file",
            "--confirm-no-prior-requests",
        ],
        "devfund-keygen" => &["--out", "--password-file"],
        "devfund-migrate" | "devfund-public" => &["--key", "--password-file"],
        "devfund-backup" | "devfund-restore" => &["--key", "--out", "--password-file"],
        "devfund-rotate" => &["--key", "--password-file", "--new-password-file"],
        _ => unreachable!(),
    };
    check_known(&flags, known)?;
    for name in known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let path = |name| {
        one(&flags, name)
            .map(Path::new)
            .ok_or_else(|| format!("{name} is required"))
    };
    let password = keystore::read_password_for(
        "Fund key",
        one(&flags, "--password-file").map(Path::new),
        matches!(command, "devfund-keygen" | "devfund-migrate"),
    )?;
    match command {
        "devfund-journal-init" => {
            if one(&flags, "--confirm-no-prior-requests").is_none() {
                return Err("explicit --confirm-no-prior-requests is required; never initialize over missing history".into());
            }
            let key_path = path("--key")?;
            let _lock = fund_keys::lock_file(key_path)?;
            let text =
                std::fs::read_to_string(path("--genesis")?).map_err(|_| "cannot read genesis")?;
            let genesis = Genesis::from_json(&text).map_err(|e| e.to_string())?;
            siworld_node::fund_payments::initialize(
                &key_path.parent().unwrap_or(Path::new(".")).join("payouts"),
                &FundKeystore::load(key_path)?,
                &password,
                &genesis,
            )?;
            println!("initialized new fund payout journal; retain it with the encrypted key");
        }
        "devfund-keygen" => {
            let store = fund_keys::generate_file(path("--out")?, &password)?;
            print_fund_keys(&store.open(&password)?);
        }
        "devfund-migrate" => fund_keys::migrate_file(path("--key")?, &password)?,
        "devfund-public" => print_fund_keys(&read_dev_fund(path("--key")?, &password)?),
        "devfund-backup" | "devfund-restore" => {
            fund_keys::copy_file(path("--key")?, path("--out")?, &password)?
        }
        "devfund-rotate" => {
            let next = keystore::read_password_for(
                "Fund key",
                one(&flags, "--new-password-file").map(Path::new),
                true,
            )?;
            fund_keys::rotate_file(path("--key")?, &password, &next)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn full_fund_command(command: &str, args: &[String]) -> Result<(), String> {
    use siworld_node::fund_payments::backup as fund_backup;
    let flags = parse_flags(args, &["--commit"])?;
    let common = &["--key", "--genesis", "--fund-witness", "--password-file"][..];
    let extra: &[&str] = match command {
        "devfund-witness-init" => &[],
        "devfund-checkpoint" => &["--out", "--previous-fund-checkpoint"],
        "devfund-backup-full" => &["--out"],
        "devfund-recover-journal" => &["--expected-fund-checkpoint"],
        "devfund-reconcile" => &[
            "--datadir",
            "--expected-height",
            "--expected-tip",
            "--expected-fund-checkpoint",
            "--commit",
        ],
        "devfund-check-full" => &["--backup", "--password-file"],
        "devfund-restore-full" => &[
            "--backup",
            "--out",
            "--fund-witness",
            "--expected-fund-checkpoint",
            "--password-file",
        ],
        _ => unreachable!(),
    };
    let known: Vec<&str> = if matches!(command, "devfund-check-full" | "devfund-restore-full") {
        extra.to_vec()
    } else {
        common.iter().chain(extra).copied().collect()
    };
    check_known(&flags, &known)?;
    for name in &known {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    let required = |name| one(&flags, name).ok_or_else(|| format!("{name} is required"));
    let path = |name| -> Result<&Path, String> { Ok(Path::new(required(name)?)) };
    let password = keystore::read_password_for(
        "Fund key",
        one(&flags, "--password-file").map(Path::new),
        false,
    )?;
    let result = if command == "devfund-check-full" {
        serde_json::to_value(fund_backup::inspect(path("--backup")?, &password)?)
    } else if command == "devfund-restore-full" {
        serde_json::to_value(fund_backup::restore(
            path("--backup")?,
            path("--out")?,
            &password,
            path("--fund-witness")?,
            path("--expected-fund-checkpoint")?,
        )?)
    } else {
        let key = path("--key")?;
        let witness = path("--fund-witness")?;
        let g = Genesis::from_json(
            &std::fs::read_to_string(path("--genesis")?).map_err(|_| "cannot read genesis")?,
        )
        .map_err(|e| e.to_string())?;
        match command {
            "devfund-witness-init" => {
                serde_json::to_value(fund_backup::enable_witness(key, witness, &password, &g)?)
            }
            "devfund-checkpoint" => serde_json::to_value(fund_backup::export_checkpoint(
                key,
                witness,
                &password,
                &g,
                path("--out")?,
                one(&flags, "--previous-fund-checkpoint").map(Path::new),
            )?),
            "devfund-backup-full" => serde_json::to_value(fund_backup::create(
                key,
                witness,
                &password,
                &g,
                path("--out")?,
            )?),
            "devfund-recover-journal" => serde_json::to_value(fund_backup::recover_journal(
                key,
                witness,
                &password,
                &g,
                path("--expected-fund-checkpoint")?,
            )?),
            "devfund-reconcile" => {
                let height = required("--expected-height")?
                    .parse::<u64>()
                    .map_err(|_| "invalid expected height")?;
                let tip = parse_hex32(required("--expected-tip")?).ok_or("invalid expected tip")?;
                let dir = datadir(&flags)?;
                let _node_lock = WalletFileLock::acquire(&dir)?;
                let _fund_lock = fund_keys::lock_file(key)?;
                let w =
                    std::fs::canonicalize(witness).map_err(|_| "cannot resolve fund witness")?;
                let d = std::fs::canonicalize(&dir).map_err(|_| "cannot resolve node directory")?;
                if d.starts_with(&w) || w.starts_with(&d) {
                    return Err("fund witness and node directories must be separate".into());
                }
                let pin = siworld_node::orders::archive::external_path(
                    path("--expected-fund-checkpoint")?,
                    &[&d],
                )?;
                let block_path = dir.join("blocks.redb");
                if !std::fs::symlink_metadata(&block_path)
                    .map_err(|_| "verified block store required")?
                    .is_file()
                {
                    return Err("regular verified block store required".into());
                }
                let store = BlockStore::open(&block_path, &g.id).map_err(|e| e.to_string())?;
                let system = proof_system(&g, false)?;
                // Fund reconciliation never needs the wallet's unrelated secret.
                let wallet = siworld_crypto::SpendKey::from_digest(
                    SecretSeed::from_os_rng()
                        .map_err(|_| "OS randomness unavailable")?
                        .derive("fund recovery ephemeral wallet", 0),
                );
                let mut node = Node::open(
                    g,
                    wallet,
                    SecretSeed::from_os_rng().map_err(|_| "OS randomness unavailable")?,
                    Some(store),
                    system,
                )
                .map_err(|e| e.to_string())?;
                node.protect_dev_fund_witnessed(
                    FundKeystore::load(key)?,
                    &password,
                    &key.parent().unwrap_or(Path::new(".")).join("payouts"),
                    witness,
                )?;
                serde_json::to_value(node.reconcile_fund(
                    &password,
                    height,
                    tip,
                    &pin,
                    one(&flags, "--commit").is_some(),
                )?)
            }
            _ => unreachable!(),
        }
    }
    .map_err(|_| "cannot encode fund recovery report")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|_| "cannot encode fund recovery report")?
    );
    Ok(())
}
fn print_fund_keys(signer: &DevFundSigner) {
    let keys = signer.verifying_keys();
    println!("direct: {}", hex_bytes(&keys.direct));
    println!("lock:   {}", hex_bytes(&keys.lock));
}
fn read_dev_fund(path: &Path, password: &str) -> Result<DevFundSigner, String> {
    let _lock = fund_keys::lock_file(path)?;
    FundKeystore::load(path)?.open(password)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Nonces per second this machine tries on one core at `iterations`.
fn measure_rate(iterations: u64) -> u64 {
    let seed = Digest([7; 32]);
    let start = Instant::now();
    let mut nonces = 0u64;
    while start.elapsed().as_millis() < 1_000 {
        std::hint::black_box(pow_hash(&seed, nonces, iterations));
        nonces += 1;
    }
    let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    nonces.saturating_mul(1_000) / ms.max(1)
}

fn genesis(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args, &[])?;
    check_known(
        &flags,
        &[
            "--network",
            "--alloc",
            "--proofs",
            "--dev-fund",
            "--fund-password-file",
            "--block-time",
            "--pow-iterations",
            "--container-size",
            "--miners",
            "--timestamp",
        ],
    )?;
    for name in ["--dev-fund", "--fund-password-file"] {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    if one(&flags, "--fund-password-file").is_some() && one(&flags, "--dev-fund").is_none() {
        return Err("--fund-password-file requires --dev-fund".into());
    }
    let network = one(&flags, "--network").ok_or("--network is required")?;
    let block_time = number(&flags, "--block-time", 60)?;
    let pow_iterations = number(&flags, "--pow-iterations", 10_000)?;
    let container_size = u32::try_from(number(&flags, "--container-size", 32)?)
        .map_err(|_| "--container-size is too large")?;
    let miners = number(&flags, "--miners", 1)?;
    let timestamp = number(&flags, "--timestamp", unix_now())?;
    let proofs = match one(&flags, "--proofs") {
        None => ProofsFile::Plonky3,
        Some(p) => ProofsFile::parse(p).ok_or(format!("--proofs {p}: expected plonky3 or mock"))?,
    };
    let allocations = all(&flags, "--alloc")
        .into_iter()
        .map(|a| {
            let (owner, amount) = a
                .split_once(':')
                .ok_or(format!("--alloc {a}: expected OWNER:AMOUNT"))?;
            Ok(AllocationFile {
                owner: owner.to_string(),
                amount: amount.to_string(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if allocations.is_empty() {
        return Err("at least one --alloc is required: testnet funds exist only at genesis".into());
    }
    if pow_iterations == 0 {
        return Err("--pow-iterations must be at least 1".into());
    }
    let dev_fund = match one(&flags, "--dev-fund") {
        Some(path) => {
            let password = keystore::read_password_for(
                "Fund key",
                one(&flags, "--fund-password-file").map(Path::new),
                false,
            )?;
            let keys = read_dev_fund(Path::new(path), &password)?.verifying_keys();
            Some(DevFundFile {
                direct: hex_bytes(&keys.direct),
                lock: hex_bytes(&keys.lock),
            })
        }
        None => None,
    };
    eprintln!("measuring this machine's hash rate for one second...");
    let rate = measure_rate(pow_iterations).saturating_mul(miners.max(1));
    let target = calibrated_target(rate, block_time);
    let genesis = Genesis::from_file(&GenesisFile {
        network: network.to_string(),
        timestamp,
        block_time,
        pow_iterations,
        target: hex(&Digest(target)),
        container_size,
        proofs,
        dev_fund,
        allocations,
    })
    .map_err(|e| e.to_string())?;
    eprintln!("genesis id {}", hex(&genesis.id));
    print!("{}", genesis.to_json());
    Ok(())
}

/// The proof system the genesis names, prepared to aggregate only on a miner.
fn proof_system(genesis: &Genesis, mine: bool) -> Result<Arc<dyn ProofSystem>, String> {
    match genesis.params.proofs {
        #[cfg(feature = "development")]
        ProofSystemKind::Mock => {
            eprintln!("WARNING: this network uses mock proofs; its coins can be forged");
            Ok(Arc::new(MockProver))
        }
        #[cfg(not(feature = "development"))]
        ProofSystemKind::Mock => Err(
            "mock networks require an explicit development build (--features development)".into(),
        ),
        #[cfg(feature = "plonky3")]
        ProofSystemKind::Plonky3 => {
            let started = Instant::now();
            let system = if mine {
                eprintln!(
                    "preparing the Plonky3 aggregation for {} slots per block (one sample proof per level; this takes a while)...",
                    genesis.params.container_size
                );
                siworld_prover::Plonky3System::for_miner(&genesis.params)
            } else {
                siworld_prover::Plonky3System::new(&genesis.params)
            }
            .map_err(|e| e.to_string())?;
            eprintln!("proof system ready in {} s", started.elapsed().as_secs());
            Ok(Arc::new(system))
        }
        #[cfg(not(feature = "plonky3"))]
        ProofSystemKind::Plonky3 => {
            let _ = mine;
            Err(
            "this network uses Plonky3 proofs, which this build of siworld-node lacks: build it with the plonky3 feature"
                .into(),
            )
        }
    }
}

fn run_node(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(
        args,
        &[
            "--mine",
            "--enable-wallet-spend",
            "--allow-plaintext-wallet",
        ],
    )?;
    check_known(
        &flags,
        &[
            "--datadir",
            "--genesis",
            "--listen",
            "--peer",
            "--rpc",
            "--enable-wallet-spend",
            "--password-file",
            "--allow-plaintext-wallet",
            "--mine",
            "--dev-fund",
            "--fund-password-file",
            "--fund-witness",
            "--worker-control",
        ],
    )?;
    for name in [
        "--dev-fund",
        "--fund-password-file",
        "--fund-witness",
        "--worker-control",
    ] {
        if all(&flags, name).len() > 1 {
            return Err(format!("duplicate option {name}"));
        }
    }
    if one(&flags, "--fund-password-file").is_some() && one(&flags, "--dev-fund").is_none() {
        return Err("--fund-password-file requires --dev-fund".into());
    }
    if one(&flags, "--fund-witness").is_some() && one(&flags, "--dev-fund").is_none() {
        return Err("--fund-witness requires --dev-fund".into());
    }
    let rpc = parse_rpc(one(&flags, "--rpc"))?;
    let dir = datadir(&flags)?;
    let _wallet_lock = WalletFileLock::acquire(&dir)?;
    let (key, wallet_store) = read_key(
        &dir,
        one(&flags, "--password-file").map(Path::new),
        one(&flags, "--allow-plaintext-wallet").is_some(),
    )?;
    let genesis_path = one(&flags, "--genesis").ok_or("--genesis is required")?;
    let text = std::fs::read_to_string(genesis_path)
        .map_err(|e| format!("cannot read {genesis_path}: {e}"))?;
    let genesis = Genesis::from_json(&text).map_err(|e| e.to_string())?;

    let multiaddrs = |name: &str| {
        all(&flags, name)
            .into_iter()
            .map(|a| a.parse().map_err(|e| format!("{name} {a}: {e}")))
            .collect::<Result<Vec<_>, String>>()
    };
    let mut listen = multiaddrs("--listen")?;
    if listen.is_empty() {
        listen.push("/ip4/0.0.0.0/tcp/30333".parse().expect("valid multiaddr"));
    }
    let config = Config {
        listen,
        peers: multiaddrs("--peer")?,
        rpc: Some(RpcConfig {
            address: rpc,
            auth: load_rpc_auth(
                &dir,
                one(&flags, "--enable-wallet-spend").is_some(),
                one(&flags, "--dev-fund").is_some(),
            )?,
        }),
        mine: one(&flags, "--mine").is_some(),
        worker: one(&flags, "--worker-control")
            .map(|path| {
                siworld_node::worker_transport::load_config(
                    Path::new(path),
                    genesis.params.container_size,
                )
            })
            .transpose()?,
    };

    let store =
        BlockStore::open(&dir.join("blocks.redb"), &genesis.id).map_err(|e| e.to_string())?;
    eprintln!("replaying {} stored blocks...", store.len());
    let randomness = SecretSeed::from_os_rng().map_err(|e| format!("OS random generator: {e}"))?;
    let system = proof_system(&genesis, config.mine)?;
    let mut node =
        Node::open(genesis, key, randomness, Some(store), system).map_err(|e| e.to_string())?;
    node.enable_payment_journal(&dir.join("payments.redb"))
        .map_err(|e| e.to_string())?;
    if let Some(store) = wallet_store {
        node.protect_wallet(store)?;
    }
    let _fund_lock = if let Some(path) = one(&flags, "--dev-fund") {
        if !config.mine {
            return Err("--dev-fund needs --mine: payouts go into this node's own blocks".into());
        }
        let path = Path::new(path);
        let lock = fund_keys::lock_file(path)?;
        let password = keystore::read_password_for(
            "Fund key",
            one(&flags, "--fund-password-file").map(Path::new),
            false,
        )?;
        let journal = path.parent().unwrap_or(Path::new(".")).join("payouts");
        let store = FundKeystore::load(path)?;
        if let Some(witness) = one(&flags, "--fund-witness") {
            let w = std::fs::canonicalize(witness).map_err(|_| "cannot resolve fund witness")?;
            let d = std::fs::canonicalize(&dir).map_err(|_| "cannot resolve node directory")?;
            if d.starts_with(&w) || w.starts_with(&d) {
                return Err("fund witness and node directories must be separate".into());
            }
            node.protect_dev_fund_witnessed(store, &password, &journal, &w)?;
        } else {
            node.protect_dev_fund(store, &password, &journal)?;
        }
        Some(lock)
    } else {
        None
    };

    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime
        .block_on(run(node, config, async {
            stop_signal().await;
            eprintln!("stopping");
        }))
        .map_err(|e| e.to_string())
}

/// The `--rpc` address, which must be a loopback address.
fn parse_rpc(flag: Option<&str>) -> Result<SocketAddr, String> {
    let address = flag
        .unwrap_or("127.0.0.1:30334")
        .parse()
        .map_err(|e| format!("--rpc: {e}"))?;
    check_rpc_address(address).map_err(|e| format!("--rpc: {e}"))
}

/// Ctrl-C, or SIGTERM from a service manager.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn init_and_credential_regeneration_preserve_wallet_identity_and_default_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("siworld-key-lifecycle-{}", std::process::id()));
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = if self.0.is_dir() {
                    std::fs::remove_dir_all(&self.0)
                } else {
                    std::fs::remove_file(&self.0)
                };
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let password_path = dir.with_extension("password");
        let password = "wallet lifecycle test password";
        siworld_node::secrets::write_secret(&password_path, password).unwrap();
        let _password_cleanup = Cleanup(password_path.clone());
        let args = vec![
            "--datadir".to_string(),
            dir.to_string_lossy().to_string(),
            "--password-file".into(),
            password_path.to_string_lossy().to_string(),
        ];
        init(&args).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let owner = read_key(&dir, Some(&password_path), false)
            .unwrap()
            .0
            .owner();
        assert!(init(&args).is_err());
        let before = read_secret(&dir.join(SPEND_TOKEN_FILE)).unwrap();
        rpc_keygen(&args[..2]).unwrap();
        assert_eq!(*read_secret(&dir.join(SPEND_TOKEN_FILE)).unwrap(), *before);
        std::fs::remove_file(dir.join(SPEND_TOKEN_FILE)).unwrap();
        assert!(load_rpc_auth(&dir, false, false).is_ok());
        assert!(load_rpc_auth(&dir, true, false).is_err());
        rpc_keygen(&args[..2]).unwrap();
        assert_ne!(*read_secret(&dir.join(SPEND_TOKEN_FILE)).unwrap(), *before);
        assert!(load_rpc_auth(&dir, true, true).is_ok());
        assert_eq!(
            read_key(&dir, Some(&password_path), false)
                .unwrap()
                .0
                .owner(),
            owner
        );
    }

    #[test]
    fn mock_network_requires_a_development_build() {
        let genesis = Genesis::from_file(&GenesisFile {
            network: "mock-guard".into(),
            timestamp: 1_000,
            block_time: 60,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 4,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![],
        })
        .unwrap();
        for mine in [false, true] {
            assert_eq!(
                proof_system(&genesis, mine).is_ok(),
                cfg!(feature = "development"),
                "mock-network support must follow the explicit build feature"
            );
        }
    }

    #[test]
    fn rpc_must_be_on_a_loopback_address() {
        assert_eq!(
            parse_rpc(None),
            Ok("127.0.0.1:30334".parse().expect("valid address"))
        );
        assert!(parse_rpc(Some("127.0.0.1:31334")).is_ok());
        assert!(parse_rpc(Some("[::1]:30334")).is_ok());
        for address in [
            "0.0.0.0:30334",
            "[::]:30334",
            "192.0.2.1:30334",
            "localhost",
        ] {
            assert!(parse_rpc(Some(address)).is_err(), "{address}");
        }
        let args = ["--datadir", "unused", "--rpc", "0.0.0.0:30334"].map(String::from);
        let e = run_node(&args).unwrap_err();
        assert!(e.contains("loopback"), "{e}");
    }
}
