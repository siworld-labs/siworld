//! `siworld-cli`: talks to a running `siworld-node` over its local RPC port.
//!
//! ```text
//! siworld-cli [--rpc ADDR] --auth-file FILE info | address | balance | send PAYMENT_ID ADDRESS AMOUNT [--priority]
//!                          | devfund PAYOUT_ID direct|lock ADDRESS AMOUNT
//! ```

use std::process::ExitCode;

use serde_json::{json, Value};
use siworld_node::keystore::{read_password, read_password_for};
use siworld_node::rpc_auth::{erase_json, RpcToken};
use siworld_node::service::call_authenticated;
use std::path::Path;

const USAGE: &str = "\
Usage:
  siworld-cli new-payment-id                                        generate an ID offline
  siworld-cli [--rpc ADDR] --auth-file FILE paymentstatus PAYMENT_ID
  siworld-cli [--rpc ADDR] --auth-file FILE info                       chain height, tip, peers
  siworld-cli [--rpc ADDR] --auth-file FILE address                    this node's address
  siworld-cli [--rpc ADDR] --auth-file FILE balance                    total, spendable and pending SIP
  siworld-cli [--rpc ADDR] --auth-file FILE --order-ledger DIR --order-witness DIR
              [--ledger-password-file FILE] send PAYMENT_ID ADDRESS AMOUNT [--priority]
  siworld-cli [--rpc ADDR] --auth-file FILE --fund-order FILE devfund PAYOUT_ID direct|lock ADDRESS AMOUNT
                                                      pay out of a development-fund
                                                      account (the node must hold
                                                      the fund key and mine)

  siworld-cli [--rpc ADDR] --auth-file FILE walletstatus
  siworld-cli [--rpc ADDR] --auth-file FILE walletlock
  siworld-cli [--rpc ADDR] --auth-file FILE [--password-file FILE] walletunlock [SECONDS]
  siworld-cli [--rpc ADDR] --auth-file FILE fundpayoutstatus PAYOUT_ID
  siworld-cli [--rpc ADDR] --auth-file FILE fundstatus | fundlock
  siworld-cli [--rpc ADDR] --auth-file FILE fundapprovals [OFFSET LIMIT]
  siworld-cli [--rpc ADDR] --auth-file FILE [--password-file FILE] fundunlock GRANT_FILE

Generate a fund PAYOUT_ID with new-payment-id and durably save the ID and complete
order before requesting devfund. After a timeout retry identical parameters and ID;
never substitute a new ID. Key-only backups exclude the fund journal.

fundunlock requires a bounded SIP grant file and the fund password; fund status,
lock and unlock use rpc-devfund.token. A new grant requires locking first.

walletunlock uses a hidden password prompt or owner-only password file; SECONDS
is 1..3600 (default 60). Lock/unlock requires the spend credential and enablement.
Initialize a separate order ledger and witness with siworld-node orders-init.
Send durably records the order and witness before RPC; keep these directories
independent of the wallet, with a separately retained current checkpoint.
Ledger passwords use their own hidden prompt or --ledger-password-file.
Save the 64-hex PAYMENT_ID before the first send. Retry the same ID, recipient,
amount and priority after a timeout; a new ID is a new payment.
ADDR defaults to 127.0.0.1:30334. AMOUNT is in SIP, e.g. 12.5.
FILE holds a scoped credential from siworld-node init or rpc-keygen.
Use rpc-read.token for reads, rpc-spend.token for send (requires the server's
--enable-wallet-spend), rpc-devfund.token for devfund. Never pass the token itself.";

fn request(args: &[String]) -> Option<Value> {
    match args {
        [m] if [
            "info",
            "address",
            "balance",
            "walletstatus",
            "walletlock",
            "fundstatus",
            "fundlock",
            "fundapprovals",
        ]
        .contains(&m.as_str()) =>
        {
            Some(json!({ "method": m }))
        }
        [m, offset, limit] if m == "fundapprovals" => Some(json!({"method":m,
            "offset": offset.parse::<usize>().ok()?, "limit": limit.parse::<usize>().ok()?})),
        [m] if m == "walletunlock" => Some(json!({"method": m, "seconds": 60})),
        [m, seconds] if m == "walletunlock" => {
            Some(json!({"method": m, "seconds": seconds.parse::<u64>().ok()?}))
        }
        [m, id] if m == "paymentstatus" => {
            let id = siworld_node::payments::PaymentId::parse(id).ok()?;
            Some(json!({"method":m,"payment_id":id.to_string()}))
        }
        [m, id, to, amount, rest @ ..] if m == "send" => {
            let id = siworld_node::payments::PaymentId::parse(id).ok()?;
            let priority = match rest {
                [] => false,
                [p] if p == "--priority" => true,
                _ => return None,
            };
            Some(
                json!({ "method": "send", "payment_id":id.to_string(), "to": to, "amount": amount, "priority": priority }),
            )
        }
        [m, id] if m == "fundpayoutstatus" => {
            let id = siworld_node::fund_payments::PayoutId::parse(id).ok()?;
            Some(json!({"method":m,"payout_id":id.to_string()}))
        }
        [m, id, account, to, amount] if m == "devfund" => {
            let id = siworld_node::fund_payments::PayoutId::parse(id).ok()?;
            Some(
                json!({ "method": "devfund", "payout_id":id.to_string(), "account": account, "to": to, "amount": amount }),
            )
        }
        [m, file] if m == "fundunlock" => {
            let grant = siworld_node::fund_keys::FundGrant::read(Path::new(file)).ok()?;
            Some(json!({"method":m,"grant":grant}))
        }
        _ => None,
    }
}

// The durable intent and witness precede every RPC, including identity reads.
// Keep the exclusive ledger handle alive until the send reply is received.
fn send_recorded(
    ledger: &mut siworld_node::orders::OrderLedger,
    request: &Value,
    mut call: impl FnMut(&Value) -> Result<Value, String>,
) -> Result<Value, String> {
    use siworld_node::payments::{PaymentId, PaymentOrder};
    let id = PaymentId::parse(request["payment_id"].as_str().ok_or("invalid payment ID")?)
        .map_err(|e| e.to_string())?;
    let to = siworld_node::address::parse_address(request["to"].as_str().ok_or("invalid address")?)
        .ok_or("invalid address")?;
    let amount =
        siworld_node::amount::parse_sip(request["amount"].as_str().ok_or("invalid amount")?)
            .ok_or("invalid amount")?;
    let priority = request["priority"].as_bool().ok_or("invalid priority")?;
    let order = PaymentOrder::new(id, &to, amount, priority);
    let cp = if ledger.state(id)? == Some(siworld_node::orders::OrderState::Dispatched) {
        ledger.begin_dispatch(&order)?
    } else {
        ledger.record(&order)?
    };
    let info = call(&json!({"method":"info"}))?;
    if info["genesis"].as_str() != Some(cp.genesis.as_str()) {
        return Err("order ledger network mismatch; send not attempted".into());
    }
    let address = call(&json!({"method":"address"}))?;
    if address["address"]
        .as_str()
        .and_then(siworld_node::address::parse_address)
        .map(|a| siworld_node::hex(&a.owner()))
        .as_deref()
        != Some(cp.owner.as_str())
    {
        return Err("order ledger wallet mismatch; send not attempted".into());
    }
    ledger.begin_dispatch(&order)?;
    let mut send = json!({"method":"send","payment_id":order.payment_id,"to":order.to,"amount":order.amount,"priority":order.priority});
    let reply = call(&send);
    erase_json(&mut send);
    reply
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut rpc = "127.0.0.1:30334".to_string();
    let mut auth_file = None;
    let mut password_file = None;
    let mut fund_order = None;
    let mut order_ledger = None;
    let mut order_witness = None;
    let mut ledger_password_file = None;
    let mut seen = std::collections::BTreeSet::new();
    while args.first().is_some_and(|arg| arg.starts_with("--")) {
        if args.len() < 2 {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
        if !seen.insert(args[0].clone()) {
            eprintln!("duplicate option");
            return ExitCode::FAILURE;
        }
        match args[0].as_str() {
            "--rpc" => rpc = args[1].clone(),
            "--auth-file" => auth_file = Some(args[1].clone()),
            "--password-file" => password_file = Some(args[1].clone()),
            "--fund-order" => fund_order = Some(args[1].clone()),
            "--order-ledger" => order_ledger = Some(args[1].clone()),
            "--order-witness" => order_witness = Some(args[1].clone()),
            "--ledger-password-file" => ledger_password_file = Some(args[1].clone()),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            }
        }
        args.drain(..2);
    }
    if args == ["new-payment-id"] && seen.is_empty() {
        return match siworld_node::payments::PaymentId::random() {
            Ok(id) => {
                println!("{id}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(auth_file) = auth_file else {
        eprintln!("--auth-file FILE is required");
        return ExitCode::FAILURE;
    };
    let token = match RpcToken::read(Path::new(&auth_file)) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(mut request) = request(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if request["method"] == "walletunlock" || request["method"] == "fundunlock" {
        let label = if request["method"] == "fundunlock" {
            "Fund key"
        } else {
            "Wallet"
        };
        match read_password_for(label, password_file.as_deref().map(Path::new), false) {
            Ok(password) => request["password"] = Value::String(password.to_string()),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    } else if password_file.is_some() {
        eprintln!("--password-file applies only to walletunlock or fundunlock");
        return ExitCode::FAILURE;
    }
    let reply = if request["method"] == "devfund" {
        (|| {
            use siworld_node::fund_payments::{PayoutId, RetainedOrder};
            let path = Path::new(
                fund_order
                    .as_deref()
                    .ok_or("devfund requires --fund-order FILE")?,
            );
            let id = PayoutId::parse(request["payout_id"].as_str().ok_or("invalid payout ID")?)
                .map_err(|e| e.to_string())?;
            let to = siworld_node::address::parse_address(
                request["to"].as_str().ok_or("invalid address")?,
            )
            .ok_or("invalid address")?;
            let amount = siworld_node::amount::parse_sip(
                request["amount"].as_str().ok_or("invalid amount")?,
            )
            .ok_or("invalid amount")?;
            let account = match request["account"].as_str() {
                Some("direct") => siworld_core::DevAccount::Direct,
                Some("lock") => siworld_core::DevAccount::Lock,
                _ => return Err("invalid fund account".into()),
            };
            if order_ledger.is_some() || order_witness.is_some() || ledger_password_file.is_some() {
                return Err("wallet ledger flags do not apply to devfund".into());
            }
            let mut retained = RetainedOrder::retain(path, id, account, &to, amount)?;
            let info = call_authenticated(&rpc, &json!({"method":"info"}), &token)?;
            retained.bind_genesis(info["genesis"].as_str().ok_or("node genesis unavailable")?)?;
            call_authenticated(&rpc, &request, &token)
        })()
    } else if fund_order.is_some() {
        Err("--fund-order applies only to devfund".into())
    } else if request["method"] == "send" {
        (|| {
            let dir = order_ledger
                .as_deref()
                .ok_or("send requires --order-ledger DIR")?;
            let witness = order_witness
                .as_deref()
                .ok_or("send requires --order-witness DIR")?;
            let password = read_password(ledger_password_file.as_deref().map(Path::new), false)?;
            let mut ledger = siworld_node::orders::OrderLedger::open(
                Path::new(dir),
                Path::new(witness),
                &password,
            )?;
            send_recorded(&mut ledger, &request, |r| {
                call_authenticated(&rpc, r, &token)
            })
        })()
    } else if order_ledger.is_some() || order_witness.is_some() || ledger_password_file.is_some() {
        Err("order ledger options apply only to send".into())
    } else {
        call_authenticated(&rpc, &request, &token)
    };
    erase_json(&mut request);
    match reply {
        Ok(reply) => match reply.get("error") {
            Some(e) => {
                eprintln!("error: {}", e.as_str().unwrap_or("unknown error"));
                ExitCode::FAILURE
            }
            None => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&reply).expect("JSON value serializes")
                );
                ExitCode::SUCCESS
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn fund_payout_requires_id_and_preserves_it_for_status() {
        assert!(request(&args(&["devfund", "direct", "address", "1"])).is_none());
        assert!(request(&args(&["devfund", "invalid", "direct", "address", "1"])).is_none());
        let id = "ab".repeat(32);
        assert_eq!(
            request(&args(&["devfund", &id, "direct", "address", "1"])).unwrap()["payout_id"],
            id
        );
        assert_eq!(
            request(&args(&["fundpayoutstatus", &id])).unwrap()["payout_id"],
            id
        );
    }
    #[test]
    fn send_requires_an_explicit_valid_id_and_status_preserves_it() {
        assert!(request(&args(&["send", "address", "1"])).is_none());
        assert!(request(&args(&["send", "invoice", "address", "1"])).is_none());
        let id = "AB".repeat(32);
        let send = request(&args(&["send", &id, "address", "1", "--priority"])).unwrap();
        assert_eq!(send["payment_id"], id.to_lowercase());
        assert_eq!(send["priority"], true);
        assert_eq!(
            request(&args(&["paymentstatus", &id])).unwrap()["payment_id"],
            send["payment_id"]
        );
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;
    use siworld_core::Digest;
    use siworld_crypto::SpendKey;
    use siworld_node::orders::OrderLedger;
    const PASSWORD: &str = "client independent ledger password";
    #[test]
    fn dispatch_witness_failure_prevents_send_and_cancelled_order_prevents_all_rpc() {
        use siworld_node::orders::Checkpoint;
        use siworld_node::payments::{PaymentId, PaymentOrder};
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "siworld-dispatch-{}",
            siworld_node::genesis::hex_bytes(&random)
        ));
        std::fs::create_dir(&root).unwrap();
        for name in ["ledger", "witness"] {
            std::fs::create_dir(root.join(name)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
        }
        let key = SpendKey::from_digest(Digest([1; 32]));
        let mut ledger = OrderLedger::create(
            &root.join("ledger"),
            &root.join("witness"),
            PASSWORD,
            Digest([3; 32]),
            key.owner(),
        )
        .unwrap();
        let order = PaymentOrder::new(
            PaymentId::random().unwrap(),
            &key.address(),
            10_000_000,
            false,
        );
        let cp = ledger.record(&order).unwrap();
        ledger
            .cancel_unsubmitted(PaymentId::parse(&order.payment_id).unwrap(), &cp)
            .unwrap();
        let mut request = json!({"method":"send","payment_id":order.payment_id,"to":order.to,"amount":order.amount,"priority":false});
        assert!(
            send_recorded(&mut ledger, &request, |_| panic!("RPC for cancelled order")).is_err()
        );
        request["payment_id"] = Value::String("cd".repeat(32));
        let mut reads = 0;
        assert!(send_recorded(&mut ledger, &request, |r| {
            match r["method"].as_str().unwrap() {
                "info" => {
                    reads += 1;
                    Ok(json!({"genesis":siworld_node::hex(&Digest([3; 32]))}))
                }
                "address" => {
                    reads += 1;
                    // The order checkpoint (3) is durable, but dispatch checkpoint (4) cannot publish.
                    std::fs::write(
                        root.join("witness").join(Checkpoint::filename(4)),
                        "obstruct publication",
                    )
                    .unwrap();
                    Ok(json!({"address":siworld_node::address::encode_address(&key.address())}))
                }
                _ => panic!("send after failed dispatch persistence"),
            }
        })
        .is_err());
        assert_eq!(reads, 2);
        drop(ledger);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn send_persists_before_rpc_and_retries_without_advancing_revision() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "siworld-client-orders-{}",
            siworld_node::genesis::hex_bytes(&random)
        ));
        std::fs::create_dir(&root).unwrap();
        let l = root.join("ledger");
        let w = root.join("witness");
        for p in [&l, &w] {
            std::fs::create_dir(p).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let owner = SpendKey::from_digest(Digest([1; 32]));
        let genesis = Digest([3; 32]);
        let mut ledger = OrderLedger::create(&l, &w, PASSWORD, genesis, owner.owner()).unwrap();
        let request = json!({"method":"send","payment_id":"ab".repeat(32),"to":siworld_node::address::encode_address(&owner.address()),"amount":"0.1","priority":false});
        let mut calls = 0;
        assert!(send_recorded(&mut ledger, &request, |_| {
            calls += 1;
            assert!(w
                .join(siworld_node::orders::Checkpoint::filename(1))
                .is_file());
            Err("timeout".into())
        })
        .is_err());
        assert_eq!(calls, 1);
        let cp = ledger.checkpoint().unwrap();
        assert_eq!(cp.sequence, 1);
        drop(ledger);
        let mut ledger = OrderLedger::open(&l, &w, PASSWORD).unwrap();
        let reply = send_recorded(&mut ledger, &request, |r| {
            match r["method"].as_str().unwrap() {
                "info" => Ok(json!({"genesis":siworld_node::hex(&genesis)})),
                "address" => {
                    Ok(json!({"address":siworld_node::address::encode_address(&owner.address())}))
                }
                "send" => {
                    assert!(w
                        .join(siworld_node::orders::Checkpoint::filename(2))
                        .is_file());
                    Ok(json!({"saved":true}))
                }
                _ => panic!(),
            }
        })
        .unwrap();
        assert_eq!(reply["saved"], true);
        assert_eq!(ledger.checkpoint().unwrap().sequence, cp.sequence + 1);
        let mut sends = 0;
        assert!(send_recorded(&mut ledger, &request, |_| {
            sends += 1;
            Ok(json!({"genesis":"wrong"}))
        })
        .is_err());
        assert_eq!(sends, 1);
        let mut next = request.clone();
        next["payment_id"] = Value::String("cd".repeat(32));
        std::fs::write(
            w.join("checkpoint-0000000000000003.json"),
            "block witness publication",
        )
        .unwrap();
        assert!(send_recorded(&mut ledger, &next, |_| panic!(
            "RPC after failed witness persistence"
        ))
        .is_err());
        drop(ledger);
        let _ = std::fs::remove_dir_all(root);
    }
}
