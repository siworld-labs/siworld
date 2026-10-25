//! The local JSON-lines RPC of one node that does not mine, so payments stay
//! in its mempool.

mod common;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use siworld_circuits::MockProver;
use siworld_core::issuance::{epoch_of, fee_base};
use siworld_core::Digest;
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::address::encode_address;
use siworld_node::amount::format_si;
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::hex;
use siworld_node::node::Node;
use siworld_node::rpc_auth::{RpcAuth, RpcToken};
use siworld_node::service::{
    call as unauthenticated_call, call_authenticated, run, Config, RpcConfig,
};

fn token(byte: u8) -> RpcToken {
    RpcToken::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
}
fn call(rpc: &str, request: &Value) -> Result<Value, String> {
    let mut request = request.clone();
    if request["method"] == "send" && request.get("payment_id").is_none() {
        request["payment_id"] = json!(siworld_node::payments::PaymentId::random()
            .unwrap()
            .to_string());
    }
    call_authenticated(rpc, &request, &token(2))
}

const SI: u64 = siworld_core::params::ATOMS_PER_SI;

#[test]
fn unauthenticated_requests_cannot_read_or_spend() {
    let rpc = start();
    for method in ["info", "address", "balance", "send", "devfund"] {
        let reply = unauthenticated_call(
            &rpc,
            &json!({"method": method, "authorized": true,
            "X-Forwarded-For": "127.0.0.1"}),
        )
        .unwrap();
        assert_eq!(reply, json!({"error": "unauthorized"}), "{method}");
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn key(i: u8) -> SpendKey {
    SpendKey::from_digest(Digest([i; 32]))
}

/// Starts a node holding 100 SI on its own thread and returns its RPC
/// address once the RPC answers.
struct RunningNode {
    _journal: common::JournalDir,
    rpc: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl std::ops::Deref for RunningNode {
    type Target = str;
    fn deref(&self) -> &str {
        &self.rpc
    }
}
impl Drop for RunningNode {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}
fn start() -> RunningNode {
    start_with_spend(true)
}
fn start_with_spend(spend: bool) -> RunningNode {
    start_configured(spend, false)
}
fn start_configured(spend: bool, protected: bool) -> RunningNode {
    let genesis = Genesis::from_file(&GenesisFile {
        network: "rpc-test".into(),
        timestamp: 1_000,
        block_time: 1,
        pow_iterations: 1,
        target: "0f".to_string() + &"ff".repeat(31),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap();
    let rpc = format!("127.0.0.1:{}", free_port());
    let config = Config {
        worker: None,
        listen: vec![format!("/ip4/127.0.0.1/tcp/{}", free_port())
            .parse()
            .unwrap()],
        peers: vec![],
        rpc: Some(RpcConfig {
            address: rpc.parse().unwrap(),
            auth: RpcAuth::new(token(1), spend.then(|| token(2)), Some(token(3))).unwrap(),
        }),
        mine: false,
    };
    let mut node = Node::open(
        genesis,
        key(1),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    let journal = common::JournalDir::attach(&mut node);
    if protected {
        node.protect_wallet(
            siworld_node::keystore::Keystore::seal(&key(1), "RPC wallet test password").unwrap(),
        )
        .unwrap();
    }
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run(node, config, async {
                let _ = stop_rx.await;
            }))
            .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while call_authenticated(&rpc, &json!({"method": "info"}), &token(1)).is_err() {
        assert!(Instant::now() < deadline, "the RPC did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    RunningNode {
        _journal: journal,
        rpc,
        shutdown: Some(stop_tx),
        thread: Some(thread),
    }
}

/// Another key's address: the payments' recipient.
fn other_address() -> Value {
    json!(encode_address(&key(2).view_key().address()))
}

/// Writes `bytes` on one connection and collects the reply lines until the
/// node closes it or stays silent for two seconds.
fn exchange(rpc: &str, bytes: &[u8]) -> Vec<String> {
    let mut stream = TcpStream::connect(rpc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(bytes).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut replies = Vec::new();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return replies,
            Ok(_) => replies.push(line),
        }
    }
}

/// midstate counterexample 5: its RPC trusted a forged X-Forwarded-For. This
/// RPC takes no identity or origin from the request: such fields change
/// nothing, and a request that is not a JSON line, such as an HTTP request a
/// web page sends to localhost, ends the connection before any of it runs.
#[test]
fn ce5_rpc_ignores_forwarded_headers() {
    let rpc = start();
    let forged = [
        ("X-Forwarded-For", json!("127.0.0.1")),
        ("x-real-ip", json!("127.0.0.1")),
        ("Forwarded", json!("for=127.0.0.1;proto=https")),
        ("Origin", json!("http://127.0.0.1")),
        ("Host", json!("127.0.0.1")),
        ("remote_addr", json!("127.0.0.1")),
        ("authorized", json!(true)),
    ];
    for method in ["info", "address", "balance", "nonexistent"] {
        let plain = call(&rpc, &json!({ "method": method })).unwrap();
        let mut request = json!({ "method": method });
        for (field, value) in &forged {
            request[field] = value.clone();
        }
        assert_eq!(call(&rpc, &request).unwrap(), plain, "{method}");
    }

    // A send smuggled in the body of an HTTP request, as a browser can post
    // one to 127.0.0.1 from any web page.
    let to = other_address();
    let body = format!("{}\n", json!({"method": "send", "to": to, "amount": "10"}));
    let http = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n\
         X-Forwarded-For: 127.0.0.1\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let replies = exchange(&rpc, http.as_bytes());
    assert!(replies.len() <= 1, "{replies:?}");
    assert!(
        replies.iter().all(|r| r.contains("invalid JSON")),
        "{replies:?}"
    );
    // Nothing was sent.
    assert_eq!(
        call(&rpc, &json!({"method": "info"})).unwrap()["mempool"],
        0
    );
    assert_eq!(
        call(&rpc, &json!({"method": "balance"})).unwrap()["spendable"],
        "100"
    );
}

#[test]
fn a_second_send_waits_for_the_first_to_confirm() {
    let rpc = start();
    let to = other_address();
    let send =
        |amount: &str| call(&rpc, &json!({"method": "send", "to": to, "amount": amount})).unwrap();
    assert_eq!(send("10")["sent"], "10");
    let change = format_si(90 * SI - fee_base(epoch_of(0)));
    assert_eq!(
        call(&rpc, &json!({"method": "balance"})).unwrap(),
        json!({ "total": "100", "spendable": "0", "pending": change })
    );

    let reply = send("5");
    assert_eq!(reply["pending"], change, "{reply}");
    let error = reply["error"].as_str().unwrap();
    assert!(
        error.contains("wait for the previous payment to confirm"),
        "{error}"
    );
    let reply = send("95");
    assert!(
        reply["error"]
            .as_str()
            .unwrap()
            .contains("insufficient funds"),
        "{reply}"
    );
    assert!(reply.get("pending").is_none(), "{reply}");
}

#[test]
fn read_spend_and_fund_capabilities_cannot_cross_boundaries() {
    let rpc = start();
    let to = other_address();
    let send = json!({"method": "send", "to": to, "amount": "10", "permission": "Spend",
        "authorized": true, "X-Forwarded-For": "127.0.0.1"});
    for byte in [1, 3] {
        assert_eq!(
            call_authenticated(&rpc, &send, &token(byte)).unwrap(),
            json!({"error": "forbidden"})
        );
    }
    for method in ["info", "address", "balance"] {
        assert!(
            call_authenticated(&rpc, &json!({"method": method}), &token(1))
                .unwrap()
                .get("error")
                .is_none()
        );
    }
    assert_eq!(
        call_authenticated(&rpc, &json!({"method": "balance"}), &token(3)).unwrap(),
        json!({"error": "forbidden"})
    );
    for byte in [1, 2] {
        assert_eq!(
            call_authenticated(&rpc, &json!({"method": "devfund"}), &token(byte)).unwrap(),
            json!({"error": "forbidden"})
        );
    }
    assert_eq!(
        call(&rpc, &json!({"method": "info"})).unwrap()["mempool"],
        0
    );
    assert_eq!(
        call(&rpc, &json!({"method": "balance"})).unwrap()["spendable"],
        "100"
    );
    assert_eq!(call(&rpc, &send).unwrap()["sent"], "10");
}

#[test]
fn disabled_spending_rejects_even_the_matching_spend_credential() {
    let rpc = start_with_spend(false);
    assert_eq!(
        call(&rpc, &json!({"method": "send"})).unwrap(),
        json!({"error": "unauthorized"})
    );
    assert_eq!(
        call_authenticated(&rpc, &json!({"method": "balance"}), &token(1)).unwrap()["spendable"],
        "100"
    );
}

#[test]
fn authentication_is_per_request_and_malformed_credentials_do_not_echo() {
    let rpc = start();
    let lines = [
        json!({"method": "info", "auth": "01".repeat(32)}),
        json!({"method": "balance"}),
        json!({"method": "send", "auth": "01".repeat(32), "amount": "10"}),
        json!({"method": "info", "auth": "ff".repeat(32)}),
        json!({"method": "info", "auth": {"nested": "SECRET-MARKER"}}),
        json!({"method": "info", "auth": "03".repeat(32)}),
    ]
    .iter()
    .map(|v| format!("{v}\n"))
    .collect::<String>();
    let replies = exchange(&rpc, lines.as_bytes());
    assert_eq!(replies.len(), 6);
    let values = replies
        .iter()
        .map(|v| serde_json::from_str::<Value>(v).unwrap())
        .collect::<Vec<_>>();
    assert!(values[0].get("error").is_none());
    for i in [1, 3, 4] {
        assert_eq!(values[i], json!({"error": "unauthorized"}));
    }
    assert_eq!(values[2], json!({"error": "forbidden"}));
    assert!(values[5].get("error").is_none());
    assert!(!replies.join("").contains("SECRET-MARKER"));
    assert_eq!(
        call(&rpc, &json!({"method": "info"})).unwrap()["mempool"],
        0
    );
}

#[test]
fn oversized_and_invalid_json_never_dispatch_a_payment() {
    let rpc = start();
    let line = format!("{}\n", " ".repeat(siworld_node::service::MAX_RPC_LINE + 1));
    let replies = exchange(&rpc, line.as_bytes());
    assert!(replies.iter().any(|r| r.contains("request too long")));
    let replies = exchange(&rpc, b"{\"auth\":\"SECRET-MARKER\",invalid}\n");
    assert_eq!(replies, ["{\"error\":\"invalid JSON\"}\n"]);
    assert_eq!(
        call(&rpc, &json!({"method": "balance"})).unwrap()["spendable"],
        "100"
    );
}

#[test]
fn rpc_listener_closes_on_service_shutdown() {
    let rpc = start();
    let address = rpc.rpc.clone();
    drop(rpc);
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn encrypted_wallet_locking_requires_password_and_spend_capability() {
    let rpc = start_configured(true, true);
    let status = || call_authenticated(&rpc, &json!({"method":"walletstatus"}), &token(1)).unwrap();
    assert_eq!(status()["locked"], true);
    assert_eq!(status()["encrypted"], true);
    assert!(call(&rpc, &json!({"method":"balance"})).unwrap()["error"]
        .as_str()
        .unwrap()
        .contains("locked"));
    assert!(call(
        &rpc,
        &json!({"method":"send", "to":other_address(), "amount":"1"})
    )
    .unwrap()["error"]
        .as_str()
        .unwrap()
        .contains("locked"));
    let unlock =
        json!({"method":"walletunlock", "password":"RPC wallet test password", "seconds":60});
    for method in ["walletlock", "walletunlock"] {
        for byte in [1, 3] {
            let mut request = unlock.clone();
            request["method"] = json!(method);
            assert_eq!(
                call_authenticated(&rpc, &request, &token(byte)).unwrap(),
                json!({"error":"forbidden"})
            );
        }
    }
    let wrong = call(
        &rpc,
        &json!({"method":"walletunlock", "password":"SECRET-INCORRECT", "seconds":60}),
    )
    .unwrap();
    assert!(wrong.get("error").is_some());
    assert!(!wrong.to_string().contains("SECRET-INCORRECT"));
    assert_eq!(status()["locked"], true);
    for seconds in [json!(0), json!(3601), json!("60"), json!(-1)] {
        let mut request = unlock.clone();
        request["seconds"] = seconds;
        assert!(call(&rpc, &request).unwrap().get("error").is_some());
    }
    assert_eq!(call(&rpc, &unlock).unwrap(), json!({"locked":false}));
    assert_eq!(
        call(&rpc, &json!({"method":"balance"})).unwrap()["spendable"],
        "100"
    );
    assert_eq!(
        call(&rpc, &json!({"method":"walletlock"})).unwrap(),
        json!({"locked":true})
    );
    let mut short = unlock.clone();
    short["seconds"] = json!(1);
    assert_eq!(call(&rpc, &short).unwrap(), json!({"locked":false}));
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(status()["locked"], true);
    assert!(
        call_authenticated(&rpc, &json!({"method":"info"}), &token(1))
            .unwrap()
            .get("error")
            .is_none()
    );
    assert!(
        call_authenticated(&rpc, &json!({"method":"address"}), &token(1))
            .unwrap()
            .get("error")
            .is_none()
    );
}

#[test]
fn disabled_spending_cannot_unlock_an_encrypted_wallet() {
    let rpc = start_configured(false, true);
    assert_eq!(
        call(
            &rpc,
            &json!({"method":"walletunlock","password":"RPC wallet test password","seconds":60})
        )
        .unwrap(),
        json!({"error":"unauthorized"})
    );
}

#[test]
fn durable_send_requires_client_id_and_retries_across_lost_and_concurrent_replies() {
    let rpc = start();
    let id = "a1".repeat(32);
    let mut request = json!({"method":"send","to":other_address(),"amount":"10","payment_id":id});
    let missing = json!({"method":"send","to":other_address(),"amount":"10"});
    assert_eq!(
        call_authenticated(&rpc, &missing, &token(2)).unwrap()["error"],
        "invalid_payment_id"
    );
    // Fully enqueue the first request, then abandon its reply.
    request["auth"] = json!("02".repeat(32));
    let mut stream = TcpStream::connect(&*rpc).unwrap();
    writeln!(stream, "{request}").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    drop(stream);
    request.as_object_mut().unwrap().remove("auth");
    let replies = std::thread::scope(|scope| {
        let calls: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| call(&rpc, &request).unwrap()))
            .collect();
        calls
            .into_iter()
            .map(|c| c.join().unwrap())
            .collect::<Vec<_>>()
    });
    for reply in &replies {
        assert_eq!(reply, &replies[0]);
        assert_eq!(reply["state"], "pending");
    }
    assert_eq!(call(&rpc, &json!({"method":"info"})).unwrap()["mempool"], 1);
    let status = json!({"method":"paymentstatus","payment_id":id});
    let receipt = call_authenticated(&rpc, &status, &token(1)).unwrap();
    assert_eq!(receipt["slot_id"], replies[0]["slot_id"]);
    assert_eq!(
        call_authenticated(&rpc, &status, &token(3)).unwrap()["error"],
        "forbidden"
    );
    request["amount"] = json!("11");
    assert_eq!(call(&rpc, &request).unwrap()["code"], "payment_id_conflict");
}
