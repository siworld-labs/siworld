//! Socket and owner-lifecycle tests use the synthetic block verifier only to
//! isolate networking. Cryptographic transport and both identity signatures
//! are real; these tests do not qualify transaction or settlement proofs.
use super::*;
use crate::chain::CandidatePolicy;
use crate::fixtures::{TestVerifier, candidate};
use crate::state::Config;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-resident-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        local::initialize_config(&path, configuration()).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn configuration() -> Config {
    Config::development([209; 32], 0).unwrap()
}
fn expected(identity: &NativeIdentity) -> ExpectedPeer {
    let binding = p2p::Binding::new(&configuration());
    let descriptor = identity.descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding).unwrap();
    ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin).unwrap()
}
struct Endpoint {
    driver: Driver,
    node: Option<Node<TestVerifier>>,
    directory: Directory,
}
impl Endpoint {
    fn new() -> Self {
        let directory = Directory::new();
        let node = Node::new(
            Store::open(
                directory.0.join("chain.redb"),
                configuration(),
                &TestVerifier,
            )
            .unwrap(),
            TestVerifier,
        );
        let identity = Arc::new(
            NativeIdentity::initialize(&directory.0, p2p::Binding::new(&configuration())).unwrap(),
        );
        let config = Configuration {
            listen: (Ipv4Addr::LOCALHOST, 0).into(),
            mining: false,
            peers: Arc::new(BTreeMap::new()),
            digest: "0".repeat(64),
        };
        let driver = Driver::new(identity, config, node.transport_budget()).unwrap();
        Self {
            driver,
            node: Some(node),
            directory,
        }
    }
    fn address(&self) -> SocketAddr {
        self.driver.listener.local_addr().unwrap()
    }
    fn follow(&mut self, other: &Self) {
        let peer = expected(&other.driver.identity);
        self.driver.peers = Arc::new(BTreeMap::from([(
            peer.fingerprint(),
            Peer {
                endpoint: other.address(),
                expected: peer,
            },
        )]));
        self.driver.scheduler = Scheduler::new(
            self.driver.local,
            &self.driver.peers.keys().copied().collect::<Vec<_>>(),
            self.driver.budget.clone(),
            self.driver.now(),
        )
        .unwrap();
    }
    fn tick(&mut self) {
        self.driver.poll().unwrap();
        for _ in 0..COMMAND_SLOTS {
            match self.driver.rx.try_recv() {
                Ok(command) => self
                    .driver
                    .handle(self.node.as_mut().unwrap(), command)
                    .unwrap(),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("owner queue unexpectedly disconnected")
                }
            }
        }
    }
    fn append(&mut self, seed: u32) {
        let node = self.node.as_mut().unwrap();
        let block = candidate(node.state(), seed);
        node.import_branch(node.state().height, &[block], CandidatePolicy::default())
            .unwrap();
    }
    fn state(&self) -> &State {
        self.node.as_ref().unwrap().state()
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.driver.shutdown();
    }
}
fn until(
    a: &mut Endpoint,
    b: &mut Endpoint,
    mut condition: impl FnMut(&Endpoint, &Endpoint) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !condition(a, b) {
        assert!(
            Instant::now() < deadline,
            "resident loopback gate exceeded its bounded wait"
        );
        a.tick();
        b.tick();
        std::thread::sleep(POLL);
    }
}
fn connect_pair(a: &mut Endpoint, b: &mut Endpoint) {
    a.follow(b);
    b.follow(a);
    until(a, b, |a, b| {
        a.driver.scheduler.status().established == 1 && b.driver.scheduler.status().established == 1
    });
}

#[test]
fn actual_resident_tls_listeners_sync_and_restart_from_the_same_persisted_state() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::new();
    source.append(100_000);
    source.append(200_000);
    connect_pair(&mut source, &mut target);
    until(&mut source, &mut target, |a, b| {
        b.state().height == 2 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(source.driver.connections >= 1 && target.driver.connections >= 1);
    assert!(
        source.driver.workers.len() <= MAX_WORKERS && target.driver.workers.len() <= MAX_WORKERS
    );
    let fingerprint = target.state().fingerprint();
    let tip = target.state().tip;
    source.driver.shutdown().unwrap();
    target.driver.shutdown().unwrap();
    drop(target.node.take());
    let restored = Store::open_existing(
        target.directory.0.join("chain.redb"),
        configuration(),
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(restored.state().height, 2);
    assert_eq!(restored.state().tip, tip);
    assert_eq!(restored.state().fingerprint(), fingerprint);
}

#[test]
fn resident_disconnect_reconnects_with_fresh_authentication_and_continues_sync() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::new();
    connect_pair(&mut source, &mut target);
    let connections = (source.driver.connections, target.driver.connections);
    for worker in source.driver.workers.values() {
        worker.cancel.cancel();
    }
    for worker in target.driver.workers.values() {
        worker.cancel.cancel();
    }
    source.append(300_000);
    until(&mut source, &mut target, |a, b| {
        a.driver.connections > connections.0
            && b.driver.connections > connections.1
            && b.state().height == 1
            && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(source.driver.failures >= 1 && target.driver.failures >= 1);
    assert_eq!(source.driver.scheduler.status().established, 1);
    assert_eq!(target.driver.scheduler.status().established, 1);
}

#[test]
fn unauthenticated_slow_socket_never_holds_the_consensus_owner_or_peer_identity() {
    let mut node = Endpoint::new();
    let mut socket = TcpStream::connect(node.address()).unwrap();
    socket.write_all(ROUTE_MAGIC).unwrap();
    node.tick();
    assert_eq!(node.driver.workers.len(), 1);
    assert_eq!(node.driver.connections, 0);
    assert_eq!(node.driver.scheduler.status().pending, 0);
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    // Only the owner touches the canonical store while socket admission waits.
    let started = Instant::now();
    node.append(400_000);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(node.state().height, 1);
    assert_eq!(node.driver.connections, 0);
    node.driver.shutdown().unwrap();
    assert!(node.driver.workers.is_empty());
    drop(socket);
}

#[test]
fn forged_routing_hint_cannot_penalize_or_establish_a_configured_identity() {
    let mut node = Endpoint::new();
    let peer = Endpoint::new();
    node.follow(&peer);
    let peer_id = peer.driver.local;
    // Suppress local dialing while exercising unauthenticated ingress. A routing
    // hint must not override this trusted local scheduling choice.
    node.driver
        .scheduler
        .disable(peer_id, node.driver.now())
        .unwrap();
    let mut socket = TcpStream::connect(node.address()).unwrap();
    let mut route = [0; 36];
    route[..4].copy_from_slice(ROUTE_MAGIC);
    route[4..].copy_from_slice(&peer_id);
    socket.write_all(&route).unwrap();
    node.tick();
    for _ in 0..4 {
        node.tick();
        std::thread::sleep(POLL);
    }
    assert_eq!(node.driver.connections, 0);
    let status = node.driver.scheduler.status();
    assert_eq!(
        (
            status.disabled,
            status.pending,
            status.established,
            status.closing
        ),
        (1, 0, 0, 0)
    );
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    drop(socket);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !node.driver.workers.is_empty() {
        assert!(Instant::now() < deadline);
        node.tick();
        std::thread::sleep(POLL);
    }
    assert_eq!(node.driver.scheduler.status().disabled, 1);
}

#[test]
fn bounded_owner_command_wait_is_cancelled_without_needing_a_socket_response() {
    let budget = Budget::default();
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    let inspected_budget = budget.clone();
    let (tx, receive) = mpsc::sync_channel(COMMAND_SLOTS);
    let thread = std::thread::spawn(move || {
        let started = Instant::now();
        let result: Result<Vec<u8>, runtime::Error> = call(&tx, &budget, &cancellation, |reply| {
            Command::Pull { id: 1, reply }
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    });
    let queued = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    signal.cancel();
    thread.join().unwrap();
    assert!(inspected_budget.available().unwrap() < p2p::CONNECTION_BYTES);
    drop(queued);
    assert_eq!(inspected_budget.available().unwrap(), p2p::CONNECTION_BYTES);
}

#[test]
fn unpinned_configuration_is_rejected_even_with_a_valid_signed_descriptor() {
    let node = Endpoint::new();
    let peer = Endpoint::new();
    let descriptor = peer.driver.identity.descriptor().unwrap();
    let file = node.directory.0.join("peers.json");
    let value = json!({
        "version":1,"engineering":true,"listen":"127.0.0.1:0","mining":false,
        "peers":[{"endpoint":peer.address().to_string(),"fingerprint":local::hex(&descriptor.fingerprint()),"descriptor":local::hex(&descriptor.encode())}]
    });
    write_once(&file, &value).unwrap();
    assert!(
        Configuration::load(
            &node.directory.0,
            &file,
            p2p::Binding::new(&configuration()),
            node.driver.local
        )
        .is_err()
    );
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &p2p::Binding::new(&configuration()))
        .unwrap();
    pin.persist(&node.directory.0).unwrap();
    let accepted = Configuration::load(
        &node.directory.0,
        &file,
        p2p::Binding::new(&configuration()),
        node.driver.local,
    )
    .unwrap();
    assert_eq!(accepted.peers.len(), 1);
    assert_eq!(
        accepted.peers.keys().copied().collect::<Vec<_>>(),
        vec![descriptor.fingerprint()]
    );
}

#[test]
fn public_resident_status_contains_only_aggregate_connection_health() {
    let mut node = Endpoint::new();
    let peer = Endpoint::new();
    node.follow(&peer);
    let status = node.driver.status(false);
    let object = status.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "authenticated_connections",
            "closed_connections",
            "closing",
            "configured",
            "connected",
            "disabled",
            "mining",
            "pending",
            "workers",
        ]
    );
    assert_eq!(status["configured"], 1);
    assert_eq!(status["connected"], 0);
    assert_eq!(status["mining"], false);
    let encoded = serde_json::to_string(&status).unwrap();
    assert!(!encoded.contains(&peer.address().to_string()));
    assert!(!encoded.contains(&local::hex(&peer.driver.local)));
    assert!(!encoded.contains("fee") && !encoded.contains("nullifier"));
}

#[test]
fn sixteenth_stalled_inbound_is_charged_and_seventeenth_is_closed_without_a_worker() {
    let mut node = Endpoint::new();
    let baseline = node.driver.budget.available().unwrap();
    let mut sockets: Vec<_> = (0..MAX_WORKERS + 1)
        .map(|_| TcpStream::connect(node.address()).unwrap())
        .collect();
    for _ in 0..5 {
        node.tick();
    }
    assert_eq!(node.driver.workers.len(), MAX_WORKERS);
    assert_eq!(node.driver.status(false)["workers"], MAX_WORKERS);
    assert_eq!(node.driver.connections, 0);
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    let charged = baseline - node.driver.budget.available().unwrap();
    assert_eq!(charged, MAX_WORKERS * WORKER_STACK);
    let mut excess = sockets.pop().unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0];
    match excess.read(&mut byte) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        _ => panic!("excess inbound socket remained open"),
    }
    let started = Instant::now();
    node.driver.shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(node.driver.workers.is_empty());
    assert_eq!(node.driver.budget.available().unwrap(), baseline);
    assert_eq!(node.driver.scheduler.status().pending, 0);
    assert_eq!(node.driver.scheduler.status().established, 0);
    drop(sockets);
}

#[test]
fn cancelled_queued_apply_cannot_import_after_the_caller_has_left() {
    let mut owner = Endpoint::new();
    let peer = Endpoint::new();
    owner.follow(&peer);
    let budget = owner.driver.budget.clone();
    let baseline = budget.available().unwrap();
    let peer_id = peer.driver.local;
    let token = owner
        .driver
        .scheduler
        .begin(peer_id, Direction::Outbound, owner.driver.now())
        .unwrap()
        .token;
    owner
        .driver
        .scheduler
        .authenticated(token, owner.driver.now())
        .unwrap();
    let cancel = Cancellation::default();
    let worker_cancel = cancel.clone();
    let join = std::thread::spawn(move || {
        while !worker_cancel.is_cancelled() {
            std::thread::sleep(POLL);
        }
        Failure::Unavailable
    });
    let id = 1;
    owner.driver.workers.insert(
        id,
        Worker {
            peer: Some(peer_id),
            token: Some(token),
            cancel: cancel.clone(),
            join,
            sync: SyncAttempt::default(),
            _reservation: budget.reserve(WORKER_STACK).unwrap(),
        },
    );
    let base = owner.state().tip_snapshot().selector;
    let (begin_send, begin_receive) = mpsc::sync_channel(1);
    owner
        .driver
        .handle(
            owner.node.as_mut().unwrap(),
            ChargedCommand {
                command: Command::Begin {
                    id,
                    meta: ReplyMeta {
                        ancestor: base,
                        after: base,
                        count: 1,
                        more: false,
                    },
                    reply: begin_send,
                },
                _reservation: budget.reserve(COMMAND_BYTES).unwrap(),
            },
        )
        .unwrap();
    begin_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let block = candidate(owner.state(), 500_000);
    let guard = budget
        .reserve(block.encoded_len().unwrap() + crate::wire::MAX_ENVELOPE_BYTES + 65536)
        .unwrap();
    let batch = Batch {
        ancestor: base,
        after: base,
        blocks: vec![block],
        more: false,
    };
    let tx = owner.driver.tx.clone();
    let waiter_cancel = cancel.clone();
    let waiter_budget = budget.clone();
    let waiter = std::thread::spawn(move || {
        let result: Result<bool, runtime::Error> =
            call(&tx, &waiter_budget, &waiter_cancel, |reply| {
                Command::Apply {
                    id,
                    batch,
                    guards: vec![guard],
                    reply,
                }
            });
        assert!(result.is_err());
    });
    let queued = owner
        .driver
        .rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let before = (
        owner.state().height,
        owner.state().tip,
        owner.state().fingerprint(),
    );
    cancel.cancel();
    waiter.join().unwrap();
    owner
        .driver
        .handle(owner.node.as_mut().unwrap(), queued)
        .unwrap();
    assert_eq!(
        (
            owner.state().height,
            owner.state().tip,
            owner.state().fingerprint()
        ),
        before
    );
    owner.driver.shutdown().unwrap();
    assert_eq!(budget.available().unwrap(), baseline);
}

#[test]
fn configuration_rejects_unknown_fields_missing_keys_and_implicit_engineering_mode() {
    let node = Endpoint::new();
    let binding = p2p::Binding::new(&configuration());
    let valid =
        json!({"version":1,"engineering":true,"listen":"127.0.0.1:0","mining":false,"peers":[]});
    let mut variants = Vec::new();
    let mut extra = valid.clone();
    extra["unknown"] = json!(true);
    variants.push(extra);
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("mining");
    variants.push(missing);
    let mut renamed = valid.clone();
    renamed.as_object_mut().unwrap().remove("mining");
    renamed["mine"] = json!(false);
    variants.push(renamed);
    let mut implicit = valid.clone();
    implicit["engineering"] = json!(false);
    variants.push(implicit);
    let mut invalid_peers = valid.clone();
    invalid_peers["peers"] = json!({});
    variants.push(invalid_peers);
    let mut invalid_bool = valid;
    invalid_bool["mining"] = json!(0);
    variants.push(invalid_bool);
    for (index, value) in variants.into_iter().enumerate() {
        let path = node.directory.0.join(format!("invalid-peers-{index}.json"));
        write_once(&path, &value).unwrap();
        assert!(Configuration::load(&node.directory.0, &path, binding, node.driver.local).is_err());
    }
}

#[test]
fn smaller_pinned_identity_alone_dials_and_both_sync_directions_survive_reconnect() {
    let mut smaller = Endpoint::new();
    let mut larger = Endpoint::new();
    if smaller.driver.local > larger.driver.local {
        std::mem::swap(&mut smaller, &mut larger);
    }
    smaller.follow(&larger);
    larger.follow(&smaller);
    larger.append(600_000);
    larger.tick();
    assert!(larger.driver.workers.is_empty());
    smaller.tick();
    assert_eq!(smaller.driver.workers.len(), 1);
    assert!(
        smaller
            .driver
            .workers
            .values()
            .all(|worker| worker.peer == Some(larger.driver.local) && worker.token.is_some())
    );
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.scheduler.status().established == 1
            && b.driver.scheduler.status().established == 1
            && a.state().height == 1
            && a.state().fingerprint() == b.state().fingerprint()
    });
    let connections = (smaller.driver.connections, larger.driver.connections);
    for worker in smaller.driver.workers.values() {
        worker.cancel.cancel();
    }
    for worker in larger.driver.workers.values() {
        worker.cancel.cancel();
    }
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.workers.is_empty() && b.driver.workers.is_empty()
    });
    // The other direction becomes the source after reconnect. Both configured
    // endpoint roles must still synchronize, although only one side dials.
    smaller.append(700_000);
    let ready = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < ready {
        larger.tick();
        assert!(larger.driver.workers.is_empty());
        std::thread::sleep(POLL);
    }
    smaller.tick();
    assert_eq!(smaller.driver.workers.len(), 1);
    assert!(
        smaller
            .driver
            .workers
            .values()
            .all(|worker| worker.peer == Some(larger.driver.local) && worker.token.is_some())
    );
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.connections > connections.0
            && b.driver.connections > connections.1
            && b.state().height == 2
            && a.state().fingerprint() == b.state().fingerprint()
    });
    assert_eq!(smaller.driver.scheduler.status().established, 1);
    assert_eq!(larger.driver.scheduler.status().established, 1);
}

#[test]
fn two_producer_jobs_cannot_starve_maximum_block_peer_admission() {
    let producer = Budget::new(PRODUCER_TOTAL_BYTES);
    let peer = Budget::default();
    let baseline = peer.available().unwrap();
    let proving = producer.reserve(PRODUCER_JOB_BYTES).unwrap();
    let mining = producer.reserve(PRODUCER_JOB_BYTES).unwrap();
    assert_eq!(producer.available().unwrap(), 0);
    assert!(matches!(
        producer.reserve(PRODUCER_JOB_BYTES),
        Err(p2p::Error::ResourceExhausted)
    ));
    assert_eq!(peer.available().unwrap(), baseline);
    let imported = peer
        .reserve(crate::wire::MAX_BLOCK_BYTES + crate::wire::MAX_ENVELOPE_BYTES + 65536)
        .unwrap();
    assert!(peer.available().unwrap() < baseline);
    drop((proving, mining));
    assert_eq!(producer.available().unwrap(), PRODUCER_TOTAL_BYTES);
    drop(imported);
    assert_eq!(peer.available().unwrap(), baseline);
}
