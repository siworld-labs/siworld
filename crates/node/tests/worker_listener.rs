use std::{net::SocketAddr, time::Duration};

use siworld_node::{
    miner_protocol::{ExpectedPeer, Handshake, WorkerRole, PROTOCOL_NAME, PROTOCOL_VERSION},
    worker_transport::{RetryPolicy, WorkerClient, WorkerConfig, WorkerListener, WorkerToken},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn token() -> WorkerToken {
    WorkerToken::from_bytes([7; 32])
}
fn offered() -> Handshake {
    Handshake {
        protocol: PROTOCOL_NAME.into(),
        version: PROTOCOL_VERSION,
        role: WorkerRole::ProofWorker,
        trusted_machine: true,
        token_digest: token().digest(),
        certificate_fingerprint: [8; 32],
        container_size: 16,
    }
}
fn config(address: SocketAddr) -> WorkerConfig {
    WorkerConfig {
        listen: address,
        expected: ExpectedPeer {
            role: WorkerRole::ProofWorker,
            token_digest: token().digest(),
            certificate_fingerprint: [8; 32],
            container_size: 16,
        },
        token: token(),
        max_connections: 1,
        io_timeout: Duration::from_millis(200),
    }
}
fn client(address: SocketAddr, hello: Handshake, secret: WorkerToken) -> WorkerClient {
    WorkerClient::new(
        address,
        hello,
        secret,
        RetryPolicy {
            attempts: 3,
            delay: Duration::from_millis(10),
            io_timeout: Duration::from_millis(200),
        },
    )
    .unwrap()
}
async fn listener() -> WorkerListener {
    WorkerListener::bind(config("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap()
}

#[tokio::test]
async fn authenticates_and_reuses_a_bounded_control_connection() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.serve());
    let mut client = client(address, offered(), token());
    client.heartbeat().await.unwrap();
    client.heartbeat().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn shape_and_credential_errors_stop_retrying_and_listener_survives() {
    for change in 0..8 {
        let listener = std::sync::Arc::new(listener().await);
        let address = listener.local_addr().unwrap();
        let accepting = listener.clone();
        let accept = tokio::spawn(async move {
            assert!(accepting.accept().await.is_err());
            assert_eq!(accepting.available_connections(), 1);
            // A deterministic failure must not cause a second connection.
            assert!(
                tokio::time::timeout(Duration::from_millis(60), accepting.accept())
                    .await
                    .is_err()
            );
            assert_eq!(accepting.available_connections(), 1);
        });
        let mut hello = offered();
        let mut secret = token();
        match change {
            0 => hello.protocol = "other".into(),
            1 => hello.version += 1,
            2 => hello.role = WorkerRole::Miner,
            3 => hello.trusted_machine = false,
            4 => hello.token_digest = [99; 32],
            5 => hello.certificate_fingerprint = [99; 32],
            6 => hello.container_size *= 2,
            _ => secret = WorkerToken::from_bytes([99; 32]),
        }
        let mut invalid_client = client(address, hello, secret);
        let error = invalid_client.heartbeat().await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            invalid_client.heartbeat().await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        accept.await.unwrap();
        let listener = std::sync::Arc::try_unwrap(listener).ok().unwrap();
        let server = tokio::spawn(listener.serve());
        client(address, offered(), token())
            .heartbeat()
            .await
            .unwrap();
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn reconnects_automatically_after_live_connection_is_closed() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.serve());
    let mut client = client(address, offered(), token());
    client.heartbeat().await.unwrap();
    server.abort();
    let _ = server.await;
    let replacement = WorkerListener::bind(config(address)).await.unwrap();
    let server = tokio::spawn(replacement.serve());
    client.heartbeat().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn timeout_and_oversized_frame_release_connection_reservations() {
    let listener = std::sync::Arc::new(listener().await);
    let address = listener.local_addr().unwrap();
    for oversized in [false, true] {
        let accepting = listener.clone();
        let accept = tokio::spawn(async move {
            let result = accepting.accept().await;
            let error = match result {
                Ok(_) => panic!("malformed handshake accepted"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                if oversized {
                    std::io::ErrorKind::InvalidData
                } else {
                    std::io::ErrorKind::TimedOut
                }
            );
            assert_eq!(accepting.available_connections(), 1);
        });
        let mut raw = tokio::net::TcpStream::connect(address).await.unwrap();
        let n = raw.read_u32_le().await.unwrap() as usize;
        let mut challenge = vec![0; n];
        raw.read_exact(&mut challenge).await.unwrap();
        if oversized {
            raw.write_u32_le(4097).await.unwrap();
        }
        accept.await.unwrap();
    }
}

#[tokio::test]
async fn refused_connection_retries_until_listener_is_ready() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(15)).await;
        WorkerListener::bind(config(address))
            .await
            .unwrap()
            .serve()
            .await;
    });
    client(address, offered(), token())
        .heartbeat()
        .await
        .unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn nonlocal_addresses_and_excess_limits_fail_before_binding() {
    let mut c = config("0.0.0.0:0".parse().unwrap());
    assert!(WorkerListener::bind(c).await.is_err());
    c = config("127.0.0.1:0".parse().unwrap());
    c.max_connections = 9;
    assert!(WorkerListener::bind(c).await.is_err());
    assert!(WorkerClient::new(
        "192.0.2.1:1234".parse().unwrap(),
        offered(),
        token(),
        RetryPolicy::default()
    )
    .is_err());
}

#[tokio::test]
async fn node_service_owns_listener_and_closes_active_sessions_on_shutdown() {
    use siworld_circuits::MockProver;
    use siworld_core::Digest;
    use siworld_crypto::{SecretSeed, SpendKey};
    use siworld_node::{
        genesis::{Genesis, GenesisFile, ProofsFile},
        node::Node,
        service::{run, Config},
    };
    let genesis = Genesis::from_file(&GenesisFile {
        network: "worker-listener-test".into(),
        timestamp: 1,
        block_time: 60,
        pow_iterations: 1000,
        target: "ff".repeat(32),
        container_size: 16,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![],
    })
    .unwrap();
    let node = Node::open(
        genesis,
        SpendKey::from_digest(Digest([23; 32])),
        SecretSeed::from_os_rng().unwrap(),
        None,
        std::sync::Arc::new(MockProver),
    )
    .unwrap();
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let service = run(
        node,
        Config {
            listen: vec![],
            peers: vec![],
            rpc: None,
            mine: false,
            worker: Some(config(address)),
        },
        async {
            let _ = stopped.await;
        },
    );
    let control = async {
        let mut client = client(address, offered(), token());
        client.heartbeat().await.unwrap();
        stop.send(()).unwrap();
        client
    };
    let (result, mut client) = tokio::join!(service, control);
    result.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(client.heartbeat().await.is_err());
}

#[tokio::test]
async fn stalled_server_handshake_times_out_then_reauthenticates() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = probe.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stalled, _) = probe.accept().await.unwrap();
        // With no challenge, the client can only close after its deadline.
        // Observe that close before handing the address to the real listener.
        let mut unexpected = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), stalled.read(&mut unexpected))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(stalled);
        drop(probe);
        let mut ready = config(address);
        ready.io_timeout = Duration::from_secs(1);
        WorkerListener::bind(ready).await.unwrap().serve().await;
    });
    let mut client = WorkerClient::new(
        address,
        offered(),
        token(),
        RetryPolicy {
            attempts: 4,
            delay: Duration::from_millis(10),
            io_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), client.heartbeat())
        .await
        .unwrap()
        .unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn active_connection_limit_is_held_until_disconnect() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.serve());
    let mut first = client(address, offered(), token());
    first.heartbeat().await.unwrap();
    let mut second = WorkerClient::new(
        address,
        offered(),
        token(),
        RetryPolicy {
            attempts: 1,
            delay: Duration::ZERO,
            io_timeout: Duration::from_millis(40),
        },
    )
    .unwrap();
    assert_eq!(
        second.heartbeat().await.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    drop(first);
    drop(second);
    client(address, offered(), token())
        .heartbeat()
        .await
        .unwrap();
    server.abort();
    let _ = server.await;
}
