use super::*;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn binding() -> Binding {
    Binding::new(&crate::state::Config::development([51; 32], 0).unwrap())
}
fn incoming(kind: u8, request: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = frame_header(kind, request, &binding().network, body.len())
        .unwrap()
        .to_vec();
    bytes.extend_from_slice(body);
    bytes
}
#[test]
fn hello_rejects_network_genesis_verifier_role_and_version_changes() {
    let binding = binding();
    let encoded = Hello {
        binding,
        role: Role::Validator,
    }
    .encode();
    assert!(Hello::decode(&encoded, &binding).is_ok());
    for offset in [0, 4, 6, 38, 70, 102] {
        let mut bad = encoded;
        bad[offset] ^= 255;
        assert!(Hello::decode(&bad, &binding).is_err(), "offset {offset}");
    }
}
#[test]
fn oversized_unknown_and_wrong_network_frames_fail_before_body_read() {
    for change in 0..3 {
        let binding = binding();
        let mut raw = frame_header(TRANSACTION, 1, &binding.network, 10).unwrap();
        match change {
            0 => raw[6] = 255,
            1 => raw[15] ^= 1,
            _ => raw[47..51].copy_from_slice(&u32::MAX.to_le_bytes()),
        }
        let mut session =
            Session::from_test_channel(Cursor::new(raw.to_vec()), binding, Budget::default());
        assert!(session.receive().is_err());
        assert_eq!(session.channel.position(), HEADER_BYTES as u64);
    }
}
#[test]
fn frames_are_network_bound_and_preserve_request_identity() {
    let binding = binding();
    let mut session =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    session
        .send_control(TRANSACTION, 71, b"synthetic envelope and sidecar")
        .unwrap();
    let raw = session.channel.into_inner();
    let mut receiver = Session::from_test_channel(Cursor::new(raw), binding, Budget::default());
    match receiver.receive().unwrap() {
        Packet::Control {
            kind,
            request,
            body,
            ..
        } => {
            assert_eq!((kind, request), (TRANSACTION, 71));
            assert_eq!(body, b"synthetic envelope and sidecar");
        }
        _ => panic!("unexpected packet"),
    }
}
#[test]
fn unavailable_stream_is_not_an_invalid_proof() {
    struct Timeout;
    impl Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    impl Write for Timeout {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut session = Session::from_test_channel(Timeout, binding(), Budget::default());
    assert_eq!(session.receive().err(), Some(Error::Unavailable));
}
#[test]
fn retained_packets_hold_shared_budget_until_dropped() {
    let budget = Budget::new(80);
    let raw = incoming(TRANSACTION, 1, b"0123456789abcdef");
    let mut first = Session::from_test_channel(Cursor::new(raw.clone()), binding(), budget.clone());
    let mut second = Session::from_test_channel(Cursor::new(raw), binding(), budget.clone());
    let retained = first.receive().unwrap();
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 80);
    assert_eq!(second.receive().err(), Some(Error::ResourceExhausted));
    assert_eq!(second.channel.position(), HEADER_BYTES as u64);
    drop(retained);
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
    let mut retry = Session::from_test_channel(
        Cursor::new(incoming(TRANSACTION, 2, b"0123456789abcdef")),
        binding(),
        budget,
    );
    assert!(retry.receive().is_ok());
}
#[test]
fn malformed_body_and_transport_errors_release_packet_reservations() {
    let budget = Budget::new(80);
    let raw = frame_header(TRANSACTION, 1, &binding().network, 16)
        .unwrap()
        .to_vec();
    let mut session = Session::from_test_channel(Cursor::new(raw), binding(), budget.clone());
    assert_eq!(session.receive().err(), Some(Error::Unavailable));
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
}
#[test]
fn handshake_slots_are_shared_bounded_and_released() {
    let budget = Budget::default();
    let mut permits = Vec::new();
    for _ in 0..MAX_HANDSHAKES {
        permits.push(budget.handshake().unwrap());
    }
    assert_eq!(
        budget.0.usage.lock().unwrap().handshake_bytes,
        HANDSHAKE_TOTAL_BYTES
    );
    assert!(matches!(budget.handshake(), Err(Error::ResourceExhausted)));
    drop(permits.pop());
    let replacement = budget.handshake().unwrap();
    drop(permits);
    drop(replacement);
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!((usage.handshakes, usage.handshake_bytes), (0, 0));
}
#[test]
fn invalid_local_block_emits_no_frame_header() {
    let binding = binding();
    let mut session =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    let block = Block {
        network: binding.network,
        height: 1,
        parent: binding.genesis,
        timestamp: 1,
        target: [0xff; 32],
        nonce: 0,
        transactions: Vec::new(),
        reward_mode: crate::state::RewardMode::Voyager,
        rewards: vec![crate::wire::RewardRecord {
            commitment: [0; 48],
            ciphertext: [0; crate::wire::REWARD_CIPHERTEXT_BYTES],
        }],
        fund_spends: Vec::new(),
        settlement_proof: vec![1],
    };
    assert_eq!(session.send_block(1, &block), Err(Error::InvalidProtocol));
    assert!(session.channel.into_inner().is_empty());
}
#[test]
fn operation_deadline_covers_header_and_body_without_resetting() {
    struct Advancing {
        data: Cursor<Vec<u8>>,
        clock: Arc<AtomicU64>,
    }
    impl Read for Advancing {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.data.read(bytes)?;
            self.clock.fetch_add(6000, Ordering::Relaxed);
            Ok(count)
        }
    }
    impl Write for Advancing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.data.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let clock = Arc::new(AtomicU64::new(0));
    let channel = Advancing {
        data: Cursor::new(incoming(TRANSACTION, 3, b"body")),
        clock: clock.clone(),
    };
    let mut session = Session::from_test_channel(channel, binding(), Budget::default());
    let deadline = Deadline {
        started: Instant::now(),
        limit: CONTROL_TIMEOUT,
        elapsed: Some(clock),
    };
    assert_eq!(
        session.receive_deadline(deadline).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(session.budget.0.usage.lock().unwrap().bytes, 0);
}
#[test]
fn expired_deadlines_fail_before_touching_the_channel() {
    let clock = Arc::new(AtomicU64::new(10_000));
    let mut session = Session::from_test_channel(
        Cursor::new(incoming(TRANSACTION, 1, b"body")),
        binding(),
        Budget::default(),
    );
    let deadline = Deadline {
        started: Instant::now(),
        limit: CONTROL_TIMEOUT,
        elapsed: Some(clock),
    };
    assert_eq!(
        session.receive_deadline(deadline).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(session.channel.position(), 0);
}

struct TestOnly {
    authentications: Arc<AtomicUsize>,
}
impl HybridAuthenticator for TestOnly {
    type Channel = TcpStream;
    fn authenticate(
        &mut self,
        socket: TcpStream,
        binding: &Binding,
        deadline: Instant,
    ) -> Result<Authenticated<Self::Channel>, Error> {
        assert!(Instant::now() < deadline);
        self.authentications.fetch_add(1, Ordering::Relaxed);
        // Socket fixtures exercise protocol integration, never hybrid security.
        Ok(Authenticated::from_verified_provider(
            socket, *binding, [9; 32],
        ))
    }
}
#[test]
fn tcp_listener_and_disconnect_reconnect_use_a_fresh_authentication() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let binding = binding();
    let server_count = Arc::new(AtomicUsize::new(0));
    let client_count = Arc::new(AtomicUsize::new(0));
    let observed_server = server_count.clone();
    let server = std::thread::spawn(move || {
        let mut auth = TestOnly {
            authentications: server_count,
        };
        let budget = Budget::default();
        for expected in [18, 19] {
            let mut session = accept_once(
                &listener,
                &mut auth,
                binding,
                Role::Validator,
                budget.clone(),
            )
            .unwrap();
            match session.receive().unwrap() {
                Packet::Control {
                    kind,
                    request,
                    body,
                    ..
                } => {
                    assert_eq!((kind, request), (GET_BLOCKS, expected));
                    session.send_control(UNAVAILABLE, request, &body).unwrap();
                }
                _ => panic!("unexpected packet"),
            }
        }
    });
    let mut auth = TestOnly {
        authentications: client_count.clone(),
    };
    let budget = Budget::default();
    for request in [18, 19] {
        let mut client = connect(
            endpoint,
            &mut auth,
            binding,
            Role::Validator,
            budget.clone(),
        )
        .unwrap();
        client
            .send_control(GET_BLOCKS, request, b"locator")
            .unwrap();
        assert!(
            matches!(client.receive().unwrap(), Packet::Control { kind: UNAVAILABLE, request: actual, .. } if actual == request)
        );
        assert_eq!(client.receive().err(), Some(Error::Unavailable));
        // A failed stream is discarded; the next iteration reconnects and
        // authenticates a fresh session instead of reusing partial framing.
    }
    server.join().unwrap();
    assert_eq!(client_count.load(Ordering::Relaxed), 2);
    assert_eq!(observed_server.load(Ordering::Relaxed), 2);
}

#[test]
fn streamed_block_roundtrip_retains_the_shared_reservation() {
    let config = Config::development([51; 32], 0).unwrap();
    let state = crate::state::State::new(config).unwrap();
    let expected = crate::fixtures::candidate(&state, 1);
    let binding = binding();
    let mut sender =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    sender.send_block(27, &expected).unwrap();
    let budget = Budget::default();
    let mut receiver = Session::from_test_channel(
        Cursor::new(sender.channel.into_inner()),
        binding,
        budget.clone(),
    );
    let packet = receiver.receive().unwrap();
    match &packet {
        Packet::Block { request, block, .. } => {
            assert_eq!(*request, 27);
            assert_eq!(block.as_ref(), &expected);
        }
        _ => panic!("unexpected control packet"),
    }
    assert!(budget.0.usage.lock().unwrap().bytes > expected.encoded_len().unwrap());
    drop(packet);
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
}

#[test]
fn failed_capability_checks_release_the_handshake_gate() {
    let binding = binding();
    let budget = Budget::default();
    let auth =
        Authenticated::from_verified_provider(Cursor::new(Vec::<u8>::new()), binding, [0; 32]);
    assert!(matches!(
        Session::establish(auth, binding, Role::Validator, budget.clone()),
        Err(Error::InvalidProtocol)
    ));
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!((usage.handshakes, usage.handshake_bytes), (0, 0));
}

#[test]
fn reserved_block_send_uses_the_existing_guard_without_double_charging() {
    let state = crate::state::State::new(Config::development([51; 32], 0).unwrap()).unwrap();
    let block = crate::fixtures::candidate(&state, 1);
    let bytes = block.encoded_len().unwrap() + 65536;
    let budget = Budget::new(bytes);
    let reservation = budget.reserve(bytes).unwrap();
    let mut sender = Session::from_test_channel(Cursor::new(Vec::new()), binding(), budget.clone());
    sender.send_reserved_block(9, &block, &reservation).unwrap();
    assert_eq!(budget.available().unwrap(), 0);
    assert_eq!(
        sender.channel.into_inner().len(),
        HEADER_BYTES + block.encoded_len().unwrap()
    );
    drop(reservation);
    assert_eq!(budget.available().unwrap(), bytes);
}

#[test]
fn reserved_block_send_rejects_foreign_or_small_guards_before_output() {
    let state = crate::state::State::new(Config::development([51; 32], 0).unwrap()).unwrap();
    let block = crate::fixtures::candidate(&state, 1);
    let bytes = block.encoded_len().unwrap() + 65536;
    let budget = Budget::new(bytes);
    let foreign_budget = Budget::new(bytes);
    let foreign = foreign_budget.reserve(bytes).unwrap();
    let mut sender = Session::from_test_channel(Cursor::new(Vec::new()), binding(), budget.clone());
    assert_eq!(
        sender.send_reserved_block(9, &block, &foreign),
        Err(Error::InvalidProtocol)
    );
    assert!(sender.channel.get_ref().is_empty());
    let small = budget.reserve(bytes - 1).unwrap();
    assert_eq!(
        sender.send_reserved_block(9, &block, &small),
        Err(Error::ResourceExhausted)
    );
    assert!(sender.channel.into_inner().is_empty());
}
