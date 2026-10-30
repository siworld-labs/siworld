//! Opt-in complete native-proof chain test, with no synthetic funding prefix.
//! Block timestamps advance at target spacing; this is not a wall-clock soak.
use super::*;
use crate::pool::Padding;
use crate::producer::{MiningSettings, assemble, prepare_padding, validate_reward_secret};
use crate::proofs::{NativeProver, NativeVerifier};
use crate::runtime::Node;
use crate::state::{RewardMode, State};
use crate::store::Store;
use crate::wallet::FeeTier;
use crate::wire::Block;
use native::multi_asset::SIP_ASSET_ID;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const PASSWORD: &str = "isolated native wallet test passphrase";
const SLOTS: usize = 64;
const LAST_FUNDING_HEIGHT: u64 = 25;

fn check_deadline(start: Instant) {
    assert!(
        start.elapsed() < Duration::from_secs(4 * 60 * 60),
        "native wallet roundtrip deadline exceeded"
    );
}

fn new_run_directory() -> PathBuf {
    let parent = std::env::var_os("SIWORLD_NATIVE_WALLET_RUN_ROOT")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .canonicalize()
        .unwrap();
    let mut suffix = [0; 16];
    getrandom::fill(&mut suffix).unwrap();
    let path = parent.join(format!(
        "native-wallet-roundtrip-{}",
        crate::local::hex(&suffix)
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path).unwrap();
    // Preserve all test directories on success or failure for independent
    // replay. The operator owns subsequent evidence review and cleanup.
    path
}

fn backed_up_wallet(path: &Path, network: Hash) -> (UnlockedWallet, RecoveryWords) {
    let pending = PendingWallet::generate(network, 0).unwrap();
    let words = pending.recovery_words();
    let parts: Vec<_> = words.expose().split(' ').collect();
    let challenge = pending.backup_challenge();
    let confirmed = pending
        .confirm_backup(challenge.map(|index| parts[index - 1]))
        .unwrap();
    (confirmed.create(path, PASSWORD).unwrap(), words)
}

fn canonical_blocks(store: &Store) -> Vec<Block> {
    (1..=store.state().height)
        .map(|height| store.block(height).unwrap())
        .collect()
}

fn fill_positions(
    state: &State,
    prover: &NativeProver,
    mut positions: Vec<Padding>,
    start: Instant,
) -> Vec<Padding> {
    while positions.len() < SLOTS {
        check_deadline(start);
        positions.push(prepare_padding(state, prover).unwrap());
    }
    positions
}

fn mine_and_accept(
    node: &mut Node<NativeVerifier>,
    receipt_directory: &Path,
    prover: &NativeProver,
    positions: Vec<Padding>,
    settings: &MiningSettings,
    identities: &mut BTreeSet<Hash>,
    start: Instant,
) {
    check_deadline(start);
    let permit = node.begin_production().unwrap();
    let timestamp = node
        .state()
        .timestamp()
        .checked_add(crate::state::TARGET_INTERVAL)
        .unwrap();
    let mut produced = assemble(node.state(), prover, positions, timestamp, settings).unwrap();
    let seed = produced.block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(
            &seed,
            produced.block.nonce,
            node.state().config.pow_iterations,
        ),
        &produced.block.target,
    ) {
        check_deadline(start);
        produced.block.nonce = produced.block.nonce.checked_add(1).unwrap();
    }
    validate_reward_secret(&produced.block, &produced.reward_secret).unwrap();
    assert_eq!(produced.block.transactions.len(), SLOTS);
    for tx in &produced.block.transactions {
        assert!(identities.insert(tx.record.statement_id(&produced.block.network)));
    }
    let id = produced.block.id().unwrap();
    // The deployment owner binds the worker result, preserves its authenticated
    // receipt, then executes the same durable verified transition for all blocks.
    let prepared = node.bind_produced(permit, produced).unwrap();
    assert_eq!(node.commit_produced(prepared).unwrap(), id);
    let stored = node.store().block(node.state().height).unwrap();
    let receipt = crate::local::read_reward(receipt_directory, &id).unwrap();
    validate_reward_secret(&stored, &receipt).unwrap();
    check_deadline(start);
}

fn progress(directory: &Path, store: &Store, stage: &str, start: Instant) {
    crate::service::atomic_json(
        &directory.join("roundtrip-progress.json"),
        &serde_json::json!({
            "schema":1, "stage":stage, "accepted_height":store.state().height,
            "required_height":26, "slots_per_block":SLOTS,
            "elapsed_ms":u64::try_from(start.elapsed().as_millis()).unwrap(),
            "commit_path":"native-node-owned-durable-receipt",
            "validated_reward_receipts":store.state().height,
        }),
    )
    .unwrap();
}

#[test]
#[ignore = "opt-in complete 26-block native genesis-funded wallet persistence roundtrip"]
fn genuine_genesis_rewards_persist_pay_and_restore_with_native_proofs() {
    assert_eq!(
        std::env::var("SIWORLD_RUN_NATIVE_WALLET_ROUNDTRIP").as_deref(),
        Ok("1"),
        "this slow test requires explicit native-wallet roundtrip opt-in"
    );
    let start = Instant::now();
    let directory = new_run_directory();
    let config =
        crate::local::initialize_asert(&directory.join("chain"), 1, [0xff; 32], 1).unwrap();
    assert!(!config.fixture);
    assert_eq!(
        config.economics,
        siworld_core::v1_economics::EconomicsParams::production()
    );
    assert_eq!(config.economics.maturity, 24);
    assert_eq!(config.target_interval, 300);
    assert_eq!(config.fund_verifying_keys.len(), 24);
    let network = config.network;
    let (sender_vault, sender_words) = backed_up_wallet(&directory.join("sender"), network);
    let (receiver_vault, receiver_words) = backed_up_wallet(&directory.join("receiver"), network);
    let recipient = receiver_vault.keys().unwrap().address();
    let settings = MiningSettings {
        mode: RewardMode::Voyager,
        recipient: sender_vault.keys().unwrap().address(),
    };
    crate::mining::save(&directory, network, &settings).unwrap();
    let settings = crate::mining::load(&directory, network).unwrap();
    let prover = NativeProver::new().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let database = directory.join("chain").join("chain.redb");
    let mut node = Node::new(
        Store::open(&database, config.clone(), &verifier).unwrap(),
        NativeVerifier::new().unwrap(),
    );
    assert_eq!(node.state().height, 0);
    assert_eq!(node.state().tree.count, 0);
    let mut identities = BTreeSet::new();
    let mut sender = sender_vault.wallet().unwrap();
    let mut first_reward = None;
    for height in 1..=LAST_FUNDING_HEIGHT {
        let positions = fill_positions(node.state(), &prover, Vec::new(), start);
        mine_and_accept(
            &mut node,
            &directory.join("chain"),
            &prover,
            positions,
            &settings,
            &mut identities,
            start,
        );
        assert_eq!(node.state().height, height);
        progress(&directory, node.store(), "native-funding", start);
        if height == 24 {
            sender
                .reconcile(config.clone(), &canonical_blocks(node.store()), &verifier)
                .unwrap();
            let reward = sender
                .receipts()
                .iter()
                .find(|receipt| receipt.height == 1 && receipt.output_index == 3)
                .expect("the first miner reward must be recovered in the reward receipt namespace");
            assert_eq!(reward.note().unlock_height, 25);
            first_reward = Some(reward.commitment);
            // Even a future local scheduler clock cannot bypass consensus
            // maturity at snapshot24. No compressed timing profile is used.
            assert!(
                sender
                    .prepare_transfer(
                        node.state(),
                        [first_reward, None],
                        &recipient,
                        SIP_ASSET_ID,
                        100_000,
                        FeeTier::Standard,
                        u64::MAX
                    )
                    .is_err()
            );
        }
    }
    let funding_fingerprint = node.state().fingerprint();
    let funding_tip = node.state().tip;
    drop(node);
    let mut node = Node::new(
        Store::open_existing(&database, config.clone(), &verifier).unwrap(),
        NativeVerifier::new().unwrap(),
    );
    assert_eq!(node.state().fingerprint(), funding_fingerprint);
    assert_eq!(node.state().tip, funding_tip);
    for height in 1..=LAST_FUNDING_HEIGHT {
        let block = node.store().block(height).unwrap();
        let receipt =
            crate::local::read_reward(&directory.join("chain"), &block.id().unwrap()).unwrap();
        validate_reward_secret(&block, &receipt).unwrap();
    }
    drop(sender);
    drop(sender_vault);
    let sender_path = directory.join("sender-restored");
    let mut sender_vault = WalletVault::restore(
        &sender_path,
        network,
        0,
        Zeroizing::new(sender_words.expose().to_owned()),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(sender_vault.keys().unwrap().address(), settings.recipient);
    let mut sender = sender_vault.wallet().unwrap();
    sender
        .reconcile(config.clone(), &canonical_blocks(node.store()), &verifier)
        .unwrap();
    let commitment = first_reward.expect("first reward inspected before maturity");
    // Only the wallet's local privacy-delay clock is advanced to its derived
    // eligibility deadline; block maturity and all consensus heights remain
    // unchanged. This is not an elapsed-time privacy-delay observation.
    let wallet_now = sender
        .automatic_ready_timestamp(&commitment)
        .unwrap()
        .unwrap();
    let prepared = sender
        .prepare_transfer(
            node.state(),
            [Some(commitment), None],
            &recipient,
            SIP_ASSET_ID,
            100_000,
            FeeTier::Standard,
            wallet_now,
        )
        .unwrap();
    let reservation = sender_vault.reserve_payment(prepared.record()).unwrap();
    let id = reservation.id();
    check_deadline(start);
    let payment = prepared.prove(&prover).unwrap();
    sender_vault
        .store_wallet_payment(&reservation, &payment, &recipient)
        .unwrap();
    assert!(sender_vault.payment_status(id).unwrap() == PaymentStatus::Prepared);
    let expected_envelope = payment.transaction.encode_envelope(&network).unwrap();
    drop(payment);
    drop(sender);
    drop(sender_vault);
    // Reopening retains the exact packet and independently validates the
    // recovered typed opening before any relay callback is invoked.
    let mut sender_vault = WalletVault::open(&sender_path, network, PASSWORD).unwrap();
    sender_vault.verified_payment_opening(id).unwrap();
    assert_eq!(
        sender_vault.payment_packet(id).unwrap().envelope(),
        expected_envelope
    );
    sender_vault
        .submit_payment(id, |packet| {
            node.submit_local(packet.envelope(), Some(&packet.sidecar()?.encode()?))
                .map(|_| ())
                .map_err(|_| "native wallet roundtrip admission failed".into())
        })
        .unwrap();
    let selected = node.select_pending(SLOTS).unwrap();
    assert_eq!(selected.len(), 1);
    let positions = fill_positions(node.state(), &prover, selected, start);
    mine_and_accept(
        &mut node,
        &directory.join("chain"),
        &prover,
        positions,
        &settings,
        &mut identities,
        start,
    );
    assert_eq!(node.state().height, 26);
    assert_eq!(identities.len(), 26 * SLOTS);
    assert!(!node.mempool().contains(&id));
    progress(&directory, node.store(), "native-payment-accepted", start);
    let expected = node.state().fingerprint();
    let expected_tip = node.state().tip;
    drop(node);
    let restored_config = crate::local::load(&directory.join("chain")).unwrap();
    assert_eq!(restored_config, config);
    let node = Node::new(
        Store::open_existing(&database, restored_config, &verifier).unwrap(),
        NativeVerifier::new().unwrap(),
    );
    assert_eq!(node.state().fingerprint(), expected);
    assert_eq!(node.state().tip, expected_tip);
    let blocks = canonical_blocks(node.store());
    for block in &blocks {
        let receipt =
            crate::local::read_reward(&directory.join("chain"), &block.id().unwrap()).unwrap();
        validate_reward_secret(block, &receipt).unwrap();
    }
    sender_vault
        .reconcile_payments(config.clone(), &blocks, &verifier)
        .unwrap();
    assert!(sender_vault.payment_status(id).unwrap() == PaymentStatus::Accepted);
    drop(receiver_vault);
    let restored = WalletVault::restore(
        &directory.join("receiver-restored"),
        network,
        0,
        Zeroizing::new(receiver_words.expose().to_owned()),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(restored.keys().unwrap().address(), recipient);
    let mut receiver = restored.wallet().unwrap();
    let report = receiver.reconcile(config, &blocks, &verifier).unwrap();
    report.check_head(26, expected_tip, expected).unwrap();
    assert_eq!(
        receiver.balance_details(node.state()).unwrap().available[&SIP_ASSET_ID],
        100_000
    );
    assert_eq!(
        receiver
            .receipts()
            .iter()
            .filter(|receipt| !receipt.spent && receipt.note().value != 0)
            .count(),
        1
    );
    check_deadline(start);
    progress(&directory, node.store(), "complete", start);
}
