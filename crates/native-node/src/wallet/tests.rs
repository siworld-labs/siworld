use super::*;
use crate::audit::tests::{TestVerifier, candidate, felt};
use crate::wire::REWARD_CIPHERTEXT_BYTES;
use native::encryption::{encrypt_change_at, encrypt_payment_with_opening};

fn wallet(network: Hash, seed: u8) -> Wallet {
    Wallet::from_seed(network, Zeroizing::new([seed; 32]), 0).unwrap()
}
fn note(owner: Digest, value: u64, asset_id: AssetId, tag: u32) -> Note {
    Note {
        asset_id,
        owner,
        value,
        unlock_height: 0,
        rho: [F::from_u32(tag); 12],
        rseed: [F::from_u32(tag + 1); 12],
    }
}
fn encrypted_record(
    state: &State,
    target: &Wallet,
    asset: AssetId,
    amount: u64,
    tag: u32,
) -> (PublicRecord, [Note; 3], PaymentEncryptionOpening) {
    let h = Hasher::new();
    let notes = [
        note(target.keys.address().owner(), amount, asset, tag),
        note(target.keys.address().owner(), 20_000, SI_ASSET_ID, tag + 10),
        note(target.keys.address().owner(), 0, SI_ASSET_ID, tag + 20),
    ];
    let ec = EncryptionContext::new(state.config.network);
    let (payment, opening) =
        encrypt_payment_with_opening(&target.keys.address(), &notes[0], &ec).unwrap();
    let public = PublicTransaction {
        nf: [
            decode_digest(&felt(tag + 100)).unwrap(),
            decode_digest(&felt(tag + 101)).unwrap(),
        ],
        cm: notes.each_ref().map(|n| h.note_cm(n)),
        payment,
        change: [
            encrypt_change_at(&target.keys.change, &notes[1], &ec, 1).unwrap(),
            encrypt_change_at(&target.keys.change, &notes[2], &ec, 2).unwrap(),
        ],
    };
    let fee = h.fee_commit(0, &[F::from_u32(tag + 200); 8]);
    (
        PublicRecord::new(
            state.tip_snapshot().selector,
            public.encode(),
            encode_digest(&fee),
        )
        .unwrap(),
        notes,
        opening,
    )
}
fn insert_record(block: &mut Block, record: PublicRecord) {
    block.transactions[0].record = record;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&block.network));
}

#[test]
fn supplied_seed_recovery_is_network_and_account_separated() {
    let first = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 0).unwrap();
    let restored = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 0).unwrap();
    assert_eq!(first.address(), restored.address());
    assert_eq!(*first.nullifier_key, *restored.nullifier_key);
    let other_network = WalletKeys::from_seed([3; 32], Zeroizing::new([2; 32]), 0).unwrap();
    let other_account = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 1).unwrap();
    assert_ne!(first.address(), other_network.address());
    assert_ne!(first.address(), other_account.address());
    assert_ne!(*first.nullifier_key, *other_network.nullifier_key);
    assert_ne!(*first.nullifier_key, *other_account.nullifier_key);
    assert!(WalletKeys::from_seed([0; 32], Zeroizing::new([2; 32]), 0).is_err());
}

#[test]
fn authenticated_rescan_recovers_all_three_outputs_without_a_sidecar() {
    let network = [4; 32];
    let config = Config::development(network, 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let original = wallet(network, 5);
    let asset = AssetId([7; 32]);
    let (record, notes, _) = encrypted_record(&state, &original, asset, 123_456, 500);
    let mut block = candidate(&state, 100_000);
    insert_record(&mut block, record);
    let mut restored = wallet(network, 5);
    restored
        .reconcile(config.clone(), &[block.clone()], &TestVerifier)
        .unwrap();
    assert_eq!(restored.receipts().len(), 3);
    assert_eq!(restored.balances(1).unwrap()[&asset], 123_456);
    assert_eq!(restored.balances(1).unwrap()[&SI_ASSET_ID], 20_000);
    for expected in &notes {
        assert!(
            restored
                .receipts()
                .iter()
                .any(|receipt| same_note(receipt.note(), expected))
        );
    }
    let mut wrong_seed = wallet(network, 6);
    wrong_seed
        .reconcile(config, &[block], &TestVerifier)
        .unwrap();
    assert!(wrong_seed.receipts().is_empty());
}

#[test]
fn reward_scanning_uses_the_same_recipient_key_and_preserves_maturity() {
    let network = [8; 32];
    let config = Config::development(network, 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let mut target = wallet(network, 9);
    let mut reward_note = note(target.keys.address().owner(), 611_014_413, SI_ASSET_ID, 700);
    reward_note.unlock_height = 101;
    let (ciphertext, _) = encrypt_payment_with_opening(
        &target.keys.address(),
        &reward_note,
        &EncryptionContext::new(network),
    )
    .unwrap();
    let mut block = candidate(&state, 100_000);
    block.reward.commitment = encode_digest(&Hasher::new().note_cm(&reward_note));
    block.reward.ciphertext = encode_payment(&ciphertext);
    assert_eq!(block.reward.ciphertext.len(), REWARD_CIPHERTEXT_BYTES);
    target.reconcile(config, &[block], &TestVerifier).unwrap();
    assert_eq!(target.receipts().len(), 1);
    assert!(target.balances(100).unwrap().is_empty());
    assert_eq!(target.balances(101).unwrap()[&SI_ASSET_ID], 611_014_413);
    let mut accepted = state;
    let mut block = candidate(&accepted, 100_000);
    block.reward.commitment = encode_digest(&Hasher::new().note_cm(&reward_note));
    block.reward.ciphertext = encode_payment(&ciphertext);
    accepted.apply(&block, &TestVerifier).unwrap();
    assert!(
        target
            .prepare_transfer(
                &accepted,
                [Some(target.receipts()[0].commitment), None],
                &target.address(),
                SI_ASSET_ID,
                100_000,
                FeeTier::Standard,
            )
            .is_err()
    );
}

#[test]
fn reorg_rescan_removes_orphans_and_reverses_orphan_spends_atomically() {
    let network = [10; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut target = wallet(network, 11);
    let (record, _, _) = encrypted_record(&state, &target, SI_ASSET_ID, 4_000_000, 800);
    let mut first = candidate(&state, 100_000);
    insert_record(&mut first, record);
    state.apply(&first, &TestVerifier).unwrap();
    target
        .reconcile(config.clone(), &[first.clone()], &TestVerifier)
        .unwrap();
    let nullifier = target.receipts()[0].nullifier;
    let mut orphan = candidate(&state, 200_000);
    orphan.transactions[0].record.body[..48].copy_from_slice(&nullifier);
    orphan
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    target
        .reconcile(config.clone(), &[first.clone(), orphan], &TestVerifier)
        .unwrap();
    assert!(target.receipts()[0].spent);
    let replacement = candidate(&state, 300_000);
    target
        .reconcile(
            config.clone(),
            &[first.clone(), replacement.clone()],
            &TestVerifier,
        )
        .unwrap();
    assert!(!target.receipts()[0].spent);
    let saved_tip = target.head();
    let mut invalid = replacement;
    invalid.settlement_proof = vec![0];
    assert!(
        target
            .reconcile(config.clone(), &[first, invalid], &TestVerifier)
            .is_err()
    );
    assert_eq!(target.head(), saved_tip);
    target.reconcile(config, &[], &TestVerifier).unwrap();
    assert!(target.receipts().is_empty());
}

#[test]
fn prebroadcast_check_rejects_every_ciphertext_commitment_and_context_change() {
    let network = [12; 32];
    let state = State::new(Config::development(network, 0).unwrap()).unwrap();
    let sender = wallet(network, 13);
    let (record, notes, opening) = encrypted_record(&state, &sender, SI_ASSET_ID, 50_000, 900);
    let public = PublicTransaction::decode(&record.body).unwrap();
    sender
        .keys
        .check_before_broadcast(&public, &notes, &sender.keys.address(), &opening)
        .unwrap();
    for kind in 0..6 {
        let mut changed = public.clone();
        match kind {
            0 => changed.payment.body[0] ^= 1,
            1 => changed.payment.kem_ciphertext[0] ^= 1,
            2 => changed.change[0].tag[0] ^= 1,
            3 => changed.change[1].body[0] ^= 1,
            4 => changed.cm[2][0] += F::ONE,
            _ => changed.change.swap(0, 1),
        }
        assert!(
            sender
                .keys
                .check_before_broadcast(&changed, &notes, &sender.keys.address(), &opening)
                .is_err()
        );
    }
    let wrong_network = wallet([14; 32], 13);
    assert!(
        wrong_network
            .keys
            .check_before_broadcast(&public, &notes, &sender.keys.address(), &opening)
            .is_err()
    );
    let wrong_opening = PaymentEncryptionOpening::from_encapsulation_coins([0; 32]);
    assert!(
        sender
            .keys
            .check_before_broadcast(&public, &notes, &sender.keys.address(), &wrong_opening)
            .is_err()
    );
}

#[test]
fn transfer_witness_balances_si_fees_and_token_change_with_two_or_one_inputs() {
    let network = [15; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 16);
    let receiver = wallet(network, 17);
    let asset = AssetId([18; 32]);
    let (record, _, _) = encrypted_record(&state, &sender, asset, 500_000, 1000);
    let mut block = candidate(&state, 100_000);
    insert_record(&mut block, record);
    // A second owned SI payment funds the private fee.
    let (record, _, _) = encrypted_record(&state, &sender, SI_ASSET_ID, 5_000_000, 2000);
    block.transactions[1].record = record;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    state.apply(&block, &TestVerifier).unwrap();
    sender.reconcile(config, &[block], &TestVerifier).unwrap();
    let token = sender
        .receipts()
        .iter()
        .find(|r| r.note.asset_id == asset && r.note.value > 0)
        .unwrap()
        .commitment;
    let si = sender
        .receipts()
        .iter()
        .find(|r| r.note.asset_id == SI_ASSET_ID && r.note.value == 5_000_000)
        .unwrap()
        .commitment;
    for tier in [FeeTier::Standard, FeeTier::Priority] {
        let prepared = sender
            .prepare_transfer(
                &state,
                [Some(token), Some(si)],
                &receiver.keys.address(),
                asset,
                100_000,
                tier,
            )
            .unwrap();
        let witness = prepared.witness();
        witness
            .check(
                &Hasher::new(),
                &decode_digest(&state.tip_snapshot().recent_root).unwrap(),
            )
            .unwrap();
        assert_eq!(witness.slot.outputs[0].asset_id, asset);
        assert_eq!(witness.slot.outputs[0].value, 100_000);
        assert_eq!(
            witness.slot.fee,
            base_fee(state.height) * if tier == FeeTier::Priority { 4 } else { 1 }
        );
        prepared
            .sidecar()
            .check_opening(prepared.record(), &network)
            .unwrap();
    }
    let one_input = sender
        .prepare_transfer(
            &state,
            [Some(si), None],
            &receiver.keys.address(),
            SI_ASSET_ID,
            100_000,
            FeeTier::Standard,
        )
        .unwrap();
    assert!(one_input.witness().slot.inputs[1].dummy);
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(token), None],
                &receiver.keys.address(),
                asset,
                100_000,
                FeeTier::Standard
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(si), Some(si)],
                &receiver.keys.address(),
                SI_ASSET_ID,
                100_000,
                FeeTier::Standard
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [None, None],
                &receiver.keys.address(),
                SI_ASSET_ID,
                100_000,
                FeeTier::Standard
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(si), None],
                &receiver.keys.address(),
                SI_ASSET_ID,
                10_000_000,
                FeeTier::Standard
            )
            .is_err()
    );
}

/// The funding history below is a synthetic fixture checked by TestVerifier.
/// Only the transfer uses actual frozen native proving/verification. This does
/// not establish genesis funding, live mining or a fully native wallet chain.
#[test]
#[ignore = "explicit frozen native wallet proof and encrypted receiver check"]
fn actual_native_wallet_proof_passes_admission_and_recipient_authentication() {
    use crate::admission::{Mempool, PeerId};
    use crate::proofs::{NativeProver, NativeVerifier};
    let network = [19; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 20);
    let receiver = wallet(network, 21);
    let (record, _, _) = encrypted_record(&state, &sender, SI_ASSET_ID, 5_000_000, 3000);
    let mut funding = candidate(&state, 100_000);
    insert_record(&mut funding, record);
    state.apply(&funding, &TestVerifier).unwrap();
    sender.reconcile(config, &[funding], &TestVerifier).unwrap();
    let commitment = sender
        .receipts()
        .iter()
        .find(|receipt| receipt.note.value == 5_000_000)
        .unwrap()
        .commitment;
    let prover = NativeProver::new().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    for tier in [FeeTier::Standard, FeeTier::Priority] {
        let prepared = sender
            .prepare_transfer(
                &state,
                [Some(commitment), None],
                &receiver.address(),
                SI_ASSET_ID,
                100_000,
                tier,
            )
            .unwrap();
        let expected =
            prepared
                .witness()
                .slot
                .output_note(&Hasher::new(), &prepared.public().nf, 0);
        let payment = prepared.prove(&prover).unwrap();
        let envelope = payment.transaction.encode_envelope(&network).unwrap();
        let sidecar = payment.sidecar.encode().unwrap();
        let mut pool = Mempool::new(network);
        let accepted = pool
            .submit_encoded(
                &state,
                PeerId([22; 32]),
                &envelope,
                Some(&sidecar),
                &verifier,
            )
            .unwrap();
        assert_eq!(accepted, payment.transaction.record.statement_id(&network));
        let public = PublicTransaction::decode(&payment.transaction.record.body).unwrap();
        let received = receiver
            .keys
            .recipient
            .decrypt_payment(
                &public.cm[0],
                &public.payment,
                &EncryptionContext::new(network),
            )
            .unwrap();
        assert!(same_note(&received, &expected));
        let receipt = payment
            .payment_opening()
            .verify_payment(
                &receiver.address(),
                &public.cm[0],
                &public.payment,
                &EncryptionContext::new(network),
            )
            .unwrap();
        assert!(same_note(&receipt, &expected));
        assert_eq!(pool.len(), 1);
    }
}
