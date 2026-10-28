use super::*;
use crate::state::Config;
use crate::wire::{PUBLIC_BYTES, PublicRecord};
use native::multi_asset::{F, Hasher};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::cell::Cell;

struct Verifier {
    calls: Cell<usize>,
    fail: Cell<Option<VerificationError>>,
}
impl AdmissionVerifier for Verifier {
    fn verify(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), VerificationError> {
        self.calls.set(self.calls.get() + 1);
        if let Some(failure) = self.fail.get() {
            return Err(failure);
        }
        if proof.iter().all(|byte| *byte == 1) {
            Ok(())
        } else {
            Err(VerificationError::Invalid)
        }
    }
}
fn verifier() -> Verifier {
    Verifier {
        calls: Cell::new(0),
        fail: Cell::new(None),
    }
}
fn state() -> State {
    State::new(Config::development([83; 32], 0).unwrap()).unwrap()
}
fn digest(value: u32) -> DigestBytes {
    let mut fields = [F::ZERO; 12];
    fields[0] = F::from_u32(value);
    encode_digest(&fields)
}
fn fixture(state: &State, seed: u32, fee: u64) -> (Transaction, Sidecar) {
    let mut body = [0; PUBLIC_BYTES];
    for i in 0..5 {
        body[i * 48..(i + 1) * 48].copy_from_slice(&digest(seed + i as u32));
    }
    let blind = core::array::from_fn(|i| seed + 100 + i as u32);
    let fee_commit = encode_digest(&Hasher::new().fee_commit(fee, &blind.map(F::from_u32)));
    let transaction = Transaction {
        record: PublicRecord::new(state.tip_snapshot().selector, body, fee_commit).unwrap(),
        proof: vec![1],
    };
    let sidecar = Sidecar {
        transaction_id: transaction.record.statement_id(&state.config.network),
        fee,
        blind,
    };
    (transaction, sidecar)
}
fn encoded(state: &State, seed: u32, fee: u64) -> (Vec<u8>, [u8; SIDECAR_BYTES]) {
    let (transaction, sidecar) = fixture(state, seed, fee);
    (
        transaction.encode_envelope(&state.config.network).unwrap(),
        sidecar.encode().unwrap(),
    )
}
fn admit(pool: &mut Mempool, state: &State, peer: u8, seed: u32, verifier: &Verifier) -> Hash {
    let (envelope, sidecar) = encoded(state, seed, 10);
    pool.submit_encoded(
        state,
        PeerId([peer; 32]),
        &envelope,
        Some(&sidecar),
        verifier,
    )
    .unwrap()
}
fn empty(pool: &Mempool) {
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.bytes(), 0);
    assert_eq!(pool.peer_count(), 0);
    assert!(pool.inputs.is_empty());
    assert!(pool.outputs.is_empty());
}

#[test]
fn malformed_headers_and_sidecars_are_rejected_before_proof_work() {
    let state = state();
    let verify = verifier();
    for offset in [0, 4, 6, 33] {
        let mut pool = Mempool::new(state.config.network);
        let (mut envelope, sidecar) = encoded(&state, 1, 10);
        envelope[offset] ^= 1;
        assert!(
            pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
                .is_err()
        );
        empty(&pool);
    }
    let mut pool = Mempool::new(state.config.network);
    let (envelope, mut sidecar) = encoded(&state, 1, 10);
    for sidecar in [None, Some(&sidecar[..SIDECAR_BYTES - 1])] {
        assert!(
            pool.submit_encoded(&state, PeerId([1; 32]), &envelope, sidecar, &verify)
                .is_err()
        );
    }
    sidecar[46..50].copy_from_slice(&F::ORDER_U32.to_le_bytes());
    assert!(
        pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
            .is_err()
    );
    assert_eq!(verify.calls.get(), 0);
    empty(&pool);
}

#[test]
fn sidecar_identity_and_opening_must_match_exactly_before_verification() {
    let state = state();
    let verify = verifier();
    let mut pool = Mempool::new(state.config.network);
    let (transaction, original) = fixture(&state, 1, 10);
    let envelope = transaction.encode_envelope(&state.config.network).unwrap();
    for field in 0..3 {
        let mut sidecar = original.clone();
        match field {
            0 => sidecar.transaction_id[0] ^= 1,
            1 => sidecar.fee += 1,
            _ => sidecar.blind[7] += 1,
        }
        assert!(
            pool.submit_encoded(
                &state,
                PeerId([1; 32]),
                &envelope,
                Some(&sidecar.encode().unwrap()),
                &verify
            )
            .is_err()
        );
        empty(&pool);
    }
    assert_eq!(verify.calls.get(), 0);
}

#[test]
fn expired_and_orphan_snapshots_do_not_reach_proof_verification() {
    for reason in 0..2 {
        let mut state = state();
        let (envelope, sidecar) = encoded(&state, 1, 10);
        if reason == 0 {
            state.height = 4096;
        } else {
            state.snapshots.back_mut().unwrap().selector.block_id[0] ^= 1;
        }
        let verify = verifier();
        let mut pool = Mempool::new(state.config.network);
        assert_eq!(
            pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify),
            Err(AdmissionError::Invalid(InvalidReason::Snapshot))
        );
        assert_eq!(verify.calls.get(), 0);
        empty(&pool);
    }
}

#[test]
fn every_input_and_output_conflict_is_rejected_atomically() {
    for field in 0..5 {
        for confirmed in [false, true] {
            let mut state = state();
            let verify = verifier();
            let mut pool = Mempool::new(state.config.network);
            let (first, _) = fixture(&state, 1, 10);
            let bytes = &first.record.body[field * 48..(field + 1) * 48];
            if confirmed {
                let digest: DigestBytes = bytes.try_into().unwrap();
                if field < 2 {
                    state.spent.insert(digest);
                } else {
                    state.commitments.insert(digest);
                }
            } else {
                admit(&mut pool, &state, 1, 1, &verify);
            }
            let (mut transaction, mut sidecar) = fixture(&state, 1000, 10);
            transaction.record.body[field * 48..(field + 1) * 48].copy_from_slice(bytes);
            sidecar.transaction_id = transaction.record.statement_id(&state.config.network);
            let envelope = transaction.encode_envelope(&state.config.network).unwrap();
            let before = (pool.len(), pool.bytes(), verify.calls.get());
            assert!(
                pool.submit_encoded(
                    &state,
                    PeerId([2; 32]),
                    &envelope,
                    Some(&sidecar.encode().unwrap()),
                    &verify
                )
                .is_err()
            );
            assert_eq!((pool.len(), pool.bytes(), verify.calls.get()), before);
        }
    }
}

#[test]
fn duplicate_inputs_and_outputs_within_one_transaction_are_refused() {
    for (source, destination) in [(0, 1), (2, 3), (2, 4), (3, 4)] {
        let state = state();
        let verify = verifier();
        let mut pool = Mempool::new(state.config.network);
        let (mut transaction, mut sidecar) = fixture(&state, 1, 10);
        let duplicate = transaction.record.body[source * 48..(source + 1) * 48].to_vec();
        transaction.record.body[destination * 48..(destination + 1) * 48]
            .copy_from_slice(&duplicate);
        sidecar.transaction_id = transaction.record.statement_id(&state.config.network);
        assert!(
            pool.submit_encoded(
                &state,
                PeerId([1; 32]),
                &transaction.encode_envelope(&state.config.network).unwrap(),
                Some(&sidecar.encode().unwrap()),
                &verify
            )
            .is_err()
        );
        assert_eq!(verify.calls.get(), 0);
        empty(&pool);
    }
}

#[test]
fn invalid_proofs_and_local_exhaustion_release_all_capacity() {
    for failure in [VerificationError::Invalid, VerificationError::Unavailable] {
        let state = state();
        let verify = verifier();
        verify.fail.set(Some(failure));
        let mut pool = Mempool::new(state.config.network);
        let (envelope, sidecar) = encoded(&state, 1, 10);
        let error = pool
            .submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
            .unwrap_err();
        assert_eq!(
            matches!(error, AdmissionError::Unavailable(_)),
            failure == VerificationError::Unavailable
        );
        empty(&pool);
        verify.fail.set(None);
        pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
            .unwrap();
    }
}

#[test]
fn byte_entry_peer_and_peer_byte_budgets_precede_proof_work() {
    for limit in 0..5 {
        let state = state();
        let verify = verifier();
        let (envelope, _) = encoded(&state, 1, 10);
        let cost = entry_bytes(envelope.len()).unwrap();
        let mut limits = Limits::default();
        match limit {
            0 => limits.entries = 1,
            1 => limits.bytes = cost,
            2 => limits.peer_entries = 1,
            3 => limits.peer_bytes = cost,
            _ => limits.peers = 1,
        }
        let mut pool = Mempool::with_limits(state.config.network, limits).unwrap();
        let first = admit(&mut pool, &state, 1, 1, &verify);
        let (envelope, sidecar) = encoded(&state, 1000, 10);
        let peer = if limit == 4 { 2 } else { 1 };
        let before = (pool.bytes(), verify.calls.get());
        assert!(matches!(
            pool.submit_encoded(
                &state,
                PeerId([peer; 32]),
                &envelope,
                Some(&sidecar),
                &verify
            ),
            Err(AdmissionError::Unavailable(_))
        ));
        assert_eq!((pool.bytes(), verify.calls.get()), before);
        assert!(pool.remove(&first));
        empty(&pool);
        pool.submit_encoded(
            &state,
            PeerId([peer; 32]),
            &envelope,
            Some(&sidecar),
            &verify,
        )
        .unwrap();
    }
}

#[test]
fn inclusion_expiry_and_reorganization_release_each_reservation_and_peer_charge() {
    for reason in 0..4 {
        let mut state = state();
        let verify = verifier();
        let mut pool = Mempool::new(state.config.network);
        let first = admit(&mut pool, &state, 1, 1, &verify);
        let public =
            PublicTransaction::decode(&pool.transaction(&first).unwrap().record.body).unwrap();
        match reason {
            0 => state.height = 4096,
            1 => state.snapshots.back_mut().unwrap().selector.block_id[0] ^= 1,
            2 => {
                state.spent.insert(encode_digest(&public.nf[1]));
            }
            _ => {
                state.commitments.insert(encode_digest(&public.cm[2]));
            }
        }
        assert_eq!(pool.prune(&state).unwrap(), 1);
        empty(&pool);
        assert_eq!(pool.prune(&state).unwrap(), 0);
    }
}

#[test]
fn production_selection_retains_private_openings_and_reservations_until_inclusion() {
    let state = state();
    let verify = verifier();
    let mut pool = Mempool::new(state.config.network);
    for (seed, fee) in [(1, 7), (1000, 19), (2000, 0)] {
        let (envelope, sidecar) = encoded(&state, seed, fee);
        pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
            .unwrap();
    }
    let before = pool.bytes();
    let positions = pool.select(&state, 3).unwrap();
    assert_eq!(
        positions
            .iter()
            .map(|position| position.opening.fee)
            .collect::<Vec<_>>(),
        vec![19, 7, 0]
    );
    for position in positions {
        let id = position
            .transaction
            .record
            .statement_id(&state.config.network);
        let sidecar = pool.sidecar(&id).unwrap();
        assert_eq!(position.opening.fee, sidecar.fee);
        assert_eq!(position.opening.blind, sidecar.blind.map(F::from_u32));
        assert!(!position.opening.dummy && !position.opening.priority);
        assert_eq!(
            position.transaction.proof.capacity(),
            position.transaction.proof.len()
        );
    }
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.bytes(), before);
    assert!(pool.select(&state, MAX_SLOTS + 1).is_err());
}

#[test]
fn proof_variants_share_one_identity_and_wire_inputs_cannot_inflate_retained_capacity() {
    let state = state();
    let verify = verifier();
    let mut pool = Mempool::new(state.config.network);
    let (mut envelope, sidecar) = encoded(&state, 1, 10);
    envelope.reserve(4 * 1024 * 1024);
    let id = pool
        .submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
        .unwrap();
    let retained = &pool.transaction(&id).unwrap().proof;
    assert_eq!(retained.capacity(), retained.len());
    let before = (pool.bytes(), verify.calls.get());
    let (mut variant, _) = fixture(&state, 1, 10);
    variant.proof.push(1);
    let variant = variant.encode_envelope(&state.config.network).unwrap();
    assert_ne!(variant.len(), envelope.len());
    assert!(
        pool.submit_encoded(&state, PeerId([2; 32]), &variant, Some(&sidecar), &verify)
            .is_err()
    );
    assert_eq!((pool.bytes(), verify.calls.get()), before);
    assert_eq!(pool.ids(), vec![id]);
    assert!(pool.bytes() < 64 * 1024);
}

#[test]
fn arbitrary_proved_fees_are_not_reinterpreted_using_the_current_fee_schedule() {
    let state = state();
    let verify = verifier();
    let mut pool = Mempool::new(state.config.network);
    let (envelope, sidecar) = encoded(&state, 1, 123_456_789);
    pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify)
        .unwrap();
    assert_eq!(verify.calls.get(), 1);
    assert_eq!(pool.select(&state, 1).unwrap()[0].opening.fee, 123_456_789);
}

#[test]
fn verification_uses_the_selected_trusted_snapshot_and_canonical_statement() {
    struct BoundVerifier {
        public: PublicTransaction,
        context: ProofContext,
        fee: Digest,
        root: Digest,
        calls: Cell<usize>,
    }
    impl AdmissionVerifier for BoundVerifier {
        fn verify(
            &self,
            public: &PublicTransaction,
            context: &ProofContext,
            fee: &Digest,
            root: &Digest,
            proof: &[u8],
        ) -> Result<(), VerificationError> {
            assert_eq!(public, &self.public);
            assert_eq!(context, &self.context);
            assert_eq!(fee, &self.fee);
            assert_eq!(root, &self.root);
            assert_eq!(proof, &[1]);
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }
    }
    let mut state = state();
    let (transaction, sidecar) = fixture(&state, 1, 10);
    let original = state.tip_snapshot().clone();
    let mut newer = original.clone();
    newer.selector.height = 1;
    newer.selector.block_id = [91; 32];
    newer.recent_root = digest(98);
    state.snapshots.push_back(newer);
    state.height = 1;
    let verify = BoundVerifier {
        public: PublicTransaction::decode(&transaction.record.body).unwrap(),
        context: ProofContext::for_snapshot(
            state.config.network,
            original.selector.height,
            original.selector.block_id,
        ),
        fee: decode_digest(&transaction.record.fee_commit).unwrap(),
        root: decode_digest(&original.recent_root).unwrap(),
        calls: Cell::new(0),
    };
    let mut pool = Mempool::new(state.config.network);
    pool.submit_encoded(
        &state,
        PeerId([1; 32]),
        &transaction.encode_envelope(&state.config.network).unwrap(),
        Some(&sidecar.encode().unwrap()),
        &verify,
    )
    .unwrap();
    assert_eq!(verify.calls.get(), 1);
}

#[test]
fn a_local_network_mismatch_is_unavailability_without_peer_blame_or_mutation() {
    let state = state();
    let verify = verifier();
    let mut pool = Mempool::new([84; 32]);
    let (envelope, sidecar) = encoded(&state, 1, 10);
    assert_eq!(
        pool.submit_encoded(&state, PeerId([1; 32]), &envelope, Some(&sidecar), &verify),
        Err(AdmissionError::Unavailable(ResourceReason::Configuration))
    );
    assert_eq!(verify.calls.get(), 0);
    empty(&pool);
}
