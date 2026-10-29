use super::*;

#[test]
fn only_strictly_greater_verified_work_selects_a_branch() {
    use siworld_core::pow::Work;
    assert!(!prefer_work(Work::from(9u64), Work::from(8u64)));
    assert!(!prefer_work(Work::from(9u64), Work::from(9u64)));
    assert!(prefer_work(Work::from(9u64), Work::from(10u64)));
}

#[test]
fn depth_23_and_24_preserve_finality_but_25_is_rejected() {
    assert_eq!(check_ancestor(50, 27), Ok(()));
    assert_eq!(check_ancestor(50, 26), Ok(()));
    assert_eq!(check_ancestor(50, 25), Err(ChainError::ReorganizationLimit));
    assert!(matches!(
        check_ancestor(50, 51),
        Err(ChainError::Invalid(_))
    ));
    assert_eq!(finalized_height(50), 26);
    assert_eq!(finalized_height(24), 0);
}

#[test]
fn resource_failures_have_no_invalid_consensus_classification() {
    assert!(!ChainError::ResourceExhausted("candidate bytes").is_invalid());
    assert!(!ChainError::Local("storage unavailable".into()).is_invalid());
    assert!(!ChainError::ReorganizationLimit.is_invalid());
    assert!(ChainError::Invalid("bad proof".into()).is_invalid());
}

fn issuance_record() -> crate::issuance::IssuanceRecord {
    let (signed, witness, _) = native::issuance::sample_issuance(crate::issuance::INITIAL_NOTES);
    crate::issuance::IssuanceRecord {
        signed,
        ciphertexts: witness.ciphertexts,
        proof: vec![1],
        fee_commitment: [0; 48],
        fee_rho: [0; 48],
    }
}

#[test]
fn candidate_budget_charges_every_issuance_owned_capacity_before_copying() {
    let state = State::new(crate::state::Config::development([9; 32], 0).unwrap()).unwrap();
    let mut block = crate::fixtures::candidate(&state, 3000);
    block.issuances.push(issuance_record());
    // Normalize fixture allocation slack before comparing each independent
    // enlarged capacity with an otherwise identical cloned candidate.
    let block = block.clone();
    let encoded_length = block.encoded_len().unwrap();
    let baseline =
        candidate_budget(std::slice::from_ref(&block), CandidatePolicy::default()).unwrap();
    for field in 0..7 {
        let mut oversized = block.clone();
        let issuance = &mut oversized.issuances[0];
        match field {
            0 => issuance.proof.reserve_exact(4096),
            1 => issuance
                .signed
                .declaration
                .metadata
                .name
                .reserve_exact(4096),
            2 => issuance
                .signed
                .declaration
                .note_commitments
                .reserve_exact(4096),
            3 => issuance
                .signed
                .declaration
                .note_ciphertext_digests
                .reserve_exact(4096),
            4 => issuance.ciphertexts.reserve_exact(4096),
            5 => issuance.ciphertexts[0].reserve_exact(4096),
            _ => oversized.issuances.reserve_exact(64),
        }
        assert_eq!(oversized.encoded_len().unwrap(), encoded_length);
        let policy = CandidatePolicy {
            max_bytes: baseline,
            ..CandidatePolicy::default()
        };
        assert!(
            matches!(
                candidate_budget(&[oversized], policy),
                Err(ChainError::ResourceExhausted("candidate bytes"))
            ),
            "unchanged encoded length must not hide owned capacity for field {field}"
        );
    }
}

#[test]
fn state_budget_charges_registered_issuer_keys_and_clone_state() {
    let mut state = State::new(crate::state::Config::development([9; 32], 0).unwrap()).unwrap();
    let empty = state_budget(&state).unwrap();
    let fixture = issuance_record();
    for index in 1..=32u8 {
        let mut record = fixture.clone();
        record.signed.declaration.asset_id.0 = [index; 32];
        record.signed.declaration.issuer_key[0] = index;
        record.signed.declaration.sequence = u64::from(index);
        record.fee_commitment[0] = index;
        state.assets.apply(&record, 1).unwrap();
    }
    let charged = state_budget(&state).unwrap();
    assert!(charged >= empty + 32 * native::issuance::ISSUER_KEY_BYTES);
    assert_eq!(
        state.assets.logical_memory_bytes(),
        state.clone().assets.logical_memory_bytes()
    );
    assert!(matches!(
        check_state_budget(
            &state,
            0,
            CandidatePolicy {
                max_bytes: empty,
                ..CandidatePolicy::default()
            }
        ),
        Err(ChainError::ResourceExhausted("candidate state bytes"))
    ));
    check_state_budget(
        &state,
        0,
        CandidatePolicy {
            max_bytes: charged,
            ..CandidatePolicy::default()
        },
    )
    .unwrap();
    assert!(
        check_state_budget(
            &state,
            0,
            CandidatePolicy {
                max_bytes: charged - 1,
                ..CandidatePolicy::default()
            }
        )
        .is_err()
    );
}

#[test]
fn state_budget_charges_fund_key_registry_capacity_without_a_consensus_change() {
    let mut state = State::new(crate::state::Config::development([10; 32], 0).unwrap()).unwrap();
    let baseline = state_budget(&state).unwrap();
    let encoded = state.config.encode_rules();
    state.config.fund_verifying_keys.reserve_exact(128);
    assert_eq!(state.config.encode_rules(), encoded);
    assert!(
        state_budget(&state).unwrap() >= baseline + 128 * crate::fund_spend::VERIFYING_KEY_BYTES
    );
    assert!(matches!(
        check_state_budget(
            &state,
            0,
            CandidatePolicy {
                max_bytes: baseline,
                ..CandidatePolicy::default()
            }
        ),
        Err(ChainError::ResourceExhausted("candidate state bytes"))
    ));
}
