//! Native public-body rejection checks; no native block validator is implied.
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_multi_asset_experiment::{
    codec::{CodecError, PUBLIC_TRANSACTION_BYTES, ProofContext, PublicTransaction},
    encryption::{ChangeCiphertext, PaymentCiphertext},
    multi_asset::F,
};

fn encoded() -> [u8; PUBLIC_TRANSACTION_BYTES] {
    PublicTransaction {
        nf: [[F::ONE; 12], [F::TWO; 12]],
        cm: [[F::ZERO; 12]; 3],
        payment: PaymentCiphertext {
            kem_ciphertext: [0; 1088],
            body: [0; 208],
            tag: [0; 16],
            view_tag: 0,
        },
        change: core::array::from_fn(|_| ChangeCiphertext {
            body: [0; 208],
            tag: [0; 16],
            nonce: [0; 12],
            view_tag: 0,
        }),
    }
    .encode()
}

#[test]
fn every_public_digest_rejects_noncanonical_field_spelling() {
    for digest in 0..5 {
        for limb in 0..12 {
            let mut bytes = encoded();
            let offset = digest * 48 + limb * 4;
            bytes[offset..offset + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert_eq!(
                PublicTransaction::decode(&bytes),
                Err(CodecError::NoncanonicalDigest)
            );
        }
    }
}

#[test]
fn duplicate_nullifiers_and_trailing_or_truncated_encodings_are_rejected() {
    let mut duplicate = encoded();
    duplicate.copy_within(0..48, 48);
    assert_eq!(
        PublicTransaction::decode(&duplicate),
        Err(CodecError::DuplicateNullifier)
    );
    let bytes = encoded();
    assert_eq!(
        PublicTransaction::decode(&bytes[..bytes.len() - 1]),
        Err(CodecError::Length)
    );
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert_eq!(
        PublicTransaction::decode(&extended),
        Err(CodecError::Length)
    );
}

#[test]
fn snapshot_identity_changes_bound_statement_even_when_public_body_matches() {
    let transaction = PublicTransaction::decode(&encoded()).unwrap();
    let first = ProofContext::for_snapshot([9; 32], 100, [1; 32]);
    let replacement = ProofContext::for_snapshot([9; 32], 100, [2; 32]);
    assert_ne!(
        transaction.ciphertext_digest(&first),
        transaction.ciphertext_digest(&replacement)
    );
    let fee = [F::ZERO; 12];
    let root = [F::ZERO; 12];
    assert_ne!(
        transaction.statement(&first, &fee, &root),
        transaction.statement(&replacement, &fee, &root)
    );
}
