use super::*;
use libcrux_ml_kem::mlkem768::MlKem768PublicKey;
use native::codec::encode_digest;
use native::encryption::{PaymentEncryptionOpening, encrypt_payment_with_opening};
use native::multi_asset::{F, SI_ASSET_ID};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

fn digest(value: u32) -> Digest {
    [F::from_u32(value); 12]
}
fn note(owner: Digest) -> Note {
    Note {
        owner,
        value: 456_789,
        unlock_height: 37,
        rho: digest(3),
        rseed: digest(4),
        asset_id: SI_ASSET_ID,
    }
}
fn context() -> EncryptionContext {
    EncryptionContext::new([11; 32])
}
fn assert_note_eq(left: &Note, right: &Note) {
    assert_eq!(left.asset_id, right.asset_id);
    assert_eq!(left.owner, right.owner);
    assert_eq!(left.value, right.value);
    assert_eq!(left.unlock_height, right.unlock_height);
    assert_eq!(left.rho, right.rho);
    assert_eq!(left.rseed, right.rseed);
}

#[test]
fn recovered_view_keys_accept_the_unchanged_native_encryptor_and_receipt() {
    let first = RecoverableViewKey::from_seed(digest(1), Zeroizing::new([7; 64])).unwrap();
    let recovered = RecoverableViewKey::from_seed(digest(1), Zeroizing::new([7; 64])).unwrap();
    let other_seed = RecoverableViewKey::from_seed(digest(1), Zeroizing::new([8; 64])).unwrap();
    let other_owner = RecoverableViewKey::from_seed(digest(2), Zeroizing::new([7; 64])).unwrap();
    assert_eq!(first.address(), recovered.address());
    assert_ne!(first.address(), other_seed.address());
    assert_ne!(first.address(), other_owner.address());
    let expected = note(first.address().owner());
    let commitment = Hasher::new().note_cm(&expected);
    let (ciphertext, opening) =
        encrypt_payment_with_opening(&first.address(), &expected, &context()).unwrap();
    assert_note_eq(
        &expected,
        &recovered
            .decrypt_payment(&commitment, &ciphertext, &context())
            .unwrap(),
    );
    assert_note_eq(
        &expected,
        &opening
            .verify_payment(&first.address(), &commitment, &ciphertext, &context())
            .unwrap(),
    );
    assert!(
        other_seed
            .decrypt_payment(&commitment, &ciphertext, &context())
            .is_err()
    );
    assert!(
        other_owner
            .decrypt_payment(&commitment, &ciphertext, &context())
            .is_err()
    );
}

#[test]
fn decoder_and_unchanged_native_receipt_reject_field_or_context_replacements() {
    let key = RecoverableViewKey::from_seed(digest(1), Zeroizing::new([7; 64])).unwrap();
    let expected = note(key.address().owner());
    let commitment = Hasher::new().note_cm(&expected);
    let (ciphertext, opening) =
        encrypt_payment_with_opening(&key.address(), &expected, &context()).unwrap();
    for kind in 0..5 {
        let mut changed = ciphertext.clone();
        match kind {
            0 => changed.kem_ciphertext[0] ^= 1,
            1 => changed.body[0] ^= 1,
            2 => changed.tag[0] ^= 1,
            3 => changed.view_tag ^= 1,
            _ => changed.body[207] ^= 1,
        }
        assert!(
            key.decrypt_payment(&commitment, &changed, &context())
                .is_err()
        );
        assert!(
            opening
                .verify_payment(&key.address(), &commitment, &changed, &context())
                .is_err()
        );
    }
    let mut wrong = commitment;
    wrong[0] += F::ONE;
    assert!(
        key.decrypt_payment(&wrong, &ciphertext, &context())
            .is_err()
    );
    assert!(
        opening
            .verify_payment(&key.address(), &wrong, &ciphertext, &context())
            .is_err()
    );
    let wrong_network = EncryptionContext::new([12; 32]);
    assert!(
        key.decrypt_payment(&commitment, &ciphertext, &wrong_network)
            .is_err()
    );
    assert!(
        opening
            .verify_payment(&key.address(), &commitment, &ciphertext, &wrong_network)
            .is_err()
    );
    let mut version = context();
    version.version += 1;
    assert_eq!(
        key.decrypt_payment(&commitment, &ciphertext, &version)
            .err(),
        Some(EncryptionError::UnsupportedVersion)
    );
}

// This helper deliberately creates an authenticated noncanonical plaintext so
// authentication alone cannot conceal a disagreement in note decoding rules.
fn raw_ciphertext(
    key: &RecoverableViewKey,
    commitment: &Digest,
    body: [u8; PLAINTEXT_LEN],
) -> (PaymentCiphertext, PaymentEncryptionOpening) {
    let coins = [19; 32];
    let (kem, shared) = mlkem768::encapsulate(
        &MlKem768PublicKey::from(key.address.encapsulation_key()),
        coins,
    );
    let secret = Zeroizing::new(shared);
    let derived = derive_secret(PAYMENT_KEY_DOMAIN, secret.as_ref());
    let aead = ChaCha20Poly1305::new(<&Key>::try_from(derived.as_slice()).unwrap());
    let mut encrypted = body;
    let tag = aead
        .encrypt_inout_detached(
            <&Nonce>::try_from([0u8; 12].as_slice()).unwrap(),
            &aad(&context(), commitment),
            encrypted.as_mut_slice().into(),
        )
        .unwrap();
    (
        PaymentCiphertext {
            kem_ciphertext: *kem.as_slice(),
            body: encrypted,
            tag: tag.into(),
            view_tag: derive_secret(PAYMENT_VIEW_DOMAIN, secret.as_ref())[0],
        },
        PaymentEncryptionOpening::from_encapsulation_coins(coins),
    )
}

#[test]
fn canonical_plaintext_limits_match_the_unchanged_native_receipt_verifier() {
    let key = RecoverableViewKey::from_seed(digest(1), Zeroizing::new([7; 64])).unwrap();
    let expected = note(key.address().owner());
    let commitment = Hasher::new().note_cm(&expected);
    let mut plaintext = [0; PLAINTEXT_LEN];
    plaintext[..8].copy_from_slice(&expected.value.to_le_bytes());
    plaintext[8..16].copy_from_slice(&expected.unlock_height.to_le_bytes());
    plaintext[16..64].copy_from_slice(&encode_digest(&expected.rho));
    plaintext[64..112].copy_from_slice(&encode_digest(&expected.rseed));
    plaintext[112..144].copy_from_slice(&expected.asset_id.0);
    let (ciphertext, opening) = raw_ciphertext(&key, &commitment, plaintext);
    assert_note_eq(
        &expected,
        &key.decrypt_payment(&commitment, &ciphertext, &context())
            .unwrap(),
    );
    assert_note_eq(
        &expected,
        &opening
            .verify_payment(&key.address(), &commitment, &ciphertext, &context())
            .unwrap(),
    );
    for kind in 0..3 {
        let mut invalid = plaintext;
        match kind {
            0 => invalid[144] = 1,
            1 => invalid[16..20].copy_from_slice(&F::ORDER_U32.to_le_bytes()),
            _ => invalid[112] = 1,
        }
        let (ciphertext, opening) = raw_ciphertext(&key, &commitment, invalid);
        let local = key
            .decrypt_payment(&commitment, &ciphertext, &context())
            .err();
        let native = opening
            .verify_payment(&key.address(), &commitment, &ciphertext, &context())
            .err();
        assert!(local.is_some());
        assert_eq!(local, native);
    }
}
