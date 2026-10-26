//! Fixed-format wallet encryption for the experimental native D8 transaction.
//!
//! Authentication and commitment reconstruction require the output key holder.
//! Public ciphertext binding does not prove encryption correctness inside the AIR.

use crate::common::{Digest, F, Hasher, Note, felt_from_canonical};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use p3_field::PrimeField32;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const FORMAT_VERSION: u16 = 1;
pub const DIGEST_BYTES: usize = 48;
pub const ENCAPSULATION_KEY_LEN: usize = 1_184;
pub const KEM_CIPHERTEXT_LEN: usize = 1_088;
pub const PLAINTEXT_LEN: usize = 208;
pub const NOTE_FIELDS_LEN: usize = 112;
pub const AEAD_TAG_LEN: usize = 16;
pub const CHANGE_NONCE_LEN: usize = 12;
pub const PAYMENT_INDEX: u8 = 0;
pub const CHANGE_INDEX: u8 = 1;

const AAD_DOMAIN: &[u8] = b"siworld route-a output aad v1\0";
const PAYMENT_KEY_DOMAIN: &str = "siworld route-a payment-key-v1";
const PAYMENT_VIEW_DOMAIN: &str = "siworld route-a payment-view-v1";
const CHANGE_KEY_DOMAIN: &str = "siworld route-a change-v1";
const CHANGE_VIEW_DOMAIN: &str = "siworld route-a change-view-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionError {
    Entropy,
    InvalidPublicKey,
    UnsupportedVersion,
    Authentication,
    InvalidPlaintext,
    CommitmentMismatch,
    OwnerMismatch,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entropy => "operating-system randomness unavailable",
            Self::InvalidPublicKey => "invalid ML-KEM-768 public key",
            Self::UnsupportedVersion => "unsupported output encryption version",
            Self::Authentication => "output authentication failed",
            Self::InvalidPlaintext => "noncanonical output plaintext",
            Self::CommitmentMismatch => "output commitment mismatch",
            Self::OwnerMismatch => "payment owner differs from address owner",
        })
    }
}

impl std::error::Error for EncryptionError {}

/// Public proof/relay context, excluded from the 1,742-byte transaction payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionContext {
    pub network: [u8; 32],
    pub version: u16,
}

impl EncryptionContext {
    pub fn new(network: [u8; 32]) -> Self {
        Self {
            network,
            version: FORMAT_VERSION,
        }
    }

    fn check(&self) -> Result<(), EncryptionError> {
        if self.version == FORMAT_VERSION {
            Ok(())
        } else {
            Err(EncryptionError::UnsupportedVersion)
        }
    }
}

/// Public fixed-width recipient fields. There is no serialized payment nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentCiphertext {
    pub kem_ciphertext: [u8; KEM_CIPHERTEXT_LEN],
    pub body: [u8; PLAINTEXT_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub view_tag: u8,
}

/// Public fixed-width change fields; the explicit nonce is part of the binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeCiphertext {
    pub nonce: [u8; CHANGE_NONCE_LEN],
    pub body: [u8; PLAINTEXT_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub view_tag: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAddress {
    owner: Digest,
    encapsulation_key: [u8; ENCAPSULATION_KEY_LEN],
}

impl PaymentAddress {
    pub fn new(
        owner: Digest,
        encapsulation_key: [u8; ENCAPSULATION_KEY_LEN],
    ) -> Result<Self, EncryptionError> {
        let public_key = MlKem768PublicKey::from(&encapsulation_key);
        if !mlkem768::validate_public_key(&public_key) {
            return Err(EncryptionError::InvalidPublicKey);
        }
        Ok(Self {
            owner,
            encapsulation_key,
        })
    }

    pub fn owner(&self) -> Digest {
        self.owner
    }
    pub fn encapsulation_key(&self) -> &[u8; ENCAPSULATION_KEY_LEN] {
        &self.encapsulation_key
    }
}

/// An owned view key. Zeroization covers owned buffers, not dependency copies.
pub struct RecipientViewKey {
    address: PaymentAddress,
    private_key: MlKem768PrivateKey,
}

impl RecipientViewKey {
    pub fn generate(owner: Digest) -> Result<Self, EncryptionError> {
        let mut seed = Zeroizing::new([0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]);
        getrandom::fill(seed.as_mut()).map_err(|_| EncryptionError::Entropy)?;
        let (mut private_key, public_key) = mlkem768::generate_key_pair(*seed).into_parts();
        let address = match PaymentAddress::new(owner, *public_key.as_slice()) {
            Ok(address) => address,
            Err(error) => {
                private_key[0..MlKem768PrivateKey::len()].zeroize();
                return Err(error);
            }
        };
        Ok(Self {
            address,
            private_key,
        })
    }

    pub fn address(&self) -> PaymentAddress {
        self.address.clone()
    }

    pub fn decrypt_payment(
        &self,
        commitment: &Digest,
        ciphertext: &PaymentCiphertext,
        context: &EncryptionContext,
    ) -> Result<Note, EncryptionError> {
        context.check()?;
        let kem = MlKem768Ciphertext::from(&ciphertext.kem_ciphertext);
        let shared_secret = Zeroizing::new(mlkem768::decapsulate(&self.private_key, &kem));
        if view_tag(PAYMENT_VIEW_DOMAIN, &shared_secret) != ciphertext.view_tag {
            return Err(EncryptionError::Authentication);
        }
        let key = derive_secret(PAYMENT_KEY_DOMAIN, shared_secret.as_ref());
        let mut plaintext = Zeroizing::new(ciphertext.body);
        open(
            &key,
            &[0; 12],
            &aad(context, PAYMENT_INDEX, commitment),
            &mut plaintext,
            &ciphertext.tag,
        )?;
        decode_note(self.address.owner, commitment, &plaintext)
    }
}

impl Zeroize for RecipientViewKey {
    fn zeroize(&mut self) {
        self.private_key[0..MlKem768PrivateKey::len()].zeroize();
    }
}
impl Drop for RecipientViewKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for RecipientViewKey {}
impl fmt::Debug for RecipientViewKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecipientViewKey(REDACTED)")
    }
}

/// Wallet-derived 256-bit sender change secret; no implicit clone is provided.
pub struct SenderChangeSecret([u8; 32]);
impl SenderChangeSecret {
    /// The caller owns erasure of any source copy used to construct this value.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, EncryptionError> {
        let mut value = Self([0; 32]);
        getrandom::fill(&mut value.0).map_err(|_| EncryptionError::Entropy)?;
        Ok(value)
    }
}
impl Zeroize for SenderChangeSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SenderChangeSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SenderChangeSecret {}
impl fmt::Debug for SenderChangeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SenderChangeSecret(REDACTED)")
    }
}

/// Fresh OS encapsulation coins provide a new payment secret for the zero nonce.
pub fn encrypt_payment(
    address: &PaymentAddress,
    note: &Note,
    context: &EncryptionContext,
) -> Result<PaymentCiphertext, EncryptionError> {
    context.check()?;
    if address.owner != note.owner {
        return Err(EncryptionError::OwnerMismatch);
    }
    let commitment = Hasher::new().note_cm(note);
    let mut coins = Zeroizing::new([0u8; 32]);
    getrandom::fill(coins.as_mut()).map_err(|_| EncryptionError::Entropy)?;
    let (kem_ciphertext, shared_secret) =
        mlkem768::encapsulate(&MlKem768PublicKey::from(&address.encapsulation_key), *coins);
    let shared_secret = Zeroizing::new(shared_secret);
    let key = derive_secret(PAYMENT_KEY_DOMAIN, shared_secret.as_ref());
    let mut body = encode_note(note);
    let tag = seal(
        &key,
        &[0; 12],
        &aad(context, PAYMENT_INDEX, &commitment),
        &mut body,
    )?;
    Ok(PaymentCiphertext {
        kem_ciphertext: *kem_ciphertext.as_slice(),
        body: *body,
        tag,
        view_tag: view_tag(PAYMENT_VIEW_DOMAIN, &shared_secret),
    })
}

pub fn encrypt_change(
    secret: &SenderChangeSecret,
    note: &Note,
    context: &EncryptionContext,
) -> Result<ChangeCiphertext, EncryptionError> {
    context.check()?;
    let commitment = Hasher::new().note_cm(note);
    let key = change_key(secret, &commitment);
    let mut nonce = [0u8; CHANGE_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| EncryptionError::Entropy)?;
    let mut body = encode_note(note);
    let tag = seal(
        &key,
        &nonce,
        &aad(context, CHANGE_INDEX, &commitment),
        &mut body,
    )?;
    Ok(ChangeCiphertext {
        nonce,
        body: *body,
        tag,
        view_tag: view_tag(CHANGE_VIEW_DOMAIN, &key),
    })
}

pub fn decrypt_change(
    secret: &SenderChangeSecret,
    owner: Digest,
    commitment: &Digest,
    ciphertext: &ChangeCiphertext,
    context: &EncryptionContext,
) -> Result<Note, EncryptionError> {
    context.check()?;
    let key = change_key(secret, commitment);
    if view_tag(CHANGE_VIEW_DOMAIN, &key) != ciphertext.view_tag {
        return Err(EncryptionError::Authentication);
    }
    let mut plaintext = Zeroizing::new(ciphertext.body);
    open(
        &key,
        &ciphertext.nonce,
        &aad(context, CHANGE_INDEX, commitment),
        &mut plaintext,
        &ciphertext.tag,
    )?;
    decode_note(owner, commitment, &plaintext)
}

fn change_key(secret: &SenderChangeSecret, commitment: &Digest) -> Zeroizing<[u8; 32]> {
    let mut kdf = Zeroizing::new(blake3::Hasher::new_derive_key(CHANGE_KEY_DOMAIN));
    kdf.update(&secret.0);
    kdf.update(&encode_digest(commitment));
    kdf.update(&[CHANGE_INDEX]);
    let output = Zeroizing::new(kdf.finalize());
    Zeroizing::new(*output.as_bytes())
}

fn derive_secret(domain: &str, material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut kdf = Zeroizing::new(blake3::Hasher::new_derive_key(domain));
    kdf.update(material);
    let output = Zeroizing::new(kdf.finalize());
    Zeroizing::new(*output.as_bytes())
}

fn view_tag(domain: &str, material: &[u8; 32]) -> u8 {
    derive_secret(domain, material)[0]
}

fn aad(context: &EncryptionContext, index: u8, commitment: &Digest) -> Vec<u8> {
    let mut data = Vec::with_capacity(AAD_DOMAIN.len() + 2 + 32 + 1 + DIGEST_BYTES);
    data.extend_from_slice(AAD_DOMAIN);
    data.extend_from_slice(&context.version.to_le_bytes());
    data.extend_from_slice(&context.network);
    data.push(index);
    data.extend_from_slice(&encode_digest(commitment));
    data
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    body: &mut [u8; PLAINTEXT_LEN],
) -> Result<[u8; AEAD_TAG_LEN], EncryptionError> {
    let aead = ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"));
    let tag = aead
        .encrypt_inout_detached(
            <&Nonce>::try_from(nonce.as_slice()).expect("fixed nonce size"),
            associated_data,
            body.as_mut_slice().into(),
        )
        .map_err(|_| EncryptionError::Authentication)?;
    Ok(tag.into())
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    body: &mut [u8; PLAINTEXT_LEN],
    tag: &[u8; AEAD_TAG_LEN],
) -> Result<(), EncryptionError> {
    let aead = ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"));
    let tag = <&Tag>::try_from(tag.as_slice()).expect("fixed tag size");
    aead.decrypt_inout_detached(
        <&Nonce>::try_from(nonce.as_slice()).expect("fixed nonce size"),
        associated_data,
        body.as_mut_slice().into(),
        tag,
    )
    .map_err(|_| EncryptionError::Authentication)
}

fn encode_digest(digest: &Digest) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0; DIGEST_BYTES];
    for (field, target) in digest.iter().zip(bytes.as_chunks_mut::<4>().0.iter_mut()) {
        target.copy_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
    bytes
}

fn decode_digest(bytes: &[u8]) -> Result<Digest, EncryptionError> {
    if bytes.len() != DIGEST_BYTES {
        return Err(EncryptionError::InvalidPlaintext);
    }
    let mut digest = [F::default(); 12];
    for (target, bytes) in digest.iter_mut().zip(bytes.as_chunks::<4>().0.iter()) {
        let word = u32::from_le_bytes(*bytes);
        *target = felt_from_canonical(word).ok_or(EncryptionError::InvalidPlaintext)?;
    }
    Ok(digest)
}

fn encode_note(note: &Note) -> Zeroizing<[u8; PLAINTEXT_LEN]> {
    let mut plaintext = Zeroizing::new([0; PLAINTEXT_LEN]);
    plaintext[0..8].copy_from_slice(&note.value.to_le_bytes());
    plaintext[8..16].copy_from_slice(&note.unlock_height.to_le_bytes());
    plaintext[16..16 + DIGEST_BYTES].copy_from_slice(&encode_digest(&note.rho));
    plaintext[16 + DIGEST_BYTES..NOTE_FIELDS_LEN].copy_from_slice(&encode_digest(&note.rseed));
    plaintext
}

fn decode_note(
    owner: Digest,
    commitment: &Digest,
    plaintext: &[u8; PLAINTEXT_LEN],
) -> Result<Note, EncryptionError> {
    if plaintext[NOTE_FIELDS_LEN..].iter().any(|byte| *byte != 0) {
        return Err(EncryptionError::InvalidPlaintext);
    }
    let note = Note {
        owner,
        value: u64::from_le_bytes(plaintext[0..8].try_into().expect("fixed value width")),
        unlock_height: u64::from_le_bytes(plaintext[8..16].try_into().expect("fixed height width")),
        rho: decode_digest(&plaintext[16..16 + DIGEST_BYTES])?,
        rseed: decode_digest(&plaintext[16 + DIGEST_BYTES..NOTE_FIELDS_LEN])?,
    };
    if Hasher::new().note_cm(&note) != *commitment {
        return Err(EncryptionError::CommitmentMismatch);
    }
    Ok(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{DIGEST, F};
    use p3_field::PrimeCharacteristicRing;

    fn digest(value: u32) -> Digest {
        [F::from_u32(value); DIGEST]
    }

    fn note(owner: Digest) -> Note {
        Note {
            owner,
            value: 456_789,
            unlock_height: 37,
            rho: digest(3),
            rseed: digest(4),
        }
    }

    fn context() -> EncryptionContext {
        EncryptionContext::new([11; 32])
    }

    fn assert_note_eq(left: &Note, right: &Note) {
        assert_eq!(left.owner, right.owner);
        assert_eq!(left.value, right.value);
        assert_eq!(left.unlock_height, right.unlock_height);
        assert_eq!(left.rho, right.rho);
        assert_eq!(left.rseed, right.rseed);
    }

    #[test]
    fn fixed_payload_dimensions_match_selected_layout() {
        assert_eq!(DIGEST_BYTES, 48);
        assert_eq!(NOTE_FIELDS_LEN, 112);
        assert_eq!(PLAINTEXT_LEN - NOTE_FIELDS_LEN, 96);
        assert_eq!(
            4 * DIGEST_BYTES
                + KEM_CIPHERTEXT_LEN
                + 2 * PLAINTEXT_LEN
                + 2 * AEAD_TAG_LEN
                + CHANGE_NONCE_LEN
                + 2,
            1_742
        );
    }

    #[test]
    fn payment_and_change_roundtrip_reconstruct_commitments() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let payment_note = note(recipient.address().owner());
        let payment_cm = Hasher::new().note_cm(&payment_note);
        let payment = encrypt_payment(&recipient.address(), &payment_note, &context()).unwrap();
        let recovered = recipient
            .decrypt_payment(&payment_cm, &payment, &context())
            .unwrap();
        assert_note_eq(&payment_note, &recovered);

        let sender = SenderChangeSecret::new([7; 32]);
        let change_note = note(digest(2));
        let change_cm = Hasher::new().note_cm(&change_note);
        let change = encrypt_change(&sender, &change_note, &context()).unwrap();
        let recovered =
            decrypt_change(&sender, change_note.owner, &change_cm, &change, &context()).unwrap();
        assert_note_eq(&change_note, &recovered);
    }

    #[test]
    fn every_public_encryption_field_is_authenticated() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let original_note = note(recipient.address().owner());
        let cm = Hasher::new().note_cm(&original_note);
        let original = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        for position in 0..KEM_CIPHERTEXT_LEN {
            let mut changed = original.clone();
            changed.kem_ciphertext[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        for position in 0..PLAINTEXT_LEN {
            let mut changed = original.clone();
            changed.body[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        for position in 0..AEAD_TAG_LEN {
            let mut changed = original.clone();
            changed.tag[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        let mut changed = original.clone();
        changed.view_tag ^= 1;
        assert!(
            recipient
                .decrypt_payment(&cm, &changed, &context())
                .is_err()
        );

        let sender = SenderChangeSecret::new([7; 32]);
        let original = encrypt_change(&sender, &original_note, &context()).unwrap();
        for position in 0..CHANGE_NONCE_LEN {
            let mut changed = original.clone();
            changed.nonce[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        for position in 0..PLAINTEXT_LEN {
            let mut changed = original.clone();
            changed.body[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        for position in 0..AEAD_TAG_LEN {
            let mut changed = original.clone();
            changed.tag[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        let mut changed = original.clone();
        changed.view_tag ^= 1;
        assert!(decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err());
    }

    #[test]
    fn context_commitment_and_key_mismatch_are_rejected() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let wrong_recipient = RecipientViewKey::generate(digest(2)).unwrap();
        let original_note = note(recipient.address().owner());
        let cm = Hasher::new().note_cm(&original_note);
        let payment = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        assert!(
            wrong_recipient
                .decrypt_payment(&cm, &payment, &context())
                .is_err()
        );
        assert!(
            recipient
                .decrypt_payment(&cm, &payment, &EncryptionContext::new([12; 32]))
                .is_err()
        );
        let mut wrong_version = context();
        wrong_version.version += 1;
        assert!(
            recipient
                .decrypt_payment(&cm, &payment, &wrong_version)
                .is_err()
        );
        for position in 0..DIGEST {
            let mut wrong_cm = cm;
            wrong_cm[position] += F::ONE;
            assert!(
                recipient
                    .decrypt_payment(&wrong_cm, &payment, &context())
                    .is_err()
            );
        }
        assert!(encrypt_payment(&recipient.address(), &note(digest(2)), &context()).is_err());

        let sender = SenderChangeSecret::new([7; 32]);
        let change = encrypt_change(&sender, &original_note, &context()).unwrap();
        assert!(
            decrypt_change(
                &SenderChangeSecret::new([8; 32]),
                original_note.owner,
                &cm,
                &change,
                &context()
            )
            .is_err()
        );
        assert!(decrypt_change(&sender, digest(2), &cm, &change, &context()).is_err());
        assert!(
            decrypt_change(
                &sender,
                original_note.owner,
                &cm,
                &change,
                &EncryptionContext::new([12; 32])
            )
            .is_err()
        );
        assert!(
            decrypt_change(&sender, original_note.owner, &cm, &change, &wrong_version).is_err()
        );
        assert!(encrypt_change(&sender, &original_note, &wrong_version).is_err());
    }

    #[test]
    fn fresh_randomness_changes_kem_ciphertext_and_change_nonce() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let original_note = note(recipient.address().owner());
        let first = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        let second = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        assert_ne!(first.kem_ciphertext, second.kem_ciphertext);
        assert_ne!(first.body, second.body);
        let sender = SenderChangeSecret::new([7; 32]);
        let first = encrypt_change(&sender, &original_note, &context()).unwrap();
        let second = encrypt_change(&sender, &original_note, &context()).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.body, second.body);
    }

    #[test]
    fn note_decoder_rejects_padding_noncanonical_fields_and_wrong_commitment() {
        let original_note = note(digest(1));
        let cm = Hasher::new().note_cm(&original_note);
        let encoded = encode_note(&original_note);
        assert_note_eq(
            &original_note,
            &decode_note(original_note.owner, &cm, &encoded).unwrap(),
        );
        for position in NOTE_FIELDS_LEN..PLAINTEXT_LEN {
            let mut malformed = encoded.clone();
            malformed[position] = 1;
            assert!(decode_note(original_note.owner, &cm, &malformed).is_err());
        }
        for offset in [16, 16 + DIGEST_BYTES] {
            for position in 0..DIGEST {
                let mut malformed = encoded.clone();
                let start = offset + 4 * position;
                malformed[start..start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                assert!(decode_note(original_note.owner, &cm, &malformed).is_err());
            }
        }
        assert!(decode_note(digest(2), &cm, &encoded).is_err());
    }

    #[test]
    fn secret_types_zeroize_owned_buffers_and_redact_debug() {
        fn erased_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        erased_on_drop::<RecipientViewKey>();
        erased_on_drop::<SenderChangeSecret>();
        let mut recipient = RecipientViewKey::generate(digest(1)).unwrap();
        assert_eq!(format!("{recipient:?}"), "RecipientViewKey(REDACTED)");
        recipient.zeroize();
        assert!(recipient.private_key.as_ref().iter().all(|byte| *byte == 0));
        let mut sender = SenderChangeSecret::new([7; 32]);
        assert_eq!(format!("{sender:?}"), "SenderChangeSecret(REDACTED)");
        sender.zeroize();
        assert!(sender.0.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_mlkem_public_keys_are_rejected() {
        assert!(PaymentAddress::new(digest(1), [255; ENCAPSULATION_KEY_LEN]).is_err());
    }
}
