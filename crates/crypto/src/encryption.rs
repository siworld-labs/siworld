//! Package encryption: ML-KEM-768 key encapsulation, then ChaCha20-Poly1305.
//!
//! Ciphertext layout (`CIPHERTEXT_LEN` = 1,344 bytes):
//! `kem_ct (1,088) ‖ AEAD(plaintext (240)) ‖ AEAD tag (16)`.
//! The plaintext is `value (8) ‖ unlock_height (8) ‖ ρ (32) ‖ rseed (32)`
//! followed by zero padding. The owner is not encrypted: the recipient
//! rebuilds the package with its own owner and checks it against `cm`, which
//! is also the AEAD's associated data. Each shared secret is fresh, so the
//! AEAD key is used once and the nonce is fixed at zero.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::MlKemSharedSecret;
use siworld_core::{Ciphertext, Commitment, Condition, Digest, Note, CIPHERTEXT_LEN};

use crate::{is_canonical, note_commitment, SpendKey};

/// ML-KEM-768 encapsulation key length.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;
const KEM_CT_LEN: usize = 1088;
const AEAD_TAG_LEN: usize = 16;
const PLAINTEXT_LEN: usize = CIPHERTEXT_LEN - KEM_CT_LEN - AEAD_TAG_LEN;
const NOTE_FIELDS_LEN: usize = 8 + 8 + 32 + 32;

const _: () = assert!(KEM_CT_LEN + PLAINTEXT_LEN + AEAD_TAG_LEN == CIPHERTEXT_LEN);
const _: () = assert!(PLAINTEXT_LEN >= NOTE_FIELDS_LEN);

/// A payment address: the owner identifier that goes into the package, and
/// the ML-KEM key its contents are encrypted to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address {
    owner: Digest,
    ek: [u8; ENCAPSULATION_KEY_LEN],
}

impl Address {
    /// Accepts only a canonical owner and an encapsulation key that passes the
    /// FIPS 203 modulus check.
    pub fn new(owner: Digest, ek: [u8; ENCAPSULATION_KEY_LEN]) -> Option<Self> {
        (is_canonical(&owner) && mlkem768::validate_public_key(&MlKem768PublicKey::from(&ek)))
            .then_some(Self { owner, ek })
    }

    pub fn owner(&self) -> Digest {
        self.owner
    }

    pub fn encapsulation_key(&self) -> &[u8; ENCAPSULATION_KEY_LEN] {
        &self.ek
    }
}

/// Decrypts packages sent to one address. It cannot spend them.
#[derive(Clone)]
pub struct ViewKey {
    owner: Digest,
    dk: MlKem768PrivateKey,
    ek: [u8; ENCAPSULATION_KEY_LEN],
}

impl Zeroize for ViewKey {
    fn zeroize(&mut self) {
        self.dk[0..MlKem768PrivateKey::len()].zeroize();
    }
}
impl Drop for ViewKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ViewKey {}
impl core::fmt::Debug for ViewKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ViewKey(REDACTED)")
    }
}

impl SpendKey {
    /// The key pair is derived deterministically from the spend key, so a
    /// wallet restored from `sk` finds its packages again.
    pub fn view_key(&self) -> ViewKey {
        let mut seed = Zeroizing::new([0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]);
        blake3::Hasher::new_derive_key("siworld v0 kem key seed")
            .update(self.0.as_bytes())
            .finalize_xof()
            .fill(seed.as_mut());
        let (dk, ek) = mlkem768::generate_key_pair(*seed).into_parts();
        ViewKey {
            owner: self.owner(),
            dk,
            ek: *ek.as_slice(),
        }
    }

    pub fn address(&self) -> Address {
        self.view_key().address()
    }
}

impl ViewKey {
    pub fn address(&self) -> Address {
        Address {
            owner: self.owner,
            ek: self.ek,
        }
    }

    /// Trial decryption. Returns the package only if the view tag, the AEAD,
    /// the zero padding, and the rebuilt commitment all check out.
    pub fn decrypt(&self, cm: &Commitment, tag: u8, ct: &Ciphertext) -> Option<Note> {
        let (kem_ct, rest) = ct.0.split_at(KEM_CT_LEN);
        let (body, aead_tag) = rest.split_at(PLAINTEXT_LEN);
        let kem_ct = MlKem768Ciphertext::try_from(kem_ct).ok()?;
        // Decapsulation never fails: a foreign ciphertext yields an unrelated
        // secret (implicit rejection), which the tag and AEAD then reject.
        let ss = Zeroizing::new(mlkem768::decapsulate(&self.dk, &kem_ct));
        if view_tag(&ss) != tag {
            return None;
        }
        let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
        plaintext.copy_from_slice(body);
        let aead_tag = Tag::try_from(aead_tag).ok()?;
        aead(&ss)
            .decrypt_inout_detached(
                &Nonce::default(),
                cm.0.as_bytes(),
                plaintext.as_mut_slice().into(),
                &aead_tag,
            )
            .ok()?;
        let note = decode_plaintext(self.owner, &plaintext)?;
        (note_commitment(&note) == *cm).then_some(note)
    }
}

/// Encrypts `note` to `to`. `randomness` must be fresh and secret for every
/// call; it determines the shared secret. Returns the ciphertext and the view
/// tag. The note's owner should be `to.owner()`, or the recipient will not
/// recognise it.
pub fn encrypt_note(to: &Address, note: &Note, randomness: &Digest) -> (Ciphertext, u8) {
    let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
    encode_plaintext(note, &mut plaintext);
    seal(to, randomness, &note_commitment(note), *plaintext)
}

fn encode_plaintext(note: &Note, out: &mut [u8; PLAINTEXT_LEN]) {
    out[0..8].copy_from_slice(&note.value.to_le_bytes());
    out[8..16].copy_from_slice(&note.cond.unlock_height.to_le_bytes());
    out[16..48].copy_from_slice(note.rho.as_bytes());
    out[48..80].copy_from_slice(note.rseed.as_bytes());
}

/// Rejects any nonzero padding byte and any non-canonical ρ or rseed, so a
/// plaintext has one encoding (and the commitment can be rebuilt at all).
fn decode_plaintext(owner: Digest, p: &[u8; PLAINTEXT_LEN]) -> Option<Note> {
    if p[NOTE_FIELDS_LEN..].iter().any(|&b| b != 0) {
        return None;
    }
    if !is_canonical(&Digest(p[16..48].try_into().expect("32 bytes")))
        || !is_canonical(&Digest(p[48..80].try_into().expect("32 bytes")))
    {
        return None;
    }
    let u64_at = |i: usize| u64::from_le_bytes(p[i..i + 8].try_into().expect("8 bytes"));
    let digest_at = |i: usize| Digest(p[i..i + 32].try_into().expect("32 bytes"));
    Some(Note {
        owner,
        value: u64_at(0),
        cond: Condition {
            unlock_height: u64_at(8),
        },
        rho: digest_at(16),
        rseed: digest_at(48),
    })
}

fn seal(
    to: &Address,
    randomness: &Digest,
    cm: &Commitment,
    plaintext: [u8; PLAINTEXT_LEN],
) -> (Ciphertext, u8) {
    let mut plaintext = Zeroizing::new(plaintext);
    let (kem_ct, ss) = mlkem768::encapsulate(&MlKem768PublicKey::from(&to.ek), randomness.0);
    let ss = Zeroizing::new(ss);
    let aead_tag = aead(&ss)
        .encrypt_inout_detached(
            &Nonce::default(),
            cm.0.as_bytes(),
            plaintext.as_mut_slice().into(),
        )
        .expect("plaintext length is fixed and small");
    let mut out = [0u8; CIPHERTEXT_LEN];
    out[..KEM_CT_LEN].copy_from_slice(kem_ct.as_slice());
    out[KEM_CT_LEN..KEM_CT_LEN + PLAINTEXT_LEN].copy_from_slice(plaintext.as_ref());
    out[KEM_CT_LEN + PLAINTEXT_LEN..].copy_from_slice(&aead_tag);
    (Ciphertext(out), view_tag(&ss))
}

fn aead(ss: &MlKemSharedSecret) -> ChaCha20Poly1305 {
    let key = Zeroizing::new(blake3::derive_key("siworld v0 note key", ss));
    ChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("32 bytes"))
}

fn view_tag(ss: &MlKemSharedSecret) -> u8 {
    Zeroizing::new(blake3::derive_key("siworld v0 view tag", ss))[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expand;

    fn sk(tag: u64) -> SpendKey {
        SpendKey::from_digest(expand(&Digest([0x11; 32]), "enc test key", tag))
    }

    fn rnd(tag: u64) -> Digest {
        expand(&Digest([0x22; 32]), "enc test randomness", tag)
    }

    fn note_to(sk: &SpendKey, value: u64) -> Note {
        Note {
            owner: sk.owner(),
            value,
            cond: Condition { unlock_height: 77 },
            rho: Digest([3; 32]),
            rseed: Digest([4; 32]),
        }
    }

    #[test]
    fn incoming_view_key_storage_erases_and_debug_hides_it() {
        fn erased_on_drop<T: ZeroizeOnDrop>() {}
        erased_on_drop::<ViewKey>();
        let mut key = sk(1).view_key();
        assert_eq!(format!("{key:?}"), "ViewKey(REDACTED)");
        assert!(key.dk.as_slice().iter().any(|b| *b != 0));
        key.zeroize();
        assert!(key.dk.as_slice().iter().all(|b| *b == 0));
    }

    #[test]
    fn layout_fills_the_fixed_ciphertext_length() {
        assert_eq!(KEM_CT_LEN, 1088);
        assert_eq!(PLAINTEXT_LEN, 240);
        let (ct, _) = encrypt_note(&sk(1).address(), &note_to(&sk(1), 5), &rnd(0));
        assert_eq!(ct.0.len(), CIPHERTEXT_LEN);
    }

    #[test]
    fn recipient_decrypts_the_package() {
        let k = sk(1);
        let note = note_to(&k, 123_456);
        let (ct, tag) = encrypt_note(&k.address(), &note, &rnd(0));
        let got = k.view_key().decrypt(&note_commitment(&note), tag, &ct);
        assert_eq!(got, Some(note));
    }

    #[test]
    fn address_and_keys_are_deterministic_per_spend_key() {
        assert_eq!(sk(1).address(), sk(1).address());
        assert_ne!(sk(1).address(), sk(2).address());
        assert_eq!(sk(1).address().owner(), sk(1).owner());
        let a = sk(1).address();
        assert_eq!(Address::new(a.owner(), *a.encapsulation_key()), Some(a));
    }

    #[test]
    fn malformed_encapsulation_key_is_rejected() {
        assert_eq!(
            Address::new(Digest([0; 32]), [0xff; ENCAPSULATION_KEY_LEN]),
            None
        );
    }

    #[test]
    fn other_keys_cannot_decrypt() {
        let note = note_to(&sk(1), 9);
        let cm = note_commitment(&note);
        for i in 0..4 {
            let (ct, tag) = encrypt_note(&sk(1).address(), &note, &rnd(i));
            // Try every tag, so the AEAD (not just the 1-byte tag) is what fails.
            for t in 0..=255u8 {
                assert_eq!(sk(2).view_key().decrypt(&cm, t, &ct), None);
            }
            assert!(sk(1).view_key().decrypt(&cm, tag, &ct).is_some());
        }
    }

    #[test]
    fn wrong_view_tag_is_skipped() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let (ct, tag) = encrypt_note(&k.address(), &note, &rnd(0));
        let cm = note_commitment(&note);
        assert_eq!(k.view_key().decrypt(&cm, tag ^ 1, &ct), None);
    }

    #[test]
    fn view_tags_and_ciphertexts_do_not_link_payments_to_one_address() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let (ct0, _) = encrypt_note(&k.address(), &note, &rnd(0));
        let (ct1, _) = encrypt_note(&k.address(), &note, &rnd(1));
        assert_ne!(ct0.0[..KEM_CT_LEN], ct1.0[..KEM_CT_LEN]);
        assert_ne!(ct0.0[KEM_CT_LEN..], ct1.0[KEM_CT_LEN..]);
        let tags: std::collections::BTreeSet<u8> = (0..64)
            .map(|i| encrypt_note(&k.address(), &note, &rnd(i)).1)
            .collect();
        assert!(tags.len() > 16, "view tags must vary per payment");
    }

    #[test]
    fn encryption_is_a_function_of_its_randomness() {
        let k = sk(1);
        let note = note_to(&k, 9);
        assert_eq!(
            encrypt_note(&k.address(), &note, &rnd(5)),
            encrypt_note(&k.address(), &note, &rnd(5))
        );
    }

    #[test]
    fn associated_data_binds_the_commitment() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let (ct, tag) = encrypt_note(&k.address(), &note, &rnd(0));
        let other = note_commitment(&note_to(&k, 10));
        assert_eq!(k.view_key().decrypt(&other, tag, &ct), None);
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let cm = note_commitment(&note);
        let (ct, tag) = encrypt_note(&k.address(), &note, &rnd(0));
        for i in [
            0,
            KEM_CT_LEN - 1,
            KEM_CT_LEN,
            KEM_CT_LEN + PLAINTEXT_LEN - 1,
            CIPHERTEXT_LEN - 1,
        ] {
            let mut bad = ct;
            bad.0[i] ^= 1;
            assert_eq!(k.view_key().decrypt(&cm, tag, &bad), None, "byte {i}");
        }
    }

    #[test]
    fn package_for_another_owner_is_not_accepted() {
        // Encrypted to k's key but committed to someone else's owner: the
        // rebuilt package does not match cm.
        let k = sk(1);
        let note = note_to(&sk(2), 9);
        let (ct, tag) = encrypt_note(&k.address(), &note, &rnd(0));
        assert_eq!(
            k.view_key().decrypt(&note_commitment(&note), tag, &ct),
            None
        );
    }

    #[test]
    fn non_canonical_plaintext_is_rejected() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let cm = note_commitment(&note);
        for at in [16, 48] {
            let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
            encode_plaintext(&note, &mut plaintext);
            // The second spelling of an element: x + p.
            let x = u32::from_le_bytes(plaintext[at..at + 4].try_into().unwrap());
            plaintext[at..at + 4].copy_from_slice(&(x + 0x7f00_0001).to_le_bytes());
            let (ct, tag) = seal(&k.address(), &rnd(0), &cm, *plaintext);
            assert_eq!(k.view_key().decrypt(&cm, tag, &ct), None, "offset {at}");
        }
    }

    #[test]
    fn non_canonical_owner_is_not_an_address() {
        let a = sk(1).address();
        assert_eq!(
            Address::new(Digest([0xff; 32]), *a.encapsulation_key()),
            None
        );
    }

    #[test]
    fn nonzero_padding_is_rejected() {
        let k = sk(1);
        let note = note_to(&k, 9);
        let cm = note_commitment(&note);
        let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
        encode_plaintext(&note, &mut plaintext);
        let (ct, tag) = seal(&k.address(), &rnd(0), &cm, *plaintext);
        assert_eq!(k.view_key().decrypt(&cm, tag, &ct), Some(note));
        plaintext[PLAINTEXT_LEN - 1] = 1;
        let (ct, tag) = seal(&k.address(), &rnd(0), &cm, *plaintext);
        assert_eq!(k.view_key().decrypt(&cm, tag, &ct), None);
    }
}
