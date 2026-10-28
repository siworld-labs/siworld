//! ML-DSA-65 (FIPS 204) signatures: the one signature scheme consensus checks
//! (docs/protocol.md, Cryptography), used by development-fund payouts and later by
//! pre-confirmation batches. The libcrux implementation.
//!
//! Keys and signatures are fixed-length byte strings on chain and in the chain
//! parameters; the lengths are consensus constants in `siworld_core::params`.

use std::fmt;

use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use siworld_core::params::{SIGNATURE_LEN, VERIFYING_KEY_LEN};
use siworld_core::Digest;

const _: () = assert!(MLDSA65VerificationKey::len() == VERIFYING_KEY_LEN);
const _: () = assert!(MLDSA65Signature::len() == SIGNATURE_LEN);

/// Separates siworld signatures from any other use of the same key.
const CONTEXT: &[u8] = b"siworld v0";

/// A signing key and its verifying key.
#[derive(Clone)]
pub struct SigningKey {
    sk: MLDSA65SigningKey,
    vk: VerifyingKey,
}

/// An ML-DSA-65 verifying (public) key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(pub [u8; VERIFYING_KEY_LEN]);

/// An ML-DSA-65 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(self.sk.as_mut_slice());
    }
}
impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}
impl zeroize::ZeroizeOnDrop for SigningKey {}
impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(REDACTED)")
    }
}

impl SigningKey {
    /// Derives a key pair from 32 bytes of secret randomness, deterministically.
    pub fn generate(seed: &Digest) -> Self {
        let pair = ml_dsa_65::generate_key_pair(seed.0);
        Self {
            sk: pair.signing_key,
            vk: VerifyingKey(*pair.verification_key.as_ref()),
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    /// Signs `message`. `randomness` hedges the signature (FIPS 204, 3.4);
    /// it may be fresh or derived, and never has to be secret for security
    /// against forgery.
    pub fn sign(&self, message: &[u8], randomness: &Digest) -> Signature {
        let sig = ml_dsa_65::sign(&self.sk, message, CONTEXT, randomness.0)
            .expect("rejection sampling fails with probability below 2^-128");
        Signature(*sig.as_ref())
    }
}

impl VerifyingKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let vk = MLDSA65VerificationKey::new(self.0);
        let sig = MLDSA65Signature::new(signature.0);
        ml_dsa_65::verify(&vk, message, CONTEXT, &sig).is_ok()
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyingKey({:?})",
            Digest(blake3::hash(&self.0).into())
        )
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?})", Digest(blake3::hash(&self.0).into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_storage_erases_and_debug_hides_it() {
        use zeroize::Zeroize;
        fn erased_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        erased_on_drop::<SigningKey>();
        let mut key = SigningKey::generate(&Digest([1; 32]));
        assert_eq!(format!("{key:?}"), "SigningKey(REDACTED)");
        assert!(key.sk.as_slice().iter().any(|b| *b != 0));
        key.zeroize();
        assert!(key.sk.as_slice().iter().all(|b| *b == 0));
    }

    #[test]
    fn signatures_verify_and_every_change_breaks_them() {
        let key = SigningKey::generate(&Digest([1; 32]));
        let other = SigningKey::generate(&Digest([2; 32]));
        assert_ne!(key.verifying_key(), other.verifying_key());
        // Key generation is deterministic in the seed.
        assert_eq!(
            SigningKey::generate(&Digest([1; 32])).verifying_key(),
            key.verifying_key()
        );

        let message = b"pay 1 SIP to alice";
        let sig = key.sign(message, &Digest([3; 32]));
        assert!(key.verifying_key().verify(message, &sig));
        // Another hedge gives another valid signature of the same message.
        let again = key.sign(message, &Digest([4; 32]));
        assert_ne!(again, sig);
        assert!(key.verifying_key().verify(message, &again));

        assert!(!other.verifying_key().verify(message, &sig));
        assert!(!key.verifying_key().verify(b"pay 2 SIP to alice", &sig));
        let mut bad = sig;
        bad.0[100] ^= 1;
        assert!(!key.verifying_key().verify(message, &bad));
        let mut bad = sig;
        bad.0[SIGNATURE_LEN - 1] ^= 1;
        assert!(!key.verifying_key().verify(message, &bad));
        let mut wrong_key = *key.verifying_key();
        wrong_key.0[7] ^= 1;
        assert!(!wrong_key.verify(message, &sig));
    }
}
