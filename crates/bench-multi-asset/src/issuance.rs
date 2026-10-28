//! Fixed-supply issuance declarations and native ML-DSA-65 authentication.
//!
//! Issuance policy is supplied by the caller. This experimental module does
//! not choose an issuance fee, its destination, metadata limits or note limits.
//! A valid signature alone never authorizes minting: the native issuance proof
//! and an independently verified SI fee payment are also required.

use crate::common::{Digest, F};
use crate::multi_asset::{AssetId, Hasher, Note, SI_ASSET_ID};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::collections::BTreeSet;

pub const ISSUER_KEY_BYTES: usize = 1952;
pub const ISSUER_SIGNATURE_BYTES: usize = 3309;
const SIGNATURE_CONTEXT: &[u8] = b"siworld asset issuance v1";
const RECORD_DOMAIN: &[u8] = b"siworld asset issuance declaration v1\0";

/// Local policy inputs, not adopted protocol constants. The caller must derive
/// them from an authenticated chain configuration before accepting issuance.
#[derive(Clone, Copy, Debug)]
pub struct IssuancePolicy {
    pub max_notes: usize,
    pub max_metadata_bytes: usize,
    pub max_ciphertext_bytes_per_note: usize,
    pub required_fee_atoms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub decimals: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceDeclaration {
    pub network: [u8; 32],
    pub version: u32,
    pub issuer_key: [u8; ISSUER_KEY_BYTES],
    pub sequence: u64,
    pub asset_id: AssetId,
    pub public_supply: u64,
    pub metadata: AssetMetadata,
    pub issuance_fee_atoms: u64,
    /// The order is signed and bound by the native proof.
    pub note_commitments: Vec<Digest>,
    /// Hashes of the complete ciphertext byte strings, in the same note order.
    pub note_ciphertext_digests: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct SignedIssuance {
    pub declaration: IssuanceDeclaration,
    pub signature: Option<[u8; ISSUER_SIGNATURE_BYTES]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssuanceError {
    WrongNetwork,
    WrongVersion,
    AssetIdMismatch,
    ReservedSiAsset,
    ZeroSupply,
    NoteLimit,
    MetadataLimit,
    WrongIssuanceFee,
    MissingSignature,
    InvalidSignature,
    NoteCountMismatch,
    CiphertextCountMismatch,
    CiphertextLimit,
    CiphertextBindingMismatch,
    NoteAssetMismatch,
    NoteCommitmentMismatch,
    DuplicateNoteCommitment,
    SupplyOverflow,
    SupplyMismatch,
    InvalidProof,
    UnpaidIssuanceFee,
    SequenceReuse,
    AssetReuse,
}

/// A full 256-bit identifier; no reduction into the KoalaBear field occurs.
pub fn derive_asset_id(
    network: &[u8; 32],
    issuer_key: &[u8; ISSUER_KEY_BYTES],
    sequence: u64,
) -> AssetId {
    let mut h = blake3::Hasher::new_derive_key("siworld asset identifier v1");
    h.update(network);
    h.update(issuer_key);
    h.update(&sequence.to_le_bytes());
    AssetId(*h.finalize().as_bytes())
}

impl IssuanceDeclaration {
    /// Canonical little-endian encoding. Variable-length fields carry explicit
    /// u64 lengths; field elements use their unique canonical u32 encodings.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(RECORD_DOMAIN);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.issuer_key);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.asset_id.0);
        out.extend_from_slice(&self.public_supply.to_le_bytes());
        out.extend_from_slice(&(self.metadata.name.len() as u64).to_le_bytes());
        out.extend_from_slice(self.metadata.name.as_bytes());
        out.push(self.metadata.decimals);
        out.extend_from_slice(&self.issuance_fee_atoms.to_le_bytes());
        out.extend_from_slice(&(self.note_commitments.len() as u64).to_le_bytes());
        for commitment in &self.note_commitments {
            for value in commitment {
                out.extend_from_slice(&value.as_canonical_u32().to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.note_ciphertext_digests.len() as u64).to_le_bytes());
        for digest in &self.note_ciphertext_digests {
            out.extend_from_slice(digest);
        }
        out
    }

    pub fn binding(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    pub fn validate(
        &self,
        network: &[u8; 32],
        version: u32,
        policy: IssuancePolicy,
    ) -> Result<(), IssuanceError> {
        if &self.network != network {
            return Err(IssuanceError::WrongNetwork);
        }
        if self.version != version {
            return Err(IssuanceError::WrongVersion);
        }
        if self.asset_id == SI_ASSET_ID {
            return Err(IssuanceError::ReservedSiAsset);
        }
        if self.asset_id != derive_asset_id(network, &self.issuer_key, self.sequence) {
            return Err(IssuanceError::AssetIdMismatch);
        }
        if self.public_supply == 0 {
            return Err(IssuanceError::ZeroSupply);
        }
        if self.note_commitments.is_empty() || self.note_commitments.len() > policy.max_notes {
            return Err(IssuanceError::NoteLimit);
        }
        if self
            .metadata
            .name
            .len()
            .checked_add(1)
            .is_none_or(|n| n > policy.max_metadata_bytes)
        {
            return Err(IssuanceError::MetadataLimit);
        }
        if self.issuance_fee_atoms != policy.required_fee_atoms {
            return Err(IssuanceError::WrongIssuanceFee);
        }
        if self.note_ciphertext_digests.len() != self.note_commitments.len() {
            return Err(IssuanceError::CiphertextCountMismatch);
        }
        let mut seen = BTreeSet::new();
        for commitment in &self.note_commitments {
            if !seen.insert(commitment.map(|v| v.as_canonical_u32())) {
                return Err(IssuanceError::DuplicateNoteCommitment);
            }
        }
        Ok(())
    }

    /// Byte binding only. The receiving wallet verifies AEAD tags and the
    /// decrypted note commitment; this does not prove encryption correctness.
    pub fn validate_ciphertexts(
        &self,
        ciphertexts: &[Vec<u8>],
        max_bytes_per_note: usize,
    ) -> Result<(), IssuanceError> {
        if ciphertexts.len() != self.note_commitments.len()
            || ciphertexts.len() != self.note_ciphertext_digests.len()
        {
            return Err(IssuanceError::CiphertextCountMismatch);
        }
        for (ciphertext, digest) in ciphertexts.iter().zip(&self.note_ciphertext_digests) {
            if ciphertext.is_empty() || ciphertext.len() > max_bytes_per_note {
                return Err(IssuanceError::CiphertextLimit);
            }
            if blake3::hash(ciphertext).as_bytes() != digest {
                return Err(IssuanceError::CiphertextBindingMismatch);
            }
        }
        Ok(())
    }

    pub fn public_inputs(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(36 + self.note_commitments.len() * crate::common::DIGEST);
        out.extend(byte_limbs(&self.asset_id.0));
        out.extend(crate::common::limbs(self.public_supply));
        out.extend(byte_limbs(&self.binding()));
        for commitment in &self.note_commitments {
            out.extend_from_slice(commitment);
        }
        out
    }
}

impl SignedIssuance {
    pub fn verify_signature(&self) -> Result<(), IssuanceError> {
        let signature = self.signature.ok_or(IssuanceError::MissingSignature)?;
        let key = MLDSA65VerificationKey::new(self.declaration.issuer_key);
        let signature = MLDSA65Signature::new(signature);
        ml_dsa_65::verify(
            &key,
            &self.declaration.canonical_bytes(),
            SIGNATURE_CONTEXT,
            &signature,
        )
        .map_err(|_| IssuanceError::InvalidSignature)
    }
}

pub(crate) fn byte_limbs(bytes: &[u8; 32]) -> [F; 16] {
    core::array::from_fn(|i| {
        F::from_u32(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32)
    })
}

#[derive(Clone, Debug)]
pub struct IssuanceWitness {
    pub declaration: IssuanceDeclaration,
    pub notes: Vec<Note>,
    pub ciphertexts: Vec<Vec<u8>>,
}

impl IssuanceWitness {
    pub fn check(&self) -> Result<(), IssuanceError> {
        self.declaration
            .validate_ciphertexts(&self.ciphertexts, usize::MAX)?;
        if self.notes.len() != self.declaration.note_commitments.len() || self.notes.is_empty() {
            return Err(IssuanceError::NoteCountMismatch);
        }
        let hasher = Hasher::new();
        let mut sum = 0u64;
        for (note, commitment) in self.notes.iter().zip(&self.declaration.note_commitments) {
            if note.asset_id != self.declaration.asset_id {
                return Err(IssuanceError::NoteAssetMismatch);
            }
            if hasher.note_cm(note) != *commitment {
                return Err(IssuanceError::NoteCommitmentMismatch);
            }
            sum = sum
                .checked_add(note.value)
                .ok_or(IssuanceError::SupplyOverflow)?;
        }
        if sum != self.declaration.public_supply {
            return Err(IssuanceError::SupplyMismatch);
        }
        Ok(())
    }
}

/// Constructed only after declaration, signature, proof and SI fee checks.
/// It does not itself mutate chain state.
pub struct VerifiedIssuance(pub(crate) IssuanceDeclaration);

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct IssuanceRegistry {
    seen_sequences: BTreeSet<([u8; ISSUER_KEY_BYTES], u64)>,
    asset_ids: BTreeSet<[u8; 32]>,
    note_commitments: BTreeSet<[u32; crate::common::DIGEST]>,
}

impl IssuanceRegistry {
    /// Every fallible check completes before mutation. Integration must append
    /// these commitments and the issuance record in one storage transaction.
    pub fn apply_verified(&mut self, issuance: VerifiedIssuance) -> Result<(), IssuanceError> {
        let d = issuance.0;
        let sequence = (d.issuer_key, d.sequence);
        if self.seen_sequences.contains(&sequence) {
            return Err(IssuanceError::SequenceReuse);
        }
        if self.asset_ids.contains(&d.asset_id.0) {
            return Err(IssuanceError::AssetReuse);
        }
        let commitments: Vec<_> = d
            .note_commitments
            .iter()
            .map(|c| c.map(|v| v.as_canonical_u32()))
            .collect();
        let mut unique = BTreeSet::new();
        if commitments
            .iter()
            .any(|c| self.note_commitments.contains(c) || !unique.insert(*c))
        {
            return Err(IssuanceError::DuplicateNoteCommitment);
        }
        self.seen_sequences.insert(sequence);
        self.asset_ids.insert(d.asset_id.0);
        self.note_commitments.extend(commitments);
        Ok(())
    }
}

/// Synthetic issuance fixture for native proof measurements and rejection tests.
/// The ML-DSA key is derived from the public repeated-byte seed `[7; 32]`;
/// this helper must never supply a deployed issuer identity or policy. Notes
/// use fresh real ML-KEM encryption and are decrypted locally before return.
pub fn sample_issuance(count: usize) -> (SignedIssuance, IssuanceWitness, IssuancePolicy) {
    let pair = ml_dsa_65::generate_key_pair([7; 32]);
    let key = *pair.verification_key.as_ref();
    let network = [9; 32];
    let asset_id = derive_asset_id(&network, &key, 1);
    let notes: Vec<_> = (0..count)
        .map(|i| Note {
            owner: [F::from_u32(10 + i as u32); 12],
            value: 100_000 + i as u64,
            unlock_height: 0,
            rho: [F::from_u32(30 + i as u32); 12],
            rseed: [F::from_u32(50 + i as u32); 12],
            asset_id,
        })
        .collect();
    let context = crate::encryption::EncryptionContext::new(network);
    let ciphertexts: Vec<_> = notes
        .iter()
        .map(|note| {
            let view = crate::encryption::RecipientViewKey::generate(note.owner)
                .expect("synthetic recipient key");
            let ciphertext = crate::encryption::encrypt_payment(&view.address(), note, &context)
                .expect("synthetic note encryption");
            let commitment = Hasher::new().note_cm(note);
            view.decrypt_payment(&commitment, &ciphertext, &context)
                .expect("synthetic note decryption");
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&ciphertext.kem_ciphertext);
            bytes.extend_from_slice(&ciphertext.body);
            bytes.extend_from_slice(&ciphertext.tag);
            bytes.push(ciphertext.view_tag);
            bytes
        })
        .collect();
    let declaration = IssuanceDeclaration {
        network,
        version: 1,
        issuer_key: key,
        sequence: 1,
        asset_id,
        public_supply: notes.iter().map(|n| n.value).sum(),
        metadata: AssetMetadata {
            name: "Synthetic fixture".into(),
            decimals: 8,
        },
        issuance_fee_atoms: 123,
        note_commitments: notes.iter().map(|n| Hasher::new().note_cm(n)).collect(),
        note_ciphertext_digests: ciphertexts
            .iter()
            .map(|c| *blake3::hash(c).as_bytes())
            .collect(),
    };
    let signature = ml_dsa_65::sign(
        &pair.signing_key,
        &declaration.canonical_bytes(),
        SIGNATURE_CONTEXT,
        [8; 32],
    )
    .unwrap();
    let signed = SignedIssuance {
        declaration: declaration.clone(),
        signature: Some(*signature.as_ref()),
    };
    let witness = IssuanceWitness {
        declaration,
        notes,
        ciphertexts,
    };
    (
        signed,
        witness,
        IssuancePolicy {
            max_notes: count,
            max_metadata_bytes: 256,
            max_ciphertext_bytes_per_note: 4096,
            required_fee_atoms: 123,
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture(count: usize) -> (SignedIssuance, IssuanceWitness, IssuancePolicy) {
        sample_issuance(count)
    }

    #[test]
    fn rejects_missing_or_invalid_issuer_authentication() {
        let (signed, _, _) = fixture(2);
        assert!(signed.verify_signature().is_ok());
        let mut missing = signed.clone();
        missing.signature = None;
        assert_eq!(
            missing.verify_signature(),
            Err(IssuanceError::MissingSignature)
        );
        let mut wrong = signed.clone();
        wrong.signature.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            wrong.verify_signature(),
            Err(IssuanceError::InvalidSignature)
        );
        let mut altered = signed;
        altered.declaration.metadata.decimals += 1;
        assert_eq!(
            altered.verify_signature(),
            Err(IssuanceError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_forged_asset_and_hidden_oversupply() {
        let (signed, mut witness, policy) = fixture(2);
        let mut forged = signed.declaration.clone();
        forged.asset_id.0[0] ^= 1;
        assert_eq!(
            forged.validate(&signed.declaration.network, 1, policy),
            Err(IssuanceError::AssetIdMismatch)
        );
        witness.notes[0].value += 1;
        witness.declaration.note_commitments[0] = Hasher::new().note_cm(&witness.notes[0]);
        assert_eq!(witness.check(), Err(IssuanceError::SupplyMismatch));
        witness.notes[0].asset_id.0[0] ^= 1;
        assert_eq!(witness.check(), Err(IssuanceError::NoteAssetMismatch));
    }

    #[test]
    fn declaration_rejects_network_version_fee_and_unbounded_records() {
        let (signed, _, policy) = fixture(2);
        let declaration = &signed.declaration;
        assert_eq!(
            declaration.validate(&[8; 32], 1, policy),
            Err(IssuanceError::WrongNetwork)
        );
        assert_eq!(
            declaration.validate(&declaration.network, 2, policy),
            Err(IssuanceError::WrongVersion)
        );
        assert_eq!(
            declaration.validate(
                &declaration.network,
                1,
                IssuancePolicy {
                    required_fee_atoms: 124,
                    ..policy
                }
            ),
            Err(IssuanceError::WrongIssuanceFee)
        );
        assert_eq!(
            declaration.validate(
                &declaration.network,
                1,
                IssuancePolicy {
                    max_notes: 1,
                    ..policy
                }
            ),
            Err(IssuanceError::NoteLimit)
        );
        assert_eq!(
            declaration.validate(
                &declaration.network,
                1,
                IssuancePolicy {
                    max_metadata_bytes: 1,
                    ..policy
                }
            ),
            Err(IssuanceError::MetadataLimit)
        );
    }

    #[test]
    fn minted_ciphertext_bytes_and_order_are_bound() {
        let (_, mut witness, _) = fixture(2);
        assert!(witness.check().is_ok());
        witness.ciphertexts[0][0] ^= 1;
        assert_eq!(
            witness.check(),
            Err(IssuanceError::CiphertextBindingMismatch)
        );
        witness.ciphertexts[0][0] ^= 1;
        witness.ciphertexts.swap(0, 1);
        assert_eq!(
            witness.check(),
            Err(IssuanceError::CiphertextBindingMismatch)
        );
        witness.ciphertexts.pop();
        assert_eq!(witness.check(), Err(IssuanceError::CiphertextCountMismatch));
    }

    #[test]
    fn registry_rejects_reuse_without_partial_updates() {
        let (_, witness, _) = fixture(2);
        let mut registry = IssuanceRegistry::default();
        registry
            .apply_verified(VerifiedIssuance(witness.declaration.clone()))
            .unwrap();
        let before = registry.clone();
        assert_eq!(
            registry.apply_verified(VerifiedIssuance(witness.declaration)),
            Err(IssuanceError::SequenceReuse)
        );
        assert_eq!(registry, before);
    }
}
