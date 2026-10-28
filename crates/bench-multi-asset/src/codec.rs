//! Fixed native transaction public encoding and proof-statement adapter.
//!
//! The codec is isolated from the retained node and is not a consensus format.
//! It binds bytes to the native relation, not encryption correctness.

use crate::Cfg;
use crate::encryption::{ChangeCiphertext, PaymentCiphertext};
use crate::multi_asset::{AccWitness, Digest, F, Hasher};
use crate::multi_asset_transaction::{TransactionProver, statement_for};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::Proof;

pub const PUBLIC_TRANSACTION_BYTES: usize = 2027;
pub const FORMAT_VERSION: u16 = 2;
pub const SUITE_ID: &[u8] = b"siworld-native-d8-w24-12-v2";
/// A stable descriptor of this isolated codec, not a registered consensus suite.
pub const CODEC_SCHEMA: &str = "multi-asset-v1:le32-canonical-koalabear:nf[2][48]:cm[3][48]:kem768[1088]:payment[208]:change[2][208]:tags[3][16]:change_nonce[2][12]:view_tags[3]";
/// Snapshot context changes the derived statement, not the fixed public encoding.
pub const PROOF_CONTEXT_SCHEMA: &str = "multi-asset-v1:network[32]:suite:version:canonical-snapshot[presence:u8,height:le64,block-id:32]";
const SNAPSHOT_CONTEXT_DOMAIN: &[u8] = b"siworld multi-asset transaction canonical snapshot v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    Length,
    NoncanonicalDigest,
    DuplicateNullifier,
    UnsupportedVersion,
    WitnessMismatch,
}

/// Trusted context selected by the verifier, not by an untrusted proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContext {
    pub network: [u8; 32],
    version: u16,
    snapshot: Option<(u64, [u8; 32])>,
}
impl ProofContext {
    /// Unbound context for isolated fixtures. Canonical transaction admission
    /// must select a snapshot identity with `bind_snapshot` before verification.
    pub fn new(network: [u8; 32]) -> Self {
        Self {
            network,
            version: FORMAT_VERSION,
            snapshot: None,
        }
    }
    pub fn for_snapshot(network: [u8; 32], height: u64, block_id: [u8; 32]) -> Self {
        Self::new(network).bind_snapshot(height, block_id)
    }
    /// Replace any supplied snapshot binding with the verifier's selected
    /// canonical identity. This method does not establish canonical membership.
    pub fn bind_snapshot(&self, height: u64, block_id: [u8; 32]) -> Self {
        Self {
            snapshot: Some((height, block_id)),
            ..*self
        }
    }
    pub fn snapshot(&self) -> Option<(u64, [u8; 32])> {
        self.snapshot
    }
    pub fn from_version(network: [u8; 32], version: u16) -> Result<Self, CodecError> {
        if version != FORMAT_VERSION {
            return Err(CodecError::UnsupportedVersion);
        }
        Ok(Self {
            network,
            version,
            snapshot: None,
        })
    }
    pub fn version(&self) -> u16 {
        self.version
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTransaction {
    pub nf: [Digest; 2],
    pub cm: [Digest; 3],
    pub payment: PaymentCiphertext,
    pub change: [ChangeCiphertext; 2],
}

pub fn encode_digest(digest: &Digest) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (dst, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(digest) {
        dst.copy_from_slice(&value.as_canonical_u32().to_le_bytes());
    }
    bytes
}

pub fn decode_digest(bytes: &[u8; 48]) -> Result<Digest, CodecError> {
    let mut digest = [F::ZERO; 12];
    for (dst, value) in digest.iter_mut().zip(bytes.as_chunks::<4>().0.iter()) {
        let value = u32::from_le_bytes(*value);
        if value >= F::ORDER_U32 {
            return Err(CodecError::NoncanonicalDigest);
        }
        *dst = F::from_u32(value);
    }
    Ok(digest)
}

impl PublicTransaction {
    pub fn encode(&self) -> [u8; PUBLIC_TRANSACTION_BYTES] {
        let mut bytes = [0; PUBLIC_TRANSACTION_BYTES];
        for (index, digest) in self.nf.iter().chain(&self.cm).enumerate() {
            bytes[index * 48..(index + 1) * 48].copy_from_slice(&encode_digest(digest));
        }
        bytes[240..1328].copy_from_slice(&self.payment.kem_ciphertext);
        bytes[1328..1536].copy_from_slice(&self.payment.body);
        bytes[1536..1744].copy_from_slice(&self.change[0].body);
        bytes[1744..1952].copy_from_slice(&self.change[1].body);
        bytes[1952..1968].copy_from_slice(&self.payment.tag);
        bytes[1968..1984].copy_from_slice(&self.change[0].tag);
        bytes[1984..2000].copy_from_slice(&self.change[1].tag);
        bytes[2000..2012].copy_from_slice(&self.change[0].nonce);
        bytes[2012..2024].copy_from_slice(&self.change[1].nonce);
        bytes[2024] = self.payment.view_tag;
        bytes[2025] = self.change[0].view_tag;
        bytes[2026] = self.change[1].view_tag;
        bytes
    }
    /// Exact-width decoding rejects malformed public fields before proving work.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let bytes: &[u8; PUBLIC_TRANSACTION_BYTES] =
            bytes.try_into().map_err(|_| CodecError::Length)?;
        let mut digests = [[F::ZERO; 12]; 5];
        for (index, digest) in digests.iter_mut().enumerate() {
            *digest = decode_digest(
                bytes[index * 48..(index + 1) * 48]
                    .try_into()
                    .expect("48 bytes"),
            )?;
        }
        if digests[0] == digests[1] {
            return Err(CodecError::DuplicateNullifier);
        }
        let change = |index: usize| ChangeCiphertext {
            body: bytes[1536 + index * 208..1744 + index * 208]
                .try_into()
                .expect("208 bytes"),
            tag: bytes[1968 + index * 16..1984 + index * 16]
                .try_into()
                .expect("16 bytes"),
            nonce: bytes[2000 + index * 12..2012 + index * 12]
                .try_into()
                .expect("12 bytes"),
            view_tag: bytes[2025 + index],
        };
        Ok(Self {
            nf: [digests[0], digests[1]],
            cm: [digests[2], digests[3], digests[4]],
            payment: PaymentCiphertext {
                kem_ciphertext: bytes[240..1328].try_into().expect("1088 bytes"),
                body: bytes[1328..1536].try_into().expect("208 bytes"),
                tag: bytes[1952..1968].try_into().expect("16 bytes"),
                view_tag: bytes[2024],
            },
            change: [change(0), change(1)],
        })
    }

    /// Bind the fixed encoding, network/suite and canonical snapshot identity.
    /// The separate presence byte distinguishes an unbound fixture from the
    /// all-zero snapshot. Height is little-endian u64, followed by 32 block-ID
    /// bytes. This digest uses the existing AIR limbs; no columns are added.
    pub fn ciphertext_digest(&self, context: &ProofContext) -> [u8; 32] {
        let mut hash =
            blake3::Hasher::new_derive_key("siworld multi-asset transaction public data v1");
        hash.update(&(SUITE_ID.len() as u16).to_le_bytes());
        hash.update(SUITE_ID);
        hash.update(&context.version.to_le_bytes());
        hash.update(&context.network);
        hash.update(&(SNAPSHOT_CONTEXT_DOMAIN.len() as u16).to_le_bytes());
        hash.update(SNAPSHOT_CONTEXT_DOMAIN);
        hash.update(&[u8::from(context.snapshot.is_some())]);
        let (height, block_id) = context.snapshot.unwrap_or((0, [0; 32]));
        hash.update(&height.to_le_bytes());
        hash.update(&block_id);
        hash.update(&self.encode());
        *hash.finalize().as_bytes()
    }

    pub fn bind_witness(
        &self,
        witness: &AccWitness,
        context: &ProofContext,
    ) -> Result<AccWitness, CodecError> {
        if self.nf[0] == self.nf[1] {
            return Err(CodecError::DuplicateNullifier);
        }
        let fields = witness.slot.public_inputs(&Hasher::new());
        if fields.nf != self.nf || fields.cm_out != self.cm {
            return Err(CodecError::WitnessMismatch);
        }
        let mut bound = witness.clone();
        bound.d_ct = self.ciphertext_digest(context);
        Ok(bound)
    }

    /// Build the production statement from the public transaction and its
    /// fee commitment. The fee opening is never accepted as a public field.
    pub fn statement(
        &self,
        context: &ProofContext,
        fee_commit: &Digest,
        accepted_root: &Digest,
    ) -> Vec<F> {
        statement_for(
            &self.nf,
            &self.cm,
            &self.ciphertext_digest(context),
            fee_commit,
            accepted_root,
            context.snapshot().map_or(0, |(height, _)| height),
        )
    }

    /// The caller selects a trusted prepared verifier and a valid root snapshot.
    /// This interface does not accept a peer-provided public statement or key.
    pub fn verify(
        &self,
        prover: &TransactionProver,
        proof: &Proof<Cfg>,
        context: &ProofContext,
        fee_commit: &Digest,
        accepted_root: &Digest,
    ) -> Result<(), String> {
        if self.nf[0] == self.nf[1] {
            return Err("duplicate nullifier".into());
        }
        prover.verify(proof, &self.statement(context, fee_commit, accepted_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_asset::{F, sample_witness};
    use p3_field::PrimeCharacteristicRing;
    fn fixture() -> (PublicTransaction, AccWitness, ProofContext) {
        let w = sample_witness(61);
        let fields = w.slot.public_inputs(&Hasher::new());
        (
            PublicTransaction {
                nf: fields.nf,
                cm: fields.cm_out,
                payment: PaymentCiphertext {
                    kem_ciphertext: [1; 1088],
                    body: [2; 208],
                    tag: [3; 16],
                    view_tag: 4,
                },
                change: core::array::from_fn(|j| ChangeCiphertext {
                    body: [5 + j as u8; 208],
                    tag: [7 + j as u8; 16],
                    nonce: [9 + j as u8; 12],
                    view_tag: 11 + j as u8,
                }),
            },
            w,
            ProofContext::for_snapshot([9; 32], 1000, [10; 32]),
        )
    }
    #[test]
    fn exact_three_output_layout_and_canonical_roundtrip() {
        let (tx, _, _) = fixture();
        let wire = tx.encode();
        assert_eq!(wire.len(), 2027);
        assert_eq!(PublicTransaction::decode(&wire), Ok(tx));
        assert_eq!(&wire[240..1328], &[1; 1088]);
        assert_eq!(&wire[1744..1952], &[6; 208]);
        assert_eq!(&wire[2012..2024], &[10; 12]);
        assert_eq!(&wire[2024..], &[4, 11, 12]);
    }
    #[test]
    fn rejects_legacy_lengths_noncanonical_limbs_and_duplicates() {
        let (tx, _, _) = fixture();
        let wire = tx.encode();
        for length in [1742, 2026] {
            assert_eq!(
                PublicTransaction::decode(&wire[..length]),
                Err(CodecError::Length)
            );
        }
        assert_eq!(
            PublicTransaction::decode(&[wire.as_slice(), &[0]].concat()),
            Err(CodecError::Length)
        );
        for limb in 0..60 {
            let mut bad = wire;
            bad[limb * 4..limb * 4 + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert_eq!(
                PublicTransaction::decode(&bad),
                Err(CodecError::NoncanonicalDigest)
            );
        }
        let mut bad = tx;
        bad.nf[1] = bad.nf[0];
        assert_eq!(
            PublicTransaction::decode(&bad.encode()),
            Err(CodecError::DuplicateNullifier)
        );
    }
    #[test]
    fn every_public_byte_and_context_changes_bound_statement() {
        let (tx, w, ctx) = fixture();
        let fields = w.slot.public_inputs(&Hasher::new());
        let root = w.anchors_root(&Hasher::new());
        let original = tx.statement(&ctx, &fields.fee_commit, &root);
        let wire = tx.encode();
        for byte in 0..wire.len() {
            let mut changed = wire;
            changed[byte] ^= 1;
            if let Ok(changed) = PublicTransaction::decode(&changed) {
                assert_ne!(
                    changed.statement(&ctx, &fields.fee_commit, &root),
                    original,
                    "wire byte {byte}"
                );
            }
        }
        assert_ne!(
            tx.ciphertext_digest(&ctx),
            tx.ciphertext_digest(&ctx.bind_snapshot(1001, [10; 32]))
        );
        assert!(ProofContext::from_version([9; 32], 1).is_err());
    }
    #[test]
    fn native_proof_uses_three_output_decoded_statement() {
        let (tx, w, ctx) = fixture();
        let bound = tx.bind_witness(&w, &ctx).unwrap();
        let p = TransactionProver::new(crate::FriParams::fast());
        let (proof, public) = p.prove(&bound);
        let fields = bound.slot.public_inputs(&Hasher::new());
        let root = bound.anchors_root(&Hasher::new());
        assert_eq!(public, tx.statement(&ctx, &fields.fee_commit, &root));
        tx.verify(&p, &proof, &ctx, &fields.fee_commit, &root)
            .unwrap();
        let mut bad = tx.clone();
        bad.cm[2][0] += F::ONE;
        assert!(
            bad.verify(&p, &proof, &ctx, &fields.fee_commit, &root)
                .is_err()
        );
    }
}
