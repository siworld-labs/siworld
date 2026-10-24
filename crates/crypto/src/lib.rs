//! Cryptographic primitives.
//!
//! Package encryption uses ML-KEM-768 and ChaCha20-Poly1305 (see
//! [`encrypt_note`]). The in-circuit hashes (owner, note commitment,
//! nullifier, output ρ, commitment-tree nodes, 𝒜 entries) are Poseidon2 with
//! the tags and packing of docs/protocol.md ("Poseidon2 packing and domain
//! tags"), built from `siworld-poseidon2`. Their inputs and outputs are
//! [`Digest`]s holding the canonical encoding of 8 field elements.
//!
//! Every in-circuit function panics on a non-canonical input. Consensus
//! rejects non-canonical encodings in a block before hashing anything
//! ([`is_canonical`]), and every value a wallet derives is canonical by
//! construction ([`expand`], [`SpendKey::nullifier_key`]).

mod encryption;
mod randomness;
mod signature;

use std::sync::OnceLock;

pub use encryption::{encrypt_note, Address, ViewKey, ENCAPSULATION_KEY_LEN};
pub use randomness::SecretSeed;
pub use signature::{Signature, SigningKey, VerifyingKey};

use siworld_core::{
    Commitment, Condition, DevAccount, Digest, Height, Note, Nullifier, Payout, PayoutSignature,
    Slot,
};
pub use siworld_poseidon2::SET_LEN;
use siworld_poseidon2::{
    self as p2, tag, Block, FieldDigest, Poseidon2, PrimeCharacteristicRing, F, LIMBS, RATE,
};

fn blake3_hash(context: &str, parts: &[&[u8]]) -> Digest {
    let mut h = blake3::Hasher::new_derive_key(context);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    Digest(*h.finalize().as_bytes())
}

fn poseidon2() -> &'static Poseidon2 {
    static INSTANCE: OnceLock<Poseidon2> = OnceLock::new();
    INSTANCE.get_or_init(Poseidon2::new)
}

/// The 8 field elements a digest encodes, or `None` if any is not canonical.
pub fn to_field(d: &Digest) -> Option<FieldDigest> {
    p2::decode(&d.0)
}

/// Whether a digest is the canonical encoding of 8 field elements, as every
/// nullifier, commitment and root on chain must be.
pub fn is_canonical(d: &Digest) -> bool {
    to_field(d).is_some()
}

fn from_field(f: &FieldDigest) -> Digest {
    Digest(p2::encode(f))
}

fn block(d: &Digest) -> Block {
    to_field(d).expect("non-canonical digest reached an in-circuit hash")
}

/// Two u64 values as one block of 16-bit limbs.
fn limb_block(a: u64, b: u64) -> Block {
    let mut out = [F::ZERO; RATE];
    out[..LIMBS].copy_from_slice(&p2::limbs(a));
    out[LIMBS..].copy_from_slice(&p2::limbs(b));
    out
}

fn sponge(tag: u32, blocks: &[Block]) -> Digest {
    from_field(&poseidon2().sponge(tag, blocks))
}

/// Maps 64 secret bytes to a canonical digest: each little-endian 64-bit
/// chunk reduced mod p (docs/protocol.md). The bias is below 2^-32 per
/// element.
fn reduce_to_digest(bytes: &[u8; 64]) -> Digest {
    let mut out = [F::ZERO; p2::DIGEST];
    for (x, chunk) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *x = F::from_u64(u64::from_le_bytes(*chunk));
    }
    from_field(&out)
}

fn blake3_wide(context: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = blake3::Hasher::new_derive_key(context);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0; 64];
    h.finalize_xof().fill(&mut out);
    out
}

/// Spend key. `owner()` is the public recipient identifier; `nullifier_key()`
/// is used only inside proofs.
/// Owned key bytes erase on drop. Cloning is explicit and creates another
/// secret value with its own erasure responsibility.
///
/// ```compile_fail
/// use siworld_crypto::SpendKey;
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<SpendKey>();
/// ```
/// ```compile_fail
/// use siworld_crypto::SpendKey;
/// use siworld_core::Digest;
/// let key = SpendKey::from_digest(Digest::ZERO);
/// println!("{:?}", key.0);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SpendKey(Digest);

impl zeroize::Zeroize for SpendKey {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0 .0);
    }
}
impl Drop for SpendKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}
impl zeroize::ZeroizeOnDrop for SpendKey {}

impl core::fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SpendKey(REDACTED)")
    }
}

impl SpendKey {
    /// Takes ownership of key material; the caller must erase any source copies.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Explicit raw-key access for local backup/storage and domain derivation.
    /// Never format or log this value.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// nk: 8 field elements derived from the spend key's bytes.
    pub fn nullifier_key(&self) -> Digest {
        let bytes = zeroize::Zeroizing::new(blake3_wide("siworld nk v1", &[self.0.as_bytes()]));
        reduce_to_digest(&bytes)
    }

    /// Recipient identifier = H(nk). Only the holder of sk can derive nk and
    /// nullify the package.
    pub fn owner(&self) -> Digest {
        owner_of(&self.nullifier_key())
    }
}

/// `owner = Poseidon2(TAG_OWNER; nk)`.
pub fn owner_of(nk: &Digest) -> Digest {
    sponge(tag::OWNER, &[block(nk)])
}

/// `cm = Poseidon2(TAG_NOTE; owner, value ‖ unlock_height, ρ, rseed)`.
pub fn note_commitment(note: &Note) -> Commitment {
    Commitment(sponge(
        tag::NOTE,
        &[
            block(&note.owner),
            limb_block(note.value, note.cond.unlock_height),
            block(&note.rho),
            block(&note.rseed),
        ],
    ))
}

/// `nf = Poseidon2(TAG_NF; nk, ρ)`.
pub fn nullifier(nk: &Digest, rho: &Digest) -> Nullifier {
    Nullifier(sponge(tag::NF, &[block(nk), block(rho)]))
}

/// ρ of output j: `ρⱼ = Poseidon2(TAG_RHO_OUT_j; nf₀, nf₁)`. Nullifiers are
/// globally unique, so ρ is globally unique, and a sender cannot create two
/// packages that share a nullifier.
///
/// # Panics
///
/// If `j` is not 0 or 1.
pub fn output_rho(nf0: &Nullifier, nf1: &Nullifier, j: usize) -> Digest {
    let tag = match j {
        0 => tag::RHO_OUT_0,
        1 => tag::RHO_OUT_1,
        _ => panic!("a slot has two outputs"),
    };
    sponge(tag, &[block(&nf0.0), block(&nf1.0)])
}

/// ρ of the miner package: `ρ = Poseidon2(TAG_MINER_RHO; height ‖ 0 × 4)`.
/// There is exactly one miner package per height.
pub fn miner_rho(height: Height) -> Digest {
    sponge(tag::MINER_RHO, &[limb_block(height, 0)])
}

/// ρ of development-fund payout `index` of block `height`:
/// `ρ = Poseidon2(TAG_PAYOUT_RHO; height ‖ index)`. A block carries at most
/// `MAX_PAYOUTS_PER_BLOCK` payouts, so (height, index) is unique.
pub fn payout_rho(height: Height, index: u32) -> Digest {
    sponge(tag::PAYOUT_RHO, &[limb_block(height, u64::from(index))])
}

/// The package a development-fund payout creates when it is payout `index` of
/// block `height` (docs/protocol.md, Economics): the public plaintext with the derived
/// ρ and no condition.
pub fn payout_note(payout: &Payout, height: Height, index: u32) -> Note {
    Note {
        owner: payout.owner,
        value: payout.amount,
        cond: Condition { unlock_height: 0 },
        rho: payout_rho(height, index),
        rseed: payout.rseed,
    }
}

/// Builds and signs a payout of `amount` from `account` to `owner`, as the
/// account's payout number `counter`, for the chain `chain_id`. `rseed` is the
/// package's commitment randomness and `hedge` the signature's randomness (see
/// [`SigningKey::sign`]).
#[allow(clippy::too_many_arguments)]
pub fn sign_payout(
    key: &SigningKey,
    chain_id: &Digest,
    account: DevAccount,
    counter: u64,
    amount: u64,
    owner: Digest,
    rseed: Digest,
    hedge: &Digest,
) -> Payout {
    let mut payout = Payout {
        account,
        counter,
        amount,
        owner,
        rseed,
        signature: PayoutSignature([0; siworld_core::params::SIGNATURE_LEN]),
    };
    payout.signature = PayoutSignature(key.sign(&payout.signed_bytes(chain_id), hedge).0);
    payout
}

/// Whether `payout` carries `key`'s signature for the chain `chain_id`.
pub fn verify_payout(key: &VerifyingKey, chain_id: &Digest, payout: &Payout) -> bool {
    key.verify(
        &payout.signed_bytes(chain_id),
        &Signature(payout.signature.0),
    )
}

/// 𝒜 entry of block h: `Poseidon2(TAG_ANCHOR; r_h, h ‖ base_fee(h))`.
pub fn anchor_entry(root: &Digest, height: Height, base_fee: u64) -> Digest {
    sponge(tag::ANCHOR, &[block(root), limb_block(height, base_fee)])
}

/// Set element of a slot: `E = Poseidon2(TAG_SET; nf₀, nf₁, cm₀, cm₁, d_ct)`
/// squeezed to [`SET_LEN`] elements, where d_ct ([`Slot::ct_digest`]) covers
/// both ciphertexts and both view tags, so E binds every public slot byte.
pub fn set_element(slot: &Slot) -> [F; SET_LEN] {
    poseidon2().set_element(
        &[block(&slot.nf[0].0), block(&slot.nf[1].0)],
        &[block(&slot.cm[0].0), block(&slot.cm[1].0)],
        &slot.ct_digest().0,
    )
}

/// ΣE: the element-wise field sum of the set elements of a multiset of
/// slots, which the container proof's root exposes and the verifier
/// recomputes from the block (docs/protocol.md, "the merge statement").
/// The sum ignores order and counts a repeated slot twice, so distinct
/// nullifiers stay a native validity rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SetSum(pub [F; SET_LEN]);

impl SetSum {
    pub const ZERO: Self = Self([F::ZERO; SET_LEN]);

    pub fn of<'a>(slots: impl IntoIterator<Item = &'a Slot>) -> Self {
        let mut sum = Self::ZERO;
        for slot in slots {
            for (x, e) in sum.0.iter_mut().zip(set_element(slot)) {
                *x += e;
            }
        }
        sum
    }
}

/// Internal node of a Poseidon2 Merkle tree (commitment tree, 𝒜): the 2-to-1
/// compression.
pub fn merkle_node(left: &Digest, right: &Digest) -> Digest {
    from_field(&poseidon2().compress(&block(left), &block(right)))
}

/// Empty leaf of the commitment tree and of unfilled 𝒜 positions: the zero
/// digest.
pub fn empty_leaf() -> Digest {
    Digest::ZERO
}

/// Out-of-circuit BLAKE3 hash with domain separation, for state roots and
/// similar values no proof recomputes.
pub fn domain_hash(context: &str, parts: &[&[u8]]) -> Digest {
    blake3_hash(context, parts)
}

/// Deterministically derives a pseudorandom canonical digest from a seed, so
/// the result can serve as a key, ρ, rseed or nk alike. Randomness that must
/// stay secret (padding, fee packages, wallet outputs) comes from a
/// [`SecretSeed`] instead.
pub fn expand(seed: &Digest, label: &str, index: u64) -> Digest {
    reduce_to_digest(&blake3_wide(
        "siworld expand v1",
        &[seed.as_bytes(), label.as_bytes(), &index.to_le_bytes()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_core::{Ciphertext, Condition, CIPHERTEXT_LEN};

    #[test]
    fn spend_key_debug_is_redacted() {
        let key = SpendKey::from_digest(Digest([0xa5; 32]));
        assert_eq!(format!("{key:?}"), "SpendKey(REDACTED)");
        assert_eq!(format!("{key:#?}"), "SpendKey(REDACTED)");
    }
    fn felts(from: u32) -> Digest {
        from_field(&core::array::from_fn(|i| F::from_u32(from + i as u32)))
    }

    fn note(value: u64) -> Note {
        Note {
            owner: felts(1),
            value,
            cond: Condition { unlock_height: 7 },
            rho: felts(9),
            rseed: felts(17),
        }
    }

    fn sponge_of(tag: u32, blocks: &[Block]) -> Digest {
        from_field(&Poseidon2::new().sponge(tag, blocks))
    }

    #[test]
    fn note_commitment_follows_the_packing() {
        let n = note(0x0001_0002_0003_0004);
        let mut values = [F::ZERO; RATE];
        for (i, v) in [4, 3, 2, 1, 7, 0, 0, 0].into_iter().enumerate() {
            values[i] = F::from_u32(v);
        }
        let expected = sponge_of(
            2,
            &[block(&n.owner), values, block(&n.rho), block(&n.rseed)],
        );
        assert_eq!(note_commitment(&n).0, expected);
        assert!(is_canonical(&expected));
    }

    #[test]
    fn note_commitment_matches_its_vector() {
        // Pins the whole note layout; recompute only with a decisions change.
        assert_eq!(
            hex(&note_commitment(&note(5)).0),
            "b6918e38b8d70803d673ca024e4d4b2fe130a266daad3e5d4a8d765367d27373"
        );
    }

    #[test]
    fn nullifier_owner_and_rho_follow_the_tags() {
        let (nk, rho) = (felts(1), felts(9));
        assert_eq!(owner_of(&nk), sponge_of(1, &[block(&nk)]));
        assert_eq!(
            nullifier(&nk, &rho).0,
            sponge_of(3, &[block(&nk), block(&rho)])
        );
        let (a, b) = (Nullifier(nk), Nullifier(rho));
        assert_eq!(
            output_rho(&a, &b, 0),
            sponge_of(4, &[block(&nk), block(&rho)])
        );
        assert_eq!(
            output_rho(&a, &b, 1),
            sponge_of(5, &[block(&nk), block(&rho)])
        );
        let mut h = [F::ZERO; RATE];
        h[0] = F::from_u32(0x5678);
        h[1] = F::from_u32(0x1234);
        assert_eq!(miner_rho(0x1234_5678), sponge_of(11, &[h]));
        let mut hi = h;
        hi[4] = F::from_u32(3);
        assert_eq!(payout_rho(0x1234_5678, 3), sponge_of(12, &[hi]));
        assert_ne!(payout_rho(0x1234_5678, 0), miner_rho(0x1234_5678));
    }

    #[test]
    fn anchor_entry_packs_height_and_base_fee() {
        let root = felts(1);
        let mut hb = [F::ZERO; RATE];
        hb[0] = F::from_u32(3);
        hb[4] = F::from_u32(0xbeef);
        hb[5] = F::from_u32(1);
        assert_eq!(
            anchor_entry(&root, 3, 0x1_beef),
            sponge_of(10, &[block(&root), hb])
        );
    }

    #[test]
    fn merkle_node_is_the_compression_and_empty_leaf_is_zero() {
        let (l, r) = (felts(1), felts(9));
        assert_eq!(
            merkle_node(&l, &r),
            from_field(&Poseidon2::new().compress(&block(&l), &block(&r)))
        );
        assert_eq!(empty_leaf(), Digest::ZERO);
        assert_eq!(to_field(&empty_leaf()), Some([F::ZERO; p2::DIGEST]));
    }

    #[test]
    fn commitment_binds_value() {
        assert_ne!(note_commitment(&note(1)), note_commitment(&note(2)));
    }

    #[test]
    fn nullifier_depends_on_key_and_rho() {
        let a = nullifier(&felts(1), &felts(2));
        assert_ne!(a, nullifier(&felts(9), &felts(2)));
        assert_ne!(a, nullifier(&felts(1), &felts(9)));
    }

    #[test]
    fn spend_key_storage_and_explicit_copies_erase_independently() {
        use zeroize::Zeroize;
        fn erased_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        erased_on_drop::<SpendKey>();
        let mut key = SpendKey::from_digest(Digest([7; 32]));
        let copy = key.clone();
        key.zeroize();
        assert_eq!(key.expose_secret(), &[0u8; 32]);
        assert_eq!(copy.expose_secret(), &[7u8; 32]);
    }

    #[test]
    fn owner_requires_spend_key() {
        let sk = SpendKey::from_digest(Digest([7; 32]));
        assert_eq!(sk.owner(), owner_of(&sk.nullifier_key()));
        assert_ne!(sk.owner(), SpendKey::from_digest(Digest([8; 32])).owner());
    }

    fn slot(seed: u32) -> Slot {
        let byte = seed as u8;
        Slot {
            nf: [Nullifier(felts(seed)), Nullifier(felts(seed + 8))],
            cm: [Commitment(felts(seed + 16)), Commitment(felts(seed + 24))],
            ct: [
                Ciphertext([byte; CIPHERTEXT_LEN]),
                Ciphertext([byte.wrapping_add(1); CIPHERTEXT_LEN]),
            ],
            tag: [byte, byte.wrapping_add(2)],
        }
    }

    #[test]
    fn set_element_hashes_the_slot_and_its_ciphertext_digest() {
        let s = slot(1);
        let e = set_element(&s);
        let expected = Poseidon2::new().set_element(
            &[block(&s.nf[0].0), block(&s.nf[1].0)],
            &[block(&s.cm[0].0), block(&s.cm[1].0)],
            &s.ct_digest().0,
        );
        assert_eq!(e, expected);

        // Every public slot byte moves E, and the field order matters.
        let mut t = s;
        t.ct[1].0[CIPHERTEXT_LEN - 1] ^= 1;
        assert_ne!(set_element(&t), e);
        let mut t = s;
        t.tag[0] ^= 1;
        assert_ne!(set_element(&t), e);
        let mut t = s;
        t.nf.swap(0, 1);
        assert_ne!(set_element(&t), e);
        let mut t = s;
        t.cm.swap(0, 1);
        assert_ne!(set_element(&t), e);
    }

    #[test]
    fn set_sum_is_an_order_independent_multiset_sum() {
        let (a, b, c) = (slot(1), slot(100), slot(200));
        assert_eq!(SetSum::of([&a, &b, &c]), SetSum::of([&c, &a, &b]));
        assert_ne!(SetSum::of([&a, &a]), SetSum::of([&a]));
        assert_eq!(SetSum::of([]), SetSum::ZERO);

        let (ea, eb) = (set_element(&a), set_element(&b));
        let sum = SetSum::of([&a, &b]);
        for i in 0..SET_LEN {
            assert_eq!(sum.0[i], ea[i] + eb[i]);
        }
    }

    #[test]
    fn derived_secrets_are_canonical() {
        // 0xff bytes reduce in every chunk; the outputs must still decode.
        for i in 0..64 {
            assert!(is_canonical(&expand(&Digest([0xff; 32]), "x", i)));
            assert!(is_canonical(
                &SpendKey::from_digest(Digest([i as u8; 32])).nullifier_key()
            ));
        }
        assert_eq!(
            reduce_to_digest(&[0xff; 64]),
            from_field(&[F::from_u64(u64::MAX); p2::DIGEST])
        );
    }

    #[test]
    fn non_canonical_digests_are_detected() {
        let mut d = Digest::ZERO;
        d.0[..4].copy_from_slice(&0x7f00_0001u32.to_le_bytes());
        assert!(!is_canonical(&d));
        assert!(is_canonical(&Digest::ZERO));
        assert!(!is_canonical(&Digest([0xff; 32])));
    }

    fn hex(d: &Digest) -> String {
        d.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
