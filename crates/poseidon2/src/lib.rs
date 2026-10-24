//! Poseidon2 over KoalaBear, width 16: the in-circuit hash fixed in
//! docs/protocol.md ("Poseidon2 instance"), and the canonical byte encoding
//! of its digests.
//!
//! This is the single native implementation. Every value the slot circuit
//! recomputes (note commitments, nullifiers, commitment-tree nodes, 𝒜
//! entries, set elements E) must be built from these functions, so native
//! code and circuit cannot drift apart. Test vectors pin the permutation and,
//! through it, Plonky3's round constants; the benchmark circuit in
//! `crates/bench-stark` is checked against this crate.
//!
//! The domain tags and the packing of u64 values follow docs/protocol.md
//! ("Poseidon2 packing and domain tags").
#![no_std]

pub use p3_field::{PrimeCharacteristicRing, PrimeField32};
pub use p3_koala_bear::KoalaBear as F;
use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
use p3_symmetric::Permutation;

/// Permutation width.
pub const WIDTH: usize = 16;
/// Sponge rate: elements absorbed per permutation.
pub const RATE: usize = 8;
/// Digest length in field elements.
pub const DIGEST: usize = 8;
/// Bytes in an encoded digest: one little-endian u32 per element.
pub const DIGEST_BYTES: usize = 4 * DIGEST;

/// Bits per limb of a u64 value.
pub const LIMB_BITS: u32 = 16;
/// Limbs per u64 value.
pub const LIMBS: usize = 4;
/// Elements of a set element E: six squeezes.
pub const SET_LEN: usize = 6 * DIGEST;
/// Bytes of the ciphertext digest d_ct (BLAKE3).
pub const DCT_BYTES: usize = 32;
/// Elements d_ct packs to: 16-bit limbs, two sponge blocks.
pub const DCT_LEN: usize = DCT_BYTES / 2;

/// The domain-tag registry (docs/protocol.md). Numbers are never reused; 6
/// and 7 are retired.
pub mod tag {
    pub const OWNER: u32 = 1;
    pub const NOTE: u32 = 2;
    pub const NF: u32 = 3;
    /// ρ of output j uses `RHO_OUT_0 + j`.
    pub const RHO_OUT_0: u32 = 4;
    pub const RHO_OUT_1: u32 = 5;
    pub const SET: u32 = 8;
    /// Merge-node statement digest, internal to the proof tree.
    pub const MERGE_NODE: u32 = 9;
    pub const ANCHOR: u32 = 10;
    /// ρ of the miner package of a block.
    pub const MINER_RHO: u32 = 11;
    /// ρ of a development-fund payout, by block height and index.
    pub const PAYOUT_RHO: u32 = 12;
}

/// A Poseidon2 digest.
pub type FieldDigest = [F; DIGEST];
/// One sponge block.
pub type Block = [F; RATE];

pub struct Poseidon2 {
    perm: Poseidon2KoalaBear<WIDTH>,
}

impl Default for Poseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2 {
    /// Plonky3's KoalaBear width-16 instance: 8 full and 20 partial rounds,
    /// S-box x³, built-in round constants.
    pub fn new() -> Self {
        Self {
            perm: default_koalabear_poseidon2_16(),
        }
    }

    pub fn permute(&self, state: [F; WIDTH]) -> [F; WIDTH] {
        self.perm.permute(state)
    }

    /// Overwrite-mode sponge with a domain tag. The first permutation input is
    /// `[block₀, tag, number of blocks, 0 × 6]`; each later block overwrites
    /// the rate and keeps the capacity of the previous output. The digest is
    /// the first [`DIGEST`] elements of the last output. Every tag has a fixed
    /// input length, so no padding rule is needed.
    ///
    /// # Panics
    ///
    /// If `blocks` is empty.
    pub fn sponge(&self, tag: u32, blocks: &[Block]) -> FieldDigest {
        digest_of(&self.absorb(tag, blocks))
    }

    /// [`Self::sponge`] squeezed to `out.len()` elements, a multiple of
    /// [`DIGEST`]: each further squeeze zeroes the rate and permutes again.
    /// The first [`DIGEST`] elements equal the sponge digest.
    ///
    /// # Panics
    ///
    /// If `blocks` is empty or `out.len()` is not a positive multiple of
    /// [`DIGEST`].
    pub fn squeeze(&self, tag: u32, blocks: &[Block], out: &mut [F]) {
        assert!(
            !out.is_empty() && out.len().is_multiple_of(DIGEST),
            "squeeze whole digests"
        );
        let mut state = self.absorb(tag, blocks);
        let mut chunks = out.as_chunks_mut::<DIGEST>().0.iter_mut();
        *chunks.next().expect("non-empty") = digest_of(&state);
        for chunk in chunks {
            state[..RATE].fill(F::ZERO);
            state = self.permute(state);
            *chunk = digest_of(&state);
        }
    }

    fn absorb(&self, tag: u32, blocks: &[Block]) -> [F; WIDTH] {
        assert!(!blocks.is_empty(), "a sponge absorbs at least one block");
        let mut state = [F::ZERO; WIDTH];
        state[RATE] = F::from_u32(tag);
        state[RATE + 1] = F::from_usize(blocks.len());
        for block in blocks {
            state[..RATE].copy_from_slice(block);
            state = self.permute(state);
        }
        state
    }

    /// Set element of a slot (docs/protocol.md, "the merge statement"):
    /// `E = Poseidon2(TAG_SET; nf₀, nf₁, cm₀, cm₁, d_ct)` squeezed to
    /// [`SET_LEN`] elements, with d_ct packed by [`pack_dct`].
    pub fn set_element(
        &self,
        nf: &[FieldDigest; 2],
        cm: &[FieldDigest; 2],
        d_ct: &[u8; DCT_BYTES],
    ) -> [F; SET_LEN] {
        let d = pack_dct(d_ct);
        let (lo, hi) = d.split_at(RATE);
        let blocks = [
            nf[0],
            nf[1],
            cm[0],
            cm[1],
            lo.try_into().expect("one block"),
            hi.try_into().expect("one block"),
        ];
        let mut e = [F::ZERO; SET_LEN];
        self.squeeze(tag::SET, &blocks, &mut e);
        e
    }

    /// Merkle 2-to-1 compression: the first [`DIGEST`] elements of
    /// `permute(left ‖ right)`.
    pub fn compress(&self, left: &FieldDigest, right: &FieldDigest) -> FieldDigest {
        let mut state = [F::ZERO; WIDTH];
        state[..DIGEST].copy_from_slice(left);
        state[DIGEST..].copy_from_slice(right);
        digest_of(&self.permute(state))
    }
}

fn digest_of(state: &[F; WIDTH]) -> FieldDigest {
    core::array::from_fn(|i| state[i])
}

/// A u64 as four 16-bit little-endian limbs, the packing of every integer
/// that enters a hash.
pub fn limbs(x: u64) -> [F; LIMBS] {
    core::array::from_fn(|i| F::from_u16((x >> (LIMB_BITS * i as u32)) as u16))
}

/// d_ct's bytes as [`DCT_LEN`] little-endian 16-bit limbs, so every element
/// is canonical and the packing is injective.
pub fn pack_dct(d_ct: &[u8; DCT_BYTES]) -> [F; DCT_LEN] {
    core::array::from_fn(|k| F::from_u16(u16::from_le_bytes([d_ct[2 * k], d_ct[2 * k + 1]])))
}

/// Decodes a field element from its canonical u32, the unique representative
/// below p. Since 2p < 2^32, every element x also has the spelling x + p, so a
/// decoder that reduced instead of rejecting would give one nullifier two
/// on-chain encodings (docs/cryptography.md).
pub fn felt_from_canonical(x: u32) -> Option<F> {
    (x < F::ORDER_U32).then(|| F::from_u32(x))
}

/// A digest's on-chain bytes: each element's canonical u32, little-endian.
pub fn encode(digest: &FieldDigest) -> [u8; DIGEST_BYTES] {
    let mut out = [0; DIGEST_BYTES];
    for (chunk, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(digest) {
        *chunk = x.as_canonical_u32().to_le_bytes();
    }
    out
}

/// Inverse of [`encode`]; `None` unless every element is canonical.
pub fn decode(bytes: &[u8; DIGEST_BYTES]) -> Option<FieldDigest> {
    let mut out = [F::ZERO; DIGEST];
    for (x, chunk) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *x = felt_from_canonical(u32::from_le_bytes(*chunk))?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felts<const N: usize>(words: [u32; N]) -> [F; N] {
        words.map(|w| felt_from_canonical(w).expect("canonical"))
    }

    fn counting<const N: usize>(from: u32) -> [F; N] {
        core::array::from_fn(|i| F::from_u32(from + i as u32))
    }

    // Vectors computed with the benchmark circuit's reference hasher
    // (crates/bench-stark/common, Plonky3 0.9.0-rc.2), which
    // crates/bench-stark/common/tests/native.rs checks against this crate.

    #[test]
    fn permutation_matches_its_vector() {
        let expected = felts([
            0x4b134812, 0x278ba7f8, 0x76944b51, 0x1c672bb2, 0x31dfa6bb, 0x6b7e9d79, 0x4945e876,
            0x78a321a8, 0x7a73bc0a, 0x5cc8abbc, 0x56beb8c0, 0x57b4c9a2, 0x193b9df3, 0x15194d64,
            0x47ba9576, 0x5eeccb64,
        ]);
        assert_eq!(Poseidon2::new().permute(counting(0)), expected);
    }

    #[test]
    fn sponge_matches_its_vector() {
        let expected = felts([
            0x5788c3e3, 0x4cd3e9fd, 0x2c89a733, 0x5c87d224, 0x405c351e, 0x598e6456, 0x031962da,
            0x1d0de44b,
        ]);
        let h = Poseidon2::new();
        assert_eq!(h.sponge(2, &[counting(1), counting(9)]), expected);
    }

    #[test]
    fn set_element_squeeze_matches_its_vector() {
        // E of nf₀ = 1..8, nf₁ = 9..16, cm₀ = 17..24, cm₁ = 25..32, d_ct = 33..48.
        let h = Poseidon2::new();
        let blocks = [1, 9, 17, 25, 33, 41].map(counting);
        let mut e = [F::ZERO; SET_LEN];
        h.squeeze(tag::SET, &blocks, &mut e);
        assert_eq!(e[..DIGEST], h.sponge(tag::SET, &blocks));
        let first = felts([
            0x137cdaa1, 0x2cc6f3e2, 0x4331da3e, 0x2800aa39, 0x3aab806e, 0x28a544b2, 0x0847888a,
            0x599c5571,
        ]);
        let last = felts([
            0x7bd246c5, 0x6241eb65, 0x24860629, 0x13ec44d9, 0x577a369a, 0x4271b1b7, 0x1c15b7c4,
            0x1a8fb894,
        ]);
        assert_eq!(e[..DIGEST], first);
        assert_eq!(e[SET_LEN - DIGEST..], last);
    }

    #[test]
    fn pack_dct_is_sixteen_little_endian_limbs() {
        let mut d_ct = [0u8; DCT_BYTES];
        d_ct[0] = 0x01;
        d_ct[1] = 0x02;
        d_ct[31] = 0xff;
        let packed = pack_dct(&d_ct);
        assert_eq!(packed[0], F::from_u32(0x0201));
        assert_eq!(packed[15], F::from_u32(0xff00));
        assert!(packed[1..15].iter().all(|x| *x == F::ZERO));
    }

    #[test]
    fn set_element_matches_its_vector() {
        // The squeeze vector above, reached from slot data: nf₀ = 1..8,
        // nf₁ = 9..16, cm₀ = 17..24, cm₁ = 25..32, and d_ct bytes that pack
        // to the limbs 33..48.
        let mut d_ct = [0u8; DCT_BYTES];
        for k in 0..DCT_LEN {
            d_ct[2 * k] = 33 + k as u8;
        }
        let h = Poseidon2::new();
        let e = h.set_element(
            &[counting(1), counting(9)],
            &[counting(17), counting(25)],
            &d_ct,
        );
        let blocks = [1, 9, 17, 25, 33, 41].map(counting);
        let mut expected = [F::ZERO; SET_LEN];
        h.squeeze(tag::SET, &blocks, &mut expected);
        assert_eq!(e, expected);
    }

    #[test]
    fn compress_matches_its_vector() {
        let expected = felts([
            0x51b983ef, 0x53100557, 0x75ce2051, 0x672bb9ae, 0x2ca97354, 0x793b3cee, 0x5abc3022,
            0x5aff2380,
        ]);
        assert_eq!(
            Poseidon2::new().compress(&counting(1), &counting(9)),
            expected
        );
    }

    #[test]
    fn tags_and_block_order_separate_sponge_outputs() {
        let h = Poseidon2::new();
        let (a, b) = (counting(1), counting(9));
        assert_ne!(h.sponge(2, &[a, b]), h.sponge(3, &[a, b]));
        assert_ne!(h.sponge(2, &[a, b]), h.sponge(2, &[b, a]));
        assert_ne!(h.sponge(2, &[a]), h.sponge(2, &[a, a]));
        // The block count separates an input from its zero-extended form.
        assert_ne!(h.sponge(2, &[a]), h.sponge(2, &[a, [F::ZERO; RATE]]));
    }

    #[test]
    fn limbs_are_16_bit_little_endian() {
        assert_eq!(
            limbs(0x0123_4567_89ab_cdef),
            felts([0xcdef, 0x89ab, 0x4567, 0x0123])
        );
        assert_eq!(limbs(u64::MAX), felts([0xffff; LIMBS]));
    }

    #[test]
    fn encoding_round_trips() {
        let d = Poseidon2::new().compress(&counting(1), &counting(9));
        let bytes = encode(&d);
        assert_eq!(&bytes[..4], &0x51b983efu32.to_le_bytes());
        assert_eq!(decode(&bytes), Some(d));
    }

    #[test]
    fn decoding_rejects_every_non_canonical_element() {
        let p = F::ORDER_U32;
        assert_eq!(p, 0x7f00_0001);
        assert_eq!(felt_from_canonical(p - 1), Some(F::NEG_ONE));
        assert_eq!(felt_from_canonical(p), None);
        assert_eq!(felt_from_canonical(u32::MAX), None);

        let zero = encode(&[F::ZERO; DIGEST]);
        for i in 0..DIGEST {
            // The second spelling of 0, in each position.
            let mut alias = zero;
            alias[4 * i..4 * i + 4].copy_from_slice(&p.to_le_bytes());
            assert_eq!(decode(&alias), None, "element {i}");
        }
        assert_eq!(decode(&zero), Some([F::ZERO; DIGEST]));
    }
}
