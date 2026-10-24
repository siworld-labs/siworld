//! The benchmark's hasher is the protocol's: it agrees with the native
//! implementation in `crates/poseidon2` on the permutation, the tagged sponge,
//! the set element E, Merkle compression and u64 limbs, and both decode only
//! canonical elements. Its relation constants are the protocol's (`crates/core`).

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_bench_common::{
    DCT_BYTES, F, Hasher, PublicInputs, felt_from_canonical, limbs, pack_dct,
};
use siworld_poseidon2::Poseidon2;

/// Deterministic pseudorandom elements (xorshift), reduced below p.
fn elements<const N: usize>(seed: &mut u64) -> [F; N] {
    core::array::from_fn(|_| {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        F::from_u32((*seed % u64::from(F::ORDER_U32)) as u32)
    })
}

#[test]
fn hasher_agrees_with_the_native_implementation() {
    let (bench, native) = (Hasher::new(), Poseidon2::new());
    let mut seed = 0x5157_0a1d_u64;
    for round in 0..64u32 {
        let state = elements::<16>(&mut seed);
        assert_eq!(bench.permute(state), native.permute(state));

        let (a, b) = (elements::<8>(&mut seed), elements::<8>(&mut seed));
        assert_eq!(bench.compress(&a, &b), native.compress(&a, &b));

        let blocks: Vec<[F; 8]> = (0..=round % 6).map(|_| elements(&mut seed)).collect();
        let tag = round % 12;
        assert_eq!(bench.sponge(tag, &blocks), native.sponge(tag, &blocks));

        let public = PublicInputs {
            nf: [elements(&mut seed), elements(&mut seed)],
            cm_out: [elements(&mut seed), elements(&mut seed)],
            anchor: [F::ZERO; 8],
            fee_commit: [F::ZERO; 8],
        };
        // d_ct is BLAKE3 output: raw bytes, packed into 16-bit limbs by both sides.
        let mut d_ct = [0u8; DCT_BYTES];
        for chunk in d_ct.chunks_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            chunk.copy_from_slice(&seed.to_le_bytes());
        }
        let packed = pack_dct(&d_ct);
        assert_eq!(packed, siworld_poseidon2::pack_dct(&d_ct));
        assert_eq!(
            public.set_element(&bench, &packed),
            native.set_element(&public.nf, &public.cm_out, &d_ct)
        );

        let x = u64::from(round).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        assert_eq!(limbs(x), siworld_poseidon2::limbs(x));
    }
}

#[test]
fn tags_match_the_registry() {
    use siworld_bench_common as b;
    use siworld_poseidon2::tag;
    assert_eq!(b::TAG_OWNER, tag::OWNER);
    assert_eq!(b::TAG_NOTE, tag::NOTE);
    assert_eq!(b::TAG_NF, tag::NF);
    assert_eq!(b::TAG_RHO, tag::RHO_OUT_0);
    assert_eq!(b::TAG_RHO + 1, tag::RHO_OUT_1);
    assert_eq!(b::TAG_SET, tag::SET);
    assert_eq!(b::TAG_ACC_NODE, tag::MERGE_NODE);
    assert_eq!(b::TAG_ANCHOR, tag::ANCHOR);
    assert_eq!(b::TAG_MINER_RHO, tag::MINER_RHO);
}

#[test]
fn both_decode_only_canonical_elements() {
    for x in [
        0,
        1,
        F::ORDER_U32 - 1,
        F::ORDER_U32,
        F::ORDER_U32 + 1,
        u32::MAX,
    ] {
        assert_eq!(
            felt_from_canonical(x),
            siworld_poseidon2::felt_from_canonical(x),
            "{x:#x}"
        );
    }
}

#[test]
fn relation_constants_match_the_protocol() {
    use siworld_core::params;
    assert_eq!(
        siworld_bench_common::MIN_PACKAGE_DEPOSIT,
        params::MIN_PACKAGE_DEPOSIT
    );
    assert_eq!(
        siworld_bench_common::FEE_BASE,
        params::INITIAL_REWARD / params::FEE_BASE_DIVISOR
    );
    assert_eq!(
        siworld_bench_common::MINER_SHARE,
        siworld_core::issuance::reward_split(params::INITIAL_REWARD).0
    );
    assert_eq!(
        siworld_bench_common::COINBASE_MATURITY,
        params::COINBASE_MATURITY
    );
}
