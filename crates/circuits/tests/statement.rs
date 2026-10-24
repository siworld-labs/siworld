//! Container root statement: the public values the container proof binds
//! (docs/protocol.md, "the merge statement").

use siworld_circuits::{
    ContainerPublic, ContainerVerifier, MockProver, MockVerifier, HEIGHT_BITS, NUM_ROOT_PUBLIC,
    ROOT_ANCHORS, ROOT_CM_MINER, ROOT_COUNT, ROOT_HEIGHT, ROOT_SET, ROOT_SHARE,
};
use siworld_core::params::COINBASE_MATURITY;
use siworld_core::{Commitment, Digest};
use siworld_crypto::{SetSum, SET_LEN};
use siworld_poseidon2::{encode, FieldDigest, PrimeCharacteristicRing, DIGEST, F, LIMBS};

fn digest(first: u32) -> (Digest, FieldDigest) {
    let f: FieldDigest = core::array::from_fn(|i| F::from_u32(first + i as u32));
    (Digest(encode(&f)), f)
}

fn public() -> ContainerPublic {
    ContainerPublic {
        set_sum: SetSum(core::array::from_fn(|i| F::from_u32(1_000 + i as u32))),
        anchors_root: digest(100).0,
        height: 7,
        miner_note_cm: Commitment(digest(200).0),
        miner_share: 0x0004_0003_0002_0001,
        count: 4,
    }
}

#[test]
fn public_values_follow_the_root_layout() {
    assert_eq!(ROOT_SET, 0);
    assert_eq!(ROOT_ANCHORS, SET_LEN);
    assert_eq!(ROOT_HEIGHT, ROOT_ANCHORS + DIGEST);
    assert_eq!(ROOT_CM_MINER, ROOT_HEIGHT + 1);
    assert_eq!(ROOT_SHARE, ROOT_CM_MINER + DIGEST);
    assert_eq!(ROOT_COUNT, ROOT_SHARE + LIMBS);
    assert_eq!(NUM_ROOT_PUBLIC, 70);

    let p = public();
    let v = p.public_values().expect("in range");
    assert_eq!(v[ROOT_SET..ROOT_ANCHORS], p.set_sum.0);
    assert_eq!(v[ROOT_ANCHORS..ROOT_HEIGHT], digest(100).1);
    assert_eq!(v[ROOT_HEIGHT], F::from_u32(7));
    assert_eq!(v[ROOT_CM_MINER..ROOT_SHARE], digest(200).1);
    // The share is four little-endian 16-bit limbs.
    assert_eq!(v[ROOT_SHARE..ROOT_COUNT], [1, 2, 3, 4].map(F::from_u32));
    assert_eq!(v[ROOT_COUNT], F::from_u32(4));
}

#[test]
fn public_values_reject_what_the_circuit_cannot_express() {
    let non_canonical = Digest([0xff; 32]);
    let mut p = public();
    p.anchors_root = non_canonical;
    assert_eq!(p.public_values(), None);

    let mut p = public();
    p.miner_note_cm = Commitment(non_canonical);
    assert_eq!(p.public_values(), None);

    // The root decomposes the height and the unlock height into HEIGHT_BITS bits.
    let limit = (1u64 << HEIGHT_BITS) - COINBASE_MATURITY;
    let mut p = public();
    p.height = limit - 1;
    assert!(p.public_values().is_some());
    p.height = limit;
    assert_eq!(p.public_values(), None);
    p.height = u64::MAX;
    assert_eq!(p.public_values(), None);

    let mut p = public();
    p.count = u32::MAX;
    assert_eq!(p.public_values(), None);
}

#[test]
fn mock_verifier_binds_every_public_value() {
    let p = public();
    let proof = MockProver::prove_statement(&p).expect("in range");
    assert!(MockVerifier.verify(&p, &proof));

    let edits: [fn(&mut ContainerPublic); 8] = [
        |p| p.set_sum.0[0] += F::ONE,
        |p| p.set_sum.0[SET_LEN - 1] += F::ONE,
        |p| p.anchors_root = digest(101).0,
        |p| p.height += 1,
        |p| p.miner_note_cm = Commitment(digest(201).0),
        |p| p.miner_share += 1,
        |p| p.miner_share += 1 << 48,
        |p| p.count += 1,
    ];
    for edit in edits {
        let mut q = public();
        edit(&mut q);
        assert!(!MockVerifier.verify(&q, &proof), "{q:?}");
    }

    let mut out = public();
    out.height = 1 << HEIGHT_BITS;
    assert_eq!(MockProver::prove_statement(&out), None);
}
