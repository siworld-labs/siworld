//! A real N = 16 root proof at the decided FRI parameters, verified against
//! the pinned key in milliseconds, with no circuit built: what a verifying
//! node does. `tests/data` holds the proof and its statement (70 canonical
//! u32 little-endian words), exported by
//! `siworld-bench-plonky3 --acc --leaves 16 --export DIR`.

use std::sync::OnceLock;

use siworld_circuits::{
    ContainerPublic, ContainerVerifier, NUM_ROOT_PUBLIC, ROOT_ANCHORS, ROOT_CM_MINER, ROOT_COUNT,
    ROOT_HEIGHT, ROOT_SET, ROOT_SHARE,
};
use siworld_core::params::{ChainParams, CONTAINER_SIZE_STEPS};
use siworld_core::{Commitment, ContainerProof, Digest};
use siworld_crypto::SetSum;
use siworld_poseidon2::{encode, felt_from_canonical, FieldDigest, F};
use siworld_prover::{pinned_root_key, Plonky3System, ROOT_KEYS};

const PROOF: &[u8] = include_bytes!("data/root-proof-n16.bin");
const STATEMENT: &[u8] = include_bytes!("data/root-statement-n16.bin");

fn verifier() -> &'static Plonky3System {
    static V: OnceLock<Plonky3System> = OnceLock::new();
    V.get_or_init(|| {
        let params = ChainParams {
            container_size: 16,
            ..ChainParams::mainnet()
        };
        let system = Plonky3System::new(&params).expect("pinned key");
        assert!(!system.aggregates(), "a verifying node builds no circuit");
        assert_eq!(system.root_key(), pinned_root_key(16).unwrap());
        system
    })
}

fn words() -> [u32; NUM_ROOT_PUBLIC] {
    assert_eq!(STATEMENT.len(), 4 * NUM_ROOT_PUBLIC);
    std::array::from_fn(|i| u32::from_le_bytes(STATEMENT[4 * i..4 * i + 4].try_into().unwrap()))
}

fn felt(w: u32) -> F {
    felt_from_canonical(w).expect("canonical statement word")
}

fn digest(w: &[u32]) -> Digest {
    let fd: FieldDigest = std::array::from_fn(|i| felt(w[i]));
    Digest(encode(&fd))
}

fn public_from(w: &[u32; NUM_ROOT_PUBLIC]) -> ContainerPublic {
    ContainerPublic {
        set_sum: SetSum(std::array::from_fn(|i| felt(w[ROOT_SET + i]))),
        anchors_root: digest(&w[ROOT_ANCHORS..ROOT_HEIGHT]),
        height: u64::from(w[ROOT_HEIGHT]),
        miner_note_cm: Commitment(digest(&w[ROOT_CM_MINER..ROOT_SHARE])),
        miner_share: w[ROOT_SHARE..ROOT_COUNT]
            .iter()
            .enumerate()
            .map(|(k, &l)| u64::from(l) << (16 * k))
            .sum(),
        count: w[ROOT_COUNT],
    }
}

fn public() -> ContainerPublic {
    public_from(&words())
}

fn proof() -> ContainerProof {
    ContainerProof(PROOF.to_vec())
}

#[test]
fn every_container_size_step_has_a_distinct_pinned_key() {
    for n in CONTAINER_SIZE_STEPS {
        assert!(pinned_root_key(n).is_some(), "N = {n}");
    }
    // Each tree embeds the keys of the levels below it, so no two sizes
    // share a root key.
    for (i, (_, a)) in ROOT_KEYS.iter().enumerate() {
        for (_, b) in &ROOT_KEYS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn the_statement_round_trips() {
    let values = public().public_values().expect("representable statement");
    let back: Vec<u32> = values
        .iter()
        .map(siworld_poseidon2::PrimeField32::as_canonical_u32)
        .collect();
    assert_eq!(back, words());
    assert_eq!(public().count, 16);
}

#[test]
fn a_real_root_proof_verifies() {
    assert!(verifier().verify(&public(), &proof()));
}

#[test]
fn the_proof_binds_every_statement_field() {
    let edits: [(usize, &str); 7] = [
        (ROOT_SET, "ΣE"),
        (ROOT_SET + 47, "ΣE"),
        (ROOT_ANCHORS + 3, "𝒜 root"),
        (ROOT_HEIGHT, "height"),
        (ROOT_CM_MINER + 7, "miner package commitment"),
        (ROOT_SHARE, "miner share"),
        (ROOT_SHARE + 3, "miner share"),
    ];
    for (at, field) in edits {
        let mut w = words();
        w[at] = (w[at] + 1) % 0x7f00_0001;
        assert!(
            !verifier().verify(&public_from(&w), &proof()),
            "{field} at {at} is not bound"
        );
    }
}

#[test]
fn the_proof_binds_its_container_size() {
    for count in [32, 64, 128, 15, 17, 0] {
        let mut p = public();
        p.count = count;
        assert!(!verifier().verify(&p, &proof()), "count {count}");
    }
}

#[test]
fn an_unrepresentable_statement_is_rejected() {
    let mut p = public();
    p.height = u64::MAX;
    assert!(!verifier().verify(&p, &proof()));
    let mut p = public();
    p.anchors_root = Digest([0xff; 32]);
    assert!(!verifier().verify(&p, &proof()));
}

#[test]
fn malformed_proofs_are_rejected_without_panicking() {
    let p = public();
    let mut cases = vec![
        Vec::new(),
        vec![0; 64],
        PROOF[..PROOF.len() - 1].to_vec(),
        PROOF[..PROOF.len() / 2].to_vec(),
        [PROOF, &[0]].concat(),
    ];
    for at in [
        0,
        8,
        11,
        16,
        64,
        PROOF.len() / 3,
        PROOF.len() / 2,
        PROOF.len() - 1,
    ] {
        let mut b = PROOF.to_vec();
        b[at] ^= 1;
        cases.push(b);
    }
    for bytes in cases {
        assert!(!verifier().verify(&p, &ContainerProof(bytes)));
    }
}

#[test]
fn a_mock_proof_is_rejected() {
    // The mock container proof is the statement digest; it is no STARK.
    let mock = ContainerProof(vec![0x5a; 32]);
    assert!(!verifier().verify(&public(), &mock));
}

#[test]
fn the_system_can_be_shared_across_threads() {
    fn shareable<T: Send + Sync>() {}
    shareable::<Plonky3System>();
}
