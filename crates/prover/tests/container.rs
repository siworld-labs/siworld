//! The Plonky3 system end to end, at `FriParams::fast()` (insecure, quick):
//! a wallet proves a payment, the producer pads the container and aggregates
//! a real root proof, and consensus accepts the block through the same
//! `check_proof` a validator runs. Tampering with anything the root statement
//! binds makes the proof fail.

use std::sync::{Arc, OnceLock};

use siworld_circuits::{
    encrypt_outputs, output_rhos, ContainerPublic, FeeOpening, InputWitness, ProofSystem,
    ProveError, RelationContext, RelationError, SlotWitness,
};
use siworld_consensus::{build_block, check_proof, BlockError, Chain, Miner, PendingTx};
use siworld_core::issuance::{block_reward, epoch_of, fee_base, reward_split};
use siworld_core::params::ChainParams;
use siworld_core::{Commitment, Condition, ContainerProof, Digest, Note};
use siworld_crypto::{expand, note_commitment, SecretSeed, SetSum, SpendKey};
use siworld_prover::{Plonky3System, SetupError};
use siworld_state::ChainState;

const SI: u64 = 100_000_000;

fn seed(tag: u64) -> Digest {
    expand(&Digest([0x51; 32]), "prover test", tag)
}

fn key(i: u64) -> SpendKey {
    SpendKey::from_digest(seed(100 + i))
}

/// Four slots per block: two aggregation levels, so a node proof is itself
/// aggregated (the root merges node proofs, not leaves).
fn params() -> ChainParams {
    ChainParams {
        container_size: 4,
        ..ChainParams::devnet()
    }
}

/// Prepared once: the setup proves a sample node per level.
fn system() -> Arc<Plonky3System> {
    static SYSTEM: OnceLock<Arc<Plonky3System>> = OnceLock::new();
    SYSTEM
        .get_or_init(|| Arc::new(Plonky3System::insecure_fast(&params(), true).expect("setup")))
        .clone()
}

fn miner() -> Miner {
    Miner {
        address: key(9).address(),
        committee_key: seed(7),
    }
}

/// Genesis holding one 10 SI package of `key(1)`.
fn genesis() -> (ChainState, Note) {
    let note = Note {
        owner: key(1).owner(),
        value: 10 * SI,
        cond: Condition::default(),
        rho: seed(1),
        rseed: seed(2),
    };
    let state = ChainState::genesis_with_commitments(&params(), &[note_commitment(&note)]);
    (state, note)
}

/// A payment of 3 SI from `key(1)`'s genesis package to `key(2)`, the change
/// back to `key(1)`, at the standard fee of the anchor's epoch.
fn payment(state: &ChainState, note: &Note, fee_delta: i64) -> SlotWitness {
    let (anchor, height) = state.anchors.latest().unwrap();
    let fee = (fee_base(epoch_of(height)) as i64 + fee_delta) as u64;
    let inputs = [
        InputWitness::Real {
            note: *note,
            sk: key(1),
            path: state.commitments.path(0).unwrap(),
        },
        InputWitness::Dummy {
            nk: seed(3),
            rho: seed(4),
        },
    ];
    let rho = output_rhos(&inputs);
    let outputs = [
        Note {
            owner: key(2).owner(),
            value: 3 * SI,
            cond: Condition::default(),
            rho: rho[0],
            rseed: seed(5),
        },
        Note {
            owner: key(1).owner(),
            value: 7 * SI - fee,
            cond: Condition::default(),
            rho: rho[1],
            rseed: seed(6),
        },
    ];
    let (ct, tag) = encrypt_outputs(
        &outputs,
        [&key(2).address(), &key(1).address()],
        [seed(10), seed(11)],
    );
    SlotWitness {
        anchor,
        inputs,
        outputs,
        ct,
        tag,
        fee,
    }
}

fn ctx(state: &ChainState) -> RelationContext<'_> {
    RelationContext {
        anchors: &state.anchors,
        tree_depth: params().commitment_tree_depth,
    }
}

#[test]
fn wallet_proof_producer_aggregation_and_validator_check() {
    let system = system();
    let p = params();
    let (state, note) = genesis();

    // The wallet's leaf proof is bound to its slot, its fee and its anchor.
    let w = payment(&state, &note, 0);
    let (slot, proof, fee) = system
        .prove_slot(&ctx(&state), &w, seed(12))
        .expect("prove");
    assert!(system.verify_slot(&state.anchors, &slot, &proof, &fee));
    assert_eq!(proof.slot_id, slot.id());
    assert_eq!(proof.anchor, w.anchor);
    assert!(!proof.body.is_empty());
    let other_fee = FeeOpening {
        fee: fee.fee * 4,
        blind: fee.blind,
    };
    assert!(
        !system.verify_slot(&state.anchors, &slot, &proof, &other_fee),
        "the fee opening is bound"
    );
    let mut other_slot = slot;
    other_slot.cm[0] = Commitment(seed(13));
    assert!(
        !system.verify_slot(&state.anchors, &other_slot, &proof, &fee),
        "the slot's commitments are bound"
    );
    let mut other_slot = slot;
    other_slot.tag[1] ^= 1;
    assert!(
        !system.verify_slot(&state.anchors, &other_slot, &proof, &fee),
        "every ciphertext byte is bound through d_ct"
    );
    let mut torn = proof.clone();
    torn.body.truncate(torn.body.len() - 1);
    assert!(!system.verify_slot(&state.anchors, &slot, &torn, &fee));
    let mut flipped = proof.clone();
    let mid = flipped.body.len() / 2;
    flipped.body[mid] ^= 1;
    assert!(
        !system.verify_slot(&state.anchors, &slot, &flipped, &fee),
        "a flipped proof byte"
    );

    // The producer pads the container, proves the miner package and the
    // validator accepts the block.
    let tx = PendingTx {
        slot,
        proof,
        fee,
        nonce: 0,
    };
    let block = build_block(
        &state,
        &state.anchors,
        &p,
        system.as_ref(),
        &miner(),
        std::slice::from_ref(&tx),
        &[],
        &SecretSeed::from_os_rng().unwrap(),
        state.timestamp() + p.target_block_time,
    )
    .expect("build");
    assert_eq!(block.body.slots.len(), 4);
    assert!(block.proof.0.len() < 4 << 20, "within MAX_PROOF_LEN");
    let height = state.height + 1;
    check_proof(&block.proof, &state, &block.body, height, system.as_ref()).expect("valid");
    let mut chain = Chain::new(p.clone(), state.clone(), system.clone());
    chain.apply_block(&block).expect("block accepted");
    assert_eq!(chain.state.height, height);

    // Everything the root statement binds.
    let mut body = block.body.clone();
    body.coinbase.miner_note_cm = Commitment(seed(14));
    assert_eq!(
        check_proof(&block.proof, &state, &body, height, system.as_ref()),
        Err(BlockError::BadProof),
        "another miner package"
    );
    let mut body = block.body.clone();
    body.slots.swap(0, 3);
    check_proof(&block.proof, &state, &body, height, system.as_ref())
        .expect("ΣE ignores the slot order");
    let mut body = block.body.clone();
    body.slots[2].ct[0].0[7] ^= 1;
    assert_eq!(
        check_proof(&block.proof, &state, &body, height, system.as_ref()),
        Err(BlockError::BadProof),
        "a changed ciphertext byte in an empty package"
    );
    assert_eq!(
        check_proof(
            &block.proof,
            &state,
            &block.body,
            height + 1,
            system.as_ref()
        ),
        Err(BlockError::BadProof),
        "another height"
    );
    let mut bytes = block.proof.0.clone();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    assert_eq!(
        check_proof(
            &ContainerProof(bytes),
            &state,
            &block.body,
            height,
            system.as_ref()
        ),
        Err(BlockError::BadProof),
        "a flipped proof byte"
    );
    let public = ContainerPublic {
        set_sum: SetSum::of(&block.body.slots),
        anchors_root: state.anchors.accumulator_root(),
        height,
        miner_note_cm: block.body.coinbase.miner_note_cm,
        miner_share: reward_split(block_reward(epoch_of(height))).0,
        count: 4,
    };
    assert!(system.verify_container(&public, &block.proof));
    assert!(
        !system.verify_container(
            &ContainerPublic {
                miner_share: public.miner_share + 1,
                ..public
            },
            &block.proof
        ),
        "the share is bound to the package"
    );
    assert!(
        !system.verify_container(&ContainerPublic { count: 2, ..public }, &block.proof),
        "the count is bound"
    );
}

#[test]
fn witnesses_that_break_the_relation_are_refused_before_proving() {
    let system = system();
    let (state, note) = genesis();
    let w = payment(&state, &note, 1);
    assert_eq!(
        system.prove_slot(&ctx(&state), &w, seed(12)).err(),
        Some(ProveError::Relation(RelationError::BadFee))
    );
}

#[test]
fn reused_subtrees_still_bind_new_leaves_anchors_and_root_witnesses() {
    use siworld_circuits::{dummy::dummy_slot, Leaf};
    use siworld_crypto::miner_rho;

    let system = system();
    let (state, _) = genesis();
    let entropy = SecretSeed::from_os_rng().unwrap();
    let anchor = state.anchors.latest().unwrap().0;
    let mut entries: Vec<_> = (0..4)
        .map(|i| {
            let (slot, proof, fee) = dummy_slot(
                system.as_ref(),
                &ctx(&state),
                anchor,
                &entropy.derive("cache test", 0),
                i,
            );
            PendingTx {
                slot,
                proof,
                fee,
                nonce: 0,
            }
        })
        .collect();
    let share = reward_split(block_reward(epoch_of(1))).0;
    let mut note = Note {
        owner: key(9).owner(),
        value: share,
        cond: Condition { unlock_height: 101 },
        rho: miner_rho(1),
        rseed: seed(890),
    };
    let prove = |entries: &[PendingTx], anchors: &siworld_state::RecentRoots, note: &Note| {
        let leaves: Vec<_> = entries
            .iter()
            .map(|t| Leaf {
                slot: &t.slot,
                proof: &t.proof,
                fee: &t.fee,
            })
            .collect();
        system.prove_container(anchors, 1, &leaves, note, share)
    };
    let public = |entries: &[PendingTx], anchors: &siworld_state::RecentRoots, note: &Note| {
        ContainerPublic {
            set_sum: SetSum::of(entries.iter().map(|t| &t.slot)),
            anchors_root: anchors.accumulator_root(),
            height: 1,
            miner_note_cm: note_commitment(note),
            miner_share: share,
            count: 4,
        }
    };
    let first = prove(&entries, &state.anchors, &note).unwrap();
    assert!(system.verify_container(&public(&entries, &state.anchors, &note), &first));
    entries.reverse();
    note.rseed = seed(891);
    let warm = prove(&entries, &state.anchors, &note).unwrap();
    assert!(system.verify_container(&public(&entries, &state.anchors, &note), &warm));
    assert!(
        !system.verify_container(&public(&entries, &state.anchors, &note), &first),
        "cached root must not retain old miner witness"
    );
    let original = entries[1].clone();
    entries[1].slot.tag[0] ^= 1;
    assert!(
        prove(&entries, &state.anchors, &note).is_err(),
        "warm cache must not bypass slot/proof binding"
    );
    entries[1] = original;
    let (slot, proof, fee) = dummy_slot(
        system.as_ref(),
        &ctx(&state),
        anchor,
        &entropy.derive("replacement", 0),
        0,
    );
    entries[1] = PendingTx {
        slot,
        proof,
        fee,
        nonce: 0,
    };
    let changed = prove(&entries, &state.anchors, &note).unwrap();
    assert!(system.verify_container(&public(&entries, &state.anchors, &note), &changed));
    assert!(!system.verify_container(&public(&entries, &state.anchors, &note), &warm));
    let mut anchors = state.anchors.clone();
    anchors.push(key(8).owner(), 1);
    let advanced = prove(&entries, &anchors, &note).unwrap();
    assert!(system.verify_container(&public(&entries, &anchors, &note), &advanced));
    assert!(
        !system.verify_container(&public(&entries, &anchors, &note), &changed),
        "different accumulator root must invalidate every old subtree"
    );
}

#[test]
fn unsupported_parameters_are_refused() {
    let p = params();
    for n in [0, 1, 3, 256] {
        let bad = ChainParams {
            container_size: n,
            ..p.clone()
        };
        assert_eq!(
            Plonky3System::insecure_fast(&bad, false).err(),
            Some(SetupError::ContainerSize(n))
        );
    }
    let bad = ChainParams {
        anchor_window: 8,
        ..p.clone()
    };
    assert_eq!(
        Plonky3System::insecure_fast(&bad, false).err(),
        Some(SetupError::AnchorWindow(8))
    );
    let bad = ChainParams {
        commitment_tree_depth: 12,
        ..p
    };
    assert_eq!(
        Plonky3System::insecure_fast(&bad, false).err(),
        Some(SetupError::TreeDepth(12))
    );
}

/// Key setup is deterministic: two independent builds of the circuits give
/// the same root verifying key, a proof from one verifies under a node that
/// trusts only the key, and a key of another container size is refused.
#[test]
fn root_keys_are_deterministic_and_verify_only_nodes_trust_them() {
    let p = ChainParams {
        container_size: 2,
        ..params()
    };
    let a = Plonky3System::insecure_fast(&p, true).expect("setup a");
    let b = Plonky3System::insecure_fast(&p, true).expect("setup b");
    assert_eq!(a.root_key(), b.root_key());
    assert!(a.aggregates());
    let verifier = Plonky3System::insecure_fast_with_key(&p, a.root_key()).expect("verifier");
    assert!(!verifier.aggregates());
    assert_eq!(verifier.root_key(), a.root_key());

    let (state, note) = genesis();
    let w = payment(&state, &note, 0);
    let (slot, proof, fee) = a.prove_slot(&ctx(&state), &w, seed(12)).expect("prove");
    assert!(verifier.verify_slot(&state.anchors, &slot, &proof, &fee));
    let tx = PendingTx {
        slot,
        proof,
        fee,
        nonce: 0,
    };
    let block = build_block(
        &state,
        &state.anchors,
        &p,
        &a,
        &miner(),
        std::slice::from_ref(&tx),
        &[],
        &SecretSeed::from_os_rng().unwrap(),
        state.timestamp() + p.target_block_time,
    )
    .expect("build");
    let height = state.height + 1;
    check_proof(&block.proof, &state, &block.body, height, &verifier).expect("verifies by key");
    check_proof(&block.proof, &state, &block.body, height, &b).expect("verifies under b");
    assert!(matches!(
        verifier.prove_container(&state.anchors, height, &[], &note, 0),
        Err(siworld_circuits::AggregateError::Prover(_))
    ));

    // A node trusting another tree's key (N = 4's) rejects the proof: the
    // key is the circuit, and only the pinned key of the right N accepts it.
    let four = system();
    assert_ne!(four.root_key(), a.root_key());
    let wrong = Plonky3System::insecure_fast_with_key(&p, four.root_key()).expect("decodes");
    assert_eq!(
        check_proof(&block.proof, &state, &block.body, height, &wrong),
        Err(BlockError::BadProof)
    );
    // And a miner that rebuilds another key than the one it is told to
    // trust refuses to start.
    let bad_key = [a.root_key(), &[0]].concat();
    assert!(matches!(
        Plonky3System::insecure_fast_with_key(&p, &bad_key).err(),
        Some(SetupError::Key(_))
    ));
}
