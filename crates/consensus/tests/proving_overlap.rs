mod common;

use std::sync::atomic::{AtomicBool, Ordering};

use siworld_circuits::{
    AggregateError, ContainerPublic, FeeOpening, Leaf, MockProver, ProofSystem, ProveError,
    RelationContext, SlotProof, SlotWitness,
};
use siworld_consensus::{build_unsealed_with_header, check_proof};
use siworld_core::{ContainerProof, Digest, Height, Note, Slot};
use siworld_state::RecentRoots;

struct OrderedProver(AtomicBool);
impl ProofSystem for OrderedProver {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        MockProver.prove_slot(ctx, w, blind)
    }
    fn verify_slot(&self, a: &RecentRoots, s: &Slot, p: &SlotProof, f: &FeeOpening) -> bool {
        MockProver.verify_slot(a, s, p, f)
    }
    fn prove_container(
        &self,
        a: &RecentRoots,
        h: Height,
        l: &[Leaf],
        n: &Note,
        s: u64,
    ) -> Result<ContainerProof, AggregateError> {
        assert!(
            self.0.load(Ordering::Acquire),
            "PoW header must be available before aggregation starts"
        );
        MockProver.prove_container(a, h, l, n, s)
    }
    fn verify_container(&self, p: &ContainerPublic, proof: &ContainerProof) -> bool {
        MockProver.verify_container(p, proof)
    }
}

#[test]
fn immutable_header_is_available_before_proving_and_matches_the_finished_block() {
    let params = common::params();
    let (state, _) = common::genesis(&params, &[]);
    let system = OrderedProver(AtomicBool::new(false));
    let mut seen = None;
    let block = build_unsealed_with_header(
        &state,
        &state.anchors,
        &params,
        &system,
        &common::miner(),
        &[],
        &[],
        &common::block_seed(1),
        common::next_timestamp(&state, &params),
        |header| {
            seen = Some(header);
            system.0.store(true, Ordering::Release);
        },
    )
    .unwrap();
    assert_eq!(seen, Some(block.header));
    check_proof(
        &block.proof,
        &state,
        &block.body,
        block.header.height,
        &system,
    )
    .unwrap();
}

#[test]
fn invalid_native_body_does_not_start_pow() {
    let params = common::params();
    let (state, _) = common::genesis(&params, &[]);
    let mut called = false;
    let result = build_unsealed_with_header(
        &state,
        &state.anchors,
        &params,
        &MockProver,
        &common::miner(),
        &[],
        &[],
        &common::block_seed(1),
        state.timestamp(),
        |_| called = true,
    );
    assert!(result.is_err());
    assert!(!called);
}
