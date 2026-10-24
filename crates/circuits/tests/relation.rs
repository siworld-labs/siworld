//! Slot relation: fee tiers, minimum deposit, conservation, anchor roots, output ρ.

use siworld_circuits::dummy::dummy_slot;
use siworld_circuits::{AggregateError, Leaf, HEIGHT_BITS};
use siworld_circuits::{InputWitness, MockProver, RelationContext, RelationError, SlotWitness};
use siworld_core::issuance::{fee_base, fee_priority};
use siworld_core::params::COINBASE_MATURITY;
use siworld_core::params::{ChainParams, MIN_PACKAGE_DEPOSIT};
use siworld_core::{Ciphertext, Condition, Digest, Note, CIPHERTEXT_LEN};
use siworld_crypto::{expand, miner_rho, note_commitment, output_rho, SpendKey};
use siworld_state::ChainState;

const SI: u64 = 100_000_000;

/// The relation does not look at ciphertexts (docs/security-model.md), so these tests leave them blank.
const NO_CT: [Ciphertext; 2] = [Ciphertext([0; CIPHERTEXT_LEN]); 2];

fn sk() -> SpendKey {
    SpendKey::from_digest(Digest([1; 32]))
}

fn note(value: u64, tag: u64) -> Note {
    Note {
        owner: sk().owner(),
        value,
        cond: Condition::default(),
        rho: expand(&Digest([2; 32]), "rho", tag),
        rseed: expand(&Digest([2; 32]), "rseed", tag),
    }
}

struct Fixture {
    params: ChainParams,
    state: ChainState,
    funded: Note,
}

fn fixture() -> Fixture {
    let params = ChainParams::devnet();
    let funded = note(SI, 0);
    let state = ChainState::genesis_with_commitments(&params, &[note_commitment(&funded)]);
    Fixture {
        params,
        state,
        funded,
    }
}

impl Fixture {
    fn real(&self) -> InputWitness {
        InputWitness::Real {
            note: self.funded,
            sk: sk(),
            path: self.state.commitments.path(0).unwrap(),
        }
    }

    fn prove(
        &self,
        inputs: [InputWitness; 2],
        outs: [u64; 2],
        fee: u64,
    ) -> Result<(), RelationError> {
        let rho = [0, 1].map(|j| output_rho(&inputs[0].nullifier(), &inputs[1].nullifier(), j));
        self.prove_with_rho(inputs, outs, fee, rho)
    }

    fn prove_with_rho(
        &self,
        inputs: [InputWitness; 2],
        outs: [u64; 2],
        fee: u64,
        rho: [Digest; 2],
    ) -> Result<(), RelationError> {
        let ctx = RelationContext {
            anchors: &self.state.anchors,
            tree_depth: self.params.commitment_tree_depth,
        };
        let mut outputs = [note(outs[0], 10), note(outs[1], 11)];
        outputs[0].rho = rho[0];
        outputs[1].rho = rho[1];
        let w = SlotWitness {
            anchor: self.state.anchors.latest().unwrap().0,
            inputs,
            outputs,
            ct: NO_CT,
            tag: [0; 2],
            fee,
        };
        MockProver::prove_slot(&ctx, &w, Digest::ZERO).map(|_| ())
    }
}

fn dummy(tag: u8) -> InputWitness {
    InputWitness::Dummy {
        nk: Digest([tag; 32]),
        rho: Digest([tag; 32]),
    }
}

#[test]
fn fee_must_be_one_of_two_tiers() {
    let f = fixture();
    let base = fee_base(0);
    let prio = fee_priority(0);
    assert_eq!(f.prove([f.real(), dummy(1)], [SI - base, 0], base), Ok(()));
    assert_eq!(f.prove([f.real(), dummy(1)], [SI - prio, 0], prio), Ok(()));
    for fee in [0, 1, base - 1, base + 1, 2 * base] {
        assert_eq!(
            f.prove([f.real(), dummy(1)], [SI - fee, 0], fee),
            Err(RelationError::BadFee),
            "fee {fee}"
        );
    }
}

#[test]
fn empty_package_pays_zero_fee() {
    let f = fixture();
    assert_eq!(f.prove([dummy(1), dummy(2)], [0, 0], 0), Ok(()));
    assert_eq!(
        f.prove([dummy(1), dummy(2)], [0, 0], fee_base(0)),
        Err(RelationError::BadFee)
    );
    // Dummy inputs minting coins from nothing: rejected by conservation.
    assert_eq!(
        f.prove([dummy(1), dummy(2)], [MIN_PACKAGE_DEPOSIT, 0], 0),
        Err(RelationError::Unbalanced)
    );
}

#[test]
fn outputs_respect_minimum_deposit() {
    let f = fixture();
    let fee = fee_base(0);
    assert_eq!(
        f.prove([f.real(), dummy(1)], [SI - fee - 1, 1], fee),
        Err(RelationError::BelowMinimumDeposit { output: 1 })
    );
    assert_eq!(
        f.prove(
            [f.real(), dummy(1)],
            [SI - fee - MIN_PACKAGE_DEPOSIT, MIN_PACKAGE_DEPOSIT],
            fee
        ),
        Ok(())
    );
    assert_eq!(f.prove([f.real(), dummy(1)], [SI - fee, 0], fee), Ok(()));
}

#[test]
fn value_is_conserved() {
    let f = fixture();
    let fee = fee_base(0);
    assert_eq!(
        f.prove([f.real(), dummy(1)], [SI - fee + 1, 0], fee),
        Err(RelationError::Unbalanced)
    );
    assert_eq!(
        f.prove([f.real(), dummy(1)], [SI - fee - 1, 0], fee),
        Err(RelationError::Unbalanced)
    );
}

#[test]
fn anchor_must_be_in_window() {
    let f = fixture();
    let ctx = RelationContext {
        anchors: &f.state.anchors,
        tree_depth: f.params.commitment_tree_depth,
    };
    let w = SlotWitness {
        anchor: Digest([9; 32]),
        inputs: [dummy(1), dummy(2)],
        outputs: [note(0, 10), note(0, 11)],
        ct: NO_CT,
        tag: [0; 2],
        fee: 0,
    };
    assert_eq!(
        MockProver::prove_slot(&ctx, &w, Digest::ZERO).unwrap_err(),
        RelationError::UnknownAnchor
    );
}

#[test]
fn output_rho_must_be_derived_from_input_nullifiers() {
    let f = fixture();
    let fee = fee_base(0);
    let inputs = || [f.real(), dummy(1)];
    let nf = inputs().map(|i| i.nullifier());
    let good = [0, 1].map(|j| output_rho(&nf[0], &nf[1], j));
    let outs = [SI / 2, SI - SI / 2 - fee];
    assert_eq!(f.prove_with_rho(inputs(), outs, fee, good), Ok(()));

    // A sender creates two packages with the same ρ for one recipient: their
    // nullifiers would collide, so this must be rejected.
    assert_eq!(
        f.prove_with_rho(inputs(), outs, fee, [good[0], good[0]]),
        Err(RelationError::RhoMismatch { output: 1 })
    );
    // An arbitrarily chosen ρ is rejected too; both outputs are checked.
    assert_eq!(
        f.prove_with_rho(inputs(), outs, fee, [Digest([7; 32]), good[1]]),
        Err(RelationError::RhoMismatch { output: 0 })
    );
    // Swapping ρ between the two outputs is rejected too: j is part of the derivation.
    assert_eq!(
        f.prove_with_rho(inputs(), outs, fee, [good[1], good[0]]),
        Err(RelationError::RhoMismatch { output: 0 })
    );
}

#[test]
fn miner_package_holds_fees_plus_share_and_its_rho_is_bound_to_height() {
    let f = fixture();
    let ctx = RelationContext {
        anchors: &f.state.anchors,
        tree_depth: f.params.commitment_tree_depth,
    };
    let anchor = f.state.anchors.latest().unwrap().0;
    let seed = Digest([3; 32]);
    let slots: Vec<_> = (0..4)
        .map(|i| dummy_slot(&MockProver, &ctx, anchor, &seed, i))
        .collect();
    let leaves: Vec<Leaf> = slots
        .iter()
        .map(|(slot, proof, fee)| Leaf { slot, proof, fee })
        .collect();
    let height = 1;
    let share = 611_014_413;
    let mut miner_note = Note {
        owner: sk().owner(),
        value: share,
        cond: Condition {
            unlock_height: height + COINBASE_MATURITY,
        },
        rho: miner_rho(height),
        rseed: Digest([4; 32]),
    };
    let prove = |note: &Note, share| {
        MockProver::prove_container(&f.state.anchors, height, &leaves, note, share)
    };
    assert!(prove(&miner_note, share).is_ok());

    // Empty packages pay no fee, so the package holds exactly the share: one
    // atom more or less, or a different share, is rejected.
    miner_note.value += 1;
    assert_eq!(
        prove(&miner_note, share).unwrap_err(),
        AggregateError::MinerNoteValue
    );
    miner_note.value = share;
    assert_eq!(
        prove(&miner_note, share + 1).unwrap_err(),
        AggregateError::MinerNoteValue
    );
    assert_eq!(
        prove(&miner_note, 0).unwrap_err(),
        AggregateError::MinerNoteValue
    );

    miner_note.cond.unlock_height += 1;
    assert_eq!(
        prove(&miner_note, share).unwrap_err(),
        AggregateError::MinerNoteUnlock
    );
    miner_note.cond.unlock_height -= 1;

    miner_note.rho = miner_rho(height + 1);
    assert_eq!(
        prove(&miner_note, share).unwrap_err(),
        AggregateError::MinerNoteRho
    );
}

#[test]
fn container_height_must_fit_the_root_statement() {
    let f = fixture();
    let ctx = RelationContext {
        anchors: &f.state.anchors,
        tree_depth: f.params.commitment_tree_depth,
    };
    let anchor = f.state.anchors.latest().unwrap().0;
    let seed = Digest([3; 32]);
    let slots: Vec<_> = (0..4)
        .map(|i| dummy_slot(&MockProver, &ctx, anchor, &seed, i))
        .collect();
    let leaves: Vec<Leaf> = slots
        .iter()
        .map(|(slot, proof, fee)| Leaf { slot, proof, fee })
        .collect();
    let miner_note = |height| Note {
        owner: sk().owner(),
        value: 0,
        cond: Condition {
            unlock_height: height + COINBASE_MATURITY,
        },
        rho: miner_rho(height),
        rseed: Digest([4; 32]),
    };
    let limit = (1 << HEIGHT_BITS) - COINBASE_MATURITY;
    for (height, ok) in [(limit - 1, true), (limit, false)] {
        let result =
            MockProver::prove_container(&f.state.anchors, height, &leaves, &miner_note(height), 0);
        assert_eq!(result.is_ok(), ok, "{height}");
        if !ok {
            assert_eq!(result.unwrap_err(), AggregateError::StatementOutOfRange);
        }
    }
}

#[test]
fn witness_debug_does_not_expose_private_values() {
    let input = InputWitness::Dummy {
        nk: Digest([0xa5; 32]),
        rho: Digest([0xb6; 32]),
    };
    assert_eq!(format!("{input:?}"), "InputWitness(REDACTED)");
    let f = fixture();
    let witness = SlotWitness {
        anchor: f.state.anchors.latest().unwrap().0,
        inputs: [f.real(), input],
        outputs: [note(123, 2), note(456, 3)],
        ct: NO_CT,
        tag: [0; 2],
        fee: 17,
    };
    assert_eq!(format!("{witness:#?}"), "SlotWitness(REDACTED)");
}

#[test]
fn native_witness_storage_has_drop_erasure() {
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn erased_on_drop<T: ZeroizeOnDrop>() {}
    erased_on_drop::<SlotWitness>();
    erased_on_drop::<InputWitness>();
    let f = fixture();
    let mut w = SlotWitness {
        anchor: f.state.anchors.latest().unwrap().0,
        inputs: [f.real(), dummy(7)],
        outputs: [note(123, 2), note(456, 3)],
        ct: NO_CT,
        tag: [0; 2],
        fee: 17,
    };
    w.zeroize();
    assert_eq!(w.fee, 0);
    for n in w.outputs {
        assert_eq!(n.rseed, Digest::ZERO);
        assert_eq!(n.value, 0);
    }
    match &w.inputs[0] {
        InputWitness::Real { sk, note, path } => {
            assert_eq!(sk.expose_secret(), &[0u8; 32]);
            assert_eq!(note.rseed, Digest::ZERO);
            assert!(path.siblings.iter().all(|s| *s == Digest::ZERO));
        }
        _ => panic!("expected a real input"),
    }
    match &w.inputs[1] {
        InputWitness::Dummy { nk, rho } => {
            assert_eq!(*nk, Digest::ZERO);
            assert_eq!(*rho, Digest::ZERO);
        }
        _ => panic!("expected a dummy input"),
    }
}
