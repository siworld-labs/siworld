//! Rejections for the versioned native economic reward relation.
use crate::multi_asset::{self as m, F, Hasher};
use crate::multi_asset_transaction::TransactionAir;
use crate::settlement::{self, RewardMode, SettlementAir};
use p3_air::check_all_constraints;
use p3_field::PrimeCharacteristicRing;

#[test]
fn snapshot_boundary_and_committed_unlock_height_are_enforced() {
    let mut w = m::sample_witness(21);
    w.slot = m::with_unlock_heights(w.slot, [1001, 0]);
    let air = TransactionAir::new();
    let (trace, public) = air.generate_at_snapshot(&w, 1000);
    assert!(
        !check_all_constraints(&air, &trace, &public, Some(1))
            .failures
            .is_empty()
    );
    assert!(
        w.check_at_snapshot(&Hasher::new(), &w.anchors_root(&Hasher::new()), 1000)
            .is_err()
    );
    assert!(
        w.check_at_snapshot(&Hasher::new(), &w.anchors_root(&Hasher::new()), 1001)
            .is_ok()
    );
    let (trace, public) = air.generate_at_snapshot(&w, 1001);
    assert!(
        check_all_constraints(&air, &trace, &public, Some(1))
            .failures
            .is_empty()
    );
    let mut forged = public;
    forged[crate::multi_asset_transaction::TRANSACTION_SNAPSHOT_HEIGHT] -= F::ONE;
    assert!(
        !check_all_constraints(&air, &trace, &forged, Some(1))
            .failures
            .is_empty()
    );
}

#[test]
fn ordinary_outputs_cannot_create_new_time_locks() {
    let mut w = m::sample_witness(22);
    w.slot.outputs[0].unlock_height = 1;
    let air = TransactionAir::new();
    let (trace, public) = air.generate_at_snapshot(&w, 1000);
    assert!(
        !check_all_constraints(&air, &trace, &public, Some(1))
            .failures
            .is_empty()
    );
}

#[test]
fn both_reward_modes_have_canonical_count_amount_and_indexed_rho() {
    for mode in [RewardMode::Voyager, RewardMode::Holder] {
        let w = settlement::sample_fixed_settlement_witness(4, mode);
        w.check(&Hasher::new()).unwrap();
        let air = SettlementAir::new(4);
        let (trace, public) = settlement::generate_trace(&air, &w);
        assert!(
            check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
        let mut altered = w.clone();
        altered.rewards[0].amount += 1;
        assert!(altered.check(&Hasher::new()).is_err());
        let (trace, public) = settlement::generate_trace(&air, &altered);
        assert!(
            !check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
        let mut wrong_count = w.clone();
        wrong_count.rewards.pop();
        assert!(wrong_count.check(&Hasher::new()).is_err());
        let mut wrong_asset = w.clone();
        wrong_asset.rewards[0].asset_id = m::AssetId([1; 32]);
        assert!(wrong_asset.check(&Hasher::new()).is_err());
        if mode == RewardMode::Holder {
            let h = Hasher::new();
            let rhos: Vec<_> = (0..5)
                .map(|i| h.reward_rho(w.plan.block_height, i))
                .collect();
            for (i, rho) in rhos.iter().enumerate() {
                assert!(!rhos[..i].contains(rho));
            }
            let mut changed = w.clone();
            changed.plan.mode = RewardMode::Voyager;
            assert!(changed.check(&h).is_err());
            let mut public = w.public_inputs();
            let commitments = settlement::reward_commitments_offset(w.capacity());
            let second = public[commitments..commitments + m::DIGEST].to_vec();
            public[commitments + m::DIGEST..commitments + 2 * m::DIGEST].copy_from_slice(&second);
            assert!(settlement::validate_settlement_public(w.capacity(), &public).is_err());
        }
    }
}
