//! Fixed-capacity confidential-fee settlement AIR and native prover.
//!
//! This is an evaluation implementation. It proves one fee-opening row per
//! fixed slot and binds the limb-wise sum to the miner amount. It does not
//! activate Scheme B on the node or consensus path.

use crate::air::{LinearLayers, P2, p2_constants};
use crate::common::{self, F, Hasher, LIMB_BITS, LIMBS, RATE, WIDTH};
use crate::fee_settlement::{SettlementSlot, verify_settlement};
use crate::{Cfg, FriParams};
use p3_air::check_all_constraints;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::Poseidon2Air;
use p3_uni_stark::SubAirBuilder;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

pub type FeeP2Air = Poseidon2Air<F, LinearLayers, WIDTH, 3, 0, 4, 23>;
const P2_OUT: usize = P2 - WIDTH;
const FEE: usize = P2;
const BLIND: usize = FEE + LIMBS;
const DUMMY: usize = BLIND + LIMBS;
const PRIORITY: usize = DUMMY + 1;
const SUM: usize = PRIORITY + 1;
// Carry columns start after the complete limb group.  Keeping the starts
// disjoint is essential: the final limb is a value, not a carry witness.
const SUM_CARRY: usize = SUM + LIMBS;
const TIER_CARRY: usize = SUM_CARRY + (LIMBS - 1);
const REWARD_CARRY: usize = TIER_CARRY + 2 * (LIMBS - 1);
const RANGE_BITS: usize = REWARD_CARRY + (LIMBS - 1);
const MAIN_WIDTH: usize = RANGE_BITS + LIMBS * LIMB_BITS;

const PRE_ACTIVE: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_LAST: usize = 2;
const PRE_SLOTS: usize = 3;

pub const fn public_len(capacity: usize) -> usize {
    capacity * common::DIGEST + 3 * LIMBS
}

/// Witness for a fixed-capacity block. `slots.len()` is the capacity and must
/// include dummy openings for every unused position.
#[derive(Clone, Debug)]
pub struct FixedSettlementWitness {
    pub base_fee: u64,
    pub issuance_reward: u64,
    pub miner_amount: u64,
    pub slots: Vec<SettlementSlot>,
}

impl FixedSettlementWitness {
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn public_inputs(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(public_len(self.capacity()));
        for slot in &self.slots {
            out.extend_from_slice(&slot.commitment);
        }
        out.extend_from_slice(&common::limbs(self.base_fee));
        out.extend_from_slice(&common::limbs(self.issuance_reward));
        out.extend_from_slice(&common::limbs(self.miner_amount));
        out
    }

    /// Check the native opening relation before invoking the AIR prover.
    pub fn check(&self, hasher: &Hasher) -> Result<(), crate::fee_settlement::SettlementError> {
        verify_settlement(
            hasher,
            &self.slots,
            self.base_fee,
            self.issuance_reward,
            self.miner_amount,
        )
        .map(|_| ())
    }
}

pub struct SettlementAir {
    pub capacity: usize,
    pub height: usize,
    p2: FeeP2Air,
}

impl SettlementAir {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        let height = capacity.next_power_of_two();
        Self {
            capacity,
            height,
            p2: FeeP2Air::new(p2_constants()),
        }
    }

    pub fn degree_bits(&self) -> usize {
        self.height.trailing_zeros() as usize
    }
    pub fn main_width(&self) -> usize {
        MAIN_WIDTH
    }
    pub fn preprocessed_width(&self) -> usize {
        PRE_SLOTS + self.capacity
    }

    /// Extract the concrete per-row constraint count for this fixed capacity.
    /// The checker is used only by the evaluation harness; proving and
    /// verification do not execute it.
    pub fn constraint_count(&self, witness: &FixedSettlementWitness) -> usize {
        let (trace, public) = generate_trace(self, witness);
        check_all_constraints(self, &trace, &public, Some(1)).total_constraints_per_row
    }
    pub fn with_min_height(mut self, min_height: usize) -> Self {
        assert!(min_height.is_power_of_two());
        if min_height > self.height {
            self.height = min_height;
        }
        self
    }
    fn slot_selector(&self, i: usize) -> usize {
        PRE_SLOTS + i
    }
}

impl BaseAir<F> for SettlementAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.preprocessed_width();
        let mut values = F::zero_vec(self.height * width);
        for r in 0..self.height {
            let row = &mut values[r * width..(r + 1) * width];
            if r < self.capacity {
                row[PRE_ACTIVE] = F::ONE;
                row[self.slot_selector(r)] = F::ONE;
            }
            if r == 0 {
                row[PRE_FIRST] = F::ONE;
            }
            if r + 1 == self.capacity {
                row[PRE_LAST] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(values, width))
    }
    fn num_public_values(&self) -> usize {
        public_len(self.capacity)
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for SettlementAir {
    fn eval(&self, b: &mut AB) {
        let mut sub = SubAirBuilder::<AB, FeeP2Air, AB::Var>::new(b, 0..P2);
        self.p2.eval(&mut sub);

        let main = b.main();
        let pre = b.preprocessed().clone();
        let pis: Vec<AB::PublicVar> = b.public_values().to_vec();
        let l = main.current_slice();
        let n = main.next_slice();
        let pl = pre.current_slice();
        let pn = pre.next_slice();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let active = x(pl[PRE_ACTIVE]);
        let next_active = x(pn[PRE_ACTIVE]);
        let first = x(pl[PRE_FIRST]);
        let last = x(pl[PRE_LAST]);

        // The first eight rate elements are fee limbs and the 256-bit blind.
        for e in 0..RATE {
            let expected = if e < LIMBS {
                x(l[FEE + e])
            } else if e < LIMBS * 2 {
                x(l[BLIND + e - LIMBS])
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero((x(l[e]) - expected) * active.clone());
        }
        b.assert_zero((x(l[RATE]) - F::from_u32(common::TAG_FEE)) * active.clone());
        b.assert_zero((x(l[RATE + 1]) - F::ONE) * active.clone());
        for e in RATE + 2..WIDTH {
            b.assert_zero(x(l[e]) * active.clone());
        }

        // Bind each permutation digest to the corresponding public commitment.
        for i in 0..self.capacity {
            let selector = x(pl[self.slot_selector(i)]);
            for e in 0..common::DIGEST {
                b.assert_zero(
                    (x(l[P2_OUT + e]) - pis[i * common::DIGEST + e].into()) * selector.clone(),
                );
            }
        }

        b.assert_bool(l[DUMMY]);
        b.assert_bool(l[PRIORITY]);
        b.assert_zero(x(l[DUMMY]) * x(l[PRIORITY]) * active.clone());
        let base_offset = self.capacity * common::DIGEST;
        for k in 0..LIMBS {
            for q in 0..LIMB_BITS {
                b.assert_bool(l[RANGE_BITS + k * LIMB_BITS + q]);
            }
            let mut limb = AB::Expr::ZERO;
            for q in 0..LIMB_BITS {
                limb += x(l[RANGE_BITS + k * LIMB_BITS + q]) * F::from_u32(1 << q);
            }
            b.assert_eq(limb, l[FEE + k]);

            let carry = if k + 1 < LIMBS {
                let c = TIER_CARRY + 2 * k;
                b.assert_bool(l[c]);
                b.assert_bool(l[c + 1]);
                x(l[c]) + x(l[c + 1]) * F::TWO
            } else {
                AB::Expr::ZERO
            };
            let prev = if k == 0 {
                AB::Expr::ZERO
            } else {
                let c = TIER_CARRY + 2 * (k - 1);
                x(l[c]) + x(l[c + 1]) * F::TWO
            };
            let mult =
                (AB::Expr::ONE - x(l[DUMMY])) * (AB::Expr::ONE + x(l[PRIORITY]) * F::from_u32(3));
            b.assert_zero(
                (mult * pis[base_offset + k].into() + prev
                    - x(l[FEE + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * active.clone(),
            );
        }

        // Running sum. A current row stores the sum after its own fee.
        // The transition is constrained only while both rows are real slots.
        for k in 0..LIMBS {
            if k + 1 < LIMBS {
                b.assert_bool(l[SUM_CARRY + k]);
            }
            let carry = if k + 1 < LIMBS {
                x(l[SUM_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            let prior = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[SUM_CARRY + k - 1])
            };
            b.assert_zero(
                (x(l[SUM + k]) + x(n[FEE + k]) + prior
                    - x(n[SUM + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * active.clone()
                    * next_active.clone()
                    * (AB::Expr::ONE - last.clone()),
            );
        }
        for k in 0..LIMBS {
            b.assert_zero((x(l[SUM + k]) - x(l[FEE + k])) * first.clone());
        }

        // On the last real row, sum + issuance = miner amount, with checked carries.
        let issuance = base_offset + LIMBS;
        let miner = base_offset + LIMBS * 2;
        for k in 0..LIMBS {
            if k + 1 < LIMBS {
                b.assert_bool(l[REWARD_CARRY + k]);
            }
            let prior = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[REWARD_CARRY + k - 1])
            };
            let carry = if k + 1 < LIMBS {
                x(l[REWARD_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero(
                (x(l[SUM + k]) + pis[issuance + k].into() + prior
                    - pis[miner + k].into()
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * last.clone(),
            );
        }

        // Padding is inert; its P2 row is still a valid zero permutation generated by the prover.
        b.assert_zero((x(l[DUMMY]) + x(l[PRIORITY])) * (AB::Expr::ONE - active));
    }
}

pub struct SettlementProver {
    pub cfg: Cfg,
    pub air: SettlementAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}

impl SettlementProver {
    pub fn new(capacity: usize, params: FriParams) -> Self {
        let cfg = params.config();
        let air = SettlementAir::new(capacity).with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("preprocessed commitment")
            .expect("preprocessed AIR");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }

    pub fn prove(&self, witness: &FixedSettlementWitness) -> (Proof<Cfg>, Vec<F>) {
        assert_eq!(witness.capacity(), self.air.capacity);
        witness
            .check(&Hasher::new())
            .expect("invalid settlement witness");
        let (trace, pis) = generate_trace(&self.air, witness);
        let proof = prove_with_preprocessed(&self.cfg, &self.air, trace, &pis, Some(&self.pdata))
            .expect("settlement proof generation");
        (proof, pis)
    }

    pub fn verify(&self, proof: &Proof<Cfg>, pis: &[F]) -> Result<(), String> {
        if pis.len() != public_len(self.air.capacity) {
            return Err("invalid settlement public-input length".into());
        }
        let numeric = self.air.capacity * common::DIGEST;
        for index in numeric..numeric + 3 * LIMBS {
            if pis[index].as_canonical_u32() >= (1u32 << LIMB_BITS) {
                return Err("non-canonical settlement numeric limb".into());
            }
        }
        for i in 0..self.air.capacity {
            let left = &pis[i * common::DIGEST..(i + 1) * common::DIGEST];
            for j in 0..i {
                let right = &pis[j * common::DIGEST..(j + 1) * common::DIGEST];
                if left == right {
                    return Err(format!("duplicate fee commitment at slot {i}"));
                }
            }
        }
        verify_with_preprocessed(&self.cfg, &self.air, proof, pis, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
}

fn generate_trace(
    air: &SettlementAir,
    witness: &FixedSettlementWitness,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = vec![F::ZERO; air.height * MAIN_WIDTH];
    let mut sum = 0u64;
    let mut cumulative = [0u32; LIMBS];
    for r in 0..air.capacity {
        let slot = &witness.slots[r];
        let off = r * MAIN_WIDTH;
        let fee = common::limbs(slot.opening.fee);
        let block = common::fee_block(slot.opening.fee, &slot.opening.blind);
        let mut input = [F::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&block);
        input[RATE] = F::from_u32(common::TAG_FEE);
        input[RATE + 1] = F::ONE;
        inputs[r] = input;
        for k in 0..LIMBS {
            rows[off + FEE + k] = fee[k];
            rows[off + BLIND + k] = slot.opening.blind[k];
            rows[off + RANGE_BITS + k * LIMB_BITS..off + RANGE_BITS + (k + 1) * LIMB_BITS]
                .copy_from_slice(&std::array::from_fn::<F, LIMB_BITS, _>(|q| {
                    F::from_u32((fee[k].as_canonical_u32() >> q) & 1)
                }));
        }
        rows[off + DUMMY] = F::from_bool(slot.opening.dummy);
        rows[off + PRIORITY] = F::from_bool(slot.opening.priority);

        sum = sum.checked_add(slot.opening.fee).expect("sum overflow");
        let sum_limbs = common::limbs(sum);
        for k in 0..LIMBS {
            rows[off + SUM + k] = sum_limbs[k];
        }
        // The carry in row r adds row r+1's fee to the cumulative sum.
        if r + 1 < air.capacity {
            let next_fee = common::limbs(witness.slots[r + 1].opening.fee);
            let mut sc = 0u64;
            for k in 0..LIMBS - 1 {
                sc = (sum_limbs[k].as_canonical_u32() as u64
                    + next_fee[k].as_canonical_u32() as u64
                    + sc)
                    >> LIMB_BITS;
                rows[off + SUM_CARRY + k] = F::from_u64(sc);
            }
        }
        let mult = if slot.opening.dummy {
            0u64
        } else if slot.opening.priority {
            4
        } else {
            1
        };
        let base = common::limbs(witness.base_fee);
        let mut tc = 0u64;
        for k in 0..LIMBS - 1 {
            tc = (mult * base[k].as_canonical_u32() as u64 + tc - fee[k].as_canonical_u32() as u64)
                >> LIMB_BITS;
            rows[off + TIER_CARRY + 2 * k] = F::from_u64(tc & 1);
            rows[off + TIER_CARRY + 2 * k + 1] = F::from_u64((tc >> 1) & 1);
        }
        cumulative = sum_limbs.map(|x| x.as_canonical_u32());
    }
    let final_off = (air.capacity - 1) * MAIN_WIDTH;
    let issuance = common::limbs(witness.issuance_reward);
    let miner = common::limbs(witness.miner_amount);
    let mut rc = 0u64;
    for k in 0..LIMBS - 1 {
        rc = (cumulative[k] as u64 + issuance[k].as_canonical_u32() as u64 + rc
            - miner[k].as_canonical_u32() as u64)
            >> LIMB_BITS;
        rows[final_off + REWARD_CARRY + k] = F::from_u64(rc);
    }

    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for r in 0..air.height {
        rows[r * MAIN_WIDTH..r * MAIN_WIDTH + P2].copy_from_slice(&p2.values[r * P2..(r + 1) * P2]);
    }
    (
        RowMajorMatrix::new(rows, MAIN_WIDTH),
        witness.public_inputs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{F, FEE_BASE, Hasher};
    use crate::fee_settlement::FeeOpening;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;

    fn blind(seed: u32) -> [F; 4] {
        core::array::from_fn(|i| F::from_u32(seed + i as u32))
    }

    fn witness(capacity: usize) -> FixedSettlementWitness {
        let hasher = Hasher::new();
        let mut slots = Vec::with_capacity(capacity);
        slots.push(SettlementSlot::from_opening(
            &hasher,
            FeeOpening::standard(blind(1)),
        ));
        for i in 1..capacity {
            slots.push(SettlementSlot::from_opening(
                &hasher,
                FeeOpening::dummy(blind(100 + i as u32)),
            ));
        }
        FixedSettlementWitness {
            base_fee: FEE_BASE,
            issuance_reward: 100,
            miner_amount: 100 + FEE_BASE,
            slots,
        }
    }

    #[test]
    fn fixed_capacity_trace_satisfies_air() {
        let w = witness(4);
        let air = SettlementAir::new(w.capacity());
        let (trace, pis) = generate_trace(&air, &w);
        let failures = check_all_constraints(&air, &trace, &pis, None).failures;
        assert!(failures.is_empty(), "settlement AIR failures: {failures:?}");
    }

    #[test]
    fn fixed_capacity_proof_round_trip() {
        let w = witness(4);
        let prover = SettlementProver::new(4, FriParams::fast());
        let (proof, pis) = prover.prove(&w);
        prover
            .verify(&proof, &pis)
            .expect("settlement proof verifies");
    }

    #[test]
    fn public_statement_has_one_commitment_per_slot() {
        let w = witness(8);
        assert_eq!(w.public_inputs().len(), public_len(8));
        assert_eq!(
            w.public_inputs().len(),
            8 * crate::common::DIGEST + 3 * LIMBS
        );
    }

    #[test]
    fn native_settlement_proof_verifies_and_binds_reward_statement() {
        let w = witness(4);
        let prover = SettlementProver::new(w.capacity(), crate::FriParams::fast());
        let (proof, public) = prover.prove(&w);
        prover
            .verify(&proof, &public)
            .expect("valid settlement proof");
        let mut changed = public.clone();
        let last = changed.len() - 1;
        changed[last] += F::ONE;
        assert!(prover.verify(&proof, &changed).is_err());
    }
}
