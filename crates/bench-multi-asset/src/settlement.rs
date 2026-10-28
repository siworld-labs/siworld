//! Fixed-capacity native confidential-fee settlement and economic reward relation.
//!
//! The verifier reconstructs the reward plan from the parent consensus state.
//! The AIR binds that trusted plan, all fee openings and the ordered reward
//! commitments. Fee totals and reward-note openings remain private.
use crate::air::{LinearLayers, P2, p2_constants};
use crate::confidential_fees::{FeeOpening, SettlementError, SettlementSlot};
use crate::multi_asset::{self as common, F, Hasher, LIMB_BITS, LIMBS, RATE, WIDTH};
use crate::{Cfg, FriParams};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_all_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::Poseidon2Air;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, SubAirBuilder, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

pub const MAX_REWARD_NOTES: usize = 5;
pub const HOLDER_UNLOCK_OFFSETS: [u64; 4] = [52_560, 105_120, 157_680, 210_240];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RewardMode {
    Voyager = 0,
    Holder = 1,
}
impl RewardMode {
    pub const fn note_count(self) -> usize {
        match self {
            Self::Voyager => 1,
            Self::Holder => 5,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardAllocation {
    pub amount: u64,
    pub unlock_height: u64,
}
/// Deterministic allocation supplied by the authenticated consensus transition.
/// Amounts exclude fees; every fee atom is added only to allocation zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardPlan {
    pub block_height: u64,
    pub mode: RewardMode,
    pub allocations: Vec<RewardAllocation>,
}
impl RewardPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.allocations.len() != self.mode.note_count()
            || self
                .allocations
                .iter()
                .any(|a| a.unlock_height < self.block_height)
        {
            return Err("reward plan count or unlock height mismatch".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct RewardNoteWitness {
    pub asset_id: common::AssetId,
    pub owner: common::Digest,
    pub rseed: common::Digest,
    pub amount: u64,
}
#[derive(Clone, Debug)]
pub struct FixedSettlementWitness {
    pub plan: RewardPlan,
    pub network: [u8; 32],
    pub transaction_list_digest: [u8; 32],
    pub rewards: Vec<RewardNoteWitness>,
    pub slots: Vec<SettlementSlot>,
}

pub const fn context_offset(capacity: usize) -> usize {
    capacity * common::DIGEST
}
pub const fn reward_mode_offset(capacity: usize) -> usize {
    context_offset(capacity) + LIMBS
}
pub const fn reward_allocations_offset(capacity: usize) -> usize {
    context_offset(capacity) + LIMBS + 2 + 32
}
pub const fn reward_commitments_offset(capacity: usize) -> usize {
    reward_allocations_offset(capacity) + MAX_REWARD_NOTES * 2 * LIMBS
}
pub const fn public_len(capacity: usize) -> usize {
    reward_commitments_offset(capacity) + MAX_REWARD_NOTES * common::DIGEST
}
fn byte_limbs(bytes: &[u8; 32]) -> [F; 16] {
    core::array::from_fn(|i| {
        F::from_u32(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32)
    })
}
/// Build the fixed statement from locally authenticated context, never from a peer's proof statement.
pub fn settlement_public(
    fees: &[common::Digest],
    plan: &RewardPlan,
    network: [u8; 32],
    list_hash: [u8; 32],
    commitments: &[common::Digest],
) -> Result<Vec<F>, String> {
    plan.validate()?;
    if fees.is_empty() || commitments.len() != plan.mode.note_count() {
        return Err("settlement commitment count mismatch".into());
    }
    let mut out = Vec::with_capacity(public_len(fees.len()));
    for fee in fees {
        out.extend_from_slice(fee);
    }
    out.extend_from_slice(&common::limbs(plan.block_height));
    out.push(F::from_u32(plan.mode as u32));
    out.push(F::from_usize(plan.mode.note_count()));
    out.extend_from_slice(&byte_limbs(&network));
    out.extend_from_slice(&byte_limbs(&list_hash));
    for i in 0..MAX_REWARD_NOTES {
        if let Some(a) = plan.allocations.get(i) {
            out.extend_from_slice(&common::limbs(a.amount));
            out.extend_from_slice(&common::limbs(a.unlock_height));
        } else {
            out.extend_from_slice(&[F::ZERO; 2 * LIMBS]);
        }
    }
    for i in 0..MAX_REWARD_NOTES {
        out.extend_from_slice(commitments.get(i).unwrap_or(&[F::ZERO; common::DIGEST]));
    }
    validate_settlement_public(fees.len(), &out)?;
    Ok(out)
}
pub fn validate_settlement_public(capacity: usize, public: &[F]) -> Result<(), String> {
    if capacity == 0 || public.len() != public_len(capacity) {
        return Err("invalid settlement public-input length".into());
    }
    let start = context_offset(capacity);
    let commitments = reward_commitments_offset(capacity);
    if public[start..commitments]
        .iter()
        .any(|x| x.as_canonical_u32() >= (1 << LIMB_BITS))
    {
        return Err("noncanonical settlement numeric or context limb".into());
    }
    let mode = public[reward_mode_offset(capacity)].as_canonical_u32();
    let count = match mode {
        0 => 1,
        1 => 5,
        _ => return Err("invalid reward mode".into()),
    };
    if public[reward_mode_offset(capacity) + 1].as_canonical_u32() as usize != count {
        return Err("reward count differs from mode".into());
    }
    let integer = |offset| {
        (0..LIMBS).fold(0u64, |a, k| {
            a | ((public[offset + k].as_canonical_u32() as u64) << (k * LIMB_BITS))
        })
    };
    let height = integer(start);
    for i in 0..MAX_REWARD_NOTES {
        let allocation = reward_allocations_offset(capacity) + i * 2 * LIMBS;
        let cm = commitments + i * common::DIGEST;
        if i < count {
            if integer(allocation + LIMBS) < height {
                return Err("reward unlock precedes block".into());
            }
            if public[cm..cm + common::DIGEST]
                .iter()
                .all(|x| *x == F::ZERO)
            {
                return Err("zero active reward commitment".into());
            }
            for previous in 0..i {
                let p = commitments + previous * common::DIGEST;
                if public[p..p + common::DIGEST] == public[cm..cm + common::DIGEST] {
                    return Err("duplicate reward commitment".into());
                }
            }
        } else if public[allocation..allocation + 2 * LIMBS]
            .iter()
            .chain(&public[cm..cm + common::DIGEST])
            .any(|x| *x != F::ZERO)
        {
            return Err("noncanonical inactive reward slot".into());
        }
    }
    for (i, left) in public[..start]
        .as_chunks::<{ common::DIGEST }>()
        .0
        .iter()
        .enumerate()
    {
        if public[..i * common::DIGEST]
            .as_chunks::<{ common::DIGEST }>()
            .0
            .iter()
            .any(|right| left == right)
        {
            return Err("duplicate settlement commitment".into());
        }
    }
    Ok(())
}
impl FixedSettlementWitness {
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub fn reward_note(&self, index: usize) -> common::Note {
        let reward = &self.rewards[index];
        common::Note {
            asset_id: reward.asset_id,
            owner: reward.owner,
            value: reward.amount,
            unlock_height: self.plan.allocations[index].unlock_height,
            rho: Hasher::new().reward_rho(self.plan.block_height, index),
            rseed: reward.rseed,
        }
    }
    pub fn reward_commitments(&self) -> Vec<common::Digest> {
        let h = Hasher::new();
        (0..self.rewards.len())
            .map(|i| h.note_cm(&self.reward_note(i)))
            .collect()
    }
    pub fn public_inputs(&self) -> Vec<F> {
        settlement_public(
            &self.slots.iter().map(|s| s.commitment).collect::<Vec<_>>(),
            &self.plan,
            self.network,
            self.transaction_list_digest,
            &self.reward_commitments(),
        )
        .expect("canonical reward context")
    }
    pub fn check(&self, h: &Hasher) -> Result<(), SettlementError> {
        self.plan
            .validate()
            .map_err(|_| SettlementError::InvalidRewardPlan)?;
        if self.rewards.len() != self.plan.mode.note_count() {
            return Err(SettlementError::InvalidRewardPlan);
        }
        if self.slots.is_empty() {
            return Err(SettlementError::EmptySettlement);
        }
        let mut sum = 0u64;
        for (i, slot) in self.slots.iter().enumerate() {
            if self.slots[..i]
                .iter()
                .any(|s| s.commitment == slot.commitment)
            {
                return Err(SettlementError::DuplicateCommitment { index: i });
            }
            if h.fee_commit(slot.opening.fee, &slot.opening.blind) != slot.commitment {
                return Err(SettlementError::CommitmentMismatch { index: i });
            }
            sum = sum
                .checked_add(slot.opening.fee)
                .ok_or(SettlementError::FeeSumOverflow)?;
        }
        for (i, (r, a)) in self.rewards.iter().zip(&self.plan.allocations).enumerate() {
            if r.asset_id != common::SIP_ASSET_ID {
                return Err(SettlementError::MinerAssetNotSip);
            }
            let expected = a
                .amount
                .checked_add(if i == 0 { sum } else { 0 })
                .ok_or(SettlementError::RewardOverflow)?;
            if r.amount != expected {
                return Err(SettlementError::MinerAmountMismatch {
                    expected,
                    actual: r.amount,
                });
            }
        }
        Ok(())
    }
}

pub type FeeP2Air = Poseidon2Air<F, LinearLayers, WIDTH, 3, 0, 4, 23>;
const P2_OUT: usize = P2 - WIDTH;
const FEE: usize = P2;
const BLIND: usize = FEE + LIMBS;
const SUM: usize = BLIND + common::FEE_BLIND_LEN;
const SUM_CARRY: usize = SUM + LIMBS;
const REWARD_CARRY: usize = SUM_CARRY + LIMBS - 1;
const RANGE_BITS: usize = REWARD_CARRY + LIMBS - 1;
const IMMEDIATE_AMOUNT: usize = RANGE_BITS + LIMBS * LIMB_BITS;
const IMMEDIATE_BITS: usize = IMMEDIATE_AMOUNT + LIMBS;
const NOTE_AMOUNT: usize = IMMEDIATE_BITS + LIMBS * LIMB_BITS;
const NOTE_BITS: usize = NOTE_AMOUNT + LIMBS;
const OWNER: usize = NOTE_BITS + LIMBS * LIMB_BITS;
const RSEED: usize = OWNER + common::DIGEST;
const RHO: usize = RSEED + common::DIGEST;
const UNLOCK: usize = RHO + common::DIGEST;
const UNLOCK_BITS: usize = UNLOCK + LIMBS;
const ASSET: usize = UNLOCK_BITS + LIMBS * LIMB_BITS;
const MAIN_WIDTH: usize = ASSET + 16;
const PRE_ACTIVE: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_LAST: usize = 2;
const PRE_REWARD: usize = 3;
const REWARD_ROWS: usize = 6;
const PRE_SLOTS: usize = PRE_REWARD + MAX_REWARD_NOTES * REWARD_ROWS;
pub struct SettlementAir {
    pub capacity: usize,
    pub height: usize,
    p2: FeeP2Air,
}
impl SettlementAir {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            capacity,
            height: (capacity + MAX_REWARD_NOTES * REWARD_ROWS).next_power_of_two(),
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
    pub fn constraint_count(&self, w: &FixedSettlementWitness) -> usize {
        let (t, p) = generate_trace(self, w);
        check_all_constraints(self, &t, &p, Some(1)).total_constraints_per_row
    }
    pub fn with_min_height(mut self, height: usize) -> Self {
        assert!(height.is_power_of_two());
        self.height = self.height.max(height);
        self
    }
    fn slot_selector(&self, i: usize) -> usize {
        PRE_SLOTS + i
    }
    fn reward_selector(&self, i: usize, stage: usize) -> usize {
        PRE_REWARD + i * REWARD_ROWS + stage
    }
}
impl BaseAir<F> for SettlementAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        public_len(self.capacity)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.preprocessed_width();
        let mut values = F::zero_vec(self.height * width);
        for r in 0..self.capacity {
            values[r * width + PRE_ACTIVE] = F::ONE;
            values[r * width + self.slot_selector(r)] = F::ONE;
        }
        values[PRE_FIRST] = F::ONE;
        values[(self.capacity - 1) * width + PRE_LAST] = F::ONE;
        for i in 0..MAX_REWARD_NOTES {
            for stage in 0..REWARD_ROWS {
                values[(self.capacity + i * REWARD_ROWS + stage) * width
                    + self.reward_selector(i, stage)] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(values, width))
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for SettlementAir {
    fn eval(&self, b: &mut AB) {
        let mut sub = SubAirBuilder::<AB, FeeP2Air, AB::Var>::new(b, 0..P2);
        self.p2.eval(&mut sub);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = main.current_slice();
        let n = main.next_slice();
        let pl = pre.current_slice();
        let pis = b.public_values().to_vec();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let active = x(pl[PRE_ACTIVE]);
        let first = x(pl[PRE_FIRST]);
        let last = x(pl[PRE_LAST]);
        for e in 0..RATE {
            let expected = if e < LIMBS {
                x(l[FEE + e])
            } else {
                x(l[BLIND + e - LIMBS])
            };
            b.assert_zero((x(l[e]) - expected) * active.clone());
        }
        b.assert_zero((x(l[RATE]) - F::from_u32(common::TAG_FEE)) * active.clone());
        b.assert_zero((x(l[RATE + 1]) - F::ONE) * active.clone());
        for e in RATE + 2..WIDTH {
            b.assert_zero(x(l[e]) * active.clone());
        }
        for i in 0..self.capacity {
            for e in 0..common::DIGEST {
                b.assert_zero(
                    (x(l[P2_OUT + e]) - pis[i * common::DIGEST + e].into())
                        * x(pl[self.slot_selector(i)]),
                );
            }
        }
        for (start, bits) in [
            (FEE, RANGE_BITS),
            (IMMEDIATE_AMOUNT, IMMEDIATE_BITS),
            (NOTE_AMOUNT, NOTE_BITS),
            (UNLOCK, UNLOCK_BITS),
        ] {
            for k in 0..LIMBS {
                let mut limb = AB::Expr::ZERO;
                for bit in 0..LIMB_BITS {
                    b.assert_bool(l[bits + k * LIMB_BITS + bit]);
                    limb += x(l[bits + k * LIMB_BITS + bit]) * F::from_u32(1 << bit);
                }
                b.assert_eq(limb, l[start + k]);
            }
        }
        for k in 0..LIMBS {
            let carry = if k + 1 < LIMBS {
                b.assert_bool(l[SUM_CARRY + k]);
                x(l[SUM_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            let previous = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[SUM_CARRY + k - 1])
            };
            b.assert_zero(
                (x(l[SUM + k]) + x(n[FEE + k]) + previous
                    - x(n[SUM + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * (active.clone() - last.clone()),
            );
            b.assert_zero((x(l[SUM + k]) - x(l[FEE + k])) * first.clone());
            let carry = if k + 1 < LIMBS {
                b.assert_bool(l[REWARD_CARRY + k]);
                x(l[REWARD_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            let previous = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[REWARD_CARRY + k - 1])
            };
            b.assert_zero(
                (x(l[SUM + k])
                    + pis[reward_allocations_offset(self.capacity) + k].into()
                    + previous
                    - x(l[IMMEDIATE_AMOUNT + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * last.clone(),
            );
            b.when_transition()
                .assert_eq(l[IMMEDIATE_AMOUNT + k], n[IMMEDIATE_AMOUNT + k]);
        }
        let mode: AB::Expr = pis[reward_mode_offset(self.capacity)].into();
        b.assert_bool(mode.clone());
        b.assert_eq(
            pis[reward_mode_offset(self.capacity) + 1],
            AB::Expr::ONE + mode.clone() * F::from_u32(4),
        );
        for limb in 0..16 {
            b.assert_zero(l[ASSET + limb]);
        }
        for i in 0..MAX_REWARD_NOTES {
            let enabled = if i == 0 { AB::Expr::ONE } else { mode.clone() };
            let inactive = AB::Expr::ONE - enabled.clone();
            let allocation = reward_allocations_offset(self.capacity) + i * 2 * LIMBS;
            for e in 0..2 * LIMBS {
                b.assert_zero(pis[allocation + e].into() * inactive.clone());
            }
            for e in 0..common::DIGEST {
                b.assert_zero(
                    pis[reward_commitments_offset(self.capacity) + i * common::DIGEST + e].into()
                        * inactive.clone(),
                );
            }
            for stage in 0..REWARD_ROWS {
                let selector = x(pl[self.reward_selector(i, stage)]);
                let selected = selector.clone() * enabled.clone();
                for k in 0..LIMBS {
                    let amount = if i == 0 {
                        x(l[IMMEDIATE_AMOUNT + k])
                    } else {
                        pis[allocation + k].into()
                    };
                    b.assert_zero((x(l[NOTE_AMOUNT + k]) - amount) * selected.clone());
                    b.assert_zero(
                        (x(l[UNLOCK + k]) - pis[allocation + LIMBS + k].into()) * selected.clone(),
                    );
                }
                if stage + 1 < REWARD_ROWS {
                    for col in NOTE_AMOUNT..MAIN_WIDTH {
                        b.when_transition()
                            .assert_zero((x(n[col]) - x(l[col])) * selector.clone());
                    }
                }
                for col in NOTE_AMOUNT..MAIN_WIDTH {
                    b.assert_zero(x(l[col]) * selector.clone() * inactive.clone());
                }
                for e in 0..RATE {
                    let value = match stage {
                        0 if e < LIMBS => pis[context_offset(self.capacity) + e].into(),
                        0 if e == LIMBS => AB::Expr::from_u32(i as u32),
                        0 => AB::Expr::ZERO,
                        1 => x(l[OWNER + e]),
                        2 if e < LIMBS => x(l[NOTE_AMOUNT + e]),
                        2 if e < 2 * LIMBS => x(l[UNLOCK + e - LIMBS]),
                        2 => x(l[ASSET + e - 2 * LIMBS]),
                        3 => x(l[ASSET + e + 4]),
                        4 => x(l[RHO + e]),
                        _ => x(l[RSEED + e]),
                    };
                    b.assert_zero((x(l[e]) - value) * selected.clone());
                }
                if stage <= 1 {
                    for e in RATE..WIDTH {
                        let value = if e == RATE {
                            F::from_u32(if stage == 0 {
                                common::TAG_MINER_RHO
                            } else {
                                common::TAG_NOTE
                            })
                        } else if e == RATE + 1 {
                            F::from_u32(if stage == 0 { 1 } else { 5 })
                        } else {
                            F::ZERO
                        };
                        b.assert_zero((x(l[e]) - value) * selected.clone());
                    }
                }
                if (1..5).contains(&stage) {
                    for e in RATE..WIDTH {
                        b.when_transition()
                            .assert_zero((x(n[e]) - x(l[P2_OUT + e])) * selected.clone());
                    }
                }
                if stage == 0 {
                    for e in 0..common::DIGEST {
                        b.assert_zero((x(l[P2_OUT + e]) - x(l[RHO + e])) * selected.clone());
                    }
                }
                if stage == 5 {
                    for e in 0..common::DIGEST {
                        b.assert_zero(
                            (x(l[P2_OUT + e])
                                - pis[reward_commitments_offset(self.capacity)
                                    + i * common::DIGEST
                                    + e]
                                    .into())
                                * selected.clone(),
                        );
                    }
                }
                for e in 0..WIDTH {
                    b.assert_zero(x(l[e]) * selector.clone() * inactive.clone());
                }
            }
        }
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
            .expect("settlement preprocessing")
            .expect("preprocessed AIR");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }
    pub fn prove(&self, w: &FixedSettlementWitness) -> (Proof<Cfg>, Vec<F>) {
        assert_eq!(w.capacity(), self.air.capacity);
        w.check(&Hasher::new()).expect("invalid reward settlement");
        let (trace, public) = generate_trace(&self.air, w);
        let proof =
            prove_with_preprocessed(&self.cfg, &self.air, trace, &public, Some(&self.pdata))
                .expect("settlement proof generation");
        (proof, public)
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        validate_settlement_public(self.air.capacity, public)?;
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
}
fn put_bits(rows: &mut [F], offset: usize, start: usize, bits: usize, value: u64) {
    let limbs = common::limbs(value);
    rows[offset + start..offset + start + LIMBS].copy_from_slice(&limbs);
    for k in 0..LIMBS {
        for bit in 0..LIMB_BITS {
            rows[offset + bits + k * LIMB_BITS + bit] =
                F::from_u32((limbs[k].as_canonical_u32() >> bit) & 1);
        }
    }
}
pub(crate) fn generate_trace(
    air: &SettlementAir,
    w: &FixedSettlementWitness,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let h = Hasher::new();
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for r in 0..air.capacity {
        let off = r * MAIN_WIDTH;
        let slot = &w.slots[r];
        inputs[r] = Hasher::first_input(
            common::TAG_FEE,
            1,
            &common::fee_block(slot.opening.fee, &slot.opening.blind),
        );
        put_bits(&mut rows, off, FEE, RANGE_BITS, slot.opening.fee);
        rows[off + BLIND..off + BLIND + common::FEE_BLIND_LEN].copy_from_slice(&slot.opening.blind);
        sum = sum.checked_add(slot.opening.fee).expect("fee sum overflow");
        let limbs = common::limbs(sum);
        rows[off + SUM..off + SUM + LIMBS].copy_from_slice(&limbs);
        if r + 1 < air.capacity {
            let next = common::limbs(w.slots[r + 1].opening.fee);
            let mut carry = 0u64;
            for k in 0..LIMBS - 1 {
                carry = (u64::from(limbs[k].as_canonical_u32())
                    + u64::from(next[k].as_canonical_u32())
                    + carry)
                    >> LIMB_BITS;
                rows[off + SUM_CARRY + k] = F::from_u64(carry);
            }
        }
    }
    for r in 0..air.height {
        put_bits(
            &mut rows,
            r * MAIN_WIDTH,
            IMMEDIATE_AMOUNT,
            IMMEDIATE_BITS,
            w.rewards[0].amount,
        );
    }
    let final_off = (air.capacity - 1) * MAIN_WIDTH;
    let total = common::limbs(sum);
    let base = common::limbs(w.plan.allocations[0].amount);
    let mut carry = 0u64;
    for k in 0..LIMBS - 1 {
        carry = (u64::from(total[k].as_canonical_u32())
            + u64::from(base[k].as_canonical_u32())
            + carry)
            >> LIMB_BITS;
        rows[final_off + REWARD_CARRY + k] = F::from_u64(carry);
    }
    for i in 0..w.rewards.len() {
        let note = w.reward_note(i);
        let row = air.capacity + i * REWARD_ROWS;
        let mut block = common::padded_block(&common::limbs(w.plan.block_height));
        block[LIMBS] = F::from_usize(i);
        inputs[row] = Hasher::first_input(common::TAG_MINER_RHO, 1, &block);
        let (note_inputs, _) = h.sponge_trace(common::TAG_NOTE, &note.blocks());
        inputs[row + 1..row + 6].copy_from_slice(&note_inputs);
        for r in row..row + REWARD_ROWS {
            let off = r * MAIN_WIDTH;
            put_bits(&mut rows, off, NOTE_AMOUNT, NOTE_BITS, note.value);
            put_bits(&mut rows, off, UNLOCK, UNLOCK_BITS, note.unlock_height);
            rows[off + OWNER..off + OWNER + common::DIGEST].copy_from_slice(&note.owner);
            rows[off + RSEED..off + RSEED + common::DIGEST].copy_from_slice(&note.rseed);
            rows[off + RHO..off + RHO + common::DIGEST].copy_from_slice(&note.rho);
            rows[off + ASSET..off + ASSET + 16].copy_from_slice(&note.asset_id.limbs());
        }
    }
    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for r in 0..air.height {
        rows[r * MAIN_WIDTH..r * MAIN_WIDTH + P2].copy_from_slice(&p2.values[r * P2..(r + 1) * P2]);
    }
    (RowMajorMatrix::new(rows, MAIN_WIDTH), w.public_inputs())
}
/// Synthetic fixed-shape fixture; its allocation is not a consensus economics oracle.
pub fn sample_fixed_settlement_witness(
    capacity: usize,
    mode: RewardMode,
) -> FixedSettlementWitness {
    let h = Hasher::new();
    let slots = (0..capacity)
        .map(|i| {
            let opening = FeeOpening {
                fee: if i == 0 { 1000 } else { 0 },
                blind: core::array::from_fn(|j| F::from_usize(1 + i * 8 + j)),
                dummy: i != 0,
                priority: false,
            };
            SettlementSlot::from_opening(&h, opening)
        })
        .collect();
    let allocations = (0..mode.note_count())
        .map(|i| RewardAllocation {
            amount: if i == 0 { 60_000 } else { 10_000 },
            unlock_height: 1000
                + if i == 0 {
                    24
                } else {
                    HOLDER_UNLOCK_OFFSETS[i - 1]
                },
        })
        .collect::<Vec<_>>();
    let rewards = allocations
        .iter()
        .enumerate()
        .map(|(i, a)| RewardNoteWitness {
            asset_id: common::SIP_ASSET_ID,
            owner: core::array::from_fn(|j| F::from_usize(800 + j)),
            rseed: core::array::from_fn(|j| F::from_usize(900 + i * 12 + j)),
            amount: a.amount + if i == 0 { 1000 } else { 0 },
        })
        .collect();
    FixedSettlementWitness {
        plan: RewardPlan {
            block_height: 1000,
            mode,
            allocations,
        },
        network: [9; 32],
        transaction_list_digest: [11; 32],
        rewards,
        slots,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_modes_satisfy_air_and_all_context_fields_are_bound() {
        for mode in [RewardMode::Voyager, RewardMode::Holder] {
            let w = sample_fixed_settlement_witness(4, mode);
            let air = SettlementAir::new(4);
            let (t, p) = generate_trace(&air, &w);
            assert!(
                check_all_constraints(&air, &t, &p, Some(1))
                    .failures
                    .is_empty()
            );
            let prover = SettlementProver::new(4, FriParams::fast());
            let (proof, p) = prover.prove(&w);
            prover.verify(&proof, &p).unwrap();
            for i in 0..p.len() {
                let mut changed = p.clone();
                changed[i] += F::ONE;
                assert!(prover.verify(&proof, &changed).is_err(), "field {i}");
            }
        }
    }
    #[test]
    fn reward_count_inactive_slots_and_numeric_encodings_are_canonical() {
        let w = sample_fixed_settlement_witness(4, RewardMode::Voyager);
        let mut p = w.public_inputs();
        p[reward_mode_offset(4) + 1] = F::from_u32(5);
        assert!(validate_settlement_public(4, &p).is_err());
        let mut p = w.public_inputs();
        p[reward_commitments_offset(4) + common::DIGEST] = F::ONE;
        assert!(validate_settlement_public(4, &p).is_err());
        let mut p = w.public_inputs();
        p[context_offset(4)] = F::from_u32(1 << LIMB_BITS);
        assert!(validate_settlement_public(4, &p).is_err());
    }
    #[test]
    fn private_fee_carries_and_each_reward_rho_are_constrained() {
        let h = Hasher::new();
        let mut w = sample_fixed_settlement_witness(4, RewardMode::Holder);
        let fees = [u16::MAX as u64, u32::MAX as u64, (1u64 << 48) - 1, 7];
        let mut sum = 0u64;
        for (slot, fee) in w.slots.iter_mut().zip(fees) {
            slot.opening.fee = fee;
            slot.commitment = h.fee_commit(fee, &slot.opening.blind);
            sum = sum.checked_add(fee).unwrap();
        }
        w.rewards[0].amount = w.plan.allocations[0].amount + sum;
        w.check(&h).unwrap();
        let air = SettlementAir::new(4);
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
        for (row, column) in [
            (0, SUM_CARRY),
            (3, REWARD_CARRY),
            (4, IMMEDIATE_AMOUNT),
            (4, NOTE_AMOUNT),
        ] {
            let mut changed = trace.clone();
            changed.values[row * MAIN_WIDTH + column] += F::ONE;
            assert!(
                !check_all_constraints(&air, &changed, &public, Some(1))
                    .failures
                    .is_empty(),
                "row {row}, column {column}"
            );
        }
        for index in 1..MAX_REWARD_NOTES {
            let mut changed = trace.clone();
            let rho = h.reward_rho(w.plan.block_height, 0);
            for stage in 0..REWARD_ROWS {
                let start = (w.capacity() + index * REWARD_ROWS + stage) * MAIN_WIDTH + RHO;
                changed.values[start..start + common::DIGEST].copy_from_slice(&rho);
            }
            assert!(
                !check_all_constraints(&air, &changed, &public, Some(1))
                    .failures
                    .is_empty(),
                "reward index {index}"
            );
        }
    }
    #[test]
    fn host_rejects_fee_overflow_and_air_rejects_wrapped_immediate_reward() {
        let h = Hasher::new();
        let mut w = sample_fixed_settlement_witness(4, RewardMode::Voyager);
        for (slot, fee) in w.slots.iter_mut().zip([u64::MAX, 1, 0, 0]) {
            slot.opening.fee = fee;
            slot.commitment = h.fee_commit(fee, &slot.opening.blind);
        }
        assert_eq!(w.check(&h), Err(SettlementError::FeeSumOverflow));
        let mut w = sample_fixed_settlement_witness(4, RewardMode::Voyager);
        w.plan.allocations[0].amount = u64::MAX;
        w.rewards[0].amount = w.slots.iter().map(|s| s.opening.fee).sum::<u64>() - 1;
        assert_eq!(w.check(&h), Err(SettlementError::RewardOverflow));
        let air = SettlementAir::new(4);
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            !check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
    }
    #[test]
    fn voyager_cannot_activate_unprovided_holder_notes_by_changing_mode() {
        let w = sample_fixed_settlement_witness(4, RewardMode::Voyager);
        let air = SettlementAir::new(4);
        let (trace, mut public) = generate_trace(&air, &w);
        public[reward_mode_offset(4)] = F::ONE;
        public[reward_mode_offset(4) + 1] = F::from_u32(5);
        assert!(validate_settlement_public(4, &public).is_err());
        assert!(
            !check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
    }
    #[test]
    fn non_sip_reward_is_rejected_by_the_air() {
        let mut w = sample_fixed_settlement_witness(4, RewardMode::Holder);
        w.rewards[2].asset_id = common::AssetId([2; 32]);
        assert!(w.check(&Hasher::new()).is_err());
        let air = SettlementAir::new(4);
        let (t, p) = generate_trace(&air, &w);
        assert!(
            !check_all_constraints(&air, &t, &p, Some(1))
                .failures
                .is_empty()
        );
    }
}
