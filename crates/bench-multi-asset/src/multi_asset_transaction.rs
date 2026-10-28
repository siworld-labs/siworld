//! Native D8/W24 transaction proof with a private recent-root membership path.
//!
//! The existing accumulator leaf relation is embedded as a sub-AIR. Its anchor
//! entry is private in this proof; a second Poseidon2 trace proves that entry's
//! depth-12 membership and binds its position to the private anchor height.
//! Public values are `[E, fee commitment, 1, recent_roots_root]`. A verifier must
//! recompute E from the canonical public transaction encoding before verifying.
//! This module does not change the retained network's codec or proof system.

use crate::multi_asset::{
    ANCHOR_DEPTH, AccWitness, DCT_BYTES, DIGEST, Digest, F, Hasher, LIMB_BITS, PublicInputs, WIDTH,
    digest_of, pack_dct,
};
use crate::multi_asset_air::{
    ACC_ENTRY_CONF, ACC_HB, ACC_REG, LinearLayers, NUM_ACC_CONF_PUBLIC, OUT, P2, P2Air, SlotAir,
    p2_constants,
};
use crate::{Cfg, FriParams, multi_asset_trace as trace};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, SubAirBuilder, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};
use std::ops::Range;

/// The public statement retains the accumulator's layout but replaces its
/// per-transaction anchor entry with the shared recent-root tree root.
pub const TRANSACTION_SNAPSHOT_HEIGHT: usize = NUM_ACC_CONF_PUBLIC;
pub const NUM_TRANSACTION_PUBLIC: usize = NUM_ACC_CONF_PUBLIC + crate::multi_asset::LIMBS;
pub const TRANSACTION_ROOT: usize = ACC_ENTRY_CONF;

/// Recompute the proof statement from canonical decoded transaction fields.
/// The caller supplies the current accepted recent-root tree root, never a
/// root copied from an untrusted proof. Ciphertext/nonces/tags must all enter
/// `ciphertext_digest` through the canonical codec's domain-separated hash.
pub fn statement_for(
    nullifiers: &[Digest; 2],
    commitments: &[Digest; 3],
    ciphertext_digest: &[u8; DCT_BYTES],
    fee_commit: &Digest,
    recent_roots_root: &Digest,
    snapshot_height: u64,
) -> Vec<F> {
    let inputs = PublicInputs {
        nf: *nullifiers,
        cm_out: *commitments,
        anchor: [F::ZERO; DIGEST],
        fee_commit: *fee_commit,
    };
    let mut statement = inputs
        .set_element(&Hasher::new(), &pack_dct(ciphertext_digest))
        .to_vec();
    statement.extend_from_slice(fee_commit);
    statement.push(F::ONE);
    statement.extend_from_slice(recent_roots_root);
    statement.extend_from_slice(&crate::multi_asset::limbs(snapshot_height));
    statement
}

/// Main columns after the embedded leaf: its now-private statement, a second
/// Poseidon2 permutation, the current path direction and the low height bits.
const HEIGHT_BITS: usize = LIMB_BITS;

pub struct TransactionAir {
    pub slot: SlotAir,
    path_p2: P2Air,
}

impl Default for TransactionAir {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionAir {
    pub fn new() -> Self {
        Self {
            slot: SlotAir::new_acc_confidential_for_snapshot(),
            path_p2: P2Air::new(p2_constants()),
        }
    }

    pub fn with_min_height(mut self, height: usize) -> Self {
        self.slot = self.slot.with_min_height(height);
        self
    }

    pub fn degree_bits(&self) -> usize {
        self.slot.degree_bits()
    }

    fn statement(&self) -> usize {
        self.slot.main_width()
    }

    fn path(&self) -> usize {
        self.statement() + NUM_TRANSACTION_PUBLIC
    }

    fn bit(&self) -> usize {
        self.path() + P2
    }

    fn height_bits(&self) -> usize {
        self.bit() + 1
    }

    fn selector(&self) -> usize {
        self.slot.preprocessed_width()
    }

    /// Generate a trace without accepting or repairing an invalid witness.
    /// Constraint checking or proof verification remains the validity decision.
    pub fn generate(&self, w: &AccWitness) -> (RowMajorMatrix<F>, Vec<F>) {
        self.generate_at_snapshot(w, w.anchor_height)
    }

    pub fn generate_at_snapshot(
        &self,
        w: &AccWitness,
        snapshot_height: u64,
    ) -> (RowMajorMatrix<F>, Vec<F>) {
        assert_eq!(w.anchor_path.len(), ANCHOR_DEPTH, "anchor path length");
        let (leaf, private_statement) =
            trace::generate_acc_confidential_at_snapshot(&self.slot, w, snapshot_height);
        let mut public = private_statement.clone();
        public[TRANSACTION_ROOT..TRANSACTION_ROOT + DIGEST]
            .copy_from_slice(&w.anchors_root(&Hasher::new()));
        let h = Hasher::new();
        let mut current = w.anchor_entry(&h);
        let mut path_inputs = Vec::with_capacity(self.slot.height);
        let mut directions = vec![F::ZERO; self.slot.height];
        for (level, (sibling, right)) in w.anchor_path.iter().enumerate() {
            let input = if *right {
                Hasher::compress_input(sibling, &current)
            } else {
                Hasher::compress_input(&current, sibling)
            };
            path_inputs.push(input);
            directions[level] = F::from_bool(*right);
            current = digest_of(&h.permute(input));
        }
        path_inputs.resize(self.slot.height, [F::ZERO; WIDTH]);
        let path = generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
            path_inputs,
            &p2_constants(),
            0,
        );
        let bits: Vec<F> = (0..HEIGHT_BITS)
            .map(|i| F::from_u32(((w.anchor_height >> i) & 1) as u32))
            .collect();
        let mut values = Vec::with_capacity(self.slot.height * self.width());
        for (row, direction) in directions.into_iter().enumerate() {
            values.extend_from_slice(leaf.row_slice(row).unwrap().as_ref());
            values.extend_from_slice(&private_statement);
            values.extend_from_slice(path.row_slice(row).unwrap().as_ref());
            values.push(direction);
            values.extend_from_slice(&bits);
            for limb in crate::multi_asset::limbs_u32(snapshot_height) {
                values.extend((0..LIMB_BITS).map(|bit| F::from_u32((limb >> bit) & 1)));
            }
        }
        (RowMajorMatrix::new(values, self.width()), public)
    }
}

impl BaseAir<F> for TransactionAir {
    fn width(&self) -> usize {
        self.height_bits() + HEIGHT_BITS + crate::multi_asset::LIMBS * LIMB_BITS
    }

    fn preprocessed_width(&self) -> usize {
        self.selector() + ANCHOR_DEPTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let leaf = self.slot.preprocessed_trace().expect("leaf selectors");
        let mut values = Vec::with_capacity(self.slot.height * self.preprocessed_width());
        for row in 0..self.slot.height {
            values.extend_from_slice(leaf.row_slice(row).unwrap().as_ref());
            values.extend((0..ANCHOR_DEPTH).map(|level| F::from_bool(row == level)));
        }
        Some(RowMajorMatrix::new(values, self.preprocessed_width()))
    }

    fn num_public_values(&self) -> usize {
        NUM_TRANSACTION_PUBLIC
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

/// A window view used to embed the leaf with private statement values.
#[derive(Clone)]
struct Columns<W> {
    inner: W,
    range: Range<usize>,
}

impl<W: WindowAccess<T>, T> WindowAccess<T> for Columns<W> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.range.clone()]
    }
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.range.clone()]
    }
}

/// The embedded leaf consumes its original public statement from private,
/// row-constant trace registers. Outer constraints bind all non-anchor values
/// to the actual public statement and replace the anchor entry by membership.
struct PrivateStatementBuilder<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    main: Columns<AB::MainWindow>,
    pre: Columns<AB::PreprocessedWindow>,
    statement: Vec<AB::Var>,
}

impl<AB: AirBuilder> AirBuilder for PrivateStatementBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type MainWindow = Columns<AB::MainWindow>;
    type PreprocessedWindow = Columns<AB::PreprocessedWindow>;
    type PublicVar = AB::Var;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.pre
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.inner.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.statement
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for TransactionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let private_statement = main.current_slice()
            [self.statement()..self.statement() + NUM_TRANSACTION_PUBLIC]
            .to_vec();
        let pre = builder.preprocessed().clone();
        let mut leaf_builder = PrivateStatementBuilder {
            main: Columns {
                inner: main.clone(),
                range: 0..self.slot.main_width(),
            },
            pre: Columns {
                inner: pre.clone(),
                range: 0..self.slot.preprocessed_width(),
            },
            statement: private_statement,
            inner: builder,
        };
        self.slot.eval(&mut leaf_builder);
        {
            let mut path_builder =
                SubAirBuilder::<AB, P2Air, AB::Var>::new(builder, self.path()..self.path() + P2);
            self.path_p2.eval(&mut path_builder);
        }
        let public = builder.public_values().to_vec();
        let local = main.current_slice();
        let next = main.next_slice();
        let selectors = pre.current_slice();
        let next_selectors = pre.next_slice();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        for col in self.statement()..self.path() {
            builder.when_transition().assert_eq(next[col], local[col]);
        }
        for i in 0..TRANSACTION_ROOT {
            builder.assert_eq(local[self.statement() + i], public[i]);
        }
        for k in 0..crate::multi_asset::LIMBS {
            builder.assert_eq(
                local[self.statement() + TRANSACTION_SNAPSHOT_HEIGHT + k],
                public[TRANSACTION_SNAPSHOT_HEIGHT + k],
            );
        }
        let mut height_low = AB::Expr::ZERO;
        for bit in 0..HEIGHT_BITS {
            let col = self.height_bits() + bit;
            builder.assert_bool(local[col]);
            builder.when_transition().assert_eq(next[col], local[col]);
            height_low += x(local[col]) * F::from_u32(1 << bit);
        }
        builder.assert_eq(height_low, local[ACC_REG + ACC_HB]);
        for k in 0..crate::multi_asset::LIMBS {
            let mut limb = AB::Expr::ZERO;
            for bit in 0..LIMB_BITS {
                let col = self.height_bits() + HEIGHT_BITS + k * LIMB_BITS + bit;
                builder.assert_bool(local[col]);
                limb += x(local[col]) * F::from_u32(1 << bit);
            }
            builder.assert_eq(limb, public[TRANSACTION_SNAPSHOT_HEIGHT + k]);
        }
        builder.assert_bool(local[self.bit()]);
        for level in 0..ANCHOR_DEPTH {
            let selector = selectors[self.selector() + level];
            builder.assert_zero(
                (x(local[self.bit()]) - x(local[self.height_bits() + level])) * x(selector),
            );
        }
        for element in 0..DIGEST {
            let current = (x(local[self.path() + DIGEST + element])
                - x(local[self.path() + element]))
                * x(local[self.bit()])
                + x(local[self.path() + element]);
            builder.assert_zero(
                (current - x(local[self.statement() + ACC_ENTRY_CONF + element]))
                    * x(selectors[self.selector()]),
            );
            let following = (x(next[self.path() + DIGEST + element])
                - x(next[self.path() + element]))
                * x(next[self.bit()])
                + x(next[self.path() + element]);
            for level in 1..ANCHOR_DEPTH {
                builder.assert_zero(
                    (following.clone() - x(local[self.path() + OUT + element]))
                        * x(next_selectors[self.selector() + level]),
                );
            }
            builder.assert_zero(
                (x(local[self.path() + OUT + element]) - public[TRANSACTION_ROOT + element].into())
                    * x(selectors[self.selector() + ANCHOR_DEPTH - 1]),
            );
        }
    }
}

/// Prepared native transaction prover. No recursive verifier or aggregation
/// circuit is constructed or executed by this interface.
pub struct TransactionProver {
    pub cfg: Cfg,
    pub air: TransactionAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}

impl TransactionProver {
    pub fn new(params: FriParams) -> Self {
        let cfg = params.config();
        let air = TransactionAir::new().with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("transaction preprocessing")
            .expect("transaction has preprocessed columns");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }
    /// Fixture helper; production callers supply a trusted height to `prove_at_snapshot`.
    pub fn prove(&self, witness: &AccWitness) -> (Proof<Cfg>, Vec<F>) {
        self.prove_at_snapshot(witness, witness.anchor_height)
    }
    /// Prove against the canonical snapshot height selected by the verifier.
    pub fn prove_at_snapshot(
        &self,
        witness: &AccWitness,
        snapshot_height: u64,
    ) -> (Proof<Cfg>, Vec<F>) {
        let (trace, public) = self.air.generate_at_snapshot(witness, snapshot_height);
        let proof =
            prove_with_preprocessed(&self.cfg, &self.air, trace, &public, Some(&self.pdata))
                .expect("transaction proof generation");
        (proof, public)
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
    /// Verify against decoded public fields and an accepted anchor-tree root.
    /// This API does not trust a statement supplied alongside the proof.
    pub fn verify_fields(
        &self,
        proof: &Proof<Cfg>,
        nullifiers: &[Digest; 2],
        commitments: &[Digest; 3],
        ciphertext_digest: &[u8; DCT_BYTES],
        fee_commit: &Digest,
        recent_roots_root: &Digest,
        snapshot_height: u64,
    ) -> Result<(), String> {
        self.verify(
            proof,
            &statement_for(
                nullifiers,
                commitments,
                ciphertext_digest,
                fee_commit,
                recent_roots_root,
                snapshot_height,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_asset::{self as m, AssetId, Hasher, SIP_ASSET_ID};
    use crate::multi_asset_air::{self as a, output};
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;

    fn failures(w: &m::AccWitness) -> usize {
        let air = TransactionAir::new();
        let (trace, public) = air.generate(w);
        check_all_constraints(&air, &trace, &public, None)
            .failures
            .len()
    }
    #[test]
    fn accepts_sip_token_and_empty_with_identical_shapes() {
        let air = TransactionAir::new();
        for w in [
            m::sample_witness(90),
            m::sample_token_witness(91),
            m::sample_empty_witness(92),
        ] {
            assert!(
                w.check(&Hasher::new(), &w.anchors_root(&Hasher::new()))
                    .is_ok()
            );
            assert_eq!(failures(&w), 0);
            let (trace, public) = air.generate(&w);
            assert_eq!(public.len(), NUM_TRANSACTION_PUBLIC);
            assert_eq!(trace.width, air.width());
            assert_eq!(trace.height(), air.slot.height);
        }
    }
    #[test]
    fn rejects_cross_asset_netting_and_token_paid_fees() {
        let mut w = m::sample_token_witness(94);
        w.slot.outputs[0].value += 1;
        w.slot.outputs[2].value -= 1;
        assert!(failures(&w) > 0);
        let mut w = m::sample_token_witness(95);
        w.slot.inputs[1].asset_id = w.slot.inputs[0].asset_id;
        w.slot.outputs[2].asset_id = w.slot.inputs[0].asset_id;
        w.slot = m::with_unlock_heights(w.slot, [100, 120]);
        assert!(failures(&w) > 0);
    }
    #[test]
    fn rejects_new_asset_creation_and_altered_id_limbs() {
        let air = TransactionAir::new();
        let w = m::sample_token_witness(97);
        let mut changed = w.clone();
        changed.slot.outputs[0].asset_id = AssetId([19; 32]);
        assert!(failures(&changed) > 0);
        for limb in 0..16 {
            let (mut trace, public) = air.generate(&w);
            let col = a::asset_col(output(0), false, limb);
            for row in trace.values.chunks_exact_mut(trace.width) {
                row[col] += F::ONE;
            }
            assert!(
                !check_all_constraints(&air, &trace, &public, None)
                    .failures
                    .is_empty()
            );
        }
    }
    #[test]
    fn rejects_out_of_range_asset_limb_even_with_updated_public_statement() {
        let w = m::sample_empty_witness(98);
        let slot_air = a::SlotAir::new_acc_confidential();
        let (valid, public) = crate::multi_asset_trace::generate_acc_confidential(&slot_air, &w);
        assert!(
            check_all_constraints(&slot_air, &valid, &public, None)
                .failures
                .is_empty()
        );
        let (trace, public) =
            crate::multi_asset_trace::generate_edited(&slot_air, &w.slot, Some(&w), &|registers| {
                for note in 0..5 {
                    registers[a::asset_col(a::note_base(note), note < 2, 15) - a::REG] =
                        F::from_u32(65536);
                }
            });
        assert!(
            !check_all_constraints(&slot_air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }
    #[test]
    fn rejects_duplicate_nullifiers_and_invalid_membership() {
        let mut w = m::sample_witness(100);
        w.slot.inputs[1] = w.slot.inputs[0].clone();
        let total = 2 * w.slot.inputs[0].value;
        w.slot.outputs[0].value = total - w.slot.fee - w.slot.outputs[1].value;
        assert!(failures(&w) > 0);
        let mut w = m::sample_witness(101);
        w.slot.inputs[0].path[2].0[0] += F::ONE;
        assert!(failures(&w) > 0);
        let mut w = m::sample_witness(102);
        w.anchor_path[2].1 ^= true;
        assert!(failures(&w) > 0);
    }
    #[test]
    fn positive_token_amounts_are_atomic_units_and_sip_keeps_minimum() {
        let mut w = m::sample_token_witness(103);
        let token_total = w.slot.inputs[0].value;
        w.slot.outputs[0].value = 1;
        w.slot.outputs[1].value = token_total - 1;
        assert_eq!(failures(&w), 0);
        let mut w = m::sample_witness(104);
        w.slot.outputs[1].value += w.slot.outputs[0].value - 1;
        w.slot.outputs[0].value = 1;
        assert!(failures(&w) > 0);
        assert_eq!(SIP_ASSET_ID, AssetId([0; 32]));
    }
    #[test]
    fn negative_carry_boundary_is_accepted_and_top_overflow_is_rejected() {
        let mut w = m::sample_witness(105);
        let word = 65536u64;
        w.slot.inputs[0].value = 4 * word;
        w.slot.inputs[1].value = word;
        w.slot.fee = 65535;
        w.base_fee = 65535;
        w.slot.outputs[0].value = 65535;
        w.slot.outputs[1].value = 65535;
        w.slot.outputs[2].value = 2 * word + 3;
        w.slot = m::with_unlock_heights(w.slot, [100, 120]);
        assert_eq!(failures(&w), 0);
        let mut over = w.clone();
        over.slot.outputs[2].value = over.slot.outputs[2].value.wrapping_add(1u64 << 48);
        assert!(failures(&over) > 0);
    }
    #[test]
    fn rejects_zero_real_fee_nonzero_empty_fee_and_unfunded_sip_fee() {
        let mut real = m::sample_token_witness(107);
        real.slot.outputs[2].value += real.slot.fee;
        real.slot.fee = 0;
        assert!(failures(&real) > 0);
        let mut empty = m::sample_empty_witness(108);
        empty.slot.fee = empty.base_fee;
        assert!(failures(&empty) > 0);
        let mut wrong_tier = m::sample_witness(109);
        wrong_tier.slot.fee_is_priority = true;
        assert!(failures(&wrong_tier) > 0);
    }

    #[test]
    fn native_d8_proof_roundtrip_and_public_field_rejection() {
        let prover = TransactionProver::new(FriParams::fast());
        let w = m::sample_token_witness(106);
        let (proof, public) = prover.prove(&w);
        prover
            .verify(&proof, &public)
            .expect("native multi-asset proof");
        let fields = w.slot.public_inputs(&Hasher::new());
        prover
            .verify_fields(
                &proof,
                &fields.nf,
                &fields.cm_out,
                &w.d_ct,
                &fields.fee_commit,
                &w.anchors_root(&Hasher::new()),
                w.anchor_height,
            )
            .unwrap();
        for field in 0..NUM_TRANSACTION_PUBLIC {
            let mut changed = public.clone();
            changed[field] += F::ONE;
            assert!(prover.verify(&proof, &changed).is_err());
        }
    }
}
