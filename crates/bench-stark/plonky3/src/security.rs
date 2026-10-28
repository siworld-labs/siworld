//! Offline D4 control analysis. Conservative envelopes are not an acceptance theorem.

use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_log_num_quotient_chunks, get_max_constraint_degree, get_symbolic_constraints,
};
use p3_circuit_prover::CircuitVerifier;
use p3_commit::Pcs;
use p3_lookup::LogUpGadget;
use p3_security::{
    GrindingSites, InstanceShape, RegimeReport, StarkAirParams,
    fri::FriRegime,
    logup::{LogUpAir, security_term},
    stark::{conjectured_security_report, proven_security_report},
};
use p3_uni_stark::{OpeningShape, StarkGenericConfig};
use serde_json::{Value, json};
use siworld_bench_common::F;

use crate::{Cfg, FriParams, SlotProver};

type EF = <Cfg as StarkGenericConfig>::Challenge;

// Floor log2(p^4) and the ideal classical collision exponent. Rounding down
// is conservative; neither integer is the field's binary encoding length.
const FIELD_BITS: usize = 123;
const COLLISION_BITS: usize = 123;

fn number(bits: f64) -> Value {
    if bits.is_finite() {
        json!(bits)
    } else if bits == f64::INFINITY {
        json!("positive_infinity")
    } else {
        panic!("invalid security estimate")
    }
}

fn breakdown(report: &RegimeReport) -> Value {
    json!({
        "regime": format!("{:?}", report.regime),
        "minimum_term_bits": number(report.security_bits()),
        "weakest_term": report.binding().label,
        "terms": report.terms().iter().map(|t| json!({
            "label": t.label, "bits": number(t.bits.bits()),
        })).collect::<Vec<_>>(),
    })
}

fn reports(
    params: FriParams,
    cfg: &Cfg,
    air: StarkAirParams,
    shape: InstanceShape,
    lookup: LogUpAir,
) -> Value {
    let fri = FriRegime {
        log_blowup: params.log_blowup as usize,
        num_queries: params.num_queries as usize,
        log_final_poly_len: 0,
        max_log_arity: 2,
        commit_pow_bits: 0,
        query_pow_bits: params.query_pow_bits as usize,
    };
    let grinding = GrindingSites {
        out_of_domain: cfg.ood_proof_of_work_bits(),
        lookup_challenge: cfg.lookup_proof_of_work_bits(),
        batch_combination: 0,
    };
    let extras: Vec<_> = security_term(&lookup, &shape, &grinding)
        .into_iter()
        .collect();
    let conjectured = conjectured_security_report(&fri, &air, &shape, &extras, &grinding);
    let proven = proven_security_report(&fri, &air, &shape, &extras, &grinding);
    json!({
        "fri": {"log_blowup": fri.log_blowup, "num_queries": fri.num_queries,
            "log_final_poly_len": 0, "max_log_arity": 2,
            "commit_pow_bits": 0, "query_pow_bits": fri.query_pow_bits},
        "grinding_sites": grinding,
        "shape": {"log_committed_trace_length": shape.log_trace_length,
            "challenge_field_bits_floor": shape.modulus_bits,
            "classical_collision_bits_floor": shape.collision_resistance,
            "num_batched_functions": shape.num_batched_functions,
            "num_constraints": air.num_constraints,
            "max_constraint_degree": air.max_constraint_degree,
            "num_quotient_chunks": air.num_quotient_chunks,
            "max_combo": air.max_combo,
            "lookup_denominators_per_row": lookup.num_interactions,
            "max_lookup_message_width": lookup.max_message_width},
        "conjectured": breakdown(&conjectured),
        "proven_johnson": proven.ldr.as_ref().map(breakdown),
        "proven_unique_decoding": breakdown(&proven.udr),
        "acceptance": false,
    })
}

/// Derive leaf dimensions from its actual AIR and committed preprocessing key.
pub fn leaf(prover: &SlotProver, params: FriParams) -> Value {
    let air = &prover.air;
    let mut layout = AirLayout::from_air(air);
    layout.preprocessed_width = prover.vk.width;
    let domain = <<Cfg as StarkGenericConfig>::Pcs as Pcs<
        EF,
        <Cfg as StarkGenericConfig>::Challenger,
    >>::natural_domain_for_degree(prover.cfg.pcs(), air.height);
    let air_shape = StarkAirParams::from_air::<F, EF, _>(air, layout, domain, 2, true);
    let functions = p3_uni_stark::num_batched_openings(
        layout.main_width,
        !air.main_next_row_columns().is_empty(),
        layout.preprocessed_width,
        !air.preprocessed_next_row_columns().is_empty(),
        air_shape.num_quotient_chunks,
        4,
        OpeningShape::hiding(4),
    );
    let shape = InstanceShape {
        log_trace_length: air.degree_bits() + prover.cfg.is_zk(),
        modulus_bits: FIELD_BITS,
        collision_resistance: COLLISION_BITS,
        num_batched_functions: functions,
    };
    json!({"base_trace_rows": air.height,
        "preprocessed_degree_bits": prover.vk.degree_bits,
        "main_width": layout.main_width, "preprocessed_width": layout.preprocessed_width,
        "public_values": layout.num_public_values,
        "report": reports(params, &prover.cfg, air_shape, shape,
            LogUpAir { num_interactions: 0, max_message_width: 0 })})
}

/// Extract every actual batch table, then overestimate a single common-domain
/// envelope. This intentionally charges all constraints, quotient chunks and
/// lookup factors at the largest trace height, with the global opening count.
/// Applicability of a multi-instance/recursive theorem remains a review item.
pub fn recursive(verifier: &CircuitVerifier<Cfg>, params: FriParams) -> Result<Value, String> {
    let airs = verifier.table_airs::<4>().map_err(|e| format!("{e:?}"))?;
    let common = verifier.common_data();
    let degrees = verifier.relation().trace_degree_bits();
    let zk = verifier.config().is_zk();
    if airs.len() != degrees.len() || airs.len() != common.lookups.len() {
        return Err("batch table metadata length mismatch".into());
    }
    let mut tables = Vec::new();
    let (mut constraints, mut degree, mut chunks, mut functions, mut denoms, mut width) =
        (0, 0, 0, 0, 0, 0);
    for (i, air) in airs.iter().enumerate() {
        let committed_log = degrees[i];
        let base_log = committed_log.checked_sub(zk).ok_or("invalid ZK degree")?;
        let prep = common
            .preprocessed
            .as_ref()
            .and_then(|p| p.instances[i].as_ref());
        let prep_width = prep.map_or(0, |p| p.width);
        let mut layout = AirLayout::from_air(air);
        layout.preprocessed_width = prep_width;
        let lookups = &common.lookups[i];
        let (base, extension) =
            get_symbolic_constraints::<F, EF, _, _>(air, layout, lookups, &LogUpGadget);
        let nconstraints = base.len() + extension.len();
        let max_degree = get_max_constraint_degree::<F, EF, _, _>(
            air,
            layout,
            1 << base_log,
            lookups,
            &LogUpGadget,
        )
        .max(air.max_constraint_degree().unwrap_or(0));
        let quotient_chunks = 1
            << (get_log_num_quotient_chunks::<F, EF, _, _>(
                air,
                layout,
                1 << base_log,
                lookups,
                zk,
                &LogUpGadget,
            ) + zk);
        let openings = p3_batch_stark::num_batched_openings(
            layout.main_width,
            !air.main_next_row_columns().is_empty(),
            prep_width,
            !air.preprocessed_next_row_columns().is_empty(),
            quotient_chunks,
            lookups.len(),
            4,
            OpeningShape::hiding(4),
        );
        // Count every tuple even for exclusive flags: conservative if the AIR
        // really enforces exclusivity, and never an underestimate if it does not.
        let table_denoms: usize = lookups.iter().map(|l| l.elements.len()).sum();
        let message_width = lookups
            .iter()
            .flat_map(|l| &l.elements)
            .map(Vec::len)
            .max()
            .unwrap_or(0);
        constraints += nconstraints;
        degree = degree.max(max_degree);
        chunks += quotient_chunks;
        functions += openings;
        denoms += table_denoms;
        width = width.max(message_width);
        tables.push(json!({"index": i, "base_trace_rows": 1usize << base_log,
            "log_committed_trace_length": committed_log,
            "main_width": layout.main_width, "preprocessed_width": prep_width,
            "preprocessed_degree_bits": prep.map(|p| p.degree_bits),
            "public_values": layout.num_public_values,
            "base_constraints": base.len(), "extension_constraints": extension.len(),
            "max_constraint_degree": max_degree,
            "num_quotient_chunks": quotient_chunks, "num_lookups": lookups.len(),
            "lookup_denominator_upper_bound": table_denoms,
            "max_lookup_message_width": message_width,
            "batched_opening_contribution": openings}));
    }
    let shape = InstanceShape {
        log_trace_length: *degrees.iter().max().ok_or("empty batch")?,
        modulus_bits: FIELD_BITS,
        collision_resistance: COLLISION_BITS,
        num_batched_functions: functions,
    };
    Ok(
        json!({"tables": tables, "exact_sum_quotient_chunks": chunks,
        "envelope_method": "all constraints/chunks/lookups at maximum committed height; exact summed opening powers; conservative screening only",
        "report": reports(params, verifier.config(), StarkAirParams {
            num_constraints: constraints, max_constraint_degree: degree,
            // The estimator requires a power-of-two quotient split. Round the
            // envelope up, preserving exact per-table counts in the ledger.
            num_quotient_chunks: chunks.next_power_of_two(), max_combo: 2,
        }, shape, LogUpAir { num_interactions: denoms, max_message_width: width })}),
    )
}

/// Sum repeated error bounds without an independence assumption.
pub fn union_bits(terms: &[(f64, usize)]) -> f64 {
    let minimum = terms
        .iter()
        .map(|(bits, _)| *bits)
        .fold(f64::INFINITY, f64::min);
    if minimum == f64::INFINITY {
        return minimum;
    }
    minimum
        - terms
            .iter()
            .map(|(bits, count)| *count as f64 * (minimum - bits).exp2())
            .sum::<f64>()
            .log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_charges_every_proof_and_error_term() {
        assert!(
            (union_bits(&[(100.0, 16), (100.0, 2), (100.0, 1)]) - (100.0 - 19f64.log2())).abs()
                < 1e-10
        );
        assert!(union_bits(&[(0.0, 1), (128.0, 19)]) <= 0.0);
    }

    #[test]
    fn d4_hash_cap_fails_even_with_many_queries() {
        let params = FriParams {
            num_queries: 92,
            ..FriParams::secure()
        };
        let cfg = params.config();
        let r = reports(
            params,
            &cfg,
            StarkAirParams {
                num_constraints: 100,
                max_constraint_degree: 3,
                num_quotient_chunks: 8,
                max_combo: 2,
            },
            InstanceShape {
                log_trace_length: 8,
                modulus_bits: FIELD_BITS,
                collision_resistance: COLLISION_BITS,
                num_batched_functions: 1000,
            },
            LogUpAir {
                num_interactions: 0,
                max_message_width: 0,
            },
        );
        assert!(r["conjectured"]["minimum_term_bits"].as_f64().unwrap() < 128.0);
        assert!(r["proven_johnson"].is_object());
        assert_eq!(r["acceptance"], false);
        assert_eq!(number(f64::INFINITY), "positive_infinity");
    }
}
