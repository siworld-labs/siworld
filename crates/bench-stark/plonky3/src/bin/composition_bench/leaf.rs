//! Experimental leaf profiles. No production parameter or key is selected here.
use std::io::Write;

use p3_air::BaseAir;
use p3_uni_stark::StarkGenericConfig;
use serde_json::{Value, json};
use siworld_bench_common::F;
use siworld_bench_plonky3::{FriParams, SlotProver};

pub fn parameters(profile: &str, recursive: FriParams) -> Result<FriParams, String> {
    if profile == "uniform" {
        return Ok(recursive);
    }
    if (
        recursive.log_blowup,
        recursive.num_queries,
        recursive.query_pow_bits,
    ) != (2, 92, 16)
    {
        return Err("leaf candidates require unchanged q92 recursive parameters".into());
    }
    let (log_blowup, num_queries) = match profile {
        "b" => (4, 46),
        "a" => (3, 62),
        "c" => (5, 37),
        _ => return Err("leaf profile must be uniform, b, a or c".into()),
    };
    Ok(FriParams {
        log_blowup,
        num_queries,
        query_pow_bits: 16,
    })
}

pub fn pin(profile: &str, params: FriParams, prover: &SlotProver) -> Result<Value, String> {
    let degree = <_ as BaseAir<F>>::max_constraint_degree(&prover.air)
        .ok_or("leaf AIR must declare its maximum constraint degree")?;
    // A conservative sufficient quotient-domain condition for this cubic AIR.
    if (1usize << params.log_blowup) < degree {
        return Err("leaf blowup is insufficient for its declared constraint degree".into());
    }
    if prover.cfg.is_zk() != 1 {
        return Err("leaf experiment requires hiding proofs".into());
    }
    Ok(json!({
        "schema": 1, "profile": profile, "experimental_only": true,
        "parameters": {"suite": "D4-W16", "log_blowup": params.log_blowup,
                       "queries": params.num_queries, "grinding": params.query_pow_bits},
        "nominal_query_grinding_score": params.conjectured_bits(),
        "air_rows": prover.air.height, "maximum_constraint_degree": degree,
        "preprocessed_width": prover.vk.width,
        "preprocessed_degree_bits": prover.vk.degree_bits,
        "preprocessed_commitment": prover.vk.commitment,
        "hiding": true,
    }))
}

pub fn check_pin(expected: &Value, actual: &Value) -> Result<(), String> {
    if expected != actual {
        return Err("leaf configuration or preprocessed key differs from the fixed pin".into());
    }
    Ok(())
}

pub fn export_pin(path: &str, pin: &Value) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create leaf pin: {e}"))?;
    let data = serde_json::to_vec_pretty(pin).map_err(|e| e.to_string())?;
    file.write_all(&data)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| format!("write leaf pin: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_cannot_silently_change_recursive_parameters() {
        assert!(parameters("b", FriParams::secure()).is_err());
        let q92 = FriParams {
            num_queries: 92,
            ..FriParams::secure()
        };
        for (name, score, height) in [("b", 200, 128), ("a", 202, 256), ("c", 201, 128)] {
            let params = parameters(name, q92).unwrap();
            assert_eq!(params.conjectured_bits(), score);
            assert_eq!(params.hiding_min_height(), height);
        }
        assert!(parameters("unknown", q92).is_err());
    }

    #[test]
    fn fixed_pin_rejects_parameter_and_key_replacement() {
        let expected = json!({"parameters": {"queries": 46}, "preprocessed_commitment": [1, 2]});
        assert!(check_pin(&expected, &expected).is_ok());
        for actual in [
            json!({"parameters": {"queries": 92}, "preprocessed_commitment": [1, 2]}),
            json!({"parameters": {"queries": 46}, "preprocessed_commitment": [1, 3]}),
        ] {
            assert!(check_pin(&expected, &actual).is_err());
        }
    }
}
