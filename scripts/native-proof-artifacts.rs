//! Reproduce public native relation keys without generating transaction proofs.
use p3_air::BaseAir;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_multi_asset_experiment::{
    FriParams,
    issuance_air::{IssuanceAir, IssuanceProver},
    multi_asset_transaction::TransactionProver,
    security::{instance_report, params_json, settlement_report, transaction_report},
    settlement::SettlementProver,
};

fn params(kind: &str) -> Result<FriParams, String> {
    let (log_blowup, num_queries) = match kind {
        "transaction" => (7, 41),
        "settlement" | "issuance" => (8, 36),
        _ => return Err("unknown native relation".into()),
    };
    Ok(FriParams {
        log_blowup,
        num_queries,
        query_pow_bits: 20,
        commit_pow_bits: 0,
        batch_pow_bits: 20,
        max_log_arity: 1,
    })
}

// These offline artifact bytes identify a fixed native relation. They are not
// an activated block/transaction wire format or a peer-supplied verifier key.
fn encode_key(
    kind: u8,
    capacity: u32,
    p: FriParams,
    width: usize,
    degree: usize,
    commitment: &[u8],
) -> Result<Vec<u8>, String> {
    if !(1..=3).contains(&kind) || commitment.is_empty() || commitment.len() > 4096 {
        return Err("invalid native public-key shape".into());
    }
    let mut out = b"SWMP\x01\x00".to_vec();
    out.push(kind);
    out.extend_from_slice(&capacity.to_le_bytes());
    for word in [
        p.log_blowup,
        p.num_queries,
        p.query_pow_bits,
        p.commit_pow_bits,
        p.batch_pow_bits,
        p.max_log_arity,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for word in [width, degree, commitment.len()] {
        out.extend_from_slice(
            &u32::try_from(word)
                .map_err(|_| "key dimension overflow")?
                .to_le_bytes(),
        );
    }
    out.extend_from_slice(commitment);
    Ok(out)
}

fn bundle(kind: &str, p: FriParams) -> Result<Value, String> {
    let security = match kind {
        "transaction" => transaction_report(p)?,
        "settlement" => settlement_report(p)?,
        "issuance" => {
            let air = IssuanceAir::new(3).with_min_height(p.hiding_min_height());
            instance_report(&air, air.height, p)?
        }
        _ => return Err("unknown native relation".into()),
    };
    if security["screen"]["passes_selected_model"] != true {
        return Err("native relation fails the selected security screen".into());
    }
    let (id, capacity, width, degree, commitment) = match kind {
        "transaction" => {
            let prover = TransactionProver::new(p);
            if prover.vk.width != prover.air.preprocessed_width() {
                return Err("transaction preprocessing width mismatch".into());
            }
            (
                1,
                0,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        "settlement" => {
            let prover = SettlementProver::new(576, p);
            (
                2,
                576,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        "issuance" => {
            let prover = IssuanceProver::new(3, p);
            (
                3,
                3,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        _ => return Err("unknown native relation".into()),
    };
    let bytes = encode_key(id, capacity, p, width, degree, &commitment)?;
    Ok(
        json!({"kind":kind,"capacity":capacity,"parameters":params_json(p),
        "security":security,"public_verifier_key":{"encoding":"SWMP-v1",
        "hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "sha256":format!("{:x}",Sha256::digest(&bytes)),"width":width,"degree_bits":degree},
        "cryptographic_approval":false,"network_activation":false}),
    )
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (kind, output, parameters, candidate) = match args.as_slice() {
        [kind, output] => (kind, output, params(kind)?, false),
        [mode, kind, b, q, g, output] if mode == "--candidate" => {
            let parse = |value: &String| value.parse::<u32>().map_err(|_| "invalid candidate integer".to_owned());
            let (b, q, g) = (parse(b)?, parse(q)?, parse(g)?);
            if !(5..=8).contains(&b) || !(1..=128).contains(&q) || ![20, 24].contains(&g) {
                return Err("unsupported candidate coordinate".into());
            }
            (kind, output, FriParams { log_blowup: b, num_queries: q,
                query_pow_bits: g, commit_pow_bits: 0, batch_pow_bits: g, max_log_arity: 1 }, true)
        }
        _ => return Err("usage: native-proof-artifacts KIND OUTPUT | --candidate KIND BLOWUP QUERIES GRINDING OUTPUT".into()),
    };
    let mut result = bundle(kind, parameters)?;
    if candidate {
        result["status"] = json!("candidate-pending-review");
        result["acceptance"] = json!(false);
    }
    let mut bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?
        .write_all(&bytes)
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_candidate_relation_is_rejected_before_setup() {
        assert_eq!(
            bundle("peer-defined", params("transaction").unwrap()).unwrap_err(),
            "unknown native relation"
        );
    }

    #[test]
    fn relation_kind_capacity_and_all_fri_fields_are_bound() {
        let p = params("settlement").unwrap();
        let original = encode_key(2, 576, p, 587, 11, &[1, 2]).unwrap();
        assert_ne!(original, encode_key(3, 576, p, 587, 11, &[1, 2]).unwrap());
        assert_ne!(original, encode_key(2, 575, p, 587, 11, &[1, 2]).unwrap());
        let mut changed = p;
        changed.batch_pow_bits += 1;
        assert_ne!(
            original,
            encode_key(2, 576, changed, 587, 11, &[1, 2]).unwrap()
        );
        assert!(encode_key(0, 576, p, 587, 11, &[1, 2]).is_err());
        assert!(encode_key(2, 576, p, 587, 11, &[]).is_err());
        assert!(params("peer-defined").is_err());
    }
}
