//! Reproduce public preprocessing and security data for a native transaction profile.
#[cfg(not(feature = "security-report"))]
fn main() {
    eprintln!("profile-artifacts requires --features security-report");
    std::process::exit(2);
}

#[cfg(feature = "security-report")]
mod artifact {
    use p3_air::BaseAir;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use siworld_multi_asset_experiment::{
        FriParams,
        multi_asset_transaction::TransactionProver,
        security::{params_json, transaction_report},
    };
    use std::{fs::OpenOptions, io::Write, path::Path};

    fn parameters(b: u32, q: u32, g: u32) -> Result<FriParams, String> {
        if !(5..=8).contains(&b) || !(1..=128).contains(&q) || ![20, 24].contains(&g) {
            return Err("unsupported transaction parameter coordinate".into());
        }
        Ok(FriParams {
            log_blowup: b,
            num_queries: q,
            query_pow_bits: g,
            commit_pow_bits: 0,
            batch_pow_bits: g,
            max_log_arity: 1,
        })
    }

    fn encode_key(
        p: FriParams,
        width: usize,
        degree_bits: usize,
        commitment: &[u8],
    ) -> Result<Vec<u8>, String> {
        if commitment.is_empty() || commitment.len() > 4096 {
            return Err("invalid public preprocessing commitment length".into());
        }
        let mut bytes = Vec::with_capacity(43 + commitment.len());
        bytes.extend_from_slice(b"SWMV");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(1);
        // This version fixes log_final_poly_len=0. All variable FRI parameters
        // are authenticated in the header, including batch grinding.
        for value in [
            p.log_blowup,
            p.num_queries,
            p.query_pow_bits,
            p.commit_pow_bits,
            p.batch_pow_bits,
            p.max_log_arity,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [width, degree_bits, commitment.len()] {
            bytes.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| "public key dimension overflow")?
                    .to_le_bytes(),
            );
        }
        bytes.extend_from_slice(commitment);
        Ok(bytes)
    }

    fn bundle(p: FriParams) -> Result<Value, String> {
        let security = transaction_report(p)?;
        if security["screen"]["passes_selected_model"] != true {
            return Err("transaction profile does not pass the selected security ledger".into());
        }
        let prover = TransactionProver::new(p);
        if *prover.cfg.descriptor() != p.descriptor()
            || prover.vk.width != prover.air.preprocessed_width()
            || prover.vk.degree_bits != prover.air.degree_bits() + 1
        {
            return Err("preprocessing key differs from the native AIR profile".into());
        }
        let commitment = postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?;
        let bytes = encode_key(p, prover.vk.width, prover.vk.degree_bits, &commitment)?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(
            json!({"schema":1,"suite":"KoalaBear-D8-Poseidon2-W24-digest12",
            "kind":"transaction","parameters":params_json(p),"security":security,
            "public_verifier_key":{"encoding":"SWMV-v1","hex":hex,
                "sha256":format!("{:x}",Sha256::digest(&bytes)),
                "width":prover.vk.width,"degree_bits":prover.vk.degree_bits},
            "cryptographic_approval":false,"network_activation":false}),
        )
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        let (mode, b, q, g, output) = match args.as_slice() {
            [b, q, g, output] => ("--output", b, q, g, output),
            [mode, b, q, g, output] if mode == "--check" => (mode.as_str(), b, q, g, output),
            _ => {
                return Err(
                    "usage: profile-artifacts [--check] BLOWUP QUERIES GRINDING PATH".into(),
                );
            }
        };
        let parse = |v: &String| {
            v.parse::<u32>()
                .map_err(|_| "invalid unsigned parameter".to_string())
        };
        let value = bundle(parameters(parse(b)?, parse(q)?, parse(g)?)?)?;
        let path = Path::new(output);
        if mode == "--check" {
            let stored: Value =
                serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if stored != value {
                return Err("public verifier key, parameters or security report changed".into());
            }
            println!("Native transaction public verifier key and security report reproduced.");
        } else {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            let mut bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
            bytes.push(b'\n');
            file.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn unsafe_and_unscanned_coordinates_are_rejected_before_setup() {
            for (b, q, g) in [
                (4, 57, 20),
                (9, 31, 24),
                (6, 0, 20),
                (6, 129, 20),
                (6, 47, 16),
            ] {
                assert!(parameters(b, q, g).is_err());
            }
            let low = parameters(6, 1, 20).unwrap();
            assert!(bundle(low).is_err());
        }
        #[test]
        fn public_key_header_binds_all_fri_parameters_and_dimensions() {
            let p = parameters(6, 47, 20).unwrap();
            let bytes = encode_key(p, 243, 9, &[1, 2, 3]).unwrap();
            assert_eq!(bytes.len(), 46);
            assert_eq!(&bytes[..7], b"SWMV\x01\x00\x01");
            let words: Vec<_> = bytes[7..43]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|w| u32::from_le_bytes(*w))
                .collect();
            assert_eq!(words, [6, 47, 20, 0, 20, 1, 243, 9, 3]);
            let mut changed = p;
            changed.batch_pow_bits = 24;
            assert_ne!(bytes, encode_key(changed, 243, 9, &[1, 2, 3]).unwrap());
            assert!(encode_key(p, 243, 9, &[]).is_err());
            assert!(encode_key(p, 243, 9, &[0; 4097]).is_err());
        }
    }
}

#[cfg(feature = "security-report")]
fn main() {
    if let Err(error) = artifact::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
