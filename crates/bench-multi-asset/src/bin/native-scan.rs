//! Actual isolated native multi-asset proof and instance-security diagnostics.
#[cfg(not(feature = "security-report"))]
fn main() {
    eprintln!("native-scan requires --features security-report");
    std::process::exit(2);
}

#[cfg(feature = "security-report")]
mod scan {
    use p3_field::PrimeCharacteristicRing;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use siworld_multi_asset_experiment::{
        FriParams,
        codec::{PUBLIC_TRANSACTION_BYTES, ProofContext, PublicTransaction},
        confidential_fees::{FeeOpening, SettlementSlot},
        encryption::{
            EncryptionContext, RecipientViewKey, SenderChangeSecret, decrypt_change_at,
            encrypt_change_at, encrypt_payment,
        },
        multi_asset::{F, Hasher, SI_ASSET_ID, sample_token_witness},
        multi_asset_transaction::TransactionProver,
        security::{params_json, settlement_report, transaction_report},
        settlement::{FixedSettlementWitness, SettlementProver},
    };
    use std::{path::Path, time::Instant};

    fn digest(seed: u32) -> [F; 12] {
        core::array::from_fn(|i| F::from_u32(seed + i as u32))
    }
    pub fn params(b: u32, q: u32, g: u32) -> FriParams {
        FriParams {
            log_blowup: b,
            num_queries: q,
            query_pow_bits: g,
            commit_pow_bits: 0,
            batch_pow_bits: g,
            max_log_arity: 1,
        }
    }
    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn source_hash() -> String {
        let mut all = Vec::new();
        for source in [
            include_bytes!("../multi_asset.rs").as_slice(),
            include_bytes!("../multi_asset_air.rs"),
            include_bytes!("../multi_asset_trace.rs"),
            include_bytes!("../multi_asset_transaction.rs"),
            include_bytes!("../codec.rs"),
            include_bytes!("../encryption.rs"),
            include_bytes!("../settlement.rs"),
            include_bytes!("../issuance.rs"),
            include_bytes!("../issuance_air.rs"),
            include_bytes!("../security.rs"),
        ] {
            all.extend_from_slice(&(source.len() as u64).to_le_bytes());
            all.extend_from_slice(source);
        }
        hash(&all)
    }
    fn screen(kind: &str, p: FriParams) -> Result<Value, String> {
        match kind {
            "transaction" => transaction_report(p),
            "settlement" => settlement_report(p),
            "issuance" => {
                let air = siworld_multi_asset_experiment::issuance_air::IssuanceAir::new(3)
                    .with_min_height(p.hiding_min_height());
                siworld_multi_asset_experiment::security::instance_report(&air, air.height, p)
            }
            _ => Err("unknown proof kind".into()),
        }
    }
    fn transaction(p: FriParams) -> Result<Value, String> {
        let start = Instant::now();
        let prover = TransactionProver::new(p);
        let setup_ns = start.elapsed().as_nanos();
        let mut witness = sample_token_witness(61);
        let h = Hasher::new();
        let fields = witness.slot.public_inputs(&h);
        let notes =
            core::array::from_fn::<_, 3, _>(|i| witness.slot.output_note(&h, &fields.nf, i));
        let recipient =
            RecipientViewKey::generate(notes[0].owner).map_err(|e| format!("view-key: {e:?}"))?;
        let secret = SenderChangeSecret::generate().map_err(|e| format!("change-key: {e:?}"))?;
        let ec = EncryptionContext::new([9; 32]);
        let public = PublicTransaction {
            nf: fields.nf,
            cm: fields.cm_out,
            payment: encrypt_payment(&recipient.address(), &notes[0], &ec)
                .map_err(|e| format!("payment: {e:?}"))?,
            change: [
                encrypt_change_at(&secret, &notes[1], &ec, 1)
                    .map_err(|e| format!("change: {e:?}"))?,
                encrypt_change_at(&secret, &notes[2], &ec, 2)
                    .map_err(|e| format!("change: {e:?}"))?,
            ],
        };
        let decoded = recipient
            .decrypt_payment(&public.cm[0], &public.payment, &ec)
            .map_err(|e| format!("payment-self-check: {e:?}"))?;
        if h.note_cm(&decoded) != public.cm[0] {
            return Err("payment commitment self-check".into());
        }
        for i in 0..2 {
            let decoded = decrypt_change_at(
                &secret,
                notes[i + 1].owner,
                &public.cm[i + 1],
                &public.change[i],
                &ec,
                (i + 1) as u8,
            )
            .map_err(|e| format!("change-self-check: {e:?}"))?;
            if h.note_cm(&decoded) != public.cm[i + 1] {
                return Err("change commitment self-check".into());
            }
        }
        let context = ProofContext::for_snapshot([9; 32], 1000, [10; 32]);
        let public =
            PublicTransaction::decode(&public.encode()).map_err(|e| format!("codec: {e:?}"))?;
        witness = public
            .bind_witness(&witness, &context)
            .map_err(|e| format!("witness: {e:?}"))?;
        let start = Instant::now();
        let (proof, statement) = prover.prove(&witness);
        let generation_ns = start.elapsed().as_nanos();
        let body = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let start = Instant::now();
        public.verify(
            &prover,
            &proof,
            &context,
            &fields.fee_commit,
            &witness.anchors_root(&h),
        )?;
        let verification_ns = start.elapsed().as_nanos();
        if public.statement(&context, &fields.fee_commit, &witness.anchors_root(&h)) != statement {
            return Err("canonical statement mismatch".into());
        }
        Ok(
            json!({"setup_ns":setup_ns,"generation_ns":generation_ns,"verification_ns":verification_ns,"proof_bytes":body.len(),"public_transaction_bytes":PUBLIC_TRANSACTION_BYTES,"permanent_position_bytes":PUBLIC_TRANSACTION_BYTES+48+40,"actual_encryption_self_check":true,"proof_within_524288_bytes":body.len()<=524288}),
        )
    }
    fn settlement(p: FriParams) -> Result<Value, String> {
        let start = Instant::now();
        let prover = SettlementProver::new(576, p);
        let setup_ns = start.elapsed().as_nanos();
        let h = Hasher::new();
        let slots = (0..576)
            .map(|i| {
                let opening = FeeOpening {
                    fee: 1000,
                    dummy: false,
                    priority: false,
                    blind: core::array::from_fn(|j| F::from_usize(1 + i * 8 + j)),
                };
                SettlementSlot {
                    commitment: h.fee_commit(opening.fee, &opening.blind),
                    opening,
                }
            })
            .collect();
        let witness = FixedSettlementWitness {
            issuance_reward: 10000,
            miner_amount: 586000,
            miner_asset_id: SI_ASSET_ID,
            block_height: 1000,
            network: [9; 32],
            transaction_list_digest: [11; 32],
            miner_owner: digest(8),
            miner_rseed: digest(9),
            slots,
        };
        let start = Instant::now();
        let (proof, public) = prover.prove(&witness);
        let generation_ns = start.elapsed().as_nanos();
        let body = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let start = Instant::now();
        prover.verify(&proof, &public)?;
        let verification_ns = start.elapsed().as_nanos();
        Ok(
            json!({"setup_ns":setup_ns,"generation_ns":generation_ns,"verification_ns":verification_ns,"proof_bytes":body.len(),"capacity":576,"reward_asset_constrained_si":true}),
        )
    }
    fn issuance(p: FriParams) -> Result<Value, String> {
        use siworld_multi_asset_experiment::{
            issuance::sample_issuance, issuance_air::IssuanceProver,
        };
        let (signed, witness, policy) = sample_issuance(3);
        let start = Instant::now();
        let prover = IssuanceProver::new(3, p);
        let setup_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let (proof, _) = prover
            .prove(&witness)
            .map_err(|e| format!("issuance: {e:?}"))?;
        let generation_ns = start.elapsed().as_nanos();
        let body = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let start = Instant::now();
        prover
            .verify_signed(
                &signed,
                &proof,
                &signed.declaration.network,
                1,
                policy,
                &witness.ciphertexts,
                |binding, fee| {
                    *binding == signed.declaration.binding() && fee == policy.required_fee_atoms
                },
            )
            .map_err(|e| format!("issuance verify: {e:?}"))?;
        let verification_ns = start.elapsed().as_nanos();
        Ok(
            json!({"setup_ns":setup_ns,"generation_ns":generation_ns,"verification_ns":verification_ns,"proof_bytes":body.len(),"initial_notes":3,"signed_record_bytes":signed.declaration.canonical_bytes().len()+siworld_multi_asset_experiment::issuance::ISSUER_SIGNATURE_BYTES,"ciphertext_bytes":witness.ciphertexts.iter().map(Vec::len).sum::<usize>(),"actual_ml_dsa65_verification":true,"actual_ml_kem_encryption_self_check":true,"si_fee_payment_fixture_only":true}),
        )
    }
    fn save(path: &Path, value: &Value) -> Result<(), String> {
        use std::io::Write;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        out.write_all(serde_json::to_string_pretty(value).unwrap().as_bytes())
            .and_then(|_| out.write_all(b"\n"))
            .map_err(|e| e.to_string())
    }
    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("screen") {
            let mut entries = Vec::new();
            for kind in ["transaction", "settlement", "issuance"] {
                for b in 4..=9 {
                    for g in [16, 20, 24] {
                        let mut found = None;
                        for q in 16..=128 {
                            let p = params(b, q, g);
                            let value = screen(kind, p)?;
                            if value["screen"]["passes_selected_model"] == true {
                                found = Some(value);
                                break;
                            }
                        }
                        entries.push(json!({"kind":kind,"log_blowup":b,"grinding":g,"minimum_passing_report":found}));
                    }
                }
            }
            let value = json!({"schema":1,"suite":"KoalaBear-D8-Poseidon2-W24-digest12","air_source_sha256":source_hash(),"dependencies_sha256":hash(include_bytes!("../../Cargo.lock")),"requested_log_blowup_grid":[4,5,6,7,8],"cap_fallback_log_blowup":9,"reports":entries,"cryptographic_approval":false,"network_activation":false});
            if let Some(path) = args.get(1) {
                save(Path::new(path), &value)?;
            } else {
                println!("{}", value);
            }
            return Ok(());
        }
        if args.len() != 6 {
            return Err("usage: native-scan <transaction|settlement|issuance> <blowup> <queries> <grinding> <workers> <new-output.json> | screen [new-output.json]".into());
        }
        let n = |i: usize| {
            args[i]
                .parse::<u32>()
                .map_err(|_| "invalid integer".to_string())
        };
        let p = params(n(1)?, n(2)?, n(3)?);
        let workers = n(4)? as usize;
        if !matches!(workers, 1 | 4)
            || std::env::var("RAYON_NUM_THREADS").ok() != Some(workers.to_string())
        {
            return Err("explicit 1 or 4 RAYON_NUM_THREADS required".into());
        }
        #[cfg(feature = "parallel")]
        let actual = p3_maybe_rayon::prelude::current_num_threads();
        #[cfg(not(feature = "parallel"))]
        let actual = 1;
        if actual != workers {
            return Err("actual worker count differs".into());
        }
        let report = screen(&args[0], p)?;
        if report["screen"]["passes_selected_model"] != true {
            return Err("parameters fail the actual AIR security screen".into());
        }
        let measurement = match args[0].as_str() {
            "transaction" => transaction(p)?,
            "settlement" => settlement(p)?,
            "issuance" => issuance(p)?,
            _ => return Err("unknown measurement kind".into()),
        };
        let binary = std::fs::read(std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        save(
            Path::new(&args[5]),
            &json!({"schema":1,"kind":args[0],"parameters":params_json(p),"workers":actual,"hiding_workers":std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").ok(),"suite":"KoalaBear-D8-Poseidon2-W24-digest12","air_source_sha256":source_hash(),"binary_sha256":hash(&binary),"dependencies_sha256":hash(include_bytes!("../../Cargo.lock")),"security":report,"measurement":measurement,"verified":true,"synthetic_fixture":true,"cryptographic_approval":false,"network_activation":false}),
        )
    }
}
#[cfg(feature = "security-report")]
fn main() {
    if let Err(error) = scan::run() {
        eprintln!("native diagnostic failed: {error}");
        std::process::exit(1);
    }
}
