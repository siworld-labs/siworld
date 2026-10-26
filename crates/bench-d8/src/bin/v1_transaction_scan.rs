//! Native transaction-AIR security screening and isolated proof diagnostics.
//!
//! The native relation is executable, but its production statement and fee
//! privacy policy are not frozen. Every output therefore remains ineligible
//! for production parameter selection. No node, chain, keys or sockets are used.

#[cfg(not(feature = "security-report"))]
fn main() {
    eprintln!("v1_transaction_scan requires the security-report feature");
    std::process::exit(2);
}

#[cfg(feature = "security-report")]
mod native {
    use p3_air::{BaseAir, symbolic::AirLayout};
    use p3_commit::Pcs;
    use p3_security::{
        GrindingSites, InstanceShape, RegimeReport, StarkAirParams,
        fri::{self, FriRegime},
        report::Regime,
        stark::{conjectured_security_report, proven_security_report},
    };
    use p3_uni_stark::{OpeningShape, StarkGenericConfig};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use siworld_d8_checkpoint_experiment::{
        Cfg, FriParams,
        codec::{ProofContext, PublicTransaction},
        common::{F, FEE_BASE, Hasher, acc_witnesses, sample_slot},
        encryption::{ChangeCiphertext, PaymentCiphertext},
        transaction::{TransactionAir, TransactionProver},
    };
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    type EF = <Cfg as StarkGenericConfig>::Challenge;
    const SUITE: &str = "KoalaBear-D8-Poseidon2-W24-digest12";
    const SCOPE: &str = "v1-native-transaction-diagnostic";
    const ACCOUNTING: &str = "single-proof-johnson-halving-bht-v1";

    /// The application hashes encoded ciphertext bytes outside the AIR. This
    /// annotation is separate from the raw p3-security PCS report and does not
    /// establish the security of the complete relation/PCS/hash composition.
    fn application_binding() -> Value {
        json!({"algorithm":"BLAKE3-256","digest_bytes":32,
            "nominal_classical_collision_bits":128,
            "nominal_bht_collision_bits":256. / 3.,
            "included_in_p3_security_report":false,
            "model_status":"nominal-collision-model-requires-review"})
    }

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn number(value: f64) -> Value {
        if value == f64::INFINITY {
            json!("positive_infinity")
        } else {
            assert!(value.is_finite());
            json!(value)
        }
    }
    fn union(values: impl Iterator<Item = f64>) -> f64 {
        let values: Vec<_> = values.filter(|v| v.is_finite()).collect();
        let m = values.iter().copied().fold(f64::INFINITY, f64::min);
        m - values.iter().map(|v| (m - v).exp2()).sum::<f64>().log2()
    }
    fn breakdown(report: &RegimeReport) -> Value {
        json!({"regime":format!("{:?}",report.regime),
            "minimum_term_bits":number(report.security_bits()),
            "weakest_term":report.binding().label,
            "terms":report.terms().iter().map(|t|json!({"label":t.label,
                "bits":number(t.bits.bits())})).collect::<Vec<_>>()})
    }
    fn params_json(p: FriParams) -> Value {
        json!({"log_blowup":p.log_blowup,"num_queries":p.num_queries,
            "query_pow_bits":p.query_pow_bits,"commit_pow_bits":p.commit_pow_bits,
            "batch_pow_bits":p.batch_pow_bits,"max_log_arity":p.max_log_arity,
            "log_final_poly_len":0})
    }
    fn source() -> Vec<u8> {
        let mut result = Vec::new();
        for (name, data) in [
            (
                "transaction.rs",
                include_bytes!("../transaction.rs").as_slice(),
            ),
            ("air.rs", include_bytes!("../air.rs").as_slice()),
            ("trace.rs", include_bytes!("../trace.rs").as_slice()),
            ("common.rs", include_bytes!("../common.rs").as_slice()),
            ("lib.rs", include_bytes!("../lib.rs").as_slice()),
        ] {
            result.extend_from_slice(name.as_bytes());
            result.push(0);
            result.extend_from_slice(&(data.len() as u64).to_le_bytes());
            result.extend_from_slice(data);
        }
        result
    }
    fn binding(p: FriParams, machine: &str) -> Result<Value, String> {
        let binary = std::fs::read(std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(json!({"schema":1,"scope":SCOPE,"suite":SUITE,
            "actual_production_air":false,"air_version":"native-transaction-v1-draft",
            "codec_version":"transaction-public-v1-draft","parameters":params_json(p),
            "air_source_sha256":sha(&source()),
            "codec_sha256":sha(include_bytes!("../codec.rs")),
            "dependencies_sha256":sha(include_bytes!("../../Cargo.lock")),
            "binary_sha256":sha(&binary),"machine_id":machine,
            "application_binding":application_binding(),
            "production_blockers":["settlement proof and witness-delivery policy are not frozen",
                "root freshness and output-encryption relation scope require review"],
            "cryptographic_approval":false,"network_activation":false}))
    }

    /// Extract symbolic dimensions directly from TransactionAir. No preprocessing
    /// commitment, key generation, proof or recursive circuit is built here.
    fn security(p: FriParams) -> Result<Value, String> {
        let air = TransactionAir::new().with_min_height(p.hiding_min_height());
        let cfg = p.config();
        let mut layout = AirLayout::from_air(&air);
        layout.preprocessed_width = air.preprocessed_width();
        let domain = <<Cfg as StarkGenericConfig>::Pcs as Pcs<
            EF,
            <Cfg as StarkGenericConfig>::Challenger,
        >>::natural_domain_for_degree(cfg.pcs(), air.slot.height);
        let a = StarkAirParams::from_air::<F, EF, _>(&air, layout, domain, 2, true);
        let functions = p3_uni_stark::num_batched_openings(
            layout.main_width,
            !air.main_next_row_columns().is_empty(),
            layout.preprocessed_width,
            !air.preprocessed_next_row_columns().is_empty(),
            a.num_quotient_chunks,
            8,
            OpeningShape::hiding(8),
        );
        let shape = InstanceShape {
            log_trace_length: air.degree_bits() + cfg.is_zk(),
            modulus_bits: 247,
            collision_resistance: 185,
            num_batched_functions: functions,
        };
        let fri = FriRegime {
            log_blowup: p.log_blowup as usize,
            num_queries: p.num_queries as usize,
            log_final_poly_len: 0,
            max_log_arity: p.max_log_arity as usize,
            commit_pow_bits: p.commit_pow_bits as usize,
            query_pow_bits: p.query_pow_bits as usize,
        };
        let grinding = GrindingSites {
            out_of_domain: cfg.ood_proof_of_work_bits(),
            lookup_challenge: cfg.lookup_proof_of_work_bits(),
            batch_combination: p.batch_pow_bits as usize,
        };
        let conjectured = conjectured_security_report(&fri, &a, &shape, &[], &grinding);
        let proven = proven_security_report(&fri, &a, &shape, &[], &grinding);
        let johnson = proven.ldr.as_ref().ok_or("no Johnson report")?;
        let m = match johnson.regime {
            Regime::ListDecoding { m } => m,
            _ => return Err("Johnson report has another regime".into()),
        };
        let folding = fri::commit_phase_error_ldr_m(&fri, &shape, m)
            .ok_or("no FRI folding bound")?
            .bits();
        let query = fri::query_phase_error(
            p3_security::proximity::alpha_ldr_m(fri.log_blowup, m),
            fri.num_queries,
            fri.query_pow_bits,
        )
        .bits();
        let folds = shape.log_trace_length + 1;
        let raw = |label| {
            johnson
                .terms()
                .iter()
                .find(|t| t.label == label)
                .map(|t| t.bits.bits())
                .expect("required Johnson term")
        };
        let mut quantum: Vec<_> = johnson
            .terms()
            .iter()
            .filter(|t| !matches!(t.label, "commitment-collision" | "low-degree-test"))
            .map(|t| t.bits.bits() / 2.)
            .collect();
        quantum.push(query / 2.);
        quantum.push(folding / 2. - (folds as f64).log2());
        let q_union = union(quantum.into_iter());
        let conjectured_union = union(conjectured.terms().iter().map(|t| t.bits.bits()));
        let johnson_union = union(johnson.terms().iter().map(|t| t.bits.bits()));
        let bht = raw("commitment-collision") * 2. / 3.;
        let passes = conjectured_union >= 128.
            && johnson_union >= 100.
            && q_union >= 80.
            && raw("deep-ali") / 2. >= 80.
            && folding / 2. - (folds as f64).log2() >= 80.
            && bht >= 80.;
        Ok(
            json!({"p3_security_version":"0.9.0-rc.2","accounting":ACCOUNTING,
            "fri":params_json(p),"grinding_sites":grinding,
            "application_binding":application_binding(),
            "shape":{"status":"actual-extracted","base_trace_rows":air.slot.height,
                "main_width":layout.main_width,"preprocessed_width":layout.preprocessed_width,
                "public_values":layout.num_public_values,"num_constraints":a.num_constraints,
                "max_constraint_degree":a.max_constraint_degree,
                "num_quotient_chunks":a.num_quotient_chunks,
                "num_batched_functions":functions,"log_committed_trace_length":shape.log_trace_length,
                "challenge_field_bits_floor":247,"classical_collision_bits_floor":185},
            "conjectured":breakdown(&conjectured),"proven_johnson":breakdown(johnson),
            "proven_unique_decoding":breakdown(&proven.udr),
            "johnson_fri_terms":[{"label":"fri-folding","bits":number(folding)},
                {"label":"fri-query","bits":number(query)}],"fri_folding_rounds":folds,
            "challenge_domain_terms":[{"label":"ood-deep-ali-domain","bits":number(raw("deep-ali"))},
                {"label":"fri-folding-domain","bits":number(folding-2.*(folds as f64).log2())}],
            "screen":{"passes_selected_model":passes,"classical_conjectured_union_bits":conjectured_union,
                "classical_johnson_union_bits":johnson_union,"quantum_johnson_challenge_union_bits":q_union,
                "bht_collision_bits":bht,"johnson_m":m,"proof_multiplicity":1},
            "application_binding_limitations":[
                "BLAKE3-256 is an external application byte binding, excluded from raw p3-security terms",
                "Nominal classical collision bits 128 and BHT bits 256/3 require model review",
                "The complete relation/PCS/application-hash composition remains unreviewed"],
            "setup_performed":false,"production_selection_allowed":false}),
        )
    }
    fn save(path: &Path, value: &Value) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())
    }
    fn cgroup() -> Result<PathBuf, String> {
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "Linux cgroup v2 required")?;
        let relative = membership
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or("unified cgroup v2 required")?;
        if relative == "/" || relative.contains("..") {
            return Err("dedicated process-tree cgroup required".into());
        }
        Ok(Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
    }
    fn memory_peak(path: &Path) -> Result<u64, String> {
        std::fs::read_to_string(path.join("memory.peak"))
            .map_err(|e| e.to_string())?
            .trim()
            .parse()
            .map_err(|_| "invalid memory.peak".into())
    }
    fn effective_cpu_max(path: &Path) -> Result<String, String> {
        let mut current = Some(path);
        while let Some(directory) = current {
            let file = directory.join("cpu.max");
            if file.exists() {
                let value = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
                if !value.split_whitespace().next().is_some_and(|s| s == "max") {
                    return Err("effective ancestor cpu.max is throttled".into());
                }
            }
            if directory == Path::new("/sys/fs/cgroup") {
                break;
            }
            current = directory.parent();
        }
        Ok("max 100000".into())
    }
    fn measure(p: FriParams, operation: &str, workers: usize) -> Result<Value, String> {
        let expected_workers = workers.to_string();
        if std::env::var("RAYON_NUM_THREADS").ok().as_deref() != Some(expected_workers.as_str()) {
            return Err("RAYON_NUM_THREADS must equal the requested worker count".into());
        }
        #[cfg(feature = "parallel")]
        let actual_workers = p3_maybe_rayon::prelude::current_num_threads();
        #[cfg(not(feature = "parallel"))]
        let actual_workers = 1;
        if !p3_maybe_rayon::PARALLEL_ENABLED || actual_workers != workers {
            return Err(
                "parallel backend and actual Rayon worker count must match the request".into(),
            );
        }
        let group = cgroup()?;
        let cpu = effective_cpu_max(&group)?;
        let start = Instant::now();
        let prover = TransactionProver::new(p);
        let setup_ns = start.elapsed().as_nanos();
        let mut witness = acc_witnesses(vec![sample_slot(61, false)], 1000, FEE_BASE, 62)
            .0
            .remove(0);
        let fields = witness.slot.public_inputs(&Hasher::new());
        let public = PublicTransaction {
            nf: fields.nf,
            cm: fields.cm_out,
            payment: PaymentCiphertext {
                kem_ciphertext: [1; 1088],
                body: [2; 208],
                tag: [3; 16],
                view_tag: 4,
            },
            change: ChangeCiphertext {
                nonce: [5; 12],
                body: [6; 208],
                tag: [7; 16],
                view_tag: 8,
            },
        };
        let context = ProofContext::new([9; 32]);
        let wire = public.encode();
        let decoded = PublicTransaction::decode(&wire).map_err(|e| format!("codec: {e:?}"))?;
        witness = decoded
            .bind_witness(&witness, &context)
            .map_err(|e| format!("witness: {e:?}"))?;
        let started = Instant::now();
        let (proof, statement) = prover.prove(&witness);
        let generation_ns = started.elapsed().as_nanos();
        let public_statement_bytes = postcard::to_allocvec(&statement)
            .map_err(|e| e.to_string())?
            .len();
        let proof_body = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let proof = postcard::from_bytes::<p3_uni_stark::Proof<Cfg>>(&proof_body)
            .map_err(|e| e.to_string())?;
        let fields = witness.slot.public_inputs(&Hasher::new());
        if statement
            != decoded.statement(
                &context,
                &fields.fee_commit,
                &witness.anchors_root(&Hasher::new()),
            )
        {
            return Err("decoded transaction statement differs from its generated proof".into());
        }
        let started = Instant::now();
        decoded.verify(
            &prover,
            &proof,
            &context,
            &fields.fee_commit,
            &witness.anchors_root(&Hasher::new()),
        )?;
        let verification_ns = started.elapsed().as_nanos();
        Ok(
            json!({"operation":operation,"workers":actual_workers,"rayon_threads":actual_workers,
            "measurement_kind":"actual-native-proof","exit_code":0,"verified":true,
            "wall_ns":if operation=="verification" {verification_ns}else{generation_ns},
            "setup_ns":setup_ns,"generation_ns":generation_ns,"verification_ns":verification_ns,
            "memory_peak_bytes":memory_peak(&group)?,"cpu_max":cpu,
            "memory_peak_scope":"dedicated cgroup lifetime, including setup and validation",
            "proof_body_bytes":proof_body.len(),"public_transaction_bytes":wire.len(),
            "public_statement_bytes":public_statement_bytes,
            "public_statement_encoding":"derived from the public codec and excluded from proof_body_bytes",
            "verification_calls":1,
            "generation_scope":"trace generation and native proof with prepared key; codec and encryption preparation are separate",
            "production_selection_allowed":false}),
        )
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let mut flags = Vec::new();
        let mut values = BTreeMap::new();
        while let Some(key) = args.next() {
            if ["--security-only", "--security-grid"].contains(&key.as_str()) {
                if flags.contains(&key) {
                    return Err("duplicate flag".into());
                }
                flags.push(key);
            } else {
                if ![
                    "--log-blowup",
                    "--grinding",
                    "--queries",
                    "--max-queries",
                    "--machine-id",
                    "--output",
                    "--operation",
                    "--trial-index",
                    "--run-id",
                ]
                .contains(&key.as_str())
                {
                    return Err(format!("unknown argument {key}"));
                }
                let value = args.next().ok_or("missing argument value")?;
                if value.starts_with("--") || values.insert(key, value).is_some() {
                    return Err("missing or duplicate argument value".into());
                }
            }
        }
        if flags.len() > 1 {
            return Err("security-only and security-grid are mutually exclusive".into());
        }
        let integer = |name: &str, default: u32| -> Result<u32, String> {
            values
                .get(name)
                .map(|v| v.parse().map_err(|_| format!("invalid {name}")))
                .unwrap_or(Ok(default))
        };
        let b = integer("--log-blowup", 4)?;
        let g = integer("--grinding", 16)?;
        let q = integer("--queries", 80)?;
        let max = integer("--max-queries", 512)?;
        if !(2..=4096).contains(&max) {
            return Err("max queries must be 2..4096".into());
        }
        let machine = values
            .get("--machine-id")
            .map(String::as_str)
            .unwrap_or("unqualified-diagnostic-host");
        let output = PathBuf::from(values.get("--output").ok_or("--output FILE required")?);
        let make = |b, q, g| FriParams {
            log_blowup: b,
            num_queries: q,
            query_pow_bits: g,
            commit_pow_bits: 0,
            batch_pow_bits: g,
            max_log_arity: 1,
        };
        if flags.iter().any(|f| f == "--security-grid") {
            let mut rows = Vec::new();
            for b in 4..=8 {
                for g in [16, 20, 24] {
                    let mut found = None;
                    for q in 2..=max {
                        let report = security(make(b, q, g))?;
                        if report["screen"]["passes_selected_model"] == true {
                            let mut report = report;
                            report.as_object_mut().unwrap().extend(
                                binding(make(b, q, g), machine)?
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            );
                            found = Some(
                                json!({"parameters":params_json(make(b,q,g)),"security":report,
                            "previous_query_security":security(make(b,q-1,g))?}),
                            );
                            break;
                        }
                    }
                    rows.push(found.unwrap_or(
                        json!({"log_blowup":b,"grinding":g,"status":"no candidate in query range"}),
                    ));
                }
            }
            save(
                &output,
                &json!({"schema":1,"scope":SCOPE,"suite":SUITE,
                "actual_production_air":false,"production_selection_allowed":false,
                "grid_pairs":15,"query_range":[2,max],"rows":rows}),
            )?;
        } else {
            if !(4..=8).contains(&b) || ![16, 20, 24].contains(&g) || !(2..=4096).contains(&q) {
                return Err("require b=4..8, g=16/20/24, q=2..4096".into());
            }
            let p = make(b, q, g);
            let mut result = binding(p, machine)?;
            if flags.iter().any(|f| f == "--security-only") {
                result
                    .as_object_mut()
                    .unwrap()
                    .extend(security(p)?.as_object().unwrap().clone());
            } else {
                let operation = values
                    .get("--operation")
                    .map(String::as_str)
                    .unwrap_or("four_worker");
                let workers = match operation {
                    "single_worker" | "verification" => 1,
                    "four_worker" => 4,
                    _ => return Err("unknown measurement operation".into()),
                };
                result
                    .as_object_mut()
                    .unwrap()
                    .extend(measure(p, operation, workers)?.as_object().unwrap().clone());
                result["trial_index"] = json!(integer("--trial-index", 1)?);
                result["run_id"] = json!(values.get("--run-id").ok_or("--run-id required")?);
            }
            save(&output, &result)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use p3_field::PrimeCharacteristicRing;

        #[test]
        fn security_extracts_native_shape_without_setup_and_remains_ineligible() {
            let report = security(FriParams {
                log_blowup: 4,
                num_queries: 80,
                query_pow_bits: 16,
                commit_pow_bits: 0,
                batch_pow_bits: 16,
                max_log_arity: 1,
            })
            .unwrap();
            assert_eq!(report["p3_security_version"], "0.9.0-rc.2");
            assert_eq!(report["shape"]["status"], "actual-extracted");
            assert_eq!(report["shape"]["public_values"], 97);
            assert!(report["shape"]["main_width"].as_u64().unwrap() > 100);
            assert_eq!(report["setup_performed"], false);
            assert_eq!(report["screen"]["proof_multiplicity"], 1);
            assert_eq!(report["production_selection_allowed"], false);
            assert_eq!(report["grinding_sites"]["batch_combination"], 16);
            assert_eq!(
                report["application_binding"]["nominal_classical_collision_bits"],
                128
            );
            assert_eq!(
                report["application_binding"]["included_in_p3_security_report"],
                false
            );
            assert_eq!(
                report["application_binding"]["nominal_bht_collision_bits"],
                256. / 3.
            );
        }

        #[test]
        fn native_hiding_pcs_rejects_modified_batch_grinding_witness() {
            let prover = TransactionProver::new(FriParams {
                batch_pow_bits: 4,
                ..FriParams::fast()
            });
            let witness = acc_witnesses(vec![sample_slot(61, false)], 1000, FEE_BASE, 62)
                .0
                .remove(0);
            let (mut proof, public) = prover.prove(&witness);
            prover.verify(&proof, &public).unwrap();
            proof.opening_proof.1.batch_pow_witness += F::ONE;
            assert!(prover.verify(&proof, &public).is_err());
        }
    }
}

#[cfg(feature = "security-report")]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("native transaction diagnostic rejected: {error}");
        std::process::exit(2);
    }
}
