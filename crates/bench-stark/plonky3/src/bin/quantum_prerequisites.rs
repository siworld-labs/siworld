//! Narrow dependency probes, not a quantum soundness or full-recursion test.
use p3_circuit::ops::Poseidon2Config;
use p3_circuit::{CircuitBuilder, CircuitRunner};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_recursion::builtin_config::SuiteIdV1;
use p3_recursion::pcs::convert_merkle_proof_to_siblings;

type D8 = BinomialExtensionField<KoalaBear, 8>;

/// Exercise the dependency's real conversion, including the non-divisible
/// digest/extension case. This establishes no in-circuit MMCS binding.
fn check_lifted_digest() {
    let digest = core::array::from_fn::<_, 12, _>(|i| KoalaBear::from_u32(i as u32 + 1));
    let lifted = convert_merkle_proof_to_siblings::<KoalaBear, D8, 12>(&[digest]);
    assert_eq!(lifted.len(), 1);
    assert_eq!(lifted[0].len(), 12);
    for (value, base) in lifted[0].iter().zip(digest) {
        let coefficients: &[KoalaBear] = value.as_basis_coefficients_slice();
        assert_eq!(coefficients[0], base);
        assert!(
            coefficients[1..]
                .iter()
                .all(|coefficient| *coefficient == KoalaBear::ZERO)
        );
    }
    // No limb, including the final four, may disappear during this conversion.
    for limb in 0..12 {
        let mut changed = digest;
        changed[limb] += KoalaBear::ONE;
        let actual = convert_merkle_proof_to_siblings::<KoalaBear, D8, 12>(&[changed]);
        assert_ne!(actual, lifted);
        for i in 0..12 {
            assert_eq!(actual[0][i] == lifted[0][i], i != limb);
        }
    }
    println!(
        "D8 native digest conversion preserves all 12 lifted scalars; each limb mutation is observed."
    );
}

/// Execute a D8 constraint circuit with non-base-field operands, then reject a
/// mismatched public result. No STARK or recursive verifier is constructed.
fn check_d8_circuit_execution() {
    let a = D8::from_basis_coefficients_fn(|i| KoalaBear::from_u32(i as u32 + 1));
    let b = D8::from_basis_coefficients_fn(|i| KoalaBear::from_u32(i as u32 + 11));
    let mut builder = CircuitBuilder::<D8>::new();
    let left = builder.alloc_private_input("left");
    let right = builder.alloc_private_input("right");
    let expected = builder.public_input();
    let product = builder.mul(left, right);
    builder.connect(product, expected);
    let circuit = builder.build().expect("D8 circuit construction");
    for (result, valid) in [(a * b, true), (a * b + D8::ONE, false)] {
        let mut runner = CircuitRunner::new(&circuit);
        runner.set_public_inputs(&[result]).expect("public result");
        runner
            .set_private_inputs(&[a, b])
            .expect("private operands");
        assert_eq!(runner.run().is_ok(), valid);
    }
    println!(
        "D8 circuit execution matches native multiplication and rejects a wrong public result."
    );
}

fn main() {
    assert_eq!(<D8 as BasedVectorSpace<KoalaBear>>::DIMENSION, 8);
    assert_eq!(D8::ONE * D8::ONE, D8::ONE);
    println!("Base-field library: KoalaBear D8 arithmetic is available.");
    check_lifted_digest();
    check_d8_circuit_execution();

    let supported = SuiteIdV1::ALL
        .iter()
        .filter(|suite| {
            let spec = suite.spec();
            spec.extension_degree == 8 && spec.digest_elements == 12
        })
        .count();
    println!("Registered recursion suites with D8 and 12-element digests: {supported}");
    // Fail if the dependency inventory changes, so the assessment is revisited.
    assert_eq!(supported, 0, "reassess the new registered suite");

    let config = Poseidon2Config::KOALA_BEAR_D4_W24;
    let inputs = config.width_ext() + 1;
    let outputs = config.rate_ext();
    config
        .validate_io_counts(inputs, outputs, false)
        .expect("W24 sponge mode");
    let error = config
        .validate_io_counts(inputs, outputs, true)
        .expect_err("reassess newly supported W24 binary Merkle geometry");
    println!(
        "Existing W24 D4 circuit supports sponge mode but rejects binary Merkle mode: {error:?}"
    );
    println!("This does not test a custom D8/W24 recursive backend or establish security.");
}
