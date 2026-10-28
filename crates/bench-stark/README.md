# STARK Benchmarks

This separate workspace contains the native witness reference in `common` and Plonky3 leaf and recursive circuits in `plonky3`. The legacy node prover imports the accumulator circuits, so they are part of its review surface. Native V1 transaction proofs use the independent D8 and multi-asset workspaces.

```sh
cargo test --release --locked -p siworld-bench-plonky3 -p siworld-bench-common
cargo run --release --locked -p siworld-bench-plonky3 -- --acc --leaves 32 --reps 5
```

See [methodology](../../docs/benchmarks.md), [cryptography](../../docs/cryptography.md) and [security boundaries](../../docs/security-model.md). Keep local measurements and exports outside version control. Reduced-security debugging cannot substantiate secure proving performance.
