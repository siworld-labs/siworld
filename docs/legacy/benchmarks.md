# Proof-System Benchmarks

> **Superseded by V1 (Route A).** This page documents the legacy recursive implementation. The retained seven-node N=2 engineering testnet uses this classical proof route; it is not a native V1 testnet or post-quantum acceptance result. See the [current V1 overview](../v1-overview.md).

## Scope

The separate `crates/bench-stark` workspace contains a native witness reference, Plonky3 AIR and recursion, and optional SP1 comparisons. The node prover imports the same accumulator circuits. Concatenated and chained modes are comparisons, not alternate node consensus modes.

No device-independent latency or throughput claim is made. Every published result requires revision, hardware, toolchain, dependency revisions, proof parameters, capacity, concurrency and sample count. Historical working measurements are not release evidence.

## Reproduction

```sh
cargo test --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 -p siworld-bench-common
```

```sh
cd crates/bench-stark
cargo run --release --locked -p siworld-bench-plonky3 \
  -- --acc --leaves 32 --reps 5
```

Use `--chain` for chained aggregation or omit the mode for concatenation. Run comparisons sequentially to avoid CPU contention. Keep unreviewed raw measurements outside version control.

## Parameters and artifacts

`--log-blowup`, `--queries` and `--pow` override proof parameters. `--fast` is insecure debugging and cannot substantiate secure proving performance. Parameter changes require soundness analysis at every layer.

```sh
cargo run --release --locked -p siworld-bench-plonky3 \
  -- --acc --leaves 16 --reps 1 --export /tmp/siworld-proof-artifacts
```

Exports contain public verification data, proof and statement. `--dump-root` supplies JSON to `scripts/proof_breakdown.py`; `leaf_params` compares leaf configurations. `scripts/set_hash_security.py` evaluates generic accumulator attacks under its stated assumptions.

SP1 has its own workspace and toolchain prerequisites. Comparison reports must identify proof form and zero-knowledge properties. An unwrapped STARK result is not automatically a confidential node proof system.

## Measurement requirements

Separate setup from steady-state leaf, internal-node and root proving. Record verification time, canonical proof size, peak memory and wall/CPU time. Label assumed parallel critical paths as estimates. Measure sustained operation and memory at the intended concurrency before drawing deployment conclusions.
