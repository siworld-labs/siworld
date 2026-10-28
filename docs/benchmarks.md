# Proof Measurement Requirements

Status: reproducible isolated native proof measurements. Benchmark results
are not full-node, wallet-latency, network or hardware acceptance.

## Native V1

The [multi-asset workspace](../crates/bench-multi-asset/README.md) implements
transaction, issuance and settlement relations. The
[actual-AIR evaluation](v1-multi-asset-evaluation.md) records the eight-profile
transaction scan and source-bound selected profile. Settlement and issuance
have separate measured profiles; identify the exact proof kind in every result.

```sh
cargo test --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --lib
cargo build --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --bin native-scan
```

Use fresh result paths and explicit worker settings. Generate one-worker
verification measurements in separate processes; a verifier call inside a
four-worker proving process does not establish single-worker performance.
Follow [Linux process-tree measurement](linux-proof-measurement.md) and
[resource accounting](memory-budgets.md) for cgroup peaks/events and hardware
qualification. The 5-GiB diagnostic scope is not a miner hardware minimum.

## Evidence requirements

Record source, dependency and artifact identities; proof kind and actual AIR
shape; parameters; toolchain/target features; CPU/model/quota/hypervisor; worker
and hiding-kernel settings; sample count; canonical proof bytes; and per-stage
wall/CPU time and charged memory. Separate one-time preparation from proving
and verification. Report memory-event deltas and process-tree scope.

Publish only inspected reproducible technical evidence. Do not publish private
raw logs, credentials, personal paths or runtime reports. Three passing trials
do not bound randomized grinding tails or shared-host contention. Source/key
freeze, independent cryptographic review and integrated acceptance are distinct.

## Legacy and paused research

The [legacy benchmark commands](legacy/benchmarks.md) describe the recursive
workspace used by the retained runtime. [V2 research](v2/README.md) is paused;
its recursive timing/memory targets do not apply to native V1. Reduced-security
or mock-proof debugging cannot substantiate secure native performance.
