# Proof Measurement Requirements

The [monetary relations](v1-economics.md) use revision
`native-v1-economics-1`. Fresh actual-AIR reports and 39 EPYC 7763 reference
trials replace pre-revision performance claims for the changed relations.
Public-key reproduction and complete CI remain release checks.

Status: reproducible isolated native proof measurements. Benchmark results
are not full-node, wallet-latency, network or hardware acceptance.

## Native V1

The [multi-asset workspace](../crates/bench-multi-asset/README.md) implements
transaction, issuance and settlement relations. The
[actual-AIR evaluation](v1-multi-asset-evaluation.md) records the eight-profile
transaction scan and source-bound selected profile. Settlement and issuance
have separate measured profiles; identify the exact proof kind in every result.

| Relation | Four-worker generation median | Largest four-worker proof | Maximum charged process-tree peak |
| --- | ---: | ---: | ---: |
| Transaction, b7/q41/g20 | 1.462877730 s | 585,808 B | 525,234,176 B |
| Fixed-576 settlement, b8/q36/g20 | 5.523829281 s | 520,203 B | 3,161,432,064 B |
| Three-note issuance, b8/q36/g20 | 0.639979907 s | 280,401 B | 211,423,232 B |

Each row has three four-worker trials. The eight-profile transaction grid has
24 trials; three selected one-worker transaction trials and twelve settlement/
issuance trials bring the run to 39. The selected transaction's maximum
four-worker generation time is 1.531155438 seconds. Across its one- and
four-worker trials the largest body is 588,832 bytes, below the 655,360-byte
cap with more than 10% measured margin. All charged peaks include fresh setup,
proving, verification and the recorder; none is an independent verifier peak.
The one-worker transaction verifier-call median is 17.006900 ms inside a
one-worker setup/prove/verify process. Independent verification-only resource
qualification remains required.

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
