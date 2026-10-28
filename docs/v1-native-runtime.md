# Native V1 Engineering Runtime

Status: the continuous single-node service and native node-integration library
are implemented engineering components. The library adds bounded admission,
authenticated-stream protocol interfaces, full-proof synchronization,
verified-work fork selection, wallet primitives and a public subsidy audit.
Remote CI compiles and tests the integration, including separately selected
native-proof tests. The real 24-hour service observation and final offline
replay remain separate required evidence; this document does not
report their completion. No production hybrid-handshake provider or network
service command is supplied. The runtime does not activate a public network,
replace an existing database or change the retained seven-node legacy network.
Independent security review remains pending.

## Scope

The [economic revision](v1-economics.md) reopens proof qualification. The
retained continuous-service observation uses its frozen pre-revision artifacts
and must not be restarted or reinterpreted as acceptance of revised economics.
New economic state, reward outputs and lock checks require separate tests,
replay evidence, source-bound keys and a new explicitly activated network.

`crates/native-node` composes the native transaction and fixed-capacity
settlement relations with a versioned block codec, canonical ordering, a common
state transition, and replay-verified local persistence. It uses D8/W24 with
12-element digests throughout; it does not truncate them into legacy digests.
The implementation imports the fixed native relation manifests and rejects
unrecognized keys, profiles, malformed proof vectors, and noncanonical fields.

Transactions have two inputs and three outputs. A block contains 64–576 slots,
in groups of 16, in strict ascending proof-independent BLAKE3 statement-ID
order. Duplicate IDs and nullifiers, including the second input, are rejected.
The statement binds the network, version, canonical snapshot identity, all
public transaction bytes and the fee commitment. Proof and sidecar bytes do
not change that identity. The block ID additionally authenticates proof bodies,
reward ciphertext, parent, timestamp, target and nonce. The ordered settlement-list digest
excludes proof bodies.

The producer and replay validator call the same state transition. Every
transaction proof and the independent settlement proof must verify before
accepted state changes. Output commitments and all SIP reward notes are appended
to the depth-40 commitment tree. Accepted snapshot identities expire after
4096 canonical entries; an absent or removed identity is invalid even when
another snapshot has the same root. The chain library verifies complete
candidate branches and selects strictly greater cumulative verified work;
advertised height or work is never authoritative. Equal work retains the
current branch. A reorganization may detach at most 24 canonical blocks;
a deeper divergence requires explicit recovery rather than automatic adoption.

The fixed 576-row settlement relation reconstructs unused zero-fee rows from
the network, block height, position count and row index with an explicit
engineering domain. These rows are internal relation inputs, not extra chain
transactions or public real/dummy classification flags. Native multi-asset hash
domains are used throughout.

## Local persistence and reward recovery

A new independent engineering directory contains its explicit network configuration,
`chain.redb` and private reward recovery receipts. Initialization refuses an
existing directory. The ASERT service uses engineering configuration format v2,
which binds a fresh network identity, genesis timestamp, immutable calibrated
target, 300-second target interval and sequential BLAKE3 work iterations.
This engineering format version is unrelated to the deferred recursive V2
roadmap. Earlier engineering directories are preserved and are not migrated
automatically. There is no reset or migration operation. Replay reconstructs
accepted state by verifying every stored block and checking its recorded state
fingerprint. Each append commits the canonical block, accepted height and
fingerprint in one durable database transaction before exposing the new state.
Branch adoption uses one redb transaction for the replacement canonical rows,
head, fingerprint and retained detached records. Detached blocks remain
checksummed evidence and are never treated as accepted-chain authority.
Missing rows, changed metadata, wrong-network data and failed proofs fail closed.
Unclean databases requiring redb repair are preserved and refused pending
explicit recovery review; automatic crash-repair tooling is not an M1 claim.

The local producer uses operating-system entropy and actual ML-KEM/ChaCha
output encryption. It authenticates and reconstructs output commitments before
proving. Reward recovery material is saved privately and synced before the
accepted block is committed. A receipt contains the spending material and
single-payment encapsulation opening needed to recover that reward; it must
never be published. Service-produced rewards still use this receipt mechanism;
they are not yet addressed to a seed-derived wallet. The separate wallet API
below does not replace these receipts or establish durable wallet recovery.

## Admission, synchronization and fork handling

`runtime::Node` composes a persistent store, verified mempool, padding pool
and one shared transport budget. Local wallet submission follows the same
proof and sidecar checks as a remote identity. Admission inspects borrowed
framing before copying proofs, resolves canonical snapshots, checks both
nullifiers and all outputs, validates the sidecar against the transaction
identity and fee commitment, then independently verifies the frozen relation.
Verified entries are retained until canonical inclusion or explicit eviction;
private fee sorting does not change canonical block ordering. Candidate
assembly checks every opening and adds the private fee sum to the SIP miner
reward with checked integer arithmetic.

The verified pool permits 512 MiB and 2,048 entries, with 16 MiB/64 entries
per opaque peer and at most 4,096 peer identities. These are logical owned-byte
bounds, not process RSS guarantees. The API distinguishes cryptographic
invalidity from local resource unavailability. Isolated verifier workers,
unverified ingress queues and the planned abuse caches are not implemented
by this in-process pool.

The streaming protocol binds network, genesis and frozen verifier manifest
before role-specific requests. A session requires an `Authenticated` channel
from an in-crate hybrid provider; no production provider is implemented and
no plaintext or classical fallback constructor is public. The provider must
supply reviewed X25519 + ML-KEM key exchange, dual Ed25519/ML-DSA identity
binding, transcript/key confirmation, authenticated records, nonce/sequence
limits, rekeying, deadlines and secret cleanup. Current TCP helpers cannot
establish production sessions until that provider exists. Session failure
requires fresh authentication on reconnect.

The library serves bounded block batches, transaction envelopes with private
sidecars and compact references. Synchronization pins peer identity, ancestor,
request sequence and continuation to one attempt; a canonical change invalidates
that attempt. Downloaded candidates are replayed through the common transition
before adoption. Compact recovery uses statement and proof digests together,
requests no more than 16 missing transactions, and does not disclose sidecars
in block-recovery responses. Network activation and deployed-listener failure
tests remain outstanding.

Missing-proof requests and exact-proof response validation are exposed as a
bounded helper. The compact announcement handler accepts a complete local
reconstruction or returns unavailability; the connection scheduler must still
orchestrate missing-proof requests or a full-proof retry. A missing reference
is not a cryptographic invalidity verdict.

Canonical locator and synchronization-base lookups reserve one maximum block
plus bookkeeping before decoding stored proofs. Exhaustion is retryable and
does not invalidate the peer or alter pending transactions.

One shared 640-MiB logical transport budget covers retained receive buffers,
with at most 16 handshakes and a 4-MiB aggregate handshake allowance. Candidate
validation additionally defaults to 32 blocks, 640 MiB of logical state/body
accounting and 1 GiB of retained detached evidence. Reconstructing a non-tip
ancestor is limited to height 4,096 because it currently replays from genesis;
this guard is local resource policy, not a checkpoint or consensus horizon.
Beyond it, reorganization returns resource unavailability until a qualified
checkpoint/replay mechanism is provided. Extending the current tip does not
require this ancestor reconstruction. Detached retention does not implement
the required three-day proof deletion lifecycle.

## Wallet and public subsidy audit

The wallet API derives separate spend, deterministic ML-KEM view and 256-bit
sender-change keys from a supplied 32-byte seed, network and account index.
After independently replaying a complete supplied canonical history, it
checks authenticated recipient/change ciphertexts and reconstructed note
commitments, derives spent status and atomically replaces private receipts.
Replaying a replacement chain removes orphan receipts and restores orphan
spends. The wallet can prepare fixed two-input/three-output SIP or issued-asset
transfers, pay standard or priority fees only in SIP, recheck all output
encodings before proving and return the transaction, matching sidecar and
private payment opening. Seed bytes and supported private buffers are erased
on drop; dependency-internal and native-field copies are outside that guarantee.

These APIs accept seeds rather than implement mnemonic backup. Protected
seed/payment-opening persistence, valid-chain funding into seed-derived
addresses, issuance admission, wallet transport and recovery from pruned
public-history segments remain separate work. A native-proof test using
synthetic funding is not full-chain M2 acceptance.

The `audit` command acquires the engineering-directory lease and independently
replays canonical proof-carrying blocks. It checks each height's integer SIP
subsidy and direct/locked development-fund credits against accepted counters,
then binds its report to the exact height, tip and state fingerprint. Output
contains only public subsidy/fund-credit records. It does not audit asset
issuance or fund spending, and it does not validate local reward recovery
receipts; the report explicitly marks these scope limits. Complete issuance
and signed fund-spending audits remain blocked on those node transitions.

## Engineering commands

### Controlled Linux package

On a qualified Linux x86_64 host:

```sh
python3 scripts/build-native-runtime.py --output .local/native-runtime-release
mkdir -p .local/native-engineering
.local/native-runtime-release/bin/siworld-native-node init .local/native-engineering/network-a 0
.local/native-runtime-release/bin/siworld-native-node mine .local/native-engineering/network-a 64
.local/native-runtime-release/bin/siworld-native-node check .local/native-engineering/network-a
.local/native-runtime-release/bin/siworld-native-node audit .local/native-engineering/network-a
.local/native-runtime-release/bin/siworld-native-node status .local/native-engineering/network-a
```

The controlled Linux build uses x86-64-v3 and places the optimized worker behind
an independently compiled baseline CPU-admission launcher. Unsupported CPUs are
rejected; there is no scalar fallback. Direct source builds on other platforms
are development diagnostics and do not establish deployment qualification.

The `init`/`mine` example is an inexpensive correctness fixture. Its optional
work-bit selector is limited to 0–24, and continuous service refuses fixture
configurations. Fixture results do not qualify ASERT timing or a sustained run.
The current subsidy and fee helper functions are reused for engineering
accounting; public activation and epoch recalibration require their own
protocol decisions and integration tests.

### Independent ASERT service

Create a different, absent directory for continuous production:

```sh
.local/native-runtime-release/bin/siworld-native-node init-service .local/native-engineering/asert-a
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-runtime-release/bin/siworld-native-node run .local/native-engineering/asert-a
```

`init-service` performs one bounded initialization-only work-rate calibration
and durably fixes its resulting target in the new configuration. Resume does
not recalibrate or change these rules. The shared integer-only ASERT transition
checks each block's timestamp, required target and sequential BLAKE3 work;
the target interval is 300 seconds. A local sleep does not substitute for work,
and stochastic block intervals need not equal exactly five minutes.

`run` acquires an exclusive engineering-directory lease, replays existing
history and reward receipts, then prepares one resident prover. A private
queue independently verifies generated positions before reserving their
identities, inputs, outputs and bytes. The service produces 64-position blocks
and replenishes the queue during work search, subject to its 128-entry and
65-MiB limits. Expired, orphaned or conflicting snapshot entries are removed;
consumed reservations prevent candidate reuse. The queue size and position
classifications are not exported. This continuous service remains a
padding-only observation service. Wallet admission and candidate composition
are separate library APIs, not new commands on the observed service.

The service remains running after its observation timer reaches 24 hours. The
following commands read the private export or request an explicit run-bound
graceful stop:

```sh
.local/native-runtime-release/bin/siworld-native-node service-status .local/native-engineering/asert-a
.local/native-runtime-release/bin/siworld-native-node stop .local/native-engineering/asert-a
```

A stop request is checked at safe boundaries and during work batches; an
in-progress proof may finish before shutdown. Graceful shutdown closes the
writer, replays all accepted blocks and verifies every local reward receipt.
It preserves the database, run receipts and event history. Error paths preserve
their evidence and do not automatically retry or restore earlier state.
`check` always acquires the engineering lease and fully replays the database
and reward receipts; use it after the service exits. `status` returns the
private export when one exists, including a stopped run's final export;
otherwise it acquires the lease and replays an idle store. An exported status
is not an independent replay. Use `service-status` for explicit live inspection.

### Real 24-hour observation

The service writes an atomic `service-status.json`, append-only
`service-events.jsonl`, and immutable per-run receipts beneath `service-runs/`.
These files are private; monitoring never opens the live database. Status binds
the run, process, binary and configuration identities, accepted state
fingerprint, cumulative work, phases, heartbeats and actual work progress.
It excludes private openings, individual fees, addresses, timed nullifiers,
position classifications and queue counts.

Start the observer in a separate supervised process on the same authorized
host, using the stable executable actually running the service. For the Linux
package this is the `libexec` worker, rather than the CPU-admission launcher:

```sh
python3 scripts/observe-native-service.py watch \
  --network-dir .local/native-engineering/asert-a \
  --binary .local/native-runtime-release/libexec/siworld-native-node \
  --config .local/native-engineering/asert-a/engineering-network.bin \
  --output .local/native-engineering/asert-a-observation
```

The output directory must be absent. The observer creates private evidence,
checks OS process identity, freezes the binary/configuration hashes and run
identity, and independently measures 86,400 actual monotonic seconds after
readiness. Five-second samples cannot have gaps longer than 15 seconds. A new
collector does not inherit earlier elapsed service time. A changed run,
unexpected exit, stale heartbeat, stalled actual work, state inconsistency,
proof error or available cgroup OOM-counter increase makes the observation
incomplete. A long block gap below two hours with continuing real PoW progress
is permitted. During ready observation, two hours without an increased accepted
height makes the window incomplete even if hashing counters keep advancing.
This is an operational investigation threshold, not a consensus rule or a
deterministic promise about the 300-second target.
On hosts without cgroup counters, their absence is recorded and sampled RSS
must not be represented as a charged-memory or OOM bound.

Read the saved summary without accessing the service:

```sh
python3 scripts/observe-native-service.py inspect \
  --output .local/native-engineering/asert-a-observation
```

An `observing` summary older than 15 seconds is rejected. Observer completion
always retains `final_replay_required=true`. After a complete window, request
graceful stop, wait for a successful exit, run `check` offline and compare the
final height, tip and state fingerprint with the accepted observation and
shutdown receipts. Preserve any failure and begin a new clean window only
after review; do not credit gaps, restarts or accelerated clocks. A single-node
24-hour window is a pre-deployment engineering gate. It does not replace
maximum-load, independent-host, retention or recovery acceptance.

## Validation and remaining gates

```sh
cargo fmt --manifest-path crates/native-node/Cargo.toml --check
cargo test --locked --manifest-path crates/native-node/Cargo.toml --lib
cargo clippy --locked --manifest-path crates/native-node/Cargo.toml --all-targets -- -D warnings
```

The new integration suite includes invalid-envelope and sidecar rejection,
wrong-network/framing and reconnect behavior, multi-batch synchronization,
verified-work branch choice, depth-24/depth-25 reorganization boundaries,
atomic failure, detached-record reopen, wallet rescan and public-audit checks.
Some tests use deterministic synthetic verifiers to isolate state and transport
behavior. Separately selected native-proof tests exercise frozen proving and
verification; the wallet proof test uses synthetic funding history. The new
suite is covered by the dedicated native runtime CI job. None of these
correctness checks substitutes for actual hybrid-provider tests,
target-hardware performance or sustained-load acceptance.

M1 does not implement issuance admission. The testnet fee is fixed at 50 SIP
(5,000,000,000 atoms), entirely credited to a dedicated development-fund
account. That account is not configured, so issuance remains closed and fails
closed. Destination configuration, atomic fee consumption/fund credit and
issuance resource bounds remain implementation gates; the mainnet fee remains
undecided. Unsupported operations are absent from the wire codec.
Production hybrid identity/record protection, a listening network service,
verifier-worker isolation, pruning/checkpoint bootstrap, real three-day
retention, Dandelion++, fund payout execution, mnemonic/protected wallet
persistence and panel controls remain incomplete. The library interfaces and
candidate limits above must not be treated as deployment qualification.
Those gates remain in the [node/network plan](v1-node-network-plan.md).
The retained seven-node legacy network and its keys/data are not inputs to this
runtime.
