# Native V1 Single-Node Engineering Runtime

Status: local M1 integration. This runtime is separate from the retained legacy
engineering network. It does not activate a public network or replace an
existing database. Independent security review remains pending.

## Scope

`crates/native-node` composes the frozen native transaction and fixed-capacity
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
reward ciphertext, parent and nonce. The ordered settlement-list digest
excludes proof bodies.

The producer and replay validator call the same state transition. Every
transaction proof and the independent settlement proof must verify before
accepted state changes. Output commitments and the SI reward note are appended
to the depth-40 commitment tree. Accepted snapshot identities expire after
4096 canonical entries; an absent or removed identity is invalid even when
another snapshot has the same root. Linear append/replay is implemented here;
fork choice and the required 24-block reorganization limit remain network-stage
work, not a claim established by a constant or snapshot-window test.

The fixed 576-row settlement relation reconstructs unused zero-fee rows from
the network, block height, position count and row index with an explicit
engineering domain. These rows are internal relation inputs, not extra chain
transactions or public real/dummy classification flags. Native multi-asset hash
domains are used throughout.

## Local persistence and reward recovery

A new engineering directory contains its explicit network configuration,
`chain.redb` and private reward recovery receipts. Initialization refuses an
existing directory. There is no reset or migration operation. Replay reconstructs
accepted state by verifying every stored block and checking its recorded state
fingerprint. Each append commits the canonical block, accepted height and
fingerprint in one durable database transaction before exposing the new state.
Missing rows, changed metadata, wrong-network data and failed proofs fail closed.
Unclean databases requiring redb repair are preserved and refused pending
explicit recovery review; automatic crash-repair tooling is not an M1 claim.

The local producer uses operating-system entropy and actual ML-KEM/ChaCha
output encryption. It authenticates and reconstructs output commitments before
proving. Reward recovery material is saved privately and synced before the
accepted block is committed. A receipt contains the spending material and
single-payment encapsulation opening needed to recover that reward; it must
never be published. This engineering receipt mechanism is not a wallet backup,
seed recovery or arbitrary ciphertext-scanning implementation.

## Engineering commands

On a qualified Linux x86_64 host:

```sh
python3 scripts/build-native-runtime.py --output .local/native-runtime-release
mkdir -p .local/native-engineering
.local/native-runtime-release/bin/siworld-native-node init .local/native-engineering/network-a 0
.local/native-runtime-release/bin/siworld-native-node mine .local/native-engineering/network-a 64
.local/native-runtime-release/bin/siworld-native-node check .local/native-engineering/network-a
.local/native-runtime-release/bin/siworld-native-node status .local/native-engineering/network-a
```

The controlled Linux build uses x86-64-v3 and places the optimized worker behind
an independently compiled baseline CPU-admission launcher. Unsupported CPUs are
rejected; there is no scalar fallback. Direct source builds on other platforms
are development diagnostics and do not establish deployment qualification.

Work bits are an explicit disposable engineering parameter, limited to 0–24.
The example uses zero to test proof and state integration without waiting for
mining difficulty. This BLAKE3 nonce check is not the production PoW/difficulty
implementation. The current subsidy and fee helper functions are reused for
engineering accounting only; public activation and any epoch recalibration
require their own protocol decision and integration tests.

Prover preparation happens at process startup and remains resident for the
operation. `mine` produces one block and exits. Persistent service scheduling,
real-wallet admission and background empty-slot queues belong to later stages.
`status` and `check` fully replay the local database in M1. `check` also verifies
local reward recovery receipts. No private openings, per-slot fees, network
addresses or real/dummy classifications are emitted in operation summaries.

## Validation and remaining gates

```sh
cargo fmt --manifest-path crates/native-node/Cargo.toml --check
cargo test --locked --manifest-path crates/native-node/Cargo.toml --lib
cargo clippy --locked --manifest-path crates/native-node/Cargo.toml --all-targets -- -D warnings
```

The explicit proof-compatibility and full-block tests are separately selected
release tests. They are correctness checks, not target-hardware performance or
sustained-load acceptance records.

M1 does not implement issuance admission: the amount, destination and
consumption rules for the permissionless issuance fee and issuance resource
budget remain open. Unsupported operations are absent from the wire codec.
It also does not implement P2P transport, mempool isolation, compact blocks,
reorganizations, pruning, checkpoints, three-day retention, hybrid identity
handshakes, Dandelion++, fund payout execution, wallet durability or panel
controls. Those gates remain in the [node/network plan](v1-node-network-plan.md).
The retained seven-node legacy network and its keys/data are not inputs to this
runtime.
