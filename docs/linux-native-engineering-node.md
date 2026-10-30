# Linux Native Engineering Node Operations

Status: operator procedure for the opt-in pinned native V1 service. Independent
two-host acceptance and qualification of the Linux network package are pending.
This guide records no completed deployment or network acceptance. The service
is an isolated engineering network, not a public testnet or a production
release. The retained network uses a different protocol and must remain
separate.

The [source repository](https://github.com/siworld-labs/siworld) supplies the
matching specifications and helper scripts. Select the exact source revision
recorded in the release handoff before using them.

The [native runtime](v1-native-runtime.md), [identity format](v1-native-identity.md),
[hybrid handshake](v1-hybrid-handshake.md) and
[wallet storage](v1-wallet-storage.md) describe the implemented interfaces.
[Deployment qualification](v1-deployment.md) defines the wider resource and
recovery gates; a successful listener test does not satisfy them.

## Package selection and verification

Build from the exact reviewed source revision on an isolated Linux x86_64
host using the pinned Rust toolchain, Python 3.11 or newer, and the required
native compiler dependencies. The host and operating system must support
x86-64-v3, including AVX2. Use the controlled packager from the repository root:

```sh
AWS_LC_SYS_USE_SYSTEM=0 python3 scripts/build-native-runtime.py \
  --native-p2p --output .local/native-peer-package
```

The output directory must not exist. Compiler/profile overrides are rejected;
the worker uses the repository's fixed `x86-64-v3` flags. Omitting
`--native-p2p` builds the default runtime without `run-network`, `init-peer` or
`peer-pin`. Do not substitute that binary for a networking package.

The package contains:

| Relative path | Purpose |
| --- | --- |
| `bin/siworld-native-node` | Independently compiled baseline CPU-admission launcher |
| `libexec/siworld-native-node` | Inspected x86-64-v3 worker |
| `build-receipt.json` | Worker/launcher hashes, build selection, ISA inspection and packaged command smoke evidence |

The resident Linux CI job also prepares a candidate bundle after its required
steps pass. Its artifact name is
`native-engineering-linux-x86_64-SOURCE_SHA`, containing
`native-engineering-linux-x86_64.tar.gz`. The extracted top-level directory is
`native-engineering-linux-x86_64`. In addition to the three packager files, the
bundle contains:

| Relative path | Purpose |
| --- | --- |
| `scripts/native-network-status.py` | Read-only exported-status and Linux process-identity check |
| `scripts/native-network-stop.py` | Controlled shutdown helper; consult the matching script's help before use |
| `docs/` | Public source-tree documentation, including this guide |
| `LICENSE`, `NOTICE` | License and required attribution |
| `metadata/native-runtime-Cargo.lock` | Locked native runtime dependencies |
| `metadata/native-proof-profiles.json` | Source-bound native proof profiles |
| `metadata/rust-toolchain.toml` | Pinned build toolchain |
| `release-manifest.json` | Source, build/runtime dependency metadata and per-file hashes |
| `SHA256SUMS` | Checksums of bundled files, including the release manifest |

The manifest must state `status: "engineering-candidate"`, the expected
`source_commit`, and the same explicit Cargo feature selection as the build
receipt. Its `corresponding_source` points to that exact repository revision.
It records the compiler, build glibc, required shared libraries and referenced
glibc symbol versions. Compare those with the target host; do not infer a
static or universally portable executable. `independent_host_acceptance` and
`systemd_qualification` remain `"pending"` in this candidate. A published CI
artifact is not a final accepted deployment package or qualified service unit.

Before extraction, authenticate the outer archive checksum and source revision
through the release handoff. Extract into a fresh staging directory. From the
extracted bundle directory, verify its complete file inventory and the guarded
entry point:

```sh
sha256sum --check SHA256SUMS
./bin/siworld-native-node --check-cpu
./bin/siworld-native-node --help
```

Compare the manifest's `files_sha256` with the installed files and compare the
manifest checksum with `SHA256SUMS`. These files establish consistency only;
an attacker could replace an archive and its checksums together without an
independently authenticated handoff. Remaining examples use the local-build
prefix `.local/native-peer-package`; substitute the extracted bundle directory
when using the candidate artifact. Bundled documentation retains source-tree
links, including links to implementation files absent from the bundle. Follow
`corresponding_source` at the recorded revision for those targets rather than
assuming every relative documentation link resolves within the archive.

Keep this directory structure intact and launch only the `bin` entry point.
Running the worker directly bypasses the package's baseline admission guard.
The build receipt records `cargo_default_features: true` and
`cargo_features: ["native-p2p"]` inside `worker_build_receipt` for this package.
`packaged_help_smoke` must identify `genesis-id`, `init-peer`, `peer-pin` and
`run-network`, with the matching worker and launcher hashes. The packager
executes the staged guarded help command with a 30-second limit before
publishing the directory and rejects changed worker/launcher hashes.

For a received package, compare its source revision, complete artifact checksum
and receipt checksum with the independently authenticated release handoff.
Then compare the installed files with the receipt:

```sh
sha256sum .local/native-peer-package/bin/siworld-native-node \
  .local/native-peer-package/libexec/siworld-native-node \
  .local/native-peer-package/build-receipt.json
.local/native-peer-package/bin/siworld-native-node --check-cpu
.local/native-peer-package/bin/siworld-native-node --help
```

The launcher hash must equal `bootstrap_sha256`; the worker hash must equal
both `worker_build_receipt.binary_sha256` and
`isa_inspection.binary_sha256`. For the networking package, compare those
hashes with `packaged_help_smoke` as well. A self-consistent receipt alone does
not authenticate a package: its checksum must come from the trusted handoff.
Retain the exact worker and receipt used for a run. Do not replace them under
a live service. CPU qualification does not establish binary compatibility
with every Linux distribution or measured resource sufficiency.

## Shared genesis and private directories

Choose a new isolated parent directory. Use a dedicated unprivileged service
account, owner-only directories and private configuration files. Do not place
runtime data, wallet material or identity keys in source control. The following
relative names are examples; they do not select deployment locations:

```sh
umask 077
mkdir -p .local/native-engineering
.local/native-peer-package/bin/siworld-native-node init-service \
  .local/native-engineering/node-a
.local/native-peer-package/bin/siworld-native-node genesis-id \
  .local/native-engineering/node-a
```

`init-service` creates a fresh ASERT engineering configuration with a one-time
work-rate calibration. Its target interval is 300 seconds; actual block
intervals are stochastic. It supplies 24 publicly reproducible synthetic fund
wallets. These test keys and shares provide no custody security and must never
be treated as a real fund allocation.

Record the 64-character lowercase genesis identifier on this trusted host and
convey it through an independently authenticated channel. Transfer only the
public `engineering-network.bin` into an owner-only staging directory on the
other host, with the file mode set to `0600`. Do not copy the live database,
identity seeds, reward receipts, wallets or service records. On that host:

```sh
.local/native-peer-package/bin/siworld-native-node genesis-id \
  .local/native-engineering/staged-genesis
.local/native-peer-package/bin/siworld-native-node init-peer \
  .local/native-engineering/node-b .local/native-engineering/staged-genesis \
  "$SIWORLD_VERIFIED_GENESIS_ID"
```

Set `SIWORLD_VERIFIED_GENESIS_ID` to the independently verified identifier,
not merely one supplied beside an untrusted configuration. The receiving
`genesis-id` output must match it. `init-peer` requires an absent destination
and checks the complete encoded configuration, including ASERT and proof
bindings. Matching only the network ID is insufficient. Running `init-service`
independently on both hosts creates different networks. The cheap `init`
fixture is not a substitute for this ASERT provisioning flow.

## Persistent identities and peer configuration

Each node creates its own Ed25519 and ML-DSA-65 identity once:

```sh
.local/native-peer-package/bin/siworld-native-node identity-init \
  .local/native-engineering/node-a
.local/native-peer-package/bin/siworld-native-node identity-public \
  .local/native-engineering/node-a > .local/native-engineering/node-a-identity.json
```

Repeat with the other host's own node directory. Export only the public JSON.
Exchange descriptors and verify their fingerprints through an independent
trusted channel. On each host, import the other host's descriptor:

```sh
.local/native-peer-package/bin/siworld-native-node peer-pin \
  .local/native-engineering/node-a .local/native-engineering/node-b-identity.json \
  "$SIWORLD_VERIFIED_PEER_FINGERPRINT"
```

The fingerprint is 64 lowercase hexadecimal characters. The descriptor must
match its signatures and the local network/genesis/verifier binding.
`peer-pin` persists an immutable pin; placing a descriptor in a peer
configuration does not establish trust.

Create a mode-`0600` JSON peer configuration on each host. The exact schema is:

```json
{
  "version": 1,
  "engineering": true,
  "listen": "192.0.2.10:40101",
  "mining": false,
  "peers": [
    {
      "endpoint": "192.0.2.20:40102",
      "fingerprint": "REPLACE_WITH_VERIFIED_FINGERPRINT",
      "descriptor": "REPLACE_WITH_COMPLETE_SIGNED_DESCRIPTOR"
    }
  ]
}
```

The addresses above are reserved documentation examples and must be replaced.
Neither port is a default. Select explicit reachable numeric IP/port pairs;
DNS names and multiaddresses are unsupported. On the other host, use its own
listening address and the first host's peer entry. Copy each peer's exact
`fingerprint` and `descriptor` values from the verified public JSON; the
complete descriptor is 10,918 lowercase hexadecimal characters.

Configure both directions and permit the chosen peer TCP traffic in the
operator's existing firewall policy. Only the node with the smaller identity
fingerprint initiates each connection and reconnect. Its configured peer
listener must be reachable; there is no reverse-dial or NAT traversal fallback.
Both nodes can synchronize over the resulting connection. At most 64 peers
may be configured; at most 16 socket workers are retained. An empty peer list
permits listening but supplies no authenticated neighbor.

The transport requires TLS 1.3 with X25519MLKEM768, followed by exporter-bound
Ed25519 and ML-DSA-65 authentication and native Hello admission. No Noise or
classical-only fallback is available. Every reconnect authenticates afresh.
Temporary failures use bounded backoff; authentication or protocol failures
can disable the configured peer for the current process. Inspect such a
failure before a controlled restart. Configuration changes require a restart;
there is no hot peer-replacement or remote administration command.

## Optional mining wallet

For a validator, leave `mining` explicitly `false`. For an engineering miner,
first create and back up its seed wallet through a trusted interactive local
terminal, then select the reward destination and mode:

```sh
.local/native-peer-package/bin/siworld-native-node wallet-create \
  .local/native-engineering/miner-wallet .local/native-engineering/node-a
.local/native-peer-package/bin/siworld-native-node wallet-configure-miner \
  .local/native-engineering/miner-wallet .local/native-engineering/node-a holder
```

`voyager` and `holder` are explicit choices; no mode is supplied by default.
Wallet commands require interactive stdin, stderr and a controlling terminal.
They never accept a mnemonic or password through command arguments or
environment variables. Complete the mnemonic backup challenge and separately
record the public network/account recovery descriptor. Keep secrets off shared
sessions and recordings. `wallet-configure-miner` changes future templates;
a template already under construction retains its original settings.

Set `mining` to `true` in that node's peer configuration only after this step.
Reward ownership and authenticated receipts are synchronized before the
atomic block/head commit. Reopening verifies indexed local reward receipts;
imported blocks do not become locally owned rewards. Missing or altered
indexed receipts are errors, not instructions to discard evidence. Preserve
the complete private node directory as well as the encrypted wallet directory.

The custody CLI does not provide a balance-rescan command, payment submission
command, public wallet RPC or web wallet. Reward recovery, payment and
recipient mnemonic restoration are exercised through the native library
integration gates. A mnemonic recovers keys and recoverable confirmed notes;
it does not recover unconfirmed payment intentions or retained payment-opening
disclosures. See the [wallet recovery procedure](v1-wallet-storage.md#recovery-procedure)
for these boundaries. Use disposable engineering wallets only.

## Foreground service, status and shutdown

Start a validator in the foreground with its explicit peer configuration:

```sh
.local/native-peer-package/bin/siworld-native-node run-network \
  .local/native-engineering/node-a .local/native-engineering/node-a-peers.json
```

For a configured miner, use the same command with the required proving worker
selection:

```sh
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
.local/native-peer-package/bin/siworld-native-node run-network \
  .local/native-engineering/node-a .local/native-engineering/node-a-peers.json
```

There is no daemonization or supervisor installation in this procedure. The
exclusive node-directory lease prevents a second writer. Do not start another
service to repair a slow or disconnected run. An initialization or replay error
must be investigated using its retained files.

From another local terminal, inspect the private atomic export:

```sh
.local/native-peer-package/bin/siworld-native-node service-status \
  .local/native-engineering/node-a
```

Check the expected run ID, process, worker hash, genesis configuration hash and
peer configuration hash against the launch record. The process is the worker
in `libexec`, since the launcher replaces itself with that executable. Inspect
height, tip, state fingerprint and cumulative work along with aggregate
configured/pending/connected/closing/disabled counts and authentication/closure
counters. A counter increasing or a socket remaining open is not proof of
chain agreement. A flat height may reflect no producing peer or stochastic
work; compare both peers and inspect status freshness before diagnosing a
stall. Do not publish endpoints, peer fingerprints, private wallet records or
individual fees in monitoring.

The matching source tree provides a one-shot read-only status checker. Supply
the expected PID and run ID from the recorded launch and the worker path,
not the launcher path:

```sh
python3 scripts/native-network-status.py \
  --network-dir .local/native-engineering/node-a \
  --binary .local/native-peer-package/libexec/siworld-native-node \
  --config .local/native-engineering/node-a/engineering-network.bin \
  --peer-config .local/native-engineering/node-a-peers.json \
  --expected-pid "$SIWORLD_EXPECTED_PID" \
  --expected-run-id "$SIWORLD_EXPECTED_RUN_ID"
```

This helper checks current-schema exports, run receipts, artifact hashes and
Linux process identity without opening the chain database. Exit status zero
means its exported-networking readiness checks passed at that instant. Other
states include starting, degraded, stale, stopping, stopped, error and
unavailable. It does not establish independent replay, reward health,
continuous observation completion or strongest-chain synchronization.

Use the blocking helper with the same frozen package. It requests a stop only
for the expected run, waits for the owned process lifetime to end and a
matching successful final receipt, then independently replays the idle store:

```sh
python3 scripts/native-network-stop.py \
  --network-dir .local/native-engineering/node-a \
  --launcher .local/native-peer-package/bin/siworld-native-node \
  --binary .local/native-peer-package/libexec/siworld-native-node \
  --config .local/native-engineering/node-a/engineering-network.bin \
  --peer-config .local/native-engineering/node-a-peers.json \
  --expected-pid "$SIWORLD_EXPECTED_PID" \
  --expected-run-id "$SIWORLD_EXPECTED_RUN_ID" \
  --timeout-seconds 600
```

Require exit status zero and `state: stopped_verified` before continuing with
the separate public accounting audit:

```sh
.local/native-peer-package/bin/siworld-native-node audit \
  .local/native-engineering/node-a
```

The stop helper never sends a signal, restarts, retries or repairs a service.
A deadline or changed run requires operator review; any command already
started is left untouched. Its successful final/replay checks do not supply
the service manager's exit code. Preserve and inspect that separately when a
supervisor is used. The default 600-second bound is an engineering starting
value, not a measured stop guarantee for arbitrary chain length; the supported
maximum is 3,600 seconds.

The bare `stop DIRECTORY EXPECTED_RUN_ID` command returns after writing the
request. It does not wait for shutdown and must not serve alone as a systemd
`ExecStop`. No qualified systemd unit is supplied in this candidate bundle.

The candidate must advertise `stop DIRECTORY [EXPECTED_RUN_ID]` and
`check DIRECTORY [--json]` in its matching help. Until the source, packaged
command checks and regression tests confirm those interfaces, this automated
shutdown/replay procedure remains pending. Use the recorded expected run ID
for controlled shutdown; a malformed or changed run ID must be rejected
without writing a stop request. The legacy form without an expected ID remains
interactive compatibility, not the automation example above.

Structured `check --json` output has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | Integer version `1` |
| `height` | Independently replayed accepted height |
| `tip` | Lowercase 64-character accepted block hash |
| `state_fingerprint` | Lowercase 64-character replayed state fingerprint |
| `proof_replay_checked` | Boolean `true` after complete proof replay |
| `local_reward_receipts_checked` | Number of independently verified local reward receipts |
| `validation_scope` | `indexed-local-rewards`, or strict legacy fallback `strict-legacy-rewards` |

The structured output contains neither cumulative work nor private receipt
content. Use the independently validated final status/replay evidence for the
additional cumulative-work comparison. An imported validator block does not
increase its local-reward count. A successful JSON parse alone is insufficient:
require a successful command exit, expected scope and exact final state.
The network stop helper requires `indexed-local-rewards`; losing the ownership
index must not become a successful legacy fallback. The resident network also
refuses unindexed legacy stores. The generic offline CLI alone retains the
strict legacy fallback for older isolated histories.

Shutdown cancels owned network/proof/work jobs, waits for
them and verifies the final accepted state and local reward evidence. A
synchronous proof already in progress may finish before exit. `check` requires
the service lease and cannot be used concurrently as a live health probe.
`audit` independently replays public supply and fund accounting. `status` may
return an old stopped export; it is not a substitute for `check`.

Preserve failures, receipts and run records. Do not erase a lock file, delete
reward evidence, overwrite a database or initialize over a failed directory.
Restart only after an operator has checked the exact artifacts and durable
state. Restarting creates a new run identity and does not extend an earlier
continuous observation window.

## Qualification and current limits

An independent two-host acceptance record must identify the exact source,
packages, host resources and genesis. A cross-platform functional test uses
the same source, rules and verifier profile, with each host's own recorded
platform-specific worker hash; a Linux x86-64 executable cannot run on an
ARM macOS peer. Such a pair does not establish Linux qualification on both
hosts. Qualify the distributable Linux x86-64-v3 package separately.

The two-host gate must observe authenticated connection,
accepted full-proof synchronization, peer interruption and fresh reconnection,
restart using the same durable node state, and matching final height, tip,
state fingerprint and cumulative work after both nodes stop and replay.
Stop production first, allow the validator to catch up to the immutable final
tip, then stop and check the validator. Verify local reward ownership and
wallet restoration separately. Two processes or containers on one host do
not meet the independent-host requirement. Package smoke evidence and library
test definitions alone do not establish a completed run.

The resident miner currently assembles 64-position engineering blocks. The
protocol's 576-position capacity does not establish resident maximum-load
acceptance.

The resident driver currently synchronizes full proof-carrying blocks through
a dedicated raw TCP/libp2p connection upgrade. It does not instantiate libp2p
Swarm, discover peers, provide public routing, or wire the existing transaction
and compact-block relay libraries into resident gossip. There is no public
issuance RPC, public network activation or remote repair interface.

Authenticated checkpoint startup and native three-day proof/sidecar pruning
remain unfinished. Do not delete old proofs manually: the current store
reopens through full proof replay. The planned retention window must not be
reported as implemented. Dandelion++ remains a separate pre-public-testnet
gate. No achieved test result in this guide establishes maximum-load,
long-duration, retention, external-audit or production acceptance.
