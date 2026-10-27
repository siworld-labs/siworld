# Node Operations

## Build

The controlled release packager below supports Linux x86_64. Other platform
adapters require separate packaging and qualification.

```sh
python3 scripts/build-prover-release.py --output .local/prover-release
python3 scripts/check-node-features.py
export PATH="$PWD/.local/prover-release/bin:$PATH"
```

The release package contains a generic-baseline launcher and a separate
x86-64-v3 worker. Start the packaged `bin/siworld-node` entry point; do not start
the internal worker directly. A Cargo build of the worker alone does not provide
the portable startup check. Default node binaries enable Plonky3 and reject mock networks. Explicit `development` builds support forgeable mock proofs. All-features builds are for verification, not deployment. Secret-file checks are implemented on Unix; unsupported adapters fail closed.

## Miner hardware requirements

The x86_64 release baseline is **x86-64-v3**. AVX2 is a minimum requirement;
AVX2 alone does not describe the entire v3 feature set. The CPU must also expose
the remaining x86-64-v3 instructions, including FMA, BMI1/BMI2, F16C, LZCNT and
MOVBE, with operating-system support for AVX register state. Virtual machines
must expose the required features to the guest. The generic-baseline launcher checks the CPU and OS-state support before
executing the internal worker and rejects an unsupported CPU with an explicit
error. It has no environment override or scalar fallback. Directly starting
the internal v3 worker is unsupported because it bypasses this admission check. The release build uses the fixed v3 target rather than
`target-cpu=native`, and release verification checks the actual proof binary
for AVX2 instructions.

AArch64 has a separate build target and requires its own hardware/resource
qualification. Historical M1 measurements do not qualify every AArch64 machine.
Native V1 hosted proof measurements used a 5-GiB zero-swap cgroup; that
boundary does not set minimum miner RAM. The [deployment profiles](v1-deployment.md)
start qualification at 16 GiB for a full validator, 32 GiB for a miner and
500 GB usable SSD minimum and 1 TB recommended, with 100-Mbps uplink
recommended over the 30-Mbps floor.
These are candidate profiles, not accepted minimums. Account separately for
prover, node, verifier, OS, caches, maintenance and reserves, then qualify the
aggregate under sustained maximum load. macOS and Windows require separate
packaging and resource/recovery qualification. Do not change retained-network
container or VM limits to accommodate new workers.

Linux D8 acceptance uses the EPYC 7763 Ubuntu 24.04 Microsoft VM profile with
two exposed cores and four vCPUs as the baseline; EPYC 9V45 is a comparison.
Record and validate the actual machine before each three-trial series. These
profiles are measurement references, not a claim of dedicated host cores or
full-node integration acceptance. See the [qualification procedure](linux-proof-measurement.md#baseline-and-comparison-hardware)
and [production acceptance plan](prover-acceptance.md).

## Native V1 bandwidth target

The selected native V1 route requires at least **30 Mbps uplink** per node;
**100 Mbps** is the deployment recommendation. Capacity stays 576 positions
per 300-second target block. At the proposed three-output codec and proof cap,
three transaction/sidecar copies plus settlement use 24.30537976 Mbps.
The [complete conditional wire model](v1-network-budget.md) includes bounded
issuance, control, authenticated-channel framing, IPv6/TCP/link overhead,
reciprocal ACKs, retransmission and recovery allowances: approximately
29.252 Mbps. Its narrow 30-Mbps margin must be qualified using the actual
listener; it is not a throughput measurement. Bulk backup/checkpoint traffic
requires separate scheduling or bandwidth. Re-extract final codec sizes after
the multi-asset scan. Preserve the 512-KiB `MAX_LEAF_PROOF_LEN` and report any
capacity failure rather than silently changing consensus limits. These targets
do not alter the retained network or establish production RAM requirements.

## Retained implementation commands

The commands below describe the existing node and its legacy proof route.
They do not activate the independent native V1 testnet. V1 deployment requires
the [native acceptance gates](prover-acceptance.md), separate genesis and
qualified platform packaging.

## Wallet initialization

```sh
siworld-node init --datadir "$HOME/.siworld-test"
siworld-node address --datadir "$HOME/.siworld-test"
```

Initialization asks for a password through hidden terminal input. It creates an encrypted key and distinct role credentials, refuses key overwrite, and uses directory mode 0700 and secret-file mode 0600. Keep authenticated backups independently. Runtime files must remain outside the repository.

## Real-proof genesis

Collect public owner digests and run in an external runtime directory. Replace OWNER_HEX with the intended 64-hex public owner:

```sh
siworld-node genesis --network siworld-test-1 \
  --alloc OWNER_HEX:100 --proofs plonky3 \
  --container-size 4 --block-time 60 --miners 1 > genesis.json
```

Genesis calibrates work on the coordinator's machine. Distribute the same file and compare genesis IDs. Create it shortly before mining because its timestamp anchors difficulty. Small capacity reduces preparation cost; it is not a production throughput measurement.

## Run

```sh
siworld-node run --datadir "$HOME/.siworld-test" \
  --genesis genesis.json --mine
```

```sh
siworld-node run --datadir "$HOME/.siworld-peer" \
  --genesis genesis.json --peer /dns4/seed.example.org/tcp/30333
```

Peer TCP defaults to 30333; authenticated loopback RPC defaults to 127.0.0.1:30334. A configured peer node waits for synchronization before mining and pauses when disconnected. Transactions flood directly, without a source-anonymity layer.

## Wallet access

```sh
siworld-cli --auth-file "$HOME/.siworld-test/rpc-read.token" info
siworld-cli --auth-file "$HOME/.siworld-test/rpc-read.token" walletstatus
```

Spending requires startup with `--enable-wallet-spend`, the separate spend credential and password unlock. Balance scans require an unlocked wallet. `walletunlock` accepts 1 through 3,600 seconds, default 60.

Bundled sends additionally require an independent encrypted order ledger and witness initialized by `siworld-node orders-init`. Retain its current checkpoint separately. Generate a payment ID offline with `siworld-cli new-payment-id`, retain the complete order, and retry identical parameters with the same ID. Consult binary usage for ledger, backup, checkpoint and reconciliation commands, and read [RPC and recovery](rpc.md) before submitting payments.

## Maintenance

Stop the node before offline key migration, reconciliation or credential rotation. Startup replays full stored blocks including proofs. Pruning is not implemented. Monitor disk use and test restart/recovery on disposable networks. Proving memory, history growth and the local reorganization bound limit the operating envelope.

## Reopened multi-asset capacity

Measurements of the two-output implementation remain baseline evidence only.
The proposed three-output codec uses 2,027 public body bytes and 2,115
permanent bytes per position. At capped proof sizes and three relay copies,
including one capped settlement per block, the payload is approximately
24.3054 Mbps at 576 positions/300 seconds, before framing, recovery and public
issuance traffic. Updated year-1/3/5 capacity and low-use tables are in
[V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md); reproduce them
with `python3 scripts/v1-storage-budget.py`. The final encoded artifact and
actual-AIR scan must replace these estimates before acceptance.
