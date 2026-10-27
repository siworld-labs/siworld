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
The next D8 experiment has a 10-GiB (10,737,418,240-byte) hard ceiling for the
proof process and all children, with zero swap. This is an experimental ceiling,
not production acceptance. The production memory budget remains undecided
until actual peak measurements are available. Recompute host admission once
that budget is selected: total RAM must also cover the node, operating system,
other admitted processes and reserves. Do not place a worker beyond a node
container's admitted capacity or change retained-network resources to fit it.

Linux D8 acceptance uses the EPYC 7763 Ubuntu 24.04 Microsoft VM profile with
two exposed cores and four vCPUs as the baseline; EPYC 9V45 is a comparison.
Record and validate the actual machine before each three-trial series. These
profiles are measurement references, not a claim of dedicated host cores or
acceptance of an unimplemented suite. See the [qualification procedure](linux-proof-measurement.md#baseline-and-comparison-hardware)
and [production acceptance plan](prover-acceptance.md).

## Native V1 bandwidth target

The selected native V1 route requires at least **25 Mbps uplink** per node.
At 576 positions per 300 seconds, a 524,288-byte proof maximum plus 1,790-byte
public data and three relay copies use 24.24167424 Mbps, leaving 3.0333% for
additional traffic. Settlement, sidecar, envelope, framing and recovery costs
must fit that margin; payload arithmetic alone is not network acceptance.
Preserve the 512-KiB `MAX_LEAF_PROOF_LEN`. If the frozen production proof cannot
fit after evaluating larger blowups, report the proposed 544-position fallback.
The [native design](route-a-v1.md#production-parameter-scan-and-capacity-gate)
specifies the calculation and activation gates. These targets do not alter the
retained seven-node network or establish a production RAM requirement.

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
