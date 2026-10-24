# Node Operations

## Build

```sh
cargo build --release --locked -p siworld-node
python3 scripts/check-node-features.py
```

Default node binaries enable Plonky3 and reject mock networks. Explicit `development` builds support forgeable mock proofs. All-features builds are for verification, not deployment. Secret-file checks are implemented on Unix; unsupported adapters fail closed.

## Wallet initialization

```sh
target/release/siworld-node init --datadir "$HOME/.siworld-test"
target/release/siworld-node address --datadir "$HOME/.siworld-test"
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
