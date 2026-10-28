# Legacy Recursive Implementation

> **Superseded by V1 (Route A).** These pages describe the runnable recursive
> implementation and retained seven-node N=2 classical engineering testnet.
> They are not native V1 operating instructions or post-quantum acceptance.

The legacy network retains its verifier, history, keys and deployment guard.
It uses two-output transactions, recursive proofs, full-proof historical replay
and a local 100-block reorganization bound. Its protocol rules must not be
silently replaced by selected native V1 requirements.

- [Construction](whitepaper.md), [architecture](architecture.md) and [protocol](protocol.md).
- [Cryptography](cryptography.md) and [security limitations](security-model.md).
- [Node operations](node-operations.md), [RPC/recovery](rpc.md) and [worker control](worker-control.md).
- [Benchmark reproduction](benchmarks.md).

See the [native V1 overview](../v1-overview.md), [current decisions](../00-decisions.md)
and [paused V2 research](../v2/README.md) for separate scopes. Native V1 requires
independent genesis, identity, directories and keys; it imports no legacy notes
or proofs.
