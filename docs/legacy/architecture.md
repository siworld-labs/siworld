# System Architecture

> **Superseded by V1 (Route A).** This page documents the legacy recursive implementation. The retained seven-node N=2 engineering testnet uses this classical proof route; it is not a native V1 testnet or post-quantum acceptance result. See the [current V1 overview](../v1-overview.md).

## Component boundaries

The `core` crate defines public types and canonical serialization. `poseidon2` defines the native tagged sponge and field encoding. `crypto` constructs notes, commitments, nullifiers, ciphertexts and signatures. `state` owns the commitment tree, recent roots, nullifier set, pending rewards and fund accounts.

`circuits` specifies the native slot relation and the proof-system interface. `prover` adapts the Plonky3 AIR and aggregation circuits in the benchmark workspace to that interface. The benchmark circuits are therefore part of the real-proof node's dependency and review surface, despite their separate Cargo workspace.

`consensus` implements construction, validation, proof of work, difficulty and fork choice. `storage` persists accepted full blocks in redb and replays them at startup. `node` supplies peer transport, a mempool, wallet operations and authenticated loopback RPC.

## Payment flow

1. The wallet reserves a durable payment ID and input notes before proving.
2. Output randomness comes from the operating system. The wallet encrypts outputs and builds a leaf proof.
3. The relay checks anti-spam work, the anchor and leaf proof before admitting the transaction.
4. A producer selects transactions and supplies valid padding to reach capacity N.
5. Native header preparation applies the shared transition. Recursive aggregation and nonce search proceed against the fixed candidate.
6. Publication requires matching candidate generations, a valid proof and valid work.
7. A receiver validates the block before updating chain state and scanning wallet notes.

## Candidate lifecycle

One background candidate task works from a state snapshot. Rebuild requests coalesce; generation checks discard stale proof and work results. Reusable padding and non-root proofs are held in bounded in-memory caches. Each new root uses fresh miner witnesses and proving randomness.

Logical cancellation does not interrupt an active proof kernel. Wallet proving, inbound verification, snapshot cloning and storage can still delay service handling. Shutdown closes RPC and header delivery before waiting for outstanding work. These restrictions matter when sizing testnets and interpreting responsiveness measurements.

## Storage and reorganization

The store retains full blocks including proofs. Startup replays accepted blocks; pruning and bounded-history operation are not implemented. The chain index uses cumulative work with a local 100-block reorganization bound. Partitions extending beyond that bound require explicit operator recovery rather than automatic convergence.

## Interfaces

Peer messages use a genesis-specific libp2p protocol over TCP, Noise and Yamux. Transaction dissemination currently floods directly. The local RPC is authenticated newline-delimited JSON over loopback TCP, not HTTP. See [node operations](node-operations.md) and [RPC](rpc.md).
