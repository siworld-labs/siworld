# Native V1 Engineering Runtime

An isolated integration of the fixed D8/W24 native transaction and settlement
relations. The single-node service is accompanied by engineering interfaces for
verified transaction admission, authenticated-stream framing, bounded full-proof
synchronization, verified-work fork selection, atomic reorganizations, private
seed-wallet transfers and public subsidy replay.

The transport has no production hybrid authenticator or plaintext fallback.
The CLI does not start a network listener. Checkpoint bootstrap, proof pruning,
protected wallet persistence and native issuance admission remain separate
implementation gates. Remote CI covers protocol rejection, synchronization,
reorganization, wallet and audit tests, with separately selected native-proof
integration tests. These checks do not qualify a network deployment. No existing
network is modified or activated.

See [the runtime scope and commands](../../docs/v1-native-runtime.md) and
[the remaining network milestones](../../docs/v1-node-network-plan.md).
