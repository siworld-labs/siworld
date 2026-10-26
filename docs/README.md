# Technical Documentation

Start with [the technical overview](whitepaper.md), [architecture](architecture.md) and [protocol](protocol.md). [Cryptography](cryptography.md) covers proof binding; [the security model](security-model.md) defines observer and deployment boundaries.

Operational interfaces are in [node operations](node-operations.md) and [RPC and recovery](rpc.md). Validation is in [testing](testing.md), measurement in [benchmarks](benchmarks.md), and implementation invariants in [development](development.md).

Experimental [proof composition](proof-composition.md), local [worker control](worker-control.md) and [memory measurement budgets](memory-budgets.md) describe the implemented boundaries and remaining acceptance work.

The planned [D8/W24 recursive suite](d8-w24-recursion.md) separates
[security screening](proof-security-review.md) from [hardware acceptance](prover-acceptance.md).
[D4 control analysis](d4-security-controls.md) explains why legacy timings do
not qualify the selected suite.

[Conditional D8 parameter screening](d8-parameter-screen.md) lists estimated
shapes and unimplemented grinding requirements. [Linux measurement](linux-proof-measurement.md)
defines the process-tree resource-control method.

The selected [native V1 transaction route](route-a-v1.md) defines the D8 native
AIR, codec and parameter-scan gates. The [fee-settlement research design](fee-settlement.md)
is a candidate mechanism and does not close the fee, root-lifetime,
encryption-binding or checkpoint-trust gates. Recursive aggregation is deferred
to V2 and its experiments are paused.
