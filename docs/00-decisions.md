# Current Protocol Decisions

Status: selected V1 design direction. The native transaction route is not
activated and its production relation, parameter freeze and node admission
budgets remain subject to the gates in [the specification](route-a-v1.md).

## Network and proof architecture

Preserve the existing seven-node N=2 network, verifier, history and keys.
Native V1 uses a separate resettable engineering network with independent
genesis, directories, keys and network identity. No existing notes or proofs
are imported. V1 uses per-transaction native STARK proofs; recursion and
historical proof compression are V2 work. N=32 is outside the current scope.

Use KoalaBear D8, standard Poseidon2 W24 and twelve-element digests. Require
classical conjectured security of at least 128 bits and quantum-halved Johnson
Fiat–Shamir terms, including query and enforced grinding terms, of at least
80 bits. Challenge-domain and selected BHT collision terms must also meet
80 bits. The approximately 81.9-bit diagnostic challenge ledger meets the
selected screen; all future parameter changes must retain at least 80 bits.
The [collision ledger](bht-security-accounting.md) distinguishes raw classical
reports from quantum model conversions and application hashes.

## Capacity and resource boundaries

The block target is 300 seconds with 64 through 576 positions in groups of 16.
Minimum node uplink is 25 Mbps. Preserve `MAX_LEAF_PROOF_LEN = 524288`
(512 KiB); do not derive a larger maximum from bandwidth or observed samples.
Each position has 1,742 bytes of public transaction body and a 48-byte fee
commitment, totaling 1,790 bytes, before sidecar/envelope traffic.

At 576 positions and three relay copies the maximum-size transaction payload
requires 24.24167424 Mbps, leaving 3.0333% uplink margin. Full-network acceptance
must additionally account for settlement, sidecars, framing and recovery.
If the frozen production proof exceeds the cap, first evaluate larger blowup.
If no eligible profile fits, report a proposed 544-position capacity and revised
budgets; this fallback does not increase the proof cap or authorize activation.

## Confidential fees and retention

Use confidential fee commitments with native fixed-capacity settlement.
Nodes validate fee-opening sidecars against the transaction and commitment
before admission; no additional sidecar signature or encryption layer is
selected. Planned hybrid X25519 + ML-KEM transport handles connection secrecy.
Transaction and settlement proofs and private sidecars remain online for four
weeks after final confirmation, then are deleted. Public fee commitments remain
permanent. See [fee settlement](fee-settlement.md) for unresolved production gates.

## Release gates

Freeze the production AIR, deterministic codec maximum, dependency revision,
trusted key and full security report before selecting production parameters.
Choose the smallest eligible proof with four-worker generation at most two
seconds. Measure generation and verification memory independently and bound
malformed-input work before adopting mempool/DoS constants. A hosted cgroup
measurement is resource evidence, not proof of complete relation coverage,
cryptographic approval, dedicated target hardware performance or node activation.
