# Native V1 Network Capacity Budget

The [monetary revision](v1-economics.md) requires new source-bound proof
measurements and final encoding of one/five reward notes, pool/burn/fund
records and lock fields. The numerical tables below retain the pre-revision
baseline and conditional allowances; they are not revised-network acceptance.
Reconcile the final formats, issuance limits and actual database overhead
before claiming bandwidth margin or SSD lifetime.

Status: reproducible engineering budget for the multi-asset codec. The
transaction proof-length limit is **655,360 bytes (640 KiB)** and the
minimum uplink is **43 Mbps**, selected from the actual-AIR performance scan;
**100 Mbps sustained uplink** remains the deployment recommendation. The
maximum remains **576 positions per 300-second target block**. This document
does not claim measured full-network acceptance or alter the retained network.

## Payload and transport assumptions

Transaction body, settlement body and issuance body limits are independent.
The transaction envelope/sidecar allowance is 657,622 bytes: the 655,360-byte
transaction proof cap plus 2,184 envelope bytes and 78 sidecar bytes. Settlement and issuance
proof caps remain 524,288 bytes; the settlement envelope adds 159 bytes.
Three copies of all 576 transaction positions plus three capped settlement
envelopes use 1,137,944,157 payload bytes per interval, or 30.34517752 Mbps.
Envelope sizes require final encoded fixtures before network qualification.

Selection requires all three four-worker generation trials on the EPYC 7763
reference host to complete within two seconds and the actual-AIR security
report to meet the selected 80-bit quantum target. Round the transaction
proof cap up to a complete 64-KiB unit while retaining at least 10% above the
largest selected-profile proof body in the evidence. The pre-economic-revision profile was
log_blowup 7, 41 queries, query/batch grinding 20, commit grinding 0, binary
folding and final polynomial log length 0. Its three reference-host generation
times were 1.332143, 1.315662 and 1.316440 seconds; proof bodies were
583,552–584,848 bytes. The cap is 12.056% above the largest observed body.
The [measurement record](v1-multi-asset-evaluation.md) contains the pinned
security report and process-tree memory evidence. Sample headroom is not a
mathematical maximum-size proof; the decoder must still enforce the cap and
wallets must handle an oversized proof without broadcasting an invalid body.

The complete conditional budget adds all of the following categories. These
are conservative accounting assumptions to qualify, not frozen wire formats:

| Category | Assumption |
| --- | --- |
| Relay | Three total application copies; the stem/fluff topology must enforce or independently budget fanout above this |
| Application framing | 16 bytes per message |
| Hybrid-channel records and multiplexing | 16-KiB plaintext records, 18-byte AEAD tag/length and 12-byte stream framing per record |
| Network packets | MTU 1,500; IPv6 40 bytes, TCP 32 bytes including options, effective payload 1,428 bytes |
| Link serialization | VLAN Ethernet, FCS, preamble and inter-frame gap add 42 bytes/packet; network plus link overhead is 114 bytes/packet |
| ACK traffic | Equal reciprocal incoming load; one outgoing ACK per two incoming segments, charged at 114 bytes |
| Compact blocks | Three full 32-byte-ID inventories, three compact-block inventories and three requests listing every position; 8 KiB/block for permanent block records |
| Issuance | One additional capped proof plus at most 16 KiB declaration/record bytes per interval, each relayed three times |
| Hybrid handshake | Eight new connections/interval at the 32-KiB aggregate handshake budget, plus framing/packet overhead |
| Keepalive | Sixteen connections, one 64-byte keepalive every 30 seconds |
| Other control | 64 KiB/interval before framing, for discovery/checkpoint-manifest and unclassified bounded control |
| Retransmission | Extra 2% of the entire framed/packetized base |
| Missing-body recovery | Extra 5% of that base, including recovered bodies and their transport costs |

Inventory and request messages include every ID, even when compact propagation
would normally avoid most requests. Missing bodies themselves use the 5%
recovery reserve; do not count unlimited recovery as an inventory-only cost.
The symmetric ACK assumption also bounds the modeled receive load. Different
receive fanout, packet loss, MTU, VPN/PPPoE encapsulation, relay fanout, bursts,
issuance limits or protocol formats require a new budget. No finite fixed
bandwidth guarantees progress under arbitrary loss, partitions or adversarial
traffic. Global/per-peer admission, rate limits and fair scheduling remain
necessary.

Issuance rate/byte limits are not yet consensus rules. The one-proof/16-KiB
entry is a finite planning envelope requiring a separately adopted limit;
unbounded permissionless issuance has no finite worst-case wire or disk budget.
At most one issuance proof is reserved in addition to the 576 ordinary proof
positions, which conservatively overcounts if issuance shares those positions.
If the selected issuance AIR needs a larger proof, or metadata/notes need more
record bytes, rerun this model and the disk model before freezing admission.

## Result and remaining margin

Reproduce with `python3 scripts/v1-network-budget.py`; use
`--transaction-proof-cap-bytes` to make a different body limit explicit and
`--link-mbps 100` for the recommended link. The script reports independent
transaction, settlement and issuance caps and every wire component.
`--legacy-baseline` reproduces the earlier 524,288-byte transaction cap and
30-Mbps link; that historical scenario does not set the current requirement.

After charging all framed payload, ACK, control, retransmission and recovery
costs, reserve at least 15% of the minimum uplink's capacity:

```text
minimum_link_mbps = ceil(wire_mbps / 0.85)
```

This reserves 15% of total capacity; multiplying the load by 1.15 would leave
less than 15% unused. The script uses integer byte/rate arithmetic when
rounding the minimum link and checks that one lower integer-Mbps link fails
the headroom condition.

The full conditional wire budget is **1,368,811,477 bytes per interval**, or
**36.50163939 Mbps**. The smallest integer-Mbps link satisfying the capacity
reserve is **43 Mbps**; a 42-Mbps link does not leave 15% unused.

| Link | Serialization at modeled load | Remaining rate | Remaining fraction |
| --- | ---: | ---: | ---: |
| 43 Mbps minimum | 254.66 seconds | 6.498 Mbps | 15.11% |
| 100 Mbps recommended | 109.50 seconds | 63.498 Mbps | 63.50% |

A 100-Mbps link provides additional concurrent catch-up and burst capacity.
The budget is interval-average serialization, not a propagation-latency bound.
Measure application and packet counters, actual handshakes, loss,
reconstruction traffic and queue growth with the real hybrid listener and
compact-block implementation at both link classes. Report any exceedance;
do not silently lower the 576-position consensus limit or weaken security to
force a fit. Future circuit optimization can reduce proof size and allow a
separately reviewed reduction in the proof cap and minimum link. It must not
change the currently selected profile or budget without regenerated evidence.
Object-storage backup uploads and bulk checkpoint downloads need a separate
rate-limited maintenance window or extra bandwidth; the 64-KiB control
allowance covers manifests, not checkpoint bodies.

## Native protocol framing check

Run `python3 scripts/v1-network-budget.py --native-protocol` to apply the
current native library codec while preserving the original default and legacy
reports. This mode uses the 51-byte application header, the four-byte gossip
envelope-length prefix and 64-byte compact references containing both statement
and proof digests. The compact fixed fields occupy 1,525 bytes, including the
reward commitment/ciphertext and settlement-length field. At 576 positions and
the independent 524,288-byte settlement cap, its payload is
`1,525 + 576 * 64 + 524,288 = 562,677` bytes.

Settlement is already carried in the compact body; this mode charges no
separate settlement message. It retains the conservative three-copy
full-reference inventory allowance and an additional 8 KiB/block record
allowance. Missing-reference requests are split into 36 batches of 16 per
copy, with a two-byte count, 64-byte references and an end marker per batch.
All capped transaction envelopes include the private sidecar and four-byte
gossip prefix. The existing issuance, packet/ACK, control, retransmission and
5% body-recovery allowances remain. Requesting every reference is a metadata
allowance; it does not authorize unbounded body recovery beyond that reserve.

| Native relay schedule | Wire bytes/300 seconds | Wire rate | Minimum link for 15% unused |
| --- | ---: | ---: | ---: |
| Settlement carried once in compact | 1,369,154,385 | 36.51078360 Mbps | 43 Mbps |
| Additional standalone settlement copy | 1,371,043,201 | 36.56115203 Mbps | 44 Mbps |

The first case leaves 15.0912% unused on a 43-Mbps link; 42 Mbps fails the
15% reserve. Reproduce the second case with `--native-protocol
--duplicate-settlement`. It leaves only 14.9741% unused at 43 Mbps and is a
sensitivity case, not a requirement to send a second settlement proof. Full
block synchronization or duplicate relay still needs an explicit schedule and
budget; the compact calculation does not include unlimited full-block copies.

The production hybrid provider remains unavailable. Its 16-KiB record/30-byte
crypto-multiplexing overhead and 32-KiB per-handshake payload allowance are
conditional assumptions, not validated provider wire limits. Eight 103-byte
session hellos are conservatively charged with an extra application frame.
The in-memory 256-KiB handshake reservation is not a transmitted-byte limit.
A larger actual handshake, record overhead or relay fanout can require a new
floor; measure and rerun the budget before activation. This calculation does
not change frozen proof parameters or establish network acceptance.
