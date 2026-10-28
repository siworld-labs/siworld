# Native V1 Network Capacity Budget

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
largest selected-profile proof body in the evidence. The selected profile is
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
