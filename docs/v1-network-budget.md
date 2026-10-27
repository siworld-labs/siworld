# Native V1 Network Capacity Budget

Status: reproducible engineering budget for the proposed multi-asset codec.
The minimum uplink is **30 Mbps**; **100 Mbps sustained uplink** is recommended.
The maximum remains **576 positions per 300-second target block**. This document
does not claim measured full-network acceptance or alter the retained network.

## Payload and transport assumptions

At the 512-KiB proof cap, each proposed transaction envelope and private sidecar
uses 526,550 bytes. Three copies of all 576 positions plus three capped
524,447-byte settlement envelopes use 911,451,741 bytes/interval, or
24.30537976 Mbps. The settlement prefix is the old 159-byte baseline and must
be re-extracted after the SI-asset reward binding changes. The transaction
prefix likewise requires final encoded fixtures.

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
`--link-mbps 100` for the recommended link. The full conditional wire model
uses approximately **29.252 Mbps**, or **1.097 GB per 300 seconds**.

| Link | Serialization at modeled load | Remaining rate | Remaining fraction |
| --- | ---: | ---: | ---: |
| 30 Mbps minimum | 292.52 seconds | 0.748 Mbps | 2.49% |
| 100 Mbps recommended | 87.75 seconds | 70.748 Mbps | 70.75% |

The model fits the 30-Mbps floor only under its stated limits, with a narrow
additional margin after the explicit retransmission/recovery reserves. A
100-Mbps link provides substantially more concurrent catch-up and burst
capacity. This is interval-average serialization, not a propagation-latency
bound or proof that a saturated 30-Mbps node can meet the 100-Mbps recovery
target. Measure application and packet counters, actual handshakes, loss,
reconstruction traffic and queue growth with the real hybrid listener and
compact-block implementation at both link classes. Report any exceedance;
do not silently lower the 576-position consensus limit, weaken security or
raise proof lengths to force a fit. Object-storage backup uploads and bulk
checkpoint downloads need a separate rate-limited maintenance window or extra
bandwidth; the 64-KiB control allowance covers manifests, not checkpoint bodies.
