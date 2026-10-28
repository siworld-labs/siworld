"""Reproduce a conditional V1 uplink wire budget, not measured throughput.

The defaults describe IPv6/TCP over a 1500-byte MTU VLAN Ethernet link,
three application relay copies, reciprocal incoming load and delayed ACKs.
All reserves and incomplete protocol-format allowances are explicit.
"""

import argparse
import json

INTERVAL_SECONDS = 300
TRANSACTION_PROOF_CAP = 655_360
SETTLEMENT_PROOF_CAP = 524_288
ISSUANCE_PROOF_CAP = 524_288
TRANSACTION_ENVELOPE_BYTES = 2184
SIDECAR_BYTES = 78
SETTLEMENT_ENVELOPE_BYTES = 159
CAPACITY_HEADROOM_PERCENT = 15
RECOMMENDED_LINK_MBPS = 100
MSS = 1428  # 1500 - IPv6(40) - TCP with options(32).
PACKET_OVERHEAD = 114  # IPv6/TCP(72) + VLAN Ethernet, FCS, preamble and IFG(42).


def ceil_div(n, d):
    return (n + d - 1) // d


def wire_message(payload):
    if payload <= 0:
        raise ValueError('positive message size required')
    framed = payload + 16  # Application message type/length budget.
    framed += ceil_div(framed, 16_384) * 30  # AEAD tag/length(18) + mux frame(12).
    packets = ceil_div(framed, MSS)
    # Outgoing data plus uplink ACKs for equal reciprocal incoming traffic.
    return framed + packets * PACKET_OVERHEAD + ceil_div(packets, 2) * PACKET_OVERHEAD


def report(positions=576, link_mbps=None, transaction_proof_cap=TRANSACTION_PROOF_CAP,
           settlement_proof_cap=SETTLEMENT_PROOF_CAP, issuance_proof_cap=ISSUANCE_PROOF_CAP,
           capacity_headroom_percent=CAPACITY_HEADROOM_PERCENT):
    if not 64 <= positions <= 576 or positions % 16:
        raise ValueError('positions must be a multiple of 16 in [64, 576]')
    if min(transaction_proof_cap, settlement_proof_cap, issuance_proof_cap) <= 0:
        raise ValueError('positive proof caps required')
    if not 0 <= capacity_headroom_percent < 100:
        raise ValueError('capacity headroom must be in [0, 100)')
    if link_mbps is not None and link_mbps <= 0:
        raise ValueError('positive link rate required')
    copies = 3
    transaction_and_sidecar = transaction_proof_cap + TRANSACTION_ENVELOPE_BYTES + SIDECAR_BYTES
    settlement_envelope = settlement_proof_cap + SETTLEMENT_ENVELOPE_BYTES
    inventory = positions * 32
    payload = copies * (positions * transaction_and_sidecar + settlement_envelope)
    components = {
        'transaction_and_sidecar_wire': copies * positions * wire_message(transaction_and_sidecar),
        'settlement_wire': copies * wire_message(settlement_envelope),
        'issuance_wire_allowance': copies * wire_message(issuance_proof_cap + 16_384),
        'inventory_wire': copies * wire_message(inventory),
        'compact_block_and_block_record_wire': copies * wire_message(inventory + 8192),
        'all_id_requests_wire': copies * wire_message(inventory + 16),
        'handshake_wire_allowance': 8 * wire_message(32_768),
        'keepalive_wire_allowance': 16 * 10 * wire_message(64),
        'other_control_wire_allowance': wire_message(65_536),
    }
    base = sum(components.values())
    components['retransmission_reserve'] = ceil_div(base * 2, 100)
    components['recovery_reserve'] = ceil_div(base * 5, 100)
    total = sum(components.values())
    # Reserve the requested fraction of link capacity after every modeled wire cost.
    minimum_link = ceil_div(total * 8 * 100,
                            INTERVAL_SECONDS * 1_000_000 * (100 - capacity_headroom_percent))
    if link_mbps is None:
        link_mbps = minimum_link
    capacity = link_mbps * 1_000_000 * INTERVAL_SECONDS // 8
    return {
        'status': 'conditional-planning-budget-not-network-acceptance',
        'positions': positions, 'interval_seconds': INTERVAL_SECONDS,
        'relay_copies': copies,
        'parameters': {
            'transaction_proof_cap_bytes': transaction_proof_cap,
            'settlement_proof_cap_bytes': settlement_proof_cap,
            'issuance_proof_cap_bytes': issuance_proof_cap,
            'transaction_envelope_bytes': TRANSACTION_ENVELOPE_BYTES,
            'sidecar_bytes': SIDECAR_BYTES,
            'settlement_envelope_bytes': SETTLEMENT_ENVELOPE_BYTES,
            'capacity_headroom_percent': capacity_headroom_percent,
            'headroom_formula': 'ceil(wire_mbps / (1 - capacity_headroom_percent / 100))',
        },
        'minimum_link_mbps': minimum_link, 'evaluated_link_mbps': link_mbps,
        'recommended_link_mbps': RECOMMENDED_LINK_MBPS,
        'transaction_settlement_payload_bytes': payload,
        'components_bytes_per_interval': components,
        'wire_bytes_per_interval': total,
        'wire_mbps': total * 8 / INTERVAL_SECONDS / 1_000_000,
        'link_capacity_bytes_per_interval': capacity,
        'remaining_bytes_per_interval': capacity - total,
        'remaining_mbps': (capacity - total) * 8 / INTERVAL_SECONDS / 1_000_000,
        'remaining_percent': (capacity - total) * 100 / capacity,
        'meets_capacity_headroom': (capacity - total) * 100 >= capacity * capacity_headroom_percent,
        'serialization_seconds': total * 8 / (link_mbps * 1_000_000),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positions', type=int, default=576)
    parser.add_argument('--link-mbps', type=int)
    parser.add_argument('--transaction-proof-cap-bytes', type=int, default=TRANSACTION_PROOF_CAP)
    parser.add_argument('--settlement-proof-cap-bytes', type=int, default=SETTLEMENT_PROOF_CAP)
    parser.add_argument('--issuance-proof-cap-bytes', type=int, default=ISSUANCE_PROOF_CAP)
    parser.add_argument('--capacity-headroom-percent', type=int, default=CAPACITY_HEADROOM_PERCENT)
    parser.add_argument('--legacy-baseline', action='store_true',
                        help='reproduce the prior 524288-byte proof caps and 30-Mbps link without extra headroom')
    args = parser.parse_args()
    if args.legacy_baseline:
        print(json.dumps(report(args.positions, 30, 524_288, 524_288, 524_288, 0),
                         indent=2, sort_keys=True))
    else:
        print(json.dumps(report(args.positions, args.link_mbps, args.transaction_proof_cap_bytes,
                                args.settlement_proof_cap_bytes, args.issuance_proof_cap_bytes,
                                args.capacity_headroom_percent), indent=2, sort_keys=True))
