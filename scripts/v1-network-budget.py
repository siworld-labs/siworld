"""Reproduce a conditional V1 uplink wire budget, not measured throughput.

The defaults describe IPv6/TCP over a 1500-byte MTU VLAN Ethernet link,
three application relay copies, reciprocal incoming load and delayed ACKs.
All reserves and incomplete protocol-format allowances are explicit.
"""

import argparse
import json

INTERVAL_SECONDS = 300
PROOF_CAP = 524_288
TRANSACTION_AND_SIDECAR = 526_550
SETTLEMENT_ENVELOPE = PROOF_CAP + 159
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


def report(positions=576, link_mbps=30):
    if not 64 <= positions <= 576 or positions % 16:
        raise ValueError('positions must be a multiple of 16 in [64, 576]')
    if link_mbps <= 0:
        raise ValueError('positive link rate required')
    copies = 3
    inventory = positions * 32
    payload = copies * (positions * TRANSACTION_AND_SIDECAR + SETTLEMENT_ENVELOPE)
    components = {
        'transaction_and_sidecar_wire': copies * positions * wire_message(TRANSACTION_AND_SIDECAR),
        'settlement_wire': copies * wire_message(SETTLEMENT_ENVELOPE),
        'issuance_wire_allowance': copies * wire_message(PROOF_CAP + 16_384),
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
    capacity = link_mbps * 1_000_000 * INTERVAL_SECONDS // 8
    return {
        'status': 'conditional-planning-budget-not-network-acceptance',
        'positions': positions, 'interval_seconds': INTERVAL_SECONDS,
        'relay_copies': copies, 'minimum_link_mbps': link_mbps,
        'transaction_settlement_payload_bytes': payload,
        'components_bytes_per_interval': components,
        'wire_bytes_per_interval': total,
        'wire_mbps': total * 8 / INTERVAL_SECONDS / 1_000_000,
        'link_capacity_bytes_per_interval': capacity,
        'remaining_bytes_per_interval': capacity - total,
        'remaining_mbps': (capacity - total) * 8 / INTERVAL_SECONDS / 1_000_000,
        'remaining_percent': (capacity - total) * 100 / capacity,
        'serialization_seconds': total * 8 / (link_mbps * 1_000_000),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positions', type=int, default=576)
    parser.add_argument('--link-mbps', type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(report(args.positions, args.link_mbps), indent=2, sort_keys=True))
