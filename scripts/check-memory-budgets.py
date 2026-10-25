#!/usr/bin/env python3
"""Validate that every panel memory field has an explicit budget state."""

import ast
import operator
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "control-panel" / "memory_trend.py"


def literal(node):
    if isinstance(node, ast.Constant) and (node.value is None or type(node.value) is int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift):
        return operator.lshift(literal(node.left), literal(node.right))
    raise ValueError(f"budget must be an integer or None: {ast.dump(node)}")


def main() -> int:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    budgets = None
    measured = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", None)
            if name == "MEMORY_BUDGETS":
                if not isinstance(node.value, ast.Dict):
                    raise SystemExit("MEMORY_BUDGETS must be a dict")
                budgets = {
                    ast.literal_eval(key): literal(value)
                    for key, value in zip(node.value.keys, node.value.values)
                }
            if name == "MEASURED_FIELDS":
                # This is derived from MEMORY_BUDGETS plus two process gauges.
                measured = True
    if not isinstance(budgets, dict) or not budgets or not measured:
        raise SystemExit("memory trend source must declare MEMORY_BUDGETS and MEASURED_FIELDS")
    for field, value in budgets.items():
        if type(value) is not int or value <= 0 or value > (3 << 30):
            raise SystemExit(f"invalid hard budget for {field}: {value!r}")
    required = {
        "managed_network_payload_bytes", "managed_codec_receive_bytes", "managed_codec_send_bytes",
        "mempool_bytes", "block_store_page_cache_bytes", "payment_journal_page_cache_bytes",
        "canonical_metadata_bytes", "nullifier_commitment_bytes", "fork_side_body_bytes",
        "proof_working_set_bytes", "allocator_retained_bytes",
    }
    if set(budgets) != required:
        raise SystemExit("memory categories must not be removed or left without a hard ceiling")
    source = SOURCE.read_text(encoding="utf-8")
    if "UNBOUNDED_CATEGORIES" not in source or '"unmeasured"' not in source:
        raise SystemExit("open and bounded memory states must be explicit")
    if len(sys.argv) > 1:
        if len(sys.argv) != 2:
            raise SystemExit("usage: check-memory-budgets.py [measurement.json]")
        spec = importlib.util.spec_from_file_location("memory_trend", SOURCE)
        model = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(model)
        history = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(history, list) or not history or len(history) > model.MAX_SAMPLES:
            raise SystemExit("measurement must contain 1..120 resource snapshots")
        previous_at = -1
        previous_ids = None
        for record in history:
            at = record.get("at")
            if type(at) not in (int, float) or not model.math.isfinite(at) or at <= previous_at:
                raise SystemExit("memory samples must have increasing finite observation times")
            previous_at = at
            rows = record.get("nodes")
            if not isinstance(rows, list) or not rows:
                raise SystemExit("memory samples must contain nodes")
            ids = [row.get("id") for row in rows]
            if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
                raise SystemExit("node identities must be unique in each memory sample")
            if previous_ids is not None and set(ids) != previous_ids:
                raise SystemExit("memory samples must cover the same node set")
            previous_ids = set(ids)
            for row in rows:
                fields = (*budgets, "memory_charged_bytes")
                if row.get("status") not in (None, "ok") or any(
                    type(row.get(field)) is not int or row[field] < 0 for field in fields
                ):
                    raise SystemExit("memory acceptance failed: missing or invalid category measurement")
                node_limit = row.get("memory_limit_bytes")
                if type(node_limit) is not int or node_limit <= 0:
                    raise SystemExit("memory acceptance failed: invalid process memory limit")
                if any(row[field] > limit for field, limit in budgets.items()) or row["memory_charged_bytes"] > min(node_limit, model.TOTAL_MEMORY_CEILING):
                    raise SystemExit("memory acceptance failed: hard ceiling exceeded")
        nodes = model.summarize(history)["nodes"]
        if not nodes or any(node["acceptance_status"] != "sample_within_ceilings"
                            or node["trends"]["memory_charged_bytes"]["budget_status"] != "within"
                            for node in nodes.values()):
            raise SystemExit("memory acceptance failed: missing measurement or hard ceiling exceeded")
    print(f"validated {len(budgets)} memory category budgets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
