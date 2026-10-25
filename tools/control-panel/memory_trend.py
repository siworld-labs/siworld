"""Private historical-memory budgets and integer growth trends.

The panel exposes this only through its authenticated local snapshot.  Values
are aggregate resource measurements; transaction, peer, address and topology
identifiers are intentionally outside this model.
"""

from collections import defaultdict
import math


MAX_SAMPLES = 120

# Hard engineering acceptance ceilings. Allocation bounds and measured
# acceptance ceilings are distinct; a declared number does not bound a growing
# data structure. Missing measurements never pass the acceptance gate.
MEMORY_BUDGETS = {
    "managed_network_payload_bytes": 128 << 20,
    "managed_codec_receive_bytes": 256 << 20,
    "managed_codec_send_bytes": 256 << 20,
    "mempool_bytes": 64 << 20,
    "block_store_page_cache_bytes": 64 << 20,
    "payment_journal_page_cache_bytes": 8 << 20,
    "canonical_metadata_bytes": 256 << 20,
    "nullifier_commitment_bytes": 512 << 20,
    "fork_side_body_bytes": 128 << 20,
    "proof_working_set_bytes": 1536 << 20,
    "allocator_retained_bytes": 512 << 20,
}

# These categories have measurement ceilings but no independent allocation
# bound in the node. They remain engineering gaps even when a sample passes.
UNBOUNDED_CATEGORIES = (
    "canonical_metadata_bytes", "nullifier_commitment_bytes", "fork_side_body_bytes",
    "proof_working_set_bytes", "allocator_retained_bytes",
)
TOTAL_MEMORY_CEILING = 3 << 30

MEASURED_FIELDS = tuple(MEMORY_BUDGETS) + (
    "memory_charged_bytes",
    "memory_working_set_bytes",
)


def _series(samples, field):
    values = []
    for sample in samples:
        at, value = sample.get("at"), sample.get(field)
        if (isinstance(at, (int, float)) and not isinstance(at, bool)
                and math.isfinite(at) and at >= 0
                and type(value) is int and value >= 0):
            values.append((int(at), value))
    return values[-MAX_SAMPLES:]


def _trend(values):
    if len(values) < 2:
        return {"samples": len(values), "status": "insufficient"}
    first_at, first_value = values[0]
    last_at, last_value = values[-1]
    duration = last_at - first_at
    if duration <= 0 or any(b[0] <= a[0] for a, b in zip(values, values[1:])):
        return {"samples": len(values), "status": "non_monotonic_clock"}
    delta = last_value - first_value
    return {
        "samples": len(values),
        "status": "measured",
        "first_bytes": first_value,
        "last_bytes": last_value,
        "delta_bytes": delta,
        "duration_seconds": duration,
        # Integer arithmetic keeps this local report deterministic and avoids
        # turning a monitoring value into a consensus-like floating point rule.
        "slope_bytes_per_hour": delta * 3600 // duration,
    }


def _budgeted_trend(values, budget):
    trend = _trend(values)
    if not values:
        return {**trend, "budget_bytes": budget, "budget_status": "unmeasured"}
    peak = max(value for _, value in values)
    trend["peak_bytes"] = peak
    trend["budget_bytes"] = budget
    if budget is None:
        trend["budget_status"] = "unknown"
    else:
        trend["budget_status"] = "exceeded" if peak > budget else "within"
        trend["over_budget_samples"] = sum(value > budget for _, value in values)
    return trend


def summarize(history):
    """Return bounded per-node and host memory trends for private display."""
    node_samples = defaultdict(list)
    vm_samples = []
    for record in history[-MAX_SAMPLES:]:
        at = record.get("at")
        if (not isinstance(at, (int, float)) or isinstance(at, bool)
                or not math.isfinite(at) or at < 0):
            continue
        at = int(at)
        vm = record.get("vm_available_bytes")
        if type(vm) is int and vm >= 0:
            vm_samples.append({"at": at, "vm_available_bytes": vm})
        for node in record.get("nodes", []):
            node_id = node.get("id")
            if isinstance(node_id, str) and node_id:
                node_samples[node_id].append({"at": at, **{
                    field: node.get(field) for field in MEASURED_FIELDS
                }, "status": node.get("status"), "epoch": node.get("epoch"),
                    "memory_limit_bytes": node.get("memory_limit_bytes")})

    nodes = {}
    for node_id, samples in sorted(node_samples.items()):
        epoch = samples[-1].get("epoch")
        # A new process is not a continuation of the old allocator/state trend.
        start = len(samples) - 1
        while start > 0 and samples[start - 1].get("epoch") == epoch:
            start -= 1
        samples = samples[start:]
        limit = samples[-1].get("memory_limit_bytes")
        total_ceiling = min(limit, TOTAL_MEMORY_CEILING) if type(limit) is int and limit > 0 else TOTAL_MEMORY_CEILING
        trends = {
            field: _budgeted_trend(_series(samples, field),
                MEMORY_BUDGETS.get(field, total_ceiling))
            for field in MEASURED_FIELDS
        }
        for field in MEMORY_BUDGETS:
            trends[field]["bound_kind"] = (
                "measurement_ceiling" if field in UNBOUNDED_CATEGORIES else "managed_allocation"
            )
        for field, trend in trends.items():
            value = samples[-1].get(field)
            if type(value) is not int or value < 0 or samples[-1].get("status") not in (None, "ok"):
                if trend["budget_status"] != "exceeded":
                    trend["budget_status"] = "unmeasured"
        missing = [field for field in (*MEMORY_BUDGETS, "memory_charged_bytes")
                   if trends[field]["budget_status"] == "unmeasured"]
        if type(limit) is not int or limit <= 0:
            missing.append("memory_limit_bytes")
        violations = [field for field, trend in trends.items()
                      if trend.get("budget_status") == "exceeded"]
        nodes[node_id] = {
            "trends": trends, "hard_budget_violations": violations,
            "unmeasured_categories": missing,
            "acceptance_status": "exceeded" if violations else (
                "unmeasured" if missing else "sample_within_ceilings"),
        }
    return {
        "version": 1,
        "scope": "local_private_memory_trends",
        "sample_limit": MAX_SAMPLES,
        "budgets": MEMORY_BUDGETS,
        "unbounded_categories": list(UNBOUNDED_CATEGORIES),
        "nodes": nodes,
        "vm_available_bytes": _trend(_series(vm_samples, "vm_available_bytes")),
    }


if __name__ == "__main__":
    raise SystemExit("import summarize() from the authenticated control panel")
