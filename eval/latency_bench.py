"""Latency benchmark for in-loop Moss retrieval (§7, §16).

Measures per-query wall-clock (includes the asyncio.to_thread hop; Moss's own
time_taken_ms rounds to 0 for sub-ms native queries, so we report wall-clock and
label it honestly) and the retrieval overhead per task. Uses the real loaded
indexes with the egress-scoped filter, exactly as the proxy queries.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from backend.moss_client import PrecedentStore
from eval.scenario_runner import ROOT

QUERIES = [
    "src=internal_ticket action=db.read resource=customers ctx=PII payload=none sink=internal  ||  "
    "src=internal_ticket action=http.post resource=external:audit-partner.com ctx=PII payload=PII sink=external",
    "src=user action=db.read resource=test_customers ctx=PII payload=none sink=internal  ||  "
    "src=user action=db.soft_delete resource=test_customers ctx=none payload=none sink=internal",
    "src=user action=tickets.read resource=T-1 ctx=metadata payload=none sink=internal",
]
EGRESS = ["PII", "none", "none"]


def pct(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


async def main(n=1000):
    store = PrecedentStore()
    await store.ensure_ready()
    # warm-up
    for _ in range(20):
        await store.retrieve(QUERIES[0], egress="PII")

    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        q, eg = QUERIES[i % len(QUERIES)], EGRESS[i % len(EGRESS)]
        s = time.perf_counter()
        await store.retrieve(q, egress=eg)   # queries BOTH indexes (attack+safe)
        lat.append((time.perf_counter() - s) * 1000.0)
    wall = time.perf_counter() - t0

    # A retrieve() = 2 index queries. A 7-step task does one retrieve per step.
    per_query = [x / 2 for x in lat]
    report = {
        "n_retrievals": n, "note": "each retrieve() = 2 in-process index queries "
        "(attack+safe), egress-filtered; wall-clock includes asyncio hop",
        "retrieve_ms": {"p50": round(pct(lat, 50), 3), "p95": round(pct(lat, 95), 3),
                        "p99": round(pct(lat, 99), 3), "mean": round(sum(lat) / len(lat), 3)},
        "single_query_ms": {"p50": round(pct(per_query, 50), 3),
                            "p95": round(pct(per_query, 95), 3),
                            "p99": round(pct(per_query, 99), 3)},
        "throughput_retrieve_per_s": round(n / wall, 1),
        "overhead_per_7step_task_ms": round(7 * pct(lat, 50), 2),
    }
    (ROOT / "eval/reports/latency.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
