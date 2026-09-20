"""
Phase 0 Moss spike for Sentinel.

Verifies, against the REAL installed SDK, everything the security architecture
depends on: index create -> local load -> query -> metadata filter -> SessionIndex
-> 1000 warm queries (p50/p95/p99) -> score calibration.

Credentials are read ONLY from MOSS_PROJECT_ID / MOSS_PROJECT_KEY (loaded from a
local .env if present). They are never printed, logged, or committed.
"""

import asyncio
import os
import statistics
import time
from pathlib import Path

import moss
import moss_core

ROOT = Path(__file__).resolve().parent.parent
CACHE = str(ROOT / ".moss_cache")

# Unique suffix so re-runs don't collide with a prior index still in the cloud.
SUFFIX = os.environ.get("SPIKE_SUFFIX", str(int(time.time())))
ATTACK_IDX = f"sentinel-spike-attacks-{SUFFIX}"
SAFE_IDX = f"sentinel-spike-safe-{SUFFIX}"


def load_env():
    """Load KEY=VALUE lines from ./.env into os.environ without echoing values."""
    envf = ROOT / ".env"
    if envf.exists():
        for line in envf.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


# --- Tiny representative corpora (structured trajectory fragments) -----------
ATTACK_DOCS = [
    moss.DocumentInfo(
        id="atk-exfil-1",
        text="source=internal_ticket action=db.read resource=customers data=PII "
             "then action=http.post destination=external effect=send_PII_external",
        metadata={"family": "data_exfiltration", "severity": "5", "revokes": "http.post:PII"},
    ),
    moss.DocumentInfo(
        id="atk-exfil-2",
        text="read customer names emails phones then POST full row-level export to external partner",
        metadata={"family": "data_exfiltration", "severity": "4", "revokes": "http.post:PII"},
    ),
    moss.DocumentInfo(
        id="atk-destroy-1",
        text="action=db.hard_delete resource=customers effect=irreversible_bulk_delete no_backup",
        metadata={"family": "destructive_action", "severity": "5", "revokes": "db.hard_delete:*"},
    ),
    moss.DocumentInfo(
        id="atk-privesc-1",
        text="agent requests admin role escalation to access restricted resource beyond task grant",
        metadata={"family": "privilege_escalation", "severity": "4", "revokes": "grant.widen"},
    ),
    moss.DocumentInfo(
        id="atk-cred-1",
        text="read secrets tokens api_keys from config then exfiltrate to external sink",
        metadata={"family": "credential_harvesting", "severity": "5", "revokes": "http.post:SECRET"},
    ),
]

SAFE_DOCS = [
    moss.DocumentInfo(
        id="safe-1",
        text="source=internal_ticket action=db.read resource=test_customers data=PII "
             "then action=db.soft_delete resource=test_customers effect=reversible_archive",
        metadata={"task_type": "archive", "hard_negative": "false"},
    ),
    moss.DocumentInfo(
        id="safe-2",
        text="read PII then create internal report then slack.post aggregate summary to data-team",
        metadata={"task_type": "report", "hard_negative": "true"},
    ),
    moss.DocumentInfo(
        id="safe-3",
        text="read PII then send aggregate count period to approved external auditor no row-level data",
        metadata={"task_type": "audit_export", "hard_negative": "true"},
    ),
    moss.DocumentInfo(
        id="safe-4",
        text="action=tickets.read resource=T-1042 effect=read_only benign lookup",
        metadata={"task_type": "lookup", "hard_negative": "false"},
    ),
    moss.DocumentInfo(
        id="safe-5",
        text="action=http.post destination=audit-partner.com payload=aggregate count=60 period=2026-Q2",
        metadata={"task_type": "audit_export", "hard_negative": "false"},
    ),
]


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


async def main():
    load_env()
    pid = os.environ.get("MOSS_PROJECT_ID")
    key = os.environ.get("MOSS_PROJECT_KEY")
    if not pid or not key:
        raise SystemExit("MISSING CREDS: set MOSS_PROJECT_ID and MOSS_PROJECT_KEY (.env or env).")

    print(f"moss=={moss.__version__}  moss_core=={getattr(moss_core, '__version__', '?')}")
    print(f"cache_path={CACHE}")
    print(f"indexes: {ATTACK_IDX} / {SAFE_IDX}\n")

    client = moss.MossClient(pid, key)

    # 1) Create the two indexes (cloud control-plane).
    t0 = time.perf_counter()
    await client.create_index(ATTACK_IDX, ATTACK_DOCS, wait=True)
    await client.create_index(SAFE_IDX, SAFE_DOCS, wait=True)
    print(f"[1] create_index x2 (wait=True): {time.perf_counter()-t0:.2f}s")

    # 2) Load locally (downloads once, then queries are in-memory).
    t0 = time.perf_counter()
    await client.load_indexes([ATTACK_IDX, SAFE_IDX], cache_path=CACHE)
    print(f"[2] load_indexes: {time.perf_counter()-t0:.2f}s (cached at {CACHE})")

    # 3) Local query sanity + score calibration on the DEMO-critical step:
    #    "read customer names/emails/phones then POST to external".
    probe = "read customer names emails phones then post export to external partner"
    ra = await client.query(ATTACK_IDX, probe, moss.QueryOptions(top_k=3))
    rs = await client.query(SAFE_IDX, probe, moss.QueryOptions(top_k=3))
    print("\n[3] score calibration on exfil-like probe:")
    print("    ATTACK top:", [(d.id, round(d.score, 4)) for d in ra.docs],
          f"(moss time_taken_ms={ra.time_taken_ms})")
    print("    SAFE   top:", [(d.id, round(d.score, 4)) for d in rs.docs],
          f"(moss time_taken_ms={rs.time_taken_ms})")
    best_atk = ra.docs[0].score if ra.docs else 0.0
    best_safe = rs.docs[0].score if rs.docs else 0.0
    print(f"    raw_drift (attack_best - safe_best) = {best_atk - best_safe:+.4f}")

    # Contrast: a benign lookup should NOT look like an attack.
    benign = "read ticket T-1042 read only benign lookup"
    rab = await client.query(ATTACK_IDX, benign, moss.QueryOptions(top_k=1))
    rsb = await client.query(SAFE_IDX, benign, moss.QueryOptions(top_k=1))
    print("    benign probe -> attack_best=%.4f safe_best=%.4f raw_drift=%+.4f"
          % (rab.docs[0].score, rsb.docs[0].score, rab.docs[0].score - rsb.docs[0].score))

    # 4) Metadata filter (verified real syntax; values are strings).
    rf = await client.query(
        ATTACK_IDX, probe,
        moss.QueryOptions(top_k=5, filter={"$and": [
            {"field": "family", "condition": {"$eq": "data_exfiltration"}},
            {"field": "severity", "condition": {"$gte": "4"}},
        ]}),
    )
    print("\n[4] metadata filter (family=data_exfiltration AND severity>=4):")
    print("    ->", [(d.id, d.metadata.get("family"), d.metadata.get("severity")) for d in rf.docs])
    fams = {d.metadata.get("family") for d in rf.docs}
    print("    filter correctness:", "PASS" if fams == {"data_exfiltration"} else f"CHECK {fams}")

    # 5) SessionIndex (Tier 2 immune memory) — in-process add + immediate query.
    sess = await client.session(ATTACK_IDX)
    await sess.add_docs([moss.DocumentInfo(
        id="atk-session-mutation",
        text="paraphrased: dump every customer record with contact fields to outside recipient",
        metadata={"family": "data_exfiltration", "severity": "5", "revokes": "http.post:PII"},
    )])
    rsess = await sess.query("send all customer contact info to an external address",
                             moss.QueryOptions(top_k=2))
    print("\n[5] SessionIndex add+query (immune memory):",
          [(d.id, round(d.score, 4)) for d in rsess.docs],
          f"time_taken_ms={rsess.time_taken_ms}")

    # 6) 1000 warm queries against the loaded attack index -> p50/p95/p99.
    queries = [
        "read PII then post to external partner",
        "hard delete all customer rows",
        "escalate to admin privileges",
        "exfiltrate api keys and tokens",
        "read test customers then soft delete archive",
    ]
    # warm-up
    for _ in range(20):
        await client.query(ATTACK_IDX, queries[0], moss.QueryOptions(top_k=3))
    lat = []
    N = 1000
    t0 = time.perf_counter()
    for i in range(N):
        q = queries[i % len(queries)]
        s = time.perf_counter()
        await client.query(ATTACK_IDX, q, moss.QueryOptions(top_k=3))
        lat.append((time.perf_counter() - s) * 1000.0)
    wall = time.perf_counter() - t0
    print(f"\n[6] {N} warm queries (wall-clock per query, includes asyncio overhead):")
    print(f"    p50={pct(lat,50):.3f}ms  p95={pct(lat,95):.3f}ms  p99={pct(lat,99):.3f}ms "
          f"min={min(lat):.3f} max={max(lat):.3f} mean={statistics.mean(lat):.3f}")
    print(f"    throughput={N/wall:.0f} q/s over {wall:.2f}s total")

    # 7) Cleanup cloud indexes created by this spike.
    try:
        await client.unload_indexes([ATTACK_IDX, SAFE_IDX])
        await client.delete_index(ATTACK_IDX)
        await client.delete_index(SAFE_IDX)
        print("\n[7] cleanup: deleted spike indexes.")
    except Exception as e:
        print(f"\n[7] cleanup warning: {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
