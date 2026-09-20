"""Tune the drift restriction threshold on the DEV BENIGN set ONLY (INV-7).

Runs every dev-benign scenario with restrictions disabled (observation mode),
records the drift EMA distribution, and sets restrict_threshold safely above the
benign maximum. Held-out data is never touched here. Writes the value back into
config/thresholds.yaml; freezing/hashing is done separately by eval/freeze.py.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import yaml

from backend.moss_client import PrecedentStore
from backend.proxy import Proxy
from eval.scenario_runner import ROOT, load_scenarios, run_scenario

POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")
MARGIN = 0.10  # safety gap above the benign maximum


async def main():
    store = PrecedentStore()
    await store.ensure_ready()
    dev = load_scenarios(ROOT / "corpus/dev/benign.jsonl")

    per = []
    for scn in dev:
        proxy = Proxy(store, POLICY, THRESH, mode="full")
        proxy.th["drift"]["restrict_threshold"] = 1e9  # observe only, never restrict
        res = await run_scenario(proxy, scn)
        per.append((scn["id"], res["max_drift_ema"], res["restricted"]))

    drifts = sorted(d for _, d, _ in per)
    max_benign = drifts[-1]
    p95 = drifts[int(0.95 * (len(drifts) - 1))]
    fired = sum(1 for _, _, r in per if r)  # must be 0 (restrictions disabled)
    threshold = round(max(0.10, max_benign + MARGIN), 3)

    print(f"dev benign scenarios: {len(dev)}")
    print(f"drift EMA  min={drifts[0]:.4f}  p95={p95:.4f}  max={max_benign:.4f}")
    print(f"chosen restrict_threshold = {threshold}  (max_benign + {MARGIN})")
    print(f"(observation-mode restrictions fired: {fired}, expected 0)")

    with open(THRESH) as f:
        th = yaml.safe_load(f)
    th["drift"]["restrict_threshold"] = threshold
    th["drift"]["_tuned_on"] = "dev/benign.jsonl"
    th["drift"]["_dev_benign_max_drift"] = round(max_benign, 4)
    with open(THRESH, "w") as f:
        yaml.safe_dump(th, f, sort_keys=False)
    print(f"wrote restrict_threshold={threshold} to {THRESH}")


if __name__ == "__main__":
    asyncio.run(main())
