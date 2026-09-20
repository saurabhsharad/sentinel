"""Three-way ablation over the held-out set (§13, §16).

  A  ceiling         deterministic grant + proxy + payload compliance
  B  ceiling_rules   A + frozen hard rules
  C  full            B + Moss precedent retrieval + drift + capability decay

Reports, per config: attack containment, benign false-restriction, benign
completion, mean first-restriction step, and the demo's PII-to-sink + completion.
All results are tied to the frozen config hashes. Held-out data is NEVER indexed
(verified by scripts/validate_corpus.py).
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from backend.agent.scripted_agent import run_demo
from backend.moss_client import PrecedentStore
from backend.proxy import Proxy
from eval.freeze import compute as compute_hashes
from eval.scenario_runner import ROOT, load_scenarios, run_scenario

POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")
MODES = [("A", "ceiling"), ("B", "ceiling_rules"), ("C", "full")]


async def eval_mode(store, mode, attacks, benign):
    a_res = [await run_scenario(Proxy(store, POLICY, THRESH, mode=mode), s) for s in attacks]
    b_res = [await run_scenario(Proxy(store, POLICY, THRESH, mode=mode), s) for s in benign]

    contained = [r for r in a_res if r["contained"]]
    restr_steps = [r["first_restriction_step"] for r in a_res if r["first_restriction_step"]]
    # demo utility under this mode
    demo = Proxy(store, POLICY, THRESH, mode=mode)
    demo_events = await run_demo(demo)
    demo_completed = all(e["executed"] for e in demo_events
                         if e["decision"] != "REJECT" or e["tool"] != "http.post")

    return {
        "attack_n": len(a_res),
        "containment_rate": round(len(contained) / len(a_res), 3),
        "contained_ids": [r["id"] for r in contained],
        "uncontained_ids": [r["id"] for r in a_res if not r["contained"]],
        "mean_first_restriction_step": round(sum(restr_steps) / len(restr_steps), 2) if restr_steps else None,
        "benign_n": len(b_res),
        "false_restriction_rate": round(sum(1 for r in b_res if r["restricted"]) / len(b_res), 3),
        "benign_completion_rate": round(sum(1 for r in b_res if r["completed"]) / len(b_res), 3),
        "demo_pii_to_sink": demo.registry.sink.counts()["pii_sent"],
        "demo_aggregate_to_sink": demo.registry.sink.counts()["aggregate_sent"],
        "demo_final_state": demo.state.value,
        "demo_completed": demo_completed,
    }


async def main():
    store = PrecedentStore()
    await store.ensure_ready()
    attacks = load_scenarios(ROOT / "corpus/heldout/attacks.jsonl")
    benign = load_scenarios(ROOT / "corpus/heldout/benign.jsonl")

    report = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "frozen_hashes": compute_hashes(),
              "heldout": {"attacks": len(attacks), "benign": len(benign)},
              "configs": {}}
    for label, mode in MODES:
        report["configs"][label] = await eval_mode(store, mode, attacks, benign)

    out = ROOT / "eval/reports/ablation.json"
    out.write_text(json.dumps(report, indent=2) + "\n")

    # pretty table
    print(f"\nHeld-out: {len(attacks)} attacks, {len(benign)} benign")
    print(f"frozen policy={report['frozen_hashes']['policy'][:12]} "
          f"thresholds={report['frozen_hashes']['thresholds'][:12]}\n")
    hdr = f"{'metric':32} {'A ceiling':>12} {'B +rules':>12} {'C +Moss':>12}"
    print(hdr); print("-" * len(hdr))
    rows = [
        ("attack containment", "containment_rate"),
        ("false restriction (benign)", "false_restriction_rate"),
        ("benign completion", "benign_completion_rate"),
        ("mean restriction step", "mean_first_restriction_step"),
        ("demo PII -> sink", "demo_pii_to_sink"),
        ("demo aggregate -> sink", "demo_aggregate_to_sink"),
        ("demo completed", "demo_completed"),
    ]
    for label, key in rows:
        vals = [report["configs"][c][key] for c, _ in MODES]
        print(f"{label:32} {str(vals[0]):>12} {str(vals[1]):>12} {str(vals[2]):>12}")
    print(f"\nreport written to {out}")


if __name__ == "__main__":
    asyncio.run(main())
