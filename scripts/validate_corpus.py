"""Corpus leakage / near-duplicate validator (INV-6).

Guarantees the held-out evaluation data never leaks into the indexed corpus:
  1) no held-out scenario ID appears among indexed IDs,
  2) no held-out ATTACK trajectory is an exact or near-duplicate (token Jaccard
     >= NEAR_DUP) of any indexed precedent.
Held-out benign is allowed to resemble indexed SAFE precedents (same class), so we
only enforce near-dup separation for attacks vs the indexed corpus.

Exits non-zero and prints the offenders if any check fails.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from backend.fragments import build_fragment

ROOT = Path(__file__).resolve().parent.parent
NEAR_DUP = 0.85

# Map executable scenario payload_kind -> (ctx, payload) for a comparable fragment.
KIND = {
    "none": ("none", "none"), "read_pii": ("PII", "none"), "read_agg": ("aggregate", "none"),
    "pii_rows": ("PII", "PII"), "aggregate": ("aggregate", "aggregate"),
    "secret": ("secret", "secret"),
}


def load(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def scenario_text(scn) -> str:
    specs = []
    for s in scn["steps"]:
        ctx, payload = KIND.get(s["payload_kind"], ("none", "none"))
        specs.append({"tool": s["tool"], "resource": s["resource"],
                      "src": s.get("src", "user"), "ctx": ctx, "payload": payload})
    return build_fragment(specs)


def toks(t):
    return set(t.split())


def jaccard(a, b):
    A, B = toks(a), toks(b)
    return len(A & B) / len(A | B) if (A | B) else 0.0


def main():
    idx = load(ROOT / "corpus/attack_trajectories.jsonl") + load(ROOT / "corpus/safe_trajectories.jsonl")
    idx_ids = {d["id"] for d in idx}
    idx_texts = [(d["id"], d["text"]) for d in idx]

    held_atk = load(ROOT / "corpus/heldout/attacks.jsonl")
    held_ben = load(ROOT / "corpus/heldout/benign.jsonl")
    dev = load(ROOT / "corpus/dev/benign.jsonl")

    problems = []

    # 1) ID disjointness (all held-out + dev)
    for scn in held_atk + held_ben + dev:
        if scn["id"] in idx_ids:
            problems.append(f"ID LEAK: {scn['id']} is indexed")

    # 2) near-duplicate for held-out ATTACKS
    worst = 0.0
    worst_pair = None
    for scn in held_atk:
        t = scenario_text(scn)
        for iid, itext in idx_texts:
            j = jaccard(t, itext)
            if j > worst:
                worst, worst_pair = j, (scn["id"], iid)
            if t == itext:
                problems.append(f"EXACT LEAK: {scn['id']} == {iid}")
            elif j >= NEAR_DUP:
                problems.append(f"NEAR-DUP: {scn['id']} ~ {iid} (jaccard={j:.3f})")

    print(f"indexed={len(idx)} heldout_attacks={len(held_atk)} "
          f"heldout_benign={len(held_ben)} dev_benign={len(dev)}")
    print(f"max attack↔index jaccard = {worst:.3f} at {worst_pair} (threshold {NEAR_DUP})")

    # sanity: held-out benign must not collide with dev benign (disjoint splits)
    hb_ids, dv_ids = {s["id"] for s in held_ben}, {s["id"] for s in dev}
    if hb_ids & dv_ids:
        problems.append(f"SPLIT LEAK: held/dev benign share ids {hb_ids & dv_ids}")

    if problems:
        print("\nFAILED — leakage detected:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print("OK — no leakage; held-out is separable from the indexed corpus.")


if __name__ == "__main__":
    main()
