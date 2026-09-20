"""Phase 2 tests: corpus leakage, frozen config, held-out isolation, and the
core ablation claim (Moss contains exfil that the ceiling+rules let through)."""
import json
from pathlib import Path

import pytest

from backend.proxy import Proxy
from eval.freeze import compute as compute_hashes
from eval.scenario_runner import load_scenarios, run_scenario

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")


def _load(p):
    return [json.loads(l) for l in (ROOT / p).read_text().splitlines() if l.strip()]


def test_inv6_heldout_never_indexed():
    idx_ids = {d["id"] for d in _load("corpus/attack_trajectories.jsonl") + _load("corpus/safe_trajectories.jsonl")}
    held = _load("corpus/heldout/attacks.jsonl") + _load("corpus/heldout/benign.jsonl") + _load("corpus/dev/benign.jsonl")
    for scn in held:
        assert scn["id"] not in idx_ids


def test_inv6_leakage_validator_passes():
    import scripts.validate_corpus as v
    try:
        v.main()  # returns normally on success; sys.exit(1) only on leakage
    except SystemExit as e:
        assert e.code in (0, None), "leakage detected by validator"


def test_inv5_frozen_hashes_match():
    lock = json.loads((ROOT / "config/frozen.lock").read_text())
    current = compute_hashes()
    for k, v in current.items():
        assert lock["hashes"][k] == v, f"{k} changed since freeze; re-run make freeze"


def test_corpus_shape():
    atk = _load("corpus/attack_trajectories.jsonl")
    safe = _load("corpus/safe_trajectories.jsonl")
    fams = {d["metadata"]["family"] for d in atk}
    assert fams == {"data_exfiltration", "destructive_action", "privilege_escalation",
                    "credential_harvesting", "covert_persistence"}
    assert sum(1 for d in safe if d["metadata"].get("hard_negative") == "true") >= 40
    # safe corpus must never egress PII/secret (keystone of egress-scoped retrieval)
    assert all(d["metadata"]["egress"] in ("none", "aggregate", "metadata") for d in safe)


async def test_ablation_moss_contains_exfil(store):
    """The core claim: an exfil-through-approved-channel held-out attack leaks under
    ceiling+rules but is contained by full Sentinel."""
    exfil = next(s for s in load_scenarios(ROOT / "corpus/heldout/attacks.jsonl")
                 if s["family"] == "data_exfiltration")

    b = await run_scenario(Proxy(store, POLICY, THRESH, mode="ceiling_rules"), exfil)
    assert b["pii_sent"] >= 1 and not b["contained"], "ceiling+rules should leak PII"

    c = await run_scenario(Proxy(store, POLICY, THRESH, mode="full"), exfil)
    assert c["pii_sent"] == 0 and c["contained"], "full Sentinel should contain exfil"


async def test_benign_not_restricted(store):
    """A representative benign external-aggregate share must not be restricted (C)."""
    legit = next(s for s in load_scenarios(ROOT / "corpus/heldout/benign.jsonl")
                 if "legit" in s["id"])
    r = await run_scenario(Proxy(store, POLICY, THRESH, mode="full"), legit)
    assert r["completed"] and not r["restricted"]
