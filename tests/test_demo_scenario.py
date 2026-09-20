"""End-to-end demo scenario tests (§28 mandatory).

Proves the demo is NOT statically blocked (attack reaches the sink under
ceiling+rules), and that full Sentinel narrows the capability so zero PII reaches
the sink while the legitimate task still completes.
"""
from pathlib import Path

from backend.agent.scripted_agent import run_demo
from backend.proxy import Proxy

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")


async def test_not_statically_blocked(store):
    """Ceiling + hard rules alone let the PII export reach the auditor sink.
    If this fails, the demo doesn't prove trajectory detection matters."""
    proxy = Proxy(store, POLICY, THRESH, mode="ceiling_rules")
    await run_demo(proxy)
    counts = proxy.registry.sink.counts()
    assert counts["pii_sent"] >= 1, "attack should NOT be statically blocked"


async def test_full_sentinel_contains_exfil(store):
    """Full Sentinel: restriction fires, no PII leaves, task still completes."""
    proxy = Proxy(store, POLICY, THRESH, mode="full")
    events = await run_demo(proxy)

    # Zero PII at the external sink; the aggregate did go out.
    counts = proxy.registry.sink.counts()
    assert counts["pii_sent"] == 0
    assert counts["aggregate_sent"] == 1

    # A restriction on http.post fired, driven by a data_exfiltration precedent.
    restricts = [e for e in events if "restriction" in e]
    assert restricts, "expected at least one restriction"
    r = restricts[0]["restriction"]
    assert r["capability"] == "http.post"
    assert "PII" in r["removed_data_classes"]
    assert r["family"] == "data_exfiltration"
    assert r["precedent_id"]  # causal evidence recorded

    # The PII POST was rejected deterministically...
    rejects = [e for e in events if e["decision"] == "REJECT"]
    assert any(e["tool"] == "http.post" for e in rejects)

    # ...and the legitimate work still finished (archive + slack executed).
    executed = {(e["tool"]) for e in events if e["executed"]}
    assert "db.soft_delete" in executed
    assert "slack.post" in executed
    assert proxy.state.value == "RESTRICTED"


async def test_reruns_are_clean(store):
    """Three consecutive runs give identical containment (Phase 4 determinism)."""
    for _ in range(3):
        proxy = Proxy(store, POLICY, THRESH, mode="full")
        await run_demo(proxy)
        assert proxy.registry.sink.counts()["pii_sent"] == 0
