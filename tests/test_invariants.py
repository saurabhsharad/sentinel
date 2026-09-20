"""Security-invariant tests (INV-1, INV-2, INV-3, hashes)."""
import ast
import random
from pathlib import Path

from backend.compliance import classify_payload
from backend.grant import build_grant, file_hash
from backend.models import Capability, Restriction, apply_restriction

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")


def _rand_cap(rng):
    dcs = {"none", "metadata", "aggregate", "PII", "secret"}
    keep = set(rng.sample(sorted(dcs), rng.randint(1, len(dcs))))
    scope = set(rng.sample(["a", "b", "c", "d"], rng.randint(1, 4)))
    return Capability(name="t", scope=scope, allowed_data_classes=set(keep),
                      payload_profile=set(keep), record_limit=rng.randint(1, 1000),
                      ttl_seconds=100, origin="policy")


def test_inv1_capability_monotonicity():
    """For arbitrary restrictions, authority only ever shrinks (INV-1)."""
    rng = random.Random(0)
    for _ in range(2000):
        cap = _rand_cap(rng)
        r = Restriction(
            capability="t",
            remove_data_classes=set(rng.sample(sorted(cap.allowed_data_classes | {"PII"}),
                                                rng.randint(0, len(cap.allowed_data_classes)))),
            remove_scope=set(rng.sample(sorted(cap.scope | {"z"}),
                                        rng.randint(0, len(cap.scope)))),
            new_record_limit=rng.choice([None, rng.randint(1, 2000)]),
        )
        after = apply_restriction(cap, r)
        assert after.allowed_data_classes <= cap.allowed_data_classes
        assert after.payload_profile <= cap.payload_profile
        assert after.scope <= cap.scope
        assert after.record_limit <= cap.record_limit


def test_inv2_agent_does_not_import_tools():
    """The agent module must not import world tools or the registry (INV-2)."""
    src = (ROOT / "backend/agent/scripted_agent.py").read_text()
    tree = ast.parse(src)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported += [n.name for n in node.names]
    for mod in imported:
        assert "world" not in mod, f"agent illegally imports {mod}"
        assert "tools" not in mod, f"agent illegally imports {mod}"
    # It may only reach the proxy and the ToolCall model.
    assert any("proxy" in m for m in imported)


def test_inv3_pii_detection_deterministic():
    assert "PII" in classify_payload({"rows": [{"name": "A", "email": "a@b.com"}]})
    assert "PII" in classify_payload({"email": "x@y.com"})
    assert "PII" in classify_payload("call me at +1-555-123-4567")
    assert classify_payload({"count": 60, "period": "2026-Q2"}) == {"aggregate"}
    assert classify_payload({}) == {"none"}
    # PII dominates aggregate when both present.
    mixed = classify_payload({"count": 3, "email": "a@b.com"})
    assert "PII" in mixed and "aggregate" not in mixed


def test_inv3_secret_detection():
    assert "secret" in classify_payload({"config": "api_key=sk-ABCD1234EFGH"})
    assert "secret" in classify_payload("Authorization: Bearer abcdef123456")


def test_config_hashes_present_and_stable():
    caps, denied, meta = build_grant(POLICY)
    assert len(meta["policy_hash"]) == 16
    assert file_hash(POLICY) == meta["policy_hash"]
    assert "db.hard_delete" in denied
    # hard_delete must never be in the granted ceiling
    assert "db.hard_delete" not in caps
