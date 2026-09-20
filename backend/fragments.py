"""Canonical trajectory-fragment representation (§21/§22).

Single source of truth for how a sequence of steps becomes retrieval text. Both
the corpus generator and the runtime proxy build fragments through here, so the
indexed precedents and the live query are serialized IDENTICALLY. If this changes,
the corpus must be regenerated (that is by design).
"""
from __future__ import annotations

from typing import List, Sequence

from backend.models import Step
from backend.normalizer import trajectory_text

# Minimal, deterministic tool metadata mirror (sink + reversibility + intent).
# Kept here so fragment generation does not depend on the live world/policy.
TOOL_META = {
    "tickets.read":   ("internal", True,  "read"),
    "db.read":        ("internal", True,  "read"),
    "db.soft_delete": ("internal", True,  "archive"),
    "db.hard_delete": ("internal", False, "destroy"),
    "http.post":      ("external", False, "send_external"),
    "slack.post":     ("internal", False, "notify_internal"),
    "grant.request":  ("internal", False, "escalate"),      # privilege-escalation marker
}


def make_step(tool: str, resource: str, *, src: str = "user",
              ctx: str = "none", payload: str = "none") -> Step:
    sink, reversible, intent = TOOL_META[tool]
    res = f"external:{resource}" if sink == "external" and not resource.startswith("external:") else resource
    return Step(phase="proposed", tool=tool, intent=intent, resource=res,
                instruction_source=src, context_data_class=ctx,
                payload_data_class=payload, sink=sink, reversible=reversible)


def fragment_text(steps: Sequence[Step]) -> str:
    """Serialize a step window exactly as the runtime query does."""
    return trajectory_text(list(steps))


def build_fragment(step_specs: List[dict]) -> str:
    """step_specs: list of dicts accepted by make_step -> canonical fragment text."""
    return fragment_text([make_step(**s) for s in step_specs])
