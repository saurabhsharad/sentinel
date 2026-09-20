"""Deterministic normalization (§21, INV-4).

The proxy — NOT the agent, NOT an LLM — turns a proposed tool call (and its
payload) into a structured Step. LLM classification is reserved only as a fallback
for instruction-source detection, which the vertical slice does not need.
"""
from __future__ import annotations

from typing import List

import yaml

from backend.compliance import classify_payload
from backend.models import Step, ToolCall

_INTENT = {
    "tickets.read": "read",
    "db.read": "read",
    "db.soft_delete": "archive",
    "db.hard_delete": "destroy",
    "http.post": "send_external",
    "slack.post": "notify_internal",
}


def dominant_class(classes) -> str:
    order = ["secret", "PII", "aggregate", "metadata", "none"]
    for c in order:
        if c in classes:
            return c
    return "none"


class Normalizer:
    def __init__(self, policy_path: str):
        with open(policy_path) as f:
            self.tool_meta = yaml.safe_load(f)["tools"]

    def normalize(self, call: ToolCall, context_data_class: str) -> Step:
        meta = self.tool_meta[call.tool]
        payload_classes = classify_payload(call.payload) if call.payload is not None else {"none"}
        payload_dc = dominant_class(payload_classes)
        # Reading pulls data INTO context; sending pushes payload OUT.
        resource = f"{'external:' if meta['sink'] == 'external' else ''}{call.resource}"
        return Step(
            phase="proposed",
            tool=call.tool,
            intent=_INTENT.get(call.tool, call.intent),
            resource=resource,
            instruction_source=call.instruction_source,
            context_data_class=context_data_class,
            payload_data_class=payload_dc,
            sink=meta["sink"],
            reversible=bool(meta["reversible"]),
        )


def trajectory_text(window: List[Step]) -> str:
    """Structured sliding-window text used for retrieval (§22)."""
    return "  ||  ".join(s.normalized_text() for s in window)
