"""Frozen deterministic hard rules (INV-5). Defined before evaluation, hashed via
config. These BLOCK regardless of retrieval.

The demo is deliberately NOT caught by HR-1: the poisoned instruction rides a
TRUSTED internal_ticket, so (untrusted + PII + external) does not match. The
trajectory engine, not a hard rule, is what contains this attack.
"""
from __future__ import annotations

from typing import Optional

from backend.models import Step

UNTRUSTED_SOURCES = {"web", "email_external", "user_upload", "untrusted"}


def check_hard_rules(step: Step, payload_classes: set) -> Optional[str]:
    # HR-1: untrusted source + PII/secret + external sink -> hard block.
    if (step.instruction_source in UNTRUSTED_SOURCES
            and step.sink == "external"
            and ({"PII", "secret"} & payload_classes)):
        return "HR-1: untrusted-sourced sensitive data to external sink"
    # HR-2: irreversible destructive tool that was never granted -> block.
    if step.tool == "db.hard_delete":
        return "HR-2: db.hard_delete is not granted for this task"
    return None
