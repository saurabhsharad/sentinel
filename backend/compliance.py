"""Deterministic payload data-class compliance (INV-3).

We NEVER ask an LLM "does this contain PII?". Classification is pure: schema /
column names / regex. classify_payload returns the SET of data classes present.
"""
from __future__ import annotations

import re
from typing import Any, Set

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s().]{7,}\d")
SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password|bearer)\b|sk-[A-Za-z0-9]{8,}")

# Column names that carry personal data (deterministic metadata, not inference).
PII_COLUMNS = {"name", "email", "phone", "address", "ssn"}
AGGREGATE_KEYS = {"count", "period", "total", "sum", "avg", "n"}


def _scan_text(s: str) -> Set[str]:
    classes: Set[str] = set()
    if SECRET_RE.search(s):
        classes.add("secret")
    if EMAIL_RE.search(s) or PHONE_RE.search(s):
        classes.add("PII")
    return classes


def classify_payload(payload: Any) -> Set[str]:
    """Return every data class present in `payload`. Empty payload -> {'none'}."""
    classes: Set[str] = set()

    def walk(obj: Any):
        if obj is None:
            return
        if isinstance(obj, dict):
            keys = {str(k).lower() for k in obj.keys()}
            if keys & PII_COLUMNS:
                classes.add("PII")
            if keys and keys <= (AGGREGATE_KEYS | {"table", "quarter", "status", "label"}):
                classes.add("aggregate")
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            classes.update(_scan_text(obj))
        elif isinstance(obj, (int, float, bool)):
            return

    walk(payload)
    if not classes:
        classes.add("none")
    # PII dominates: if row-level personal data is present, it is not merely aggregate.
    if "PII" in classes:
        classes.discard("aggregate")
    return classes


def check_compliance(cap, payload: Any):
    """Deterministic gate. Returns (ok, offending_class, present_classes)."""
    present = classify_payload(payload)
    for dc in present:
        if dc == "none":
            continue
        if not cap.allows(dc):
            return False, dc, present
    return True, None, present
