"""Fake external HTTP sink (audit-partner.com).

Records EXACTLY what was sent so the UI can prove PII never left the system.
Nothing here reaches the real network.
"""
from __future__ import annotations

from typing import Any, Dict, List


class ExternalSink:
    def __init__(self):
        self.received: List[Dict[str, Any]] = []

    def post(self, destination: str, payload: Any) -> dict:
        record = {"destination": destination, "payload": payload}
        self.received.append(record)
        return {"status": 200, "stored": record}

    # --- forensic accessors for the UI ---
    def contents(self) -> List[Dict[str, Any]]:
        return self.received

    def counts(self) -> dict:
        """How many payloads carried PII vs aggregate-only (proven by inspection)."""
        from backend.compliance import classify_payload
        pii = sum(1 for r in self.received if "PII" in classify_payload(r["payload"]))
        agg = len(self.received) - pii
        return {"total_sent": len(self.received), "pii_sent": pii, "aggregate_sent": agg}
