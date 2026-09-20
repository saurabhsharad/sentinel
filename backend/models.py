"""Core data model for Sentinel (Phase 1 vertical slice).

Capability is structured authority (§19), not a bare string. Restriction can only
narrow it (INV-1 monotonicity). Step is the deterministic normalized unit (§21).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Set


class AuthorityState(str, Enum):
    SCOPED = "SCOPED"          # normal authority
    RESTRICTED = "RESTRICTED"  # specific capabilities narrowed; agent continues
    REVOKED = "REVOKED"        # only safe reads remain; agent must stop (reserved)


# Data classes ordered roughly by sensitivity; used for deterministic compliance.
DATA_CLASSES = ("none", "metadata", "aggregate", "PII", "secret")


@dataclass
class Capability:
    """Structured authority for one tool. Narrowing intersects the allowed sets."""
    name: str
    scope: Set[str]                      # destinations / resources this may touch
    allowed_data_classes: Set[str]       # data classes permitted in the payload
    payload_profile: Set[str]            # advertised payload shapes (aggregate, PII, ...)
    record_limit: int
    ttl_seconds: int
    origin: str                          # "policy" | "regrant"
    granted_at: float = field(default_factory=time.time)

    def ttl_remaining(self) -> float:
        return max(0.0, self.ttl_seconds - (time.time() - self.granted_at))

    def allows(self, data_class: str) -> bool:
        return data_class in self.allowed_data_classes

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "scope": sorted(self.scope),
            "allowed_data_classes": [d for d in DATA_CLASSES if d in self.allowed_data_classes],
            "payload_profile": [d for d in DATA_CLASSES if d in self.payload_profile],
            "record_limit": self.record_limit,
            "ttl_remaining_s": round(self.ttl_remaining(), 1),
            "origin": self.origin,
        }


@dataclass(frozen=True)
class Restriction:
    """Evidence-driven narrowing. Retrieval can ONLY emit these (INV-1)."""
    capability: str
    remove_data_classes: Set[str] = field(default_factory=set)  # data classes to drop
    remove_scope: Set[str] = field(default_factory=set)         # destinations to drop
    new_record_limit: Optional[int] = None                      # only if smaller
    reason: str = ""
    # Causal evidence (§12): every restriction records why.
    precedent_id: str = ""
    family: str = ""
    score: float = 0.0
    drift: float = 0.0


def apply_restriction(cap: Capability, r: Restriction) -> Capability:
    """Return a NEW capability that is a strict subset of `cap` (monotonic).

    This is the single choke point enforcing INV-1: it can only remove, never add.
    """
    new_allowed = set(cap.allowed_data_classes) - set(r.remove_data_classes)
    new_payload = set(cap.payload_profile) - set(r.remove_data_classes)
    new_scope = set(cap.scope) - set(r.remove_scope)
    new_limit = cap.record_limit
    if r.new_record_limit is not None:
        new_limit = min(cap.record_limit, r.new_record_limit)  # never widen
    return replace(
        cap,
        allowed_data_classes=new_allowed,
        payload_profile=new_payload,
        scope=new_scope,
        record_limit=new_limit,
    )


@dataclass
class Step:
    """A deterministically normalized trajectory step (§21)."""
    phase: str                # "proposed" | "observed"
    tool: str
    intent: str
    resource: str
    instruction_source: str   # "user" | "internal_ticket" | ...
    context_data_class: str   # most sensitive data currently in context
    payload_data_class: str   # data class of the outgoing payload (none if read)
    sink: str                 # "internal" | "external"
    reversible: bool

    def normalized_text(self) -> str:
        """Structured transition text used for retrieval (§22). Deterministic."""
        return (
            f"src={self.instruction_source} action={self.tool} intent={self.intent} "
            f"resource={self.resource} ctx={self.context_data_class} "
            f"payload={self.payload_data_class} sink={self.sink} "
            f"reversible={'true' if self.reversible else 'false'}"
        )

    def snapshot(self) -> dict:
        d = self.__dict__.copy()
        d["normalized_text"] = self.normalized_text()
        return d


@dataclass
class ToolCall:
    """A proposed call from the agent to the proxy. The agent supplies the intent
    and the raw payload; the proxy (not the agent) determines everything else."""
    tool: str
    resource: str            # destination / table
    intent: str
    payload: object = None   # raw data the agent wants to send (rows, dict, text)
    instruction_source: str = "user"
