"""Deterministic task grant (§3, INV-1). Only this (or an explicit human re-grant)
may GRANT authority. Retrieval never calls into here."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from backend.models import Capability


def file_hash(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


def build_grant(policy_path: str) -> Tuple[Dict[str, Capability], List[str], dict]:
    with open(policy_path) as f:
        policy = yaml.safe_load(f)
    tg = policy["task_grant"]
    ttl = tg["ttl_seconds"]
    caps: Dict[str, Capability] = {}
    for c in tg["capabilities"]:
        caps[c["name"]] = Capability(
            name=c["name"],
            scope=set(c["scope"]),
            allowed_data_classes=set(c["allowed_data_classes"]),
            payload_profile=set(c["payload_profile"]),
            record_limit=c["record_limit"],
            ttl_seconds=ttl,
            origin=c.get("origin", "policy"),
        )
    denied = list(tg.get("denied", []))
    meta = {"policy_hash": file_hash(policy_path)}
    return caps, denied, meta
