"""The ONLY module permitted to import the Moss SDK (§20).

Exposes a small PrecedentStore abstraction over the real (async) Moss API,
grounded in the Phase-0 findings:
  - all methods are async; query() runs in-process (no network) once loaded
  - metadata values are strings; filter syntax is {"$and":[{"field","condition"}]}
  - scores are compressed ~0.8-1.0; we keep raw scores and never fabricate gaps
Credentials come ONLY from MOSS_PROJECT_ID / MOSS_PROJECT_KEY (env or ./.env);
they are never printed, logged, or committed.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import moss  # the single import boundary

ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = str(ROOT / ".moss_cache")
ATTACK_INDEX = "sentinel-attacks"
SAFE_INDEX = "sentinel-safe"


def _load_env():
    envf = ROOT / ".env"
    if envf.exists():
        for line in envf.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.replace("export ", "").strip(),
                                  v.strip().strip('"').strip("'"))


def _read_corpus(path: Path) -> List["moss.DocumentInfo"]:
    docs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        docs.append(moss.DocumentInfo(
            id=obj["id"], text=obj["text"],
            metadata={k: str(v) for k, v in obj.get("metadata", {}).items()},
        ))
    return docs


@dataclass
class Precedent:
    id: str
    score: float
    family: str          # attack family, or task_type for safe
    revokes: str         # attack directive, "" for safe
    text: str
    metadata: Dict[str, str]


class MossUnavailable(RuntimeError):
    """Raised when retrieval fails/times out -> proxy must FAIL CLOSED (INV-8)."""


class PrecedentStore:
    def __init__(self, query_timeout_s: float = 2.0):
        _load_env()
        pid, key = os.environ.get("MOSS_PROJECT_ID"), os.environ.get("MOSS_PROJECT_KEY")
        if not pid or not key:
            raise RuntimeError("Missing MOSS_PROJECT_ID / MOSS_PROJECT_KEY (set in ./.env).")
        self._client = moss.MossClient(pid, key)
        self._timeout = query_timeout_s
        self._ready = False

    async def ensure_ready(self, rebuild: bool = False):
        """Create the two indexes if missing (cloud), then load them locally.

        Cold path is slow (~create + download); cache_path makes restarts fast.
        """
        existing = {i.name for i in await self._client.list_indexes()}
        specs = [(ATTACK_INDEX, ROOT / "corpus/attack_trajectories.jsonl"),
                 (SAFE_INDEX, ROOT / "corpus/safe_trajectories.jsonl")]
        for name, path in specs:
            if rebuild and name in existing:
                await self._client.delete_index(name)
                existing.discard(name)
            if name not in existing:
                await self._client.create_index(name, _read_corpus(path), wait=True)
        await self._client.load_indexes([ATTACK_INDEX, SAFE_INDEX], cache_path=CACHE_PATH)
        self._ready = True

    async def _query(self, index: str, text: str, top_k: int, alpha: float,
                     filt: Optional[dict]) -> List["moss.QueryResultDocumentInfo"]:
        opts = moss.QueryOptions(top_k=top_k, alpha=alpha, filter=filt)
        try:
            res = await asyncio.wait_for(self._client.query(index, text, opts), self._timeout)
        except (asyncio.TimeoutError, Exception) as e:  # noqa: BLE001 fail closed on ANY error
            raise MossUnavailable(f"{index} query failed: {type(e).__name__}") from e
        return res.docs

    @staticmethod
    def _egress_filter(egress: Optional[str], exclude_family: Optional[str] = None) -> Optional[dict]:
        """Build a metadata filter scoping precedents to a FACTUAL egress data-class.
        `egress` is a property of the precedent's behavior (the data class it actually
        sends externally), NOT its attack/safe label. `exclude_family` is used only by
        the causality-verification experiment to remove a family from retrieval."""
        conds = []
        if egress:
            conds.append({"field": "egress", "condition": {"$eq": egress}})
        if exclude_family:
            conds.append({"field": "family", "condition": {"$ne": exclude_family}})
        if not conds:
            return None
        return {"$and": conds}

    async def retrieve(self, text: str, top_k: int = 3, alpha: float = 0.8,
                       egress: Optional[str] = None,
                       attack_exclude_family: Optional[str] = None
                       ) -> Dict[str, List[Precedent]]:
        """Before/after retrieval against BOTH indexes, scoped to the current step's
        egress data-class (a factual metadata filter). The safe corpus never egresses
        PII/secret (a true domain property, not a label), so a PII/secret-egress query
        matches only attack precedents; an aggregate/none egress query matches safe.
        `attack_exclude_family` removes a family from the ATTACK query only, used by the
        precedent-necessity experiment to prove retrieval (not egress class) is causal."""
        adocs = await self._query(ATTACK_INDEX, text, top_k, alpha,
                                  self._egress_filter(egress, attack_exclude_family))
        sdocs = await self._query(SAFE_INDEX, text, top_k, alpha, self._egress_filter(egress))
        attacks = [Precedent(d.id, float(d.score), d.metadata.get("family", ""),
                             d.metadata.get("revokes", ""), d.text, dict(d.metadata))
                   for d in adocs]
        safes = [Precedent(d.id, float(d.score), d.metadata.get("task_type", ""),
                           "", d.text, dict(d.metadata)) for d in sdocs]
        return {"attack": attacks, "safe": safes}
