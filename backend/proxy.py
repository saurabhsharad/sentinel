"""The enforcement proxy — the single, non-bypassable choke point (INV-2).

The agent holds NO tool credentials and never imports world.tools. It sends a
ToolCall to propose(); the proxy owns normalization, retrieval, drift, capability
decay, hard rules, compliance, execution, and event emission.

Decision pipeline per proposed call:
  1. deterministic capability check (ceiling: exists? in scope?)
  2. deterministic normalization -> Step (INV-4)
  3. before-retrieval against attack + safe indexes (Moss, in-loop)
  4. drift update (EMA over raw_drift)
  5. precedent-driven capability decay  (retrieval can only REDUCE)  [INV-1]
  6. frozen hard rules
  7. deterministic payload compliance against the (possibly narrowed) capability [INV-3]
  8. execute via registry, or REJECT back to the agent
  9. observe -> update context data class -> emit event snapshot
Fail-closed (INV-8): if retrieval errors, external sinks lose PII/secret.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

import yaml

from backend.compliance import check_compliance, classify_payload
from backend.decay import DriftEngine, filter_relevant, select_restriction
from backend.grant import build_grant
from backend.hard_rules import check_hard_rules
from backend.models import (AuthorityState, Capability, Restriction, Step,
                            ToolCall, apply_restriction)
from backend.moss_client import MossUnavailable, PrecedentStore
from backend.normalizer import Normalizer, dominant_class, trajectory_text
from backend.world.tools import ToolRegistry


class Proxy:
    # Ablation configs (§13): A=ceiling, B=ceiling+rules, C=full (ceiling+rules+moss).
    # Payload compliance is part of the ceiling and is ON in every mode.
    MODES = {"ceiling", "ceiling_rules", "full"}

    def __init__(self, precedent_store: PrecedentStore,
                 policy_path: str, thresholds_path: str, mode: str = "full"):
        assert mode in self.MODES, mode
        self.mode = mode
        self.caps, self.denied, self.meta = build_grant(policy_path)
        self.registry = ToolRegistry()
        self.normalizer = Normalizer(policy_path)
        self.store = precedent_store
        with open(thresholds_path) as f:
            self.th = yaml.safe_load(f)
        self.drift = DriftEngine(self.th["drift"]["alpha_ema"])
        self.window: List[Step] = []
        self.context_dc = "none"      # most sensitive data currently in context
        self.state = AuthorityState.SCOPED
        self.step_no = 0
        self.events: List[dict] = []

    # --- authority snapshot for the UI ---
    def authority_snapshot(self) -> List[dict]:
        return [c.snapshot() for c in self.caps.values()]

    def _push_window(self, step: Step):
        self.window.append(step)
        w = self.th["retrieval"]["window_size"]
        if len(self.window) > w + 1:
            self.window = self.window[-(w + 1):]

    async def propose(self, call: ToolCall) -> dict:
        self.step_no += 1
        ev: dict = {"step": self.step_no, "tool": call.tool, "resource": call.resource,
                    "intent": call.intent, "phase": "proposed"}

        # 1) deterministic capability ceiling
        cap: Optional[Capability] = self.caps.get(call.tool)
        if cap is None or call.tool in self.denied:
            return self._finish(ev, "DENY", detail=f"{call.tool} not in task grant",
                                executed=False)
        scoped = ("*" in cap.scope) or (call.resource in cap.scope)
        if not scoped:
            return self._finish(ev, "DENY",
                                detail=f"{call.resource} outside scope of {call.tool}",
                                executed=False)

        # 2) deterministic normalization
        step = self.normalizer.normalize(call, self.context_dc)
        self._push_window(step)
        ev["normalized"] = step.normalized_text()

        # 3-5) Intelligence layer (Moss retrieval -> drift -> capability decay).
        # Only in "full" mode; retrieval can only ever REDUCE authority (INV-1).
        restriction: Optional[Restriction] = None
        if self.mode == "full":
            traj = trajectory_text(self.window)
            # Egress class of THIS step scopes the attack-vs-safe comparison.
            egress = step.payload_data_class if step.sink == "external" else "none"
            moss_failed = False
            attacks, safes = [], []
            _t0 = time.perf_counter()
            try:
                hits = await self.store.retrieve(
                    traj, top_k=self.th["retrieval"]["top_k"],
                    alpha=self.th["retrieval"]["alpha"], egress=egress)
                attacks, safes = hits["attack"], hits["safe"]
            except MossUnavailable as e:
                moss_failed = True
                ev["moss_error"] = str(e)
            # Hot-path retrieval latency for THIS step (wall-clock, includes the
            # asyncio hop; = 2 in-process index queries). Honest live number.
            retrieval_ms = round((time.perf_counter() - _t0) * 1000.0, 2)

            # Relevance filtering (§7): only precedents that can actually restrict
            # THIS step's tool (and whose data class is still authorized) count
            # toward drift. Everything retrieved is still shown for transparency.
            rel = filter_relevant(attacks, call.tool, self.caps)
            best_safe = safes[0].score if safes else 0.0
            # Neutral drift when no actionable attack precedent (avoids poisoning the
            # EMA with -best_safe on steps that cannot be restricted).
            best_atk = rel[0].score if rel else 0.0
            raw, drift_ema = self.drift.update(best_atk, (best_safe if rel else best_atk))
            ev["retrieval"] = {
                "attack": [{"id": p.id, "score": round(p.score, 4), "family": p.family,
                            "revokes": p.revokes,
                            "relevant": p in rel} for p in attacks],
                "safe": [{"id": p.id, "score": round(p.score, 4), "family": p.family}
                         for p in safes],
                "egress": egress,
                "best_relevant_attack": round(best_atk, 4),
                "raw_drift": round(raw, 4), "drift_ema": round(drift_ema, 4),
                "moss_ran": not moss_failed, "latency_ms": retrieval_ms,
            }
            if moss_failed:
                restriction = self._fail_closed(step)  # INV-8
            else:
                restriction = select_restriction(
                    rel, drift_ema, self.th["drift"]["restrict_threshold"],
                    self.caps, raw,
                    require_positive_raw=self.th["drift"].get("require_positive_raw", True))
            if restriction is not None:
                self._apply(restriction, ev)
                cap = self.caps.get(call.tool)  # refresh (may have narrowed)

        # 6) frozen hard rules (config B and C)
        payload_classes = classify_payload(call.payload)
        if self.mode in ("ceiling_rules", "full"):
            hr = check_hard_rules(step, payload_classes)
            if hr:
                return self._finish(ev, "BLOCK", detail=hr, executed=False)

        # 7) deterministic payload compliance against current authority
        ok, offending, present = check_compliance(cap, call.payload)
        ev["payload_classes"] = sorted(present)
        if not ok:
            return self._finish(
                ev, "REJECT", executed=False,
                detail=(f"Capability narrowed to {sorted(cap.allowed_data_classes)}. "
                        f"Payload contains forbidden data class {offending}."),
                agent_feedback={"error": "capability_narrowed",
                                "forbidden_class": offending,
                                "allowed": sorted(cap.allowed_data_classes)})

        # 8) execute
        result = self.registry.dispatch(call.tool, call.resource, call.payload)

        # 9) observe -> update context data class from what came back
        obs_classes = classify_payload(result)
        self.context_dc = dominant_class({self.context_dc} | obs_classes)
        return self._finish(ev, "ALLOW", executed=True, detail="executed", result=result)

    def _fail_closed(self, step: Step) -> Optional[Restriction]:
        """INV-8: retrieval failed -> strip PII/secret from external-sink capability."""
        if step.sink != "external":
            return None
        cap = self.caps.get(step.tool)
        if not cap:
            return None
        remove = {"PII", "secret"} & cap.allowed_data_classes
        if not remove:
            return None
        return Restriction(capability=step.tool, remove_data_classes=remove,
                           reason="FAIL-CLOSED: retrieval unavailable; external sink "
                                  "restricted to non-sensitive payloads.",
                           precedent_id="fail-closed", family="fail_closed")

    def _apply(self, r: Restriction, ev: dict):
        old = self.caps[r.capability].snapshot()
        self.caps[r.capability] = apply_restriction(self.caps[r.capability], r)
        new = self.caps[r.capability].snapshot()
        self.state = AuthorityState.RESTRICTED
        ev["restriction"] = {
            "capability": r.capability, "reason": r.reason,
            "precedent_id": r.precedent_id, "family": r.family,
            "score": round(r.score, 4), "drift": r.drift,
            "removed_data_classes": sorted(r.remove_data_classes),
            "old": old, "new": new,
        }

    def _finish(self, ev: dict, decision: str, detail: str = "", executed: bool = False,
                result=None, agent_feedback=None) -> dict:
        ev["decision"] = decision
        ev["detail"] = detail
        ev["executed"] = executed
        ev["state"] = self.state.value
        ev["authority"] = self.authority_snapshot()
        ev["sink"] = {"counts": self.registry.sink.counts(),
                      "contents": self.registry.sink.contents()}
        if agent_feedback is not None:
            ev["agent_feedback"] = agent_feedback
        # keep result out of the persisted event if it is bulk PII (never leak it)
        self.events.append(ev)
        return {**ev, "_result": result, "_agent_feedback": agent_feedback}
