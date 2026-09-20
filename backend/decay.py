"""Trajectory drift (§23) and capability-decay selection.

Honest to Phase 0: raw_drift = best_attack_score - best_safe_score is SMALL
(~0.02-0.03) and we keep it as-is (no fabricated 0.86). EMA smooths it. A
restriction is emitted ONLY when the smoothed drift crosses a provisional
threshold AND the top attack precedent supplies a `revokes` directive naming the
capability + data class to narrow. Retrieval can only ever REDUCE authority.
"""
from __future__ import annotations

from typing import List, Optional

from backend.models import Capability, Restriction
from backend.moss_client import Precedent


class DriftEngine:
    def __init__(self, alpha_ema: float):
        self.alpha = alpha_ema
        self.drift = 0.0
        self.initialized = False

    def update(self, best_attack: float, best_safe: float):
        raw = best_attack - best_safe
        if not self.initialized:
            self.drift = raw
            self.initialized = True
        else:
            self.drift = self.alpha * raw + (1 - self.alpha) * self.drift
        return raw, self.drift


def _parse_revokes(revokes: str):
    """'http.post:PII' -> ('http.post', 'PII'); 'db.hard_delete:*' -> (..., '*')."""
    if ":" not in revokes:
        return revokes, "*"
    cap, dc = revokes.split(":", 1)
    return cap, dc


def filter_relevant(attacks: List[Precedent], tool: str, caps: dict) -> List[Precedent]:
    """Keep only precedents whose revocation applies to the CURRENT step:
    the revoked capability is the tool being proposed AND that authority still
    exists to remove. This prevents a precedent from driving drift on steps it
    cannot actually restrict (e.g. residual exfil similarity on a slack.post, or
    on an http.post whose PII was already dropped). Retrieval stays honest but
    only counts where it can act."""
    out = []
    for a in attacks:
        if not a.revokes:
            continue
        cap_name, dc = _parse_revokes(a.revokes)
        if cap_name != tool:
            continue
        cap = caps.get(cap_name)
        if cap is None:
            continue  # capability not granted -> handled by the ceiling, not Moss
        remaining = set(cap.allowed_data_classes) - {"none"}
        if dc == "*":
            if remaining:
                out.append(a)
        elif dc in cap.allowed_data_classes:
            out.append(a)
    return out


def select_restriction(
    attacks: List[Precedent],
    drift_ema: float,
    threshold: float,
    caps: dict,          # name -> Capability (current authority snapshot)
    raw_drift: float,
    require_positive_raw: bool = True,
) -> Optional[Restriction]:
    """Deterministic restriction selection driven by retrieved precedent evidence."""
    if drift_ema < threshold or not attacks:
        return None
    if require_positive_raw and raw_drift <= 0:
        return None  # current step is safe-leaning; don't restrict on stale EMA
    top = attacks[0]
    if not top.revokes:
        return None
    cap_name, dc = _parse_revokes(top.revokes)
    cap: Capability = caps.get(cap_name)
    if cap is None:
        return None  # nothing to narrow

    # Only narrow if it actually removes something the capability still has.
    if dc == "*":
        remove = set(cap.allowed_data_classes) - {"none"}
    else:
        remove = {dc} & cap.allowed_data_classes
    if not remove:
        return None

    return Restriction(
        capability=cap_name,
        remove_data_classes=remove,
        reason=(f"Trajectory resembles {top.family.replace('_', ' ')}; narrowing "
                f"{cap_name} to drop {'/'.join(sorted(remove))}."),
        precedent_id=top.id,
        family=top.family,
        score=top.score,
        drift=round(drift_ema, 4),
    )
