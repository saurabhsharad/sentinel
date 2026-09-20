# Sentinel — Product Requirements Document (PRD)

**Product:** Sentinel — Adaptive Runtime Security for AI Agents
**Tagline:** Don't trust the agent. Don't block the agent. Control its authority.
**Event:** YC Fall 2026 × Moss — *The Zero Latency Builder Sprint*
**Theme:** Agent Reliability, Security & Evaluation
**Status:** Functional prototype (frozen eval configuration)
**Demo:** https://youtu.be/v5xE2jWmj6Q · **Repo:** https://github.com/saurabhsharad/sentinel

---

## 1. Overview

Sentinel is a runtime security layer that sits between an AI agent and its tools. It
enforces a deterministic, task-scoped **capability ceiling** through a non-bypassable
proxy, and uses **Moss** for in-process semantic retrieval of *trajectory* precedents.
When the agent's live sequence of actions begins to resemble a known attack, Sentinel
**narrows only the offending authority** (e.g. drops `PII` from an already-approved
external `http.post`) instead of blocking the whole agent — so legitimate work
continues.

**Core invariant:** deterministic policy can *grant* authority; retrieval can only ever
*reduce* it (`capabilities_after ⊆ capabilities_before`).

## 2. Problem statement

AI agents increasingly take real actions (deploy, delete, export, email, call internal
APIs). Static permissions and hard-coded guardrails evaluate **one action at a time**
and can't see the **context around a sequence of actions**. Attacks emerge from a chain
of individually-permitted steps that convert legitimate authority into a data-exfiltration
or destruction channel. A trusted internal ticket can instruct an agent to "include the
full customer export" for an *approved* auditor — every step is allowed, so nothing static
stops the bulk PII from leaving. The risk is only visible in the **trajectory**.

## 3. Goals / Non-goals

**Goals**
- Detect trajectory-level risk **at runtime**, on every proposed action.
- Reduce blast radius by narrowing *only* the dangerous capability, preserving task utility.
- Keep the security decision **deterministic and auditable**; make retrieval fast enough to run in-loop.
- Demonstrate meaningful, measurable use of Moss in the retrieval layer.

**Non-goals**
- Not a claim to "solve prompt injection" or prevent all attacks.
- Not an LLM-based judge of safety; the LLM does not make the security decision.
- Not claiming Moss semantically distinguishes malicious vs. legitimate PII egress (our evaluation does not establish that).

## 4. Target users

- **Platform / security engineers** deploying autonomous agents who need runtime guardrails that understand context, not just per-call permissions.
- **Agent developers** who want to keep agents useful (not hard-blocked) while containing dangerous action sequences.

## 5. User stories

1. As a security engineer, I want the agent to be **unable to hold tool credentials**, so every action must pass a single enforcement point.
2. As a security engineer, I want dangerous **sequences** caught even when each step is individually permitted.
3. As an agent developer, I want a restriction to **narrow one capability**, not kill the agent, so the legitimate task still completes.
4. As a reviewer, I want **evidence** for every restriction (which precedent, which revocation, what drift) — not a black box.
5. As an evaluator, I want **measured** security/latency numbers on a held-out set, tied to a frozen config.

## 6. Functional requirements

| # | Requirement | Status |
|---|---|---|
| F1 | Deterministic task grant (capability ceiling) from `policy.yaml` | ✅ |
| F2 | Non-bypassable enforcement proxy; agent holds no credentials | ✅ |
| F3 | Deterministic normalization of each action into a structured `Step` | ✅ |
| F4 | In-process Moss retrieval of attack + safe precedents, egress-scoped | ✅ |
| F5 | Trajectory drift (EMA) + capability decay; retrieval can only reduce | ✅ |
| F6 | Deterministic payload compliance (PII/secret detection, no LLM) | ✅ |
| F7 | Frozen hard rules; fail-closed on Moss failure | ✅ |
| F8 | Three states: SCOPED → RESTRICTED → REVOKED | ✅ (SCOPED→RESTRICTED exercised) |
| F9 | Live security console (authority panel, causal chain, evidence) | ✅ |
| F10 | Evaluation harness: held-out eval, 3-way ablation, latency bench, causality | ✅ |

## 7. Non-functional requirements

- **Latency:** Moss retrieval must be fast enough to run twice per step. Measured: **p50 4.38 ms / p95 4.70 ms / p99 4.76 ms** per query (1000 warm in-process queries); ~61 ms total per 7-step task. Cold index load (~7 s) is one-time startup, not request latency.
- **Determinism / auditability:** policy, thresholds, and corpus are hashed into a lock file; every eval report embeds the hashes.
- **Integrity:** held-out data is never indexed (exact-ID + near-duplicate checks); thresholds tuned only on a dev-benign set, then frozen.
- **Safety:** credentials only in environment variables; never logged, committed, or shipped to the frontend.

## 8. Architecture (summary)

`USER → task grant → AGENT → ENFORCEMENT PROXY → {Moss retrieval ⇄ 2 indexes} → decision → TOOLS`, with an
observation loop back into the proxy. See `docs/architecture.png`.

- **Moss** = fast semantic retrieval of precedents (`moss_client.py` is the only module importing Moss).
- **Security engine** = policy, authorization, risk, capability decay (`proxy.py`, `decay.py`, `hard_rules.py`, `compliance.py`).
- **Agent** = proposes and executes (`agent/scripted_agent.py`); holds no credentials.

**Moss usage detail:** each trajectory fragment carries a *factual* `egress` metadata field
(the data class it actually sends externally). At each step the proxy filters both indexes by
the current step's egress class (a deterministic Moss metadata filter) and ranks by semantic
similarity. Drift = EMA of (best attack − best safe). A restriction fires only when smoothed
drift crosses a frozen threshold **and** the top applicable precedent supplies a `revokes`
directive. Moss supplies context; the deterministic engine makes the decision.

## 9. Success metrics (measured, held-out, frozen config)

| Metric | A: ceiling | B: +rules | C: +Moss |
|---|---|---|---|
| Attack containment (recall) | 0.30 | 0.30 | **1.00** |
| False restriction (benign) | 0.0 | 0.0 | 0.0 |
| Benign completion | 1.0 | 1.0 | 1.0 |
| Demo PII → external sink | 1 | 1 | **0** |

- **Counterfactual (causality):** remove the applicable precedents from retrieval and hold the trajectory fixed → the block disappears and PII leaks — proving the restriction is caused by retrieval + applicable precedent + revocation, not the egress class alone.
- **14/14 automated tests** pass (incl. capability-monotonicity property test and "not statically blocked" test).

## 10. Evaluation methodology

- **Corpus:** 140 attack precedents (5 families), 126 safe (40 hard negatives), generated deterministically with representation parity to the runtime query.
- **Held-out:** 20 attack + 25 benign *executable* scenarios, built from resources disjoint from the indexed corpus (max token-Jaccard 0.737 < 0.85). Never indexed.
- **Ablation:** A = deterministic ceiling; B = ceiling + hard rules; C = full Sentinel + Moss.
- **Reproduce:** `make phase2` (generate → validate → rebuild-index → tune → freeze → eval → latency → verify → tests). Reports in `eval/reports/`.

## 11. Risks & limitations

- The `moss-minilm` embedding cannot separate a PII-egress trajectory from an aggregate-egress one on semantics alone (both ~1.0). Separation comes from the **factual** egress-metadata scoping + deterministic compliance. In this constrained tool-world a deterministic egress rule could achieve similar containment; Moss's *measured* added value is generalization across renamed/reordered/paraphrased held-out attacks, revocation routing per family, and evidence-graded drift.
- Prototype world uses a mock enterprise (6 tools, SQLite). Live LLM agent path exists but the deterministic scripted agent is the demo-critical path.

## 12. Milestones

- **Phase 0** — Moss SDK verification & latency spike ✅
- **Phase 1** — thin vertical slice (proxy + one restriction + console) ✅
- **Phase 2** — full corpus, held-out eval, ablation, frozen thresholds, causality ✅
- **Phase 3** — security console, evidence view, README, demo video ✅

## 13. Future work

Immune memory (SessionIndex: confirm an attack once → index it → catch the mutated retry
earlier), targeted human re-grant, and a broader tool world where retrieval-driven
generalization across novel channels becomes the headline benefit.
