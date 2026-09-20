# Sentinel — Adaptive Runtime Security for AI Agents

> Don't trust the agent. Don't block the agent. **Control its authority.**

## 💡 Inspiration

AI agents have crossed a line: they no longer just *generate answers*, they *take actions* — deploy code, delete records, export data, send email, call internal APIs. But the way we secure them hasn't caught up. Static permissions and hard-coded guardrails ask one question — *"is this agent allowed to call this tool?"* — and they ask it about **one action at a time**.

The problem is that agents rarely get hacked in a single obviously-bad step. They get hacked across a **sequence** of individually reasonable steps that quietly turn *legitimate* authority into *dangerous* authority. A trusted internal ticket says "include the full customer export for the auditor." The auditor is already approved to receive data. Every single step is permitted by policy — so nothing static stops the bulk PII from leaving. The danger is only visible in the **trajectory**.

We wanted to build the thing that watches the trajectory.

## 🛡️ What it does

Sentinel is a runtime security layer that sits between an AI agent and its tools. The agent holds **no tool credentials** — it can only *propose* actions to a non-bypassable enforcement proxy. For every proposed action, Sentinel:

1. Checks it against a **deterministic, task-scoped capability ceiling**.
2. Normalizes it into a structured trajectory step.
3. Uses **Moss** to retrieve, *in the execution loop*, the most similar **attack** and **safe** trajectory precedents.
4. Computes trajectory **drift** and, if the live path resembles a known attack, **narrows only the offending authority** — e.g. drops `PII` from an already-approved external `http.post` while keeping `aggregate`.
5. Enforces the narrowed capability with **deterministic** payload compliance.

The result: Sentinel **doesn't stop the agent** — it removes the dangerous slice of authority and lets the legitimate task finish.

**The core invariant:** deterministic policy can *grant* authority; retrieval can only ever *reduce* it.

\\( \text{capabilities}_{\text{after}} \subseteq \text{capabilities}_{\text{before}} \\)

## 🎬 The demo (the strongest moment)

A trusted ticket pushes the agent to POST **row-level customer PII** to the approved auditor. Static auth allows the channel, and because the source is *trusted*, it slips past the hard rule that blocks *untrusted* PII egress.

- **Step 4:** the agent proposes `http.post(PII → audit-partner.com)`.
- Moss retrieves the matching precedent — `atk-exfil-00 · data_exfiltration · 0.9937`, which `revokes http.post:PII`.
- Sentinel narrows `http.post`: **`aggregate ✓ / PII ✗`**.
- Deterministic compliance **rejects** the PII payload.
- The agent **adapts**, sends the aggregate count, the task completes — and **0 PII rows leave the system.**

Run the same task with only a static ceiling + hard rules, and **200 PII rows leak**.

## 🔧 How we built it

**Backend** — Python + FastAPI (fully async), SQLite mock enterprise (customers / test_customers / orders), and six tools behind one enforcement proxy. Key modules:

- `proxy.py` — the single, non-bypassable choke point (capability check → normalize → Moss retrieve → drift → capability decay → hard rules → deterministic compliance → execute).
- `moss_client.py` — the **only** module that imports Moss. Two persistent indexes (`sentinel-attacks`, `sentinel-safe`) built once and loaded locally; queries run **in-process**.
- `compliance.py` — deterministic PII/secret detection (regex + schema, never an LLM).
- `models.py` — structured `Capability` + a monotonic `apply_restriction` that can only ever shrink authority.

**The Moss integration (the heart).** Each trajectory fragment carries a **factual** `egress` metadata field — the data class it *actually* sends to an external sink, computed from its steps (not its attack/safe label). At each step the proxy filters both indexes by the current step's egress class (a deterministic Moss metadata filter) and ranks by semantic similarity. Drift is an EMA over the attack-vs-safe gap:

$$ \text{drift}_t = \alpha \cdot (\text{best\_attack} - \text{best\_safe}) + (1-\alpha)\cdot \text{drift}_{t-1} $$

A restriction fires only when the smoothed drift crosses a threshold **and** the top applicable precedent supplies a `revokes` directive.

**Roles are cleanly separated:**

- **Moss** → fast semantic retrieval of relevant precedents.
- **Security engine** → policy, authorization, risk, capability decay.
- **Agent** → proposes and executes.

Moss supplies context; it **does not** make the decision.

**Evaluation.** A generated corpus (140 attack precedents across 5 families, 126 safe with 40 hard negatives), a held-out set (20 attacks / 25 benign) built from **disjoint** resources so it can't be memorized, a leakage validator, thresholds tuned **only** on a dev-benign set and then frozen + hashed, and a three-way ablation harness (A: ceiling · B: ceiling+rules · C: full Sentinel).

## 📊 Measured results (frozen config, held-out)

| Metric | A ceiling | B +rules | C +Moss |
|---|---|---|---|
| Attack containment (recall) | 0.30 | 0.30 | **1.00** |
| False restriction (benign) | 0.0 | 0.0 | 0.0 |
| Benign completion | 1.0 | 1.0 | 1.0 |
| Demo PII → sink | 1 | 1 | **0** |

- **Moss retrieval latency (1000 warm in-process queries):** p50 **4.38 ms** · p95 **4.70 ms** · p99 **4.76 ms** per query (~61 ms total per 7-step task).
- **Counterfactual:** hold the trajectory fixed and remove the applicable precedents from retrieval → the block *disappears* and PII leaks. This proves the restriction is caused by **retrieval + applicable precedent + revocation**, not the egress class alone.
- **14/14 automated tests** pass, including the capability-monotonicity property test and the "the demo is not statically blocked" test.

## 🧗 Challenges we faced

**The embedding can't tell malicious PII egress from legitimate PII egress.** Our honest, hard-won finding: `moss-minilm` scores a bulk-exfil trajectory and a legitimate aggregate share **both ~1.0** — one payload token doesn't move a compressed cosine score. So we *did not* pretend Moss "knows PII is bad." Instead we scope retrieval by the **factual** egress class and let deterministic compliance handle payload policy. We ran a counterfactual to prove Moss retrieval is still causally load-bearing, and we say plainly in our README what our evaluation does and does **not** establish.

**Keeping retrieval honest and fast in the loop.** Moss runs *twice per step*, so a 7-step task does ~14 retrievals. We had to keep that genuinely in-process — and clearly separate the ~7 s one-time cold index load from the ~4 ms hot-path query, rather than reporting cold-start as request latency.

**Preventing evaluation self-deception.** No held-out leakage (we check exact-ID and near-duplicate, max token-Jaccard 0.737), no tuning on held-out data, and frozen + hashed policy/thresholds so every number ties to an exact config.

## 📚 What we learned

- **Security for agents is about authority over time, not a yes/no per call.** The most useful unit isn't the action — it's the trajectory.
- **Retrieval belongs *inside* the loop.** When semantic lookup costs single-digit milliseconds, you can afford to consult security precedent on *every* action instead of treating it as an expensive one-time step. That is the capability Moss unlocked for us.
- **Honest framing is a feature.** Naming exactly what our system does and doesn't do made the whole thing more defensible, not less.

## 🚀 What's next

Immune memory (confirm an attack once → session-index it → catch the mutated retry earlier), targeted human re-grant, and expanding the tool world so retrieval-driven **generalization** across novel channels becomes the headline benefit.

---

**Sentinel** — *Adaptive Runtime Security for AI Agents.* Powered by Moss semantic retrieval.
Built for **YC Fall 2026 × Moss: The Zero Latency Builder Sprint** · theme *Agent Reliability, Security & Evaluation*.
