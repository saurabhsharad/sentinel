# Brag Plan: Sentinel

## What is this app?
Sentinel is a security layer for AI agents that watches an agent's *trajectory* in real time and, using Moss retrieval inside the execution loop, narrows only the dangerous authority the moment the path starts to resemble a known attack — instead of blocking the whole agent.

## The angle
Agents don't get hacked in one obviously-bad action. They get hacked across a
sequence of individually reasonable steps that quietly turn approved authority into
an exfiltration channel. The video's premise: a *trusted* ticket asks an agent to
"include the full customer export" for an already-approved auditor — every step is
allowed — and Sentinel is the thing that watches the *shape of the trajectory*,
narrows `http.post` from `PII` to `aggregate`, and proves **zero PII left the
system.** Confident, measured, real numbers. Not a gimmick.

## Hook (first 2-3 seconds)
Black screen, mono type snaps in: **"Agents don't get hacked in one step."** →
beat → **"They get hacked across a sequence."** The whole thesis in two lines.

## Key moments (the middle)
- The `http.post → audit-partner.com` capability card flips **`PII ✓` → `PII ✗`** while `aggregate ✓` stays — authority *narrowing*, not blocking.
- The causal chain igniting left-to-right: `trajectory → Moss precedent → drift → authority decay → payload rejection → safe retry`.
- The external sink counter: **PII SENT → 0** in green, aggregate → 1.
- The ablation jump: containment **0.30 → 0.30 → 1.00** (ceiling → +rules → +Moss).
- Moss in the loop at **4.38 ms** p50.

## Outro / punchline
**"We didn't block the agent. We controlled its authority."** → SENTINEL wordmark
with the blue accent dot.

## User flow worth showing
The live console's canonical run (entry → key action → result):
1. Agent reads a trusted ticket and customer PII (authority: all green).
2. It attempts to POST row-level PII to the approved auditor → Sentinel narrows `http.post`, the PII payload is **rejected**.
3. Agent adapts, sends the aggregate count → task completes, **PII sent = 0**.

## Tone
- Preset: polished
- Creative direction: quiet, premium security-product film — motion-driven, confident, zero gimmicks
- Interpretation: restrained pacing, generous holds on the key numbers, one decisive color shift (green "0" / red narrowing), no jokey energy — the credibility *is* the flex.

## Format: landscape — 1920x1080
## Duration: 20s

## Visual identity (from the project)
- Background: #0a0d14 (with a subtle radial #14203a glow top-right)
- Accent: #6ea8fe (blue)
- Positive / "0 PII": #37d99a (green)
- Danger / narrowing: #ff5f6d (red) · Restricted: #ffb454 (amber)
- Text: #e8eefb
- Display font: system sans (Segoe UI / -apple-system), heavy weight
- Body/technical font: SFMono / Menlo (monospace — used for all authority/latency text)
- Strongest visual element: the CURRENT AUTHORITY capability card with `aggregate ✓ / PII ✗` chips, and the big green `PII SENT = 0`.

## Share copy (draft)
We didn't block the agent — we controlled its authority. Sentinel watches an AI
agent's trajectory with Moss in the loop (4.38 ms/query) and narrows just the
dangerous capability: PII exfiltration blocked, the legit task still finishes. 0.30 → 1.00 containment. 🛡️

## Audio direction
- Role: cinematic-but-restrained bed — a low, confident pulse that supports, never distracts
- Music: bundled polished/cinematic track (tense-to-resolved arc); mono-tech mood
- Music treatment: start at 0s, low volume bed, gentle swell into the "PII SENT = 0" reveal, clean fade on the outro wordmark
- Music cue guidance: read bundled cue preset if present; otherwise detect beats at composition time. Target strong cues at ~2s (hook line 2), the PII✓→✗ flip, and the "0" reveal.
- Audio-reactive treatment: subtle — a faint glow/presence lift on the accent at the "0" reveal only
- SFX posture: sparse, motion-matched — one dry "lock"/click on the narrowing, one soft confirm on "0"
- Audio-coupled moments: mono text typing on the hook, chain nodes igniting in sequence, the sink counter ticking to 0
- Restraint rule: no whooshes on every cut, no riser spam; silence and hold are allowed to carry the numbers

## Storyboard

### Scene 1 — Hook — 3s
Black (#0a0d14). Mono text types/snaps: line 1 "Agents don't get hacked in one step." then line 2 "They get hacked across a sequence." Faint blue accent underline.
Sequential/interaction: yes — two lines arrive one after the other; second line lands on a beat.
Audio intent: quiet tension establishing.
Audio-coupled idea: typed text; beat-aligned second line.
Music: low tense bed begins.
Transition mood: clean → Scene 2

### Scene 2 — The setup (authority is all-green) — 3.5s
Title chip "CURRENT AUTHORITY". Three mono capability rows fade in: `tickets.read ✓`, `db.read → customers  aggregate ✓ PII ✓`, `http.post → audit-partner.com  aggregate ✓ PII ✓`. A small caption: "trusted ticket · every step approved".
Sequential/interaction: yes — capability rows arrive one by one.
Audio intent: calm, "everything looks fine".
Audio-coupled idea: card-by-card reveal.
Music: steady bed.
Transition mood: soft → Scene 3

### Scene 3 — The turn (narrowing) — 4s
Focus pushes to the `http.post` row. The agent line "POST customers(name,email,phone) → audit-partner.com" appears. Then the causal chain ignites left→right: trajectory → Moss precedent (chip: "data_exfiltration · sim 0.99") → drift 0.79 → authority decay. On "authority decay", the `PII ✓` chip flips to **`PII ✗`** (red, small shake); `aggregate ✓` stays green.
Sequential/interaction: yes — chain nodes ignite in sequence, then the chip flips.
Audio intent: rising, decisive; a single dry "lock" hit on the flip.
Audio-coupled idea: beat-aligned chain nodes; SFX on the PII✗ flip.
Music: swell.
Transition mood: hard → Scene 4

### Scene 4 — The proof (PII SENT = 0) — 4s
Cut to the EXTERNAL SINK panel. "PII sent" counter sits at big red as a "rows ×200" ghost briefly appears, then is struck through and the number resolves to a huge green **0**. Beside it: "aggregate sent  1". Caption: "the legit task still finished".
Sequential/interaction: yes — the ghost PII payload is rejected, counter resolves to 0.
Audio intent: release/resolve; soft confirm on "0".
Audio-coupled idea: counter ticking to 0; confirm SFX.
Music: resolve, presence lift.
Transition mood: clean → Scene 5

### Scene 5 — The receipts (ablation + latency) — 3.5s
Three-bar comparison: "ceiling 0.30", "+rules 0.30", "+Moss 1.00" — the third bar shoots to full green. Small mono line: "Moss in the loop · 4.38 ms/query · held-out, frozen config".
Sequential/interaction: yes — bars fill left to right, the C bar overshoots to 1.00.
Audio intent: confident, earned.
Audio-coupled idea: bars filling on beat.
Music: steady, building to outro.
Transition mood: clean → Scene 6

### Scene 6 — Outro — 2s
Center: **"We didn't block the agent. We controlled its authority."** → fades to the SENTINEL wordmark with the blue accent dot and the line "Trajectory-governed authority · Moss in the loop".
Sequential/interaction: none.
Audio intent: final calm confidence; clean fade out.
Audio-coupled idea: none.
Music: resolve and fade.
Transition mood: soft fade to black
