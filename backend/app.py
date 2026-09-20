"""FastAPI app for the Sentinel vertical slice.

Loads the Moss indexes ONCE at startup (cold ~cache-dependent), then each /api/run
builds a fresh Proxy + world so consecutive demo runs are clean and deterministic.
"""
from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.agent.scripted_agent import run_demo
from backend.moss_client import PrecedentStore
from backend.proxy import Proxy

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "config/policy.yaml")
THRESH = str(ROOT / "config/thresholds.yaml")
REPORTS = ROOT / "eval/reports"

_store: PrecedentStore | None = None
_cold_load_s: float | None = None   # one-time index load, NOT request latency


async def get_store() -> PrecedentStore:
    global _store, _cold_load_s
    if _store is None:
        s = PrecedentStore()
        t0 = time.perf_counter()
        await s.ensure_ready()
        _cold_load_s = round(time.perf_counter() - t0, 2)
        _store = s
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm indexes so /api/run only ever pays the hot-path (~few ms) query cost.
    await get_store()
    yield


app = FastAPI(title="Sentinel", version="0.3.0", lifespan=lifespan)


@app.get("/api/health")
async def health():
    return {"ok": True, "moss_ready": _store is not None,
            "cold_load_s": _cold_load_s}


def _read_report(name: str):
    p = REPORTS / name
    try:
        return json.loads(p.read_text()) if p.exists() else None
    except Exception:
        return None


@app.get("/api/evidence")
async def evidence():
    """Serve the REAL frozen Phase-2 reports (never fabricated in the UI)."""
    lock = _read_report("../../config/frozen.lock") or {}
    return {
        "ablation": _read_report("ablation.json"),
        "latency": _read_report("latency.json"),
        "causality": _read_report("causality.json"),
        "tests": _read_report("tests.json"),
        "cold_load_s": _cold_load_s,
        "frozen": {"policy": (lock.get("hashes", {}) or {}).get("policy", "")[:12],
                   "thresholds": (lock.get("hashes", {}) or {}).get("thresholds", "")[:12]},
    }


@app.post("/api/run")
async def run(mode: str = "full"):
    store = await get_store()
    proxy = Proxy(store, POLICY, THRESH, mode=mode)
    events = await run_demo(proxy)
    # strip private fields (never expose raw PII rows to the client)
    clean = [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]
    return JSONResponse({
        "mode": mode,
        "policy_hash": proxy.meta["policy_hash"],
        "final_state": proxy.state.value,
        "sink": proxy.registry.sink.counts(),
        "events": clean,
    })


# Serve the basic UI.
app.mount("/", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="ui")


async def _cli():
    """Headless run for verification (no server)."""
    store = await get_store()
    proxy = Proxy(store, POLICY, THRESH)
    events = await run_demo(proxy)
    print("=" * 78)
    for e in events:
        line = f"STEP {e['step']:>1} {e['tool']:<14} -> {e['decision']:<7} | {e['detail']}"
        print(line)
        r = e.get("retrieval")
        if r:
            atk = r["attack"][0] if r["attack"] else {}
            sf = r["safe"][0] if r["safe"] else {}
            print(f"        moss_ran={r['moss_ran']} atk_best={atk.get('score')}({atk.get('id')}) "
                  f"safe_best={sf.get('score')}({sf.get('id')}) "
                  f"raw_drift={r['raw_drift']} drift_ema={r['drift_ema']}")
        if "restriction" in e:
            rr = e["restriction"]
            print(f"        >>> RESTRICT {rr['capability']}: -{rr['removed_data_classes']} "
                  f"(precedent={rr['precedent_id']} family={rr['family']} "
                  f"score={rr['score']} drift={rr['drift']})")
    print("=" * 78)
    print("FINAL STATE:", proxy.state.value)
    print("SINK COUNTS:", proxy.registry.sink.counts())
    for r in proxy.registry.sink.contents():
        p = r["payload"]
        shape = (f"rows x{len(p['rows'])}" if isinstance(p, dict) and "rows" in p
                 else (str(p) if isinstance(p, dict) else type(p).__name__))
        print(f"SINK -> {r['destination']}: {shape}")


if __name__ == "__main__":
    asyncio.run(_cli())
