VENV=.venv/bin
.PHONY: install run demo test rebuild-index spike gen validate tune freeze eval latency phase2

install:
	python3.12 -m venv .venv && $(VENV)/pip install -q -U pip && $(VENV)/pip install -q -r requirements.txt

run:            ## serve the console at http://127.0.0.1:8011
	$(VENV)/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8011

demo:           ## headless run of the demo trajectory (prints the causal chain)
	$(VENV)/python -m backend.app

test:
	$(VENV)/python -m pytest

rebuild-index:  ## delete + recreate the Moss indexes from the corpus
	$(VENV)/python -c "import asyncio; from backend.moss_client import PrecedentStore; \
	asyncio.run(PrecedentStore().ensure_ready(rebuild=True))"

spike:          ## re-run the Phase-0 Moss verification spike
	$(VENV)/python scripts/moss_spike.py

# --- Phase 2: corpus + evaluation pipeline ---
gen:            ## (re)generate the corpus + held-out/dev scenarios
	$(VENV)/python -m scripts.generate_variants

validate:       ## leakage / near-duplicate checks (INV-6)
	$(VENV)/python -m scripts.validate_corpus

tune:           ## tune drift threshold on dev benign ONLY (INV-7)
	$(VENV)/python -m eval.tune_thresholds

freeze:         ## hash policy/thresholds/corpus into config/frozen.lock (INV-5)
	$(VENV)/python -m eval.freeze

eval:           ## three-way ablation over held-out (A/B/C)
	$(VENV)/python -m eval.run_eval

latency:        ## 1000-query in-loop retrieval latency (p50/p95/p99)
	$(VENV)/python -m eval.latency_bench

verify:         ## causality checks: precedent-necessity, hard-negative, family routing
	$(VENV)/python -m eval.verify_causality

tests-report:   ## run tests and record counts for the evidence panel
	$(VENV)/python -m eval.collect_tests

evidence: eval latency verify tests-report  ## regenerate all evidence report files

phase2: gen validate rebuild-index tune freeze eval latency verify tests-report  ## full pipeline
