"""Freeze + hash the evaluation configuration (INV-5, INV-7).

Writes config/frozen.lock with sha256 hashes of the policy, thresholds, and the
indexed corpus. Every evaluation report embeds these hashes so results are tied to
an exact, immutable configuration. Re-run after any intentional config change.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "policy": "config/policy.yaml",
    "thresholds": "config/thresholds.yaml",
    "attack_corpus": "corpus/attack_trajectories.jsonl",
    "safe_corpus": "corpus/safe_trajectories.jsonl",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute() -> dict:
    return {k: sha(ROOT / v) for k, v in FILES.items()}


def main():
    hashes = compute()
    lock = {"frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hashes": hashes, "files": FILES}
    (ROOT / "config/frozen.lock").write_text(json.dumps(lock, indent=2) + "\n")
    print("FROZEN:")
    for k, v in hashes.items():
        print(f"  {k:16} {v[:16]}")


if __name__ == "__main__":
    main()
