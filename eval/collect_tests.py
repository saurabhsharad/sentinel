"""Run the test suite in-process and record the real pass/fail counts to
eval/reports/tests.json. No hardcoded numbers; the evidence panel shows what ran."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class _Recorder:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            if report.passed:
                self.passed += 1
            elif report.failed:
                self.failed += 1


def main():
    rec = _Recorder()
    code = pytest.main(["-q", str(ROOT / "tests")], plugins=[rec])
    report = {"passed": rec.passed, "failed": rec.failed,
              "total": rec.passed + rec.failed,
              "ok": rec.failed == 0 and rec.passed > 0, "exit_code": int(code)}
    (ROOT / "eval/reports/tests.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
