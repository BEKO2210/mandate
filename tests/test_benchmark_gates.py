"""Benchmark gate G265.

docs/PERFORMANCE.md quotes numbers from benchmarks/bench_engine.py. The
script has to keep running, keep measuring what it says it measures, and
keep counting errors rather than dropping them — the numbers are never a
gate, the method is.
"""

from __future__ import annotations

import json
import subprocess
import sys


def test_g265_the_benchmark_runs_and_accounts_for_every_request(tmp_path):
    out = tmp_path / "bench.json"
    done = subprocess.run(
        [sys.executable, "benchmarks/bench_engine.py", "--requests", "15", "--procs", "1,2",
         "--warmup", "2", "--scenario", "mixed", "--store", str(tmp_path), "--json", str(out)],
        capture_output=True, text=True, timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    report = json.loads(out.read_text())
    assert [r["procs"] for r in report["runs"]] == [1, 2]
    for run in report["runs"]:
        assert run["errors"] == 0
        assert run["completed"] == run["requests"] == 15 * run["procs"]
        # Mixed: each worker denies every odd request (7 of 15) and executes the rest.
        assert run["outcomes"] == {"EXECUTED": 8 * run["procs"], "DENIED": 7 * run["procs"]}
        for part in ("submit_intent", "execute", "total"):
            p = run[part]
            assert 0 < p["p50_ms"] <= p["p95_ms"] <= p["p99_ms"] <= p["max_ms"], (part, p)
    assert report["machine"]["sqlite"] and report["machine"]["python"]
