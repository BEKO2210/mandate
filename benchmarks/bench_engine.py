"""How long a decision takes, and how many a ledger file can take.

    python benchmarks/bench_engine.py --requests 2000 --procs 1,4,8

Every request is what the gateway does for an agent: verify and evaluate a
signed intent, reserve budget, sign a receipt, chain it (`submit_intent`),
then claim the execution, call the upstream and record the result, signed and
chained again (`execute`). The upstream is a stub that answers at once, so
the numbers are Mandate's own cost — no network, no upstream latency.

Workers are separate processes on one SQLite file, as gateway workers are.
Signing the intent is the agent's work and is not timed.

The numbers are for this machine only. Run it where you would deploy before
quoting any of them.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mandate.crypto import KeyPair, sign_object, utcnow  # noqa: E402
from mandate.engine import Engine  # noqa: E402
from mandate.executor import ExecutionResult  # noqa: E402
from mandate.keys import PersistedDevKeyProvider  # noqa: E402
from mandate.ledger import Ledger  # noqa: E402
from mandate.models import Constraint, Intent  # noqa: E402
from mandate.routes import Operation, Route, RouteRegistry  # noqa: E402

AUDIENCE = "mandate://bench"


class StubExecutor:
    """An upstream that answers at once, so only Mandate is measured."""

    def forward(self, route, method, path, body, idempotency_key):
        return ExecutionResult("EXECUTED", 200, 0, "sha256:" + "0" * 64)


def _engine(store: Path) -> Engine:
    route = Route(
        AUDIENCE, "https://api.example.com", ("POST",), ("/orders",),
        operations=(Operation("purchase.office", "POST", "/orders"),),
    )
    return Engine(
        ledger=Ledger(store / "mandate.sqlite"),
        key_provider=PersistedDevKeyProvider(store / "enforcer-keys"),
        routes=RouteRegistry([route]),
        executor=StubExecutor(),
    )


def setup(store: Path) -> dict:
    engine = _engine(store)
    person, pkp = engine.register_principal("Bench Principal")
    org, _ = engine.register_principal("Bench Org", kind="org")
    agent, akp = engine.register_agent("BenchBot", org.did, "bench", "d")
    grant = engine.issue_grant(
        person, pkp, agent, organization="Bench Org", purpose="benchmark",
        scopes=["purchase.office"], not_after=utcnow() + timedelta(days=1),
        constraints=Constraint(
            currency="EUR", max_amount=10, max_daily_amount=10**9,
            audiences=[AUDIENCE], counterparties_deny=["denied.example"],
        ),
    )
    engine.ledger.close()
    return {"grant_id": grant["id"], "agent_key": akp.private_bytes().hex()}


def _intent(akp: KeyPair, grant_id: str, deny: bool) -> dict:
    intent = Intent.create(
        agent_did=akp.did(), grant_id=grant_id, action="purchase.office",
        amount=1, currency="EUR", audience=AUDIENCE, nonce=uuid4().hex,
        counterparty="denied.example" if deny else "paper.example",
    )
    return sign_object(akp, intent.to_dict())


def worker(store: str, state: dict, requests: int, scenario: str, warmup: int, start, out) -> None:
    engine = _engine(Path(store))
    akp = KeyPair.from_private_bytes(bytes.fromhex(state["agent_key"]))
    submit, execute, total, errors, outcomes = [], [], [], [], {}

    def one(i: int, record: bool) -> None:
        deny = scenario == "deny" or (scenario == "mixed" and i % 2)
        signed = _intent(akp, state["grant_id"], deny)
        t0 = time.perf_counter_ns()
        try:
            rec = engine.submit_intent(signed)
            t1 = time.perf_counter_ns()
            outcome = rec["outcome"]
            if outcome == "AUTHORIZED":
                outcome = engine.execute(rec["id"], idempotency_key=uuid4().hex)["outcome"]
            t2 = time.perf_counter_ns()
        except Exception as exc:  # counted, never hidden
            if record:
                errors.append(f"{type(exc).__name__}: {exc}")
            return
        if record:
            submit.append(t1 - t0)
            if t2 > t1 and outcome == "EXECUTED":
                execute.append(t2 - t1)
            total.append(t2 - t0)
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

    for i in range(warmup):
        one(i, record=False)
    start.wait()
    began = time.perf_counter()
    for i in range(requests):
        one(i, record=True)
    out.put({
        "submit": submit, "execute": execute, "total": total,
        "errors": errors, "outcomes": outcomes, "seconds": time.perf_counter() - began,
    })
    engine.ledger.close()


def percentiles(ns: list[int]) -> dict:
    if not ns:
        return {}
    ordered = sorted(ns)

    def rank(p: float) -> float:
        # Nearest rank: a percentile that is an actual observation.
        return ordered[max(0, min(len(ordered) - 1, round(p / 100 * len(ordered)) - 1))] / 1e6

    return {
        "p50_ms": rank(50), "p95_ms": rank(95), "p99_ms": rank(99),
        "max_ms": ordered[-1] / 1e6, "mean_ms": statistics.fmean(ordered) / 1e6,
    }


def run(procs: int, requests: int, scenario: str, warmup: int, base: Path | None) -> dict:
    store = Path(tempfile.mkdtemp(prefix="mandate-bench-", dir=base))
    state = setup(store)
    ctx = multiprocessing.get_context("spawn")
    start, out = ctx.Barrier(procs), ctx.Queue()
    workers = [
        ctx.Process(target=worker, args=(str(store), state, requests, scenario, warmup, start, out))
        for _ in range(procs)
    ]
    for w in workers:
        w.start()
    results = [out.get(timeout=600) for _ in workers]
    for w in workers:
        w.join(timeout=60)
    merged = {key: [v for r in results for v in r[key]] for key in ("submit", "execute", "total", "errors")}
    outcomes: dict[str, int] = {}
    for r in results:
        for k, v in r["outcomes"].items():
            outcomes[k] = outcomes.get(k, 0) + v
    wall = max(r["seconds"] for r in results)
    done = len(merged["total"])
    return {
        "procs": procs,
        "requests": procs * requests,
        "completed": done,
        "throughput_per_s": round(done / wall, 1) if wall else None,
        "outcomes": outcomes,
        "errors": len(merged["errors"]),
        "error_kinds": sorted({e.split(":")[0] for e in merged["errors"]}),
        "submit_intent": percentiles(merged["submit"]),
        "execute": percentiles(merged["execute"]),
        "total": percentiles(merged["total"]),
        "store": str(store),
    }


def _mount_type(path: Path) -> str:
    try:
        best, kind = "", "?"
        for line in Path("/proc/mounts").read_text().splitlines():
            _, mount, fstype, *_ = line.split()
            if str(path.resolve()).startswith(mount) and len(mount) > len(best):
                best, kind = mount, fstype
        return kind
    except OSError:
        return "?"


def machine(base: Path) -> dict:
    cpu = "?"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    probe = sqlite3.connect(":memory:")
    return {
        "platform": platform.platform(),
        "cpu": cpu,
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "sqlite_default_synchronous": probe.execute("PRAGMA synchronous").fetchone()[0],
        "store_filesystem": _mount_type(base),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--requests", type=int, default=1000, help="per worker")
    parser.add_argument("--procs", default="1,4", help="comma-separated worker counts")
    parser.add_argument("--scenario", choices=["allow", "deny", "mixed"], default="allow")
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--store", default=None, help="directory for the ledgers (default: system temp)")
    parser.add_argument("--json", default=None, help="write the results here as JSON")
    args = parser.parse_args(argv)

    base = Path(args.store) if args.store else Path(tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    info = machine(base)
    if info["store_filesystem"] in {"tmpfs", "ramfs"}:
        print(f"note: {base} is {info['store_filesystem']}; fsync costs nothing there, "
              "so these numbers flatter a disk-backed ledger", file=sys.stderr)
    runs = [run(int(p), args.requests, args.scenario, args.warmup, base) for p in args.procs.split(",")]

    print(f"{info['cpu']} ({info['cpus']} CPUs), Python {info['python']}, SQLite {info['sqlite']}, "
          f"store on {info['store_filesystem']}; scenario {args.scenario}")
    print(f"{'procs':>5} {'done':>7} {'req/s':>8} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'max ms':>8}  errors")
    for r in runs:
        t = r["total"]
        print(f"{r['procs']:>5} {r['completed']:>7} {r['throughput_per_s']:>8} "
              f"{t.get('p50_ms', 0):>8.2f} {t.get('p95_ms', 0):>8.2f} {t.get('p99_ms', 0):>8.2f} "
              f"{t.get('max_ms', 0):>8.2f}  {r['errors']} {','.join(r['error_kinds'])}")
    if args.json:
        Path(args.json).write_text(json.dumps({"machine": info, "scenario": args.scenario, "runs": runs}, indent=2))
    return 0 if all(r["errors"] == 0 for r in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
