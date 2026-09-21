"""v0.2.2 recovery gates G64-G67.

In 0.2.1 a process that died inside forward() left the receipt in EXECUTING
forever, while the signed body still said AUTHORIZED and a retry handed that
body back as if nothing had been dispatched. Authorization must never be
reported for a request that may already have left the building.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from mandate.engine import Engine, MandateError
from mandate.executor import ExecutionResult
from mandate.keys import PersistedDevKeyProvider
from mandate.routes import Route, RouteRegistry
from mandate.store import Store

from .test_hardening import Clock, _grant, _intent

START = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


class Crashing:
    """Raises out of forward() the way an unhandled error or a signal would."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls = 0

    def forward(self, *args, **kwargs):
        self.calls += 1
        raise self.exc


def _world(tmp_path, executor, clock):
    route = Route("mandate://procurement", "http://127.0.0.1:9/", ("POST",), ("/orders",))
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
        executor=executor,
        clock=clock,
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    grant = _grant(engine, person, pkp, agent)
    return engine, akp, grant


def _state(engine, receipt_id):
    with engine.ledger.tx() as tx:
        row = tx.get_receipt(receipt_id)
    return row["state"], json.loads(row["body"])["outcome"]


def test_g64_executor_error_ends_as_unknown_not_authorized(tmp_path):
    clock = Clock(START)
    engine, akp, grant = _world(tmp_path, Crashing(RuntimeError("boom")), clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    assert rec["outcome"] == "AUTHORIZED"

    out = engine.execute(rec["id"])

    assert out["outcome"] == "EXECUTION_UNKNOWN"
    assert _state(engine, rec["id"]) == ("EXECUTION_UNKNOWN", "EXECUTION_UNKNOWN")
    with engine.ledger.tx() as tx:
        # An unknown outcome keeps the reservation; the money is not free again.
        assert tx.spent(grant["id"], "EUR", "2026-09-20") == 1000
    assert engine.execute(rec["id"])["outcome"] == "EXECUTION_UNKNOWN"


def test_g65_stored_body_never_claims_authorized_while_executing(tmp_path):
    clock = Clock(START)
    # BaseException escapes the engine the way SIGINT would: the claim is
    # committed, the process is gone, nothing closes the receipt.
    engine, akp, grant = _world(tmp_path, Crashing(KeyboardInterrupt()), clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    with pytest.raises(KeyboardInterrupt):
        engine.execute(rec["id"])

    state, outcome = _state(engine, rec["id"])
    assert state == "EXECUTING"
    assert outcome == "EXECUTING"  # 0.2.1 stored AUTHORIZED here
    # The signed body a reader gets back must agree with the ledger.
    assert engine.get_receipt(rec["id"])["outcome"] == "EXECUTING"


def test_g66_stale_claim_is_reconciled_to_unknown(tmp_path):
    clock = Clock(START)
    engine, akp, grant = _world(tmp_path, Crashing(KeyboardInterrupt()), clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    with pytest.raises(KeyboardInterrupt):
        engine.execute(rec["id"])

    # Still in flight as far as this engine knows.
    assert engine.reconcile_stale_executions() == []
    assert _state(engine, rec["id"])[0] == "EXECUTING"

    clock.set(START + timedelta(seconds=engine.execution_stale_after_s + 1))
    assert engine.reconcile_stale_executions() == [rec["id"]]

    assert _state(engine, rec["id"]) == ("EXECUTION_UNKNOWN", "EXECUTION_UNKNOWN")
    with engine.ledger.tx() as tx:
        assert tx.spent(grant["id"], "EUR", "2026-09-20") == 1000
        assert tx.get_execution_by_receipt(rec["id"])["state"] == "EXECUTION_UNKNOWN"
    # Reconciling twice is a no-op, and the claim stays single-use.
    assert engine.reconcile_stale_executions() == []


def test_g67_retry_of_a_stale_claim_never_returns_authorized(tmp_path):
    clock = Clock(START)
    crashing = Crashing(KeyboardInterrupt())
    engine, akp, grant = _world(tmp_path, crashing, clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    with pytest.raises(KeyboardInterrupt):
        engine.execute(rec["id"])

    clock.set(START + timedelta(seconds=engine.execution_stale_after_s + 1))
    out = engine.execute(rec["id"])

    assert out["outcome"] == "EXECUTION_UNKNOWN"
    assert crashing.calls == 1  # no second dispatch
    assert _state(engine, rec["id"]) == ("EXECUTION_UNKNOWN", "EXECUTION_UNKNOWN")


def test_g68_legacy_float_budget_rows_migrate_to_minor_units(tmp_path):
    path = tmp_path / "legacy.sqlite"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE budget (
          grant_id TEXT NOT NULL, currency TEXT NOT NULL, day TEXT NOT NULL,
          reserved REAL NOT NULL DEFAULT 0, committed REAL NOT NULL DEFAULT 0,
          PRIMARY KEY (grant_id, currency, day)
        );
        """
    )
    con.execute(
        "INSERT INTO budget(grant_id, currency, day, reserved, committed) VALUES (?,?,?,?,?)",
        ("g", "EUR", "2026-09-19", 0.9999999999999999, 12.30),
    )
    con.commit()
    con.close()

    from mandate.ledger import Ledger

    led = Ledger(path)
    try:
        with led.tx() as tx:
            snap = tx.budget_snapshot_minor("g", "EUR", "2026-09-19")
        assert snap == {"reserved": 100, "committed": 1230}
    finally:
        led.close()


def test_g69_executor_result_is_not_bypassed_by_a_missing_binding(tmp_path):
    clock = Clock(START)

    class Ok:
        def forward(self, *args, **kwargs):
            return ExecutionResult("EXECUTED", 200, 3, "hash")

    engine, akp, grant = _world(tmp_path, Ok(), clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    with engine.ledger.tx() as tx:
        tx.l._conn.execute("DELETE FROM budget_bindings WHERE receipt_id=?", (rec["id"],))
    with pytest.raises(MandateError):
        engine.execute(rec["id"])
    assert _state(engine, rec["id"])[0] == "AUTHORIZED"
