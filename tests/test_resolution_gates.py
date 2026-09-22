"""Resolution gates G220-G225.

EXECUTION_UNKNOWN was a dead end. The engine is right not to guess whether an
upstream acted — but the only way for a person who *knows* to say so was to
edit the database, which is exactly what the chain exists to catch. And the
reservation stayed held forever, so every unknown outcome permanently shrank
a grant's daily budget.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mandate.cli import main
from mandate.crypto import sign_object, verify_object
from mandate.engine import MandateError
from mandate.executor import ExecutionResult
from mandate.gateway_config import build_engine, load_gateway_config

from .test_execution_recovery import Crashing, _world
from .test_hardening import Clock, _intent

START = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
DAY = "2026-09-20"


def _unknown(tmp_path, amount=600):
    """A grant with a 1000 daily budget and one 600 execution nobody can vouch for."""
    engine, akp, grant = _world(tmp_path, Crashing(RuntimeError("socket closed")), Clock(START))
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=amount))
    assert engine.execute(rec["id"])["outcome"] == "EXECUTION_UNKNOWN"
    return engine, akp, grant, rec


def _budget(engine, grant, day=DAY):
    with engine.ledger.tx() as tx:
        return tx.budget_snapshot_minor(grant["id"], "EUR", day)


def test_g220_a_confirmed_execution_is_signed_chained_and_spends_the_budget(tmp_path):
    engine, _, grant, rec = _unknown(tmp_path)
    assert _budget(engine, grant) == {"reserved": 60000, "committed": 0}

    out = engine.resolve_unknown(
        rec["id"], "EXECUTED", operator="Belkis", reason="ERP shows order 4711 created 12:00:03",
    )

    assert out["outcome"] == "EXECUTED" and verify_object(out)
    resolution = out["execution"]["resolution"]
    assert resolution["from"] == "EXECUTION_UNKNOWN" and resolution["by"] == "Belkis"
    assert "4711" in resolution["reason"]
    assert _budget(engine, grant) == {"reserved": 0, "committed": 60000}
    report = engine.verify_chain(expect_signer=engine.enforcer_did)
    assert report.ok, report.reason
    assert engine.unknown_receipts() == []


def test_g221_a_confirmed_non_execution_gives_the_budget_back(tmp_path):
    """Without resolution the 600 stayed reserved forever, and a 500 order —
    well inside the 1000 daily limit — was refused for the rest of the day."""
    engine, akp, grant, rec = _unknown(tmp_path)
    engine.executor = type("Ok", (), {"forward": lambda self, *a: ExecutionResult("EXECUTED", 200, 1, "h")})()
    blocked = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=500))
    assert blocked["outcome"] == "DENIED"

    engine.resolve_unknown(rec["id"], "EXECUTION_FAILED", operator="Belkis",
                           reason="ERP has no order with this idempotency key")

    assert _budget(engine, grant) == {"reserved": 0, "committed": 0}
    retry = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=500))
    assert retry["outcome"] == "AUTHORIZED"
    assert engine.verify_chain(expect_signer=engine.enforcer_did).ok


def test_g222_only_an_unknown_outcome_can_be_resolved_and_only_once(tmp_path):
    engine, akp, grant, rec = _unknown(tmp_path)
    fine = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=1))

    def refused(match, receipt_id=rec["id"], outcome="EXECUTED", **kw):
        kw.setdefault("operator", "Belkis")
        kw.setdefault("reason", "checked")
        with pytest.raises(MandateError, match=match):
            engine.resolve_unknown(receipt_id, outcome, **kw)

    refused("not EXECUTION_UNKNOWN", receipt_id=fine["id"])
    refused("EXECUTED or EXECUTION_FAILED", outcome="DENIED")
    refused("EXECUTED or EXECUTION_FAILED", outcome="EXECUTION_UNKNOWN")
    refused("operator's name and a reason", operator="  ")
    refused("operator's name and a reason", reason="")
    refused("printable", reason="ok\x1b[2Jcleared")
    refused("limited", reason="x" * 2001)
    refused("not found", tenant="someone-else")
    refused("not found", receipt_id="rcpt_missing")

    engine.resolve_unknown(rec["id"], "EXECUTED", operator="Belkis", reason="confirmed")
    # A second finding, even the opposite one, cannot overwrite the first.
    refused("is EXECUTED, not EXECUTION_UNKNOWN", outcome="EXECUTION_FAILED")
    assert _budget(engine, grant) == {"reserved": 100, "committed": 60000}


def test_g223_a_legacy_receipt_settles_the_day_it_reserved_not_today(tmp_path):
    """Before budget bindings existed, settlement fell back to *today*.

    `execute()` refuses such a receipt before dispatching, so there the
    fallback was dead code. Resolution is where one still arrives: an
    unknown outcome from before bindings, looked into the next morning.
    Settling on today would release a reservation that day never made and
    leave the real one held forever."""
    clock = Clock(START.replace(hour=23, minute=59))
    engine, akp, grant = _world(tmp_path, Crashing(RuntimeError("reset")), clock)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=300))
    unknown = engine.execute(rec["id"])
    assert unknown["outcome"] == "EXECUTION_UNKNOWN"

    # Make it a pre-0.2.1 receipt: no binding, no budget_day anywhere.
    with engine.ledger.tx() as tx:
        tx.l._conn.execute("DELETE FROM budget_bindings WHERE receipt_id=?", (rec["id"],))
        body = {k: v for k, v in unknown.items() if k not in {"proof", "budget_day"}}
        tx.l._conn.execute(
            "UPDATE receipts SET budget_day=NULL, body=? WHERE id=?",
            (json.dumps(sign_object(engine.enforcer, body)), rec["id"]),
        )

    clock.set(START + timedelta(hours=12, minutes=2))  # the next day, 00:01
    resolve = lambda **kw: engine.resolve_unknown(  # noqa: E731
        rec["id"], "EXECUTION_FAILED", operator="Belkis", reason="not in ERP", **kw)
    # Nothing records the day. The receipt's created_at is not it: on the
    # approval path the reservation is made when the human approves.
    with pytest.raises(MandateError, match="name the day it reserved"):
        resolve()
    with pytest.raises(MandateError, match="YYYY-MM-DD"):
        resolve(budget_day="20.09.2026")
    assert engine.unknown_receipts()[0]["id"] == rec["id"], "a refusal must change nothing"

    out = resolve(budget_day=DAY)
    assert out["execution"]["resolution"]["budget_day"] == DAY
    assert _budget(engine, grant, DAY) == {"reserved": 0, "committed": 0}
    assert _budget(engine, grant, "2026-09-21") == {"reserved": 0, "committed": 0}


def test_g225_a_recorded_day_cannot_be_overridden(tmp_path):
    engine, _, _, rec = _unknown(tmp_path)
    with pytest.raises(MandateError, match=f"reserved on {DAY}, not 2026-09-19"):
        engine.resolve_unknown(rec["id"], "EXECUTED", operator="B", reason="r",
                               budget_day="2026-09-19")


def test_g224_an_operator_resolves_from_the_command_line(tmp_path, capsys):
    raw = {
        "store": "state", "auth": {"kind": "open"},
        "routes": [{"audience": "mandate://procurement", "base_url": "https://erp.example.com",
                    "allowed_paths": ["/orders"]}],
    }
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    config = load_gateway_config(path)
    engine = build_engine(config)
    engine.executor = Crashing(TimeoutError("read timed out"))
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    from .test_hardening import _grant

    grant = _grant(engine, person, pkp, agent)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    assert engine.execute(rec["id"])["outcome"] == "EXECUTION_UNKNOWN"
    engine.ledger.close()

    assert main(["gateway", "unknown", "--config", str(path)]) == 0
    listed = capsys.readouterr().out
    assert rec["id"] in listed and "https://erp.example.com/orders" in listed

    args = ["gateway", "resolve", "--config", str(path), "--receipt", rec["id"],
            "--outcome", "failed", "--by", "Belkis", "--reason", "no order in ERP"]
    assert main(args) == 0
    assert "EXECUTION_UNKNOWN -> EXECUTION_FAILED, reservation released" in capsys.readouterr().out
    assert main(args) == 1, "resolving twice must fail"
    assert "not EXECUTION_UNKNOWN" in capsys.readouterr().err

    audit = build_engine(config)
    assert audit.verify_chain(expect_signer=audit.enforcer_did).ok
