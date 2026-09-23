"""Fail-closed gates G249-G252.

Two defaults that let a request through when a field was simply absent.

An approval without `created_at` was treated as created now, so a signed
approval kept forever stayed usable: the same fault v0.9.0 closed for
intents, left open one call later. And a grant's counterparty allow-list
was consulted only when the intent named a counterparty; a tool call that
left the vendor out passed the list it was meant to be held to.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from mandate.crypto import iso, sign_object, utcnow
from mandate.engine import MandateError
from mandate.models import Constraint

from .dummy_upstream import DummyUpstream
from .test_mcp_gates import CONFIG, FakeUpstream, _config, _world
from .test_security_gates import _intent, _setup


def _approval(rec, pkp, **overrides):
    intent = rec["intent"]
    body = {
        "type": "MandateApproval",
        "approval_id": "appr_" + "c" * 24,
        "receipt_id": rec["id"],
        "intent_id": intent["id"],
        "grant_id": rec["grant_id"],
        "principal_did": rec["principal_did"],
        "agent_did": rec["agent_did"],
        "audience": intent["audience"],
        "action": intent["action"],
        "amount": intent["amount"],
        "currency": intent["currency"],
        "nonce": "cd" * 16,
        "created_at": iso(utcnow()),
        "not_after": iso(utcnow() + timedelta(minutes=10)),
    }
    body.update(overrides)
    return sign_object(pkp, {k: v for k, v in body.items() if v is not None})


@pytest.fixture
def held(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, _, pkp, _, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        assert rec["outcome"] == "HUMAN_REQUIRED"
        yield engine, dummy, pkp, rec
    finally:
        dummy.stop()


def _state(engine, rec):
    with engine.ledger.tx() as tx:
        return tx.get_receipt(rec["id"])["state"]


def test_g249_an_approval_without_a_creation_time_is_refused(held):
    engine, dummy, pkp, rec = held
    undated = _approval(rec, pkp, created_at=None, not_after=None)

    with pytest.raises(MandateError, match="created_at is required"):
        engine.submit_approval(undated)

    assert _state(engine, rec) == "HUMAN_REQUIRED"
    assert dummy.call_count() == 0


def test_g250_a_stale_or_malformed_approval_is_refused_not_crashed(held):
    engine, dummy, pkp, rec = held
    stale = _approval(rec, pkp, created_at=iso(utcnow() - timedelta(minutes=11)), not_after=None)
    with pytest.raises(MandateError, match="approval not fresh"):
        engine.submit_approval(stale)

    # A malformed expiry used to escape as a ValueError, a 500 at the gateway.
    malformed = _approval(rec, pkp, approval_id="appr_" + "d" * 24, not_after="tomorrow")
    with pytest.raises(MandateError, match="invalid approval: not_after"):
        engine.submit_approval(malformed)

    assert _state(engine, rec) == "HUMAN_REQUIRED"
    assert dummy.call_count() == 0


def test_g251_an_allow_list_is_not_passed_by_leaving_the_counterparty_out(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, _ = _setup(tmp_path, dummy)
        grant = engine.issue_grant(
            person, pkp, agent, organization="Aslani GmbH", purpose="buy",
            scopes=["purchase.office"], not_after=utcnow() + timedelta(days=1),
            constraints=Constraint(
                max_amount=500, max_daily_amount=500, currency="EUR",
                audiences=["mandate://procurement"],
                counterparties_allow=["paper-co.example"],
            ),
        )
        unnamed = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
        named = engine.submit_intent(_intent(
            akp, grant["id"], action="purchase.office", amount=10, counterparty="paper-co.example",
        ))
        moves_no_money = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office"))
    finally:
        dummy.stop()

    assert unnamed["outcome"] == "DENIED"
    assert "counterparty required by the grant's allow-list" in unnamed["decision"]["reasons"]
    assert named["outcome"] == "AUTHORIZED", named["decision"]["reasons"]
    # The list names who may be paid; a call that pays nobody is not its to refuse.
    assert moves_no_money["outcome"] == "AUTHORIZED", moves_no_money["decision"]["reasons"]


def test_g252_a_tool_call_without_its_counterparty_is_not_signed(tmp_path):
    upstream = FakeUpstream()
    _, engine, _, guard = _world(tmp_path, upstream)

    for args in (
        {"amount": 10, "currency": "EUR"},                    # vendor absent
        {"amount": 10, "currency": "EUR", "vendor": ""},      # vendor empty
        {"amount": 10, "currency": "EUR", "vendor": "x" * 300},  # would be cut to fit
    ):
        decision = guard.call("pay_invoice", args)
        assert decision.outcome == "UNMAPPED", (args, decision.text)
        assert decision.receipt_id is None

    assert upstream.calls == []
    with engine.ledger.tx() as tx:
        assert tx.l._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0
    assert CONFIG["tools"]["pay_invoice"]["counterparty_from"] == "vendor"
    assert _config(tmp_path).mapping.rules["pay_invoice"].counterparty_from == "vendor"
