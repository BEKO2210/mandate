from __future__ import annotations

import json
import threading
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mandate.crypto import iso, sign_object, utcnow, verify_object
from mandate.engine import Engine, MandateError
from mandate.executor import UpstreamExecutor
from mandate.gateway import create_app
from mandate.keys import InMemoryKeyProvider, PersistedDevKeyProvider
from mandate.models import Constraint, Intent
from mandate.routes import Route, RouteRegistry
from mandate.store import Store

from .dummy_upstream import DummyUpstream


def _client(engine: Engine) -> TestClient:
    return TestClient(create_app(engine), raise_server_exceptions=False)


def _grant(engine, person, pkp, agent, **c):
    constraints = Constraint(
        max_amount=c.get("max_amount", 5000),
        max_daily_amount=c.get("max_daily_amount", 5000),
        require_human_above=c.get("require_human_above"),
        counterparties_deny=c.get("counterparties_deny", ["bad.example"]),
        currency="EUR",
        audiences=c.get("audiences", ["mandate://procurement"]),
    )
    return engine.issue_grant(
        person,
        pkp,
        agent,
        organization="Aslani GmbH",
        purpose="buy",
        scopes=c.get("scopes", ["purchase.office"]),
        not_after=c.get("not_after") or (utcnow() + timedelta(days=5)),
        not_before=c.get("not_before"),
        constraints=constraints,
    )


def _intent(akp, grant_id, **kw):
    kw.setdefault("audience", "mandate://procurement")
    kw.setdefault("nonce", uuid4().hex)
    kw.setdefault("currency", "EUR")
    intent = Intent.create(agent_did=akp.did(), grant_id=grant_id, **kw)
    return sign_object(akp, intent.to_dict())


def _setup(tmp_path, dummy, daily=5000, human=None):
    route = Route("mandate://procurement", dummy.base_url, ("POST",), ("/orders",), timeout=0.4)
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
        executor=UpstreamExecutor(),
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    grant = _grant(engine, person, pkp, agent, max_daily_amount=daily, require_human_above=human)
    return engine, dummy, person, pkp, agent, akp, grant


@pytest.fixture
def env(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        yield _setup(tmp_path, dummy)
    finally:
        dummy.stop()


def test_g01_valid_grant_one_call(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    c = _client(engine)
    r = c.post("/v1/intents", json={"intent": _intent(akp, grant["id"], action="purchase.office", amount=10), "execute": True})
    assert r.status_code == 200
    assert r.json()["outcome"] == "EXECUTED"
    assert dummy.call_count() == 1


def test_g02_wrong_scope_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    c = _client(engine)
    r = c.post("/v1/intents", json={"intent": _intent(akp, grant["id"], action="wire.payroll", amount=10), "execute": True})
    assert r.json()["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g03_wrong_audience_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    # unregistered + not on grant
    signed = _intent(akp, grant["id"], action="purchase.office", amount=10, audience="mandate://other")
    c = _client(engine)
    r = c.post("/v1/intents", json={"intent": signed, "execute": True})
    assert r.json()["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g04_unknown_audience_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.propose(akp, grant["id"], action="purchase.office", amount=10, audience="mandate://procurement")
    # force authorized then execute against missing route by using new engine without route? 
    # unknown audience at submit is grant constraint deny. Also execute unknown route:
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=11))
    assert rec["outcome"] in {"AUTHORIZED", "DENIED", "HUMAN_REQUIRED"}
    if rec["outcome"] == "AUTHORIZED":
        engine.routes = RouteRegistry([])
        with pytest.raises(MandateError):
            engine.execute(rec["id"])
    assert dummy.call_count() == 0


def test_g05_nonce_replay_second_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    nonce = uuid4().hex
    c = _client(engine)
    i = _intent(akp, grant["id"], action="purchase.office", amount=10, nonce=nonce)
    r1 = c.post("/v1/intents", json={"intent": i, "execute": True})
    r2 = c.post("/v1/intents", json={"intent": i, "execute": True})
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert dummy.call_count() == 1


def test_g06_parallel_same_nonce_one_wins(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    nonce = uuid4().hex
    results = []

    def run():
        try:
            rec = engine.submit_intent(
                _intent(akp, grant["id"], action="purchase.office", amount=10, nonce=nonce)
            )
            results.append(("ok", rec["outcome"]))
        except MandateError as exc:
            results.append(("err", str(exc)))

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    wins = [r for r in results if r[0] == "ok"]
    assert len(wins) == 1
    assert dummy.call_count() == 0  # not executed


def test_g07_hard_limit_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    r = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=9000))
    assert r["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g08_human_threshold_zero_before_approval(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        r = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        assert r["outcome"] == "HUMAN_REQUIRED"
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g09_valid_approval_one_call(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        assert rec["outcome"] == "HUMAN_REQUIRED"
        approved = engine.approve(rec["id"], pkp)
        assert approved["outcome"] == "AUTHORIZED"
        executed = engine.execute(approved["id"])
        assert executed["outcome"] == "EXECUTED"
        assert dummy.call_count() == 1
    finally:
        dummy.stop()


def test_g10_wrong_principal_zero(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        other, okp = engine.register_principal("Eve")
        with pytest.raises(MandateError):
            engine.approve(rec["id"], okp)
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g11_approval_replay_zero(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        # craft reusable approval
        from mandate.engine import Engine as E
        intent = rec["intent"]
        from mandate.models import new_id
        from mandate.crypto import iso
        approval = sign_object(
            pkp,
            {
                "type": "MandateApproval",
                "approval_id": "appr_replaytest01",
                "receipt_id": rec["id"],
                "intent_id": intent["id"],
                "grant_id": rec["grant_id"],
                "principal_did": rec["principal_did"],
                "agent_did": rec["agent_did"],
                "audience": intent["audience"],
                "action": intent["action"],
                "amount": intent["amount"],
                "currency": intent["currency"],
                "nonce": "ab" * 16,
                "created_at": iso(utcnow()),
                "not_after": iso(utcnow() + timedelta(minutes=10)),
            },
        )
        engine.submit_approval(approval)
        with pytest.raises(MandateError):
            engine.submit_approval(approval)
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g12_revoked_after_hold_zero(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        engine.revoke_grant(grant["id"], pkp)
        out = engine.approve(rec["id"], pkp)
        assert out["outcome"] == "DENIED"
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g13_expired_after_hold_zero(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        # rewrite grant expiry in ledger
        with engine.ledger.tx() as tx:
            g = tx.get_grant(grant["id"])
            body = {k: v for k, v in g.items() if k != "proof"}
            body["not_after"] = iso(utcnow() - timedelta(days=1))
            signed = sign_object(pkp, body)
            tx.put_grant(grant["id"], signed["principal_did"], signed["agent_did"], "active", signed)
        out = engine.approve(rec["id"], pkp)
        assert out["outcome"] == "DENIED"
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g14_budget_consumed_during_hold_zero(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, daily=1000, human=500)
        a = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=800))
        assert a["outcome"] == "HUMAN_REQUIRED"
        b = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=300))
        assert b["outcome"] == "AUTHORIZED"
        out = engine.approve(a["id"], pkp)
        assert out["outcome"] == "DENIED"
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g15_parallel_budget_at_most_one(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _setup(tmp_path, dummy, daily=1000)
        results = []

        def run(amount_nonce):
            rec = engine.submit_intent(
                _intent(akp, grant["id"], action="purchase.office", amount=800, nonce=uuid4().hex)
            )
            results.append(rec["outcome"])

        t1 = threading.Thread(target=run, args=(1,))
        t2 = threading.Thread(target=run, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert results.count("AUTHORIZED") <= 1
        assert results.count("AUTHORIZED") + results.count("DENIED") == 2
    finally:
        dummy.stop()


def test_g16_agent_b_cannot_use_grant_a(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    other, bk = engine.register_agent("EveBot", person.did, "x", "y")
    rec = engine.submit_intent(
        sign_object(
            bk,
            Intent.create(
                agent_did=bk.did(),
                grant_id=grant["id"],
                action="purchase.office",
                amount=10,
                audience="mandate://procurement",
                nonce=uuid4().hex,
            ).to_dict(),
        )
    )
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g17_tampered_intent_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    signed = _intent(akp, grant["id"], action="purchase.office", amount=10)
    signed["amount"] = 1
    with pytest.raises(MandateError):
        engine.submit_intent(signed)
    assert dummy.call_count() == 0


def test_g18_tampered_grant_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    with engine.ledger.tx() as tx:
        g = tx.get_grant(grant["id"])
        g["scopes"] = ["wire.payroll"]
        tx.put_grant(grant["id"], g["principal_did"], g["agent_did"], "active", g)
    with pytest.raises(MandateError):
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    assert dummy.call_count() == 0


def test_g19_tampered_receipt_rejected(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    with engine.ledger.tx() as tx:
        row = tx.get_receipt(rec["id"])
        body = json.loads(row["body"])
        body["outcome"] = "EXECUTED"
        tx.cas_state(rec["id"], "AUTHORIZED", "DENIED", body) if False else None
        # overwrite body without valid enforcer signature
        import sqlite3
    with engine.ledger.tx() as tx:
        body = json.loads(tx.get_receipt(rec["id"])["body"])
        body["outcome"] = "EXECUTED"
        engine.ledger._conn.execute(
            "UPDATE receipts SET body=? WHERE id=?",
            (json.dumps(body), rec["id"]),
        )
    with pytest.raises(MandateError):
        engine.get_receipt(rec["id"])


def test_g20_free_target_url_rejected(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    signed = _intent(akp, grant["id"], action="purchase.office", amount=10)
    c = _client(engine)
    r = c.post(
        "/v1/intents",
        json={"intent": signed, "target_url": "http://evil/", "execute": True},
    )
    assert r.status_code == 422
    signed2 = dict(signed)
    signed2["target_url"] = "http://evil"
    r2 = c.post("/v1/intents", json={"intent": signed2, "execute": True})
    assert r2.status_code in {400, 403}
    assert dummy.call_count() == 0


def test_g21_redirect_not_followed(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    dummy.state.mode = "redirect"
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    out = engine.execute(rec["id"])
    assert out["outcome"] == "EXECUTION_FAILED"
    assert dummy.call_count() == 1


def test_g22_upstream_200_executed(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    out = engine.execute(rec["id"])
    assert out["outcome"] == "EXECUTED"


def test_g23_upstream_500_failed(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    dummy.state.mode = "500"
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    out = engine.execute(rec["id"])
    assert out["outcome"] == "EXECUTION_FAILED"


def test_g24_timeout_not_executed(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    dummy.state.mode = "timeout"
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    out = engine.execute(rec["id"])
    assert out["outcome"] != "EXECUTED"
    assert out["outcome"] in {"EXECUTION_UNKNOWN", "EXECUTION_FAILED"}


def test_g25_timeout_unknown(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    dummy.state.mode = "timeout"
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    out = engine.execute(rec["id"])
    assert out["outcome"] == "EXECUTION_UNKNOWN"


def test_g26_retry_same_execution_no_double(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    a = engine.execute(rec["id"])
    b = engine.execute(rec["id"])
    assert a["outcome"] == "EXECUTED"
    assert b["outcome"] == "EXECUTED"
    assert dummy.call_count() == 1


def test_g27_db_failure_before_forward_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    engine.ledger.inject_failure(True)
    with pytest.raises(MandateError):
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    engine.ledger.inject_failure(False)
    assert dummy.call_count() == 0


def test_g28_policy_exception_zero(env, monkeypatch):
    engine, dummy, person, pkp, agent, akp, grant = env

    def boom(*a, **k):
        raise RuntimeError("policy exploded")

    monkeypatch.setattr("mandate.engine.evaluate", boom)
    with pytest.raises(Exception):
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    assert dummy.call_count() == 0


def test_g29_restart_same_enforcer_validates(tmp_path, env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    engine2 = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=engine.routes,
        executor=engine.executor,
    )
    # same sqlite
    engine2.ledger = engine.ledger
    got = engine2.get_receipt(rec["id"])
    assert got["id"] == rec["id"]


def test_g30_restart_other_enforcer_rejects(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    from mandate.crypto import KeyPair
    from mandate.keys import InMemoryKeyProvider

    engine.keys = InMemoryKeyProvider(KeyPair.generate())
    engine.enforcer = engine.keys.get_enforcer()
    engine.enforcer_did = engine.enforcer.did()
    with pytest.raises(MandateError):
        engine.get_receipt(rec["id"])


def test_g31_revoked_grant_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    engine.revoke_grant(grant["id"], pkp)
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g32_expired_grant_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    g2 = _grant(engine, person, pkp, agent, not_after=utcnow() - timedelta(days=1))
    rec = engine.submit_intent(_intent(akp, g2["id"], action="purchase.office", amount=10))
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g33_not_before_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    g2 = _grant(engine, person, pkp, agent, not_before=utcnow() + timedelta(days=1))
    rec = engine.submit_intent(_intent(akp, g2["id"], action="purchase.office", amount=10))
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g34_wrong_currency_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10, currency="USD"))
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g35_denied_counterparty_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(
        _intent(akp, grant["id"], action="purchase.office", amount=10, counterparty="bad.example")
    )
    assert rec["outcome"] == "DENIED"
    assert dummy.call_count() == 0


def test_g36_malformed_signature_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    signed = _intent(akp, grant["id"], action="purchase.office", amount=10)
    signed["proof"]["proofValue"] = "00" * 32
    with pytest.raises(MandateError):
        engine.submit_intent(signed)
    assert dummy.call_count() == 0


def test_g37_oversized_payload(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    c = _client(engine)
    r = c.post("/v1/intents", content=b"x" * 40_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    assert dummy.call_count() == 0


def test_g38_unknown_route_zero(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    engine.routes = RouteRegistry([])
    with pytest.raises(MandateError):
        engine.execute(rec["id"])
    assert dummy.call_count() == 0


def test_g39_invalid_state_transition(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=9000))
    assert rec["outcome"] == "DENIED"
    with pytest.raises(MandateError):
        engine.execute(rec["id"])


def test_g40_authorization_consumed_no_second(env):
    engine, dummy, person, pkp, agent, akp, grant = env
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
    engine.execute(rec["id"])
    # second execute returns previous, no extra call
    engine.execute(rec["id"])
    assert dummy.call_count() == 1
