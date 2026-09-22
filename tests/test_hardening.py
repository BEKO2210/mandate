"""v0.2.1 security hardening gates G41-G57 plus red-team extras."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mandate.crypto import sign_object, utcnow
from mandate.engine import Engine, MandateError
from mandate.executor import UpstreamExecutor, assert_safe_destination
from mandate.auth import OpenAccess
from mandate.gateway import create_app
from mandate.keys import PersistedDevKeyProvider
from mandate.models import Constraint, Intent
from mandate.routes import Route, RouteRegistry
from mandate.store import Store
from mandate.validate import MAX_BODY

from .dummy_upstream import DummyUpstream


class Clock:
    def __init__(self, when: datetime) -> None:
        self.when = when

    def __call__(self) -> datetime:
        return self.when

    def set(self, when: datetime) -> None:
        self.when = when


def _grant(engine, person, pkp, agent, **c):
    constraints = Constraint(
        max_amount=c.get("max_amount", 5000),
        max_daily_amount=c.get("max_daily_amount", 1000),
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


def _world(tmp_path, dummy, clock=None, human=None, daily=1000, policy="allow_private"):
    route = Route(
        "mandate://procurement",
        dummy.base_url,
        ("POST",),
        ("/orders",),
        timeout=0.4,
        network_policy=policy,
    )
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
        executor=UpstreamExecutor(),
        clock=clock,
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    grant = _grant(engine, person, pkp, agent, max_daily_amount=daily, require_human_above=human)
    return engine, dummy, person, pkp, agent, akp, grant


PRE = datetime(2026, 9, 19, 23, 59, 50, tzinfo=timezone.utc)
POST = datetime(2026, 9, 20, 0, 0, 2, tzinfo=timezone.utc)


def test_g41_commit_stays_on_authorization_day(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        clock = Clock(PRE)
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, clock=clock)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=800))
        assert rec["outcome"] == "AUTHORIZED"
        assert rec["budget_day"] == "2026-09-19"
        with engine.ledger.tx() as tx:
            snap = tx.budget_snapshot(grant["id"], "EUR", "2026-09-19")
            assert snap["reserved"] == 800
            assert snap["committed"] == 0
        clock.set(POST)
        out = engine.execute(rec["id"])
        assert out["outcome"] == "EXECUTED"
        with engine.ledger.tx() as tx:
            old = tx.budget_snapshot(grant["id"], "EUR", "2026-09-19")
            new = tx.budget_snapshot(grant["id"], "EUR", "2026-09-20")
        assert old["reserved"] == 0
        assert old["committed"] == 800
        assert new["reserved"] == 0
        assert new["committed"] == 0
        assert dummy.call_count() == 1
    finally:
        dummy.stop()


def test_g42_failed_execution_releases_original_day(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        clock = Clock(PRE)
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, clock=clock)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=800))
        dummy.state.mode = "500"
        clock.set(POST)
        out = engine.execute(rec["id"])
        assert out["outcome"] == "EXECUTION_FAILED"
        with engine.ledger.tx() as tx:
            old = tx.budget_snapshot(grant["id"], "EUR", "2026-09-19")
            new = tx.budget_snapshot(grant["id"], "EUR", "2026-09-20")
        assert old["reserved"] == 0
        assert old["committed"] == 0
        assert new["reserved"] == 0 and new["committed"] == 0
    finally:
        dummy.stop()


def test_g43_unknown_holds_original_day(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        clock = Clock(PRE)
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, clock=clock)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=800))
        dummy.state.mode = "timeout"
        clock.set(POST)
        out = engine.execute(rec["id"])
        assert out["outcome"] == "EXECUTION_UNKNOWN"
        with engine.ledger.tx() as tx:
            old = tx.budget_snapshot(grant["id"], "EUR", "2026-09-19")
            new = tx.budget_snapshot(grant["id"], "EUR", "2026-09-20")
        assert old["reserved"] == 800
        assert old["committed"] == 0
        assert new["reserved"] == 0 and new["committed"] == 0
    finally:
        dummy.stop()


def test_g44_human_approval_binds_reservation_day(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        clock = Clock(PRE)
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, clock=clock, human=50)
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=80))
        assert rec["outcome"] == "HUMAN_REQUIRED"
        approved = engine.approve(rec["id"], pkp)
        assert approved["outcome"] == "AUTHORIZED"
        assert approved["budget_day"] == "2026-09-19"
        clock.set(POST)
        out = engine.execute(approved["id"])
        assert out["outcome"] == "EXECUTED"
        with engine.ledger.tx() as tx:
            old = tx.budget_snapshot(grant["id"], "EUR", "2026-09-19")
            new = tx.budget_snapshot(grant["id"], "EUR", "2026-09-20")
        assert old["committed"] == 80
        assert old["reserved"] == 0
        assert new["committed"] == 0
    finally:
        dummy.stop()


def test_g45_default_route_blocks_loopback(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, policy="public")
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
        assert rec["outcome"] == "AUTHORIZED"
        out = engine.execute(rec["id"])
        assert out["outcome"] == "EXECUTION_FAILED"
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g46_allow_private_permits_test_upstream(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, policy="allow_private")
        rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=10))
        out = engine.execute(rec["id"])
        assert out["outcome"] == "EXECUTED"
        assert dummy.call_count() == 1
    finally:
        dummy.stop()


def test_g47_metadata_ipv4_blocked():
    route = Route("mandate://x", "http://169.254.169.254", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://169.254.169.254/orders", route)
    route2 = Route("mandate://x", "http://169.254.169.254", network_policy="allow_private")
    with pytest.raises(ValueError):
        assert_safe_destination("http://169.254.169.254/orders", route2)


def test_g48_ipv6_loopback_blocked():
    route = Route("mandate://x", "http://[::1]", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://[::1]/orders", route)


def test_g49_hostname_all_private_blocked(monkeypatch):
    def fake_gai(host, port, *a, **k):
        return [(2, 1, 6, "", ("10.1.2.3", port))]

    monkeypatch.setattr("mandate.executor.socket.getaddrinfo", fake_gai)
    route = Route("mandate://x", "http://internal.example", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://internal.example/orders", route)


def test_g50_mixed_public_private_fail_closed(monkeypatch):
    def fake_gai(host, port, *a, **k):
        return [
            (2, 1, 6, "", ("93.184.216.34", port)),
            (2, 1, 6, "", ("192.168.1.8", port)),
        ]

    monkeypatch.setattr("mandate.executor.socket.getaddrinfo", fake_gai)
    route = Route("mandate://x", "http://mixed.example", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://mixed.example/orders", route)


def test_g51_agent_cannot_override_network_policy(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy, policy="public")
        signed = _intent(akp, grant["id"], action="purchase.office", amount=10)
        signed["network_policy"] = "allow_private"
        c = TestClient(create_app(engine, auth=OpenAccess()), raise_server_exceptions=False)
        r = c.post("/v1/intents", json={"intent": signed, "execute": True})
        assert r.status_code in {400, 403}
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g52_registered_public_destination_allowed(monkeypatch):
    def fake_gai(host, port, *a, **k):
        return [(2, 1, 6, "", ("93.184.216.34", port or 443))]

    monkeypatch.setattr("mandate.executor.socket.getaddrinfo", fake_gai)
    route = Route("mandate://x", "https://example.com", network_policy="public")
    ips = assert_safe_destination("https://example.com/orders", route)
    assert "93.184.216.34" in ips


def test_g53_content_length_over_limit_skips_engine(tmp_path):
    dummy = DummyUpstream()
    dummy.start()
    try:
        engine, dummy, person, pkp, agent, akp, grant = _world(tmp_path, dummy)
        hits = {"n": 0}
        orig = engine.submit_intent

        def wrapped(intent):
            hits["n"] += 1
            return orig(intent)

        engine.submit_intent = wrapped  # type: ignore[method-assign]
        c = TestClient(create_app(engine, auth=OpenAccess()), raise_server_exceptions=False)
        r = c.post(
            "/v1/intents",
            content=b"x" * (MAX_BODY + 50),
            headers={"Content-Type": "application/json", "Content-Length": str(MAX_BODY + 50)},
        )
        assert r.status_code == 413
        assert hits["n"] == 0
        assert dummy.call_count() == 0
    finally:
        dummy.stop()


def test_g54_chunked_without_content_length_over_limit():
    app = create_app(Engine(), auth=OpenAccess())

    async def run():
        chunks = [b"a" * 1000 for _ in range((MAX_BODY // 1000) + 2)]
        state = {"i": 0}

        async def receive():
            i = state["i"]
            state["i"] += 1
            if i < len(chunks):
                return {"type": "http.request", "body": chunks[i], "more_body": i < len(chunks) - 1}
            return {"type": "http.request", "body": b"", "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/intents",
            "raw_path": b"/v1/intents",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 123),
            "server": ("test", 80),
        }
        await app(scope, receive, send)
        starts = [m for m in sent if m.get("type") == "http.response.start"]
        assert starts and starts[0]["status"] == 413

    asyncio.run(run())


def test_g55_payload_exactly_max_body_not_413():
    app = create_app(Engine(), auth=OpenAccess())
    c = TestClient(app, raise_server_exceptions=False)
    body = b"{" + b"a" * (MAX_BODY - 2) + b"}"
    assert len(body) == MAX_BODY
    r = c.post("/v1/intents", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code != 413


def test_g56_payload_max_plus_one_is_413():
    app = create_app(Engine(), auth=OpenAccess())
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/v1/intents", content=b"x" * (MAX_BODY + 1), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_g57_malformed_oversized_json_size_wins():
    app = create_app(Engine(), auth=OpenAccess())
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/v1/intents", content=b"{not-json" + b"x" * MAX_BODY, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_rt_ipv4_mapped_loopback_blocked():
    route = Route("mandate://x", "http://[::ffff:127.0.0.1]", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://[::ffff:127.0.0.1]/x", route)


def test_rt_trailing_dot_and_case(monkeypatch):
    def fake_gai(host, port, *a, **k):
        return [(2, 1, 6, "", ("10.0.0.9", port))]

    monkeypatch.setattr("mandate.executor.socket.getaddrinfo", fake_gai)
    route = Route("mandate://x", "http://Evil.Example.", network_policy="public")
    with pytest.raises(ValueError):
        assert_safe_destination("http://evil.example./x", route)


def test_rt_schema_upgrade_adds_bindings(tmp_path):
    import sqlite3

    path = tmp_path / "old.sqlite"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE receipts (
          id TEXT PRIMARY KEY,
          grant_id TEXT, agent_did TEXT, principal_did TEXT,
          audience TEXT, nonce TEXT, action TEXT, amount REAL,
          currency TEXT, state TEXT, execution_id TEXT, body TEXT NOT NULL
        );
        """
    )
    con.execute(
        "INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce, action, amount, currency, state, execution_id, body) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("rcpt_old", "g", "a", "p", "mandate://x", "n", "purchase.office", 1, "EUR", "DENIED", None, "{}"),
    )
    con.commit()
    con.close()
    from mandate.ledger import Ledger

    led = Ledger(path)
    cols = {row[1] for row in led._conn.execute("PRAGMA table_info(receipts)")}
    assert "budget_day" in cols
    tables = {row[0] for row in led._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "budget_bindings" in tables
    row = led._conn.execute("SELECT id FROM receipts WHERE id='rcpt_old'").fetchone()
    assert row[0] == "rcpt_old"
    led.close()
