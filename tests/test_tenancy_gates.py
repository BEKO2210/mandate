"""v0.4.0 access gates G81-G98.

Signed objects say who authored a grant. They never said who may reach the
gateway, read a receipt, or how often. Until 0.3.0 anyone who could open a
socket could do all three.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mandate.auth import (
    SCOPE_INTENTS_WRITE,
    SCOPE_RECEIPTS_READ,
    AuthError,
    LedgerApiKeyAuth,
    OpenAccess,
    RateLimited,
    RateLimiter,
    issue_api_key,
    parse_token,
)
from mandate.crypto import sign_object, utcnow
from mandate.engine import Engine, MandateError
from mandate.gateway import create_app
from mandate.keys import PersistedDevKeyProvider
from mandate.models import Constraint, Intent
from mandate.routes import Route, RouteRegistry
from mandate.store import Store


def _engine(tmp_path):
    route = Route("mandate://procurement", "https://api.example.com", ("POST",), ("/orders",))
    return Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
    )


def _tenant_world(engine, tenant):
    person, pkp = engine.register_principal("Belkis", tenant=tenant)
    org, _ = engine.register_principal("Org", kind="org", tenant=tenant)
    agent, akp = engine.register_agent("Bot", org.did, "M", "d", tenant=tenant)
    grant = engine.issue_grant(
        person, pkp, agent,
        organization="Org", purpose="buy", scopes=["purchase.office"],
        not_after=utcnow() + timedelta(days=5),
        constraints=Constraint(currency="EUR", max_amount=5000, max_daily_amount=1000,
                               audiences=["mandate://procurement"]),
        tenant=tenant,
    )
    return person, pkp, agent, akp, grant


def _intent(akp, grant_id, **kw):
    kw.setdefault("audience", "mandate://procurement")
    kw.setdefault("nonce", uuid4().hex)
    kw.setdefault("currency", "EUR")
    kw.setdefault("action", "purchase.office")
    return sign_object(akp, Intent.create(agent_did=akp.did(), grant_id=grant_id, **kw).to_dict())


# --- Tenancy in the engine -------------------------------------------------

def test_g81_a_grant_of_another_tenant_is_not_found(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp_a, grant_a = _tenant_world(engine, "acme")
    _tenant_world(engine, "globex")

    with pytest.raises(MandateError) as exc:
        engine.submit_intent(_intent(akp_a, grant_a["id"], amount=10.00), tenant="globex")
    # Absent, not forbidden: no existence oracle across tenants.
    assert "unknown grant" in str(exc.value)


def test_g82_receipts_are_invisible_across_tenants(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "acme")
    rec = engine.submit_intent(_intent(akp, grant["id"], amount=10.00), tenant="acme")

    assert engine.get_receipt(rec["id"], tenant="acme")["id"] == rec["id"]
    assert engine.get_receipt(rec["id"], tenant="globex") is None


def test_g83_execution_of_another_tenants_receipt_is_refused(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "acme")
    rec = engine.submit_intent(_intent(akp, grant["id"], amount=10.00), tenant="acme")
    assert rec["outcome"] == "AUTHORIZED"

    engine.executor = object()  # must never be reached
    with pytest.raises(MandateError) as exc:
        engine.execute(rec["id"], tenant="globex")
    assert "unknown receipt" in str(exc.value)


def test_g84_nonces_are_scoped_per_tenant(tmp_path):
    """One tenant must not be able to burn another tenant's nonces."""
    engine = _engine(tmp_path)
    _, _, _, akp_a, grant_a = _tenant_world(engine, "acme")
    _, _, _, akp_b, grant_b = _tenant_world(engine, "globex")
    shared = uuid4().hex

    first = engine.submit_intent(_intent(akp_a, grant_a["id"], amount=1.00, nonce=shared), tenant="acme")
    second = engine.submit_intent(_intent(akp_b, grant_b["id"], amount=1.00, nonce=shared), tenant="globex")
    assert first["outcome"] == "AUTHORIZED"
    assert second["outcome"] == "AUTHORIZED"

    # Within one tenant the replay is still refused.
    with pytest.raises(MandateError) as exc:
        engine.submit_intent(_intent(akp_a, grant_a["id"], amount=1.00, nonce=shared), tenant="acme")
    assert "replay" in str(exc.value)


def test_g85_routes_are_tenant_scoped():
    acme = Route("mandate://procurement", "https://acme.example.com", tenant="acme")
    globex = Route("mandate://procurement", "https://globex.example.com", tenant="globex")
    registry = RouteRegistry([acme, globex])

    assert registry.get("mandate://procurement", tenant="acme").base_url == "https://acme.example.com"
    assert registry.get("mandate://procurement", tenant="globex").base_url == "https://globex.example.com"
    assert registry.get("mandate://procurement", tenant="nobody") is None
    assert registry.known("mandate://procurement", tenant="acme")
    assert not registry.known("mandate://procurement", tenant="nobody")


# --- API keys --------------------------------------------------------------

def test_g86_key_verification(tmp_path):
    engine = _engine(tmp_path)
    token, key_id = issue_api_key(engine.ledger, tenant="acme", name="ci")
    auth = LedgerApiKeyAuth(engine.ledger)

    ctx = auth.authenticate({"authorization": f"Bearer {token}"})
    assert (ctx.tenant, ctx.key_id) == ("acme", key_id)

    with pytest.raises(AuthError):
        auth.authenticate({})
    with pytest.raises(AuthError):
        auth.authenticate({"authorization": "Basic abc"})
    with pytest.raises(AuthError):
        auth.authenticate({"authorization": "Bearer nonsense"})
    # Right id, wrong secret.
    with pytest.raises(AuthError):
        auth.authenticate({"authorization": f"Bearer mk_{key_id}_wrongsecret"})
    # An unknown id must not be distinguishable from a wrong secret.
    with pytest.raises(AuthError):
        auth.authenticate({"authorization": "Bearer mk_0011223344556677_whatever"})


def test_g87_secret_is_not_stored(tmp_path):
    engine = _engine(tmp_path)
    token, key_id = issue_api_key(engine.ledger, tenant="acme", name="ci")
    _, secret = parse_token(token)
    with engine.ledger.tx() as tx:
        row = tx.get_api_key(key_id)
        listed = tx.list_api_keys("acme")
    assert secret not in row["secret_hash"]
    assert row["secret_hash"] != secret
    assert "secret_hash" not in listed[0]


def test_g88_disabled_and_expired_keys_are_refused(tmp_path):
    engine = _engine(tmp_path)
    auth = LedgerApiKeyAuth(engine.ledger)

    token, key_id = issue_api_key(engine.ledger, tenant="acme", name="ci")
    with engine.ledger.tx() as tx:
        assert tx.disable_api_key(key_id) is True
    with pytest.raises(AuthError, match="disabled"):
        auth.authenticate({"authorization": f"Bearer {token}"})

    past, _ = issue_api_key(
        engine.ledger, tenant="acme", name="stale", expires_at=utcnow() - timedelta(seconds=1)
    )
    with pytest.raises(AuthError, match="expired"):
        auth.authenticate({"authorization": f"Bearer {past}"})


def test_g89_scopes_gate_each_endpoint(tmp_path):
    engine = _engine(tmp_path)
    token, _ = issue_api_key(engine.ledger, tenant="acme", name="reader", scopes=[SCOPE_RECEIPTS_READ])
    ctx = LedgerApiKeyAuth(engine.ledger).authenticate({"authorization": f"Bearer {token}"})

    assert ctx.allows(SCOPE_RECEIPTS_READ)
    ctx.require(SCOPE_RECEIPTS_READ)
    with pytest.raises(AuthError) as exc:
        ctx.require(SCOPE_INTENTS_WRITE)
    # Valid credential, wrong permission: 403, not 401.
    assert exc.value.status == 403


def test_g90_unknown_scope_is_refused_at_issue_time(tmp_path):
    engine = _engine(tmp_path)
    with pytest.raises(ValueError):
        issue_api_key(engine.ledger, tenant="acme", name="bad", scopes=["everything"])


# --- Rate limiting ---------------------------------------------------------

def test_g91_rate_limiter_refills_over_time():
    now = [0.0]
    limiter = RateLimiter(per_minute=60, burst=2, clock=lambda: now[0])

    limiter.check("k")
    limiter.check("k")
    with pytest.raises(RateLimited) as exc:
        limiter.check("k")
    assert exc.value.status == 429
    assert exc.value.retry_after > 0

    now[0] += 1.0  # one token per second at 60/min
    limiter.check("k")
    # Buckets are per key, so one caller cannot starve another.
    limiter.check("other")


# --- Gateway ---------------------------------------------------------------

def _client(engine, auth, **kw):
    return TestClient(create_app(engine, auth=auth, **kw), raise_server_exceptions=False)


def test_g92_gateway_refuses_to_start_without_an_authenticator(tmp_path):
    with pytest.raises(ValueError, match="requires an authenticator"):
        create_app(_engine(tmp_path))


def test_g93_endpoints_require_a_key_and_health_stays_quiet(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "acme")
    client = _client(engine, LedgerApiKeyAuth(engine.ledger))

    anon = client.get("/health")
    assert anon.status_code == 200
    # Liveness is public; the enforcer identity is not.
    assert anon.json() == {"ok": True}
    assert client.get("/v1/info").status_code == 401

    r = client.post("/v1/intents", json={"intent": _intent(akp, grant["id"], amount=1.00)})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert client.get("/v1/receipts/rcpt_0000000000000000").status_code == 401

    token, _ = issue_api_key(engine.ledger, tenant="acme", name="ci")
    head = {"Authorization": f"Bearer {token}"}
    assert client.get("/v1/info", headers=head).json()["tenant"] == "acme"
    ok = client.post("/v1/intents", json={"intent": _intent(akp, grant["id"], amount=1.00)}, headers=head)
    assert ok.status_code == 200, ok.text
    assert ok.json()["outcome"] == "AUTHORIZED"


def test_g94_one_tenant_cannot_read_another_tenants_receipt(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "acme")
    _tenant_world(engine, "globex")
    client = _client(engine, LedgerApiKeyAuth(engine.ledger))

    acme_token, _ = issue_api_key(engine.ledger, tenant="acme", name="acme")
    globex_token, _ = issue_api_key(engine.ledger, tenant="globex", name="globex")

    created = client.post(
        "/v1/intents",
        json={"intent": _intent(akp, grant["id"], amount=1.00)},
        headers={"Authorization": f"Bearer {acme_token}"},
    )
    receipt_id = created.json()["id"]

    mine = client.get(f"/v1/receipts/{receipt_id}", headers={"Authorization": f"Bearer {acme_token}"})
    assert mine.status_code == 200

    theirs = client.get(f"/v1/receipts/{receipt_id}", headers={"Authorization": f"Bearer {globex_token}"})
    # 404, not 403: holding a valid key elsewhere must not confirm existence.
    assert theirs.status_code == 404


def test_g95_scope_and_rate_limit_are_enforced_by_the_gateway(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "acme")
    client = _client(engine, LedgerApiKeyAuth(engine.ledger), rate_limiter=RateLimiter(per_minute=60, burst=2))

    reader, _ = issue_api_key(engine.ledger, tenant="acme", name="reader", scopes=[SCOPE_RECEIPTS_READ])
    denied = client.post(
        "/v1/intents",
        json={"intent": _intent(akp, grant["id"], amount=1.00)},
        headers={"Authorization": f"Bearer {reader}"},
    )
    assert denied.status_code == 403

    limited = [
        client.get("/v1/receipts/rcpt_0000000000000000", headers={"Authorization": f"Bearer {reader}"}).status_code
        for _ in range(4)
    ]
    assert 429 in limited
    last = client.get("/v1/receipts/rcpt_0000000000000000", headers={"Authorization": f"Bearer {reader}"})
    assert last.status_code == 429
    assert int(last.headers["retry-after"]) >= 1


def test_g96_oversized_body_is_rejected_before_authentication(tmp_path):
    """Size is checked at the ASGI boundary, so no credential check buffers it."""
    engine = _engine(tmp_path)
    client = _client(engine, LedgerApiKeyAuth(engine.ledger))
    r = client.post("/v1/intents", content=b"x" * 40_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_g97_open_access_stays_available_for_single_tenant_use(tmp_path):
    engine = _engine(tmp_path)
    _, _, _, akp, grant = _tenant_world(engine, "default")
    client = _client(engine, OpenAccess())
    r = client.post("/v1/intents", json={"intent": _intent(akp, grant["id"], amount=1.00)})
    assert r.status_code == 200
    assert r.json()["outcome"] == "AUTHORIZED"


def test_g98_a_grant_cannot_name_an_agent_from_another_tenant(tmp_path):
    engine = _engine(tmp_path)
    person, pkp, _, _, _ = _tenant_world(engine, "acme")
    _, _, other_agent, _, _ = _tenant_world(engine, "globex")

    with pytest.raises(MandateError, match="unknown agent"):
        engine.issue_grant(
            person, pkp, other_agent,
            organization="Org", purpose="buy", scopes=["purchase.office"],
            not_after=utcnow() + timedelta(days=5),
            constraints=Constraint(currency="EUR", max_amount=10),
            tenant="acme",
        )


def test_g99_cli_issues_lists_and_disables_keys(tmp_path, capsys):
    from mandate.cli import main
    from mandate.ledger import Ledger

    db = str(tmp_path / "cli.sqlite")
    assert main(["keys", "new", "--db", db, "--tenant", "acme", "--name", "ci",
                 "--scopes", "intents:write,receipts:read"]) == 0
    out = capsys.readouterr().out
    token = [l.split(": ", 1)[1].strip() for l in out.splitlines() if l.startswith("token")][0]
    key_id = [l.split(": ", 1)[1].strip() for l in out.splitlines() if l.startswith("key id")][0]

    ledger = Ledger(db)
    try:
        ctx = LedgerApiKeyAuth(ledger).authenticate({"authorization": f"Bearer {token}"})
        assert ctx.tenant == "acme"
        assert ctx.scopes == {"intents:write", "receipts:read"}
        assert not ctx.allows("approvals:write")
    finally:
        ledger.close()

    assert main(["keys", "list", "--db", db, "--tenant", "acme"]) == 0
    listing = capsys.readouterr().out
    assert key_id in listing and "active" in listing
    # The secret never appears in a listing.
    _, secret = parse_token(token)
    assert secret not in listing

    assert main(["keys", "disable", "--db", db, "--id", key_id]) == 0
    capsys.readouterr()
    ledger = Ledger(db)
    try:
        with pytest.raises(AuthError, match="disabled"):
            LedgerApiKeyAuth(ledger).authenticate({"authorization": f"Bearer {token}"})
    finally:
        ledger.close()
    # Disabling twice reports failure rather than pretending.
    assert main(["keys", "disable", "--db", db, "--id", key_id]) == 1


def test_g100_an_idempotency_key_does_not_cross_tenants(tmp_path):
    """Two tenants may use the same caller-chosen key without seeing each other."""
    from mandate.executor import ExecutionResult

    class Ok:
        def forward(self, route, method, path, body, idem):
            return ExecutionResult("EXECUTED", 200, 1, "hash")

    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([
            Route("mandate://procurement", "https://acme.example.com", ("POST",), ("/orders",), tenant="acme"),
            Route("mandate://procurement", "https://globex.example.com", ("POST",), ("/orders",), tenant="globex"),
        ]),
        executor=Ok(),
    )
    _, _, _, akp_a, grant_a = _tenant_world(engine, "acme")
    _, _, _, akp_b, grant_b = _tenant_world(engine, "globex")

    a = engine.submit_intent(_intent(akp_a, grant_a["id"], amount=1.00), tenant="acme")
    b = engine.submit_intent(_intent(akp_b, grant_b["id"], amount=1.00), tenant="globex")

    out_a = engine.execute(a["id"], idempotency_key="shared-key", tenant="acme")
    out_b = engine.execute(b["id"], idempotency_key="shared-key", tenant="globex")

    assert out_a["outcome"] == "EXECUTED"
    assert out_b["outcome"] == "EXECUTED"
    # Each tenant got its own receipt back, not the other's.
    assert out_a["id"] == a["id"]
    assert out_b["id"] == b["id"]
    assert out_a["execution"]["idempotency_key"] == "shared-key"
    # Within one tenant the key is still single-use.
    assert engine.execute(a["id"], idempotency_key="shared-key", tenant="acme")["id"] == a["id"]
