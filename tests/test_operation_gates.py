"""v0.3.0 operation gates G70-G80.

An agent signs an intent. The gateway, not the agent, decides which method,
path and body bytes leave the building — and commits to their hash before
sending, so a receipt states what was sent, not merely what was authorized.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from mandate.engine import Engine, MandateError
from mandate.keys import PersistedDevKeyProvider
from mandate.payload import PayloadError, build_payload, encode
from mandate.routes import Operation, Route, RouteConfigError, RouteRegistry
from mandate.store import Store
from mandate.executor import UpstreamExecutor

from .dummy_upstream import DummyUpstream
from .test_hardening import _grant, _intent

ORDER = Operation(
    action="purchase.office",
    method="POST",
    path="/orders",
    fields=("action", "amount_minor", "currency", "counterparty", "execution_id"),
    context_fields=("sku", "quantity"),
)


def _world_with_scopes(tmp_path, dummy, operations, scopes):
    return _world(tmp_path, dummy, operations, scopes=scopes)


def _world(
    tmp_path, dummy, operations=(), executor=None, paths=("/orders",), methods=("POST",), scopes=None
):
    route = Route(
        audience="mandate://procurement",
        base_url=dummy.base_url,
        allowed_methods=methods,
        allowed_paths=paths,
        timeout=1.0,
        network_policy="allow_private",
        operations=tuple(operations),
    )
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
        executor=executor or UpstreamExecutor(),
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    grant = _grant(engine, person, pkp, agent, scopes=scopes or ["purchase.office"])
    return engine, akp, grant


@pytest.fixture
def dummy():
    u = DummyUpstream()
    u.start()
    yield u
    u.stop()


def test_g70_operation_decides_the_body_the_agent_does_not(tmp_path, dummy):
    engine, akp, grant = _world(tmp_path, dummy, [ORDER])
    rec = engine.submit_intent(
        _intent(
            akp, grant["id"], action="purchase.office", amount=12.30,
            counterparty="büro-bedarf.de", summary="not declared, must not be sent",
            context={"sku": "A4-80G", "quantity": 10, "internal_note": "must not be sent"},
        )
    )
    out = engine.execute(rec["id"])

    assert out["outcome"] == "EXECUTED"
    call = dummy.state.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "/orders"
    assert call["payload"] == {
        "action": "purchase.office",
        "amount_minor": 1230,
        "currency": "EUR",
        "counterparty": "büro-bedarf.de",
        "execution_id": out["execution"]["execution_id"],
        "sku": "A4-80G",
        "quantity": 10,
    }
    # Neither an undeclared intent field nor an undeclared context key travels.
    assert "summary" not in call["payload"]
    assert "internal_note" not in call["payload"]


def test_g71_receipt_hash_matches_the_bytes_the_upstream_received(tmp_path, dummy):
    engine, akp, grant = _world(tmp_path, dummy, [ORDER])
    rec = engine.submit_intent(
        _intent(
            akp, grant["id"], action="purchase.office", amount=12.30,
            counterparty="büro-bedarf.de", context={"sku": "A4-80G", "quantity": 10},
        )
    )
    out = engine.execute(rec["id"])

    raw = dummy.state.calls[0]["raw"]
    request = out["execution"]["request"]
    assert request["hash"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert request["size"] == len(raw)
    assert request["method"] == "POST"
    assert request["destination"] == dummy.base_url + "/orders"
    assert dummy.state.calls[0]["content_type"] == "application/json"


def test_g72_hash_is_signed_before_the_request_is_sent(tmp_path, dummy):
    """The commitment must precede the dispatch, not describe it afterwards."""
    captured: dict[str, bytes] = {}

    class CaptureThenDie:
        def forward(self, route, method, path, body, idem):
            captured["body"] = body
            # Nothing after this point can write to the receipt.
            raise KeyboardInterrupt()

    engine, akp, grant = _world(tmp_path, dummy, [ORDER], executor=CaptureThenDie())
    rec = engine.submit_intent(
        _intent(
            akp, grant["id"], action="purchase.office", amount=12.30,
            counterparty="büro-bedarf.de", context={"sku": "A4-80G", "quantity": 10},
        )
    )
    with pytest.raises(KeyboardInterrupt):
        engine.execute(rec["id"])

    with engine.ledger.tx() as tx:
        stored = json.loads(tx.get_receipt(rec["id"])["body"])
    assert stored["outcome"] == "EXECUTING"
    assert stored["execution"]["request"]["hash"] == (
        "sha256:" + hashlib.sha256(captured["body"]).hexdigest()
    )


def test_g73_missing_declared_context_field_fails_closed(tmp_path, dummy):
    engine, akp, grant = _world(tmp_path, dummy, [ORDER])
    rec = engine.submit_intent(
        _intent(
            akp, grant["id"], action="purchase.office", amount=12.30,
            counterparty="x.example", context={"sku": "A4-80G"},  # quantity missing
        )
    )
    with pytest.raises(MandateError) as exc:
        engine.execute(rec["id"])
    assert "quantity" in str(exc.value)
    assert dummy.call_count() == 0
    with engine.ledger.tx() as tx:
        assert tx.get_receipt(rec["id"])["state"] == "AUTHORIZED"


def test_g74_non_scalar_context_value_is_refused(tmp_path, dummy):
    engine, akp, grant = _world(tmp_path, dummy, [ORDER])
    rec = engine.submit_intent(
        _intent(
            akp, grant["id"], action="purchase.office", amount=12.30,
            counterparty="x.example",
            context={"sku": {"nested": "shape"}, "quantity": 1},
        )
    )
    with pytest.raises(MandateError) as exc:
        engine.execute(rec["id"])
    assert "scalar" in str(exc.value)
    assert dummy.call_count() == 0


def test_g75_authorized_action_without_an_operation_never_dispatches(tmp_path, dummy):
    """An action the grant permits but the route does not implement fails closed."""
    engine, akp, grant = _world_with_scopes(
        tmp_path, dummy, [ORDER], scopes=["purchase.office", "purchase.it"]
    )
    rec = engine.submit_intent(_intent(akp, grant["id"], action="purchase.it", amount=1.00))
    # The grant authorizes it; only the route has nothing to send.
    assert rec["outcome"] == "AUTHORIZED"

    with pytest.raises(MandateError) as exc:
        engine.execute(rec["id"])

    assert "operation" in str(exc.value) and "purchase.it" in str(exc.value)
    assert dummy.call_count() == 0
    with engine.ledger.tx() as tx:
        assert tx.get_receipt(rec["id"])["state"] == "AUTHORIZED"


def test_g76_route_config_refuses_to_widen_its_own_allowlists():
    with pytest.raises(RouteConfigError):
        Route("mandate://x", "https://api.example.com", ("POST",), ("/orders",),
              operations=(Operation("a.b", "DELETE", "/orders"),))
    with pytest.raises(RouteConfigError):
        Route("mandate://x", "https://api.example.com", ("POST",), ("/orders",),
              operations=(Operation("a.b", "POST", "/elsewhere"),))
    with pytest.raises(RouteConfigError):
        Operation("a.b", "POST", "/orders", fields=("action", "secret_key"))
    with pytest.raises(RouteConfigError):
        Operation("a.b", "POST", "/orders", fields=("action", "amount"), context_fields=("amount",))
    with pytest.raises(RouteConfigError):
        Route("mandate://x", "https://api.example.com", ("POST",), ("/orders",),
              operations=(Operation("a.b", "POST", "/orders"), Operation("a.b", "POST", "/orders")))


def test_g77_a_non_post_operation_is_dispatched_as_declared(tmp_path, dummy):
    put = Operation("purchase.office", "PUT", "/inventory", fields=("action", "execution_id"))
    engine, akp, grant = _world(
        tmp_path, dummy, [put], paths=("/inventory",), methods=("PUT",)
    )
    out = engine.execute(
        engine.submit_intent(
            _intent(akp, grant["id"], action="purchase.office", amount=5.00)
        )["id"]
    )
    assert out["outcome"] == "EXECUTED"
    call = dummy.state.calls[0]
    assert (call["method"], call["path"]) == ("PUT", "/inventory")
    assert set(call["payload"]) == {"action", "execution_id"}


def test_g78_route_without_operations_keeps_the_pre_0_3_body(tmp_path, dummy):
    engine, akp, grant = _world(tmp_path, dummy, [])
    out = engine.execute(
        engine.submit_intent(
            _intent(akp, grant["id"], action="purchase.office", amount=12.30)
        )["id"]
    )
    assert out["outcome"] == "EXECUTED"
    assert dummy.state.calls[0]["payload"] == {
        "action": "purchase.office",
        "amount": 12.3,
        "currency": "EUR",
        "execution_id": out["execution"]["execution_id"],
    }
    assert out["execution"]["request"]["hash"].startswith("sha256:")


def test_g79_payload_builder_rejects_oversized_strings():
    op = Operation("a.b", "POST", "/orders", fields=("action",), context_fields=("note",))

    class FakeIntent:
        id = "intent_1"
        action = "a.b"
        amount = None
        currency = "EUR"
        counterparty = None
        summary = ""
        context = {"note": "x" * 257}

    with pytest.raises(PayloadError):
        build_payload(op, FakeIntent(), "exec_1")
    FakeIntent.context = {"note": "ok"}
    assert encode(build_payload(op, FakeIntent(), "exec_1")) == b'{"action":"a.b","note":"ok"}'


def test_g80_amountless_intent_sends_null_not_zero(tmp_path, dummy):
    op = Operation(
        "purchase.office", "POST", "/orders",
        fields=("action", "amount_minor", "currency", "execution_id"),
    )
    engine, akp, grant = _world(tmp_path, dummy, [op])
    out = engine.execute(
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office"))["id"]
    )
    assert out["outcome"] == "EXECUTED"
    assert dummy.state.calls[0]["payload"]["amount_minor"] is None
