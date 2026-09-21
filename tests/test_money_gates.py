"""v0.2.2 money gates G58-G63. Amounts are exact or they are refused.

G58 and G59 are the reproduced 0.2.1 defect: float arithmetic decided a cap
wrongly. They must stay red on any return to float money.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest

from mandate.crypto import sign_object, utcnow
from mandate.engine import Engine, MandateError
from mandate.keys import PersistedDevKeyProvider
from mandate.models import Constraint, Intent
from mandate.money import MoneyError, format_minor, from_minor, to_minor
from mandate.routes import Route, RouteRegistry
from mandate.store import Store

from .test_hardening import _intent


def _engine(tmp_path):
    route = Route("mandate://procurement", "http://127.0.0.1:9/", ("POST",), ("/orders",))
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=PersistedDevKeyProvider(tmp_path / "keys"),
        routes=RouteRegistry([route]),
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    return engine, person, pkp, agent, akp


def _grant_with(engine, person, pkp, agent, **c):
    return engine.issue_grant(
        person, pkp, agent,
        organization="Aslani GmbH",
        purpose="buy",
        scopes=["purchase.office"],
        not_after=utcnow() + timedelta(days=5),
        constraints=Constraint(
            currency=c.get("currency", "EUR"),
            max_amount=c.get("max_amount", 5000),
            max_daily_amount=c.get("max_daily_amount"),
            require_human_above=c.get("require_human_above"),
            audiences=["mandate://procurement"],
        ),
    )


def test_g58_two_amounts_that_float_rejected_fit_the_cap(tmp_path):
    """0.10 + 0.20 is exactly 0.30. Under a 0.30 cap both must pass."""
    engine, person, pkp, agent, akp = _engine(tmp_path)
    grant = _grant_with(engine, person, pkp, agent, max_daily_amount=0.30)

    first = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=0.10))
    second = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=0.20))

    assert first["outcome"] == "AUTHORIZED"
    assert second["outcome"] == "AUTHORIZED", second["decision"]["reasons"]
    with engine.ledger.tx() as tx:
        assert tx.spent(grant["id"], "EUR", utcnow().strftime("%Y-%m-%d")) == 30
        assert tx.budget_snapshot(grant["id"], "EUR", utcnow().strftime("%Y-%m-%d"))["reserved"] == Decimal("0.30")


def test_g59_repeated_small_amounts_do_not_drift(tmp_path):
    engine, person, pkp, agent, akp = _engine(tmp_path)
    grant = _grant_with(engine, person, pkp, agent, max_daily_amount=1.00)
    day = utcnow().strftime("%Y-%m-%d")

    outcomes = [
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=0.10))["outcome"]
        for _ in range(10)
    ]
    assert outcomes == ["AUTHORIZED"] * 10
    with engine.ledger.tx() as tx:
        # Exactly 100 minor units, not 99.99999999999999.
        assert tx.spent(grant["id"], "EUR", day) == 100

    over = engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=0.01))
    assert over["outcome"] == "DENIED"
    with engine.ledger.tx() as tx:
        assert tx.spent(grant["id"], "EUR", day) == 100


def test_g60_amount_finer_than_the_currency_is_refused(tmp_path):
    engine, person, pkp, agent, akp = _engine(tmp_path)
    grant = _grant_with(engine, person, pkp, agent, max_daily_amount=10)
    with pytest.raises(MandateError) as exc:
        engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=0.001))
    assert "amount" in str(exc.value)


def test_g61_zero_exponent_currency(tmp_path):
    engine, person, pkp, agent, akp = _engine(tmp_path)
    grant = _grant_with(engine, person, pkp, agent, currency="JPY", max_daily_amount=1000, max_amount=1000)
    day = utcnow().strftime("%Y-%m-%d")

    ok = engine.submit_intent(
        _intent(akp, grant["id"], action="purchase.office", amount=700, currency="JPY")
    )
    assert ok["outcome"] == "AUTHORIZED"
    with engine.ledger.tx() as tx:
        # JPY has no minor unit: 700 yen is 700, not 70000.
        assert tx.spent(grant["id"], "JPY", day) == 700

    with pytest.raises(MandateError):
        engine.submit_intent(
            _intent(akp, grant["id"], action="purchase.office", amount=0.5, currency="JPY")
        )


def test_g62_declared_amount_minor_must_agree(tmp_path):
    engine, person, pkp, agent, akp = _engine(tmp_path)
    grant = _grant_with(engine, person, pkp, agent, max_daily_amount=100)

    intent = Intent.create(
        agent_did=akp.did(), grant_id=grant["id"], action="purchase.office",
        amount=10.00, currency="EUR", audience="mandate://procurement",
        nonce="ab" * 8,
    )
    body = intent.to_dict()
    body["amount_minor"] = 1  # claims 0.01 EUR while the decimal says 10.00
    with pytest.raises(MandateError) as exc:
        engine.submit_intent(sign_object(akp, body))
    assert "amount_minor" in str(exc.value)

    body["amount_minor"] = 1000
    body["nonce"] = "cd" * 8
    accepted = engine.submit_intent(sign_object(akp, body))
    assert accepted["outcome"] == "AUTHORIZED"
    assert accepted["amount_minor"] == 1000


def test_g63_money_conversion_is_exact():
    assert to_minor(0.10, "EUR") == 10
    assert to_minor(0.20, "EUR") == 20
    assert to_minor(0.30, "EUR") == 30
    assert to_minor(0.1, "EUR") + to_minor(0.2, "EUR") == to_minor(0.3, "EUR")
    with pytest.raises(MoneyError):
        to_minor(2.675, "EUR")  # half a cent is not a EUR amount, it is a rounding decision
    assert to_minor(1, "JPY") == 1
    assert to_minor("1.005", "BHD") == 1005
    assert from_minor(30, "EUR") == Decimal("0.30")
    assert format_minor(30, "EUR") == "0.30"
    assert format_minor(700, "JPY") == "700"
    for bad in (-1, 0.001, float("nan"), float("inf"), True, None, "abc"):
        with pytest.raises(MoneyError):
            to_minor(bad, "EUR")
