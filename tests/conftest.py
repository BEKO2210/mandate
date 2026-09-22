from __future__ import annotations

from datetime import timedelta

import pytest

from mandate.crypto import utcnow
from mandate.engine import Engine
from mandate.executor import UpstreamExecutor
from mandate.keys import PersistedDevKeyProvider
from mandate.models import Constraint
from mandate.routes import Route, RouteRegistry
from mandate.store import Store

from .dummy_upstream import DummyUpstream


@pytest.fixture
def dummy():
    u = DummyUpstream()
    u.start()
    yield u
    u.stop()


@pytest.fixture
def harness(tmp_path, dummy):
    route = Route(
        audience="mandate://procurement",
        base_url=dummy.base_url,
        allowed_methods=("POST",),
        allowed_paths=("/orders",),
        timeout=0.4,
        network_policy="allow_private",
    )
    keys = PersistedDevKeyProvider(tmp_path / "enforcer-keys")
    engine = Engine(
        Store(tmp_path / "obj"),
        key_provider=keys,
        routes=RouteRegistry([route]),
        executor=UpstreamExecutor(),
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Aslani GmbH", kind="org")
    agent, akp = engine.register_agent("ProcureBot", org.did, "Mandate", "demo")
    grant = engine.issue_grant(
        person,
        pkp,
        agent,
        organization="Aslani GmbH",
        purpose="buy",
        scopes=["purchase.office", "purchase.it"],
        not_after=utcnow() + timedelta(days=5),
        constraints=Constraint(
            max_amount=5000,
            max_daily_amount=1000,
            require_human_above=700,
            counterparties_deny=["bad.example"],
            currency="EUR",
        ),
    )
    return {
        "engine": engine,
        "dummy": dummy,
        "person": person,
        "pkp": pkp,
        "agent": agent,
        "akp": akp,
        "grant": grant,
        "keys": keys,
        "tmp": tmp_path,
        "route": route,
    }
