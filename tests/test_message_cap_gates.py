"""Signer message-cap gates G226-G228.

AWS KMS signs at most 4096 bytes. The claim signed before dispatch could fit
while the result signed after it did not — the result adds the status, the
response hash and the executor's error text, which was unbounded. Reproduced:
with a 1100-byte context and a verbose 502 from the upstream, the request was
sent, the EXECUTION_FAILED receipt could not be signed, the real outcome was
lost, and the receipt sat in EXECUTING until the next restart turned it into
EXECUTION_UNKNOWN with its reservation held.
"""

from __future__ import annotations

import pytest

from mandate.crypto import canonical_json, verify_object
from mandate.engine import ERROR_LIMIT, Engine, ExecutionUnknown, MandateError, bounded_error
from mandate.executor import ExecutionResult
from mandate.keys import SignerKeyProvider
from mandate.ledger import Ledger
from mandate.routes import Operation, Route, RouteRegistry
from mandate.signing import AwsKmsSigner

from .test_hardening import _grant, _intent
from .test_signing_gates import FakeAwsClient

class Recording:
    def __init__(self, result: ExecutionResult) -> None:
        self.result, self.calls = result, 0

    def forward(self, *args):
        self.calls += 1
        return self.result


def _kms_world(tmp_path, executor):
    op = Operation("purchase.office", "POST", "/orders", context_fields=("note",), max_string=4000)
    route = Route("mandate://procurement", "https://api.example.com", ("POST",), ("/orders",),
                  operations=(op,))
    engine = Engine(
        ledger=Ledger(tmp_path / "l.sqlite"),
        key_provider=SignerKeyProvider(AwsKmsSigner(FakeAwsClient(), "alias/mandate")),
        routes=RouteRegistry([route]),
        executor=executor,
    )
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Org", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")
    grant = _grant(engine, person, pkp, agent)
    return engine, akp, grant


def _submit(engine, akp, grant, note_bytes):
    return engine.submit_intent(_intent(
        akp, grant["id"], action="purchase.office", amount=1, context={"note": "n" * note_bytes},
    ))


def _budget(engine, grant):
    from datetime import datetime, timezone

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with engine.ledger.tx() as tx:
        return tx.budget_snapshot_minor(grant["id"], "EUR", day)


def test_g226_an_outcome_that_could_not_be_signed_is_refused_before_dispatch(tmp_path):
    upstream = Recording(ExecutionResult("EXECUTED", 200, 5, "h" * 64))
    engine, akp, grant = _kms_world(tmp_path, upstream)
    rec = _submit(engine, akp, grant, 1900)  # signable now, not after dispatch
    assert rec["outcome"] == "AUTHORIZED"

    out = engine.execute(rec["id"])

    assert upstream.calls == 0, "nothing may be sent whose outcome cannot be recorded"
    assert out["outcome"] == "DENIED" and verify_object(out)
    assert "at most 4096" in out["decision"]["reasons"][0]
    assert _budget(engine, grant)["reserved"] == 0, "the reservation is released"
    assert engine.verify_chain(expect_signer=engine.enforcer_did).ok
    with pytest.raises(MandateError, match="DENIED -> EXECUTING"):
        engine.execute(rec["id"])  # and it stays refused
    assert upstream.calls == 0


def test_g227_whatever_the_upstream_says_the_outcome_is_recorded(tmp_path):
    """Sweep the context size across the whole range the signer accepts, for
    each outcome an upstream can produce. Every execution is either refused
    before dispatch or has its outcome recorded — never dispatched-and-lost.
    An unknown one can still be resolved with a short finding.

    One test rather than a parametrized three: the landing page states the
    suite's size, and it counts test functions."""
    verbose = "upstream said: \u00e9\"\\\x00" + "x" * 5000
    for state in ("EXECUTED", "EXECUTION_FAILED", "EXECUTION_UNKNOWN"):
        upstream = Recording(ExecutionResult(state, 502, 10**7, "f" * 64, verbose))
        (tmp_path / state).mkdir()
        engine, akp, grant = _kms_world(tmp_path / state, upstream)
        recorded = refused = 0
        for note in range(0, 2000, 40):
            try:
                rec = _submit(engine, akp, grant, note)
            except MandateError:
                break  # the receipt itself no longer fits; nothing was authorized
            calls = upstream.calls
            try:
                out = engine.execute(rec["id"])
            except ExecutionUnknown as exc:  # pragma: no cover - the bug this gate pins
                pytest.fail(f"{state}: dispatched and lost at context {note}: {exc}")
            if out["outcome"] == "DENIED":
                assert upstream.calls == calls
                refused += 1
                continue
            assert out["outcome"] == state and verify_object(out)
            error = out["execution"]["error"]
            assert len(error) <= ERROR_LIMIT and len(error.encode()) == len(error)
            if state == "EXECUTION_UNKNOWN":
                out = engine.resolve_unknown(
                    rec["id"], "EXECUTION_FAILED", operator="x" * 32, reason="y" * 128,
                )
                assert out["outcome"] == "EXECUTION_FAILED"
            assert len(canonical_json({k: v for k, v in out.items() if k != "proof"})) <= 4096
            recorded += 1
        assert recorded and refused, (state, recorded, refused)
        assert engine.verify_chain(expect_signer=engine.enforcer_did).ok


def test_g228_an_error_costs_one_byte_per_character_and_at_most_the_limit():
    assert bounded_error(None) is None
    assert bounded_error("timeout") == "timeout"
    weird = bounded_error('é"\\\x00\n\u202e' + "z" * 500)
    assert len(weird) == ERROR_LIMIT and weird.endswith("...")
    assert all(" " <= ch <= "~" and ch not in '"\\' for ch in weird)
    assert len(canonical_json(weird)) == len(weird) + 2  # just the two quotes
