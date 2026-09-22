"""Nonce gates G233-G234.

Every consumed nonce was kept forever, so the table grew with all traffic the
gateway ever saw. Forgetting one is safe only once the intent carrying it can
no longer pass the freshness check — and an intent *without* a creation time
passed it forever, because a missing `created_at` was read as "now".
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

import mandate.validate as validate
from mandate.crypto import sign_object, utcnow
from mandate.engine import MandateError
from mandate.ledger import Ledger
from mandate.validate import NONCE_RETENTION_S

from .test_execution_recovery import Crashing, _world
from .test_hardening import Clock, _intent

START = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def test_g233_a_nonce_is_forgotten_only_after_its_intent_went_stale(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    t0 = time.time()
    with ledger.tx() as tx:
        assert tx.consume_nonce("mandate://a", "n1", "r1", now=t0)
        assert not tx.consume_nonce("mandate://a", "n1", "r2", now=t0 + NONCE_RETENTION_S - 1)
        assert tx.consume_nonce("mandate://a", "n2", "r3", now=t0 + NONCE_RETENTION_S + 1)
        rows = tx.l._conn.execute("SELECT nonce FROM nonces ORDER BY nonce").fetchall()
    assert [r["nonce"] for r in rows] == ["n2"], "n1 is past retention and must be gone"

    # And forgetting it opens nothing: by then the intent is stale.
    engine, akp, grant = _world(tmp_path / "e", Crashing(RuntimeError("x")), Clock(START))
    signed = _intent(akp, grant["id"], action="purchase.office", amount=1)
    assert engine.submit_intent(signed)["outcome"] == "AUTHORIZED"
    with engine.ledger.tx() as tx:
        tx.l._conn.execute("DELETE FROM nonces")  # as if the window had passed
    later = utcnow() + timedelta(seconds=NONCE_RETENTION_S)
    monkeypatch.setattr(validate, "utcnow", lambda: later)
    with pytest.raises(MandateError, match="not fresh"):
        engine.submit_intent(signed)


def test_g234_an_intent_must_say_when_it_was_made(tmp_path):
    """Without this, pruning nonces would reopen every such intent to replay."""
    engine, akp, grant = _world(tmp_path, Crashing(RuntimeError("x")), Clock(START))
    signed = _intent(akp, grant["id"], action="purchase.office", amount=1)
    body = {k: v for k, v in signed.items() if k not in {"proof", "created_at"}}
    with pytest.raises(MandateError, match="created_at is required"):
        engine.submit_intent(sign_object(akp, body))
