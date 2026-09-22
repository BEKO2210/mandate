"""Rate-limit gates G207-G211.

The limiter used to be a dict in the gateway's memory. That bounds one
process, and a gateway is normally run behind several workers, so the limit a
key actually got was the configured one multiplied by however many processes
happened to be serving. The bucket now lives in the ledger every worker
already shares.
"""

from __future__ import annotations

import multiprocessing
import threading

import pytest
from fastapi.testclient import TestClient

from mandate.auth import LedgerRateLimiter, OpenAccess, RateLimited
from mandate.engine import Engine
from mandate.gateway import create_app
from mandate.keys import PersistedDevKeyProvider
from mandate.ledger import Ledger, StorageError
from mandate.routes import Route, RouteRegistry
from mandate.store import Store

BURST = 10


def _hammer(path, attempts, start, results):
    """One gateway worker: its own process, its own connection, one ledger."""
    limiter = LedgerRateLimiter(Ledger(path), per_minute=1, burst=BURST, clock=lambda: 1_000.0)
    start.wait()
    allowed = 0
    for _ in range(attempts):
        try:
            limiter.check("key-1")
        except RateLimited:
            continue
        allowed += 1
    results.put(allowed)


def test_g207_separate_processes_share_one_bucket(tmp_path):
    """Four real processes, each trying 25 times against a burst of 10.

    With a per-process bucket each of them gets 10, and 40 requests pass. The
    clock is frozen, so no refill can blur the count: exactly the burst may
    pass, however the processes interleave.
    """
    path = tmp_path / "mandate.sqlite"
    Ledger(path).close()  # schema exists before the workers race to use it
    ctx = multiprocessing.get_context("spawn")
    start, results = ctx.Event(), ctx.Queue()
    workers = [ctx.Process(target=_hammer, args=(path, 25, start, results)) for _ in range(4)]
    for worker in workers:
        worker.start()
    start.set()
    counts = [results.get(timeout=60) for _ in workers]
    for worker in workers:
        worker.join(timeout=60)
        assert worker.exitcode == 0
    assert sum(counts) == BURST, f"processes were allowed {counts}"


def _engine(root):
    route = Route("mandate://t", "https://api.example.com", ("POST",), ("/orders",))
    return Engine(
        Store(root / "obj"),
        key_provider=PersistedDevKeyProvider(root / "keys"),
        routes=RouteRegistry([route]),
    )


def test_g208_the_gateway_shares_its_limit_by_default(tmp_path):
    """Two gateway instances on one ledger are two workers. Without being
    told anything, they must draw from the same bucket."""
    first, second = _engine(tmp_path), _engine(tmp_path)
    default = create_app(first, auth=OpenAccess()).app.state.rate_limiter
    assert isinstance(default, LedgerRateLimiter), type(default).__name__
    assert default.ledger is first.ledger

    frozen = lambda: 5_000.0  # noqa: E731
    apps = [
        TestClient(create_app(engine, auth=OpenAccess(),
                              rate_limiter=LedgerRateLimiter(engine.ledger, burst=2, clock=frozen)))
        for engine in (first, second)
    ]
    codes = [apps[i % 2].get("/v1/info").status_code for i in range(4)]
    assert codes == [200, 200, 429, 429], codes


def test_g209_a_clock_that_steps_back_refills_nothing(tmp_path):
    """Wall time is shared across processes, but it can be stepped. Stepping
    it back and then forward again must not pay out the same minute twice."""
    now = [100.0]
    limiter = LedgerRateLimiter(Ledger(tmp_path / "l.sqlite"), per_minute=60, burst=2,
                                clock=lambda: now[0])
    limiter.check("k")
    limiter.check("k")
    now[0] = 40.0
    with pytest.raises(RateLimited):
        limiter.check("k")
    now[0] = 100.0
    with pytest.raises(RateLimited):
        limiter.check("k")
    now[0] = 101.0  # one real second later: one token, as configured
    limiter.check("k")
    with pytest.raises(RateLimited):
        limiter.check("k")


def test_g210_a_limiter_that_cannot_count_does_not_let_requests_through(tmp_path):
    """The limiter's store fails while the engine's does not, so a 5xx here
    can only come from the limiter refusing to pass an unmetered request."""
    engine = _engine(tmp_path)
    counter = Ledger(tmp_path / "counter.sqlite")
    client = TestClient(create_app(engine, auth=OpenAccess(), rate_limiter=LedgerRateLimiter(counter)),
                        raise_server_exceptions=False)
    assert client.get("/v1/info").status_code == 200
    counter.inject_failure()
    with pytest.raises(StorageError):
        LedgerRateLimiter(counter).check("k")
    assert client.get("/v1/info").status_code >= 500
    with pytest.raises(ValueError):
        LedgerRateLimiter(counter, burst=0)


def test_g211_a_transaction_that_cannot_begin_gives_its_lock_back(tmp_path):
    """Found while writing G210: the ledger took its lock and then began the
    transaction. When beginning failed, the lock was never released, and the
    next transaction on any other thread waited forever. With several
    processes on one file, "database is locked" is a normal answer, so one
    busy moment would have hung the gateway for good."""
    ledger = Ledger(tmp_path / "l.sqlite")
    ledger.inject_failure()
    with pytest.raises(StorageError):
        with ledger.tx():
            pass
    ledger.inject_failure(False)

    done = threading.Event()

    def other_request():
        with ledger.tx() as tx:
            tx.take_rate_token("k", 1.0, 1.0, 1.0)
        done.set()

    threading.Thread(target=other_request, daemon=True).start()
    assert done.wait(timeout=5), "the lock from the failed transaction was never released"
