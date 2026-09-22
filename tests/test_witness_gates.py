"""Witness gates G229-G232.

`mandate chain anchor` wrote heads to a file, and whether that file was out of
the operator's reach was left to the operator. A head the operator can edit
proves nothing about truncation. Heads now go to a witness over HTTP — by
command, and on a schedule while the gateway runs — and every failure is loud.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import threading

import pytest

from mandate.cli import main
from mandate.gateway_config import GatewayConfigError, build_app, parse_gateway_config
from mandate.witness import AnchorSchedule, WitnessError, check_witness_url, post_anchors

from .test_execution_recovery import Crashing, _world
from .test_hardening import Clock, _grant, _intent
from .test_resolution_gates import START


class Witness:
    """A witness on loopback that records what it was handed."""

    def __init__(self, status=200, location=None):
        received: list = []
        self.received = received

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.headers.get("Authorization"), json.loads(body)))
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(b'{"accepted": true}')

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/anchors"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def no_proxy(monkeypatch):
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)


def _chain(tmp_path):
    engine, akp, grant = _world(tmp_path, Crashing(RuntimeError("x")), Clock(START))
    engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=1))
    return engine


def test_g229_the_heads_reach_the_witness_and_match_the_chain(tmp_path, no_proxy, monkeypatch, capsys):
    engine = _chain(tmp_path)
    head = engine.chain_head()
    witness = Witness()
    monkeypatch.setenv("WITNESS_TOKEN", "s3cret")
    db = str(engine.ledger.path)
    try:
        code = main(["chain", "anchor", "--db", db, "--witness", witness.url,
                     "--witness-token-env", "WITNESS_TOKEN", "--file", str(tmp_path / "a.jsonl")])
    finally:
        witness.close()
    assert code == 0, capsys.readouterr()
    [(auth, body)] = witness.received
    assert auth == "Bearer s3cret"
    [anchor] = body["anchors"]
    assert (anchor["seq"], anchor["entry_hash"]) == (head["seq"], head["entry_hash"])
    # The file is the same shape the verifier reads, so --anchors still works.
    assert json.loads((tmp_path / "a.jsonl").read_text()) == anchor
    assert main(["chain", "verify", "--db", db, "--anchors", str(tmp_path / "a.jsonl")]) == 0


def test_g230_a_witness_that_does_not_accept_is_a_failure(tmp_path, no_proxy, capsys):
    """Non-2xx, a redirect, an unreachable host, plain http off loopback and a
    missing token all fail with a non-zero exit — and none of them writes the
    file as if the anchor had been witnessed."""
    engine = _chain(tmp_path)
    db = str(engine.ledger.path)
    out = tmp_path / "a.jsonl"

    for witness in (Witness(status=500), Witness(status=302, location="https://elsewhere.example/")):
        try:
            assert main(["chain", "anchor", "--db", db, "--witness", witness.url, "--file", str(out)]) == 1
        finally:
            witness.close()
        assert "witness FAILED" in capsys.readouterr().err
        assert len(witness.received) == 1, "a redirect must not be followed"
    assert not out.exists()

    for bad in ("http://witness.example/anchors", "ftp://127.0.0.1/", "https://u:p@w.example/"):
        with pytest.raises(WitnessError):
            check_witness_url(bad)
    with pytest.raises(WitnessError, match="unreachable"):
        post_anchors("http://127.0.0.1:9/anchors", [{"seq": 1}], timeout=1)
    assert main(["chain", "anchor", "--db", db, "--witness", "https://w.example",
                 "--witness-token-env", "NOT_SET_ANYWHERE"]) == 1
    assert "is not set" in capsys.readouterr().err
    assert main(["chain", "anchor", "--db", db]) == 2


def test_g231_gateway_workers_anchor_once_per_interval(tmp_path, no_proxy):
    """Two workers on one ledger, both running the schedule: one post per
    interval between them, not one each."""
    engine = _chain(tmp_path)
    witness = Witness()
    schedule = AnchorSchedule(url=witness.url, every_s=60)
    try:
        now = 1_000.0
        posts = 0
        for tick in range(6):  # three intervals, two workers each
            for _worker in range(2):
                if schedule.due(engine, now=now + (tick // 2) * 60):
                    schedule.run_once(engine)
                    posts += 1
    finally:
        witness.close()
    assert posts == 3 == len(witness.received)


def test_g232_the_gateway_file_configures_anchoring_and_refuses_it_half_set(tmp_path, no_proxy, monkeypatch):
    base = {"store": "s", "auth": {"kind": "open"},
            "routes": [{"audience": "mandate://p", "base_url": "https://api.example.com"}]}

    def refused(anchoring, match):
        with pytest.raises(GatewayConfigError, match=match):
            parse_gateway_config({**base, "anchoring": anchoring}, tmp_path)

    refused({"witness": "http://w.example/", "every_s": 300}, "https")
    refused({"witness": "https://w.example/", "every_s": 5}, "every_s must be an integer >= 60")
    refused({"witness": "https://w.example/"}, "missing")
    refused({"witness": "https://w.example/", "every_s": 300, "retry": 1}, "unknown keys")

    witness = Witness()
    config = parse_gateway_config(
        {**base, "anchoring": {"witness": witness.url, "every_s": 60, "token_env": "WT"}}, tmp_path,
    )
    with pytest.raises(GatewayConfigError, match=r"\$WT is not set"):
        build_app(config)
    monkeypatch.setenv("WT", "t")
    app = build_app(config)
    engine = app.app.state.engine
    person, pkp = engine.register_principal("B")
    org, _ = engine.register_principal("O", kind="org")
    agent, akp = engine.register_agent("Bot", org.did, "M", "d")

    async def run_briefly():
        task = asyncio.create_task(config.anchoring.loop(engine))
        for _ in range(100):
            await asyncio.sleep(0.02)
            if witness.received:
                break
        task.cancel()

    # An empty chain has nothing to anchor; give it one entry first.

    grant = _grant(engine, person, pkp, agent)
    engine.submit_intent(_intent(akp, grant["id"], action="purchase.office", amount=1))
    try:
        asyncio.run(run_briefly())
    finally:
        witness.close()
    assert witness.received and witness.received[0][0] == "Bearer t"
