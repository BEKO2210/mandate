"""Gates G237-G243, from the review of v0.9.0.

Each one is a finding that held up when checked against the code. The most
serious: a Vault signer block with `"allow_insecure": "false"` — a string —
went through bool(), which reads any non-empty string as True, so the
refusal to send the Vault token over plain HTTP was switched *off* by a
setting that says the opposite.
"""

from __future__ import annotations

import json
import multiprocessing
import socket
import socketserver
import sqlite3
import threading

import pytest

from mandate.cli import main
from mandate.engine import MandateError
from mandate.executor import UpstreamExecutor
from mandate.gateway_config import GatewayConfigError, parse_gateway_config
from mandate.ledger import Ledger
from mandate.mcp.config import parse_config
from mandate.mcp.mapping import MappingError
from mandate.signing import SigningError, check_signer_block
from mandate.witness import WitnessError, check_witness_url, post_anchors

from .test_chain_gates import _sql
from .test_chain_gates import _world as _chain_world
from .test_network_gates import _route
from .test_resolution_gates import _unknown
from .test_witness_gates import Witness
from .tls_fixtures import HOST, FlippingResolver, free_port_on, make_pki, serve_tls

GATEWAY = {"store": "s", "auth": {"kind": "open"},
           "routes": [{"audience": "mandate://p", "base_url": "https://api.example.com"}]}
MCP = {"audience": "mandate://g", "upstream": {"command": "true"}, "tools": {"t": "a.b"}}


def test_g237_signer_blocks_are_as_strict_as_the_file_around_them(tmp_path):
    vault = {"kind": "vault-transit", "key": "k"}
    with pytest.raises(SigningError, match="allow_insecure must be true or false"):
        check_signer_block({**vault, "allow_insecure": "false"})
    with pytest.raises(SigningError, match=r"unknown keys \['dId'\]"):
        check_signer_block({"kind": "file", "path": "k", "dId": "did:key:z6Mk"})
    with pytest.raises(SigningError, match="must be a string"):
        check_signer_block({"kind": "aws-kms", "key_id": ["arn"]})
    with pytest.raises(SigningError, match="unknown signer kind"):
        check_signer_block({"kind": "yubikey"})
    check_signer_block({**vault, "allow_insecure": False})

    with pytest.raises(GatewayConfigError, match="enforcer_signer: .*allow_insecure"):
        parse_gateway_config({**GATEWAY, "enforcer_signer": {**vault, "allow_insecure": "false"}}, tmp_path)
    for name in ("agent_signer", "enforcer_signer", "principal_signer"):
        with pytest.raises(MappingError, match=f"{name}: .*unknown keys"):
            parse_config({**MCP, name: {"kind": "file", "path": "k", "didd": "x"}})

    # And a policy that is not a string is a configuration error, not a crash.
    route = {**GATEWAY["routes"][0], "network_policy": ["public"]}
    with pytest.raises(GatewayConfigError, match="public or allow_private"):
        parse_gateway_config({**GATEWAY, "routes": [route]}, tmp_path)


def test_g238_a_budget_day_must_be_written_the_way_budgets_are_keyed(tmp_path):
    """strptime accepts 2026-9-20; the budget row is 2026-09-20. The unpadded
    form would have released a reservation on a day that never made one."""
    engine, _, _, rec = _unknown(tmp_path)
    with pytest.raises(MandateError, match="as in 2026-09-20"):
        engine.resolve_unknown(rec["id"], "EXECUTED", operator="B", reason="r", budget_day="2026-9-20")


def test_g239_a_plain_http_witness_is_never_reached_through_a_proxy(monkeypatch):
    handed: list[str] = []

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            handed.append(self.rfile.readline().decode(errors="replace").strip())
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy.server_address[1]}")
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    witness = Witness()
    try:
        post_anchors(witness.url, [{"seq": 1}], token="secret")
    finally:
        witness.close()
        proxy.shutdown()
    assert handed == [], f"the proxy saw {handed}, token included"
    assert witness.received[0][0] == "Bearer secret"

    with pytest.raises(WitnessError, match="invalid port"):
        check_witness_url("http://127.0.0.1:bad/anchors")


def test_g240_a_ca_trusted_through_ssl_cert_file_is_still_trusted(tmp_path, monkeypatch):
    """Ignoring proxy variables also dropped httpx's reading of SSL_CERT_FILE,
    so an upstream behind a private CA trusted that way stopped verifying."""
    ca = make_pki(tmp_path)
    port = free_port_on("127.0.0.2")
    server = serve_tls("127.0.0.2", port, tmp_path)
    monkeypatch.setattr(socket, "getaddrinfo", FlippingResolver("127.0.0.2", "127.0.0.2"))
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    try:
        result = UpstreamExecutor().forward(_route(port), "POST", "/do", b"{}", "idem-g240")
    finally:
        server.shutdown()
    assert result.state == "EXECUTED", (result.state, result.error)
    assert server.hits == [f"{HOST}:{port}"]


def test_g241_gateway_check_loads_the_key_serve_would_load(tmp_path, capsys):
    config = tmp_path / "gateway.json"
    config.write_text(json.dumps(GATEWAY), encoding="utf-8")
    assert main(["gateway", "check", "--config", str(config)]) == 0
    assert "generated at first start" in capsys.readouterr().out

    key = tmp_path / "s" / "enforcer-keys" / "enforcer.key"
    key.parent.mkdir(parents=True)
    key.write_text("not a key", encoding="utf-8")
    assert main(["gateway", "check", "--config", str(config)]) == 1
    assert "UNUSABLE" in capsys.readouterr().out


def test_g242_a_damaged_anchor_file_fails_verification(tmp_path, capsys):
    """The only anchor for the tenant is damaged, and the chain has been cut
    short. The good lines are still checked, but what remains checks nothing,
    so the run must not end in 0."""
    engine, db, ids, _ = _chain_world(tmp_path, calls=3)
    head = engine.chain_head()
    engine.ledger.close()
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(json.dumps({"tenant": "default", "seq": str(head["seq"]),
                                   "entry_hash": head["entry_hash"]}) + "\n", encoding="utf-8")
    _sql(db, "DELETE FROM chain WHERE seq = ?", head["seq"])
    _sql(db, "DELETE FROM receipts WHERE id = ?", head["receipt_id"])
    assert main(["chain", "verify", "--db", str(db), "--anchors", str(anchors)]) == 1
    out = capsys.readouterr().out
    assert "line 1" in out and "are not anchors" in out


def _open(path, start):
    start.wait()
    Ledger(path).close()


def test_g243_workers_opening_an_old_ledger_together_all_start(tmp_path):
    """Before the nonce column existed. Every worker checked the schema and
    altered it without a lock, so the second one to get there died on a
    duplicate column. The check and the ALTER now share one write lock. A
    race cannot be forced from here; this is the regression guard."""
    path = tmp_path / "old.sqlite"
    Ledger(path).close()
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE n2 (tenant TEXT NOT NULL, audience TEXT NOT NULL, nonce TEXT NOT NULL,"
        " receipt_id TEXT, PRIMARY KEY (tenant, audience, nonce));"
        "INSERT INTO n2 VALUES ('default', 'a', 'n', 'r');"
        "DROP TABLE nonces; ALTER TABLE n2 RENAME TO nonces;"
    )
    con.close()
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    workers = [ctx.Process(target=_open, args=(path, start)) for _ in range(6)]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(timeout=60)
    assert [w.exitcode for w in workers] == [0] * 6
    with Ledger(path).tx() as tx:
        assert not tx.consume_nonce("a", "n", "r2"), "the old nonce survived the migration"
