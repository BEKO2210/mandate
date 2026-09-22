"""Configuration gates G213-G219.

The HTTP gateway could only be assembled in Python, and the MCP guard read
its file loosely: an unknown key was ignored. For a guard, "ignored" means a
misspelt limit is silently no limit. Both files are now read strictly, and
the gateway can be run from one.
"""

from __future__ import annotations

import http.server
import json
import threading
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mandate.cli import main
from mandate.crypto import KeyPair, sign_object, utcnow, verify_object
from mandate.gateway_config import GatewayConfigError, build_app, load_gateway_config, parse_gateway_config
from mandate.mcp.config import load_config, parse_config
from mandate.mcp.mapping import MappingError
from mandate.models import Constraint, Intent


def _write_key(path):
    kp = KeyPair.generate()
    path.write_text(kp.private_bytes().hex(), encoding="utf-8")
    return kp


def _gateway_raw(base_url="https://api.example.com/v2"):
    return {
        "store": "state",
        "auth": {"kind": "open"},
        "routes": [{
            "audience": "mandate://procurement",
            "base_url": base_url,
            "allowed_methods": ["POST"],
            "allowed_paths": ["/orders"],
            "network_policy": "allow_private",
            "timeout": 3,
            "operations": [{
                "action": "purchase.office", "method": "POST", "path": "/orders",
                "fields": ["action", "amount", "currency", "execution_id"],
            }],
        }],
    }


def _write(tmp_path, raw, name="gateway.json"):
    path = tmp_path / name
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_g213_a_gateway_run_from_a_file_enforces_and_forwards(tmp_path, monkeypatch):
    """End to end, with nothing assembled in Python: the file names the
    route, the operation and the path prefix, and a real upstream is asked
    for exactly what the receipt records."""
    seen = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    try:
        config = load_gateway_config(_write(
            tmp_path, _gateway_raw(f"http://127.0.0.1:{server.server_address[1]}/v2")
        ))
        app = build_app(config)
        engine = app.app.state.engine
        person, pkp = engine.register_principal("Belkis")
        org, _ = engine.register_principal("Org", kind="org")
        agent, akp = engine.register_agent("Bot", org.did, "M", "d")
        grant = engine.issue_grant(
            person, pkp, agent, organization="Org", purpose="buy", scopes=["purchase.office"],
            not_after=utcnow() + timedelta(days=1),
            constraints=Constraint(currency="EUR", max_amount=100,
                                   audiences=["mandate://procurement"]),
        )
        intent = sign_object(akp, Intent.create(
            agent_did=akp.did(), grant_id=grant["id"], action="purchase.office",
            amount=12.5, currency="EUR", audience="mandate://procurement", nonce=uuid4().hex,
        ).to_dict())
        client = TestClient(app)
        receipt = client.post("/v1/intents", json={"intent": intent, "execute": True}).json()
        over = sign_object(akp, Intent.create(
            agent_did=akp.did(), grant_id=grant["id"], action="purchase.office",
            amount=500, currency="EUR", audience="mandate://procurement", nonce=uuid4().hex,
        ).to_dict())
        denied = client.post("/v1/intents", json={"intent": over, "execute": True}).json()
    finally:
        server.shutdown()
    assert receipt["outcome"] == "EXECUTED", receipt
    assert denied["outcome"] == "DENIED", denied
    assert [path for path, _ in seen] == ["/v2/orders"], "the denied intent must not reach it"
    assert seen[0][1]["amount"] == 12.5 and set(seen[0][1]) == {"action", "amount", "currency", "execution_id"}
    assert config.store == tmp_path / "state"


def test_g214_the_gateway_file_is_read_strictly(tmp_path):
    """Every way a file can be subtly wrong is an error with a location,
    never a default."""
    def refused(change, match):
        raw = _gateway_raw()
        change(raw)
        with pytest.raises(GatewayConfigError, match=match):
            parse_gateway_config(raw, tmp_path)

    refused(lambda r: r.update(enforcer_singer={"kind": "file"}), r"unknown keys \['enforcer_singer'\]")
    refused(lambda r: r["routes"][0].update(follow_redirects=True), r"routes\[0\] has unknown keys")
    refused(lambda r: r["routes"][0]["operations"][0].update(feilds=[]), r"operations\[0\] has unknown")
    refused(lambda r: r["routes"][0]["operations"][0].update(fields=["amount", "ssn"]), "unknown intent fields")
    refused(lambda r: r.update(rate_limit={"per_minute": True}), "per_minute must be an integer")
    refused(lambda r: r.update(rate_limit={"burst": 0}), "burst must be an integer >= 1")
    refused(lambda r: r.update(auth={"kind": "none"}), "api_keys or open")
    refused(lambda r: r.update(auth={"kind": "api_keys", "tenant": "x"}), "only applies to open")
    refused(lambda r: r.update(routes=[]), "non-empty list")
    refused(lambda r: r.pop("store"), r"missing \['store'\]")
    refused(lambda r: r["routes"][0].update(base_url="ftp://x.example"), "http or https")
    refused(lambda r: r["routes"][0].update(base_url="https://u:p@x.example"), "credentials")
    refused(lambda r: r["routes"][0].update(base_url="https://x.example/?a=1"), "query or fragment")
    refused(lambda r: r["routes"][0].update(base_url="https://x.example:99999"), "invalid port")
    refused(lambda r: r["routes"][0].update(timeout=0), "timeout must be in")
    refused(lambda r: r["routes"][0].update(timeout=float("nan")), "number of seconds")
    refused(lambda r: r["routes"][0].update(network_policy="any"), "public or allow_private")
    refused(lambda r: r["routes"][0].update(allowed_paths=["orders"]), "absolute paths")
    refused(lambda r: r["routes"][0].update(allowed_methods=["TRACE"]), "unsupported")
    refused(lambda r: r["routes"][0]["operations"][0].update(path="/other"), "not in allowed_paths")
    refused(lambda r: r["routes"].append(dict(r["routes"][0])), "duplicate route")
    refused(lambda r: r.update(enforcer_signer="file"), "must be an object")

    dup = tmp_path / "dup.json"
    dup.write_text('{"store": "a", "store": "b", "routes": []}', encoding="utf-8")
    with pytest.raises(GatewayConfigError, match="duplicate key 'store'"):
        load_gateway_config(dup)


def test_g215_paths_are_relative_to_the_file_and_the_signer_is_the_enforcer(tmp_path, monkeypatch):
    conf_dir = tmp_path / "etc"
    conf_dir.mkdir()
    kp = _write_key(conf_dir / "enforcer.key")
    raw = {**_gateway_raw(), "enforcer_signer": {"kind": "file", "path": "enforcer.key"},
           "auth": {"kind": "api_keys"}}
    path = _write(conf_dir, raw)
    monkeypatch.chdir(tmp_path)  # somewhere else entirely
    config = load_gateway_config(path)
    assert config.store == conf_dir / "state"
    app = build_app(config)
    engine = app.app.state.engine
    assert engine.enforcer_did == kp.did()
    assert not (config.store / "enforcer-keys").exists(), "no local key may be generated"
    # api_keys is the default and was chosen: an anonymous caller is refused.
    assert TestClient(app).get("/v1/info").status_code == 401


def test_g216_gateway_check_reports_problems_and_exits_nonzero(tmp_path, capsys):
    good = _write(tmp_path, _gateway_raw())
    assert main(["gateway", "check", "--config", str(good)]) == 0
    out = capsys.readouterr().out
    assert "OPEN" in out and "mandate://procurement" in out and "shared by all workers" in out

    assert main(["gateway", "check", "--config", str(_write(tmp_path, {**_gateway_raw(), "extra": 1}, "bad.json"))]) == 1
    assert "INVALID" in capsys.readouterr().err

    missing_ca = _write(tmp_path, {**_gateway_raw(), "ca_bundle": "nope.pem"}, "ca.json")
    assert main(["gateway", "check", "--config", str(missing_ca)]) == 1
    assert "does not exist" in capsys.readouterr().out

    broken = _write(tmp_path, {**_gateway_raw(), "enforcer_signer": {"kind": "file", "path": "absent.key"}}, "s.json")
    assert main(["gateway", "check", "--config", str(broken)]) == 1
    assert "UNUSABLE" in capsys.readouterr().out


MCP = {
    "audience": "mandate://github",
    "upstream": {"command": "true"},
    "tools": {"create_issue": "github.issue.create"},
    "grant": {"constraints": {"currency": "EUR", "max_daily_amount": 100}},
}


def test_g217_a_misspelt_guard_limit_is_refused_not_dropped(tmp_path):
    """`max_daily_ammount` used to be ignored, and the grant was issued with
    no daily limit. A security file that tolerates typos is choosing the
    permissive reading of every one of them."""
    raw = json.loads(json.dumps(MCP))
    raw["grant"]["constraints"]["max_daily_ammount"] = raw["grant"]["constraints"].pop("max_daily_amount")
    with pytest.raises(MappingError, match="grant.constraints has unknown keys"):
        parse_config(raw)
    with pytest.raises(MappingError, match="configuration has unknown keys"):
        parse_config({**MCP, "enforcer_singer": {"kind": "file"}})
    with pytest.raises(MappingError, match="upstream has unknown keys"):
        parse_config({**MCP, "upstream": {"command": "true", "argv": []}})
    with pytest.raises(MappingError, match="grant has unknown keys"):
        parse_config({**MCP, "grant": {"day": 3}})
    dup = tmp_path / "dup.json"
    dup.write_text('{"audience": "a", "audience": "b"}', encoding="utf-8")
    with pytest.raises(MappingError, match="duplicate key"):
        load_config(dup)
    parse_config(MCP)  # the correct spelling still loads


def test_g218_the_grant_can_be_issued_by_a_key_the_guard_never_writes(tmp_path):
    from mandate.mcp.server import bootstrap, build_engine

    principal = _write_key(tmp_path / "principal-in-kms.key")
    raw = {**json.loads(json.dumps(MCP)), "store": str(tmp_path / "store"),
           "principal_signer": {"kind": "file", "path": str(tmp_path / "principal-in-kms.key")}}
    config = parse_config(raw)

    async def call_tool(name, arguments):  # never called here
        raise AssertionError

    engine, _ = build_engine(config, call_tool, ["create_issue"])
    state = bootstrap(config, engine)
    assert state["principal_did"] == principal.did()
    assert not (config.store_path / "keys" / "principal.key").exists()
    with engine.ledger.tx() as tx:
        grant = tx.get_grant(state["grant_id"])
    assert grant["principal_did"] == principal.did()
    assert verify_object(grant)


def test_g219_served_workers_share_one_limit(tmp_path):
    """The real entry point, `mandate gateway serve`, with two worker
    processes. Six requests against a burst of three: which worker answers
    each one is up to the kernel, and it must not matter."""
    import os
    import socket
    import subprocess
    import sys
    import time

    import httpx

    raw = {**_gateway_raw(), "rate_limit": {"per_minute": 1, "burst": 3}}
    config = _write(tmp_path, raw)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    proc = subprocess.Popen(
        [sys.executable, "-m", "mandate", "gateway", "serve", "--config", str(config),
         "--port", str(port), "--workers", "2"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=5) as client:
            deadline = time.monotonic() + 30
            while True:
                try:
                    client.get("/health")
                    break
                except httpx.TransportError:
                    assert proc.poll() is None, proc.stdout.read().decode()
                    assert time.monotonic() < deadline, "gateway did not start"
                    time.sleep(0.2)
            codes = [client.get("/v1/info").status_code for _ in range(6)]
    finally:
        proc.terminate()
        proc.wait(timeout=15)
    assert codes == [200, 200, 200, 429, 429, 429], codes
