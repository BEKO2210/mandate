"""MCP onboarding gates G256-G261.

Three things stood between a developer and a guarded MCP server in Claude
Code or Cursor. The store was resolved against whatever directory the client
started the guard in, so a client quietly got a fresh principal, agent and
grant of its own. A call held for human approval could never be released:
the model was told it would run once approved, and nothing could approve it.
And nothing said how to connect a client at all.
"""

from __future__ import annotations

import io
import json
import shlex
import sys
from pathlib import Path

from mandate.cli import main
from mandate.mcp.clients import snippets
from mandate.mcp.config import load_config, read_state
from mandate.mcp.guard import McpGuard
from mandate.mcp.server import build_engine, load_agent_signer, load_principal_signer, open_guard

from .test_mcp_gates import CONFIG, FakeUpstream, _direct_bridge, _world

OVER_THRESHOLD = {"amount": 800, "currency": "EUR", "vendor": "dell.com"}


def _write_config(directory: Path, **overrides) -> Path:
    raw = json.loads(json.dumps(CONFIG))
    raw.pop("store", None)
    raw.update(overrides)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guard.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _guard(config, upstream) -> McpGuard:
    """The guard `serve` would build over an already initialized store."""
    engine, executor = build_engine(config, upstream.call_tool, sorted(config.mapping.rules))
    executor._bridge = _direct_bridge
    state = read_state(config)
    return McpGuard(
        engine=engine, agent_signer=load_agent_signer(config), grant_id=state["grant_id"],
        mapping=config.mapping, tenant=config.tenant, executor=executor,
    )


def _state(guard, receipt_id):
    with guard.engine.ledger.tx() as tx:
        return tx.get_receipt(receipt_id)["state"]


def test_g256_a_relative_store_follows_the_config_file(tmp_path, monkeypatch):
    path = _write_config(tmp_path / "project", store=".mandate-mcp")
    elsewhere = tmp_path / "client-launch-dir"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert main(["mcp", "init", "--config", str(path)]) == 0

    config = load_config(path)
    assert config.store_path == tmp_path / "project" / ".mandate-mcp"
    assert (config.store_path / "guard-state.json").exists()
    assert not any(elsewhere.iterdir()), "nothing may be created where the client happened to start"
    # A second start from yet another directory finds the same grant.
    monkeypatch.chdir(tmp_path)
    assert read_state(load_config(path))["grant_id"] == read_state(config)["grant_id"]

    # A guard initialized under the old rule — store beside where it was
    # started — is not silently replaced by an empty one beside the file.
    old_home = tmp_path / "old-launch-dir"
    moved = _write_config(tmp_path / "moved", store=".mandate-mcp")
    monkeypatch.chdir(old_home.parent)
    old_home.mkdir()
    monkeypatch.chdir(old_home)
    legacy = old_home / ".mandate-mcp"
    legacy.mkdir()
    (legacy / "guard-state.json").write_text("{}", encoding="utf-8")
    assert main(["mcp", "init", "--config", str(moved)]) == 1
    assert not (tmp_path / "moved" / ".mandate-mcp").exists(), "no second identity may be minted"


def test_g257_a_held_call_runs_exactly_once_after_approval(tmp_path):
    upstream = FakeUpstream(reply="paid")
    config, _, _, guard = _world(tmp_path, upstream)

    held = guard.call("pay_invoice", OVER_THRESHOLD)
    assert held.outcome == "HUMAN_REQUIRED" and upstream.calls == []
    assert "Tell the user" in held.text and "mandate mcp approve" not in held.text

    ran = guard.approve(held.receipt_id, load_principal_signer(config))
    assert ran.allowed and ran.outcome == "EXECUTED" and ran.text == "paid"
    assert upstream.calls == [("pay_invoice", OVER_THRESHOLD)]

    again = guard.approve(held.receipt_id, load_principal_signer(config))
    assert not again.allowed and again.outcome == "REFUSED"
    assert len(upstream.calls) == 1
    assert guard.engine.verify_chain(expect_signer=guard.engine.enforcer_did).ok

    # Approved, then the process stopped before dispatch: not stranded.
    upstream = FakeUpstream(reply="paid")
    config, _, _, guard = _world(tmp_path / "stopped", upstream)
    second = guard.call("pay_invoice", OVER_THRESHOLD)
    guard.engine.approve(second.receipt_id, load_principal_signer(config), tenant=guard.tenant)
    assert [r["id"] for r in guard.engine.approved_unclaimed(guard.tenant)] == [second.receipt_id]
    assert guard.approve(second.receipt_id, load_principal_signer(config)).outcome == "REFUSED"
    resumed = guard.resume(second.receipt_id)
    assert resumed.outcome == "EXECUTED" and upstream.calls == [("pay_invoice", OVER_THRESHOLD)]
    assert guard.engine.approved_unclaimed(guard.tenant) == []
    guard.resume(second.receipt_id)
    assert len(upstream.calls) == 1, "the execution claim keeps it to once"


def test_g258_the_agent_cannot_approve_its_own_call(tmp_path):
    upstream = FakeUpstream()
    config, _, _, guard = _world(tmp_path, upstream)
    held = guard.call("pay_invoice", OVER_THRESHOLD)

    refused = guard.approve(held.receipt_id, load_agent_signer(config))

    assert not refused.allowed and refused.outcome == "REFUSED"
    assert upstream.calls == []
    assert _state(guard, held.receipt_id) == "HUMAN_REQUIRED"

    # Approving signs nothing as the agent: a missing agent key cannot block it.
    (config.store_path / "keys" / "agent.key").unlink()
    approver, _ = open_guard(config, upstream.call_tool, ["pay_invoice"], need_agent=False)
    approver.executor._bridge = _direct_bridge
    assert approver.approve(held.receipt_id, load_principal_signer(config)).outcome == "EXECUTED"
    assert len(upstream.calls) == 1


def test_g259_pending_shows_what_approval_would_run(tmp_path, capsys, monkeypatch):
    path = _write_config(tmp_path, store=str(tmp_path / "store"))
    assert main(["mcp", "init", "--config", str(path)]) == 0
    upstream = FakeUpstream()
    held = _guard(load_config(path), upstream).call("pay_invoice", OVER_THRESHOLD)
    capsys.readouterr()

    assert main(["mcp", "pending", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert held.receipt_id in out and "pay_invoice" in out and "800" in out
    assert '"vendor":"dell.com"' in out and "requires human approval" in out

    # The screen a principal decides on cannot be driven by the call itself.
    _guard(load_config(path), upstream).call("pay_invoice", {**OVER_THRESHOLD, "vendor": "evil\x1b[2J.com"})
    assert main(["mcp", "pending", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "evil\\x1b[2J.com" in out

    # Without a terminal and without --yes, approve refuses before running anything.
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["mcp", "approve", "--config", str(path), "--receipt", held.receipt_id]) == 1
    assert "without a terminal" in capsys.readouterr().err
    assert upstream.calls == []
    assert main(["mcp", "approve", "--config", str(path), "--receipt", "rcpt_nope"]) == 1


def test_g260_client_snippets_are_absolute_and_parse(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = snippets("guard.json", "mandate_guard")
    target = str((tmp_path / "guard.json").resolve())

    argv = shlex.split(s["claude_code"])
    assert argv[:4] == ["claude", "mcp", "add", "mandate_guard"]
    assert argv[4] == "--" and argv[5] == sys.executable
    assert argv[-2:] == ["--config", target]

    entry = json.loads(s["json"])["mcpServers"]["mandate_guard"]
    assert entry["command"] == sys.executable and Path(entry["command"]).is_absolute()
    assert entry["args"] == ["-m", "mandate", "mcp", "serve", "--config", target]


def test_g261_a_bad_config_is_one_line_not_a_traceback(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    for cmd in ("init", "serve", "pending"):
        assert main(["mcp", cmd, "--config", str(missing)]) == 1
        err = capsys.readouterr().err
        assert err.startswith("configuration: INVALID") and "Traceback" not in err

    broken = tmp_path / "broken.json"
    broken.write_text('{"audience": "mandate://x", "audience": "mandate://y"}', encoding="utf-8")
    assert main(["mcp", "init", "--config", str(broken)]) == 1
    assert "duplicate key" in capsys.readouterr().err

    unknown_home = _write_config(tmp_path / "tilde", store="~no_such_user_zz9/store")
    assert main(["mcp", "pending", "--config", str(unknown_home)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("configuration: INVALID") and "Traceback" not in err
