"""v0.5.0 MCP guard gates G101-G119.

The guard is the point where an agent's tool call meets its grant. These gates
cover the decision, not the protocol: mapping, refusal text, the execution
path, and the invariant that the tools a model can see are the tools the
configuration mapped.
"""

from __future__ import annotations

import json

import pytest

from mandate.crypto import canonical_json, utcnow
from mandate.mcp.config import parse_config
from mandate.mcp.executor import McpExecutor, normalize_result
from mandate.mcp.guard import McpGuard
from mandate.mcp.mapping import MappingError, ToolMapping, ToolRule, normalize_action
from mandate.mcp.server import BASE_URL, bootstrap, build_engine, load_agent_signer
from mandate.routes import Route

CONFIG = {
    "audience": "mandate://github",
    "upstream": {"command": "npx", "args": ["-y", "server-github"]},
    "tools": {
        "create_issue": {"action": "repo.issue.create"},
        "pay_invoice": {
            "action": "finance.invoice.pay",
            "amount_from": "amount",
            "currency_from": "currency",
            "counterparty_from": "vendor",
        },
    },
    "grant": {
        "organization": "Aslani GmbH",
        "purpose": "repo automation",
        "constraints": {
            "currency": "EUR",
            "max_amount": 5000,
            "max_daily_amount": 1000,
            "require_human_above": 700,
            "counterparties_deny": ["shady.example"],
        },
    },
}


def _config(tmp_path, **overrides):
    raw = json.loads(json.dumps(CONFIG))
    raw["store"] = str(tmp_path / "store")
    raw.update(overrides)
    return parse_config(raw)


class FakeUpstream:
    """Stands in for a live MCP peer. Records what it was actually asked."""

    def __init__(self, reply="ok", is_error=False, raises=None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.reply = reply
        self.is_error = is_error
        self.raises = raises

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.raises is not None:
            raise self.raises
        return {"is_error": self.is_error, "content": [{"type": "text", "text": self.reply}]}


def _direct_bridge(call_tool, tool, arguments, timeout):
    """Run the coroutine here instead of handing it to an event loop."""
    import asyncio

    return asyncio.run(call_tool(tool, arguments))


def _world(tmp_path, upstream, config=None):
    config = config or _config(tmp_path)
    tools = sorted(config.mapping.rules)
    engine, executor = build_engine(config, upstream.call_tool, tools)
    executor._bridge = _direct_bridge
    state = bootstrap(config, engine)
    guard = McpGuard(
        engine=engine,
        agent_signer=load_agent_signer(config),
        grant_id=state["grant_id"],
        mapping=config.mapping,
        tenant=config.tenant,
        executor=executor,
    )
    return config, engine, executor, guard


# --- Mapping ---------------------------------------------------------------

def test_g101_an_unmapped_tool_is_refused_not_guessed():
    mapping = ToolMapping("mandate://x", {"create_issue": ToolRule("repo.issue.create")})
    with pytest.raises(MappingError, match="not mapped"):
        mapping.intent_fields("delete_repository", {})

    permissive = ToolMapping("mandate://x", {}, allow_unmapped=True)
    assert permissive.intent_fields("delete_repository", {})["action"] == "delete_repository"


def test_g102_arguments_travel_as_one_document_not_as_named_fields():
    """An MCP tool may take a `url`; a signed intent may not have that key."""
    mapping = ToolMapping("mandate://x", {"fetch": ToolRule("web.fetch")})
    fields = mapping.intent_fields("fetch", {"url": "https://example.com", "host": "x"})

    assert set(fields["context"]) == {"tool", "arguments_json"}
    assert "url" not in fields["context"]
    assert json.loads(fields["context"]["arguments_json"])["url"] == "https://example.com"
    # The document is canonical, so the same arguments always hash the same.
    assert fields["context"]["arguments_json"] == canonical_json(
        {"host": "x", "url": "https://example.com"}
    ).decode()


def test_g103_money_arguments_must_be_numbers():
    mapping = ToolMapping(
        "mandate://x",
        {"pay": ToolRule("finance.pay", amount_from="amount", currency_from="currency")},
    )
    fields = mapping.intent_fields("pay", {"amount": 12.30, "currency": "eur"})
    assert (fields["amount"], fields["currency"]) == (12.30, "EUR")

    with pytest.raises(MappingError, match="must be a number"):
        mapping.intent_fields("pay", {"amount": "12.30", "currency": "EUR"})
    with pytest.raises(MappingError, match="did not provide"):
        mapping.intent_fields("pay", {"currency": "EUR"})


def test_g104_oversized_arguments_are_refused_before_signing():
    mapping = ToolMapping("mandate://x", {"write": ToolRule("file.write")})
    with pytest.raises(MappingError, match="larger than"):
        mapping.intent_fields("write", {"body": "x" * 4000})


def test_g105_action_names_are_constrained():
    assert normalize_action("create-Issue") == "create_issue"
    assert normalize_action("GitHub.Repo.Create") == "github.repo.create"
    with pytest.raises(MappingError):
        normalize_action("")
    with pytest.raises(MappingError):
        ToolRule(action="Not Valid")


def test_g106_a_guard_that_maps_nothing_is_a_configuration_error():
    with pytest.raises(MappingError, match="refuse every call"):
        parse_config({**CONFIG, "tools": {}})
    with pytest.raises(MappingError, match="unknown settings"):
        parse_config({**CONFIG, "tools": {"x": {"action": "a.b", "typo": 1}}})


# --- Executor --------------------------------------------------------------

def _route(tool="create_issue"):
    return Route(
        audience="mandate://github",
        base_url=BASE_URL,
        allowed_methods=("POST",),
        allowed_paths=("/" + tool,),
    )


def _body(tool="create_issue", **arguments):
    return canonical_json(
        {"action": "repo.issue.create", "execution_id": "exec_1",
         "tool": tool, "arguments_json": canonical_json(arguments).decode()}
    )


def test_g107_executor_forwards_the_arguments_it_was_given():
    upstream = FakeUpstream(reply="issue #7 created")
    ex = McpExecutor(upstream.call_tool, bridge=_direct_bridge)

    result = ex.forward(_route(), "POST", "/create_issue", _body(repo="beko/mandate"), "idem-1")

    assert result.state == "EXECUTED"
    assert upstream.calls == [("create_issue", {"repo": "beko/mandate"})]
    assert ex.take_payload("idem-1") == "issue #7 created"
    # Collected once; the receipt is the durable record, not this buffer.
    assert ex.take_payload("idem-1") is None


def test_g108_a_tool_error_is_a_failed_execution_not_a_success():
    upstream = FakeUpstream(reply="repo not found", is_error=True)
    ex = McpExecutor(upstream.call_tool, bridge=_direct_bridge)
    result = ex.forward(_route(), "POST", "/create_issue", _body(repo="x"), "idem-2")
    assert result.state == "EXECUTION_FAILED"
    assert result.body_hash


def test_g109_a_broken_transport_is_unknown_not_failed():
    """The tool may have run before the pipe broke, so the outcome is unknown."""
    upstream = FakeUpstream(raises=ConnectionResetError("pipe"))
    ex = McpExecutor(upstream.call_tool, bridge=_direct_bridge)
    result = ex.forward(_route(), "POST", "/create_issue", _body(repo="x"), "idem-3")
    assert result.state == "EXECUTION_UNKNOWN"


def test_g110_the_body_must_agree_with_the_authorized_path():
    upstream = FakeUpstream()
    ex = McpExecutor(upstream.call_tool, bridge=_direct_bridge)
    result = ex.forward(_route(), "POST", "/create_issue", _body(tool="delete_repo"), "idem-4")
    assert result.state == "EXECUTION_FAILED"
    assert "does not match" in result.error
    assert upstream.calls == []


def test_g111_results_are_normalized_from_both_sdk_spellings():
    class V1:
        isError = True
        content = [type("C", (), {"text": "boom"})()]

    class V2:
        is_error = False
        content = [type("C", (), {"text": "fine"})()]

    assert normalize_result(V1()) == (True, "boom")
    assert normalize_result(V2()) == (False, "fine")
    assert normalize_result("plain") == (False, "plain")
    assert normalize_result(None) == (False, "")


# --- Guard decisions -------------------------------------------------------

def test_g112_an_allowed_call_reaches_the_upstream_and_leaves_a_receipt(tmp_path):
    upstream = FakeUpstream(reply="issue #7 created")
    config, engine, _, guard = _world(tmp_path, upstream)

    decision = guard.call("create_issue", {"repo": "beko/mandate", "title": "hi"})

    assert decision.allowed
    assert decision.text == "issue #7 created"
    assert decision.outcome == "EXECUTED"
    assert upstream.calls == [("create_issue", {"repo": "beko/mandate", "title": "hi"})]

    receipt = engine.get_receipt(decision.receipt_id, tenant=config.tenant)
    assert receipt["outcome"] == "EXECUTED"
    # The receipt binds what was sent; it does not carry the response itself.
    assert receipt["execution"]["request"]["hash"].startswith("sha256:")
    assert "payload" not in receipt["execution"]
    assert "issue #7" not in json.dumps(receipt)


def test_g113_a_denied_call_never_reaches_the_upstream_and_says_why(tmp_path):
    upstream = FakeUpstream()
    _, _, _, guard = _world(tmp_path, upstream)

    decision = guard.call(
        "pay_invoice", {"amount": 9000.00, "currency": "EUR", "vendor": "dell.com"}
    )

    assert not decision.allowed
    assert upstream.calls == []
    assert "exceeds max_amount" in decision.text
    # The refusal points at the grant, so the agent does not retry the tool.
    assert "grant" in decision.text and decision.receipt_id in decision.text
    assert decision.to_tool_result()["isError"] is True


def test_g114_a_call_over_the_human_threshold_waits_instead_of_running(tmp_path):
    upstream = FakeUpstream()
    _, engine, _, guard = _world(tmp_path, upstream)

    decision = guard.call(
        "pay_invoice", {"amount": 800.00, "currency": "EUR", "vendor": "dell.com"}
    )

    assert not decision.allowed
    assert decision.outcome == "HUMAN_REQUIRED"
    assert upstream.calls == []
    assert "approval" in decision.text and "Do not retry" in decision.text
    with engine.ledger.tx() as tx:
        assert tx.get_receipt(decision.receipt_id)["state"] == "HUMAN_REQUIRED"


def test_g115_an_unmapped_tool_is_refused_before_any_intent_is_signed(tmp_path):
    upstream = FakeUpstream()
    _, engine, _, guard = _world(tmp_path, upstream)

    decision = guard.call("delete_repository", {"repo": "beko/mandate"})

    assert not decision.allowed
    assert decision.outcome == "UNMAPPED"
    assert decision.receipt_id is None
    assert upstream.calls == []
    with engine.ledger.tx() as tx:
        assert tx.l._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0


def test_g116_an_unknown_upstream_outcome_keeps_the_budget_reserved(tmp_path):
    upstream = FakeUpstream(raises=ConnectionResetError("pipe"))
    config, engine, _, guard = _world(tmp_path, upstream)

    decision = guard.call("pay_invoice", {"amount": 10.00, "currency": "EUR", "vendor": "dell.com"})

    assert not decision.allowed
    assert decision.outcome == "EXECUTION_UNKNOWN"
    assert "check whether the action took effect" in decision.text
    day = utcnow().strftime("%Y-%m-%d")
    with engine.ledger.tx() as tx:
        grant_id = json.loads(tx.get_receipt(decision.receipt_id)["body"])["grant_id"]
        assert tx.spent(grant_id, "EUR", day) == 1000


def test_g117_the_grant_covers_exactly_the_mapped_actions(tmp_path):
    upstream = FakeUpstream()
    config, engine, _, guard = _world(tmp_path, upstream)
    assert config.scopes() == ["finance.invoice.pay", "repo.issue.create"]

    with engine.ledger.tx() as tx:
        grant = tx.get_grant(guard.grant_id, tenant=config.tenant)
    assert sorted(grant["scopes"]) == ["finance.invoice.pay", "repo.issue.create"]
    # Nothing outside the mapping is in scope, so a stray action cannot ride along.
    assert "delete_repository" not in grant["scopes"]


def test_g118_setup_is_idempotent_and_keys_stay_private(tmp_path):
    upstream = FakeUpstream()
    config, engine, _, guard = _world(tmp_path, upstream)

    from mandate.mcp.config import read_state

    state = read_state(config)
    assert state["grant_id"] == guard.grant_id
    key = config.store_path / "keys" / "agent.key"
    assert key.exists()
    assert oct(key.stat().st_mode)[-3:] == "600"
    assert load_agent_signer(config).did() == state["agent_did"]


# --- SDK wiring ------------------------------------------------------------

def test_g119_the_server_mirrors_upstream_schemas_and_maps_refusals(tmp_path):
    """The protocol surface: schemas pass through, a refusal is an MCP error."""
    import anyio

    pytest.importorskip("mcp", reason="the guard's transport needs the MCP SDK")
    import mcp.types as types

    from mandate.mcp.server import make_server

    upstream = FakeUpstream(reply="issue #7 created")
    _, _, _, guard = _world(tmp_path, upstream)

    schema = {
        "type": "object",
        "properties": {"repo": {"type": "string"}, "title": {"type": "string"}},
        "required": ["repo"],
    }
    tools = [types.Tool(name="create_issue", description="Create an issue", inputSchema=schema)]
    server = make_server("mandate_guard", tools, guard)

    async def exercise():
        listed = await server.get_request_handler("tools/list").handler(
            None, types.PaginatedRequestParams()
        )
        call = server.get_request_handler("tools/call").handler
        ok = await call(
            None,
            types.CallToolRequestParams(
                name="create_issue", arguments={"repo": "beko/mandate", "title": "hi"}
            ),
        )
        denied = await call(
            None, types.CallToolRequestParams(name="delete_repository", arguments={})
        )
        return listed, ok, denied

    listed, ok, denied = anyio.run(exercise)

    # The model sees the upstream's own schema, not one derived from Python.
    assert listed.tools[0].input_schema == schema
    assert ok.is_error is False
    assert ok.content[0].text == "issue #7 created"
    assert upstream.calls == [("create_issue", {"repo": "beko/mandate", "title": "hi"})]
    # A tool the guard does not expose is refused, not forwarded.
    assert denied.is_error is True
    assert "Unknown tool" in denied.content[0].text
