"""Run the guard as an MCP server in front of another MCP server.

    model ──stdio──▶ mandate guard ──stdio──▶ upstream MCP server

The model never reaches the upstream. Each call is turned into a signed intent,
evaluated against the grant, and only then dispatched — by the same engine, the
same ledger and the same receipts as the HTTP gateway.

The upstream's tool schemas are passed through verbatim, so the model sees the
tools it already knows. That is why this uses the low-level server API: the
higher-level one derives a schema from a Python signature, which a proxy has no
way to provide.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..crypto import KeyPair, utcnow
from ..engine import Engine
from ..keys import PersistedDevKeyProvider
from ..ledger import Ledger
from ..routes import Route, RouteRegistry
from .config import GuardConfig, read_state, write_state
from .executor import McpExecutor
from .guard import McpGuard

BASE_URL = "mcp://upstream"

INSTRUCTIONS = (
    "These tools are enforced by Mandate. Every call is authorized against a "
    "signed grant before it runs, and produces a signed receipt. A refusal names "
    "the limit that refused it — it is a property of the grant, not of the tool, "
    "so retrying the same call unchanged will be refused again."
)


def log(message: str) -> None:
    """stdio transport owns stdout; diagnostics go to stderr."""
    print(f"[mandate-guard] {message}", file=sys.stderr, flush=True)


def build_engine(config: GuardConfig, call_tool, tool_names: list[str]) -> tuple[Engine, McpExecutor]:
    """An engine whose executor dispatches over MCP instead of HTTP."""
    store = config.store_path
    store.mkdir(parents=True, exist_ok=True)
    mapped = [t for t in tool_names if t in config.mapping.rules or config.mapping.allow_unmapped]
    operations = tuple(config.mapping.operation_for(t) for t in mapped)
    route = Route(
        audience=config.audience,
        base_url=BASE_URL,
        allowed_methods=("POST",),
        allowed_paths=tuple("/" + t for t in mapped),
        timeout=config.timeout,
        operations=operations,
        tenant=config.tenant,
    )
    executor = McpExecutor(call_tool, timeout=config.timeout)
    engine = Engine(
        ledger=Ledger(store / "mandate.sqlite"),
        key_provider=PersistedDevKeyProvider(store / "enforcer-keys"),
        routes=RouteRegistry([route]),
        executor=executor,
    )
    return engine, executor


def bootstrap(config: GuardConfig, engine: Engine) -> dict[str, str]:
    """Create the principal, agent and grant this guard runs under.

    Development convenience: both private keys are written to the store as
    plain files. A deployment that matters issues the grant elsewhere and gives
    the guard only the agent key.
    """
    keys = config.store_path / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    principal, principal_kp = engine.register_principal(
        config.grant.organization, kind="org", tenant=config.tenant
    )
    agent, agent_kp = engine.register_agent(
        name=config.server_name,
        operator_did=principal.did,
        developer="Mandate",
        model="mcp-guard",
        tenant=config.tenant,
    )
    grant = engine.issue_grant(
        principal=principal,
        principal_kp=principal_kp,
        agent=agent,
        organization=config.grant.organization,
        purpose=config.grant.purpose,
        scopes=config.scopes(),
        not_after=utcnow() + timedelta(days=config.grant.days),
        constraints=config.grant.to_constraint(),
        tenant=config.tenant,
    )
    _write_key(keys / "principal.key", principal_kp)
    _write_key(keys / "agent.key", agent_kp)
    state = {
        "principal_did": principal.did,
        "agent_did": agent.did,
        "grant_id": grant["id"],
        "tenant": config.tenant,
    }
    write_state(config, state)
    return state


def _write_key(path: Path, kp: KeyPair) -> None:
    path.write_text(kp.private_bytes().hex(), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_agent_key(config: GuardConfig) -> KeyPair:
    path = config.store_path / "keys" / "agent.key"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing; run `mandate mcp init --config <file>` first"
        )
    return KeyPair.from_private_bytes(bytes.fromhex(path.read_text(encoding="utf-8").strip()))


def make_server(name: str, tools: list[Any], guard: McpGuard):
    """Re-expose `tools`, each call routed through the guard."""
    import anyio
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server(name, instructions=INSTRUCTIONS)
    exposed = {tool.name: tool for tool in tools}

    async def on_list(ctx, params):
        return types.ListToolsResult(tools=list(exposed.values()))

    async def on_call(ctx, params):
        tool = params.name
        arguments = dict(params.arguments or {})
        if tool not in exposed:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool {tool!r}.")],
                isError=True,
            )
        # The engine and its ledger are synchronous; the upstream call is not.
        # The worker thread is what lets the executor hand its coroutine back.
        decision = await anyio.to_thread.run_sync(lambda: guard.call(tool, arguments))
        if not decision.allowed:
            log(f"{tool}: {decision.outcome} ({decision.receipt_id})")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=decision.text)],
            isError=not decision.allowed,
        )

    server.add_request_handler("tools/list", types.PaginatedRequestParams, on_list)
    server.add_request_handler("tools/call", types.CallToolRequestParams, on_call)
    return server


async def serve(config: GuardConfig) -> None:
    """Connect to the upstream, mirror its tools, and serve the guard on stdio."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server.stdio import stdio_server

    params = StdioServerParameters(
        command=config.upstream.command,
        args=list(config.upstream.args),
        env=config.upstream.env or None,
        cwd=config.upstream.cwd,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [t.name for t in listed.tools]
            exposed, hidden = _partition(config, names)
            if hidden:
                log(f"not exposing unmapped tools: {', '.join(hidden)}")
            if not exposed:
                raise SystemExit(
                    "none of the upstream tools are mapped; nothing to expose"
                )
            log(f"exposing {len(exposed)} of {len(names)} upstream tools")

            engine, executor = build_engine(config, session.call_tool, exposed)
            state = read_state(config) or bootstrap(config, engine)
            guard = McpGuard(
                engine=engine,
                agent_kp=load_agent_key(config),
                grant_id=state["grant_id"],
                mapping=config.mapping,
                tenant=config.tenant,
                executor=executor,
            )
            log(f"grant {state['grant_id']} for tenant {config.tenant}")

            tools = [t for t in listed.tools if t.name in set(exposed)]
            server = make_server(config.server_name, tools, guard)
            async with stdio_server() as (r, w):
                await server.run(r, w, server.create_initialization_options())


def _partition(config: GuardConfig, names: list[str]) -> tuple[list[str], list[str]]:
    if config.mapping.allow_unmapped:
        return list(names), []
    exposed = [n for n in names if n in config.mapping.rules]
    return exposed, [n for n in names if n not in config.mapping.rules]
