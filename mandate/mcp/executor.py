"""Execute an authorized call against an upstream MCP server.

This is an executor in the same sense as `UpstreamExecutor`: the engine claims
the execution, hands over the exact bytes it committed to, and records what
came back. The difference is only the transport — a tool call over MCP instead
of an HTTP request.

The engine is synchronous and the MCP client is not, so `forward` runs in the
worker thread that `anyio.to_thread.run_sync` started and hands the coroutine
back to the event loop with `anyio.from_thread.run`.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Awaitable, Callable

from ..crypto import canonical_json
from ..executor import ExecutionResult
from ..routes import Route

ToolCall = Callable[[str, dict], Awaitable[Any]]

MAX_HASHED_RESPONSE = 4096
MAX_PENDING_PAYLOADS = 64


class McpExecutor:
    """Forward one authorized tool call. Never decides whether it may happen."""

    def __init__(self, call_tool: ToolCall, timeout: float = 30.0, bridge=None) -> None:
        self._call_tool = call_tool
        self.timeout = timeout
        # Injectable so the enforcement path can be tested without an event loop.
        self._bridge = bridge or _anyio_bridge
        # The upstream's content is handed to the caller here, beside the
        # receipt, never inside it: a signed receipt binds the hash of what was
        # sent and received, and must not grow to hold the response itself.
        self._payloads: dict[str, str] = {}

    def take_payload(self, idempotency_key: str) -> str | None:
        """Read and drop the response for one execution."""
        return self._payloads.pop(idempotency_key, None)

    def _keep(self, idempotency_key: str, text: str) -> None:
        if len(self._payloads) >= MAX_PENDING_PAYLOADS:
            # Nobody collected these; drop the oldest rather than grow forever.
            self._payloads.pop(next(iter(self._payloads)), None)
        self._payloads[idempotency_key] = text

    def forward(
        self, route: Route, method: str, path: str, body: bytes, idempotency_key: str
    ) -> ExecutionResult:
        if method not in route.allowed_methods:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "method not allowed")
        if path not in route.allowed_paths:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "path not allowed")

        try:
            payload = json.loads(body.decode("utf-8"))
            tool = payload["tool"]
            arguments = json.loads(payload["arguments_json"])
        except (ValueError, KeyError, UnicodeDecodeError) as exc:
            return ExecutionResult(
                "EXECUTION_FAILED", None, 0, None, f"unusable request body: {exc}"
            )
        if "/" + tool != path:
            # The path is what the route authorized; the body must agree with it.
            return ExecutionResult(
                "EXECUTION_FAILED", None, 0, None, "tool does not match the authorized path"
            )

        t0 = time.monotonic()
        try:
            result = self._bridge(self._call_tool, tool, arguments, self.timeout)
        except TimeoutError:
            return ExecutionResult(
                "EXECUTION_UNKNOWN", None, _ms(t0), None, "timeout",
            )
        except Exception as exc:
            # The tool may have run before the transport broke, so the outcome
            # is unknown rather than failed.
            return ExecutionResult(
                "EXECUTION_UNKNOWN", None, _ms(t0), None, f"transport error: {type(exc).__name__}"
            )

        is_error, text = normalize_result(result)
        digest = hashlib.sha256(text.encode("utf-8")[:MAX_HASHED_RESPONSE]).hexdigest()
        self._keep(idempotency_key, text)
        if is_error:
            # The tool ran and reported failure, like a non-2xx HTTP response.
            return ExecutionResult(
                "EXECUTION_FAILED", None, _ms(t0), digest, "tool reported an error", payload=text
            )
        return ExecutionResult("EXECUTED", None, _ms(t0), digest, None, payload=text)


def normalize_result(result: Any) -> tuple[bool, str]:
    """Reduce an MCP result to (is_error, text) without importing the SDK."""
    if result is None:
        return False, ""
    if isinstance(result, str):
        return False, result

    # mcp 1.x exposed `isError`; 2.x renamed it to `is_error` and kept the
    # wire alias, so both spellings have to be understood here.
    is_error = bool(
        getattr(result, "is_error", None)
        or getattr(result, "isError", None)
        or (isinstance(result, dict) and (result.get("is_error") or result.get("isError")))
    )
    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if content is None:
        return is_error, _stringify(result)

    parts: list[str] = []
    for item in content if isinstance(content, list) else [content]:
        text = getattr(item, "text", None)
        if text is None and isinstance(item, dict):
            text = item.get("text")
        parts.append(text if isinstance(text, str) else _stringify(item))
    return is_error, "\n".join(p for p in parts if p)


def _stringify(value: Any) -> str:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return canonical_json(dump(mode="json")).decode("utf-8")
        except Exception:
            pass
    try:
        return canonical_json(value).decode("utf-8")
    except Exception:
        return str(value)


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def _anyio_bridge(call_tool: ToolCall, tool: str, arguments: dict, timeout: float) -> Any:
    import anyio

    async def run() -> Any:
        with anyio.fail_after(timeout):
            return await call_tool(tool, arguments)

    return anyio.from_thread.run(run)
