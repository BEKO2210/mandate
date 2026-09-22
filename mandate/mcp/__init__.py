"""Mandate in front of an MCP server.

`serve` and `make_server` need the `mcp` package (`pip install mandate[mcp]`).
Everything that decides whether a call may happen — the mapping and the guard —
imports nothing from the SDK, so enforcement can be tested on its own.
"""

from .config import GuardConfig, load_config, parse_config
from .executor import McpExecutor, normalize_result
from .guard import GuardDecision, McpGuard
from .mapping import MappingError, ToolMapping, ToolRule

__all__ = [
    "GuardConfig",
    "GuardDecision",
    "McpExecutor",
    "McpGuard",
    "MappingError",
    "ToolMapping",
    "ToolRule",
    "load_config",
    "normalize_result",
    "parse_config",
]
