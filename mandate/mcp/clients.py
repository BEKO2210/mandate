"""Ready-to-paste lines that connect an MCP client to the guard.

Absolute paths throughout: a client started from a desktop launcher has
neither the shell's working directory nor its PATH, so `mandate` alone may not
be found, and a relative `--config` would point somewhere else. The Python
interpreter that ran `mandate mcp init` is the one that has Mandate installed.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path


def serve_command(config_path: str | Path) -> list[str]:
    config = str(Path(config_path).expanduser().resolve())
    return [sys.executable, "-m", "mandate", "mcp", "serve", "--config", config]


def snippets(config_path: str | Path, name: str) -> dict[str, str]:
    """`claude_code`: a shell line. `json`: an `mcpServers` entry for Cursor
    (`.cursor/mcp.json`) and Claude Desktop (`claude_desktop_config.json`)."""
    command = serve_command(config_path)
    entry = {"mcpServers": {name: {"command": command[0], "args": command[1:]}}}
    return {
        "claude_code": shlex.join(["claude", "mcp", "add", name, "--", *command]),
        "json": json.dumps(entry, indent=2),
    }


def describe(config_path: str | Path, name: str) -> str:
    s = snippets(config_path, name)
    return (
        "Connect a client:\n"
        f"  Claude Code:\n    {s['claude_code']}\n"
        "  Cursor (.cursor/mcp.json) or Claude Desktop (claude_desktop_config.json):\n"
        + "\n".join("    " + line for line in s["json"].splitlines())
    )
