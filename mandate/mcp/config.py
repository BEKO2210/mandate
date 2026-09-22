"""Guard configuration, read from one JSON file.

Everything an agent must not choose lives here: which tools exist, what each
one counts as, the grant's limits, and where the upstream server comes from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..auth import DEFAULT_TENANT
from ..models import Constraint
from .mapping import MappingError, ToolMapping, ToolRule

DEFAULT_STORE = ".mandate-mcp"
DEFAULT_TIMEOUT = 30.0
DEFAULT_GRANT_DAYS = 30


@dataclass(frozen=True)
class UpstreamConfig:
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None


@dataclass(frozen=True)
class GrantConfig:
    organization: str = "Mandate"
    purpose: str = "MCP tool use"
    days: int = DEFAULT_GRANT_DAYS
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_constraint(self) -> Constraint:
        c = dict(self.constraints)
        return Constraint(
            currency=c.get("currency", "EUR"),
            max_amount=c.get("max_amount"),
            max_daily_amount=c.get("max_daily_amount"),
            require_human_above=c.get("require_human_above"),
            counterparties_allow=list(c.get("counterparties_allow") or []),
            counterparties_deny=list(c.get("counterparties_deny") or []),
        )


@dataclass
class GuardConfig:
    audience: str
    upstream: UpstreamConfig
    mapping: ToolMapping
    grant: GrantConfig = field(default_factory=GrantConfig)
    tenant: str = DEFAULT_TENANT
    store: str = DEFAULT_STORE
    timeout: float = DEFAULT_TIMEOUT
    server_name: str = "mandate_guard"

    @property
    def store_path(self) -> Path:
        return Path(self.store)

    @property
    def state_path(self) -> Path:
        return self.store_path / "guard-state.json"

    def scopes(self) -> list[str]:
        """The grant covers exactly the actions this guard can produce."""
        return sorted({rule.action for rule in self.mapping.rules.values()})


def load_config(path: str | Path) -> GuardConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> GuardConfig:
    try:
        upstream_raw = raw["upstream"]
        upstream = UpstreamConfig(
            command=upstream_raw["command"],
            args=tuple(upstream_raw.get("args") or ()),
            env=dict(upstream_raw.get("env") or {}),
            cwd=upstream_raw.get("cwd"),
        )
    except (KeyError, TypeError) as exc:
        raise MappingError(f"upstream must name a command to run: {exc}") from exc

    rules: dict[str, ToolRule] = {}
    for tool, spec in (raw.get("tools") or {}).items():
        if isinstance(spec, str):
            spec = {"action": spec}
        if not isinstance(spec, dict) or "action" not in spec:
            raise MappingError(f"tool {tool!r} needs an action")
        unknown = set(spec) - {
            "action", "amount_from", "currency_from", "currency", "counterparty_from"
        }
        if unknown:
            raise MappingError(f"tool {tool!r} has unknown settings {sorted(unknown)}")
        rules[tool] = ToolRule(**spec)

    mapping = ToolMapping(
        audience=raw.get("audience", ""),
        rules=rules,
        allow_unmapped=bool(raw.get("allow_unmapped", False)),
    )
    if not rules and not mapping.allow_unmapped:
        raise MappingError(
            "no tools are mapped and allow_unmapped is false, so this guard would "
            "refuse every call"
        )

    grant_raw = raw.get("grant") or {}
    grant = GrantConfig(
        organization=grant_raw.get("organization", "Mandate"),
        purpose=grant_raw.get("purpose", "MCP tool use"),
        days=int(grant_raw.get("days", DEFAULT_GRANT_DAYS)),
        constraints=dict(grant_raw.get("constraints") or {}),
    )

    return GuardConfig(
        audience=mapping.audience,
        upstream=upstream,
        mapping=mapping,
        grant=grant,
        tenant=raw.get("tenant", DEFAULT_TENANT),
        store=raw.get("store", DEFAULT_STORE),
        timeout=float(raw.get("timeout", DEFAULT_TIMEOUT)),
        server_name=raw.get("server_name", "mandate_guard"),
    )


def read_state(config: GuardConfig) -> dict[str, str] | None:
    if not config.state_path.exists():
        return None
    return json.loads(config.state_path.read_text(encoding="utf-8"))


def write_state(config: GuardConfig, state: dict[str, str]) -> None:
    config.store_path.mkdir(parents=True, exist_ok=True)
    config.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
