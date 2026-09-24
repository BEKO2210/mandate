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
from ..signing import Signer, SigningError, check_signer_block, signer_from_config
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
    # Where the two keys live. Absent means the development default: a file in
    # the store, readable by this process. A block here means a key manager,
    # and then the guard signs without ever holding the key.
    agent_signer: dict[str, Any] | None = None
    enforcer_signer: dict[str, Any] | None = None
    # The key that issues the grant. Absent, `mcp init` writes it to the store
    # as a file; with a block it stays in the key manager.
    principal_signer: dict[str, Any] | None = None
    # `store` as the file wrote it, before it was anchored to the file's
    # directory. Kept so a store the guard used to resolve against its working
    # directory can be recognised instead of silently replaced.
    store_as_written: str | None = None

    def build_agent_signer(self) -> Signer | None:
        return signer_from_config(self.agent_signer) if self.agent_signer else None

    def build_enforcer_signer(self) -> Signer | None:
        return signer_from_config(self.enforcer_signer) if self.enforcer_signer else None

    def build_principal_signer(self) -> Signer | None:
        return signer_from_config(self.principal_signer) if self.principal_signer else None

    @property
    def holds_agent_key(self) -> bool:
        """True when the agent's private key is a file this process reads."""
        return not self.agent_signer or self.agent_signer.get("kind") == "file"

    @property
    def store_path(self) -> Path:
        return Path(self.store)

    @property
    def state_path(self) -> Path:
        return self.store_path / "guard-state.json"

    def scopes(self) -> list[str]:
        """The grant covers exactly the actions this guard can produce."""
        return sorted({rule.action for rule in self.mapping.rules.values()})


# Every key this file may contain. Anything else is refused rather than
# ignored: a misspelt `max_daily_amount` used to be dropped without a word,
# and the grant was issued with no daily limit at all.
_TOP = {"audience", "upstream", "tools", "allow_unmapped", "grant", "tenant", "store",
        "timeout", "server_name", "agent_signer", "enforcer_signer", "principal_signer"}
_UPSTREAM = {"command", "args", "env", "cwd"}
_GRANT = {"organization", "purpose", "days", "constraints"}
_CONSTRAINTS = {"currency", "max_amount", "max_daily_amount", "require_human_above",
                "counterparties_allow", "counterparties_deny"}


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MappingError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _known(block: Any, allowed: set[str], where: str) -> None:
    if not isinstance(block, dict):
        raise MappingError(f"{where} must be an object")
    unknown = set(block) - allowed
    if unknown:
        raise MappingError(f"{where} has unknown keys {sorted(unknown)}")


def load_config(path: str | Path) -> GuardConfig:
    """Read a guard configuration; relative paths in it follow the file.

    Claude Code, Cursor and Claude Desktop start the guard from a directory
    of their choosing. A store resolved against *that* would be a different
    store per client — and `serve` then bootstraps a fresh principal, agent
    and grant there without a word.
    """
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
    config = parse_config(raw, base_dir=path.resolve().parent)
    _refuse_a_stranded_store(config)
    return config


def _refuse_a_stranded_store(config: GuardConfig) -> None:
    """A relative store used to follow the working directory. If one was
    initialized that way and the store the file now points at is empty, using
    the new one would mint a second principal, agent and grant — with none of
    the old receipts or budget behind them. Refuse, and say where the old one is.
    """
    written = config.store_as_written
    if not written or Path(written).expanduser().is_absolute() or config.state_path.exists():
        return
    legacy = (Path.cwd() / written).resolve()
    if legacy != config.store_path.resolve() and (legacy / "guard-state.json").exists():
        raise MappingError(
            f"store {written!r} now resolves next to the configuration file "
            f"({config.store_path}), which is empty, but a guard was initialized at "
            f"{legacy}. Set \"store\" to that absolute path to keep its grant, "
            f"receipts and budget, or move it next to the configuration file."
        )


def _relative(base: Path | None, value: Any) -> Any:
    if base is None or not isinstance(value, str) or not value:
        return value
    try:
        path = Path(value).expanduser()
    except RuntimeError as exc:  # an unknown ~user
        raise MappingError(f"{value}: {exc}") from exc
    return str(path if path.is_absolute() else base / path)


def parse_config(raw: dict[str, Any], base_dir: str | Path | None = None) -> GuardConfig:
    """`base_dir` anchors relative paths; without one they are left as given."""
    base = Path(base_dir) if base_dir is not None else None
    _known(raw, _TOP, "configuration")
    if isinstance(raw.get("upstream"), dict):
        _known(raw["upstream"], _UPSTREAM, "upstream")
    if raw.get("grant") is not None:
        _known(raw["grant"], _GRANT, "grant")
        if raw["grant"].get("constraints") is not None:
            _known(raw["grant"]["constraints"], _CONSTRAINTS, "grant.constraints")
    try:
        upstream_raw = raw["upstream"]
        upstream = UpstreamConfig(
            command=upstream_raw["command"],
            args=tuple(upstream_raw.get("args") or ()),
            env=dict(upstream_raw.get("env") or {}),
            cwd=_relative(base, upstream_raw.get("cwd")),
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

    for name in ("agent_signer", "enforcer_signer", "principal_signer"):
        block = raw.get(name)
        if block is not None and not isinstance(block, dict):
            raise MappingError(f"{name} must be an object naming a signer kind")
        if isinstance(block, dict) and not block.get("kind"):
            raise MappingError(f"{name} needs a kind (file, aws-kms, gcp-kms, …)")
        if isinstance(block, dict):
            try:
                check_signer_block(block)
            except SigningError as exc:
                raise MappingError(f"{name}: {exc}") from exc

    signers = {}
    for name in ("agent_signer", "enforcer_signer", "principal_signer"):
        block = raw.get(name)
        if isinstance(block, dict) and block.get("kind") == "file" and "path" in block:
            block = {**block, "path": _relative(base, block["path"])}
        signers[name] = block

    return GuardConfig(
        audience=mapping.audience,
        upstream=upstream,
        mapping=mapping,
        grant=grant,
        tenant=raw.get("tenant", DEFAULT_TENANT),
        store=_relative(base, raw.get("store", DEFAULT_STORE)),
        timeout=float(raw.get("timeout", DEFAULT_TIMEOUT)),
        server_name=raw.get("server_name", "mandate_guard"),
        agent_signer=signers["agent_signer"],
        enforcer_signer=signers["enforcer_signer"],
        principal_signer=signers["principal_signer"],
        store_as_written=raw.get("store", DEFAULT_STORE),
    )


def read_state(config: GuardConfig) -> dict[str, str] | None:
    if not config.state_path.exists():
        return None
    return json.loads(config.state_path.read_text(encoding="utf-8"))


def write_state(config: GuardConfig, state: dict[str, str]) -> None:
    config.store_path.mkdir(parents=True, exist_ok=True)
    config.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
