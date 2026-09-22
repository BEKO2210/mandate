"""HTTP gateway configuration, read from one JSON file.

Until this module the gateway could only be assembled in Python: routes,
operations and the enforcer's signer were constructor arguments. That is fine
for tests and wrong for an operator, who then writes code to run a security
boundary. Everything the gateway needs is now one file, and the file is read
strictly — an unknown key, a wrong type or a duplicate member is an error,
never a default. A misspelt `enforcer_signer` that silently fell back to a
local key file would be the worst kind of configuration bug: one that works.

Relative paths (`store`, `ca_bundle`, a file signer's `path`) are relative to
the configuration file, so the same file means the same thing from any
working directory.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .auth import DEFAULT_TENANT, LedgerApiKeyAuth, LedgerRateLimiter, OpenAccess
from .engine import DEFAULT_EXECUTION_STALE_AFTER_S, Engine
from .executor import UpstreamExecutor
from .keys import PersistedDevKeyProvider, SignerKeyProvider
from .ledger import Ledger
from .routes import ALLOWED_METHODS, INTENT_FIELDS, Operation, Route, RouteConfigError, RouteRegistry
from .signing import Signer, SigningError, check_signer_block, signer_from_config
from .witness import AnchorSchedule, WitnessError, check_witness_url, token_from_env

ENV_VAR = "MANDATE_GATEWAY_CONFIG"
MAX_TIMEOUT_S = 120.0

_TOP = {"store", "routes", "enforcer_signer", "auth", "rate_limit", "ca_bundle",
        "execution_stale_after_s", "anchoring"}
_ANCHORING = {"witness", "every_s", "token_env"}
MIN_ANCHOR_INTERVAL_S = 60
_ROUTE = {"audience", "base_url", "tenant", "allowed_methods", "allowed_paths", "timeout",
          "network_policy", "operations"}
_OPERATION = {"action", "method", "path", "fields", "context_fields", "max_string"}
_AUTH = {"kind", "tenant"}
_RATE = {"per_minute", "burst"}


class GatewayConfigError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayConfig:
    store: Path
    routes: tuple[Route, ...]
    enforcer_signer: dict[str, Any] | None = None
    auth: str = "api_keys"
    open_tenant: str = DEFAULT_TENANT
    per_minute: int = 120
    burst: int | None = None
    ca_bundle: str | None = None
    execution_stale_after_s: int = DEFAULT_EXECUTION_STALE_AFTER_S
    anchoring: AnchorSchedule | None = None

    @property
    def ledger_path(self) -> Path:
        return self.store / "mandate.sqlite"

    def build_enforcer_signer(self) -> Signer | None:
        return signer_from_config(self.enforcer_signer) if self.enforcer_signer else None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise GatewayConfigError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _obj(value: Any, where: str, allowed: set[str], required: tuple[str, ...] = ()) -> dict:
    if not isinstance(value, dict):
        raise GatewayConfigError(f"{where} must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise GatewayConfigError(f"{where} has unknown keys {sorted(unknown)}")
    missing = [k for k in required if k not in value]
    if missing:
        raise GatewayConfigError(f"{where} is missing {missing}")
    return value


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GatewayConfigError(f"{where} must be a non-empty string")
    return value


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise GatewayConfigError(f"{where} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise GatewayConfigError(f"{where} has duplicates")
    return tuple(value)


def _int(value: Any, where: str, minimum: int) -> int:
    # bool is an int in Python; `"burst": true` is a mistake, not a 1.
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GatewayConfigError(f"{where} must be an integer >= {minimum}")
    return value


def _seconds(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise GatewayConfigError(f"{where} must be a number of seconds")
    if not 0 < value <= MAX_TIMEOUT_S:
        raise GatewayConfigError(f"{where} must be in (0, {MAX_TIMEOUT_S:g}]")
    return float(value)


def _base_url(value: Any, where: str) -> str:
    url = _str(value, where)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise GatewayConfigError(f"{where} must be http or https")
    if not parsed.hostname:
        raise GatewayConfigError(f"{where} needs a host")
    if parsed.username or parsed.password:
        raise GatewayConfigError(f"{where} must not carry credentials")
    if parsed.query or parsed.fragment or url.endswith("?") or url.endswith("#"):
        raise GatewayConfigError(f"{where} must not have a query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise GatewayConfigError(f"{where} has an invalid port") from exc
    return url


def _operation(raw: Any, where: str) -> Operation:
    raw = _obj(raw, where, _OPERATION, required=("action", "method", "path"))
    kwargs: dict[str, Any] = {
        "action": _str(raw["action"], f"{where}.action"),
        "method": _str(raw["method"], f"{where}.method"),
        "path": _str(raw["path"], f"{where}.path"),
    }
    if "fields" in raw:
        kwargs["fields"] = _str_list(raw["fields"], f"{where}.fields")
        unknown = set(kwargs["fields"]) - INTENT_FIELDS
        if unknown:
            raise GatewayConfigError(
                f"{where}.fields has unknown intent fields {sorted(unknown)}; "
                f"known: {sorted(INTENT_FIELDS)}"
            )
    if "context_fields" in raw:
        kwargs["context_fields"] = _str_list(raw["context_fields"], f"{where}.context_fields")
    if "max_string" in raw:
        kwargs["max_string"] = _int(raw["max_string"], f"{where}.max_string", 0)
    try:
        return Operation(**kwargs)
    except RouteConfigError as exc:
        raise GatewayConfigError(f"{where}: {exc}") from exc


def _route(raw: Any, where: str) -> Route:
    raw = _obj(raw, where, _ROUTE, required=("audience", "base_url"))
    kwargs: dict[str, Any] = {
        "audience": _str(raw["audience"], f"{where}.audience"),
        "base_url": _base_url(raw["base_url"], f"{where}.base_url"),
    }
    if "tenant" in raw:
        kwargs["tenant"] = _str(raw["tenant"], f"{where}.tenant")
    if "allowed_methods" in raw:
        methods = _str_list(raw["allowed_methods"], f"{where}.allowed_methods")
        unknown = set(methods) - ALLOWED_METHODS
        if unknown:
            raise GatewayConfigError(f"{where}.allowed_methods has unsupported {sorted(unknown)}")
        kwargs["allowed_methods"] = methods
    if "allowed_paths" in raw:
        paths = _str_list(raw["allowed_paths"], f"{where}.allowed_paths")
        bad = [p for p in paths if not p.startswith("/") or "?" in p or "#" in p]
        if bad:
            raise GatewayConfigError(f"{where}.allowed_paths must be absolute paths: {bad}")
        kwargs["allowed_paths"] = paths
    if "timeout" in raw:
        kwargs["timeout"] = _seconds(raw["timeout"], f"{where}.timeout")
    if "network_policy" in raw:
        policy = raw["network_policy"]
        if not isinstance(policy, str) or policy not in {"public", "allow_private"}:
            raise GatewayConfigError(f"{where}.network_policy must be public or allow_private")
        kwargs["network_policy"] = policy
    if "operations" in raw:
        if not isinstance(raw["operations"], list):
            raise GatewayConfigError(f"{where}.operations must be a list")
        kwargs["operations"] = tuple(
            _operation(op, f"{where}.operations[{i}]") for i, op in enumerate(raw["operations"])
        )
    try:
        return Route(**kwargs)
    except RouteConfigError as exc:
        raise GatewayConfigError(f"{where}: {exc}") from exc


def _relative(base: Path, value: str) -> str:
    path = Path(value)
    return str(path if path.is_absolute() else base / path)


def parse_gateway_config(raw: Any, base_dir: str | Path = ".") -> GatewayConfig:
    base = Path(base_dir)
    raw = _obj(raw, "configuration", _TOP, required=("store", "routes"))

    if not isinstance(raw["routes"], list) or not raw["routes"]:
        raise GatewayConfigError(
            "routes must be a non-empty list; without one this gateway would refuse every intent"
        )
    routes = tuple(_route(r, f"routes[{i}]") for i, r in enumerate(raw["routes"]))
    try:
        RouteRegistry(list(routes))
    except RouteConfigError as exc:
        raise GatewayConfigError(str(exc)) from exc

    signer = raw.get("enforcer_signer")
    if signer is not None:
        # The signer's own keys depend on its kind and are checked by
        # signer_from_config when the gateway is built.
        if not isinstance(signer, dict):
            raise GatewayConfigError("enforcer_signer must be an object naming a signer kind")
        signer = dict(signer)
        _str(signer.get("kind"), "enforcer_signer.kind")
        try:
            check_signer_block(signer)
        except SigningError as exc:
            raise GatewayConfigError(f"enforcer_signer: {exc}") from exc
        if signer["kind"] == "file" and isinstance(signer.get("path"), str):
            signer["path"] = _relative(base, signer["path"])

    auth, open_tenant = "api_keys", DEFAULT_TENANT
    if "auth" in raw:
        block = _obj(raw["auth"], "auth", _AUTH, required=("kind",))
        auth = block["kind"]
        if auth not in {"api_keys", "open"}:
            raise GatewayConfigError("auth.kind must be api_keys or open")
        if "tenant" in block:
            if auth != "open":
                raise GatewayConfigError("auth.tenant only applies to open access")
            open_tenant = _str(block["tenant"], "auth.tenant")

    per_minute, burst = 120, None
    if "rate_limit" in raw:
        block = _obj(raw["rate_limit"], "rate_limit", _RATE)
        if "per_minute" in block:
            per_minute = _int(block["per_minute"], "rate_limit.per_minute", 1)
        if "burst" in block:
            burst = _int(block["burst"], "rate_limit.burst", 1)

    ca_bundle = None
    if "ca_bundle" in raw:
        ca_bundle = _relative(base, _str(raw["ca_bundle"], "ca_bundle"))

    stale = DEFAULT_EXECUTION_STALE_AFTER_S
    if "execution_stale_after_s" in raw:
        stale = _int(raw["execution_stale_after_s"], "execution_stale_after_s", 1)

    anchoring = None
    if "anchoring" in raw:
        block = _obj(raw["anchoring"], "anchoring", _ANCHORING, required=("witness", "every_s"))
        try:
            url = check_witness_url(_str(block["witness"], "anchoring.witness"))
        except WitnessError as exc:
            raise GatewayConfigError(f"anchoring.witness: {exc}") from exc
        every = _int(block["every_s"], "anchoring.every_s", MIN_ANCHOR_INTERVAL_S)
        token_env = _str(block["token_env"], "anchoring.token_env") if "token_env" in block else None
        anchoring = AnchorSchedule(url=url, every_s=float(every), token_env=token_env)

    return GatewayConfig(
        store=Path(_relative(base, _str(raw["store"], "store"))),
        routes=routes,
        enforcer_signer=signer,
        auth=auth,
        open_tenant=open_tenant,
        per_minute=per_minute,
        burst=burst,
        ca_bundle=ca_bundle,
        execution_stale_after_s=stale,
        anchoring=anchoring,
    )


def load_gateway_config(path: str | Path) -> GatewayConfig:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as exc:
        raise GatewayConfigError(f"{path} is not valid JSON: {exc}") from exc
    return parse_gateway_config(raw, base_dir=path.resolve().parent)


def build_engine(config: GatewayConfig) -> Engine:
    config.store.mkdir(parents=True, exist_ok=True)
    signer = config.build_enforcer_signer()
    keys = (
        SignerKeyProvider(signer)
        if signer is not None
        else PersistedDevKeyProvider(config.store / "enforcer-keys")
    )
    return Engine(
        ledger=Ledger(config.ledger_path),
        key_provider=keys,
        routes=RouteRegistry(list(config.routes)),
        executor=UpstreamExecutor(verify=config.ca_bundle or True),
        execution_stale_after_s=config.execution_stale_after_s,
    )


def build_app(config: GatewayConfig):
    from .gateway import create_app

    engine = build_engine(config)
    auth = OpenAccess(config.open_tenant) if config.auth == "open" else LedgerApiKeyAuth(engine.ledger)
    limiter = LedgerRateLimiter(engine.ledger, per_minute=config.per_minute, burst=config.burst)
    if config.anchoring is not None:
        # A token that is missing now would fail every run later, quietly
        # from the caller's point of view. Refuse to start instead.
        try:
            token_from_env(config.anchoring.token_env)
        except WitnessError as exc:
            raise GatewayConfigError(f"anchoring: {exc}") from exc
    return create_app(engine, auth=auth, rate_limiter=limiter, anchoring=config.anchoring)


def app_from_env():
    """uvicorn factory for multi-worker serving: every worker reads the same
    file named by MANDATE_GATEWAY_CONFIG and shares the same ledger."""
    path = os.environ.get(ENV_VAR)
    if not path:
        raise GatewayConfigError(f"{ENV_VAR} is not set")
    return build_app(load_gateway_config(path))
