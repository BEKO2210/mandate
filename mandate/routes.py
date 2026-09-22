"""Server-side route registry. Agents never supply destinations."""

from __future__ import annotations

from dataclasses import dataclass, field

# Intent fields an operation may put into an upstream request body. The agent
# chooses their values but never their names, and nothing outside this set can
# reach the upstream.
INTENT_FIELDS = frozenset(
    {
        "action",
        "amount",
        "amount_minor",
        "currency",
        "counterparty",
        "summary",
        "intent_id",
        "execution_id",
    }
)

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


class RouteConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Operation:
    """What one signed action is allowed to send, decided server-side.

    ``fields`` and ``context_fields`` are an allowlist. A declared context
    field is required: an operation either gets the value it was configured
    for or the execution fails closed.
    """

    action: str
    method: str
    path: str
    fields: tuple[str, ...] = ("action", "amount", "currency", "execution_id")
    context_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.action:
            raise RouteConfigError("operation needs an action")
        if self.method not in ALLOWED_METHODS:
            raise RouteConfigError(f"unsupported method {self.method}")
        if not self.path.startswith("/"):
            raise RouteConfigError("operation path must start with /")
        unknown = set(self.fields) - INTENT_FIELDS
        if unknown:
            raise RouteConfigError(f"unknown intent fields {sorted(unknown)}")
        if len(set(self.fields)) != len(self.fields):
            raise RouteConfigError("duplicate intent field")
        if len(set(self.context_fields)) != len(self.context_fields):
            raise RouteConfigError("duplicate context field")
        overlap = set(self.fields) & set(self.context_fields)
        if overlap:
            raise RouteConfigError(f"context field shadows intent field {sorted(overlap)}")


@dataclass(frozen=True)
class Route:
    audience: str
    base_url: str
    allowed_methods: tuple[str, ...] = ("POST",)
    allowed_paths: tuple[str, ...] = ("/",)
    timeout: float = 5.0
    follow_redirects: bool = False
    network_policy: str = "public"
    operations: tuple[Operation, ...] = ()
    # Routes are tenant-scoped. Sharing one is an explicit act, not a default.
    tenant: str = "default"

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for op in self.operations:
            if op.action in seen:
                raise RouteConfigError(f"duplicate operation for action {op.action}")
            seen.add(op.action)
            # The allowlists stay authoritative: an operation cannot widen them.
            if op.method not in self.allowed_methods:
                raise RouteConfigError(f"operation method {op.method} not in allowed_methods")
            if op.path not in self.allowed_paths:
                raise RouteConfigError(f"operation path {op.path} not in allowed_paths")

    def operation_for(self, action: str) -> Operation | None:
        for op in self.operations:
            if op.action == action:
                return op
        return None


class RouteRegistry:
    """Audiences are resolved within a tenant. Two tenants may reuse a name
    without ever reaching each other's upstream."""

    def __init__(self, routes: list[Route] | None = None) -> None:
        self._routes: dict[tuple[str, str], Route] = {}
        for r in routes or []:
            key = (r.tenant, r.audience)
            if key in self._routes:
                raise RouteConfigError(f"duplicate route {r.audience} for tenant {r.tenant}")
            self._routes[key] = r

    def get(self, audience: str, tenant: str = "default") -> Route | None:
        return self._routes.get((tenant, audience))

    def known(self, audience: str, tenant: str = "default") -> bool:
        return (tenant, audience) in self._routes
