"""Server-side route registry. Agents never supply destinations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Route:
    audience: str
    base_url: str
    allowed_methods: tuple[str, ...] = ("POST",)
    allowed_paths: tuple[str, ...] = ("/",)
    timeout: float = 5.0
    follow_redirects: bool = False


class RouteRegistry:
    def __init__(self, routes: list[Route] | None = None) -> None:
        self._routes = {r.audience: r for r in (routes or [])}

    def get(self, audience: str) -> Route | None:
        return self._routes.get(audience)

    def known(self, audience: str) -> bool:
        return audience in self._routes
