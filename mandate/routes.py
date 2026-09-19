from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Route:
    audience: str
    base_url: str
    allowed_methods: tuple[str, ...] = ("POST",)
    allowed_paths: tuple[str, ...] = ("/",)
    timeout: float = 5.0
    follow_redirects: bool = False

class RouteRegistry:
    def __init__(self, routes=None):
        self._routes = {r.audience: r for r in (routes or [])}
    def get(self, audience):
        return self._routes.get(audience)
    def known(self, audience):
        return audience in self._routes
