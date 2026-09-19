"""Trusted upstream connector. Fail closed. No open proxy."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from .routes import Route


class ExecutionResult:
    def __init__(
        self,
        state: str,
        status: int | None,
        latency_ms: int,
        body_hash: str | None,
        error: str | None = None,
    ) -> None:
        self.state = state
        self.status = status
        self.latency_ms = latency_ms
        self.body_hash = body_hash
        self.error = error


_BLOCKED_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}


def _host_blocked(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h in _BLOCKED_HOSTS or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def assert_safe_destination(url: str, route: Route) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("blocked scheme")
    if parsed.username or parsed.password:
        raise ValueError("userinfo forbidden")
    host = parsed.hostname or ""
    expected = urlparse(route.base_url)
    if host != (expected.hostname or ""):
        raise ValueError("host not in registry")
    if parsed.port and expected.port and parsed.port != expected.port:
        raise ValueError("port mismatch")
    if host != (expected.hostname or ""):
        raise ValueError("host mismatch")


class UpstreamExecutor:
    def forward(self, route: Route, method: str, path: str, json_body: dict, idempotency_key: str) -> ExecutionResult:
        if method not in route.allowed_methods:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "method not allowed")
        if path not in route.allowed_paths:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "path not allowed")
        url = route.base_url.rstrip("/") + path
        try:
            assert_safe_destination(url, route)
        except ValueError as exc:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, str(exc))

        import time

        t0 = time.monotonic()
        try:
            with httpx.Client(timeout=route.timeout, follow_redirects=False) as client:
                resp = client.request(
                    method,
                    url,
                    json=json_body,
                    headers={"X-Idempotency-Key": idempotency_key, "X-Mandate-Audience": route.audience},
                )
        except httpx.TimeoutException:
            return ExecutionResult("EXECUTION_UNKNOWN", None, int((time.monotonic() - t0) * 1000), None, "timeout")
        except httpx.HTTPError as exc:
            return ExecutionResult("EXECUTION_FAILED", None, int((time.monotonic() - t0) * 1000), None, str(exc))

        latency = int((time.monotonic() - t0) * 1000)
        if 300 <= resp.status_code < 400:
            return ExecutionResult("EXECUTION_FAILED", resp.status_code, latency, None, "redirect refused")
        digest = hashlib.sha256(resp.content[:4096]).hexdigest()
        if 200 <= resp.status_code < 300:
            return ExecutionResult("EXECUTED", resp.status_code, latency, digest)
        return ExecutionResult("EXECUTION_FAILED", resp.status_code, latency, digest)
