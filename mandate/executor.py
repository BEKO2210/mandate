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
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}

_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.169.253"),
}


def _normalize_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return ipaddress.ip_address(mapped)
    return ip


def _host_blocked(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTS or h.endswith(".localhost"):
        return True
    if "metadata" in h:
        return True
    try:
        ip = _normalize_ip(ipaddress.ip_address(h))
        return _ip_blocked(ip, "public")
    except ValueError:
        return False


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, policy: str) -> bool:
    ip = _normalize_ip(ip)
    if ip in _METADATA_IPS:
        return True
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if policy == "allow_private":
        return False
    return bool(ip.is_private or ip.is_loopback)


def resolve_destination(host: str, port: int | None) -> list[str]:
    infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        addrs.append(sockaddr[0])
    if not addrs:
        raise ValueError("destination did not resolve")
    return addrs


def assert_safe_destination(url: str, route: Route) -> list[str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("blocked scheme")
    if parsed.username or parsed.password:
        raise ValueError("userinfo forbidden")
    host = (parsed.hostname or "").lower().rstrip(".")
    expected = urlparse(route.base_url)
    expected_host = (expected.hostname or "").lower().rstrip(".")
    if host != expected_host:
        raise ValueError("host not in registry")
    if parsed.port and expected.port and parsed.port != expected.port:
        raise ValueError("port mismatch")

    policy = getattr(route, "network_policy", None) or "public"
    if policy not in {"public", "allow_private"}:
        raise ValueError("unknown network policy")
    if "metadata" in host:
        raise ValueError("blocked metadata host")
    if host in _BLOCKED_HOSTS and policy != "allow_private":
        raise ValueError("blocked host")

    try:
        literal = _normalize_ip(ipaddress.ip_address(host))
        if _ip_blocked(literal, policy):
            raise ValueError("blocked address")
        return [str(literal)]
    except ValueError as exc:
        if str(exc) in {"blocked address"}:
            raise
        pass

    try:
        resolved = resolve_destination(host, parsed.port or expected.port)
    except OSError as exc:
        raise ValueError(f"resolution failed: {exc}") from exc

    blocked = []
    allowed = []
    for raw in resolved:
        try:
            ip = _normalize_ip(ipaddress.ip_address(raw))
        except ValueError:
            blocked.append(raw)
            continue
        if _ip_blocked(ip, policy):
            blocked.append(str(ip))
        else:
            allowed.append(str(ip))
    if blocked:
        raise ValueError("blocked resolved address")
    if not allowed:
        raise ValueError("no allowed resolved address")
    return allowed


class UpstreamExecutor:
    def forward(self, route: Route, method: str, path: str, json_body: dict, idempotency_key: str) -> ExecutionResult:
        if method not in route.allowed_methods:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "method not allowed")
        if path not in route.allowed_paths:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, "path not allowed")
        url = route.base_url.rstrip("/") + path
        try:
            pinned = assert_safe_destination(url, route)
        except ValueError as exc:
            return ExecutionResult("EXECUTION_FAILED", None, 0, None, str(exc))

        import time

        t0 = time.monotonic()
        parsed = urlparse(url)
        connect_url = url
        headers = {"X-Idempotency-Key": idempotency_key, "X-Mandate-Audience": route.audience}
        if parsed.scheme == "http" and pinned:
            host = parsed.hostname or ""
            port = parsed.port or 80
            ip = pinned[0]
            if ":" in ip and not ip.startswith("["):
                ip_lit = f"[{ip}]"
            else:
                ip_lit = ip
            connect_url = f"http://{ip_lit}:{port}{path}"
            headers["Host"] = host if not parsed.port else f"{host}:{parsed.port}"

        try:
            with httpx.Client(timeout=route.timeout, follow_redirects=False) as client:
                resp = client.request(
                    method,
                    connect_url,
                    json=json_body,
                    headers=headers,
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
