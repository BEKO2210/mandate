"""Trusted upstream connector. Fail closed. No open proxy."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
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
        payload: object | None = None,
    ) -> None:
        self.state = state
        self.status = status
        self.latency_ms = latency_ms
        self.body_hash = body_hash
        self.error = error
        # In-process transport for the upstream's response. Only its hash is
        # signed into the receipt; the payload itself is never persisted.
        self.payload = payload


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
    """Send an authorized request to the address the destination policy approved.

    `verify` is httpx's: True (the system trust store), or a path to a CA
    bundle for an upstream behind a private CA. It is never allowed to be
    False — a destination check that ends at an unauthenticated peer checks
    nothing.
    """

    def __init__(self, verify: bool | str = True) -> None:
        if verify is False:
            raise ValueError("certificate verification cannot be disabled")
        # httpx deprecates a CA *path*; build the context here so the policy —
        # hostname checking on, the platform's strictness kept — is ours.
        self._verify: bool | ssl.SSLContext = (
            ssl.create_default_context(cafile=verify) if isinstance(verify, str) else verify
        )

    def forward(
        self, route: Route, method: str, path: str, body: bytes, idempotency_key: str
    ) -> ExecutionResult:
        """Send exactly `body`. The receipt already committed to its hash."""
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
        headers = {
            "X-Idempotency-Key": idempotency_key,
            "X-Mandate-Audience": route.audience,
            "Content-Type": "application/json",
            # Same form as execution.request.hash in the receipt.
            "X-Mandate-Request-Hash": "sha256:" + hashlib.sha256(body).hexdigest(),
        }
        # Connect to the address the policy approved, for both schemes.
        #
        # HTTPS used to connect by *name*, so httpx resolved it a second time
        # and a resolver that changed its answer between check and connect
        # sent an authorized request somewhere the check never saw. TLS did
        # not save it: whoever controls a domain's DNS can also hold a valid
        # certificate for it. Reproduced before fixing — two resolutions, the
        # approved server got nothing, an internal one got the request and
        # answered 200. Now the socket goes to the pinned IP and the name is
        # used only where it belongs: SNI, certificate verification, Host.
        extensions: dict = {}
        if pinned:
            host = parsed.hostname or ""
            default = 443 if parsed.scheme == "https" else 80
            port = parsed.port or default
            ip = pinned[0]
            ip_lit = f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip
            # The whole path of the checked URL, not just the operation's: a
            # base_url of https://api.example/v2 used to lose its /v2 here,
            # so the request went to a path the receipt never named.
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            connect_url = f"{parsed.scheme}://{ip_lit}:{port}{target}"
            headers["Host"] = host if not parsed.port else f"{host}:{parsed.port}"
            if parsed.scheme == "https":
                extensions["sni_hostname"] = host

        try:
            # trust_env=False: never route through a proxy named in the
            # environment. With HTTPS_PROXY set — ordinary in a corporate
            # network — every request went to the proxy as `CONNECT host:443`
            # and the proxy resolved the name itself, so the destination
            # policy checked one address and the proxy connected to another.
            # Reproduced: the proxy was handed the hostname, never the pinned
            # IP. A gateway that must egress through a proxy cannot enforce a
            # destination policy it does not resolve, so it is not supported.
            with httpx.Client(
                timeout=route.timeout, follow_redirects=False,
                trust_env=False, verify=self._verify,
            ) as client:
                resp = client.request(
                    method,
                    connect_url,
                    content=body,
                    headers=headers,
                    extensions=extensions,
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
