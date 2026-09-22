"""Network-boundary gates G202-G206.

The destination policy decides which address an authorized request may
reach. These gates attack the gap between that decision and the socket:
a resolver that answers differently the second time it is asked, and an
environment that quietly routes everything through a proxy which resolves
names for itself. Both were reproduced against the executor before it was
fixed; each gate below fails against that code.
"""

from __future__ import annotations

import socket
import socketserver
import threading

import pytest

from mandate.executor import UpstreamExecutor
from mandate.routes import Route
from tests.tls_fixtures import (
    HOST,
    FlippingResolver,
    free_port_on,
    make_pki,
    serve_tls,
)


def _route(port: int, timeout: float = 3.0) -> Route:
    return Route(
        audience="mandate://t", base_url=f"https://{HOST}:{port}",
        allowed_methods=("POST",), allowed_paths=("/do",),
        network_policy="allow_private", timeout=timeout,
    )


@pytest.fixture
def two_peers(tmp_path, monkeypatch):
    """One hostname, two servers, and DNS that switches between them."""
    ca = make_pki(tmp_path, names=(HOST, "someone-else.test"))
    port = free_port_on("127.0.0.2", "127.0.0.1")
    approved = serve_tls("127.0.0.2", port, tmp_path)
    internal = serve_tls("127.0.0.1", port, tmp_path)
    resolver = FlippingResolver(first="127.0.0.2", later="127.0.0.1")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    # Keep this environment's own proxy out of it, so the gates test the
    # executor and not the sandbox; G204 puts a proxy back on purpose.
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    yield {"ca": ca, "port": port, "approved": approved, "internal": internal,
           "resolver": resolver, "dir": tmp_path}
    approved.shutdown()
    internal.shutdown()


def test_g202_https_connects_to_the_address_the_policy_approved(two_peers):
    """The name is resolved once, checked once, and connected to once.

    Before the fix HTTPS connected by name, so httpx resolved it again: the
    approved server got nothing and an internal one answered 200. TLS did not
    prevent it, because whoever controls a domain's DNS can hold a valid
    certificate for it — the fixture's certificate is valid for both peers.
    """
    result = UpstreamExecutor(verify=str(two_peers["ca"])).forward(
        _route(two_peers["port"]), "POST", "/do", b"{}", "idem-g202",
    )
    assert result.state == "EXECUTED", (result.state, result.error)
    assert two_peers["resolver"].calls == 1, "the name must be resolved exactly once"
    assert len(two_peers["approved"].hits) == 1
    assert two_peers["internal"].hits == [], "an address the check never saw was reached"
    # The name still travels where it belongs.
    assert two_peers["approved"].hits[0] == f"{HOST}:{two_peers['port']}"


def test_g203_the_certificate_is_still_checked_against_the_name(tmp_path, monkeypatch):
    """The negative control for G202, and the one that makes it mean anything.

    Connecting to an IP while calling it a name is exactly what a broken
    implementation would also do if it had simply stopped verifying. So the
    approved peer here presents a certificate for a *different* name, signed
    by the trusted CA. It has to be refused, or G202's green says nothing.
    """
    ca = make_pki(tmp_path, names=(HOST, "someone-else.test"))
    port = free_port_on("127.0.0.2")
    impostor = serve_tls("127.0.0.2", port, tmp_path, name="someone-else.test")
    monkeypatch.setattr(socket, "getaddrinfo", FlippingResolver("127.0.0.2", "127.0.0.2"))
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    try:
        result = UpstreamExecutor(verify=str(ca)).forward(
            _route(port), "POST", "/do", b"{}", "idem-g203",
        )
    finally:
        impostor.shutdown()
    assert result.state == "EXECUTION_FAILED", (result.state, result.error)
    assert "certificate" in (result.error or "").lower() or "hostname" in (result.error or "").lower(), result.error
    assert impostor.hits == [], "no request may reach a peer that failed verification"


def test_g204_a_proxy_in_the_environment_is_not_obeyed(two_peers, monkeypatch):
    """With HTTPS_PROXY set, every request used to go to the proxy as
    `CONNECT host:443`, and the proxy resolved the name itself — the policy
    checked one address and the proxy connected to another. In a corporate
    network that variable is the normal case, not an attack."""
    handed: list[str] = []

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            handed.append(self.rfile.readline().decode(errors="replace").strip())
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")

    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{proxy.server_address[1]}"
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    try:
        result = UpstreamExecutor(verify=str(two_peers["ca"])).forward(
            _route(two_peers["port"]), "POST", "/do", b"{}", "idem-g204",
        )
    finally:
        proxy.shutdown()
    assert handed == [], f"the proxy was handed {handed}"
    assert result.state == "EXECUTED", (result.state, result.error)
    assert len(two_peers["approved"].hits) == 1


def test_g205_certificate_verification_cannot_be_switched_off(tmp_path):
    """A destination check that ends at an unauthenticated peer checks nothing.

    And a private CA that is misconfigured fails when the gateway starts, not
    on the first authorized request — by then the receipt is already signed
    and the only honest outcome left is a failure the operator could have
    been told about at boot.
    """
    with pytest.raises(ValueError, match="cannot be disabled"):
        UpstreamExecutor(verify=False)
    UpstreamExecutor()                                  # the system trust store
    UpstreamExecutor(verify=str(make_pki(tmp_path)))    # a private CA that exists
    with pytest.raises(OSError):
        UpstreamExecutor(verify=str(tmp_path / "no-such-ca.pem"))


def test_g206_plain_http_is_pinned_too(tmp_path, monkeypatch):
    """HTTP was pinned before this release; G202 must not have broken it, and
    the flipping resolver must not reach the internal peer on this scheme
    either."""
    import http.server

    class Recorder(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.server.hits.append(self.headers.get("Host"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    port = free_port_on("127.0.0.2", "127.0.0.1")
    servers = {}
    for ip in ("127.0.0.2", "127.0.0.1"):
        srv = http.server.HTTPServer((ip, port), Recorder)
        srv.hits = []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers[ip] = srv
    resolver = FlippingResolver("127.0.0.2", "127.0.0.1")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    route = Route(
        audience="mandate://t", base_url=f"http://{HOST}:{port}",
        allowed_methods=("POST",), allowed_paths=("/do",),
        network_policy="allow_private", timeout=3,
    )
    try:
        result = UpstreamExecutor().forward(route, "POST", "/do", b"{}", "idem-g206")
    finally:
        for srv in servers.values():
            srv.shutdown()
    assert result.state == "EXECUTED", (result.state, result.error)
    assert resolver.calls == 1
    assert len(servers["127.0.0.2"].hits) == 1
    assert servers["127.0.0.1"].hits == []
