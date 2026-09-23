"""TLS upstreams behind one hostname, and a resolver that changes its mind.

Shared by the network-boundary gates. Everything binds to loopback aliases
(127.0.0.1, 127.0.0.2) on the same port, so a single URL can be made to
mean two different peers depending on when its name is resolved — which is
exactly the attack the executor has to be immune to.
"""

from __future__ import annotations

import datetime
import http.server
import pathlib
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = "upstream.test"


def make_pki(directory: pathlib.Path, names: tuple[str, ...] = (HOST,)) -> pathlib.Path:
    """A throwaway CA and one leaf per name. Returns the CA bundle path."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mandate test CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        # Python 3.13 turns on VERIFY_X509_STRICT, which rejects a chain whose
        # certificates lack key identifiers. Real certificates carry them;
        # the first version of these fixtures did not, and passed on 3.11.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name in names:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (directory / f"{name}.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (directory / f"{name}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    return directory / "ca.pem"


class _Recorder(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - the stdlib's name
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.hits.append(self.headers.get("Host"))
        self.server.paths.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # silence
        pass


def serve_tls(ip: str, port: int, directory: pathlib.Path, name: str = HOST):
    """An HTTPS server on ip:port presenting the leaf issued for `name`."""
    server = http.server.HTTPServer((ip, port), _Recorder)
    server.hits, server.paths = [], []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / f"{name}.pem", directory / f"{name}.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class FlippingResolver:
    """The first lookup of HOST returns `first`; every later one returns `later`."""

    def __init__(self, first: str, later: str):
        self.first, self.later, self.calls = first, later, 0
        self._real = socket.getaddrinfo

    def __call__(self, host, port, *args, **kwargs):
        if host != HOST:
            return self._real(host, port, *args, **kwargs)
        self.calls += 1
        ip = self.first if self.calls == 1 else self.later
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))]


def free_port_on(*ips: str) -> int:
    """A port number that is free on every one of `ips` at once."""
    for _ in range(50):
        probe = socket.socket()
        probe.bind((ips[0], 0))
        port = probe.getsockname()[1]
        probe.close()
        try:
            for ip in ips[1:]:
                other = socket.socket()
                other.bind((ip, port))
                other.close()
        except OSError:
            continue
        return port
    raise RuntimeError("no common free port")
