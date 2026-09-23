"""Handing chain heads to someone who does not run the database.

A prefix of a valid chain is a valid chain, so truncation from the end is
invisible to anyone who only has the database. `mandate chain anchor --file`
wrote heads down; whether that file was out of the operator's reach was left
to the operator, and a file on the same disk buys nothing. This posts them to
a witness — an HTTP endpoint run by someone else: an auditor, a customer, a
transparency log — so that keeping a head is something the gateway does, not
something a runbook asks for.

Failures are loud by design. An anchoring job that fails quietly is
indistinguishable from one that works until the day the anchor is needed.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

log = logging.getLogger("mandate.witness")

#: The bucket key under which workers agree whose turn it is. API key ids are
#: hex, and OpenAccess uses "open", so this cannot collide with a caller.
_RUN_KEY = "system:anchor-witness"


class WitnessError(Exception):
    pass


def check_witness_url(url: str) -> str:
    """HTTPS, or plain HTTP to a loopback address (a local relay or a test)."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise WitnessError(f"witness URL is invalid: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WitnessError(f"witness must be an http(s) URL, got {url!r}")
    try:
        parsed.port
    except ValueError as exc:
        raise WitnessError(f"witness URL has an invalid port: {exc}") from exc
    if parsed.username or parsed.password:
        raise WitnessError("witness URL must not carry credentials; use a token variable")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise WitnessError("witness must use https; plain http only to a loopback address")
    return url


def token_from_env(name: str | None, env: dict[str, str] | None = None) -> str | None:
    if not name:
        return None
    value = (env if env is not None else os.environ).get(name, "")
    if not value:
        raise WitnessError(f"witness token variable ${name} is not set")
    return value


def post_anchors(
    url: str, anchors: list[dict[str, Any]], *, token: str | None = None, timeout: float = 10.0,
) -> str:
    """POST `{"anchors": [...]}` to the witness; return the SHA-256 of its reply.

    A redirect is a failure, not something to follow: the anchor was handed
    to whoever answered, and that has to be the witness that was configured.
    """
    check_witness_url(url)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"anchors": anchors}, sort_keys=True).encode("utf-8")
    # Environment proxies only for https, where the proxy sees a CONNECT and
    # an encrypted stream it can neither read the token from nor answer for.
    # Over plain http (loopback only) a proxy would read the token and could
    # reply 2xx on the witness's behalf.
    trust_env = urlparse(url).scheme == "https"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=trust_env) as client:
            resp = client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise WitnessError(f"witness unreachable: {type(exc).__name__}: {exc}") from exc
    if not 200 <= resp.status_code < 300:
        raise WitnessError(f"witness answered {resp.status_code}; the anchors were not accepted")
    return hashlib.sha256(resp.content).hexdigest()


def current_anchors(engine) -> list[dict[str, Any]]:
    with engine.ledger.tx() as tx:
        tenants = tx.chain_tenants() or []
    return [a for a in (engine.anchor_chain(t) for t in tenants) if a]


@dataclass(frozen=True)
class AnchorSchedule:
    """Post every tenant's head to `url` once per `every_s`, across all
    workers serving one ledger."""

    url: str
    every_s: float
    token_env: str | None = None

    def due(self, engine, now: float | None = None) -> bool:
        """Claim this interval's run. Exactly one worker gets True."""
        with engine.ledger.tx() as tx:
            wait = tx.take_rate_token(
                _RUN_KEY, time.time() if now is None else now, 1.0 / self.every_s, 1.0
            )
        return wait == 0.0

    def run_once(self, engine) -> str | None:
        anchors = current_anchors(engine)
        if not anchors:
            return None
        digest = post_anchors(self.url, anchors, token=token_from_env(self.token_env))
        log.info("anchored %d tenant head(s) with %s (reply %s)", len(anchors), self.url, digest)
        return digest

    async def loop(self, engine) -> None:
        while True:
            try:
                if await asyncio.to_thread(self.due, engine):
                    await asyncio.to_thread(self.run_once, engine)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the loop must outlive one bad run
                log.error("anchoring to %s FAILED: %s", self.url, exc)
            await asyncio.sleep(min(self.every_s, 30.0))
