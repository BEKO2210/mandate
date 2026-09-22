"""HTTP enforcement gateway. Agents never reach upstream directly."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from .auth import (
    SCOPE_APPROVALS_WRITE,
    SCOPE_INTENTS_WRITE,
    SCOPE_RECEIPTS_READ,
    AuthContext,
    AuthError,
    Authenticator,
    RateLimited,
    RateLimiter,
)
from .engine import Engine, MandateError
from .limits import BodyLimitMiddleware
from .validate import ValidationError, reject_forbidden

VERSION = "0.5.0"


class IntentEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: dict[str, Any]
    execute: bool = False


class ApprovalEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval: dict[str, Any]
    execute: bool = True


def _unauthorized(exc: AuthError) -> HTTPException:
    headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else {}
    if isinstance(exc, RateLimited):
        headers = {"Retry-After": str(max(1, int(exc.retry_after) + 1))}
    return HTTPException(exc.status, str(exc), headers=headers)


def create_app(
    engine: Engine,
    auth: Authenticator | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the gateway.

    `auth` is required. Running unauthenticated has to be chosen out loud by
    passing `OpenAccess()`, so no deployment gets there by omission.
    """
    if auth is None:
        raise ValueError(
            "create_app requires an authenticator; pass auth=OpenAccess() "
            "to run unauthenticated for single-tenant development"
        )
    limiter = rate_limiter if rate_limiter is not None else RateLimiter()

    def _context(request: Request, scope: str) -> AuthContext:
        try:
            ctx = auth.authenticate(request.headers)
            ctx.require(scope)
            limiter.check(ctx.key_id)
        except AuthError as exc:
            raise _unauthorized(exc) from exc
        return ctx

    def intents_context(request: Request) -> AuthContext:
        return _context(request, SCOPE_INTENTS_WRITE)

    def approvals_context(request: Request) -> AuthContext:
        return _context(request, SCOPE_APPROVALS_WRITE)

    def receipts_context(request: Request) -> AuthContext:
        return _context(request, SCOPE_RECEIPTS_READ)

    @asynccontextmanager
    async def lifespan(instance: FastAPI):
        # A process that died mid-execution leaves receipts in EXECUTING.
        # They are closed out as EXECUTION_UNKNOWN before serving traffic.
        instance.state.reconciled = engine.reconcile_stale_executions()
        yield

    app = FastAPI(title="Mandate Enforcement Gateway", version=VERSION, lifespan=lifespan)
    app.state.engine = engine
    app.state.auth = auth
    app.state.rate_limiter = limiter

    @app.get("/health")
    def health():
        # Liveness only. It touches no storage and reveals no identity, so it
        # cannot be used to amplify load or to probe for keys.
        return {"ok": True}

    @app.get("/v1/info")
    def info(ctx: AuthContext = Depends(receipts_context)):
        # The head travels to the caller on purpose. A chain cannot prove what
        # was deleted from its own end; a head held by someone who is not the
        # operator can.
        head = engine.chain_head(ctx.tenant)
        return {
            "ok": True,
            "enforcer_did": engine.enforcer_did,
            "version": VERSION,
            "tenant": ctx.tenant,
            "chain": {
                "head": head["entry_hash"] if head else None,
                "length": head["seq"] if head else 0,
            },
        }

    @app.post("/v1/intents")
    def post_intent(env: IntentEnvelope, ctx: AuthContext = Depends(intents_context)):
        try:
            reject_forbidden(env.intent)
            receipt = engine.submit_intent(env.intent, tenant=ctx.tenant)
        except MandateError as exc:
            msg = str(exc)
            if "replay" in msg:
                raise HTTPException(409, msg)
            if "signature" in msg or "invalid" in msg or "forbidden" in msg:
                raise HTTPException(400, msg)
            if "storage" in msg:
                raise HTTPException(503, msg)
            raise HTTPException(403, msg)
        except ValidationError as exc:
            raise HTTPException(400, str(exc))
        state = receipt.get("outcome")
        if env.execute and state == "AUTHORIZED":
            try:
                receipt = engine.execute(receipt["id"], tenant=ctx.tenant)
            except MandateError as exc:
                if "storage" in str(exc):
                    raise HTTPException(503, str(exc))
                raise HTTPException(409, str(exc))
        return receipt

    @app.post("/v1/approvals")
    def post_approval(env: ApprovalEnvelope, ctx: AuthContext = Depends(approvals_context)):
        try:
            reject_forbidden(env.approval)
            receipt = engine.submit_approval(env.approval, tenant=ctx.tenant)
        except MandateError as exc:
            msg = str(exc)
            if "replay" in msg:
                raise HTTPException(409, msg)
            if "storage" in msg:
                raise HTTPException(503, msg)
            raise HTTPException(403, msg)
        if env.execute and receipt.get("outcome") == "AUTHORIZED":
            try:
                receipt = engine.execute(receipt["id"], tenant=ctx.tenant)
            except MandateError as exc:
                raise HTTPException(409, str(exc))
        return receipt

    @app.get("/v1/receipts/{receipt_id}")
    def get_receipt(receipt_id: str, ctx: AuthContext = Depends(receipts_context)):
        try:
            rec = engine.get_receipt(receipt_id, tenant=ctx.tenant)
        except MandateError as exc:
            raise HTTPException(403, str(exc))
        if not rec:
            raise HTTPException(404, "unknown receipt")
        return rec

    return BodyLimitMiddleware(app)
