"""HTTP enforcement gateway. Agents never reach upstream directly."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .engine import Engine, MandateError
from .limits import BodyLimitMiddleware
from .validate import ValidationError, reject_forbidden


class IntentEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: dict[str, Any]
    execute: bool = False


class ApprovalEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval: dict[str, Any]
    execute: bool = True


def create_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="Mandate Enforcement Gateway", version="0.2.1")
    app.state.engine = engine

    @app.get("/health")
    def health():
        return {"ok": True, "enforcer_did": engine.enforcer_did, "version": "0.2.1"}

    @app.post("/v1/intents")
    def post_intent(env: IntentEnvelope):
        try:
            reject_forbidden(env.intent)
            receipt = engine.submit_intent(env.intent)
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
                receipt = engine.execute(receipt["id"])
            except MandateError as exc:
                if "storage" in str(exc):
                    raise HTTPException(503, str(exc))
                raise HTTPException(409, str(exc))
        return receipt

    @app.post("/v1/approvals")
    def post_approval(env: ApprovalEnvelope):
        try:
            reject_forbidden(env.approval)
            receipt = engine.submit_approval(env.approval)
        except MandateError as exc:
            msg = str(exc)
            if "replay" in msg:
                raise HTTPException(409, msg)
            if "storage" in msg:
                raise HTTPException(503, msg)
            raise HTTPException(403, msg)
        if env.execute and receipt.get("outcome") == "AUTHORIZED":
            try:
                receipt = engine.execute(receipt["id"])
            except MandateError as exc:
                raise HTTPException(409, str(exc))
        return receipt

    @app.get("/v1/receipts/{receipt_id}")
    def get_receipt(receipt_id: str):
        try:
            rec = engine.get_receipt(receipt_id)
        except MandateError as exc:
            raise HTTPException(403, str(exc))
        if not rec:
            raise HTTPException(404, "unknown receipt")
        return rec

    return BodyLimitMiddleware(app)
