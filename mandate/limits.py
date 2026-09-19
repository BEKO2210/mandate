"""Bounded ASGI request body reader. Reject before unbounded buffering."""

from __future__ import annotations

from .validate import MAX_BODY


class BodyTooLarge(Exception):
    pass


def _header_map(scope: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        out[key.decode("latin1").lower()] = value.decode("latin1")
    return out


class BodyLimitMiddleware:
    def __init__(self, app, max_body: int = MAX_BODY) -> None:
        self.app = app
        self.max_body = max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = _header_map(scope)
        raw_cl = headers.get("content-length")
        if raw_cl is not None:
            try:
                declared = int(raw_cl)
            except ValueError:
                declared = None
            else:
                if declared > self.max_body:
                    await _send_413(send)
                    return

        seen = 0
        overflow = False
        downstream_started = False
        limit_response_sent = False

        async def safe_send(message):
            nonlocal downstream_started
            # Once the middleware has emitted its own 413, any response the
            # downstream framework tries to send after seeing http.disconnect
            # must be suppressed. ASGI permits only one response start.
            if limit_response_sent:
                return
            if message.get("type") == "http.response.start":
                downstream_started = True
            await send(message)

        async def bounded_receive():
            nonlocal seen, overflow, limit_response_sent
            if overflow:
                return {"type": "http.disconnect"}

            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body") or b""
                seen += len(chunk)
                if seen > self.max_body:
                    overflow = True
                    if not downstream_started and not limit_response_sent:
                        limit_response_sent = True
                        await _send_413(send)
                    return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, bounded_receive, safe_send)
        except BodyTooLarge:
            if not downstream_started and not limit_response_sent:
                limit_response_sent = True
                await _send_413(send)
        except Exception:
            if overflow:
                # If the 413 was already emitted, the overflow path is complete.
                # Otherwise the downstream response had already started and we
                # cannot legally replace it with a second response start.
                return
            raise


async def _send_413(send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b'{"error":"payload too large"}',
        }
    )
