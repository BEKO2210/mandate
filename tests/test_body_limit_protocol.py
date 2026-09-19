from __future__ import annotations

import asyncio

from mandate.limits import BodyLimitMiddleware


def test_stream_overflow_sends_only_one_413_response():
    sent = []
    receive_messages = [
        {"type": "http.request", "body": b"12345", "more_body": False},
    ]

    async def receive():
        if receive_messages:
            return receive_messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        # Simulate a framework that reacts to the disconnect by trying to emit
        # its own error response after the middleware has detected overflow.
        await receive()
        await send({"type": "http.response.start", "status": 400, "headers": []})
        await send({"type": "http.response.body", "body": b"downstream"})

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/intents",
        "headers": [],
    }

    asyncio.run(BodyLimitMiddleware(downstream, max_body=4)(scope, receive, send))

    starts = [m for m in sent if m.get("type") == "http.response.start"]
    bodies = [m for m in sent if m.get("type") == "http.response.body"]

    assert len(starts) == 1
    assert starts[0]["status"] == 413
    assert len(bodies) == 1
    assert bodies[0]["body"] == b'{"error":"payload too large"}'
