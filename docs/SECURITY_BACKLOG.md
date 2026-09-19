# Security hardening backlog after v0.2

This file tracks narrowly scoped follow-ups discovered during independent review of the remotely reproducible v0.2 Golden tree.

## SH-01 — Budget reservation day must be stable

Current authorization reserves against the UTC day returned by `_day()`, while later commit/release during execution calls `_day()` again.

A request authorized before UTC midnight and executed after midnight can therefore mutate a different budget row than the one originally reserved.

Required property:

> The budget window selected at authorization must remain bound to that authorization through commit, release, or EXECUTION_UNKNOWN handling.

Acceptance test: authorize before UTC midnight, execute after midnight, and prove the original reservation is committed/released exactly once with no stranded or negative accounting.

## SH-02 — Route destination resolution policy

`mandate/executor.py` defines `_host_blocked()`, but `assert_safe_destination()` does not currently enforce it.

The server-side RouteRegistry prevents client-supplied target URLs, but explicit policy is still needed for:

- loopback
- RFC1918/private ranges
- link-local
- cloud metadata destinations
- multicast/reserved/unspecified addresses
- hostname resolution that returns blocked addresses

Test/dev loopback must require an explicit server-side opt-in; it must never be inferred from agent input.

Any residual DNS time-of-check/time-of-use limitation must be documented honestly.

## SH-03 — Request body limit before buffering

The FastAPI middleware currently calls `await request.body()` and only then compares the buffered size to `MAX_BODY`.

Required property:

> Oversized requests must be rejected without first buffering an unbounded body in application memory.

Implement a bounded ASGI receive path or equivalent mechanism and test both Content-Length-known and chunked/streamed oversized requests.

## Scope

Do not add MCP, A2A, EUDI, subdelegation, UI, marketplace, or payment-network work in this hardening round.

All existing G01-G40 tests must remain unchanged and green. New regressions should extend the suite rather than weaken existing gates.
