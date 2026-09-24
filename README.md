# Mandate v0.10.0

**A permission layer for AI agents.** An agent may *propose* a call — buy
something, pay an invoice, open an issue. Mandate lets it through only if a
signed grant allows it: the right scope, under budget, a vendor on the list, a
human's approval above a threshold. Every decision, a denial included, becomes
a signed receipt in a chain nobody can edit quietly.

No model reads the prompt and guesses what the agent meant. The rules are
deterministic, and a refusal names the rule that fired.

## How it works

```
                  signed grant
  Principal ───────────────────────┐   scope · budget · vendors · approval above X
                                   ▼
  Agent ── tool call ──▶  ┌──────────────────┐ ── allowed ──▶  Tool / API
  (Claude Code, Cursor,   │     MANDATE      │                 (MCP server, HTTP route)
   any MCP client)        │ verify · decide  │ ── held ──────▶ Human: mandate mcp approve
                          │ reserve · sign   │ ── denied ───▶  nothing is sent
                          └────────┬─────────┘
                                   ▼
                     receipt chain (signed, hash-linked, verifiable without a key)
```

- **Principal** — you, or your organization. Issues the grant and holds the
  key that approves.
- **Agent** — proposes calls. It cannot choose the MCP server or HTTP route a
  call is sent to — those are configured, not supplied — raise a limit, or
  approve itself.
- **Mandate** — sits in between, as an MCP guard (stdio) or an HTTP gateway.
  The tool behind it does not change.
- **Receipts** — every outcome is signed and chained. `mandate chain verify`
  proves nothing in the chain was edited, removed or inserted; entries cut off
  its end show only against a head kept elsewhere (`--anchors`).

## Quickstart

> Mandate is not on PyPI yet. The PyPI package named `mandate` is an
> unrelated project — install from this repository.

**1. Watch it decide** — an agent buying office supplies, no model or network needed:

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
mandate demo shop
```

```
1. [RAN    ] look at the catalogue
2. [RAN    ] copy paper, 40 EUR
3. [DENIED ] toner from a vendor the grant does not name
4. [REFUSED] an order that names no vendor
5. [HELD   ] a laptop, 250 EUR — over the approval threshold
6. [DENIED ] a 800 EUR order — over the per-order limit
7. [RAN    ] the human approves rcpt_…
8. [DENIED ] sticky notes, 20 EUR — the day's budget is spent

Orders placed: 2 (290 EUR). Receipt chain: intact.
```

**2. Put it in front of your own MCP server** — write a `guard.json`
([example](examples/mcp_shop/guard.json), [reference](docs/MCP.md)), then:

```bash
mandate mcp init  --config guard.json    # creates keys and the grant; prints the Claude Code / Cursor lines
mandate mcp serve --config guard.json    # what the client starts
mandate mcp pending --config guard.json  # calls waiting for you
mandate mcp approve --config guard.json --receipt rcpt_…
```

**3. Or run the HTTP gateway** — for agents that call APIs directly:

```bash
mandate gateway check --config gateway.json
mandate gateway serve --config gateway.json --workers 4
```

As a container: `docker build -t mandate .` — see [docs/DOCKER.md](docs/DOCKER.md).

## What you get

- **Hard limits** — per call, per day, per vendor, in integer minor units (no
  floating-point money).
- **Human approval where it matters** — above a threshold the call is held
  until the principal's key signs; then it runs exactly once.
- **Nothing the grant did not name** — an MCP tool that is not mapped is not
  exposed; an HTTP route is registered server-side, never supplied by the agent.
- **Evidence that survives the operator** — a hash-chained receipt log,
  anchors to an external witness, keys in AWS KMS, Cloud KMS or Vault.
- **Fast enough to forget** — a few milliseconds per decision
  ([docs/PERFORMANCE.md](docs/PERFORMANCE.md)).

## Documentation

| | |
|---|---|
| [docs/MCP.md](docs/MCP.md) | The MCP guard: configuration, clients, human approval |
| [docs/GATEWAY.md](docs/GATEWAY.md) | The HTTP gateway: routes, keys, tenants, rate limits |
| [docs/CHAIN.md](docs/CHAIN.md) | The receipt chain, anchors, key rotation |
| [docs/KMS.md](docs/KMS.md) | Keeping signing keys out of the process |
| [docs/DOCKER.md](docs/DOCKER.md) | Running it as a container |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | What a decision costs, and the ceiling |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What it defends against, and what it does not |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Grants, intents and receipts on the wire |
| [docs/HISTORY.md](docs/HISTORY.md) | What each release added |
| [CHANGELOG.md](CHANGELOG.md) | Every change |

## What this does not do

- Guess intent. Every decision is deterministic policy over signed fields —
  scopes, amounts, budgets, counterparties, audience. What an agent *meant* is
  bounded by how narrowly the grant is written, and by human approval above a
  threshold, not by a model's reading of it.
- Move money. Mandate authorizes a call to a payment or ordering API; it is not
  one.
- Speak MCP over HTTP or SSE. The guard uses stdio on both sides.
- A2A, EUDI, wallets, a UI, subdelegation, organization credentials, a
  marketplace, or perfect exactly-once HTTP.

An admin API for routes and keys is not implemented; configuration is a file
and keys are managed with `mandate keys`.

## Known limitations

The receipt binds the request body the gateway *committed to sending*. It does not prove the upstream received those bytes; only the response hash speaks to that.

On timeout or an unknown executor error the state is `EXECUTION_UNKNOWN` and the reservation is kept. Settling it is a human decision, recorded with `mandate gateway resolve` — signed, chained, with who decided and why.

A key manager does not bound a live compromise: code inside the signing process can ask it for signatures for as long as it is there. Without `principal_signer`, the key that issues grants is a local development file.

The receipt chain makes edited history detectable, not impossible. Truncation from the end of a chain is invisible unless a head was kept elsewhere, and a compromised enforcer key can re-sign receipts and chain together.

## Money

Wire format stays decimal (`"amount": 12.30`). Everything past validation is an
integer in minor units, so `0.10 + 0.20` is exactly `0.30` against a `0.30` cap.
An intent may also declare `"amount_minor": 1230`; if it does, it must agree.

## Development

```bash
pip install -e ".[mcp]" pytest ruff
python -m pytest tests/ -q      # every gate is an attack scenario, named G001 upwards
ruff check .
```
