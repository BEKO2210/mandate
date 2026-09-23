# Mandate in front of an MCP server

```
model ──stdio──▶ mandate guard ──stdio──▶ upstream MCP server
```

The model talks to the guard and never to the upstream. Each tool call becomes
a signed intent, is evaluated against a grant, and only then dispatched — by
the same engine, ledger and receipts the HTTP gateway uses.

## Why a guard rather than a new protocol

An agent runtime already speaks MCP. Asking it to speak a second envelope
format instead is the reason enforcement layers do not get adopted. The guard
re-exposes the upstream's tools with their own schemas, so nothing on the model
side changes: the same tool names, the same arguments, an extra refusal it has
to respect.

## Configure

```json
{
  "audience": "mandate://demo",
  "store": ".mandate-mcp",
  "upstream": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
  "tools": {
    "create_issue": {"action": "repo.issue.create"},
    "pay_invoice": {
      "action": "finance.invoice.pay",
      "amount_from": "amount",
      "currency_from": "currency"
    }
  },
  "grant": {
    "organization": "Aslani GmbH",
    "purpose": "repo automation",
    "constraints": {"currency": "EUR", "max_amount": 100, "max_daily_amount": 500}
  }
}
```

The file is read strictly. An unknown key, at any level, is an error rather
than something to skip: a misspelt `max_daily_amount` used to be dropped
silently and the grant issued with no daily limit. Duplicate keys are refused
for the same reason — which of the two wins is not a question a security
configuration should leave to a JSON parser.

`tools` is the whole surface. **A tool that is not mapped is not exposed**, so
the model cannot call what the configuration never considered. Set
`allow_unmapped` if you want the opposite, and know what you are choosing.

`amount_from` names the argument that carries money. It must be a number: a
string amount would have to be parsed, and a parse is a guess — the guard
refuses instead.

`counterparty_from` names the argument that says who is paid or addressed —
a vendor, a recipient. Once configured it is required: a call without it, with
an empty value, or with one longer than 256 characters is refused before
anything is signed, so a grant's `counterparties_allow` cannot be skipped by
leaving the name out.

## Run

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
mandate mcp init  --config guard.json   # principal, agent and grant, once
mandate mcp serve --config guard.json   # stdio, for the agent runtime to spawn
```

From the repository: the PyPI project named `mandate` is an unrelated package,
so installing by that name gets someone else's code.

`init` writes development keys under `<store>/keys`. An `agent_signer` block
means the key already exists somewhere, so none is generated or written here.
Where "somewhere" is depends on the kind: `aws-kms`, `gcp-kms`, `vault-transit`
and `command` keep it out of this process entirely, while `file` points at a
key this process reads — convenient, but the key is still in memory. See
[KMS.md](KMS.md).

A deployment that matters issues the grant elsewhere and gives the guard only
access to the agent key.

## What the model sees

From a real run against a three-tool upstream:

```
visible tools: ['create_issue', 'pay_invoice']          # delete_repository is not mapped
create_issue  -> UPSTREAM RAN create_issue on beko/mandate      isError: False
pay_invoice 40 EUR  -> UPSTREAM RAN pay_invoice on x            isError: False
pay_invoice 900 EUR -> Mandate denied this call: amount 900.00 exceeds max_amount 100.00;
                       amount would exceed daily cap 500.00 (already spent 40.00). This is a
                       limit of grant grant_a34…, not of the tool. Receipt rcpt_0eb….
                                                                 isError: True
```

A refusal names the rule, the grant and the receipt. An agent told only
"denied" retries the same call; an agent told which limit refused it can pick a
smaller amount or ask for a new grant.

`HUMAN_REQUIRED` is reported as an error too, with the receipt id and an
explicit instruction not to retry — the call is held, not lost.

## How arguments are carried

Tool arguments never become named fields of the intent. They travel as one
canonical JSON document under `context.arguments_json`, because an MCP tool may
legitimately take an argument called `url` or `host` — key names a signed
intent forbids anywhere. The document is hashed into the receipt before
dispatch, exactly like an HTTP request body, so the receipt states which
arguments were sent.

## What the receipt records

```json
"request": {
  "method": "POST",
  "path": "/create_issue",
  "destination": "mcp://upstream/create_issue",
  "hash": "sha256:d07daefc…",
  "size": 138
}
```

The upstream's response is **not** in the receipt. Only its hash is signed; the
content goes to the model beside the receipt. A receipt is evidence, not a log
of everything that passed through.

`method` is always `POST`: MCP has no request methods, and the field keeps the
route allowlists the same shape as the HTTP side.

## Outcomes

| Upstream behaviour | State | Budget |
|---|---|---|
| Tool returns content | `EXECUTED` | committed |
| Tool reports an error (`isError`) | `EXECUTION_FAILED` | released |
| Timeout or broken transport | `EXECUTION_UNKNOWN` | kept reserved |

`mandate mcp unknown --config guard.json` lists the unknown outcomes with what
was sent; `mandate mcp resolve --config guard.json --receipt … --outcome
executed|failed --by … --reason …` records what the upstream says happened.

A tool error is treated like a non-2xx HTTP response: the call happened and
failed. A broken pipe is not — the tool may have run before the transport
died, so the outcome is unknown and the reservation stays until a human
reconciles it.

## Trust boundary

The guard signs intents on the agent's behalf. The model cannot sign, so the
enforcement boundary is the guard process, not the model: anything that can run
code in that process can make the guard sign — with a local key by reading it,
with a key manager by asking. Run it as the agent runtime's child process, with
the store readable only by that user.

Moving the key out of the process (`agent_signer`) removes the exfiltratable
secret and makes revocation effective. It does not shrink the boundary; the
grant's limits do that.

The guard runs the engine in-process, so there is no API key and no tenant
check on the way in — those exist on the HTTP gateway, where the caller is
remote. Here the caller is the local process that spawned the guard.
