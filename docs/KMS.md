# Keys that never enter the process

Until v0.6.0 a Mandate signer *was* a private key: an `Ed25519PrivateKey` held
in memory by the process that signs with it, loaded from a file next to the
ledger. That is defensible for a gateway on a server you control. It stopped
being defensible when the MCP guard shipped, because the guard held the agent
key in the same process a model is talking to.

A signer is now anything that can answer two questions:

```python
did()            # which key is this, as a did:key
sign(payload)    # an Ed25519 signature over exactly these bytes
```

`KeyPair` answers both from memory. A **key manager** answers them without
handing the key back.

## What this actually buys

| | key in a file | key in a key manager |
|---|---|---|
| Read the key from the host | yes | no |
| Sign while the host is compromised | yes | yes |
| Sign **after** access is revoked | yes, forever | no |
| Evidence that a signature happened | none | the provider's audit log, where it keeps one |
| Rotate | replace the file, re-issue every grant | new key version |

The second row is the honest one. A key manager does not stop an attacker who
owns the process from signing *while they own it* — the process can still ask
for signatures, and Mandate's grant limits, not the key, are what bound the
damage. What it removes is the durable secret: nothing exfiltrable, and nothing
that keeps working after you cut access.

The audit row is worth less than it looks. AWS KMS, Cloud KMS and Vault record
signing operations somewhere the host cannot edit; a `command` signer records
whatever the command it fronts records, which may be nothing at all. Treat a
signing log as a property of the provider you chose, not of this abstraction.

## Configure

An MCP guard configuration gains two optional blocks. Both default to the
development behaviour — a key file under the store.

```json
{
  "audience": "mandate://demo",
  "upstream": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
  "agent_signer": {
    "kind": "aws-kms",
    "key_id": "arn:aws:kms:eu-central-1:1234:key/abcd",
    "region": "eu-central-1"
  },
  "tools": {"create_issue": {"action": "repo.issue.create"}}
}
```

Secrets are never in the file. A Vault token is read from the environment, an
AWS or GCP client uses its ambient credentials. A configuration like the one
above can be committed.

### The kinds

| `kind` | Where the key lives | Needs |
|---|---|---|
| `file` | this process (development default) | `path` |
| `aws-kms` | AWS KMS, spec `ECC_NIST_EDWARDS25519` | `key_id`, `region`; `pip install boto3` |
| `gcp-kms` | Cloud KMS, algorithm `EC_SIGN_ED25519` | `key` (a crypto key *version*); `pip install google-cloud-kms` |
| `vault-transit` | Vault transit, key type `ed25519` | `key`, `$VAULT_ADDR`, `$VAULT_TOKEN` |
| `command` | whatever the command fronts | `argv`, `did` |

`command` is the escape hatch: the payload goes to the command's stdin, a
signature comes back on stdout as hex, base64 or 64 raw bytes. That covers
PKCS#11 wrappers, smartcards, an agent on another host — anything with a CLI.
The argv is a fixed list, never a shell string, so nothing in a signed payload
can influence what runs.

Both cloud adapters take an injected client, so `boto3` and `google-cloud-kms`
stay out of Mandate's dependencies and the enforcement path is testable without
a cloud account.

## Ed25519, specifically

Mandate signs with Ed25519 because `did:key` *is* the public key — a receipt
carries its own verification material and needs no directory. That constrains
which key managers can hold a Mandate key: the key must be Ed25519, and the
signature must be PureEdDSA over the message, not over a digest.

* **AWS KMS** — key spec `ECC_NIST_EDWARDS25519`, signing algorithm
  `ED25519_SHA_512` with `MessageType=RAW`. The `_PH_` (pre-hash) variant signs
  something else and would never verify; the adapter always sends `RAW`.
* **Google Cloud KMS** — `EC_SIGN_ED25519`, PureEdDSA, raw data in.
* **Vault transit** — key type `ed25519`. Vault will not export a transit key,
  which is the point.

A key manager that offers only RSA and NIST curves cannot hold a Mandate key
directly. Front it with a `command` signer, or give that deployment a key of
the kind it can hold and record the different DID.

### AWS KMS will not sign anything over 4096 bytes

`Sign` caps its `Message` at 4096 bytes. That is not a comfortable margin here:

| Object | Canonical bytes |
|---|---|
| Intent, no context | ~470 |
| Intent, full 2048-byte context | ~2 500 |
| **EXECUTED receipt, no context** | **~2 900** |
| Receipt with a 2031-byte context | **4 115 — refused** |

A context of 2031 bytes is legal (`MAX_CONTEXT_BYTES` is 2048) and produces a
receipt AWS KMS rejects. For the **enforcer** key that failure lands
mid-execution, after the upstream has already been called.

KMS's documented workaround — hash it yourself and send `MessageType=DIGEST` —
does not apply. With an Ed25519 key that selects `ED25519_PH_SHA_512`, which is
HashEdDSA: a different signature scheme that a plain Ed25519 verifier rejects,
so the object would no longer verify against its own `did:key`.

`AwsKmsSigner` therefore refuses oversized payloads itself, with a message that
says what to do, rather than passing an AWS error code up. In practice:

* **Agent key on AWS KMS** — fine. Intents stay well under the limit unless a
  tool sends very large arguments.
* **Enforcer key on AWS KMS** — only with room to spare. Receipts embed the
  intent, so lower `MAX_CONTEXT_BYTES`, or use Vault transit, Cloud KMS or a
  command signer, none of which have a comparable limit.

## Two invariants

**Every remote signature is verified before it is returned.** An Ed25519 verify
costs microseconds. A key manager pointed at the wrong key, returning a
DER-wrapped signature, or silently truncating one is caught at sign time, where
it is a loud error, rather than at audit time, where it is an unverifiable
receipt nobody can explain.

**The DID binds the key.** If a signer is configured with a `did`, a signature
that does not verify against it fails. Swapping the key under a running
deployment cannot quietly re-point a grant at a different signer; it stops
signing instead.

## Prove it before you depend on it

```bash
$ mandate signer check --config guard.json
agent    : aws-kms ok, held elsewhere
           did:key:z6MkkhyuVBwNZmivX7Vc8ru1daomtU6Lc5wL3gHg9iki9asL
enforcer : local development key in .mandate-mcp
```

The check signs a fixed probe and verifies it, compares the DID the key manager
publishes against the one the grant was issued to, and exits non-zero on a
mismatch. The probe is not a Mandate object — a signature over it authorizes
nothing.

The guard runs the same check at startup and refuses to serve if it fails. The
alternative is discovering a broken key during a tool call, where it reaches a
model as a refused action rather than an operator as a fixable error.

## When the key manager is down

The call is refused with `SIGNER_UNAVAILABLE` and **nothing is dispatched**. An
unsigned intent must never reach an upstream; a call nobody can attribute is
worse than a call that did not happen.

The model is told only that the key is unavailable, that this is not a limit of
the grant, and that retrying will not help. The key manager's own error —
which can name hosts, paths and ARNs — goes to the guard's log on stderr,
because the refusal text is tool output a model reads.

## Bootstrapping without a private key

With `agent_signer` configured, `mandate mcp init` never generates an agent key
and writes nothing:

```
$ mandate mcp init --config guard.json
principal : did:key:z6Mkun…
agent     : did:key:z6Mkkh…
grant     : grant_529ee2972e6c44de
agent key : aws-kms — not written here
```

The principal key — the one that issues the grant — takes a block of its own,
`principal_signer`. Without it `mcp init` writes a development key to the
store; with it the grant is signed in the key manager and no principal key
exists on the host at all. Issuing a grant is an operator action, so the
guard's serving identity needs no access to that key: give `mcp init` the
permission, and the running guard only the agent key.

## The enforcer key

The gateway signs receipts with the enforcer key. It takes the same treatment:

```python
from mandate import Engine
from mandate.keys import SignerKeyProvider
from mandate.signing import signer_from_config

engine = Engine(
    ledger=ledger,
    key_provider=SignerKeyProvider(signer_from_config({
        "kind": "vault-transit", "key": "mandate-enforcer",
    })),
)
```

Receipts verify exactly as before: the DID is the public key either way, so
nothing downstream has to know where the key lived.

For an MCP guard and for the HTTP gateway the same thing is one config block,
`enforcer_signer`; see `docs/GATEWAY.md` for the gateway's file.
