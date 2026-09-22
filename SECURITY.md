# Security policy

Mandate is a pre-1.0 enforcement gateway. It is being hardened in public and
has not been independently audited. Do not put it in front of a system whose
compromise you cannot absorb.

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Please include a reproduction against a clean
clone, the commit you tested, and the impact you believe it has.

Do not open a public issue for an unfixed vulnerability.

Expect an acknowledgement within 7 days and an assessment within 30 days.
Credit is given in the changelog unless you ask otherwise.

## Scope

In scope:

- Bypassing authorization: reaching a registered upstream without a currently
  valid, principal-signed grant
- Bypassing authentication, or reading, writing or affecting the records of a
  tenant other than the one the presented key belongs to
- Budget, nonce, approval or execution-claim defects: double spend, replay,
  double dispatch, a receipt that misstates what happened
- Forging, tampering with or misattributing a signed object
- Reaching an unregistered destination, or a private or metadata address under
  the default `public` network policy

Known and documented, so not a finding on their own — see `docs/THREAT_MODEL.md`
and `docs/SECURITY_BACKLOG.md`:

- HTTPS DNS TOCTOU: the TLS peer IP is not pinned
- The rate limiter is in-process, so it bounds one gateway process
- Receipts are individually signed but not chained; an operator with database
  access can delete or roll back history
- `EXECUTION_UNKNOWN` holds its reservation until a human reconciles it
- The receipt binds the body the gateway committed to sending, not proof of
  upstream receipt
- Routes and operations are configured in code, not from a file or admin API
- The MCP guard holds the agent key, so its process is the enforcement
  boundary; code running inside it can make it sign

## Supported versions

Only the latest tagged version is supported.
