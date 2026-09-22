from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from .auth import issue_api_key, normalize_scopes
from .crypto import utcnow, verify_object
from .examples_runner import run_belkis_demo
from .ledger import Ledger

DEFAULT_DB = Path(".mandate") / "mandate.sqlite"


def _ledger(path: str | Path) -> Ledger:
    return Ledger(Path(path))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mandate", description="Identity + Permission + Transaction OS for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="Run the Belkis procurement scenario")
    v = sub.add_parser("verify", help="Verify a signed Mandate object")
    v.add_argument("file")

    keys = sub.add_parser("keys", help="Manage gateway API keys")
    keys_sub = keys.add_subparsers(dest="keys_cmd", required=True)

    new = keys_sub.add_parser("new", help="Issue a key. The token is printed once and never stored.")
    new.add_argument("--db", default=str(DEFAULT_DB))
    new.add_argument("--tenant", required=True)
    new.add_argument("--name", required=True)
    new.add_argument(
        "--scopes",
        default="*",
        help="Comma-separated: intents:write, approvals:write, receipts:read, or *",
    )
    new.add_argument("--days", type=int, default=None, help="Expire the key after N days")

    ls = keys_sub.add_parser("list", help="List keys (never their secrets)")
    ls.add_argument("--db", default=str(DEFAULT_DB))
    ls.add_argument("--tenant", default=None)

    off = keys_sub.add_parser("disable", help="Disable a key immediately")
    off.add_argument("--db", default=str(DEFAULT_DB))
    off.add_argument("--id", required=True)

    mcp_cmd = sub.add_parser("mcp", help="Run Mandate in front of an MCP server")
    mcp_sub = mcp_cmd.add_subparsers(dest="mcp_cmd", required=True)
    mcp_init = mcp_sub.add_parser("init", help="Create the principal, agent and grant")
    mcp_init.add_argument("--config", required=True)
    mcp_serve = mcp_sub.add_parser("serve", help="Serve the guard on stdio")
    mcp_serve.add_argument("--config", required=True)

    ch = sub.add_parser("chain", help="Inspect the receipt chain")
    ch_sub = ch.add_subparsers(dest="chain_cmd", required=True)
    ch_verify = ch_sub.add_parser(
        "verify", help="Walk the chain and report the first thing that does not add up"
    )
    ch_verify.add_argument("--db", default=str(DEFAULT_DB))
    ch_verify.add_argument("--tenant", default=None, help="Default: every tenant")
    ch_verify.add_argument(
        "--expect-head",
        default=None,
        help="A head you kept earlier. Without one, truncation cannot be detected.",
    )
    ch_verify.add_argument(
        "--expect-signer", default=None, help="The enforcer DID you expect to have signed"
    )
    ch_verify.add_argument(
        "--anchors",
        default=None,
        help="A file of heads kept earlier by `mandate chain anchor`",
    )
    ch_head = ch_sub.add_parser("head", help="Print the current head, to keep elsewhere")
    ch_head.add_argument("--db", default=str(DEFAULT_DB))
    ch_head.add_argument("--tenant", default="default")

    ch_anchor = ch_sub.add_parser(
        "anchor", help="Append the current head to a file kept outside this database"
    )
    ch_anchor.add_argument("--db", default=str(DEFAULT_DB))
    ch_anchor.add_argument("--tenant", default=None, help="Default: every tenant")
    ch_anchor.add_argument(
        "--file", required=True,
        help="Where to append. Put it somewhere the database operator cannot reach.",
    )

    ch_rotate = ch_sub.add_parser(
        "rotate", help="Record a change of signing key, signed by the key leaving"
    )
    ch_rotate.add_argument("--db", default=str(DEFAULT_DB))
    ch_rotate.add_argument("--tenant", default="default")
    ch_rotate.add_argument("--config", required=True, help="An MCP guard configuration file")
    ch_rotate.add_argument("--to", required=True, help="The did:key taking over")

    gw = sub.add_parser("gateway", help="Run the HTTP enforcement gateway from a configuration file")
    gw_sub = gw.add_subparsers(dest="gateway_cmd", required=True)
    gw_check = gw_sub.add_parser(
        "check", help="Validate the configuration and prove the enforcer can sign"
    )
    gw_check.add_argument("--config", required=True)
    gw_serve = gw_sub.add_parser("serve", help="Serve the gateway")
    gw_serve.add_argument("--config", required=True)
    gw_serve.add_argument("--host", default="127.0.0.1")
    gw_serve.add_argument("--port", type=int, default=8080)
    gw_serve.add_argument(
        "--workers", type=int, default=1,
        help="Worker processes. They share one ledger, and so one rate limit per key.",
    )

    signer = sub.add_parser("signer", help="Inspect the keys Mandate signs with")
    signer_sub = signer.add_subparsers(dest="signer_cmd", required=True)
    check = signer_sub.add_parser(
        "check", help="Prove a configured signer can sign, before anything depends on it"
    )
    check.add_argument("--config", required=True, help="An MCP guard configuration file")

    args = p.parse_args(argv)

    if args.cmd == "demo":
        run_belkis_demo()
        return 0

    if args.cmd == "verify":
        obj = json.loads(Path(args.file).read_text(encoding="utf-8"))
        ok = verify_object(obj)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1

    if args.cmd == "keys":
        return _keys(args)

    if args.cmd == "mcp":
        return _mcp(args)

    if args.cmd == "signer":
        return _signer(args)

    if args.cmd == "gateway":
        return _gateway(args)

    if args.cmd == "chain":
        return _chain(args)

    return 2


def _mcp(args) -> int:
    from .mcp.config import load_config, read_state

    config = load_config(args.config)

    if args.mcp_cmd == "init":
        from .mcp.server import bootstrap, build_engine

        existing = read_state(config)
        if existing:
            print(f"already initialized: grant {existing['grant_id']}")
            return 0
        # No upstream connection is needed to mint the grant, so the executor
        # is never called here.
        engine, _ = build_engine(config, _refuse_call, sorted(config.mapping.rules))
        state = bootstrap(config, engine)
        print(f"principal : {state['principal_did']}")
        print(f"agent     : {state['agent_did']}")
        print(f"grant     : {state['grant_id']}")
        print(f"scopes    : {', '.join(config.scopes())}")
        if config.agent_signer:
            print(f"agent key : {config.agent_signer.get('kind')} — not written here")
        else:
            print(f"agent key : {config.store_path / 'keys' / 'agent.key'} (development key)")
        if config.principal_signer:
            print(f"principal key: {config.principal_signer.get('kind')} — not written here")
        else:
            print(f"principal key: {config.store_path / 'keys' / 'principal.key'} (development key)")
        print(f"keys in   : {config.store_path / 'keys'} (keep them private)")
        return 0

    if args.mcp_cmd == "serve":
        import anyio

        from .mcp.server import serve

        anyio.run(serve, config)
        return 0

    return 2


#: What `mandate chain anchor` writes, and therefore the only shape this
#: reader accepts. `type(...) is` rather than isinstance, because a bool is
#: not a sequence number.
ANCHOR_SHAPE = {"tenant": str, "seq": int, "entry_hash": str}


def _anchor_problem(record: dict) -> str | None:
    """Why this is not an anchor, or None.

    The anchor file is the one input a verifier reads from outside itself, and
    it has been wrong twice in two different ways: a `seq` that could not be
    hashed crashed the run, and garbage values were announced as real anchor
    divergence. Both were caught downstream, one field at a time, which is
    guessing at what hostile input looks like. Bounding the shape at the door
    is the answer that does not need a new guess for the next field.
    """
    for key, want in ANCHOR_SHAPE.items():
        if key not in record:
            return f"has no {key}"
        if type(record[key]) is not want:
            return f"has a {type(record[key]).__name__} {key}, expected {want.__name__}"
    if record["seq"] < 1:
        return f"has seq {record['seq']}, and sequence numbers start at 1"
    return None


def _read_anchors(path: str | None) -> list[dict]:
    """Heads written down earlier, one JSON object per line.

    A line that cannot be read is reported and skipped rather than fatal: the
    file lives outside this system's control by design, so a verifier that
    dies on one bad line is a verifier an operator can silence with one bad
    line. A line that is readable but is not an anchor is reported here, with
    its number, rather than downstream where the context is gone.
    """
    if not path:
        return []
    out: list[dict] = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            print(f"  ! anchor file line {number} is unreadable: {exc}")
            continue
        if not isinstance(record, dict):
            print(f"  ! anchor file line {number} is not an object")
            continue
        problem = _anchor_problem(record)
        if problem:
            print(f"  ! anchor file line {number} {problem}; it is not an anchor")
            continue
        out.append(record)
    return out


def _chain(args) -> int:
    """Verification has to be runnable by someone who does not trust the
    operator, so it reads the database directly and needs no running gateway."""
    from .engine import Engine

    engine = Engine(ledger=_ledger(args.db))
    try:
        if args.chain_cmd == "head":
            head = engine.chain_head(args.tenant)
            if not head:
                print(f"{args.tenant}: the chain is empty")
                return 0
            print(f"tenant : {args.tenant}")
            print(f"seq    : {head['seq']}")
            print(f"head   : {head['entry_hash']}")
            print("Keep this where the operator of this database cannot reach it.")
            return 0

        if args.chain_cmd == "anchor":
            with engine.ledger.tx() as tx:
                tenants = [args.tenant] if args.tenant else (tx.chain_tenants() or [])
            written = 0
            with open(args.file, "a", encoding="utf-8") as fh:
                for tenant in tenants:
                    anchor = engine.anchor_chain(tenant)
                    if not anchor:
                        print(f"{tenant}: the chain is empty, nothing to anchor")
                        continue
                    fh.write(json.dumps(anchor, sort_keys=True) + "\n")
                    print(f"{tenant}: seq {anchor['seq']} {anchor['entry_hash']}")
                    written += 1
            if written:
                print(
                    f"Appended {written} anchor(s) to {args.file}. It is worth "
                    f"something only where this database's operator cannot edit it."
                )
            return 0

        if args.chain_cmd == "rotate":
            from .mcp.config import load_config
            from .signing import SigningError

            config = load_config(args.config)
            try:
                engine.enforcer = config.build_enforcer_signer() or engine.enforcer
                entry = engine.rotate_signer(args.to, args.tenant)
            except (SigningError, ValueError) as exc:
                print(f"rotation refused: {exc}")
                return 1
            print(f"tenant : {args.tenant}")
            print(f"seq    : {entry['seq']}")
            print(f"from   : {entry['signer']}")
            print(f"to     : {entry['outcome']}")
            print("Signed by the outgoing key. Point the deployment at the new one now.")
            return 0

        if args.chain_cmd == "verify":
            anchors = _read_anchors(args.anchors)
            with engine.ledger.tx() as tx:
                tenants = [args.tenant] if args.tenant else (tx.chain_tenants() or ["default"])
            failed = False
            for tenant in tenants:
                report = engine.verify_chain(
                    tenant, expect_head=args.expect_head,
                    expect_signer=args.expect_signer, anchors=anchors,
                )
                print(report.summary())
                for problem in report.mismatches:
                    print(f"  ! {problem}")
                for note in report.notes:
                    print(f"  - {note}")
                failed = failed or not report.ok
            if not args.expect_head and not anchors:
                print(
                    "Note: with neither --expect-head nor --anchors, entries deleted "
                    "from the end of the chain cannot be detected. "
                    "`mandate chain anchor` writes the heads this needs."
                )
            return 1 if failed else 0
    finally:
        engine.ledger.close()
    return 2


def _gateway(args) -> int:
    from .gateway_config import GatewayConfigError, load_gateway_config
    from .signing import SigningError

    try:
        config = load_gateway_config(args.config)
    except (GatewayConfigError, OSError) as exc:
        print(f"configuration: INVALID — {exc}", file=sys.stderr)
        return 1

    if args.gateway_cmd == "check":
        failed = False
        print(f"store     : {config.store}")
        for route in config.routes:
            ops = ", ".join(op.action for op in route.operations) or "no operations"
            print(f"route     : {route.tenant}/{route.audience} -> {route.base_url} "
                  f"[{route.network_policy}] ({ops})")
        if config.auth == "open":
            print(f"auth      : OPEN — no authentication, every caller is tenant {config.open_tenant}")
        else:
            print("auth      : api keys (mandate keys new --db "
                  f"{config.ledger_path} --tenant … --name …)")
        print(f"rate limit: {config.per_minute}/min per key, burst "
              f"{config.burst or config.per_minute}, shared by all workers")
        print(f"upstream  : TLS verified against {config.ca_bundle or 'the system trust store'}")
        if config.ca_bundle and not Path(config.ca_bundle).is_file():
            print(f"{'':10}  UNUSABLE — {config.ca_bundle} does not exist")
            failed = True
        try:
            signer = config.build_enforcer_signer()
            if signer is None:
                print(f"enforcer  : local development key in {config.store / 'enforcer-keys'}")
            else:
                report = signer.check()
                held = "held by this process" if report["signer"] == "file" else "held elsewhere"
                print(f"enforcer  : {report['signer']} ok, {held}")
                print(f"{'':10}  {report['did']}")
        except SigningError as exc:
            print(f"enforcer  : UNUSABLE — {exc}")
            failed = True
        return 1 if failed else 0

    if args.gateway_cmd == "serve":
        import os

        import uvicorn

        from .gateway_config import ENV_VAR

        if args.workers < 1:
            print("--workers must be at least 1", file=sys.stderr)
            return 2
        # Every worker builds its app from the same file, so a factory rather
        # than an app object: an object cannot be handed to other processes.
        os.environ[ENV_VAR] = str(Path(args.config).resolve())
        uvicorn.run(
            "mandate.gateway_config:app_from_env", factory=True,
            host=args.host, port=args.port, workers=args.workers,
        )
        return 0
    return 2


def _signer(args) -> int:
    """Answer one question: can this configuration actually sign, and as whom?

    Worth its own command because the alternative is finding out during a tool
    call, where the failure reaches a model as a refused action rather than an
    operator as a fixable error.
    """
    from .mcp.config import load_config, read_state
    from .mcp.server import load_agent_signer
    from .signing import SigningError

    config = load_config(args.config)
    state = read_state(config) or {}
    failed = False

    for label, build in (
        ("agent", lambda: load_agent_signer(config)),
        ("enforcer", config.build_enforcer_signer),
        ("principal", config.build_principal_signer),
    ):
        try:
            signer = build()
        except (SigningError, FileNotFoundError) as exc:
            print(f"{label:<9}: UNUSABLE — {exc}")
            failed = True
            continue
        if signer is None:
            print(f"{label:<9}: local development key in {config.store_path}")
            continue
        try:
            report = signer.check()
        except SigningError as exc:
            print(f"{label:<9}: UNUSABLE — {exc}")
            failed = True
            continue
        held = "held by this process" if report["signer"] == "file" else "held elsewhere"
        print(f"{label:<9}: {report['signer']} ok, {held}")
        print(f"{'':9}  {report['did']}")
        expected = state.get(f"{label}_did") if label in {"agent", "principal"} else None
        if expected and expected != report["did"]:
            role = "issued to" if label == "agent" else "issued by"
            print(f"{'':9}  MISMATCH — the grant was {role} {expected}")
            failed = True

    return 1 if failed else 0


async def _refuse_call(name: str, arguments: dict) -> None:
    raise RuntimeError("this engine was built for setup only and cannot dispatch")


def _keys(args) -> int:
    ledger = _ledger(args.db)
    try:
        if args.keys_cmd == "new":
            scopes = normalize_scopes(args.scopes.split(","))
            expires = utcnow() + timedelta(days=args.days) if args.days else None
            token, key_id = issue_api_key(
                ledger, tenant=args.tenant, name=args.name, scopes=scopes, expires_at=expires
            )
            print(f"key id   : {key_id}")
            print(f"tenant   : {args.tenant}")
            print(f"scopes   : {','.join(sorted(scopes))}")
            print(f"expires  : {expires.isoformat() if expires else 'never'}")
            print(f"token    : {token}")
            print("Store the token now. It is not recoverable.")
            return 0

        if args.keys_cmd == "list":
            with ledger.tx() as tx:
                rows = tx.list_api_keys(args.tenant)
            for r in rows:
                state = "disabled" if r["disabled"] else "active"
                print(
                    f"{r['id']}  {r['tenant']:<16} {state:<8} {r['scopes']:<40} "
                    f"{r['name']} (created {r['created_at']}, expires {r['expires_at'] or 'never'})"
                )
            if not rows:
                print("no keys")
            return 0

        if args.keys_cmd == "disable":
            with ledger.tx() as tx:
                changed = tx.disable_api_key(args.id)
                if changed:
                    tx.audit("apikey.disabled", {"key_id": args.id})
            print("disabled" if changed else "no active key with that id")
            return 0 if changed else 1
    finally:
        ledger.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
