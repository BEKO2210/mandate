from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

from .auth import issue_api_key, normalize_scopes
from .crypto import sign_object, utcnow, verify_object
from .examples_runner import run_belkis_demo
from .ledger import Ledger

DEFAULT_DB = Path(".mandate") / "mandate.sqlite"


def _ledger(path: str | Path) -> Ledger:
    return Ledger(Path(path))


def _add_resolution_commands(group) -> None:
    unknown = group.add_parser(
        "unknown", help="List receipts whose outcome nobody knows (EXECUTION_UNKNOWN)"
    )
    unknown.add_argument("--config", required=True)
    unknown.add_argument("--tenant", default=None)
    resolve = group.add_parser(
        "resolve",
        help="Record what the upstream says happened to an EXECUTION_UNKNOWN receipt",
    )
    resolve.add_argument("--config", required=True)
    resolve.add_argument("--receipt", required=True)
    resolve.add_argument("--tenant", default="default")
    resolve.add_argument(
        "--outcome", required=True, choices=["executed", "failed"],
        help="executed: the upstream acted, the budget is spent. failed: it did not, "
             "the reservation is released.",
    )
    resolve.add_argument("--by", required=True, help="Who checked the upstream")
    resolve.add_argument("--reason", required=True, help="What they found, and where")
    resolve.add_argument(
        "--budget-day", default=None,
        help="Only for a receipt from before budget bindings that records no "
             "reservation day: the day (YYYY-MM-DD) it reserved",
    )


def _resolution(engine, args) -> int:
    from .engine import MandateError

    if args.resolve_cmd == "unknown":
        rows = engine.unknown_receipts(args.tenant)
        for rec in rows:
            execution = rec.get("execution") or {}
            request = execution.get("request") or {}
            print(f"{rec['id']}  {rec['tenant']:<12} {rec.get('intent', {}).get('action', '?')}")
            print(f"{'':22}{request.get('method', '?')} {request.get('destination', '?')}")
            print(f"{'':22}idempotency {execution.get('idempotency_key', '?')}, "
                  f"request {request.get('hash', '?')}, started {execution.get('started_at', '?')}")
            print(f"{'':22}{execution.get('error') or ''}")
        if not rows:
            print("no receipts in EXECUTION_UNKNOWN")
        return 0

    outcome = "EXECUTED" if args.outcome == "executed" else "EXECUTION_FAILED"
    try:
        rec = engine.resolve_unknown(
            args.receipt, outcome, operator=args.by, reason=args.reason, tenant=args.tenant,
            budget_day=args.budget_day,
        )
    except MandateError as exc:
        print(f"not resolved: {exc}", file=sys.stderr)
        return 1
    settled = "committed" if outcome == "EXECUTED" else "released"
    print(f"{rec['id']}: EXECUTION_UNKNOWN -> {outcome}, reservation {settled}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mandate", description="Identity + Permission + Transaction OS for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo", help="Run a demo scenario")
    demo.add_argument(
        "scenario", nargs="?", default="belkis", choices=["belkis", "shop"],
        help="belkis: the engine alone. shop: an agent buying through the MCP guard (needs the mcp extra)",
    )
    demo.add_argument("--dir", default=None, help="shop: where to keep its files (default: a new temp dir)")
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
    mcp_init.add_argument(
        "--example", choices=["shop"], default=None,
        help="Write a ready configuration first: shop is the demo shop, with a procurement grant",
    )
    mcp_serve = mcp_sub.add_parser("serve", help="Serve the guard on stdio")
    mcp_serve.add_argument("--config", required=True)
    mcp_pending = mcp_sub.add_parser("pending", help="List calls waiting for your approval")
    mcp_pending.add_argument("--config", required=True)
    mcp_approve = mcp_sub.add_parser(
        "approve", help="Approve a waiting call as its principal; it runs once"
    )
    mcp_approve.add_argument("--config", required=True)
    mcp_approve.add_argument("--receipt", required=True)
    mcp_approve.add_argument(
        "--yes", action="store_true", help="Do not ask; for scripts run by the principal"
    )
    _add_resolution_commands(mcp_sub)

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
        "--file", default=None,
        help="Where to append. Put it somewhere the database operator cannot reach.",
    )
    ch_anchor.add_argument(
        "--witness", default=None,
        help="POST the heads to this URL, run by someone other than the operator",
    )
    ch_anchor.add_argument(
        "--witness-token-env", default=None,
        help="Environment variable holding a bearer token for the witness",
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
    _add_resolution_commands(gw_sub)
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
        if args.scenario == "shop":
            try:
                import mcp  # noqa: F401
            except ImportError:
                print(f"the shop demo runs the MCP guard, which needs the mcp extra: {INSTALL_MCP}", file=sys.stderr)
                return 1
            from .demo_shop.scenario import EXPECTED, run

            result = run(args.dir)
            return 0 if result["outcomes"] == EXPECTED and result["chain_ok"] else 1
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


#: The one install line for the MCP extra, until the project owns a PyPI name.
INSTALL_MCP = 'pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"'


def _mcp(args) -> int:
    from .mcp.config import load_config, read_state
    from .mcp.mapping import MappingError

    if getattr(args, "example", None) == "shop":
        from .demo_shop.config import guard_config

        path = Path(args.config)
        if path.exists():
            print(f"{path} exists; --example writes a new file and will not overwrite one", file=sys.stderr)
            return 1
        path.parent.mkdir(parents=True, exist_ok=True)
        orders = path.resolve().parent / "orders.jsonl"
        path.write_text(json.dumps(guard_config(str(orders), store=".mandate-shop"), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}: the demo shop behind a procurement grant (orders go to {orders})")

    try:
        config = load_config(args.config)
    except (MappingError, OSError, ValueError) as exc:
        # The same one-line answer `mandate gateway` gives, not a traceback.
        print(f"configuration: INVALID — {exc}", file=sys.stderr)
        return 1

    if args.mcp_cmd == "init":
        from .mcp.server import bootstrap, build_engine

        from .mcp.clients import describe

        existing = read_state(config)
        if existing:
            print(f"already initialized: grant {existing['grant_id']}")
            print(f"store     : {config.store_path.resolve()}")
            print()
            print(describe(args.config, config.server_name))
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
        print()
        print(describe(args.config, config.server_name))
        return 0

    if args.mcp_cmd in {"unknown", "resolve"}:
        from .mcp.server import build_engine

        engine, _ = build_engine(config, _refuse_call, sorted(config.mapping.rules))
        args.resolve_cmd = args.mcp_cmd
        return _resolution(engine, args)

    if args.mcp_cmd == "pending":
        from .mcp.server import build_engine

        engine, _ = build_engine(config, _refuse_call, sorted(config.mapping.rules))
        held = engine.held_receipts(config.tenant) + engine.approved_unclaimed(config.tenant)
        for rec in held:
            print(_describe_held(rec))
        if not held:
            print("nothing is waiting for approval")
        return 0

    if args.mcp_cmd == "approve":
        return _mcp_approve(config, args)

    if args.mcp_cmd == "serve":
        try:
            import anyio

            from .mcp.server import serve
            import mcp  # noqa: F401  - the SDK is imported lazily inside serve()
        except ImportError:
            print(f"the MCP guard needs the mcp extra: {INSTALL_MCP}", file=sys.stderr)
            return 1

        anyio.run(serve, config)
        return 0

    return 2


def _printable(value) -> str:
    """Show a value from a signed intent without letting it drive the terminal.

    This is the screen a principal decides on; a counterparty carrying escape
    sequences could redraw it. The signed value itself is never changed.
    """
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


def _describe_held(rec: dict) -> str:
    intent = rec.get("intent") or {}
    context = intent.get("context") or {}
    money = f"{intent.get('amount')} {intent.get('currency')}" if intent.get("amount") is not None else "-"
    decision = rec.get("decision") or {}
    reasons = "; ".join(decision.get("reasons") or [])
    label = "approved, dispatch never started" if decision.get("approval_id") else "held because"
    return (
        f"{rec['id']}  {context.get('tool', intent.get('action', '?'))}  {money}"
        f"  {_printable(intent.get('counterparty') or '')}\n"
        f"{'':22}arguments {_printable(context.get('arguments_json', '{}'))}\n"
        f"{'':22}{label}: {_printable(reasons)}  (since {_printable(intent.get('created_at', '?'))})"
    )


def _mcp_approve(config, args) -> int:
    """Show the principal what they approve, then run it once."""
    from .mcp.server import build_engine
    from .signing import SigningError

    engine, _ = build_engine(config, _refuse_call, sorted(config.mapping.rules))
    held = {rec["id"]: rec for rec in engine.held_receipts(config.tenant)}
    # Approved before, but the process stopped before the call was dispatched.
    stranded = {rec["id"]: rec for rec in engine.approved_unclaimed(config.tenant)}
    rec = held.get(args.receipt) or stranded.get(args.receipt)
    if rec is None:
        print(f"{args.receipt} is not waiting for approval (see `mandate mcp pending`)", file=sys.stderr)
        return 1
    resume = args.receipt in stranded
    print(_describe_held(rec))
    if not args.yes:
        # Friction, not a security boundary: an agent with a shell can pass
        # --yes too. What keeps approval out of the agent's reach is a
        # principal key it cannot read — `principal_signer` (docs/MCP.md).
        if not sys.stdin.isatty():
            print("refusing to approve without a terminal; the principal passes --yes", file=sys.stderr)
            return 1
        question = "Run this approved call now?" if resume else "Approve and run this call once?"
        if input(f"{question} [y/N] ").strip().lower() not in {"y", "yes"}:
            print("not approved")
            return 1
    try:
        import anyio

        from .mcp.server import approve_held
    except ImportError:
        print(f"approving runs the call, which needs the mcp extra: {INSTALL_MCP}", file=sys.stderr)
        return 1
    try:
        decision = anyio.run(lambda: approve_held(config, args.receipt, resume=resume))
    except (FileNotFoundError, SigningError) as exc:
        print(f"cannot approve: {exc}", file=sys.stderr)
        return 1
    print(f"{decision.outcome}: {decision.text}")
    return 0 if decision.allowed else 1


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


def _read_anchors(path: str | None) -> tuple[list[dict], int]:
    """Heads written down earlier, one JSON object per line; and how many
    lines were not anchors.

    A line that cannot be read is reported and skipped rather than fatal: the
    file lives outside this system's control by design, so a verifier that
    dies on one bad line is a verifier an operator can silence with one bad
    line. But skipped is not the same as fine. If the only anchor for a tenant
    was damaged, what remains checks nothing and a truncated chain would pass;
    so the count comes back, and `chain verify` fails on any unusable line.
    """
    if not path:
        return [], 0
    out: list[dict] = []
    bad = 0
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            print(f"  ! anchor file line {number} is unreadable: {exc}")
            bad += 1
            continue
        if not isinstance(record, dict):
            print(f"  ! anchor file line {number} is not an object")
            bad += 1
            continue
        problem = _anchor_problem(record)
        if problem:
            print(f"  ! anchor file line {number} {problem}; it is not an anchor")
            bad += 1
            continue
        out.append(record)
    return out, bad


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
            from .witness import WitnessError, post_anchors, token_from_env

            if not args.file and not args.witness:
                print("anchor needs --file, --witness or both", file=sys.stderr)
                return 2
            with engine.ledger.tx() as tx:
                tenants = [args.tenant] if args.tenant else (tx.chain_tenants() or [])
            anchors = []
            for tenant in tenants:
                anchor = engine.anchor_chain(tenant)
                if not anchor:
                    print(f"{tenant}: the chain is empty, nothing to anchor")
                    continue
                print(f"{tenant}: seq {anchor['seq']} {anchor['entry_hash']}")
                anchors.append(anchor)
            if not anchors:
                return 0
            if args.witness:
                # Before the file: a witness that refuses is the failure worth
                # stopping for, and the file can be written on the retry.
                try:
                    digest = post_anchors(
                        args.witness, anchors, token=token_from_env(args.witness_token_env)
                    )
                except WitnessError as exc:
                    print(f"witness FAILED: {exc}", file=sys.stderr)
                    return 1
                print(f"Witnessed by {args.witness} (reply sha256 {digest}).")
            if args.file:
                with open(args.file, "a", encoding="utf-8") as fh:
                    for anchor in anchors:
                        fh.write(json.dumps(anchor, sort_keys=True) + "\n")
                print(
                    f"Appended {len(anchors)} anchor(s) to {args.file}. It is worth "
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
            anchors, unusable = _read_anchors(args.anchors)
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
            if unusable:
                print(
                    f"FAILED: {unusable} line(s) of {args.anchors} are not anchors. The "
                    "chain was checked against the rest, but a damaged anchor file "
                    "cannot vouch for the chain's end."
                )
                failed = True
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

    if args.gateway_cmd in {"unknown", "resolve"}:
        from .gateway_config import build_engine

        args.resolve_cmd = args.gateway_cmd
        return _resolution(build_engine(config), args)

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
        if config.anchoring is None:
            print("anchoring : OFF — truncation of the chain's end is detectable only "
                  "against heads kept elsewhere")
        else:
            print(f"anchoring : every {config.anchoring.every_s:g}s to {config.anchoring.url}")
            if config.anchoring.token_env and not os.environ.get(config.anchoring.token_env):
                print(f"{'':10}  UNUSABLE — ${config.anchoring.token_env} is not set")
                failed = True
        if config.ca_bundle and not Path(config.ca_bundle).is_file():
            print(f"{'':10}  UNUSABLE — {config.ca_bundle} does not exist")
            failed = True
        try:
            signer = config.build_enforcer_signer()
            if signer is None:
                dev_key = config.store / "enforcer-keys" / "enforcer.key"
                if not dev_key.exists():
                    print(f"enforcer  : local development key, generated at first start in "
                          f"{dev_key.parent}")
                else:
                    # The key `serve` would load. A damaged one used to pass
                    # this check and then stop the gateway from starting.
                    from .signing import FileSigner

                    dev = FileSigner(dev_key)
                    if not verify_object(sign_object(dev, {"probe": "gateway check"}),
                                         expected_did=dev.did()):
                        raise SigningError(f"{dev_key} signs, but not as {dev.did()}")
                    print("enforcer  : local development key ok, held by this process")
                    print(f"{'':10}  {dev.did()}")
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
