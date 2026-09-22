"""v0.6.0 signing gates G120-G157.

Until now "the signer" and "the private key" were the same object. These gates
cover the separation: a signer is something that can name a DID and produce a
signature, whether it holds the key or asks a key manager that will not hand it
back.

The gates that matter most are not the adapters. They are G123-G127: a remote
signer that returns the wrong thing must fail at sign time, loudly, rather than
produce a receipt nobody can verify later.
"""

from __future__ import annotations

import base64
import json

import pytest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mandate.crypto import KeyPair, canonical_json, sign_object, verify_object
from mandate.engine import Engine
from mandate.keys import SignerKeyProvider
from mandate.ledger import Ledger
from mandate.mcp.config import parse_config
from mandate.mcp.guard import McpGuard
from mandate.mcp.server import bootstrap, build_engine, load_agent_signer
from mandate.signing import (
    PROBE,
    AwsKmsSigner,
    CommandSigner,
    FileSigner,
    GcpKmsSigner,
    RemoteSigner,
    Signer,
    SigningError,
    VaultTransitSigner,
    signer_from_config,
)

from .test_mcp_gates import CONFIG, FakeUpstream, _direct_bridge


# --- Doubles ---------------------------------------------------------------


class FakeKms(RemoteSigner):
    """A key manager that happens to run in this process.

    It stands in for AWS/GCP/Vault wherever the gate is about the contract
    rather than about one vendor's API shape.
    """

    name = "fake-kms"

    def __init__(self, kp=None, *, publishes=True, **kw) -> None:
        super().__init__(**kw)
        self.kp = kp or KeyPair.generate()
        self.publishes = publishes
        self.signed: list[bytes] = []

    def _sign_remote(self, payload: bytes) -> bytes:
        self.signed.append(payload)
        return self.kp.sign(payload)

    def _fetch_public_bytes(self) -> bytes:
        if not self.publishes:
            return super()._fetch_public_bytes()
        return self.kp.public_bytes()


class BrokenKms(RemoteSigner):
    name = "broken-kms"

    def __init__(self, result, did) -> None:
        super().__init__(did=did)
        self._result = result

    def _sign_remote(self, payload: bytes):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class FakeAwsClient:
    """The shape boto3's KMS client exposes, and nothing more."""

    def __init__(self, kp=None, key_spec="ECC_NIST_EDWARDS25519") -> None:
        self.kp = kp or KeyPair.generate()
        self.key_spec = key_spec
        self.calls: list[dict] = []

    def sign(self, **kw):
        self.calls.append(kw)
        return {"Signature": self.kp.sign(kw["Message"])}

    def get_public_key(self, **kw):
        der = self.kp.public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der, "KeySpec": self.key_spec}


class _GcpResult:
    def __init__(self, **kw) -> None:
        self.__dict__.update(kw)


class FakeGcpClient:
    def __init__(self, kp=None) -> None:
        self.kp = kp or KeyPair.generate()
        self.requests: list[dict] = []

    def asymmetric_sign(self, request):
        self.requests.append(request)
        return _GcpResult(signature=self.kp.sign(request["data"]))

    def get_public_key(self, request):
        pem = self.kp.public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return _GcpResult(pem=pem.decode("ascii"))


class FakeVault:
    """Vault's transit API over a recorded transport."""

    def __init__(self, kp=None, version=2, key_type="ed25519") -> None:
        self.kp = kp or KeyPair.generate()
        self.version = version
        self.key_type = key_type
        self.seen: list[tuple[str, str, dict]] = []
        self.timeouts: list[float] = []
        self.status = 200
        self.body: bytes | None = None

    def transport(self, method, url, headers, body, timeout=10.0):
        self.seen.append((method, url, headers))
        self.timeouts.append(timeout)
        if self.body is not None or self.status != 200:
            return self.status, self.body or b'{"errors":["permission denied"]}'
        if "/sign/" in url:
            payload = base64.b64decode(json.loads(body)["input"])
            sig = base64.b64encode(self.kp.sign(payload)).decode("ascii")
            return 200, json.dumps({"data": {"signature": f"vault:v{self.version}:{sig}"}}).encode()
        keys = {
            "1": {"public_key": base64.b64encode(KeyPair.generate().public_bytes()).decode()},
            str(self.version): {
                "public_key": base64.b64encode(self.kp.public_bytes()).decode()
            },
        }
        data = {"type": self.key_type, "latest_version": self.version, "keys": keys}
        return 200, json.dumps({"data": data}).encode()


def _vault(fake, **kw):
    kw.setdefault("address", "https://vault.example:8200")
    kw.setdefault("token", "s.tok")
    kw.setdefault("key", "mandate-agent")
    return VaultTransitSigner(transport=fake.transport, **kw)


class _Completed:
    def __init__(self, stdout=b"", returncode=0, stderr=b"") -> None:
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


# --- The abstraction -------------------------------------------------------


def test_g120_a_local_keypair_is_already_a_signer():
    """One code path, not two: nothing special-cases where the key lives."""
    kp = KeyPair.generate()
    assert isinstance(kp, Signer)
    assert isinstance(FakeKms(), Signer)


def test_g121_a_receipt_signed_by_a_key_manager_verifies_like_any_other(tmp_path):
    kms = FakeKms()
    engine = Engine(
        ledger=Ledger(tmp_path / "m.sqlite"), key_provider=SignerKeyProvider(kms)
    )
    assert engine.enforcer_did == kms.did()

    person, pkp = engine.register_principal("Belkis")
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "test")
    from datetime import timedelta

    from mandate.crypto import utcnow

    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="p",
        scopes=["x.do"], not_after=utcnow() + timedelta(days=1),
    )
    receipt = engine.propose(akp, grant["id"], "x.do", summary="s")
    assert verify_object(receipt, expected_did=kms.did())
    assert kms.signed, "the key manager, not a local key, produced the signature"


def test_g122_registering_with_a_signer_generates_no_private_key(tmp_path):
    """The engine records a DID the key manager already holds."""
    kms = FakeKms()
    engine = Engine(ledger=Ledger(tmp_path / "m.sqlite"))
    agent, returned = engine.register_agent(
        "Bot", "did:key:zOperator", "Mandate", "test", signer=kms
    )
    assert returned is kms
    assert agent.did == kms.did()
    assert not hasattr(returned, "private_bytes")


# --- What makes a remote signature trustworthy -----------------------------


def test_g123_a_signature_from_the_wrong_key_is_refused_at_sign_time():
    """The DID is the public key. A signer that holds another one is caught."""
    theirs = KeyPair.generate()
    mine = KeyPair.generate()
    signer = BrokenKms(theirs.sign(b"whatever"), did=mine.did())
    with pytest.raises(SigningError, match="does not verify against"):
        signer.sign(b"payload")


def test_g124_a_der_wrapped_or_truncated_signature_is_refused():
    kp = KeyPair.generate()
    with pytest.raises(SigningError, match="70-byte signature"):
        BrokenKms(b"\x30" * 70, did=kp.did()).sign(b"p")
    with pytest.raises(SigningError, match="0-byte signature"):
        BrokenKms(b"", did=kp.did()).sign(b"p")


def test_g125_a_signer_that_returns_something_other_than_bytes_is_refused():
    kp = KeyPair.generate()
    with pytest.raises(SigningError, match="not bytes"):
        BrokenKms("deadbeef", did=kp.did()).sign(b"p")


def test_g126_check_reports_a_key_swap_as_a_mismatch_not_as_a_bad_signature():
    """The operator needs to know which DID is wrong, not just that one is."""
    held = KeyPair.generate()
    expected = KeyPair.generate()
    signer = FakeKms(held, did=expected.did())
    with pytest.raises(SigningError) as exc:
        signer.check()
    assert held.did() in str(exc.value) and expected.did() in str(exc.value)


def test_g127_a_signer_that_publishes_nothing_is_still_proven_by_the_probe():
    kp = KeyPair.generate()
    ok = FakeKms(kp, publishes=False, did=kp.did())
    report = ok.check()
    assert report["did"] == kp.did() and report["published_key"] is False

    wrong = FakeKms(KeyPair.generate(), publishes=False, did=kp.did())
    with pytest.raises(SigningError, match="does not verify"):
        wrong.check()


def test_g128_a_probe_signature_can_never_be_replayed_as_a_mandate_object():
    """`check()` signs bytes that are not the canonical form of any object."""
    with pytest.raises(ValueError):
        json.loads(PROBE)
    assert PROBE != canonical_json({})


# --- AWS KMS ---------------------------------------------------------------


def test_g129_aws_signs_the_raw_message_not_a_digest():
    """PureEdDSA over the message is what a local key does; the digest
    variant would sign something else and never verify."""
    client = FakeAwsClient()
    signer = AwsKmsSigner(client, "arn:aws:kms:eu-central-1:1:key/abc")
    signed = sign_object(signer, {"a": 1})
    assert verify_object(signed)
    call = client.calls[0]
    assert call["MessageType"] == "RAW"
    assert call["SigningAlgorithm"] == "ED25519_SHA_512"
    assert call["KeyId"].startswith("arn:aws:kms:")


def test_g130_aws_refuses_a_key_that_is_not_ed25519():
    client = FakeAwsClient(key_spec="ECC_NIST_P256")
    with pytest.raises(SigningError, match="ECC_NIST_P256"):
        AwsKmsSigner(client, "arn:key").did()


def test_g150_aws_refuses_a_payload_over_its_4096_byte_limit(tmp_path):
    """Found by measuring, not by reading: an EXECUTED receipt is already ~2.9 KiB,
    and a context of 2031 bytes — legal under MAX_CONTEXT_BYTES — pushes a receipt
    past 4096. KMS would reject it mid-execution. Signing a digest instead is not
    an escape: ED25519_PH_SHA_512 is HashEdDSA and would not verify as did:key."""
    from datetime import timedelta

    from mandate.crypto import utcnow
    from mandate.validate import MAX_CONTEXT_BYTES

    engine = Engine(ledger=Ledger(tmp_path / "m.sqlite"))
    person, pkp = engine.register_principal("Belkis")
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "t")
    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="p",
        scopes=["x.do"], not_after=utcnow() + timedelta(days=1),
    )
    context = {"note": "x" * 2000, "ticket": "INC-4711"}
    assert len(canonical_json(context)) <= MAX_CONTEXT_BYTES, "a legal context"
    receipt = engine.propose(akp, grant["id"], "x.do", summary="s", context=context)
    payload = canonical_json({k: v for k, v in receipt.items() if k != "proof"})
    assert len(payload) > AwsKmsSigner.MAX_MESSAGE

    signer = AwsKmsSigner(FakeAwsClient(), "arn:key")
    with pytest.raises(SigningError, match="cannot sign"):
        signer.sign(payload)
    # And it says what to do instead, rather than leaving an AWS error code.
    with pytest.raises(SigningError, match="vault-transit"):
        signer.sign(payload)


def test_g131_aws_derives_the_did_from_the_key_kms_publishes():
    client = FakeAwsClient()
    assert AwsKmsSigner(client, "arn:key").did() == client.kp.did()


# --- Google Cloud KMS ------------------------------------------------------


def test_g132_gcp_signs_raw_data_and_derives_its_did_from_the_pem():
    client = FakeGcpClient()
    signer = GcpKmsSigner(client, "projects/p/…/cryptoKeyVersions/1")
    assert signer.did() == client.kp.did()
    assert verify_object(sign_object(signer, {"b": 2}))
    assert client.requests[0]["data"] == canonical_json({"b": 2})


# --- Vault transit ---------------------------------------------------------


def test_g133_vault_signatures_are_unwrapped_from_their_version_prefix():
    fake = FakeVault()
    signer = _vault(fake, timeout=3.5)
    assert verify_object(sign_object(signer, {"c": 3}))
    assert fake.timeouts == [3.5] * len(fake.timeouts), "the configured timeout is used"


def test_g134_vault_public_key_comes_from_the_latest_version():
    fake = FakeVault(version=2)
    assert _vault(fake).did() == fake.kp.did()


def test_g135_vault_over_plain_http_is_refused():
    """The token travels in a header; http would put it on the wire."""
    with pytest.raises(SigningError, match="clear text"):
        _vault(FakeVault(), address="http://vault.internal:8200")
    assert _vault(FakeVault(), address="http://vault.internal:8200", allow_insecure=True)


def test_g136_vault_without_a_token_is_refused():
    with pytest.raises(SigningError, match="VAULT_TOKEN"):
        _vault(FakeVault(), token="")


def test_g137_a_vault_error_never_carries_the_token_into_the_message():
    fake = FakeVault()
    fake.status = 403
    signer = _vault(fake, token="s.super-secret-token")
    with pytest.raises(SigningError) as exc:
        signer.sign(b"p")
    assert "403" in str(exc.value)
    assert "s.super-secret-token" not in str(exc.value)


def test_g138_a_command_may_answer_in_hex_base64_or_raw_bytes():
    kp = KeyPair.generate()
    sig = kp.sign(b"p")
    for stdout in (sig, sig.hex().encode(), base64.b64encode(sig), sig.hex().encode() + b"\n"):
        signer = CommandSigner(
            ["/bin/false"], did=kp.did(), runner=lambda *a, **k: _Completed(stdout)
        )
        assert signer.sign(b"p") == sig


def test_g139_a_command_signer_without_a_did_is_refused():
    """Nothing else would bind its signatures to a key."""
    with pytest.raises(SigningError, match="needs a did"):
        CommandSigner(["/usr/bin/sign"])


def test_g140_a_failing_command_is_a_signing_error_not_a_signature():
    kp = KeyPair.generate()
    signer = CommandSigner(
        ["/usr/bin/sign"], did=kp.did(),
        runner=lambda *a, **k: _Completed(b"", returncode=2, stderr=b"no slot"),
    )
    with pytest.raises(SigningError, match="exited 2"):
        signer.sign(b"p")


# --- Configuration ---------------------------------------------------------


def test_g141_an_unknown_signer_kind_names_the_ones_that_exist():
    with pytest.raises(SigningError, match="aws-kms"):
        signer_from_config({"kind": "azure-vault"})


def test_g142_the_vault_token_comes_from_the_environment_not_the_config_file():
    spec = {"kind": "vault-transit", "key": "k", "token": "s.in-the-file"}
    with pytest.raises(SigningError, match="VAULT_ADDR"):
        signer_from_config(spec, env={})
    signer = signer_from_config(
        spec, env={"VAULT_ADDR": "https://v:8200", "VAULT_TOKEN": "s.from-env"}
    )
    assert signer._token == "s.from-env"


def test_g143_a_file_signer_says_what_is_wrong_with_the_file(tmp_path):
    missing = tmp_path / "nope.key"
    with pytest.raises(SigningError, match="does not exist"):
        FileSigner(missing)
    junk = tmp_path / "junk.key"
    junk.write_text("not a key", encoding="utf-8")
    with pytest.raises(SigningError, match="hex-encoded"):
        FileSigner(junk)

    good = tmp_path / "good.key"
    kp = KeyPair.generate()
    good.write_text(kp.private_bytes().hex(), encoding="utf-8")
    assert FileSigner(good).did() == kp.did()


def test_g148_a_signer_block_without_a_kind_is_refused(tmp_path):
    from mandate.mcp.mapping import MappingError

    raw = json.loads(json.dumps(CONFIG))
    raw["store"] = str(tmp_path / "s")
    raw["agent_signer"] = {"key_id": "arn:key"}
    with pytest.raises(MappingError, match="needs a kind"):
        parse_config(raw)
    raw["agent_signer"] = "aws-kms"
    with pytest.raises(MappingError, match="must be an object"):
        parse_config(raw)


# --- The guard with a key it does not hold ---------------------------------


def _guard_world(tmp_path, upstream, agent_signer=None):
    """A guard whose agent key lives in a key manager.

    The configuration declares a signer kind exactly as a real one would; only
    the object it resolves to is a double, so the paths that ask "is the key
    local?" see what they would see in production.
    """
    raw = json.loads(json.dumps(CONFIG))
    raw["store"] = str(tmp_path / "store")
    if agent_signer is not None:
        raw["agent_signer"] = {"kind": "fake-kms"}
    config = parse_config(raw)
    if agent_signer is not None:
        config.build_agent_signer = lambda: agent_signer
    engine, executor = build_engine(config, upstream.call_tool, sorted(config.mapping.rules))
    executor._bridge = _direct_bridge
    state = bootstrap(config, engine)
    guard = McpGuard(
        engine=engine,
        agent_signer=agent_signer or load_agent_signer(config),
        grant_id=state["grant_id"],
        mapping=config.mapping,
        tenant=config.tenant,
        executor=executor,
    )
    return config, state, guard, executor


def test_g144_an_unavailable_signer_refuses_the_call_and_dispatches_nothing(tmp_path):
    """A call nobody can attribute is worse than a call that did not happen.

    The key manager was reachable when the grant was issued and is not
    reachable now — the failure mode a remote key actually has.
    """
    upstream = FakeUpstream()
    kms = FakeKms()
    _, _, guard, _ = _guard_world(tmp_path, upstream, agent_signer=kms)
    guard.agent_signer = BrokenKms(SigningError("kms unreachable"), did=kms.did())

    decision = guard.call("create_issue", {"repo": "beko/mandate"})
    assert not decision.allowed
    assert decision.outcome == "SIGNER_UNAVAILABLE"
    assert "could not sign" in decision.text
    assert upstream.calls == [], "nothing may reach the upstream unsigned"


def test_g149_a_key_managers_error_reaches_the_operator_not_the_model(tmp_path):
    """`text` is tool output a model reads. A signer error can name hosts,
    paths and ARNs, so it goes to the log instead."""
    upstream = FakeUpstream()
    kms = FakeKms()
    _, _, guard, _ = _guard_world(tmp_path, upstream, agent_signer=kms)
    leak = "vault.internal.example:8200 token s.abc /etc/keys/agent.key"
    guard.agent_signer = BrokenKms(SigningError(leak), did=kms.did())

    decision = guard.call("create_issue", {"repo": "beko/mandate"})
    assert leak not in decision.text
    assert "retrying will not clear it" in decision.text
    assert decision.detail == leak


def test_g145_bootstrap_with_a_key_manager_writes_no_agent_key(tmp_path):
    upstream = FakeUpstream()
    kms = FakeKms()
    config, state, _, _ = _guard_world(tmp_path, upstream, agent_signer=kms)

    assert state["agent_did"] == kms.did()
    assert not (config.store_path / "keys" / "agent.key").exists()
    # The principal key is still local: issuing a grant is an operator action,
    # not something the guard process does while serving.
    assert (config.store_path / "keys" / "principal.key").exists()
    assert config.holds_agent_key is False


def test_g146_a_configured_signer_wins_over_a_key_file_that_is_lying_around(tmp_path):
    upstream = FakeUpstream()
    kms = FakeKms()
    config, _, _, _ = _guard_world(tmp_path, upstream, agent_signer=kms)
    stale = config.store_path / "keys" / "agent.key"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(KeyPair.generate().private_bytes().hex(), encoding="utf-8")

    assert load_agent_signer(config).did() == kms.did()


def test_g147_a_tool_call_runs_end_to_end_with_a_key_the_process_cannot_read(tmp_path):
    upstream = FakeUpstream(reply="issue #1 created")
    kms = FakeKms()
    _, state, guard, _ = _guard_world(tmp_path, upstream, agent_signer=kms)

    decision = guard.call("create_issue", {"repo": "beko/mandate", "title": "t"})
    assert decision.allowed, decision.text
    assert decision.text == "issue #1 created"
    assert upstream.calls[0][0] == "create_issue"
    # Every signature on the way there came from the key manager.
    assert len(kms.signed) >= 1
    assert state["agent_did"] == kms.did()


# --- Round two: what independent review found -------------------------------


def test_g151_a_malformed_configured_did_is_a_signing_error_not_a_valueerror():
    """`crypto.verify` parses the DID outside its own try block, so a bad one
    surfaced as ValueError/AttributeError past every SigningError handler."""
    kp = KeyPair.generate()
    for bad in ("not-a-did", "did:web:example.com", 12345, b"did:key:z"):
        with pytest.raises(SigningError):
            CommandSigner(["/x"], did=bad, runner=lambda *a, **k: _Completed(kp.sign(b"p")))
    good = CommandSigner(["/x"], did=kp.did(), runner=lambda *a, **k: _Completed(kp.sign(b"p")))
    assert good.sign(b"p") == kp.sign(b"p")


def test_g152_the_vault_token_is_never_resent_to_a_redirect_target():
    """Reproduced against a live server before the fix: urllib copies ordinary
    headers onto a redirected request, across origins and across an
    https-to-http downgrade, so a 302 handed `X-Vault-Token` to the new host."""
    import http.server
    import threading

    from mandate.signing import _urllib_transport

    seen: dict[str, dict] = {}

    class Attacker(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["headers"] = dict(self.headers)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    class Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{attacker_port}/stolen")
            self.end_headers()

        def log_message(self, *a):
            pass

    attacker = http.server.HTTPServer(("127.0.0.1", 0), Attacker)
    attacker_port = attacker.server_address[1]
    redirector = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=attacker.serve_forever, daemon=True).start()
    threading.Thread(target=redirector.serve_forever, daemon=True).start()
    try:
        status, _ = _urllib_transport(
            "GET",
            f"http://127.0.0.1:{redirector.server_address[1]}/v1/transit/keys/k",
            {"X-Vault-Token": "s.SUPER-SECRET"},
            None,
            5.0,
        )
        assert status == 302, "the redirect is surfaced, not followed"
        assert "headers" not in seen, "the redirect target was never contacted"
    finally:
        attacker.shutdown()
        redirector.shutdown()


def test_g153_a_signing_failure_before_dispatch_sends_nothing(tmp_path):
    """The claim is signed first so an unsignable execution never leaves."""
    from mandate.engine import ExecutionUnknown, MandateError

    world = _engine_world(tmp_path)
    world["engine"].enforcer = _FailAfter(world["kms"], after=1)  # claim signing fails
    with pytest.raises(MandateError) as exc:
        world["engine"].execute(world["receipt_id"], idempotency_key="idem-1")
    assert not isinstance(exc.value, ExecutionUnknown)
    assert "could not be signed" in str(exc.value)
    assert world["upstream"].forwarded == [], "nothing may be dispatched"
    # The key manager's own words stay out of a message a model can read.
    assert "vault.internal" not in str(exc.value)


def test_g154_a_signing_failure_after_dispatch_is_unknown_not_failed(tmp_path):
    """The upstream already acted. Reporting a failed dispatch would invite
    exactly the retry that must not happen."""
    from mandate.engine import ExecutionUnknown

    world = _engine_world(tmp_path)
    world["engine"].enforcer = _FailAfter(world["kms"], after=2)  # final receipt fails
    with pytest.raises(ExecutionUnknown) as exc:
        world["engine"].execute(world["receipt_id"], idempotency_key="idem-2")
    assert exc.value.receipt_id == world["receipt_id"]
    assert world["upstream"].forwarded, "the call did go out"

    # The receipt stays EXECUTING with its reservation, for the reconciler.
    with world["engine"].ledger.tx() as tx:
        row = tx.get_receipt(world["receipt_id"])
    assert row["state"] == "EXECUTING"

    # Once the key manager is back, the reconciler closes it out as unknown.
    world["engine"].enforcer = world["kms"]
    reconciled = world["engine"].reconcile_stale_executions(stale_after_s=-1)
    assert world["receipt_id"] in reconciled


def test_g155_the_guard_reports_an_unrecordable_dispatch_as_unknown(tmp_path):
    """And keeps the key manager's error out of the model's tool output."""
    upstream = FakeUpstream()
    kms = FakeKms()
    _, _, guard, _ = _guard_world(tmp_path, upstream, agent_signer=kms)
    leak = "vault.internal.example:8200 token s.abc"
    # Three signatures reach the enforcer on this path: the AUTHORIZED receipt,
    # the EXECUTING claim, then the final one. Break the last.
    guard.engine.enforcer = _FailAfter(guard.engine.enforcer, after=3, message=leak)

    decision = guard.call("create_issue", {"repo": "beko/mandate"})
    assert decision.outcome == "EXECUTION_UNKNOWN"
    assert "Do not retry blindly" in decision.text
    assert "could not dispatch" not in decision.text
    assert leak not in decision.text and leak in (decision.detail or "")
    assert upstream.calls, "the upstream was reached"


def test_g156_the_guard_will_not_serve_with_an_enforcer_that_cannot_sign():
    """`Engine` only asks the enforcer for its DID, which a remote signer can
    answer from a published key without being able to sign at all."""
    kp = KeyPair.generate()

    class PublishesButCannotSign(FakeKms):
        name = "half-broken"

        def _sign_remote(self, payload: bytes) -> bytes:
            raise SigningError("kms: AccessDeniedException on kms:Sign")

    signer = PublishesButCannotSign(kp)
    assert signer.did() == kp.did(), "naming itself works"
    with pytest.raises(SigningError, match="AccessDenied"):
        signer.check()


class _FailAfter:
    """A signer that works n times and then stops, to land a failure on one
    specific signature inside `Engine.execute()`.

    Only signatures over Mandate *objects* are counted. Chain entries sign a
    `sha256:…` string, and counting those too would tie these gates to how many
    entries the chain happens to append — which is not what they are about.
    """

    name = "fail-after"

    def __init__(self, inner, after: int, message: str = "key manager unreachable") -> None:
        self._inner = inner
        self._after = after
        self._message = message
        self.calls = 0

    @staticmethod
    def _is_object(payload: bytes) -> bool:
        return payload[:1] == b"{"

    def did(self) -> str:
        return self._inner.did()

    def sign(self, payload: bytes) -> bytes:
        if not self._is_object(payload):
            return self._inner.sign(payload)
        self.calls += 1
        if self.calls >= self._after:
            raise SigningError(self._message)
        return self._inner.sign(payload)

    def sign_hex(self, payload: bytes) -> str:
        return self.sign(payload).hex()


class _RecordingExecutor:
    def __init__(self) -> None:
        self.forwarded: list[tuple] = []

    def forward(self, route, method, path, body, idempotency_key):
        from mandate.executor import ExecutionResult

        self.forwarded.append((method, path, body))
        return ExecutionResult("EXECUTED", 200, 3, "sha256:x", None)


def _engine_world(tmp_path):
    """An authorized receipt, one `execute()` away from dispatch."""
    from datetime import timedelta

    from mandate.crypto import utcnow
    from mandate.routes import Route, RouteRegistry

    kms = FakeKms()
    upstream = _RecordingExecutor()
    route = Route(
        audience="mandate://local",
        base_url="https://upstream.example",
        allowed_methods=("POST",),
        allowed_paths=("/do",),
    )
    engine = Engine(
        ledger=Ledger(tmp_path / "m.sqlite"),
        key_provider=SignerKeyProvider(kms),
        routes=RouteRegistry([route]),
        executor=upstream,
    )
    person, pkp = engine.register_principal("Belkis")
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "t")
    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="p",
        scopes=["x.do"], not_after=utcnow() + timedelta(days=1),
    )
    receipt = engine.propose(akp, grant["id"], "x.do", summary="s")
    assert receipt["outcome"] == "AUTHORIZED", receipt
    return {
        "engine": engine, "kms": kms, "upstream": upstream, "receipt_id": receipt["id"],
    }


def test_g157_losing_the_final_state_race_is_unknown_not_a_failed_dispatch(tmp_path):
    """A real race, not a mock: the reconciler moves the receipt out of
    EXECUTING while the upstream call is still in flight, so the final CAS
    loses. The call went out, so "could not dispatch it" would invite exactly
    the retry that must not happen.

    Found by review after the first fix landed — the same defect one line
    further down, which the earlier change had deliberately left alone.
    """
    import threading
    from datetime import timedelta

    from mandate.crypto import utcnow
    from mandate.engine import ExecutionUnknown
    from mandate.executor import ExecutionResult
    from mandate.routes import Route, RouteRegistry

    class BlockingExecutor:
        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()

        def forward(self, route, method, path, body, idempotency_key):
            self.entered.set()          # the request has gone out
            self.release.wait(10)       # and we are waiting on the upstream
            return ExecutionResult("EXECUTED", 200, 3, "sha256:x", None)

    executor = BlockingExecutor()
    engine = Engine(
        ledger=Ledger(tmp_path / "m.sqlite"),
        routes=RouteRegistry([Route(
            audience="mandate://local", base_url="https://up.example",
            allowed_methods=("POST",), allowed_paths=("/do",),
        )]),
        executor=executor,
    )
    person, pkp = engine.register_principal("Belkis")
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "t")
    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="p",
        scopes=["x.do"], not_after=utcnow() + timedelta(days=1),
    )
    receipt_id = engine.propose(akp, grant["id"], "x.do", summary="s")["id"]

    outcome: dict = {}

    def run():
        try:
            outcome["result"] = engine.execute(receipt_id, idempotency_key="i")
        except Exception as exc:  # noqa: BLE001 - the point of the gate
            outcome["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert executor.entered.wait(10), "the executor was never reached"
        assert engine.reconcile_stale_executions(stale_after_s=-1) == [receipt_id]
    finally:
        executor.release.set()
        worker.join(15)

    error = outcome.get("error")
    assert isinstance(error, ExecutionUnknown), f"got {error!r}"
    assert error.receipt_id == receipt_id
