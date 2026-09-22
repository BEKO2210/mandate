"""Signing keys that never have to enter this process.

Every release so far assumed the signer *is* the private key: `KeyPair` holds
an `Ed25519PrivateKey` object, and anything that can read that object — a
dependency, a crash dump, a debugger, a file the wrong user can open — can sign
in the principal's or the agent's name for as long as the key lives. The MCP
guard made that concrete: it holds the agent key in the same process the model
talks to.

This module separates *being able to sign* from *holding the key*. A `Signer`
is anything that can answer two questions:

    did()              which key is this, as a did:key
    sign(payload)      an Ed25519 signature over exactly these bytes

`KeyPair` answers both from memory. A `RemoteSigner` answers them by asking a
key manager that will not hand the key back — AWS KMS, Google Cloud KMS, Vault's
transit engine, or any command that fronts an HSM. The process can then produce
signatures it can never forge offline, and revoking access to the key manager
revokes signing, which deleting a file on a compromised host does not.

Two invariants hold for every remote signer:

* **Every signature is verified before it is returned.** An Ed25519 verify costs
  microseconds. A key manager that is pointed at the wrong key, returns a
  DER-wrapped signature, or silently truncates one is caught at sign time,
  where it is a loud error, rather than at audit time, where it is an
  unverifiable receipt nobody can explain.
* **The DID binds the key.** `did:key` *is* the public key. If a signer is
  configured with a DID, a signature that does not verify against that DID
  fails — so swapping the key manager's key under a running deployment cannot
  quietly re-point a grant at a different signer.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import urllib.error
import urllib.request
from typing import Any, Callable, Protocol, runtime_checkable

from .crypto import KeyPair, public_bytes_to_did, verify

# Signed by `check()` only. It is not a Mandate object and carries no
# authority, so a signature over it grants nothing — it only proves that the
# key manager holds the key the DID names.
PROBE = b"mandate/signer-check/v1"

SIGNATURE_BYTES = 64
PUBLIC_KEY_BYTES = 32
DEFAULT_TIMEOUT = 10.0


class SigningError(Exception):
    """The signer could not produce a signature that can be trusted."""


@runtime_checkable
class Signer(Protocol):
    """What the rest of Mandate needs from a key. `KeyPair` satisfies it."""

    def did(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...

    def sign_hex(self, payload: bytes) -> str: ...


class RemoteSigner:
    """A signer whose private key is held somewhere this process cannot read.

    Subclasses implement `_sign_remote`, and `_fetch_public_bytes` when the key
    manager will publish the public key. Everything that makes the result
    trustworthy — length, verification, DID binding — happens here, once.
    """

    name = "remote"

    def __init__(self, *, did: str | None = None) -> None:
        self._did = did
        self._public: bytes | None = None

    # --- to implement -----------------------------------------------------

    def _sign_remote(self, payload: bytes) -> bytes:
        raise NotImplementedError

    def _fetch_public_bytes(self) -> bytes:
        """Raise if the key manager does not publish the public key."""
        raise SigningError(
            f"{self.name} cannot publish its public key; give this signer a did"
        )

    # --- the contract -----------------------------------------------------

    def public_bytes(self) -> bytes:
        if self._public is None:
            pub = self._fetch_public_bytes()
            if len(pub) != PUBLIC_KEY_BYTES:
                raise SigningError(
                    f"{self.name} returned a {len(pub)}-byte public key; "
                    f"Ed25519 keys are {PUBLIC_KEY_BYTES} bytes"
                )
            self._public = pub
        return self._public

    def did(self) -> str:
        if self._did is None:
            self._did = public_bytes_to_did(self.public_bytes())
        return self._did

    def sign(self, payload: bytes) -> bytes:
        raw = self._sign_remote(payload)
        if not isinstance(raw, (bytes, bytearray)):
            raise SigningError(f"{self.name} returned {type(raw).__name__}, not bytes")
        raw = bytes(raw)
        if len(raw) != SIGNATURE_BYTES:
            raise SigningError(
                f"{self.name} returned a {len(raw)}-byte signature; an Ed25519 "
                f"signature is {SIGNATURE_BYTES} bytes (is the key Ed25519, and is "
                f"the signature raw rather than DER-wrapped?)"
            )
        if not verify(self.did(), payload, raw.hex()):
            raise SigningError(
                f"{self.name} produced a signature that does not verify against "
                f"{self.did()}. The key manager is holding a different key than "
                f"this signer is configured for; refusing to emit it."
            )
        return raw

    def sign_hex(self, payload: bytes) -> str:
        return self.sign(payload).hex()

    def check(self) -> dict[str, Any]:
        """Prove the signer works, before anything depends on it.

        Signs a fixed probe and verifies it. When the key manager also
        publishes the public key, the DID derived from it is compared with the
        configured one, so a mismatch is reported as a mismatch rather than as
        a failed signature.
        """
        configured = self._did
        published: str | None = None
        try:
            published = public_bytes_to_did(self.public_bytes())
        except SigningError:
            pass  # a signer that cannot publish is proven by the probe alone
        if configured and published and configured != published:
            raise SigningError(
                f"{self.name} holds {published} but this signer is configured for "
                f"{configured}. A grant naming the configured DID would be signed "
                f"by a key it does not name."
            )
        signature = self.sign(PROBE)
        if not verify(self.did(), PROBE, signature.hex()):
            raise SigningError(f"{self.name} cannot sign for {self.did()}")
        return {"signer": self.name, "did": self.did(), "published_key": published is not None}


# --------------------------------------------------------------------------
# AWS KMS
# --------------------------------------------------------------------------


class AwsKmsSigner(RemoteSigner):
    """AWS KMS, key spec `ECC_NIST_EDWARDS25519`.

    The client is injected rather than constructed here: it keeps boto3 out of
    the dependency list and lets the enforcement path be tested without an AWS
    account. `signer_from_config` builds a real one on demand.

    `ED25519_SHA_512` with `MessageType=RAW` is PureEdDSA over the message —
    the same thing a local key does — so the signature verifies against the
    same DID. The digest variant would sign something else entirely.
    """

    name = "aws-kms"

    #: KMS rejects a `Sign` message over 4096 bytes. Its documented workaround —
    #: hash it yourself and send `MessageType=DIGEST` — is not available here:
    #: with an Ed25519 key that selects `ED25519_PH_SHA_512`, which is HashEdDSA
    #: and does not verify as a plain Ed25519 signature, so the receipt would no
    #: longer verify against its own `did:key`.
    MAX_MESSAGE = 4096

    def __init__(self, client: Any, key_id: str, *, did: str | None = None) -> None:
        super().__init__(did=did)
        self._client = client
        self.key_id = key_id

    def _sign_remote(self, payload: bytes) -> bytes:
        if len(payload) > self.MAX_MESSAGE:
            raise SigningError(
                f"aws-kms cannot sign {len(payload)} bytes; its limit is "
                f"{self.MAX_MESSAGE}. Signing a digest instead would need "
                f"ED25519_PH_SHA_512, whose signatures do not verify as plain "
                f"Ed25519, so the object would no longer verify against its own "
                f"did:key. Use vault-transit, gcp-kms or a command signer for "
                f"objects this size, or lower MAX_CONTEXT_BYTES."
            )
        try:
            result = self._client.sign(
                KeyId=self.key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm="ED25519_SHA_512",
            )
        except Exception as exc:  # the SDK's own errors are not ours to model
            raise SigningError(f"aws-kms sign failed: {type(exc).__name__}: {exc}") from exc
        return _as_bytes(_field(result, "Signature", "aws-kms"), "aws-kms signature")

    def _fetch_public_bytes(self) -> bytes:
        try:
            result = self._client.get_public_key(KeyId=self.key_id)
        except Exception as exc:
            raise SigningError(f"aws-kms get_public_key failed: {exc}") from exc
        spec = _maybe(result, "KeySpec")
        if spec and spec != "ECC_NIST_EDWARDS25519":
            raise SigningError(
                f"aws-kms key {self.key_id} has spec {spec}; Mandate signs with "
                f"Ed25519 (ECC_NIST_EDWARDS25519)"
            )
        return _public_from_der(_as_bytes(_field(result, "PublicKey", "aws-kms"), "aws-kms key"))


# --------------------------------------------------------------------------
# Google Cloud KMS
# --------------------------------------------------------------------------


class GcpKmsSigner(RemoteSigner):
    """Google Cloud KMS, algorithm `EC_SIGN_ED25519` (PureEdDSA)."""

    name = "gcp-kms"

    def __init__(self, client: Any, key_name: str, *, did: str | None = None) -> None:
        super().__init__(did=did)
        self._client = client
        self.key_name = key_name

    def _sign_remote(self, payload: bytes) -> bytes:
        try:
            result = self._client.asymmetric_sign(
                request={"name": self.key_name, "data": payload}
            )
        except Exception as exc:
            raise SigningError(f"gcp-kms sign failed: {type(exc).__name__}: {exc}") from exc
        return _as_bytes(_field(result, "signature", "gcp-kms"), "gcp-kms signature")

    def _fetch_public_bytes(self) -> bytes:
        try:
            result = self._client.get_public_key(request={"name": self.key_name})
        except Exception as exc:
            raise SigningError(f"gcp-kms get_public_key failed: {exc}") from exc
        pem = _field(result, "pem", "gcp-kms")
        return _public_from_pem(pem)


# --------------------------------------------------------------------------
# HashiCorp Vault, transit engine
# --------------------------------------------------------------------------


Transport = Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]]


class VaultTransitSigner(RemoteSigner):
    """Vault's transit engine with an `ed25519` key.

    Vault never exports a transit key, which is the whole point. The token is
    read from the environment, never from a config file, so a configuration
    checked into a repository cannot carry it.
    """

    name = "vault-transit"

    def __init__(
        self,
        address: str,
        token: str,
        key: str,
        *,
        mount: str = "transit",
        did: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Transport | None = None,
        allow_insecure: bool = False,
    ) -> None:
        super().__init__(did=did)
        address = address.rstrip("/")
        if address.startswith("http://") and not allow_insecure:
            raise SigningError(
                "vault address is plain http, which would put the token on the "
                "wire in clear text; use https or set allow_insecure"
            )
        if not token:
            raise SigningError("vault token is empty; set VAULT_TOKEN")
        self.address = address
        self.key = key
        self.mount = mount.strip("/")
        self._token = token
        self._timeout = timeout
        self._transport = transport or _urllib_transport

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.address}/v1/{self.mount}/{path}"
        headers = {"X-Vault-Token": self._token, "Content-Type": "application/json"}
        raw = json.dumps(body).encode("utf-8") if body is not None else None
        try:
            status, payload = self._transport(method, url, headers, raw, self._timeout)
        except Exception as exc:
            raise SigningError(f"vault {method} {path} failed: {type(exc).__name__}") from exc
        if status != 200:
            # Vault's error bodies can name the key; the token is never in them.
            raise SigningError(f"vault {method} {path} returned {status}: {payload[:200]!r}")
        try:
            return json.loads(payload)["data"]
        except (ValueError, KeyError) as exc:
            raise SigningError(f"vault {method} {path} returned an unusable body") from exc

    def _sign_remote(self, payload: bytes) -> bytes:
        data = self._call(
            "POST", f"sign/{self.key}", {"input": base64.b64encode(payload).decode("ascii")}
        )
        signature = data.get("signature")
        if not isinstance(signature, str):
            raise SigningError("vault returned no signature")
        # "vault:v1:<base64>" — the version prefix says which key version signed.
        _, _, encoded = signature.rpartition(":")
        try:
            return base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise SigningError("vault signature is not base64") from exc

    def _fetch_public_bytes(self) -> bytes:
        data = self._call("GET", f"keys/{self.key}")
        if data.get("type") not in (None, "ed25519"):
            raise SigningError(
                f"vault key {self.key} is {data['type']}; Mandate signs with ed25519"
            )
        versions = data.get("keys") or {}
        if not isinstance(versions, dict) or not versions:
            raise SigningError("vault returned no key versions")
        latest = str(data.get("latest_version") or max(versions, key=_as_int))
        entry = versions.get(latest) or versions[max(versions, key=_as_int)]
        encoded = entry.get("public_key") if isinstance(entry, dict) else entry
        if not isinstance(encoded, str):
            raise SigningError("vault returned no public key")
        try:
            return base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise SigningError("vault public key is not base64") from exc


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# --------------------------------------------------------------------------
# An external command: HSMs, PKCS#11, smartcards, anything with a CLI
# --------------------------------------------------------------------------


class CommandSigner(RemoteSigner):
    """Delegate signing to a command that holds the key.

    The payload goes to the command's stdin; the signature comes back on
    stdout as hex, base64 or 64 raw bytes. This is the escape hatch for key
    managers Mandate does not know about — a PKCS#11 wrapper, a smartcard, an
    agent on another host. The command is a fixed argv, never a shell string,
    so nothing in a signed payload can influence what runs.
    """

    name = "command"

    def __init__(
        self,
        argv: list[str],
        *,
        did: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
        runner: Callable[..., Any] | None = None,
    ) -> None:
        super().__init__(did=did)
        if not argv:
            raise SigningError("command signer needs an argv")
        if not did:
            raise SigningError(
                "command signer needs a did: the command is not asked for its "
                "public key, so the DID is what binds its signatures"
            )
        self.argv = list(argv)
        self._timeout = timeout
        self._env = env
        self._runner = runner or subprocess.run

    def _sign_remote(self, payload: bytes) -> bytes:
        try:
            result = self._runner(
                self.argv,
                input=payload,
                capture_output=True,
                timeout=self._timeout,
                env=self._env,
                check=False,
            )
        except Exception as exc:
            raise SigningError(f"signer command failed to run: {exc}") from exc
        if getattr(result, "returncode", 1) != 0:
            err = (getattr(result, "stderr", b"") or b"")[:200]
            raise SigningError(f"signer command exited {result.returncode}: {err!r}")
        return _decode_signature(getattr(result, "stdout", b"") or b"")


def _decode_signature(out: bytes) -> bytes:
    if len(out) == SIGNATURE_BYTES:
        return out
    text = out.strip().decode("ascii", "ignore")
    for decode in (bytes.fromhex, lambda s: base64.b64decode(s, validate=True)):
        try:
            raw = decode(text)
        except Exception:
            continue
        if len(raw) == SIGNATURE_BYTES:
            return raw
    raise SigningError(
        "signer command produced no usable signature (expected 64 raw bytes, "
        "hex or base64)"
    )


# --------------------------------------------------------------------------
# Building a signer from configuration
# --------------------------------------------------------------------------


class FileSigner:
    """The development default: an Ed25519 key in a file this process reads.

    Kept as a named kind so a configuration always says out loud where its key
    lives, and so `mandate signer check` reports "file" rather than silence.
    """

    name = "file"

    def __init__(self, path: str | os.PathLike, *, did: str | None = None) -> None:
        self.path = str(path)
        try:
            text = pathlib.Path(self.path).read_text(encoding="utf-8")
            raw = bytes.fromhex(text.strip())
            self._kp = KeyPair.from_private_bytes(raw)
        except FileNotFoundError as exc:
            raise SigningError(f"{self.path} does not exist") from exc
        except ValueError as exc:
            raise SigningError(f"{self.path} is not a hex-encoded Ed25519 key") from exc
        if did and did != self._kp.did():
            raise SigningError(
                f"{self.path} holds {self._kp.did()} but this signer is "
                f"configured for {did}"
            )

    def did(self) -> str:
        return self._kp.did()

    def sign(self, payload: bytes) -> bytes:
        return self._kp.sign(payload)

    def sign_hex(self, payload: bytes) -> str:
        return self._kp.sign_hex(payload)

    def check(self) -> dict[str, Any]:
        return {"signer": self.name, "did": self.did(), "published_key": True}


def signer_from_config(spec: dict[str, Any], env: dict[str, str] | None = None) -> Signer:
    """Build a signer from one configuration block.

    Secrets are read from the environment, never from the block itself, so a
    configuration file can be committed without carrying credentials.
    """
    env = env if env is not None else dict(os.environ)
    if not isinstance(spec, dict):
        raise SigningError("signer configuration must be an object")
    kind = spec.get("kind")
    did = spec.get("did")

    if kind == "file":
        path = spec.get("path")
        if not path:
            raise SigningError("file signer needs a path")
        return FileSigner(path, did=did)

    if kind == "aws-kms":
        key_id = _required(spec, "key_id", kind)
        try:
            import boto3  # imported here so the SDK is not a dependency
        except ImportError as exc:
            raise SigningError("aws-kms needs boto3 (pip install boto3)") from exc
        client = boto3.client("kms", region_name=spec.get("region"))
        return AwsKmsSigner(client, key_id, did=did)

    if kind == "gcp-kms":
        key_name = _required(spec, "key", kind)
        try:
            from google.cloud import kms  # type: ignore
        except ImportError as exc:
            raise SigningError(
                "gcp-kms needs google-cloud-kms (pip install google-cloud-kms)"
            ) from exc
        return GcpKmsSigner(kms.KeyManagementServiceClient(), key_name, did=did)

    if kind == "vault-transit":
        key = _required(spec, "key", kind)
        address = env.get(spec.get("address_env", "VAULT_ADDR"), "")
        token = env.get(spec.get("token_env", "VAULT_TOKEN"), "")
        if not address:
            raise SigningError(
                f"vault-transit needs an address in ${spec.get('address_env', 'VAULT_ADDR')}"
            )
        return VaultTransitSigner(
            address,
            token,
            key,
            mount=spec.get("mount", "transit"),
            did=did,
            allow_insecure=bool(spec.get("allow_insecure", False)),
        )

    if kind == "command":
        argv = spec.get("argv")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise SigningError("command signer needs argv as a list of strings")
        return CommandSigner(argv, did=did)

    raise SigningError(
        f"unknown signer kind {kind!r}; use file, aws-kms, gcp-kms, "
        f"vault-transit or command"
    )


def _required(spec: dict[str, Any], field: str, kind: str) -> str:
    value = spec.get(field)
    if not isinstance(value, str) or not value:
        raise SigningError(f"{kind} signer needs {field}")
    return value


def _field(result: Any, name: str, who: str) -> Any:
    """Read one field off a dict or an SDK response object, whichever came."""
    value = result.get(name) if isinstance(result, dict) else getattr(result, name, None)
    if value is None:
        raise SigningError(f"{who} returned no {name}")
    return value


def _as_bytes(value: Any, what: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise SigningError(f"{what} is {type(value).__name__}, not bytes")


def _maybe(result: Any, name: str) -> Any:
    return result.get(name) if isinstance(result, dict) else getattr(result, name, None)


def _public_from_der(der: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    return _raw_public(_load(load_der_public_key, der, "DER"))


def _public_from_pem(pem: str | bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    data = pem.encode("ascii") if isinstance(pem, str) else pem
    return _raw_public(_load(load_pem_public_key, data, "PEM"))


def _load(loader: Callable[[bytes], Any], data: bytes, kind: str) -> Any:
    """Keep a malformed key inside SigningError, where callers catch it."""
    try:
        return loader(data)
    except Exception as exc:
        raise SigningError(f"the key manager published unreadable {kind}: {exc}") from exc


def _raw_public(key: Any) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if not isinstance(key, Ed25519PublicKey):
        raise SigningError(
            f"the key manager published a {type(key).__name__}; Mandate signs "
            f"with Ed25519"
        )
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
