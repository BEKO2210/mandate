from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + out[::-1].decode("ascii")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch.encode("ascii"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = sum(1 for ch in s if ch == "1") if s.startswith("1") else 0
    # count leading ones only
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = Ed25519PrivateKey.generate()
        return cls(private=priv, public=priv.public_key())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private=priv, public=priv.public_key())

    def private_bytes(self) -> bytes:
        return self.private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def did(self) -> str:
        return public_bytes_to_did(self.public_bytes())

    def sign(self, payload: bytes) -> bytes:
        return self.private.sign(payload)

    def sign_hex(self, payload: bytes) -> str:
        return self.sign(payload).hex()


def public_bytes_to_did(pub: bytes) -> str:
    if len(pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + pub)


def did_to_public_bytes(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did}")
    raw = _b58decode(did[len("did:key:z") :])
    if not raw.startswith(_ED25519_MULTICODEC) or len(raw) != 34:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]


def verify(did: str, payload: bytes, signature_hex: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(did_to_public_bytes(did))
    try:
        pub.verify(bytes.fromhex(signature_hex), payload)
        return True
    except Exception:
        return False


def sign_object(kp: KeyPair, obj: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in obj.items() if k != "proof"}
    payload = canonical_json(body)
    proof = {
        "type": "Ed25519Signature2026",
        "created": iso(utcnow()),
        "verificationMethod": kp.did() + "#" + kp.did().split(":")[-1],
        "proofPurpose": "assertionMethod",
        "proofValue": kp.sign_hex(payload),
        "payloadHash": sha256_hex(payload),
    }
    return {**body, "proof": proof}


def verify_object(obj: dict[str, Any], expected_did: str | None = None) -> bool:
    if "proof" not in obj:
        return False
    proof = obj["proof"]
    body = {k: v for k, v in obj.items() if k != "proof"}
    payload = canonical_json(body)
    signer = expected_did if expected_did else proof.get("verificationMethod", "").split("#")[0]
    if proof.get("payloadHash") and proof["payloadHash"] != sha256_hex(payload):
        return False
    return verify(signer, payload, proof.get("proofValue", ""))
