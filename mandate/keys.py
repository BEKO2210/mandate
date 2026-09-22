"""Key providers live outside the object/grant store.

A provider hands the engine something that can sign, not necessarily a key it
holds: `SignerKeyProvider` keeps the enforcer key in a key manager, so the
process that signs receipts cannot export the key it signs them with.
"""

from __future__ import annotations

from pathlib import Path

from .crypto import KeyPair
from .signing import Signer


class KeyProvider:
    def get_enforcer(self) -> Signer:
        raise NotImplementedError


class EphemeralKeyProvider(KeyProvider):
    """New key every construction. Tests only."""

    def __init__(self) -> None:
        self._kp = KeyPair.generate()

    def get_enforcer(self) -> KeyPair:
        return self._kp


class InMemoryKeyProvider(KeyProvider):
    def __init__(self, kp: KeyPair) -> None:
        self._kp = kp

    def get_enforcer(self) -> KeyPair:
        return self._kp


class PersistedDevKeyProvider(KeyProvider):
    """Dev-only file key store. Never colocated with grant/receipt JSON."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._path = self.directory / "enforcer.key"
        if self._path.exists():
            raw = bytes.fromhex(self._path.read_text(encoding="utf-8").strip())
            self._kp = KeyPair.from_private_bytes(raw)
        else:
            self._kp = KeyPair.generate()
            self._path.write_text(self._kp.private_bytes().hex(), encoding="utf-8")
            try:
                self._path.chmod(0o600)
            except OSError:
                pass

    def get_enforcer(self) -> KeyPair:
        return self._kp


class SignerKeyProvider(KeyProvider):
    """The enforcer signs through a key manager it cannot read the key from.

    `Engine` only ever asks the enforcer key to sign, so anything satisfying
    `Signer` works here — AWS KMS, Cloud KMS, Vault transit, or a command
    fronting an HSM. Receipts stay verifiable by the same `did:key` as before,
    because the DID is the public key either way.
    """

    def __init__(self, signer: Signer) -> None:
        self._signer = signer

    def get_enforcer(self) -> Signer:
        return self._signer
