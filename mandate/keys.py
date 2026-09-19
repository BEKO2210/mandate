"""Key providers live outside the object/grant store."""

from __future__ import annotations

from pathlib import Path

from .crypto import KeyPair


class KeyProvider:
    def get_enforcer(self) -> KeyPair:
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
