from __future__ import annotations
from pathlib import Path
from .crypto import KeyPair

class KeyProvider:
    def get_enforcer(self):
        raise NotImplementedError

class EphemeralKeyProvider(KeyProvider):
    def __init__(self):
        self._kp = KeyPair.generate()
    def get_enforcer(self):
        return self._kp

class InMemoryKeyProvider(KeyProvider):
    def __init__(self, kp):
        self._kp = kp
    def get_enforcer(self):
        return self._kp

class PersistedDevKeyProvider(KeyProvider):
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._path = self.directory / "enforcer.key"
        if self._path.exists():
            self._kp = KeyPair.from_private_bytes(bytes.fromhex(self._path.read_text().strip()))
        else:
            self._kp = KeyPair.generate()
            self._path.write_text(self._kp.private_bytes().hex())
            try:
                self._path.chmod(0o600)
            except OSError:
                pass
    def get_enforcer(self):
        return self._kp
