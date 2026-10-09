from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path


class LocalAccessManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def is_configured(self) -> bool:
        return self.path.exists()

    def configure(self, passphrase: str) -> None:
        self._validate(passphrase)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 300000)
        payload = {"salt": salt.hex(), "digest": digest.hex(), "iterations": 300000}
        self.path.write_text(json.dumps(payload), encoding="utf-8")

    def verify(self, passphrase: str) -> bool:
        if not self.path.exists():
            return False
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            salt = bytes.fromhex(str(payload["salt"]))
            expected = bytes.fromhex(str(payload["digest"]))
            iterations = int(payload.get("iterations", 300000))
            actual = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False

    def change(self, current: str, new_passphrase: str) -> bool:
        if not self.verify(current):
            return False
        self.configure(new_passphrase)
        return True

    def _validate(self, passphrase: str) -> None:
        if len(passphrase) < 8:
            raise ValueError("A chave local deve ter pelo menos 8 caracteres.")
        if len(passphrase) > 128:
            raise ValueError("A chave local deve ter no máximo 128 caracteres.")
