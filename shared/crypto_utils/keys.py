from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


@dataclass(slots=True)
class IdentityKeyPair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        private_key = x25519.X25519PrivateKey.generate()
        return cls(private_key=private_key, public_key=private_key.public_key())

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


def derive_shared_secret(private_key: x25519.X25519PrivateKey, peer_public: bytes) -> bytes:
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
    return private_key.exchange(peer_public_key)


def hkdf_expand(secret: bytes, salt: bytes, info: bytes, size: int = 64) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=size, salt=salt, info=info).derive(secret)


def secure_random(size: int = 32) -> bytes:
    return os.urandom(size)
