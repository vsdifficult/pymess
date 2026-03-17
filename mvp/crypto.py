from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class KeyPair:
    private: x25519.X25519PrivateKey
    public: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        private = x25519.X25519PrivateKey.generate()
        return cls(private=private, public=private.public_key())

    def private_b64(self) -> str:
        raw = self.private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return _b64e(raw)

    def public_b64(self) -> str:
        raw = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64e(raw)

    @classmethod
    def from_private_b64(cls, private_b64: str) -> "KeyPair":
        private = x25519.X25519PrivateKey.from_private_bytes(_b64d(private_b64))
        return cls(private=private, public=private.public_key())


def derive_shared_key(my_private: x25519.X25519PrivateKey, peer_public_b64: str) -> bytes:
    peer = x25519.X25519PublicKey.from_public_bytes(_b64d(peer_public_b64))
    shared_secret = my_private.exchange(peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pymess-mvp").derive(shared_secret)


def encrypt_message(my_private: x25519.X25519PrivateKey, peer_public_b64: str, plaintext: str) -> str:
    key = derive_shared_key(my_private, peer_public_b64)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    envelope = {"n": _b64e(nonce), "c": _b64e(ciphertext)}
    return json.dumps(envelope, separators=(",", ":"))


def decrypt_message(my_private: x25519.X25519PrivateKey, peer_public_b64: str, envelope_json: str) -> str:
    envelope = json.loads(envelope_json)
    key = derive_shared_key(my_private, peer_public_b64)
    plaintext = AESGCM(key).decrypt(_b64d(envelope["n"]), _b64d(envelope["c"]), None)
    return plaintext.decode("utf-8")
