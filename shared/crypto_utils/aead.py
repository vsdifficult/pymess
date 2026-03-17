from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_aes256_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_aes256_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
