from __future__ import annotations

import hashlib
import ssl


def verify_certificate_fingerprint(cert_der: bytes, expected_sha256_hex: str) -> bool:
    digest = hashlib.sha256(cert_der).hexdigest()
    return digest.lower() == expected_sha256_hex.lower()


def tls13_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx
