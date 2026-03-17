from __future__ import annotations

import zlib
from datetime import datetime, timezone
from uuid import uuid4

from shared.crypto_utils.aead import decrypt_aes256_gcm, encrypt_aes256_gcm
from shared.crypto_utils.keys import IdentityKeyPair, b64d, b64e, derive_shared_secret, secure_random
from shared.crypto_utils.ratchet import RatchetState


class SecureSession:
    def __init__(self, my_identity: IdentityKeyPair, peer_public_b64: str, initiator: bool = True) -> None:
        self.my_identity = my_identity
        peer_pub = b64d(peer_public_b64)
        secret = derive_shared_secret(my_identity.private_key, peer_pub)
        self.ratchet = RatchetState.initialize(secret)
        self.initiator = initiator

    def _pack_plaintext(self, plaintext: str) -> tuple[bytes, bool]:
        source = plaintext.encode()
        compressed = zlib.compress(source, level=6)
        if len(compressed) + 8 < len(source):
            return compressed, True
        return source, False

    def encrypt_for_transport(self, sender: str, recipient: str, plaintext: str) -> dict:
        keys = self.ratchet.next_sending_message_key()
        nonce = secure_random(12)
        aad = f"{sender}:{recipient}".encode()
        packed, is_compressed = self._pack_plaintext(plaintext)
        ciphertext = encrypt_aes256_gcm(keys.message_key[:32], nonce, packed, aad)
        return {
            "sender_id": sender,
            "recipient_id": recipient,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "aad": b64e(aad),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "msg_id": uuid4().hex,
            "ratchet_header": {"n": self.ratchet.send_count, "init": self.initiator, "zip": is_compressed},
        }

    def decrypt_from_transport(self, envelope: dict) -> str:
        keys = self.ratchet.next_receiving_message_key()
        packed = decrypt_aes256_gcm(
            keys.message_key[:32],
            b64d(envelope["nonce"]),
            b64d(envelope["ciphertext"]),
            b64d(envelope["aad"]) if envelope.get("aad") else None,
        )
        if envelope.get("ratchet_header", {}).get("zip"):
            packed = zlib.decompress(packed)
        return packed.decode()
