from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes

from shared.crypto_utils.keys import hkdf_expand, secure_random


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha256")


@dataclass(slots=True)
class MessageKeys:
    chain_key: bytes
    message_key: bytes


@dataclass(slots=True)
class RatchetState:
    root_key: bytes
    sending_chain_key: bytes
    receiving_chain_key: bytes
    send_count: int = 0
    recv_count: int = 0

    @classmethod
    def initialize(cls, dh_secret: bytes) -> "RatchetState":
        material = hkdf_expand(dh_secret, salt=secure_random(32), info=b"pymess-init", size=96)
        return cls(root_key=material[:32], sending_chain_key=material[32:64], receiving_chain_key=material[64:96])

    def next_sending_message_key(self) -> MessageKeys:
        next_chain = _hmac_sha256(self.sending_chain_key, b"chain")
        message_key = _hmac_sha256(self.sending_chain_key, b"message")
        self.sending_chain_key = next_chain
        self.send_count += 1
        return MessageKeys(chain_key=next_chain, message_key=message_key)

    def next_receiving_message_key(self) -> MessageKeys:
        next_chain = _hmac_sha256(self.receiving_chain_key, b"chain")
        message_key = _hmac_sha256(self.receiving_chain_key, b"message")
        self.receiving_chain_key = next_chain
        self.recv_count += 1
        return MessageKeys(chain_key=next_chain, message_key=message_key)

    def dh_ratchet_step(self, dh_output: bytes) -> None:
        material = hkdf_expand(dh_output, salt=self.root_key, info=b"pymess-dh-ratchet", size=96)
        self.root_key = material[:32]
        self.sending_chain_key = material[32:64]
        self.receiving_chain_key = material[64:96]
        self.send_count = 0
        self.recv_count = 0
