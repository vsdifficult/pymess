from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class KeyBundle(BaseModel):
    identity_key: str
    signed_prekey: str
    one_time_prekey: str | None = None


class EncryptedEnvelope(BaseModel):
    sender_id: str
    recipient_id: str
    nonce: str
    ciphertext: str
    aad: str | None = None
    timestamp: datetime
    msg_id: str = Field(min_length=12)
    ratchet_header: dict[str, int | str]


class Ack(BaseModel):
    message: str
