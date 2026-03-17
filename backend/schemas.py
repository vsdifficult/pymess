from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from shared.protocol.models import EncryptedEnvelope, KeyBundle


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    device_id: str = Field(min_length=8, max_length=128)
    key_bundle: KeyBundle


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class MessageIn(EncryptedEnvelope):
    pass


class MessageOut(BaseModel):
    msg_id: str
    sender_id: str
    nonce: str
    ciphertext: str
    aad: str | None
    ratchet_header: dict
    timestamp: datetime
