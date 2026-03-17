from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    device_id: Mapped[str] = mapped_column(String(128))
    identity_key: Mapped[str] = mapped_column(Text)
    signed_prekey: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token: Mapped[str] = mapped_column(String(256), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class EncryptedMessage(Base):
    __tablename__ = "encrypted_messages"
    __table_args__ = (UniqueConstraint("msg_id", name="uq_msg_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    msg_id: Mapped[str] = mapped_column(String(128), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    nonce: Mapped[str] = mapped_column(Text)
    ciphertext: Mapped[str] = mapped_column(Text)
    aad: Mapped[str | None] = mapped_column(Text, nullable=True)
    ratchet_header: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
