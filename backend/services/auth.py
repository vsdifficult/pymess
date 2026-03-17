from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from backend.config import settings
from backend.storage import Storage, UserRecord

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(user_id: int, device_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "device_id": device_id,
        "jti": secrets.token_urlsafe(12),
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "iat": now,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def create_refresh_token(user_id: int, store: Storage) -> str:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days)
    await store.create_refresh_token(user_id, token, expires_at)
    return token


async def rotate_refresh_token(token: str, store: Storage) -> tuple[UserRecord, str] | None:
    refresh = await store.get_refresh_token(token)
    if not refresh or refresh.revoked or refresh.expires_at < datetime.now(timezone.utc):
        return None
    user = await store.get_user_by_id(refresh.user_id)
    if not user:
        return None
    await store.revoke_refresh_token(token)
    new_token = await create_refresh_token(refresh.user_id, store)
    return user, new_token


def decode_access_token(token: str) -> tuple[int, str]:
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    return int(payload["sub"]), str(payload["device_id"])


async def get_user_by_username(username: str, store: Storage) -> UserRecord | None:
    return await store.get_user_by_username(username)
