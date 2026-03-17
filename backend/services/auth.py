from __future__ import annotations

import secrets
from datetime import datetime, timezone, timedelta

import jwt
from passlib.context import CryptContext

from backend.config import settings
from backend.storage import Storage, UserRecord

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "exp": now + timedelta(minutes=settings.access_token_minutes), "iat": now}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def create_refresh_token(user_id: int, store: Storage) -> str:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days)
    await store.create_refresh_token(user_id, token, expires_at)
    return token


async def rotate_refresh_token(token: str, store: Storage) -> tuple[int, str] | None:
    refresh = await store.get_refresh_token(token)
    if not refresh or refresh.revoked or refresh.expires_at < datetime.now(timezone.utc):
        return None
    await store.revoke_refresh_token(token)
    new_token = await create_refresh_token(refresh.user_id, store)
    return refresh.user_id, new_token


def decode_access_token(token: str) -> int:
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    return int(payload["sub"])


async def get_user_by_username(username: str, store: Storage) -> UserRecord | None:
    return await store.get_user_by_username(username)
