from __future__ import annotations

import secrets
from datetime import datetime, timezone, timedelta

import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.models import RefreshToken, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "exp": now + timedelta(minutes=settings.access_token_minutes), "iat": now}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def create_refresh_token(user_id: int, db: AsyncSession) -> str:
    token = secrets.token_urlsafe(48)
    record = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
    )
    db.add(record)
    await db.commit()
    return token


async def rotate_refresh_token(token: str, db: AsyncSession) -> tuple[int, str] | None:
    result = await db.execute(select(RefreshToken).where(RefreshToken.token == token, RefreshToken.revoked.is_(False)))
    refresh = result.scalar_one_or_none()
    if not refresh or refresh.expires_at < datetime.now(timezone.utc):
        return None
    refresh.revoked = True
    new_token = await create_refresh_token(refresh.user_id, db)
    return refresh.user_id, new_token


def decode_access_token(token: str) -> int:
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    return int(payload["sub"])


async def get_user_by_username(username: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()
