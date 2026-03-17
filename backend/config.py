from __future__ import annotations

from pydantic import BaseModel


class Settings(BaseModel):
    database_url: str = "sqlite+aiosqlite:///./pymess.db"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 14
    tls_min_version: str = "TLSv1_3"


settings = Settings()
