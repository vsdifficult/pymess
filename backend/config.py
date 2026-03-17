from __future__ import annotations

import os
from pydantic import BaseModel


class Settings(BaseModel):
    jwt_secret: str = os.getenv("PYMESS_JWT_SECRET", "change-me-in-production")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = int(os.getenv("PYMESS_ACCESS_TOKEN_MINUTES", "15"))
    refresh_token_days: int = int(os.getenv("PYMESS_REFRESH_TOKEN_DAYS", "14"))
    tls_min_version: str = "TLSv1_3"

    use_supabase: bool = os.getenv("PYMESS_USE_SUPABASE", "false").lower() == "true"
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")


settings = Settings()
