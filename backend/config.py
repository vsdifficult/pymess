from __future__ import annotations

import os
from pydantic import BaseModel


class Settings(BaseModel):
    jwt_secret: str = os.getenv("PYMESS_JWT_SECRET", "change-me-in-production")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = int(os.getenv("PYMESS_ACCESS_TOKEN_MINUTES", "15"))
    refresh_token_days: int = int(os.getenv("PYMESS_REFRESH_TOKEN_DAYS", "14"))
    tls_min_version: str = "TLSv1_3"

    use_supabase: bool = os.getenv("PYMESS_USE_SUPABASE", "true").lower() == "true"
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    pending_batch_size: int = int(os.getenv("PYMESS_PENDING_BATCH_SIZE", "100"))
    replay_ttl_seconds: int = int(os.getenv("PYMESS_REPLAY_TTL_SECONDS", "300"))
    gzip_min_size: int = int(os.getenv("PYMESS_GZIP_MIN_SIZE", "512"))
    max_ciphertext_b64_len: int = int(os.getenv("PYMESS_MAX_CIPHERTEXT_B64_LEN", "24576"))
    max_db_rows_soft_limit: int = int(os.getenv("PYMESS_MAX_DB_ROWS_SOFT_LIMIT", "450000"))

    push_firebase_token: str = os.getenv("PUSH_FIREBASE_TOKEN", "")
    push_onesignal_token: str = os.getenv("PUSH_ONESIGNAL_TOKEN", "")
    oauth_google_key: str = os.getenv("OAUTH_GOOGLE_KEY", "")
    oauth_apple_key: str = os.getenv("OAUTH_APPLE_KEY", "")
    analytics_token: str = os.getenv("ANALYTICS_TOKEN", "")


settings = Settings()
