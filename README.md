# PyMess — production-focused Supabase secure messenger

## 1) Architecture diagram (text)

```text
Android (Kivy) / Windows (PyQt)
  - Device-generated X25519 keys
  - Double Ratchet state per session
  - AES-256-GCM envelope encryption
  - Optional compression before encryption
            |
            | TLS + JWT + X-Device-ID
            v
FastAPI gateway (zero-knowledge routing)
  - Auth/session checks
  - Replay protection + rate limiting
  - Contact/group metadata routing
  - Offline sync API
            |
            v
Supabase (free-tier aware)
  - Auth (email/password, JWT)
  - Postgres: users, contacts, ciphertext envelopes
  - Realtime on encrypted_messages/group_messages
  - Storage bucket for encrypted files only
```

## 2) What is implemented

- Client-side E2EE primitives (X25519 + AES-256-GCM + simplified Double Ratchet).
- Supabase-backed storage for encrypted messages and metadata.
- Contact add/remove/list, encrypted 1:1 and encrypted group message APIs.
- Offline message sync with pending batch retrieval.
- Replay protection, device-bound JWT, rate limiting, security headers.
- Integration token placeholders for push/OAuth/analytics.
- Free-tier aware retention strategy and row-budget guards.

## 3) Supabase setup scripts

- `backend_supabase/migrations/001_init.sql`
- `backend_supabase/migrations/002_retention.sql`
- `backend_supabase/functions/realtime-notify.sql`

Enable Realtime for `encrypted_messages`, `group_messages`.
Create storage bucket `encrypted-files` (store encrypted blobs only).

## 4) Environment variables

```bash
# Core
export PYMESS_USE_SUPABASE=true
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="<service-role-key>"
export PYMESS_JWT_SECRET="<strong-random-secret>"

# Security and traffic
export PYMESS_REPLAY_TTL_SECONDS=300
export PYMESS_PENDING_BATCH_SIZE=100
export PYMESS_GZIP_MIN_SIZE=512
export PYMESS_MAX_CIPHERTEXT_B64_LEN=24576

# Free tier control
export PYMESS_MAX_DB_ROWS_SOFT_LIMIT=450000

# Integrations placeholders
export PUSH_FIREBASE_TOKEN=""
export PUSH_ONESIGNAL_TOKEN=""
export OAUTH_GOOGLE_KEY=""
export OAUTH_APPLE_KEY=""
export ANALYTICS_TOKEN=""
```

## 5) Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

## 6) Optional Docker

```bash
docker build -t pymess .
docker run --env-file .env -p 8000:8000 pymess
```

## 7) Threat model (summary)

- MITM: mitigated by TLS + authenticated key lookup flow.
- Replay: nonce + timestamp window checks.
- Server breach: attacker sees ciphertext + metadata only.
- Device compromise: handled operationally via keystore/DPAPI and token revocation.

## 8) Limitations

- Ratchet implementation is simplified; production should use a fully audited protocol implementation.
- Android Keystore and Windows DPAPI are placeholders in UI clients.
- Supabase Auth integration is expected to be configured in project dashboard for email/password and optional OAuth.
