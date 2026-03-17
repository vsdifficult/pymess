# PyMess (Supabase Branch)

Эта ветка (`supabase-version`) переводит backend на Supabase (Postgres через PostgREST) для хранения **только зашифрованных данных и метаданных**.

## Архитектура (Supabase)

```text
Android (Kivy) / Windows (PyQt)
   |  E2EE envelope (AES-256-GCM + ratchet metadata)
   v
FastAPI Gateway
   - JWT/refresh
   - replay protection
   - rate limiting
   - routing only
   v
Supabase Postgres
   - users (public keys + device binding)
   - refresh_tokens
   - encrypted_messages (ciphertext blobs only)
```

## Переменные окружения

```bash
export PYMESS_USE_SUPABASE=true
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="<service-role-key>"
export PYMESS_JWT_SECRET="<strong-random-secret>"
```

Если `PYMESS_USE_SUPABASE=false`, backend запускается с in-memory storage (удобно для локальных тестов).

## SQL для Supabase

```sql
create table if not exists users (
  id bigint generated always as identity primary key,
  username text unique not null,
  password_hash text not null,
  device_id text not null,
  identity_key text not null,
  signed_prekey text not null,
  created_at timestamptz not null default now()
);

create table if not exists refresh_tokens (
  id bigint generated always as identity primary key,
  user_id bigint not null references users(id) on delete cascade,
  token text unique not null,
  expires_at timestamptz not null,
  revoked boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists encrypted_messages (
  id bigint generated always as identity primary key,
  msg_id text unique not null,
  sender_id bigint not null references users(id) on delete cascade,
  recipient_id bigint not null references users(id) on delete cascade,
  nonce text not null,
  ciphertext text not null,
  aad text,
  ratchet_header text not null,
  timestamp timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_users_username on users(username);
create index if not exists idx_messages_recipient on encrypted_messages(recipient_id);
```

## Запуск

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

## Безопасность

- Сервер не расшифровывает сообщения; хранит только encrypted envelope.
- Приватные ключи остаются на клиентах.
- Replay-защита: nonce + timestamp.
- JWT access + refresh rotation.
