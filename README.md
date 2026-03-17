# PyMess MVP (Supabase-only, minimal)

## 1) Architecture diagram

```text
Python CLI client
  - local X25519 keypair per user
  - AES-256-GCM encrypt/decrypt on client
  - no plaintext leaves client
        |
        v
Supabase only
  - Auth: email/password + JWT
  - Postgres: users, messages(ciphertext only)
  - Realtime: subscribe to messages inserts
```

No custom backend server is used.

## 2) Minimal files

- `mvp/client.py` — full client (register/login/find/send/inbox/realtime)
- `mvp/crypto.py` — crypto module (X25519 + HKDF + AES-256-GCM)
- `supabase_mvp.sql` — minimal SQL schema + RLS policies
- `mvp/README.md` — quickstart

## 3) Config

```bash
export SUPABASE_URL="your_url_here"
export SUPABASE_KEY="your_anon_key_here"
```

## 4) Quick start

```bash
pip install supabase cryptography
python -m mvp.client register --email alice@mail.com --password 'StrongPass123!' --username alice
python -m mvp.client register --email bob@mail.com --password 'StrongPass123!' --username bob
python -m mvp.client send --email alice@mail.com --password 'StrongPass123!' --to bob --text 'hello'
python -m mvp.client inbox --email bob@mail.com --password 'StrongPass123!'
```

## 5) Security

- AES-256-GCM encrypts every message before insert.
- Shared key derived from X25519 Diffie-Hellman + HKDF.
- Supabase stores only ciphertext envelope in `messages.ciphertext`.
- Private keys stay local in `~/.pymess_mvp_keys.json`.

## 6) Scope intentionally excluded

- No group chats
- No file uploads
- No push notifications
- No analytics
- No extra backend service
