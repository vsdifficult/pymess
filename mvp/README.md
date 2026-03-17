# Minimal Supabase-only encrypted messenger (MVP)

## Env
```bash
export SUPABASE_URL="your_url_here"
export SUPABASE_KEY="your_anon_key_here"
```

## Install
```bash
pip install supabase cryptography
```

## Setup Supabase
1. Create project in Supabase.
2. Enable Email/Password auth.
3. Run SQL from `supabase_mvp.sql`.
4. Enable Realtime for `public.messages` table.

## Usage
```bash
python -m mvp.client register --email alice@mail.com --password 'StrongPass123!' --username alice
python -m mvp.client register --email bob@mail.com --password 'StrongPass123!' --username bob

python -m mvp.client find --username bob
python -m mvp.client send --email alice@mail.com --password 'StrongPass123!' --to bob --text 'hello'
python -m mvp.client inbox --email bob@mail.com --password 'StrongPass123!'
```

Realtime listener:
```bash
python -m mvp.client realtime --email bob@mail.com --password 'StrongPass123!'
```

## Notes
- E2EE: AES-256-GCM, key from X25519 Diffie-Hellman + HKDF.
- Supabase stores only `ciphertext` envelope JSON.
- Private keys are local in `~/.pymess_mvp_keys.json` and never sent to server.
