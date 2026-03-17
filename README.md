# PyMess: Cross-Platform Secure Messaging (Android + Windows)

## 1) Architecture diagram (text)

```text
+-------------------------+                  +-------------------------------------+
| Android Client (Kivy)   |                  | Windows Client (PyQt6)              |
| - local key generation  |                  | - local key generation              |
| - Double Ratchet state  |                  | - Double Ratchet state              |
| - AES-256-GCM encrypt   |                  | - AES-256-GCM encrypt               |
+------------+------------+                  +----------------+--------------------+
             | TLS 1.3 + cert pinning                         |
             +-----------------------------+------------------+
                                           |
                                  +--------v---------+
                                  | FastAPI Gateway  |
                                  | JWT auth         |
                                  | Rate limiting    |
                                  | Replay checks    |
                                  +--------+---------+
                                           |
                   +-----------------------+------------------------+
                   |                                                |
            +------v------+                                  +------v------+
            | PostgreSQL  |                                  | Redis       |
            | user/meta   |                                  | sessions,   |
            | encrypted   |                                  | queue/pres. |
            | envelopes   |                                  +-------------+
            +-------------+

Zero-knowledge server: only encrypted envelopes and metadata are stored.
```

## 2) Full backend code (FastAPI)

Implemented under `backend/`:
- `backend/main.py`: app startup and health endpoint.
- `backend/api/routes.py`: registration, login, refresh, prekey lookup, send/pending messages, WebSocket.
- `backend/services/*`: auth, message routing, replay protection, rate limiting.
- `backend/models.py`: users, refresh tokens, encrypted message storage.

## 3) Client code (Android + Windows)

- `client_android/main.py`: Kivy app with secure session creation and client-side encryption before send.
- `client_windows/main.py`: PyQt6 desktop client with same encrypted envelope flow.

> Production note: replace placeholder secure stores with Android Keystore (`pyjnius`) and Windows DPAPI (`win32crypt`).

## 4) Crypto module implementation

Shared crypto is implemented in `shared/`:
- `shared/crypto_utils/keys.py`: X25519 key generation + DH + HKDF.
- `shared/crypto_utils/aead.py`: AES-256-GCM wrappers.
- `shared/crypto_utils/ratchet.py`: simplified Double Ratchet chain/root handling.
- `shared/protocol/client_session.py`: per-message key derivation and encrypted envelope formatting.

Each message:
1. derives a fresh message key from ratchet chain key,
2. encrypts with AES-256-GCM,
3. attaches ratchet header and timestamp/nonce.

## 5) Setup instructions

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
uvicorn backend.main:app --host 0.0.0.0 --port 8000
pytest backend/tests -q
```

Mobile/desktop apps import shared crypto modules and call backend API over TLS.

## 6) Security explanation

### Threat model
- **MITM:** mitigated via TLS 1.3 and certificate pinning hooks (`backend/crypto/tls_pinning.py`).
- **Replay attacks:** mitigated with nonce + timestamp checks (`ReplayProtector`).
- **Key leakage (server-side):** server never receives private keys; private keys generated and retained on-device.
- **Credential theft impact:** short-lived JWT access tokens + refresh rotation.

### Why crypto choices are secure
- **X25519 Diffie-Hellman:** modern, widely reviewed ECDH primitive.
- **HKDF-SHA256:** secure key separation/derivation from shared secrets.
- **AES-256-GCM:** AEAD gives confidentiality + integrity/authentication.
- **Double Ratchet-style chain:** forward secrecy by evolving message keys and never reusing them.

### Limitations
- Simplified Double Ratchet (no skipped-key storage or full asynchronous header key logic).
- Group chat key management is not fully implemented yet (current code is 1-to-1 foundation).
- Secure storage classes in clients are placeholders requiring platform-specific bindings.
- Redis/PostgreSQL integrations are interface-ready; local SQLite is used by default for quick start.

## Bonus placeholders
- `shared/protocol/client_session.py` can be extended to hybrid P2P transport abstraction.
- Post-quantum placeholder can be added via Kyber KEM wrapper alongside X25519 during handshake.
- TOR/onion routing can be layered through SOCKS5 proxy configuration in HTTP/WebSocket clients.
