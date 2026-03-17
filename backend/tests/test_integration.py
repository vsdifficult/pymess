from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app


def test_healthz() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_replay_protection_rejects_duplicate_nonce() -> None:
    client = TestClient(app)

    user_payload = {
        "username": "alice",
        "password": "averysecurepassword",
        "device_id": "android-device-1",
        "key_bundle": {"identity_key": "a2V5", "signed_prekey": "cHJla2V5"},
    }
    client.post("/api/auth/register", json=user_payload)

    user_payload["username"] = "bob"
    user_payload["device_id"] = "android-device-2"
    client.post("/api/auth/register", json=user_payload)

    login = client.post("/api/auth/login", json={"username": "alice", "password": "averysecurepassword", "device_id": "android-device-1"})
    token = login.json()["access_token"]

    message = {
        "sender_id": "alice",
        "recipient_id": "bob",
        "nonce": "bm9uY2UxMjM=",
        "ciphertext": "YmxvYg==",
        "aad": "YWFk",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "msg_id": "abc123abc123",
        "ratchet_header": {"n": 1},
    }

    first = client.post("/api/messages", json=message, headers={"Authorization": f"Bearer {token}", "X-Device-ID": "android-device-1"})
    second = client.post("/api/messages", json={**message, "msg_id": "abc123abc124"}, headers={"Authorization": f"Bearer {token}", "X-Device-ID": "android-device-1"})

    assert first.status_code == 200
    assert second.status_code == 400
