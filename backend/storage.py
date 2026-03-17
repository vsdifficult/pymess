from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from fastapi import HTTPException

from backend.config import settings
from backend.schemas import MessageIn, MessageOut


@dataclass
class UserRecord:
    id: int
    username: str
    password_hash: str
    device_id: str
    identity_key: str
    signed_prekey: str


@dataclass
class RefreshTokenRecord:
    user_id: int
    token: str
    expires_at: datetime
    revoked: bool


class Storage(Protocol):
    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord: ...

    async def get_user_by_username(self, username: str) -> UserRecord | None: ...

    async def get_user_by_id(self, user_id: int) -> UserRecord | None: ...

    async def create_refresh_token(self, user_id: int, token: str, expires_at: datetime) -> None: ...

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord | None: ...

    async def revoke_refresh_token(self, token: str) -> None: ...

    async def store_message(self, message: MessageIn, sender_id: int, recipient_id: int) -> None: ...

    async def fetch_pending_messages(self, user_id: int) -> list[MessageOut]: ...


class InMemoryStorage:
    def __init__(self) -> None:
        self._users: dict[int, UserRecord] = {}
        self._users_by_name: dict[str, int] = {}
        self._refresh: dict[str, RefreshTokenRecord] = {}
        self._messages: list[dict] = []
        self._next_user = 1

    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord:
        user = UserRecord(
            id=self._next_user,
            username=username,
            password_hash=password_hash,
            device_id=device_id,
            identity_key=identity_key,
            signed_prekey=signed_prekey,
        )
        self._next_user += 1
        self._users[user.id] = user
        self._users_by_name[username] = user.id
        return user

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        uid = self._users_by_name.get(username)
        return self._users.get(uid) if uid else None

    async def get_user_by_id(self, user_id: int) -> UserRecord | None:
        return self._users.get(user_id)

    async def create_refresh_token(self, user_id: int, token: str, expires_at: datetime) -> None:
        self._refresh[token] = RefreshTokenRecord(user_id=user_id, token=token, expires_at=expires_at, revoked=False)

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord | None:
        return self._refresh.get(token)

    async def revoke_refresh_token(self, token: str) -> None:
        if token in self._refresh:
            self._refresh[token].revoked = True

    async def store_message(self, message: MessageIn, sender_id: int, recipient_id: int) -> None:
        self._messages.append(
            {
                "msg_id": message.msg_id,
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "nonce": message.nonce,
                "ciphertext": message.ciphertext,
                "aad": message.aad,
                "ratchet_header": message.ratchet_header,
                "timestamp": message.timestamp,
            }
        )

    async def fetch_pending_messages(self, user_id: int) -> list[MessageOut]:
        pending = [m for m in self._messages if m["recipient_id"] == user_id]
        self._messages = [m for m in self._messages if m["recipient_id"] != user_id]
        outputs: list[MessageOut] = []
        for m in pending:
            sender = self._users[m["sender_id"]]
            outputs.append(
                MessageOut(
                    msg_id=m["msg_id"],
                    sender_id=sender.username,
                    nonce=m["nonce"],
                    ciphertext=m["ciphertext"],
                    aad=m["aad"],
                    ratchet_header=m["ratchet_header"],
                    timestamp=m["timestamp"],
                )
            )
        return outputs


class SupabaseStorage:
    def __init__(self, supabase_url: str, service_role_key: str) -> None:
        from supabase import create_client

        self.client = create_client(supabase_url, service_role_key)

    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord:
        payload = {
            "username": username,
            "password_hash": password_hash,
            "device_id": device_id,
            "identity_key": identity_key,
            "signed_prekey": signed_prekey,
        }
        response = self.client.table("users").insert(payload).execute()
        row = response.data[0]
        return UserRecord(**row)

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        response = self.client.table("users").select("*").eq("username", username).limit(1).execute()
        if not response.data:
            return None
        return UserRecord(**response.data[0])

    async def get_user_by_id(self, user_id: int) -> UserRecord | None:
        response = self.client.table("users").select("*").eq("id", user_id).limit(1).execute()
        if not response.data:
            return None
        return UserRecord(**response.data[0])

    async def create_refresh_token(self, user_id: int, token: str, expires_at: datetime) -> None:
        self.client.table("refresh_tokens").insert(
            {"user_id": user_id, "token": token, "expires_at": expires_at.isoformat(), "revoked": False}
        ).execute()

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord | None:
        response = self.client.table("refresh_tokens").select("*").eq("token", token).limit(1).execute()
        if not response.data:
            return None
        row = response.data[0]
        return RefreshTokenRecord(
            user_id=row["user_id"],
            token=row["token"],
            revoked=row["revoked"],
            expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")),
        )

    async def revoke_refresh_token(self, token: str) -> None:
        self.client.table("refresh_tokens").update({"revoked": True}).eq("token", token).execute()

    async def store_message(self, message: MessageIn, sender_id: int, recipient_id: int) -> None:
        self.client.table("encrypted_messages").insert(
            {
                "msg_id": message.msg_id,
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "nonce": message.nonce,
                "ciphertext": message.ciphertext,
                "aad": message.aad,
                "ratchet_header": json.dumps(message.ratchet_header),
                "timestamp": message.timestamp.isoformat(),
            }
        ).execute()

    async def fetch_pending_messages(self, user_id: int) -> list[MessageOut]:
        messages_response = self.client.table("encrypted_messages").select("*").eq("recipient_id", user_id).execute()
        rows = messages_response.data or []
        outputs: list[MessageOut] = []
        for row in rows:
            sender = await self.get_user_by_id(row["sender_id"])
            if not sender:
                continue
            outputs.append(
                MessageOut(
                    msg_id=row["msg_id"],
                    sender_id=sender.username,
                    nonce=row["nonce"],
                    ciphertext=row["ciphertext"],
                    aad=row.get("aad"),
                    ratchet_header=json.loads(row["ratchet_header"]),
                    timestamp=datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")),
                )
            )

        if rows:
            ids = [row["id"] for row in rows]
            self.client.table("encrypted_messages").delete().in_("id", ids).execute()
        return outputs


def build_storage() -> Storage:
    if settings.use_supabase:
        if not settings.supabase_url or not settings.supabase_service_role_key:
            raise HTTPException(status_code=500, detail="Supabase is enabled but SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is missing")
        return SupabaseStorage(settings.supabase_url, settings.supabase_service_role_key)
    return InMemoryStorage()


storage: Storage = build_storage()
