from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from fastapi import HTTPException

from backend.config import settings
from backend.schemas import GroupMessageIn, MessageIn, MessageOut


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


@dataclass
class GroupRecord:
    group_id: str
    group_name: str
    owner_id: int


class Storage(Protocol):
    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord: ...

    async def get_user_by_username(self, username: str) -> UserRecord | None: ...

    async def get_user_by_id(self, user_id: int) -> UserRecord | None: ...

    async def create_refresh_token(self, user_id: int, token: str, expires_at: datetime) -> None: ...

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord | None: ...

    async def revoke_refresh_token(self, token: str) -> None: ...

    async def store_message(self, message: MessageIn, sender_id: int, recipient_id: int) -> None: ...

    async def fetch_pending_messages(self, user_id: int, limit: int) -> list[MessageOut]: ...

    async def add_contact(self, user_id: int, contact_id: int) -> None: ...

    async def remove_contact(self, user_id: int, contact_id: int) -> None: ...

    async def get_contacts(self, user_id: int) -> list[str]: ...

    async def create_group(self, owner_id: int, group_name: str, encrypted_group_key: str, member_ids: list[int]) -> GroupRecord: ...

    async def store_group_message(self, message: GroupMessageIn, sender_id: int) -> None: ...


class InMemoryStorage:
    def __init__(self) -> None:
        self._users: dict[int, UserRecord] = {}
        self._username_index: dict[str, int] = {}
        self._refresh: dict[str, RefreshTokenRecord] = {}
        self._messages: list[dict] = []
        self._contacts: dict[int, set[int]] = {}
        self._groups: dict[str, GroupRecord] = {}
        self._group_members: dict[str, set[int]] = {}
        self._next_id = 1

    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord:
        user = UserRecord(
            id=self._next_id,
            username=username,
            password_hash=password_hash,
            device_id=device_id,
            identity_key=identity_key,
            signed_prekey=signed_prekey,
        )
        self._users[self._next_id] = user
        self._username_index[username] = self._next_id
        self._next_id += 1
        return user

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        user_id = self._username_index.get(username)
        return self._users.get(user_id) if user_id else None

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

    async def fetch_pending_messages(self, user_id: int, limit: int) -> list[MessageOut]:
        pending = [m for m in self._messages if m["recipient_id"] == user_id][:limit]
        taken_ids = {m["msg_id"] for m in pending}
        self._messages = [m for m in self._messages if m["msg_id"] not in taken_ids]
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

    async def add_contact(self, user_id: int, contact_id: int) -> None:
        self._contacts.setdefault(user_id, set()).add(contact_id)
        self._contacts.setdefault(contact_id, set()).add(user_id)

    async def remove_contact(self, user_id: int, contact_id: int) -> None:
        self._contacts.setdefault(user_id, set()).discard(contact_id)
        self._contacts.setdefault(contact_id, set()).discard(user_id)

    async def get_contacts(self, user_id: int) -> list[str]:
        ids = self._contacts.get(user_id, set())
        return [self._users[uid].username for uid in ids if uid in self._users]

    async def create_group(self, owner_id: int, group_name: str, encrypted_group_key: str, member_ids: list[int]) -> GroupRecord:
        _ = encrypted_group_key
        group_id = f"g{len(self._groups) + 1:08d}"
        group = GroupRecord(group_id=group_id, group_name=group_name, owner_id=owner_id)
        self._groups[group_id] = group
        self._group_members[group_id] = set([owner_id, *member_ids])
        return group

    async def store_group_message(self, message: GroupMessageIn, sender_id: int) -> None:
        _ = sender_id
        _ = message


class SupabaseStorage:
    def __init__(self, supabase_url: str, service_role_key: str) -> None:
        from supabase import create_client

        self.client = create_client(supabase_url, service_role_key)

    async def _enforce_message_row_budget(self) -> None:
        budget = settings.max_db_rows_soft_limit
        try:
            count_row = self.client.table("encrypted_messages").select("id", count="exact", head=True).execute()
            count = int(getattr(count_row, "count", 0) or 0)
        except Exception:
            return

        if count > budget:
            overshoot = min(count - budget, 2000)
            old_rows = self.client.table("encrypted_messages").select("id").order("id").limit(overshoot).execute().data or []
            if old_rows:
                old_ids = [row["id"] for row in old_rows]
                self.client.table("encrypted_messages").delete().in_("id", old_ids).execute()

    async def create_user(self, username: str, password_hash: str, device_id: str, identity_key: str, signed_prekey: str) -> UserRecord:
        response = (
            self.client.table("users")
            .insert(
                {
                    "username": username,
                    "password_hash": password_hash,
                    "device_id": device_id,
                    "identity_key": identity_key,
                    "signed_prekey": signed_prekey,
                }
            )
            .execute()
        )
        return UserRecord(**response.data[0])

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
        await self._enforce_message_row_budget()
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

    async def fetch_pending_messages(self, user_id: int, limit: int) -> list[MessageOut]:
        rows = (
            self.client.table("encrypted_messages")
            .select("*")
            .eq("recipient_id", user_id)
            .order("id")
            .limit(limit)
            .execute()
            .data
            or []
        )

        outputs: list[MessageOut] = []
        sender_cache: dict[int, str] = {}
        for row in rows:
            sender_id = int(row["sender_id"])
            if sender_id not in sender_cache:
                sender = await self.get_user_by_id(sender_id)
                sender_cache[sender_id] = sender.username if sender else "unknown"

            outputs.append(
                MessageOut(
                    msg_id=row["msg_id"],
                    sender_id=sender_cache[sender_id],
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

    async def add_contact(self, user_id: int, contact_id: int) -> None:
        for left, right in ((user_id, contact_id), (contact_id, user_id)):
            self.client.table("contacts").upsert({"user_id": left, "contact_id": right}, on_conflict="user_id,contact_id").execute()

    async def remove_contact(self, user_id: int, contact_id: int) -> None:
        self.client.table("contacts").delete().eq("user_id", user_id).eq("contact_id", contact_id).execute()
        self.client.table("contacts").delete().eq("user_id", contact_id).eq("contact_id", user_id).execute()

    async def get_contacts(self, user_id: int) -> list[str]:
        response = self.client.table("contacts").select("contact_id").eq("user_id", user_id).execute()
        ids = [row["contact_id"] for row in (response.data or [])]
        if not ids:
            return []
        users = self.client.table("users").select("username").in_("id", ids).execute().data or []
        return [row["username"] for row in users]

    async def create_group(self, owner_id: int, group_name: str, encrypted_group_key: str, member_ids: list[int]) -> GroupRecord:
        payload = {"owner_id": owner_id, "group_name": group_name, "encrypted_group_key": encrypted_group_key}
        created = self.client.table("groups").insert(payload).execute().data[0]
        group_id = created["group_id"]
        member_payload = [{"group_id": group_id, "user_id": uid} for uid in set([owner_id, *member_ids])]
        self.client.table("group_members").insert(member_payload).execute()
        return GroupRecord(group_id=group_id, group_name=group_name, owner_id=owner_id)

    async def store_group_message(self, message: GroupMessageIn, sender_id: int) -> None:
        self.client.table("group_messages").insert(
            {
                "group_id": message.group_id,
                "sender_id": sender_id,
                "msg_id": message.msg_id,
                "nonce": message.nonce,
                "ciphertext": message.ciphertext,
                "aad": message.aad,
                "timestamp": message.timestamp.isoformat(),
            }
        ).execute()


def build_storage() -> Storage:
    if settings.use_supabase:
        if not settings.supabase_url or not settings.supabase_service_role_key:
            raise HTTPException(status_code=500, detail="Supabase is enabled but SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is missing")
        return SupabaseStorage(settings.supabase_url, settings.supabase_service_role_key)
    return InMemoryStorage()


storage: Storage = build_storage()
