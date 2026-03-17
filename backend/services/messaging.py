from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket

from backend.schemas import MessageIn, MessageOut
from backend.storage import Storage


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: dict[int, set[WebSocket]] = defaultdict(set)

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self.connections[user_id].add(ws)

    def disconnect(self, user_id: int, ws: WebSocket) -> None:
        self.connections[user_id].discard(ws)

    async def notify_user(self, user_id: int, payload: dict) -> None:
        for ws in list(self.connections[user_id]):
            await ws.send_json(payload)


async def store_message(message: MessageIn, sender_id: int, recipient_id: int, store: Storage) -> None:
    await store.store_message(message, sender_id=sender_id, recipient_id=recipient_id)


async def fetch_pending_messages(user_id: int, store: Storage, limit: int) -> list[MessageOut]:
    return await store.fetch_pending_messages(user_id, limit)
