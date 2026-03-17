from __future__ import annotations

import json
from collections import defaultdict

from fastapi import WebSocket
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import EncryptedMessage, User
from backend.schemas import MessageIn, MessageOut


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


async def store_message(message: MessageIn, sender_id: int, recipient_id: int, db: AsyncSession) -> None:
    db_record = EncryptedMessage(
        msg_id=message.msg_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        nonce=message.nonce,
        ciphertext=message.ciphertext,
        aad=message.aad,
        ratchet_header=json.dumps(message.ratchet_header),
        timestamp=message.timestamp,
    )
    db.add(db_record)
    await db.commit()


async def fetch_pending_messages(user_id: int, db: AsyncSession) -> list[MessageOut]:
    result = await db.execute(select(EncryptedMessage, User.username).join(User, EncryptedMessage.sender_id == User.id).where(EncryptedMessage.recipient_id == user_id))
    rows = result.all()
    outputs = [
        MessageOut(
            msg_id=row.EncryptedMessage.msg_id,
            sender_id=row.username,
            nonce=row.EncryptedMessage.nonce,
            ciphertext=row.EncryptedMessage.ciphertext,
            aad=row.EncryptedMessage.aad,
            ratchet_header=json.loads(row.EncryptedMessage.ratchet_header),
            timestamp=row.EncryptedMessage.timestamp,
        )
        for row in rows
    ]
    for row in rows:
        await db.delete(row.EncryptedMessage)
    await db.commit()
    return outputs
