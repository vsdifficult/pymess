from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, WebSocket, WebSocketDisconnect

from backend.schemas import LoginRequest, MessageIn, RefreshRequest, RegisterRequest, TokenResponse
from backend.services.auth import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    get_user_by_username,
    hash_password,
    rotate_refresh_token,
    verify_password,
)
from backend.services.messaging import ConnectionManager, fetch_pending_messages, store_message
from backend.services.security import RateLimiter, ReplayProtector
from backend.storage import Storage, storage

router = APIRouter()
manager = ConnectionManager()
replay_protector = ReplayProtector()
rate_limiter = RateLimiter()


def get_storage() -> Storage:
    return storage


def _bearer_token(auth_header: str | None) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return auth_header.split(" ", 1)[1]


async def current_user_id(authorization: str | None = Header(default=None)) -> int:
    token = _bearer_token(authorization)
    try:
        return decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@router.post("/auth/register", response_model=TokenResponse)
async def register(payload: RegisterRequest, store: Storage = Depends(get_storage)) -> TokenResponse:
    if not rate_limiter.allow(f"register:{payload.device_id}"):
        raise HTTPException(status_code=429, detail="Too many requests")
    if await get_user_by_username(payload.username, store):
        raise HTTPException(status_code=409, detail="Username already exists")

    user = await store.create_user(
        username=payload.username,
        password_hash=hash_password(payload.password),
        device_id=payload.device_id,
        identity_key=payload.key_bundle.identity_key,
        signed_prekey=payload.key_bundle.signed_prekey,
    )

    access_token = create_access_token(user.id)
    refresh_token = await create_refresh_token(user.id, store)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, store: Storage = Depends(get_storage)) -> TokenResponse:
    user = await get_user_by_username(payload.username, store)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.device_id != payload.device_id:
        raise HTTPException(status_code=403, detail="Device mismatch")

    access_token = create_access_token(user.id)
    refresh_token = await create_refresh_token(user.id, store)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, store: Storage = Depends(get_storage)) -> TokenResponse:
    rotated = await rotate_refresh_token(payload.refresh_token, store)
    if not rotated:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user_id, refresh_token = rotated
    access_token = create_access_token(user_id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/users/{username}/prekey")
async def prekey_lookup(username: str, user_id: int = Depends(current_user_id), store: Storage = Depends(get_storage)) -> dict:
    _ = user_id
    user = await get_user_by_username(username, store)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"identity_key": user.identity_key, "signed_prekey": user.signed_prekey}


@router.post("/messages")
async def send_message(payload: MessageIn, user_id: int = Depends(current_user_id), store: Storage = Depends(get_storage)) -> dict:
    if not rate_limiter.allow(f"msg:{user_id}"):
        raise HTTPException(status_code=429, detail="Too many messages")
    if not replay_protector.validate(payload.nonce, payload.timestamp):
        raise HTTPException(status_code=400, detail="Replay protection failed")

    recipient = await get_user_by_username(payload.recipient_id, store)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    await store_message(payload, sender_id=user_id, recipient_id=recipient.id, store=store)
    await manager.notify_user(
        recipient.id,
        {"event": "new_message", "msg_id": payload.msg_id, "timestamp": datetime.now(timezone.utc).isoformat()},
    )
    return {"status": "queued"}


@router.get("/messages/pending")
async def pending_messages(user_id: int = Depends(current_user_id), store: Storage = Depends(get_storage)) -> list[dict]:
    messages = await fetch_pending_messages(user_id, store)
    return [m.model_dump() for m in messages]


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str) -> None:
    try:
        user_id = decode_access_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await manager.connect(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
