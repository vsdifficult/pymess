from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect

from backend.config import settings
from backend.schemas import (
    ContactUpdateRequest,
    GroupCreateRequest,
    GroupMessageIn,
    LoginRequest,
    MessageIn,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
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
replay_protector = ReplayProtector(settings.replay_ttl_seconds)
rate_limiter = RateLimiter()
login_limiter = RateLimiter(max_requests=10, window_seconds=60)


def get_storage() -> Storage:
    return storage


def _bearer_token(auth_header: str | None) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return auth_header.split(" ", 1)[1]


async def current_user_context(
    authorization: str | None = Header(default=None),
    x_device_id: str | None = Header(default=None),
) -> tuple[int, str]:
    token = _bearer_token(authorization)
    try:
        user_id, token_device_id = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    if not x_device_id or x_device_id != token_device_id:
        raise HTTPException(status_code=403, detail="Device binding check failed")
    return user_id, token_device_id


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

    access_token = create_access_token(user.id, payload.device_id)
    refresh_token = await create_refresh_token(user.id, store)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, store: Storage = Depends(get_storage)) -> TokenResponse:
    if not login_limiter.allow(f"login:{payload.username}"):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    user = await get_user_by_username(payload.username, store)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.device_id != payload.device_id:
        raise HTTPException(status_code=403, detail="Device mismatch")

    access_token = create_access_token(user.id, payload.device_id)
    refresh_token = await create_refresh_token(user.id, store)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, store: Storage = Depends(get_storage)) -> TokenResponse:
    rotated = await rotate_refresh_token(payload.refresh_token, store)
    if not rotated:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user, refresh_token = rotated
    access_token = create_access_token(user.id, user.device_id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/users/{username}/prekey")
async def prekey_lookup(username: str, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    _ = context
    user = await get_user_by_username(username, store)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"identity_key": user.identity_key, "signed_prekey": user.signed_prekey}


@router.post("/contacts/add")
async def add_contact(payload: ContactUpdateRequest, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    user_id, _ = context
    contact = await get_user_by_username(payload.contact_username, store)
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    await store.add_contact(user_id, contact.id)
    return {"status": "ok"}


@router.post("/contacts/remove")
async def remove_contact(payload: ContactUpdateRequest, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    user_id, _ = context
    contact = await get_user_by_username(payload.contact_username, store)
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    await store.remove_contact(user_id, contact.id)
    return {"status": "ok"}


@router.get("/contacts")
async def list_contacts(context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    user_id, _ = context
    contacts = await store.get_contacts(user_id)
    return {"contacts": contacts}


@router.post("/groups")
async def create_group(payload: GroupCreateRequest, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    owner_id, _ = context
    members: list[int] = []
    for member in payload.members:
        user = await get_user_by_username(member, store)
        if user:
            members.append(user.id)
    group = await store.create_group(owner_id, payload.group_name, payload.encrypted_group_key, members)
    return {"group_id": group.group_id, "group_name": group.group_name}


@router.post("/groups/messages")
async def send_group_message(payload: GroupMessageIn, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    user_id, _ = context
    if not replay_protector.validate(payload.nonce, user_id, payload.timestamp):
        raise HTTPException(status_code=400, detail="Replay protection failed")
    await store.store_group_message(payload, sender_id=user_id)
    return {"status": "queued"}


@router.post("/messages")
async def send_message(payload: MessageIn, context: tuple[int, str] = Depends(current_user_context), store: Storage = Depends(get_storage)) -> dict:
    user_id, _ = context
    if len(payload.ciphertext) > settings.max_ciphertext_b64_len:
        raise HTTPException(status_code=413, detail="Ciphertext too large")
    if not rate_limiter.allow(f"msg:{user_id}"):
        raise HTTPException(status_code=429, detail="Too many messages")
    if not replay_protector.validate(payload.nonce, user_id, payload.timestamp):
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
async def pending_messages(
    context: tuple[int, str] = Depends(current_user_context),
    store: Storage = Depends(get_storage),
    limit: int = Query(default=settings.pending_batch_size, ge=1, le=500),
) -> list[dict]:
    user_id, _ = context
    messages = await fetch_pending_messages(user_id, store, limit)
    return [m.model_dump() for m in messages]


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str, device_id: str) -> None:
    try:
        user_id, token_device_id = decode_access_token(token)
        if device_id != token_device_id:
            await websocket.close(code=4403)
            return
    except Exception:
        await websocket.close(code=4401)
        return

    await manager.connect(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
