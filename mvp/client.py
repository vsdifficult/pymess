from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from supabase import Client, create_client

from mvp.crypto import KeyPair, decrypt_message, encrypt_message

KEY_FILE = Path.home() / ".pymess_mvp_keys.json"


def get_supabase() -> Client:
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    if not url or not key:
        raise RuntimeError("Set SUPABASE_URL and SUPABASE_KEY")
    return create_client(url, key)


def _load_local_keys() -> dict[str, str]:
    if KEY_FILE.exists():
        return json.loads(KEY_FILE.read_text())
    return {}


def _save_local_keys(data: dict[str, str]) -> None:
    KEY_FILE.write_text(json.dumps(data))


def _ensure_keypair(user_id: str) -> KeyPair:
    store = _load_local_keys()
    if user_id in store:
        return KeyPair.from_private_b64(store[user_id])
    kp = KeyPair.generate()
    store[user_id] = kp.private_b64()
    _save_local_keys(store)
    return kp


def register(email: str, password: str, username: str) -> None:
    sb = get_supabase()
    auth = sb.auth.sign_up({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Sign-up failed")
    kp = _ensure_keypair(auth.user.id)
    sb.table("users").upsert({"id": auth.user.id, "username": username, "public_key": kp.public_b64()}, on_conflict="id").execute()
    print(f"registered: {auth.user.id}")


def login(email: str, password: str) -> str:
    sb = get_supabase()
    auth = sb.auth.sign_in_with_password({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Login failed")
    _ensure_keypair(auth.user.id)
    print(f"logged in: {auth.user.id}")
    return auth.user.id


def find_user(username: str) -> dict[str, Any]:
    sb = get_supabase()
    row = sb.table("users").select("id,username,public_key").eq("username", username).limit(1).execute().data
    if not row:
        raise RuntimeError("User not found")
    return row[0]


def send(email: str, password: str, to_username: str, text: str) -> None:
    sb = get_supabase()
    auth = sb.auth.sign_in_with_password({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Login failed")

    me = sb.table("users").select("id,public_key").eq("id", auth.user.id).limit(1).execute().data[0]
    peer = find_user(to_username)
    kp = _ensure_keypair(auth.user.id)
    ciphertext = encrypt_message(kp.private, peer["public_key"], text)
    sb.table("messages").insert({"sender_id": me["id"], "receiver_id": peer["id"], "ciphertext": ciphertext}).execute()
    print("sent")



def send_by_id(email: str, password: str, receiver_id: str, text: str) -> None:
    sb = get_supabase()
    auth = sb.auth.sign_in_with_password({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Login failed")

    me = sb.table("users").select("id").eq("id", auth.user.id).limit(1).execute().data[0]
    peer_rows = sb.table("users").select("id,public_key").eq("id", receiver_id).limit(1).execute().data
    if not peer_rows:
        raise RuntimeError("Receiver not found")
    peer = peer_rows[0]
    kp = _ensure_keypair(auth.user.id)
    ciphertext = encrypt_message(kp.private, peer["public_key"], text)
    sb.table("messages").insert({"sender_id": me["id"], "receiver_id": peer["id"], "ciphertext": ciphertext}).execute()
    print("sent")

def inbox(email: str, password: str) -> None:
    sb = get_supabase()
    auth = sb.auth.sign_in_with_password({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Login failed")

    me = sb.table("users").select("id").eq("id", auth.user.id).limit(1).execute().data[0]
    kp = _ensure_keypair(auth.user.id)
    rows = (
        sb.table("messages")
        .select("id,sender_id,ciphertext,created_at")
        .eq("receiver_id", me["id"])
        .order("id")
        .limit(100)
        .execute()
        .data
        or []
    )
    if not rows:
        print("inbox empty")
        return

    sender_ids = list({row["sender_id"] for row in rows})
    users = sb.table("users").select("id,username,public_key").in_("id", sender_ids).execute().data or []
    user_map = {u["id"]: u for u in users}

    for row in rows:
        sender = user_map.get(row["sender_id"])
        if not sender:
            continue
        plaintext = decrypt_message(kp.private, sender["public_key"], row["ciphertext"])
        print(f"[{row['created_at']}] {sender['username']}: {plaintext}")


def realtime(email: str, password: str) -> None:
    sb = get_supabase()
    auth = sb.auth.sign_in_with_password({"email": email, "password": password})
    if not auth.user:
        raise RuntimeError("Login failed")

    kp = _ensure_keypair(auth.user.id)

    users = sb.table("users").select("id,username,public_key").execute().data or []
    user_map = {u["id"]: u for u in users}

    def _on_insert(payload: dict[str, Any]) -> None:
        row = payload.get("new", {})
        if row.get("receiver_id") != auth.user.id:
            return
        sender = user_map.get(row.get("sender_id"))
        if not sender:
            return
        plaintext = decrypt_message(kp.private, sender["public_key"], row["ciphertext"])
        print(f"\n{sender['username']}: {plaintext}")

    channel = sb.channel("messages-live")
    channel.on_postgres_changes(
        event="INSERT",
        schema="public",
        table="messages",
        callback=_on_insert,
    )
    channel.subscribe()
    print("Realtime listening... Ctrl+C to exit")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        channel.unsubscribe()


def main() -> None:
    parser = argparse.ArgumentParser(description="PyMess MVP (Supabase-only)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("register")
    r.add_argument("--email", required=True)
    r.add_argument("--password", required=True)
    r.add_argument("--username", required=True)

    l = sub.add_parser("login")
    l.add_argument("--email", required=True)
    l.add_argument("--password", required=True)

    f = sub.add_parser("find")
    f.add_argument("--username", required=True)

    s = sub.add_parser("send")
    s.add_argument("--email", required=True)
    s.add_argument("--password", required=True)
    s.add_argument("--to", required=True)
    s.add_argument("--text", required=True)

    sid = sub.add_parser("send-id")
    sid.add_argument("--email", required=True)
    sid.add_argument("--password", required=True)
    sid.add_argument("--id", required=True)
    sid.add_argument("--text", required=True)

    i = sub.add_parser("inbox")
    i.add_argument("--email", required=True)
    i.add_argument("--password", required=True)

    rt = sub.add_parser("realtime")
    rt.add_argument("--email", required=True)
    rt.add_argument("--password", required=True)

    args = parser.parse_args()
    if args.cmd == "register":
        register(args.email, args.password, args.username)
    elif args.cmd == "login":
        login(args.email, args.password)
    elif args.cmd == "find":
        user = find_user(args.username)
        print(f"{user['username']} => {user['id']}")
    elif args.cmd == "send":
        send(args.email, args.password, args.to, args.text)
    elif args.cmd == "send-id":
        send_by_id(args.email, args.password, args.id, args.text)
    elif args.cmd == "inbox":
        inbox(args.email, args.password)
    elif args.cmd == "realtime":
        realtime(args.email, args.password)


if __name__ == "__main__":
    main()
