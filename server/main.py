import json
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from server.db import Store, connect, init_db
from server.security import (
    MAX_CIPHERTEXT_B64,
    SESSION_TTL_SECONDS,
    USERNAME_RE,
    RateLimiter,
    hash_password,
    hash_token,
    new_session_token,
    now,
    verify_password,
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

store: Store
limiter = RateLimiter()
sockets: dict[int, set[WebSocket]] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global store
    conn = connect()
    init_db(conn)
    store = Store(conn)
    yield
    conn.close()


app = FastAPI(title="Sealed Chat", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_rate(bucket: str, key: str, limit: int, window: float = 60.0) -> None:
    if not limiter.allow(bucket, key, limit, window):
        raise HTTPException(status_code=429, detail="Too many requests, slow down.")


def user_from_auth(request: Request):
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing session.")
    token = header.split(" ", 1)[1].strip()
    return user_from_token(token)


def user_from_token(token: str):
    row = store.query_one(
        """
        SELECT u.id, u.username, u.ecdh_public, u.ecdsa_public, u.wrapped_keys, u.wrap_salt
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.expires_at > ?
        """,
        (hash_token(token), now()),
    )
    if not row:
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.")
    return row


class RegisterIn(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=128)
    ecdh_public: str
    ecdsa_public: str
    wrapped_keys: str
    wrap_salt: str

    @field_validator("username")
    @classmethod
    def username_ok(cls, value: str) -> str:
        if not re.match(USERNAME_RE, value):
            raise ValueError("Use 3-24 letters, numbers, or underscores.")
        return value

    @field_validator("ecdh_public", "ecdsa_public", "wrapped_keys", "wrap_salt")
    @classmethod
    def not_empty(cls, value: str) -> str:
        if not value or len(value) > 20000:
            raise ValueError("Invalid key material.")
        return value


class LoginIn(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=128)


class MessageIn(BaseModel):
    id: str = Field(min_length=8, max_length=64)
    recipient: str
    iv: str
    ciphertext: str
    signature: str
    seq: int = Field(ge=1, le=1_000_000_000)
    client_ts: int

    @field_validator("iv", "signature")
    @classmethod
    def b64ish(cls, value: str) -> str:
        if not value or len(value) > 1024:
            raise ValueError("Invalid field.")
        return value

    @field_validator("ciphertext")
    @classmethod
    def ciphertext_ok(cls, value: str) -> str:
        if not value or len(value) > MAX_CIPHERTEXT_B64:
            raise ValueError("Message too large.")
        return value


class AckIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=100)


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/register")
async def register(body: RegisterIn, request: Request):
    require_rate("register", client_ip(request), 5)
    existing = store.query_one("SELECT id FROM users WHERE username = ?", (body.username,))
    if existing:
        raise HTTPException(status_code=409, detail="That username is taken.")
    cur = store.execute(
        """
        INSERT INTO users (username, password_hash, ecdh_public, ecdsa_public, wrapped_keys, wrap_salt, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            body.username,
            hash_password(body.password),
            body.ecdh_public,
            body.ecdsa_public,
            body.wrapped_keys,
            body.wrap_salt,
            now(),
        ),
    )
    token = issue_session(cur.lastrowid)
    return {
        "token": token,
        "user": {
            "id": cur.lastrowid,
            "username": body.username,
            "ecdh_public": body.ecdh_public,
            "ecdsa_public": body.ecdsa_public,
            "wrapped_keys": body.wrapped_keys,
            "wrap_salt": body.wrap_salt,
        },
    }


@app.post("/api/login")
async def login(body: LoginIn, request: Request):
    require_rate("login", client_ip(request), 8)
    row = store.query_one(
        """
        SELECT id, username, password_hash, ecdh_public, ecdsa_public, wrapped_keys, wrap_salt
        FROM users WHERE username = ?
        """,
        (body.username,),
    )
    if not row or not verify_password(row["password_hash"], body.password):
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    store.execute("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?", (row["id"], now()))
    token = issue_session(row["id"])
    return {
        "token": token,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "ecdh_public": row["ecdh_public"],
            "ecdsa_public": row["ecdsa_public"],
            "wrapped_keys": row["wrapped_keys"],
            "wrap_salt": row["wrap_salt"],
        },
    }


@app.post("/api/logout")
async def logout(request: Request):
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        token = header.split(" ", 1)[1].strip()
        store.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    return {"ok": True}


@app.get("/api/users")
async def list_users(request: Request):
    me = user_from_auth(request)
    require_rate("users", str(me["id"]), 30)
    rows = store.query(
        "SELECT username, ecdh_public, ecdsa_public FROM users WHERE id != ? ORDER BY username",
        (me["id"],),
    )
    return {
        "users": [
            {"username": r["username"], "ecdh_public": r["ecdh_public"], "ecdsa_public": r["ecdsa_public"]}
            for r in rows
        ]
    }


@app.get("/api/users/{username}")
async def get_user(username: str, request: Request):
    me = user_from_auth(request)
    require_rate("userlookup", str(me["id"]), 40)
    row = store.query_one(
        "SELECT username, ecdh_public, ecdsa_public FROM users WHERE username = ?",
        (username,),
    )
    if not row:
        raise HTTPException(status_code=404, detail="No user with that name.")
    return {
        "username": row["username"],
        "ecdh_public": row["ecdh_public"],
        "ecdsa_public": row["ecdsa_public"],
    }


@app.post("/api/messages")
async def send_message(body: MessageIn, request: Request):
    me = user_from_auth(request)
    require_rate("send", str(me["id"]), 40)
    if abs(body.client_ts - now()) > 60 * 10:
        raise HTTPException(status_code=400, detail="Message timestamp is too far off.")
    recipient = store.query_one("SELECT id, username FROM users WHERE username = ?", (body.recipient,))
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found.")
    if recipient["id"] == me["id"]:
        raise HTTPException(status_code=400, detail="You cannot message yourself.")
    existing = store.query_one("SELECT id FROM messages WHERE id = ?", (body.id,))
    if existing:
        raise HTTPException(status_code=409, detail="Replay detected: message id already used.")
    store.execute(
        """
        INSERT INTO messages (id, sender_id, recipient_id, iv, ciphertext, signature, seq, client_ts, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            body.id,
            me["id"],
            recipient["id"],
            body.iv,
            body.ciphertext,
            body.signature,
            body.seq,
            body.client_ts,
            now(),
        ),
    )
    payload = {
        "type": "message",
        "message": {
            "id": body.id,
            "sender": me["username"],
            "recipient": recipient["username"],
            "iv": body.iv,
            "ciphertext": body.ciphertext,
            "signature": body.signature,
            "seq": body.seq,
            "client_ts": body.client_ts,
        },
    }
    await push(recipient["id"], payload)
    return {"ok": True}


@app.get("/api/messages/pending")
async def pending_messages(request: Request):
    me = user_from_auth(request)
    rows = store.query(
        """
        SELECT m.id, u.username AS sender, me.username AS recipient,
               m.iv, m.ciphertext, m.signature, m.seq, m.client_ts
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        JOIN users me ON me.id = m.recipient_id
        WHERE m.recipient_id = ?
        ORDER BY m.created_at ASC
        LIMIT 200
        """,
        (me["id"],),
    )
    return {
        "messages": [
            {
                "id": r["id"],
                "sender": r["sender"],
                "recipient": r["recipient"],
                "iv": r["iv"],
                "ciphertext": r["ciphertext"],
                "signature": r["signature"],
                "seq": r["seq"],
                "client_ts": r["client_ts"],
            }
            for r in rows
        ]
    }


@app.post("/api/messages/ack")
async def ack_messages(body: AckIn, request: Request):
    me = user_from_auth(request)
    placeholders = ",".join("?" * len(body.ids))
    store.execute(
        f"DELETE FROM messages WHERE recipient_id = ? AND id IN ({placeholders})",
        (me["id"], *body.ids),
    )
    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    user = None
    try:
        raw = await ws.receive_text()
        if len(raw) > 4096:
            await ws.close(code=1009)
            return
        data = json.loads(raw)
        if data.get("type") != "auth" or not data.get("token"):
            await ws.close(code=1008)
            return
        ip = ws.client.host if ws.client else "unknown"
        if not limiter.allow("ws", ip, 20, 60):
            await ws.close(code=1008)
            return
        user = user_from_token(data["token"])
        sockets.setdefault(user["id"], set()).add(ws)
        await ws.send_text(json.dumps({"type": "ready", "username": user["username"]}))
        while True:
            incoming = await ws.receive_text()
            if len(incoming) > 256:
                continue
            parsed = json.loads(incoming)
            if parsed.get("type") == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except (WebSocketDisconnect, HTTPException, json.JSONDecodeError):
        pass
    finally:
        if user and user["id"] in sockets:
            sockets[user["id"]].discard(ws)
            if not sockets[user["id"]]:
                sockets.pop(user["id"], None)


async def push(user_id: int, payload: dict) -> None:
    dead = []
    for ws in list(sockets.get(user_id, ())):
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        sockets.get(user_id, set()).discard(ws)


def issue_session(user_id: int) -> str:
    token = new_session_token()
    store.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), user_id, now() + SESSION_TTL_SECONDS, now()),
    )
    return token
