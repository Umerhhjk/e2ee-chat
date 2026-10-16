# Sealed Chat

Small end-to-end encrypted messenger for learning how to deploy a real app. The server is a store-and-forward relay. It never receives plaintext and has no keys that can decrypt messages.

## How encryption works

Each account generates an ECDH P-256 key (for a shared conversation secret) and an ECDSA P-256 key (for signatures). Private keys are wrapped with a key derived from the password and stored on the server as an opaque blob. Public keys are public.

When you send a message:

1. This browser encrypts the text with AES-GCM using the ECDH shared secret.
2. It signs the ciphertext and metadata.
3. Only that sealed packet goes to the server.
4. The recipient verifies the signature, then decrypts locally.

Chat history lives in an encrypted SQLite database in the browser (sql.js). Locking the session overwrites that blob before deleting it.

This is a teaching project, not a Signal replacement. Browser storage can never be fully forensic-proof.

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 in two browsers (or a normal window and a private window), create two accounts, and chat.

## Deploy with Docker

```bash
docker compose up --build -d
```

Point a reverse proxy at port 8000 and use HTTPS in production so WebSockets and passwords stay on TLS.
