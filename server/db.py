import os
import libsql_client

TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL", "sqlite:///:memory:")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "")

def connect() -> libsql_client.ClientSync:
    # Use the synchronous client to match your existing app architecture
    return libsql_client.create_client_sync(
        url=TURSO_DATABASE_URL, 
        auth_token=TURSO_AUTH_TOKEN
    )

def init_db(client: libsql_client.ClientSync) -> None:
    client.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            ecdh_public TEXT NOT NULL,
            ecdsa_public TEXT NOT NULL,
            wrapped_keys TEXT NOT NULL,
            wrap_salt TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    client.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    client.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            iv TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            signature TEXT NOT NULL,
            seq INTEGER NOT NULL,
            client_ts INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    client.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, created_at)")
    client.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")


class Store:
    def __init__(self, client: libsql_client.ClientSync):
        self.client = client

    def execute(self, sql: str, params=()):
        # libsql-client expects sequences for params, so we cast tuples to lists
        return self.client.execute(sql, list(params))

    def query(self, sql: str, params=()):
        return self.execute(sql, params).rows

    def query_one(self, sql: str, params=()):
        rows = self.execute(sql, params).rows
        return rows[0] if rows else None