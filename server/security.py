import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

SESSION_TTL_SECONDS = 60 * 60 * 24
MAX_BODY_CHARS = 4000
MAX_CIPHERTEXT_B64 = 12000
USERNAME_RE = r"^[a-zA-Z0-9_]{3,24}$"


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        password_hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def now() -> int:
    return int(time.time())


class RateLimiter:
    """In-memory sliding window. Enough for a small test deploy."""

    def __init__(self):
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def allow(self, bucket: str, key: str, limit: int, window_seconds: float) -> bool:
        stamp = time.monotonic()
        q = self._hits[(bucket, key)]
        cutoff = stamp - window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(stamp)
        return True


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
