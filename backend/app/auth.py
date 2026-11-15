import hashlib
import hmac
import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Request
from app.database import run_query

_hasher = PasswordHasher()
_LEGACY_SHA256 = re.compile(r"[0-9a-f]{64}")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if _LEGACY_SHA256.fullmatch(password_hash):
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy, password_hash)
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    if _LEGACY_SHA256.fullmatch(password_hash):
        return True
    return _hasher.check_needs_rehash(password_hash)


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)


STAFF_ROLES = ("admin", "teacher", "ta")
VALID_ROLES = ("admin", "teacher", "ta", "student")


def has_role(user, *roles) -> bool:
    # Authorization must use the role stored server-side for the session, never a value sent by the client.
    return user is not None and user["role"] in roles
