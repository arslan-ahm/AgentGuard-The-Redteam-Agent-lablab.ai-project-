"""Password hashing and bearer tokens (brief 6.2: auth). Owner: Sohaib.

- Passwords: salted scrypt, constant-time compare. Only the hash is stored.
- Tokens: ``base64url(json{sub, exp}).hmac_sha256`` signed with ``SECRET_KEY``. Stateless, short
  lived. An empty ``SECRET_KEY`` disables auth entirely (503) instead of signing with a
  guessable key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

TOKEN_TTL_S = 8 * 3600
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
_MIN_SECRET_LEN = 16


def hash_password(password: str) -> str:
    """``scrypt$<salt b64>$<hash b64>`` with a fresh random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return f"scrypt${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. Malformed stored hashes never match."""
    try:
        scheme, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = _unb64(salt_b64), _unb64(hash_b64)
        if len(salt) != 16 or len(expected) != 32:
            return False
        digest = hashlib.scrypt(
            password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
        )
    except ValueError:
        return False
    return hmac.compare_digest(digest, expected)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# A real hash of a random password: verified against when the user does not exist, so the
# response time does not reveal which emails have accounts.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


class AuthNotConfiguredError(RuntimeError):
    """``SECRET_KEY`` is missing or too short."""


def _key(secret: str) -> bytes:
    if len(secret) < _MIN_SECRET_LEN:
        raise AuthNotConfiguredError("SECRET_KEY must be set (at least 16 characters)")
    return secret.encode()


def create_token(subject: str, secret: str, *, now: float | None = None) -> str:
    """Signed bearer token for ``subject`` valid for ``TOKEN_TTL_S`` seconds."""
    issued = time.time() if now is None else now
    payload = _b64(json.dumps({"sub": subject, "exp": int(issued) + TOKEN_TTL_S}).encode())
    signature = hmac.new(_key(secret), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64(signature)}"


def verify_token(token: str, secret: str, *, now: float | None = None) -> str | None:
    """The token's subject, or ``None`` if it is malformed, forged or expired."""
    try:
        payload, signature = token.split(".")
        expected = hmac.new(_key(secret), payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(signature), expected):
            return None
        data = json.loads(_unb64(payload))
        subject, expires = data["sub"], data["exp"]
    except (ValueError, KeyError, TypeError):
        return None
    current = time.time() if now is None else now
    if not isinstance(subject, str) or not isinstance(expires, int) or expires <= current:
        return None
    return subject


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "unauthorized", "message": "missing or invalid bearer token"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_user_factory(secret_getter: Callable[[Request], str]) -> Callable[..., str]:
    """Build the ``current_user`` dependency for a way of looking up the signing secret."""

    def current_user(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> str:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise _unauthorized()
        try:
            subject = verify_token(token.strip(), secret_getter(request))
        except AuthNotConfiguredError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "auth_not_configured", "message": str(exc)},
            ) from exc
        if subject is None:
            raise _unauthorized()
        return subject

    return current_user


__all__ = [
    "DUMMY_HASH",
    "TOKEN_TTL_S",
    "AuthNotConfiguredError",
    "Depends",
    "create_token",
    "current_user_factory",
    "hash_password",
    "verify_password",
    "verify_token",
]
