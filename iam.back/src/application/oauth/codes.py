"""Создаёт и одноразово использует authorization code."""

import hashlib
import secrets

from ddf.application.cache import Cache

from .dtos import AuthorizationCode

_PREFIX = "iam:oauth:codes"
_CODE_BYTES = 32
_MAX_CODE_LENGTH = 256


def _cache_key(code: str) -> str:
    digest = hashlib.sha256(code.encode("ascii")).hexdigest()
    return f"{_PREFIX}:{digest}"


async def create_authorization_code(
    cache: Cache[AuthorizationCode],
    payload: AuthorizationCode,
    *,
    ttl: int = 120,
) -> str:
    """Создаёт одноразовый authorization code."""

    if ttl <= 0:
        raise ValueError("Code TTL must be positive")

    code = secrets.token_urlsafe(_CODE_BYTES)
    await cache.set(_cache_key(code), payload, ttl=ttl)


async def consume_authorization_code(cache: Cache[AuthorizationCode], code: str) -> AuthorizationCode | None:
    """Атомарно получает и удаляет authorization code."""

    if not code.strip() or len(code) > _MAX_CODE_LENGTH:
        return None

    try:
        key = _cache_key(code)
    except UnicodeDecodeError:
        return None

    return await cache.pop(key)


__all__ = ["consume_authorization_code", "create_authorization_code"]
