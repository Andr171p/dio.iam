"""Черный список токенов (хранит отозванные токены, которые ещё не истекли)."""

from typing import Literal, TypedDict

import hashlib
import math
import time

from ddf.application.cache import Cache

from .config import TokenDenyListConfig

type TokenType = Literal["access", "refresh"]

config = TokenDenyListConfig()


class TokenClaims(TypedDict):
    iss: str
    jti: str
    exp: int


def _cache_key(claims: TokenClaims, token_type: TokenType) -> str:
    key_id = "\0".join((claims["iss"], claims["jti"], token_type))
    digest = hashlib.sha256(key_id.encode("utf-8")).hexdigest()
    return f"{config.prefix}:{digest}"


async def deny(cache: Cache[bool], claims: TokenClaims, token_type: TokenType) -> None:
    ttl = math.ceil(claims["exp"] + config.leeway - time.time())

    if ttl <= 0:
        return

    await cache.set(_cache_key(claims, token_type), True, ttl=ttl)


async def is_revoked(cache: Cache[bool], claims: TokenClaims, token_type: TokenType) -> bool:
    return await cache.exists(_cache_key(claims, token_type))


__all__ = ["deny", "is_revoked"]
