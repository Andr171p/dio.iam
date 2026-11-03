from typing import Any

import time
from collections.abc import Mapping
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization

from .claims import RefreshTokenClaims
from .config import JwtConfig
from .dtos import CreateAccessTokenDTO

config = JwtConfig()  # type: ignore

_private_key = serialization.load_pem_private_key(
    config.private_key.get_secret_value().encode("utf-8"),
    password=None,
)


def public_key() -> str:
    return _private_key.public_key()


def create_access_token(dto: CreateAccessTokenDTO) -> str:
    now = int(time.time())
    ttl = int(config.access_token_expires_in.total_seconds())

    claims = {
        "iss": str(config.issuer).rstrip("/"),
        "sub": str(dto.subject),
        "aud": config.audience,
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        # Principal type
        "ptp": dto.subject_type,
    }
    headers = {"kid": config.key_id, "typ": "at+jwt", "token_use": "access"}

    if dto.client_id is not None:
        claims["client_id"] = dto.client_id

    if dto.session_id is not None:
        claims["sid"] = str(dto.session_id)

    if dto.organization_id is not None and dto.membership_id is not None:
        claims["org_id"] = str(dto.organization_id)
        claims["mid"] = str(dto.membership_id)

    return jwt.encode(claims, key=_private_key, algorithm=config.algorithm, headers=headers)


def create_refresh_token(
    *,
    subject: UUID,
    client_id: str,
    grant_id: UUID,
    membership_id: UUID | None = None,
) -> str:
    now = int(time.time())
    ttl = int(config.refresh_token_expires_in.total_seconds())

    claims = {
        "iss": str(config.issuer).rstrip("/"),
        "sub": str(subject),
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        # Grant identifier for rotation family
        "gti": str(grant_id),
        # Authenticated client
        "client_id": client_id,
    }
    headers = {"kid": config.key_id, "typ": "refresh+jwt", "token_use": "refresh"}

    if membership_id is not None:
        claims["mid"] = str(membership_id)

    return jwt.encode(claims, key=_private_key, algorithm=config.algorithm, headers=headers)


def verify_access_token(token: str) -> Mapping[str, Any]:
    decoded = jwt.decode_complete(
        token,
        key=public_key(),
        algorithms=[config.algorithm],
        issuer=str(config.issuer).rstrip("/"),
        audience=config.audience,
        options={
            "require": [
                "iss",
                "sub",
                "aud",
                "jti",
                "iat",
                "exp",
            ],
        },
    )

    if decoded["header"].get("typ") not in ("at+jwt", "application/at+jwt"):
        raise jwt.InvalidTokenError("Invalid token type")

    claims = decoded["payload"]

    if claims.get("token_use") != "access":
        raise jwt.InvalidTokenError("Invalid token usage")

    return claims


def verify_refresh_token(token: str) -> RefreshTokenClaims:
    ...


__all__ = [
    "CreateAccessTokenDTO",
    "create_access_token",
    "create_refresh_token",
    "public_key",
    "verify_access_token",
    "verify_refresh_token",
]
