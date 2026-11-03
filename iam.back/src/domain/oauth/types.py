from typing import Literal

from enum import StrEnum

type GrantType = Literal["authorization_code", "client_credentials", "refresh_token"]


class ClientAuthMethod(StrEnum):
    NONE = "none"
    CLIENT_SECRET_BASIC = "client_secret_basic"


__all__ = ["ClientAuthMethod", "GrantType"]
