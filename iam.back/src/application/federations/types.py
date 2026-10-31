from typing import Annotated

from enum import StrEnum

from pydantic import Field

BrowserBinding = Annotated[
    str,
    Field(
        min_length=43,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Случайный секрет браузерного контекста, используемый для защиты OAuth-транзакции",
    ),
]

CodeVerifier = Annotated[
    str,
    Field(
        min_length=43,
        max_length=128,
        pattern=r"^[A-Za-z0-9._~-]+$",
        repr=False,
        description="PKCE verifier, хранимый только на стороне сервера",
    )
]

State = Annotated[
    str,
    Field(
        min_length=32,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Одноразовый OAuth state, генерируемый IAM",
    )
]

Nonce = Annotated[
    str,
    Field(
        min_length=32,
        max_length=128,
        repr=False,
        description="OIDC nonce для связывания ID Token с авторизацией",
    )
]


class AuthIntent(StrEnum):
    LOGIN = "login"
    LINK = "link"
