from typing import Literal

from datetime import timedelta

from pydantic import AnyHttpUrl, Field, PositiveInt, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class JwtConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JWT_")

    issuer: AnyHttpUrl = Field(description="Адрес сервера подписывающего токены")
    audience: str = Field(min_length=1, description="Для какого сервиса предназначен токен (аудитория)")
    algorithm: Literal["RS256"] = Field(default="RS256")
    private_key: SecretStr = Field(repr=False, description="Приватный ключ для подписи JWT")
    key_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Идентификатор ключа подписи JWT (kid)",
    )

    access_token_expires_in: timedelta = Field(
        ge=timedelta(seconds=1),
        description="Время жизни access токена",
    )
    refresh_token_expires_in: timedelta = Field(
        ge=timedelta(seconds=1),
        description="Время жизни refresh токена",
    )


class TokenDenyListConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TOKEN_DENYLIST_")

    leeway: PositiveInt = Field(default=5, description="Погрешность для расчёта TTL")
    prefix: str = Field(default="iam:tokens:denied", description="Кеш префикс")
