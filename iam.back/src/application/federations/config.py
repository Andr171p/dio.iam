from datetime import timedelta

from pydantic import Field, HttpUrl, PositiveInt
from pydantic_settings import BaseSettings, SettingsConfigDict


class FederationConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FEDERATION_")

    public_url: HttpUrl = Field(description="Публичный базовый URL IAM (нужен дли формирования redirectUri)")
    ttl: PositiveInt = Field(default=300, description="Время жизни state")
    reauth_max_age: timedelta = Field(default_factory=lambda: timedelta(minutes=10))
