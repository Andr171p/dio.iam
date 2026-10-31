from pydantic import Field, HttpUrl, PositiveFloat, PositiveInt, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class VkOAuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VK_OAUTH_")

    base_url: HttpUrl = Field(default="https://id.vk.ru", description="Хост сервиса VK ID")
    client_id: str = Field(min_length=1, description="Публичный идентификатор приложения")
    client_secret: SecretStr = Field(description="Секретный ключ приложения")
    scope: str = Field(default="email", description="Запрашиваемые права VK ID")
    prompt: str | None = Field(default=None, description="Необязательные параметры экрана авторизации")

    timeout: PositiveFloat = Field(default=10.0, description="Таймаут запросов")
    connect_timeout: PositiveFloat = Field(default=5.0, description="Для установки соединения")

    pool_limit: PositiveInt = Field(default=100, description="Кол-во одновременных соединений")
    pool_limit_per_host: PositiveInt = Field(
        default=10,
        description="Одновременные соединения именно с VK ID",
    )
    keepalive_timeout: PositiveInt = Field(
        default=30,
        description="Через сколько секунд будет закрыто простаивающее соединение",
    )
