from pydantic import AnyHttpUrl, BaseModel, ConfigDict, EmailStr, Field, SecretStr


class VkTokens(BaseModel):
    """Ответ VK ID при обмене или обновлении токена."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    access_token: SecretStr = Field(repr=False)
    refresh_token: SecretStr | None = Field(default=None, repr=False)
    id_token: SecretStr | None = Field(default=None, repr=False)

    state: str
    token_type: str | None = None
    expires_in: int | None = Field(default=None, ge=0)
    user_id: int | str | None = None
    scope: str | None = None


class VkIdUser(BaseModel):
    """Профиль пользователя VK ID."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: int | str = Field(description="Идентификатор пользователя.",)
    first_name: str | None = Field(default=None, description="Имя пользователя")
    last_name: str | None = Field(default=None, description="Фамилия пользователя")
    email: EmailStr | None = Field(default=None, description="Почта пользователя")
    phone: str | None = Field(default=None, description="Телефон пользователя")
    avatar: AnyHttpUrl | None = Field(default=None, description="Ссылка на фото профиля")
    verified: bool = Field(default=False, description="Статус верификации пользователя")
