from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl

from .types import AuthIntent, CodeVerifier, Nonce, State


class FlowState(BaseModel):
    """Временная транзакция федерации, сохраняемая в кэш."""

    provider: str = Field(
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
        description="Ключ внешнего провайдера из registry",
    )
    intent: AuthIntent = Field(description="Цель аутентификации: вход или привязка")
    state: State
    verifier: CodeVerifier
    nonce: Nonce | None = None
    authorization_id: UUID | None = Field(default=None, description="Идентификатор исходного OIDC-flow")
    user_id: UUID | None = Field(default=None, description="Пользователь, инициировавший flow")
    session_id: UUID | None = Field(default=None, description="IAM-сессия, инициировавшая привязку")


class AuthorizationStart(BaseModel):
    model_config = ConfigDict(frozen=True)

    redirect_uri: HttpUrl
    state: State
    code_challenge: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="PKCE S256 challenge в формате base64url без padding.",
    )
    nonce: Nonce | None = None


class AuthorizationCallback(BaseModel):
    model_config = ConfigDict(frozen=True)

    params: Mapping[str, str]
    redirect_uri: HttpUrl
    code_verifier: CodeVerifier
    expected_nonce: str | None = Field(
        default=None,
        description="Ожидаемый nonce для проверки OIDC ID Token",
    )


class UserInfo(BaseModel):
    """Нормализованное представление внешнего пользователя."""

    subject: str = Field(
        min_length=1,
        max_length=512,
        description="Стабильный идентификатор у внешнего провайдера",
    )
    email: EmailStr | None = None
    email_verified: bool = Field(default=False, description="Подтверждена ли почта у провайдера")
    display_name: str | None = Field(
        default=None,
        max_length=200,
        description="Отображаемое имя пользователя",
    )


class FederatedResult(BaseModel):
    """Результат пройденной аутентификации у провайдера."""

    provider: str = Field(min_length=2, max_length=64, description="Ключ внешнего провайдера")
    intent: AuthIntent = Field(description="Намерение пользователя")
    user_info: UserInfo = Field(description="Полученная информация от провайдера")

    authorization_id: UUID | None = Field(default=None, description="Идентификатор исходного OIDC-flow")
    user_id: UUID | None = Field(default=None, description="Пользователь, инициировавший flow")
    session_id: UUID | None = Field(default=None, description="IAM-сессия, инициировавшая привязку")
