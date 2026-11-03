from typing import Annotated, Literal, TypedDict

from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, PositiveInt


class OrganizationContext(TypedDict):
    organization_id: UUID
    membership_id: UUID


class AuthorizationCode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: UUID
    session_id: UUID

    client_id: str
    redirect_uri: AnyHttpUrl

    code_challenge: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")
    nonce: str | None = None

    audience: str
    scopes: frozenset[str]

    context: OrganizationContext | None = Field(
        default=None,
        description="Дополнительный контекст организации",
    )

# ========================================================================================================
# Запросы с разными видами grant_type
# ========================================================================================================


class AuthorizationCodeRequest(BaseModel):
    grant_type: Literal["authorization_code"]

    code: str = Field(min_length=1)
    redirect_uri: AnyHttpUrl
    code_verifier: str = Field(min_length=43, max_length=128)
    client_id: str | None = None


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]

    refresh_token: str = Field(min_length=1)
    client_id: str | None = None


class ClientCredentialsRequest(BaseModel):
    grant_type: Literal["client_credentials"]

    scope: str = Field(default="")
    client_id: str | None = None


type TokenRequest = Annotated[
    AuthorizationCodeRequest
    | RefreshTokenRequest
    | ClientCredentialsRequest,
    Field(discriminator="grant_type"),
]


class TokenResponse(BaseModel):
    """Ответ после успешной авторизации."""

    access_token: str = Field(description="Маложивущий токен (около 15 минут)")
    token_type: Literal["Bearer"] = Field(default="Bearer")
    expires_in: PositiveInt

    refresh_token: str | None = Field(
        default=None,
        description="Долгоживущий токен, нужен для получения новой пары",
    )
    scope: str | None = None


class AuthorizationRequest(BaseModel):
    response_type: Literal["code"]

    client_id: str
    redirect_uri: AnyHttpUrl

    scope: str = ""
    state: str

    code_challenge: str = Field(min_length=43, max_length=43)
    code_challenge_method: Literal["S256"]

    organization_id: UUID | None = Field(
        default=None,
        description="Опциональный кастомный параметр, для авторизации в выбранной организации",
    )


__all__ = [
    "AuthorizationCode",
    "AuthorizationCodeRequest",
    "AuthorizationRequest",
    "ClientCredentialsRequest",
    "RefreshTokenRequest",
    "TokenRequest",
    "TokenResponse",
]
