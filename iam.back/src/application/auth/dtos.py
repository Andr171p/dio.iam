from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AuthType(StrEnum):
    USER = "user"
    CLIENT = "client"


class Auth(BaseModel):
    model_config = ConfigDict(frozen=True)

    class User(BaseModel):
        id: UUID
        email: EmailStr
        organization_id: UUID | None = None
        membership_id: UUID | None = None

    id: UUID
    type: AuthType

    user: User | None = None


class AuthUser(Auth):
    """Авторизованный пользователь."""
    user: Auth.User


class AuthClient(Auth):
    """Авторизованное клиентское приложение."""

    class Client(BaseModel):
        id: UUID
        client_id: str
        scopes: frozenset[str] = Field(default_factory=frozenset)
        organization_id: UUID | None = None

    client: Client
