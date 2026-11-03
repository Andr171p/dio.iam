from typing import Literal

from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class CreateAccessTokenDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: UUID = Field(description="Идентификатор субъекта")
    subject_type: Literal["user", "client"] = Field(description="Тип субъекта авторизации")
    client_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Публичный идентификатор клиента",
    )
    email: EmailStr | None = Field(default=None, description="Почта пользователя")

    scopes: frozenset[str]
    session_id: UUID | None = Field(default=None, description="Идентификатор SSO сессии")

    organization_id: UUID | None = Field(default=None, description="Выбранная организация")
    membership_id: UUID | None = Field(default=None, description="Членство в организации")
