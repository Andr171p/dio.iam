from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, TypeAdapter


class AccessTokenClaims(BaseModel):
    ...


class RefreshTokenClaims(BaseModel):
    subject: UUID = Field(alias="sub")
    jti: UUID
    grant_id: UUID = Field(alias="gti")
    client_id: str
    membership_id: UUID | None = Field(default=None, alias="mid")
    expires_at: datetime = Field(alias="exp")


refresh_token_validator = TypeAdapter(RefreshTokenClaims)
