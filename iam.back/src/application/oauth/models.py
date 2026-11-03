from typing import Annotated

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from typing_extensions import Doc


@dataclass(frozen=True, slots=True)
class UserAuthentication:
    """Контекст аутентификации пользователя."""

    user_id: UUID
    session_id: Annotated[UUID, Doc("Текущая SSO сессия")]

    organization_id: UUID | None = None
    membership_id: UUID | None = None


@dataclass
class OAuthGrant:
    """"""

    id: UUID
    user: UserAuthentication

    audience: str
    client_id: str
    scopes: frozenset[str]

    current_jti: UUID
    expires_at: datetime

    revoked_at: datetime | None = None

    def is_active(self, now: datetime) -> bool:
        return self.revoked_at is None and now < self.expires_at

    def rotate(self, expected_jti: UUID, new_jti: UUID, now: datetime) -> bool:
        if not self.is_active(now):
            raise ...

        if self.current_jti != expected_jti:
            self.revoke(now)
            return False

        self.current_jti = new_jti
        return True

    def revoke(self, now: datetime) -> None:
        if self.revoked_at is None:
            self.revoked_at = now
