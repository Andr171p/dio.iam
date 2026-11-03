from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from ddf.domain.exceptions import InvariantViolationError
from ddf.domain.models import AggregateRoot

from src.domain.identity.vo import SecretHash

from .types import AuthMethod
from .vo import SessionLifetime


def _create_session_lifetime(
    now: datetime,
    absolute_timeout: timedelta,
    idle_timeout: timedelta,
) -> SessionLifetime:
    expires_at = now + absolute_timeout
    return SessionLifetime(
        last_seen_at=now,
        expires_at=expires_at,
        idle_expires_at=min(expires_at, now + idle_timeout),
    )


@dataclass(kw_only=True)
class AuthenticationSession(AggregateRoot):
    """Интерактивная SSO-сессия пользователя в IAM."""

    user_id: UUID
    authenticated_at: datetime
    lifetime: SessionLifetime

    method: AuthMethod
    provider: str | None = None

    credential_hash: SecretHash = field(repr=False)

    revoked_at: datetime | None = None

    def is_valid(self, now: datetime) -> bool:
        return self.revoked_at is None and not self.lifetime.is_expired(now)

    def touch(self, now: datetime, idle_timeout: timedelta) -> None:
        if not self.is_valid(now):
            raise InvariantViolationError("Authentication session is not active.")

        self.lifetime = self.lifetime.touch(now, idle_timeout)
        self.updated_at = now

    def revoke(self, now: datetime) -> None:
        if self.revoked_at is not None:
            return

        self.revoked_at = now
        self.updated_at = now

    def reauthenticate(
        self,
        now: datetime,
        *,
        method: AuthMethod,
        absolute_timeout: timedelta,
        idle_timeout: timedelta,
    ) -> None:
        if self.revoked_at is not None:
            raise InvariantViolationError("Authentication session is revoked.")

        self.authenticated_at = now
        self.method = method
        self.lifetime = _create_session_lifetime(now, absolute_timeout, idle_timeout)
        self.updated_at = now
