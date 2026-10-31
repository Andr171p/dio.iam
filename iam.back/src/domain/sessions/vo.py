from typing import Annotated, Self

from dataclasses import dataclass
from datetime import datetime, timedelta

from typing_extensions import Doc


@dataclass(frozen=True, slots=True)
class SessionLifetime:
    """Время жизни SSO сессии."""

    last_seen_at: datetime
    expires_at: Annotated[datetime, Doc("Абсолютное истечение сессии")]
    idle_expires_at: Annotated[datetime, Doc("Момент когда сессия исчезнет из-за отсутствия активности")]

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at or now >= self.idle_expires_at

    def touch(self, now: datetime, idle_timeout: timedelta) -> Self:
        return SessionLifetime(
            last_seen_at=now,
            expires_at=self.expires_at,
            idle_expires_at=min(self.expires_at, now + idle_timeout),
        )

