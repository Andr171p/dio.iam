from typing import Annotated

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from ddf.domain.models import AggregateRoot, Entity
from typing_extensions import Doc

from .types import OrganizationStatus


@dataclass(kw_only=True)
class Organization(AggregateRoot):
    """"""

    name: str
    slug: str
    description: str | None = None
    logo_id: Annotated[UUID | None, Doc("Идентификатор логотипа из сервиса Media")] = None
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    created_by: UUID | None = None


@dataclass(kw_only=True)
class LegalEntity(Entity):
    ...


@dataclass(kw_only=True)
class Membership(AggregateRoot):
    """Членство пользователя в организации.

    ``Membership`` является источником авторизации.

    Именно ``Membership`` определяет:

     • в какой организации работает пользователь;
     • какие роли действуют;
     • срок действия доступа;
     • активность доступа.

    Один ``User`` может иметь множество ``Membership``.

    Пример:

        User
            ├── Membership (OpenAI)
            │      ├── Admin
            │      └── HR
            │
            └── Membership (Microsoft)
                   └── Viewer

    Все проверки доступа выполняются относительно конкретного Membership.
    """

    user_id: UUID
    organization_id: UUID
    roles: set[UUID] = field(default_factory=set)
    expires_at: datetime | None = None
    is_active: bool = True

    def grant_role(self, role_id: UUID) -> None:
        if role_id in self.roles:
            return

        self.roles.add(role_id)
        self.updated_at = datetime.now(UTC)

    def revoke_role(self, role_id: UUID) -> None:
        if role_id not in self.roles:
            return

        self.roles.remove(role_id)
        self.updated_at = datetime.now(UTC)
