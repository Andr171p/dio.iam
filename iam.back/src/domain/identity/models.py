from typing import Annotated, Any

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from ddf.domain.models import AggregateRoot
from ddf.domain.vo import Email, FullName, Username
from typing_extensions import Doc

from .vo import SecretHash


@dataclass(kw_only=True)
class User(AggregateRoot):
    """Пользователь системы (человек).

    ``User`` представляет физического пользователя независимо
    от организаций, в которых он состоит.

    Не содержит ролей или разрешений.

    Один пользователь может одновременно состоять
    в нескольких организациях через Membership и иметь
    в каждой из них собственный набор ролей.

    Отвечает только за:

    - аутентификацию;
    - персональные данные;
    - глобальный жизненный цикл учетной записи.
    """

    email: Email
    email_verified: bool = False
    username: Username | None = None
    full_name: FullName | None = None
    avatar_url: str | None = None
    password_hash: SecretHash
    is_active: bool = True


@dataclass(kw_only=True)
class FederatedIdentity(AggregateRoot):
    """Подключенный внешний аккаунт пользователя."""

    user_id: UUID
    provider: Annotated[str, Doc("Ключ внешнего провайдера ('vk', 'yandex')")]
    subject: Annotated[str, Doc("Внешний идентификатор пользователя")]

    profile: Annotated[dict[str, Any], Doc("Нормализованные данные")] = field(default_factory=dict)
    raw_data: Annotated[dict[str, Any], Doc("Сырой ответ от провайдера")] = field(default_factory=dict)

    linked_at: datetime
    last_authenticated_at: datetime | None = None
