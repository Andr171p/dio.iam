from dataclasses import dataclass

from ddf.domain.models import AggregateRoot
from ddf.domain.vo import Email, FullName, Username

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
    username: Username | None = None
    full_name: FullName | None = None
    avatar_url: str | None = None
    password_hash: SecretHash
    is_active: bool = True
