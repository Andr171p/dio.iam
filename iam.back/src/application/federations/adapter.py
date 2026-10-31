from typing import Protocol

from .dtos import AuthorizationCallback, AuthorizationStart, UserInfo


class FederationAdapter(Protocol):
    @property
    def provider(self) -> str:
        """Стабильный ключ реализации."""

    def authorization_url(self, start: AuthorizationStart) -> str:
        """Формирует URL внешнего провайдера."""

    async def authenticate(self, callback: AuthorizationCallback) -> UserInfo:
        """Завершает внешнюю аутентификацию и возвращает нормализованный профиль."""
