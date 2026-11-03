

class OAuthAuthorizationService:
    """Отвечает за SSO, проверка клиента, scopes, организации и создание authorization code."""

    async def authorize(self): ...
