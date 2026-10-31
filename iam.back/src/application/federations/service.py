import base64
import hashlib
from collections.abc import Mapping
from uuid import UUID

from ddf.application.cache import Cache
from pydantic import HttpUrl

from src.domain.sessions.models import AuthenticationSession

from .builders import build_flow_state
from .config import FederationConfig
from .dtos import AuthorizationCallback, AuthorizationStart, FederatedResult, FlowState
from .exceptions import InvalidFederationStateError
from .registry import get_federation_provider
from .types import AuthIntent, BrowserBinding
from .validation import parse_and_validate_callback, validate_auth_intent, validate_session_match


def _cache_key(provider: str, state: str, browser_binding: str) -> str:
    """Детерминированный ключ для кеширования состояния потока аутентификации."""
    raw = f"{provider}\0{state}\0{browser_binding}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"iam:federation:{digest}"


def _callback_url(config: FederationConfig, *, provider: str) -> HttpUrl:
    """Формирует URL для редиректа и обработки callback конкретного провайдера."""
    return HttpUrl(f"{str(config.public_url).rstrip('/')}/auth/federation/{provider}/callback")


def _generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class FederationService:
    """Оркестрация внешней OAuth/OIDC-аутентификации."""

    def __init__(self, cache: Cache[FlowState], config: FederationConfig) -> None:
        self._cache = cache
        self._config = config

    async def start(
        self,
        provider_name: str,
        *,
        browser_binding: BrowserBinding,
        intent: AuthIntent,
        authorization_id: UUID | None = None,
        session: AuthenticationSession | None = None,
    ) -> str:
        """Начинает внешнюю авторизацию и получает redirect URL."""

        provider = get_federation_provider(provider_name)
        validate_auth_intent(
            self._config,
            intent=intent,
            session=session,
            authorization_id=authorization_id,
        )

        flow = build_flow_state(
            provider=provider_name,
            intent=intent,
            authorization_id=authorization_id,
            session=session,
        )

        start = AuthorizationStart(
            redirect_uri=_callback_url(self._config, provider=provider_name),
            state=flow.state,
            code_challenge=_generate_code_challenge(flow.verifier),
            nonce=flow.nonce,
        )
        url = provider.authorization_url(start)

        await self._cache.set(
            _cache_key(provider_name, flow.state, browser_binding),
            flow,
            ttl=self._config.ttl,
        )
        return url

    async def complete(
        self,
        provider_name: str,
        params: Mapping[str, str],
        *,
        browser_binding: BrowserBinding,
        session: AuthenticationSession | None = None,
    ) -> FederatedResult:
        provider = get_federation_provider(provider_name)

        state = parse_and_validate_callback(params)

        cache_key = _cache_key(provider_name, state, browser_binding)
        cached_flow = await self._cache.get(cache_key)
        await self._cache.delete(cache_key)  # TODO: сделать атомарное удаление через ``cache.pop``

        if cached_flow is None or cached_flow.provider != provider_name or cached_flow.state != state:
            raise InvalidFederationStateError()

        validate_session_match(self._config, state=cached_flow, session=session)

        callback = AuthorizationCallback(
            redirect_uri=_callback_url(self._config, provider=provider_name),
            params=dict(params),
            code_verifier=cached_flow.verifier,
            expected_nonce=cached_flow.nonce,
        )
        user_info = await provider.authenticate(callback)

        return FederatedResult(
            provider=provider_name,
            intent=cached_flow.intent,
            user_info=user_info,
            authorization_id=cached_flow.authorization_id,
            user_id=cached_flow.user_id,
            session_id=cached_flow.session_id,
        )


__all__ = ["FederationService"]
