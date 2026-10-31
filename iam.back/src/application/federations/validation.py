import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

from src.domain.sessions.models import AuthenticationSession

from .config import FederationConfig
from .dtos import FlowState
from .exceptions import (
    FederationDeniedError,
    InvalidFederationStateError,
    InvalidProviderCallbackError,
    ReauthenticationRequiredError,
)
from .types import AuthIntent

_STATE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


def parse_and_validate_callback(params: Mapping[str, str]) -> str:
    """Извлекает state из callback-параметров и проверяет их валидность."""
    if not (state := params.get("state")) or not _STATE_PATTERN.match(state):
        raise InvalidFederationStateError()

    if "error" in params:
        error = params["error"]
        description = params.get("error_description", "No description provided")
        raise FederationDeniedError(f"Identity provider returned error={error!r}. Description: {description}")

    if not params.get("code"):
        raise InvalidProviderCallbackError("Callback invalid. Code missmatch.")

    return state


def require_recent_session(session: AuthenticationSession | None, *, reauth_max_age: timedelta) -> None:
    now = datetime.now(UTC)

    if session is None or not session.is_valid(now):
        raise ReauthenticationRequiredError("SSO session expired or invalid.")

    authenticated_at = session.authenticated_at

    if authenticated_at.tzinfo is None:
        raise ReauthenticationRequiredError("Invalid SSO session.")

    age = now - authenticated_at

    if not timedelta(0) <= age <= reauth_max_age:
        raise ReauthenticationRequiredError("SSO session expired.")


def validate_auth_intent(
    config: FederationConfig,
    *,
    intent: AuthIntent,
    session: AuthenticationSession,
    authorization_id: UUID | None,
) -> None:
    """Проверяет намерение пользователя."""

    if intent == AuthIntent.LINK:
        require_recent_session(session, reauth_max_age=config.reauth_max_age)

        if authorization_id is not None:
            raise ValueError("LINK cannot contain an authorizationId")

    elif intent != AuthIntent.LOGIN:
        raise ValueError("Unsupported federation intent")


def validate_flow_state_before_cache(
    *,
    intent: AuthIntent,
    user_id: UUID | None,
    session_id: UUID | None,
    authorization_id: UUID | None,
) -> None:
    """Валидация перед сохранением в кеш (fail-fast)."""

    if intent == AuthIntent.LINK:
        if user_id is None or session_id is None or authorization_id is not None:
            raise ValueError("LINK requires userId and sessionId, and forbids authorizationId")

    elif user_id is not None or session_id is not None:
        raise ValueError("LOGIN cannot contain userId or sessionId")


def validate_session_match(
    config: FederationConfig,
    *,
    state: FlowState,
    session: AuthenticationSession | None,
) -> None:
    if state.intent != AuthIntent.LINK:
        return

    require_recent_session(session, reauth_max_age=config.reauth_max_age)

    if (
        session is None
        or state.user_id != session.user_id
        or state.session_id != session.id
    ):
        raise InvalidFederationStateError()
