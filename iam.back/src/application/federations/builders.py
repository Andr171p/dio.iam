import secrets
from uuid import UUID

from src.domain.sessions.models import AuthenticationSession

from .dtos import FlowState
from .types import AuthIntent
from .validation import validate_flow_state_before_cache

_STATE_BYTES = _NONCE_BYTES = 32
_VERIFIER_BYTES = 48


def build_flow_state(
    *,
    provider: str,
    intent: AuthIntent,
    authorization_id: UUID | None = None,
    session: AuthenticationSession | None = None,
) -> FlowState:
    validate_flow_state_before_cache(
        intent=intent,
        user_id=None if session is None else session.user_id,
        session_id=None if session is None else session.id,
        authorization_id=authorization_id,
    )
    return FlowState(
        provider=provider,
        intent=intent,
        state=secrets.token_urlsafe(_STATE_BYTES),
        verifier=secrets.token_urlsafe(_VERIFIER_BYTES),
        nonce=secrets.token_urlsafe(_NONCE_BYTES),
        authorization_id=authorization_id,
        user_id=session.user_id if (session and intent == AuthIntent.LINK) else None,
        session_id=session.id if (session and intent == AuthIntent.LINK) else None,
    )
