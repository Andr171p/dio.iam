import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

from ddf.application.cache import Cache
from ddf.application.uow import UnitOfWork

from src.application.oauth import codes
from src.application.oauth.dtos import AuthorizationCode, AuthorizationCodeRequest, TokenResponse
from src.application.oauth.models import OAuthGrant, UserAuthentication
from src.application.oauth.rotation import OAuthGrantRepository
from src.domain.oauth.models import Client

from .issue import issue_user_tokens


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    actual = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(actual, challenge)


def _build_oauth_grant(authorization: AuthorizationCode, refresh_ttl: timedelta) -> OAuthGrant:
    now = datetime.now(UTC)
    ctx = authorization.context

    organization_id = None if not ctx else ctx["organization_id"]
    membership_id = None if not ctx else ctx["membership_id"]

    user = UserAuthentication(
        user_id=authorization.user_id,
        session_id=authorization.session_id,
        organization_id=organization_id,
        membership_id=membership_id,
    )

    return OAuthGrant(
        id=uuid.uuid7(),  # type: ignore
        user=user,
        audience=authorization.audience,
        client_id=authorization.client_id,
        scopes=authorization.scopes,
        current_jti=uuid.uuid4(),
        expires_at=now + refresh_ttl,
    )


async def exchange_code(
    request: AuthorizationCodeRequest,
    client: Client,
    *,
    uow: UnitOfWork,
    grant_repository: OAuthGrantRepository,
    cache: Cache[AuthorizationCode],
) -> TokenResponse:
    """Обменивает код на токены."""

    if (authorization := await codes.consume_authorization_code(cache, request.code)) is None:
        raise ...

    if (
        authorization.client_id != client.client_id
        or authorization.redirect_uri != request.redirect_uri
        or not _verify_pkce(request.code_verifier, authorization.code_challenge)
    ):
        raise ...

    grant = _build_oauth_grant(authorization, ...)
    await grant_repository.create(grant)

    tokens = issue_user_tokens(grant)
    await uow.commit()

    return tokens
