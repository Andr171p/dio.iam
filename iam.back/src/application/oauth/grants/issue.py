from datetime import UTC, datetime

from src.application.oauth.dtos import TokenResponse
from src.application.oauth.models import OAuthGrant
from src.application.security.jwt import CreateAccessTokenDTO, create_access_token, create_refresh_token


def issue_user_tokens(grant: OAuthGrant) -> TokenResponse:
    """Выпускает токены для уже аутентифицированного пользователя."""

    now = datetime.now(UTC)

    if not grant.is_active(now):
        ...

    dto = CreateAccessTokenDTO(
        subject=grant.user.user_id,
        client_id=grant.client_id,
        scopes=grant.scopes,
        session_id=grant.user.session_id,
        organization_id=grant.user.organization_id,
        membership_id=grant.user.membership_id,
    )
    access_token = create_access_token(dto)

    refresh_token = create_refresh_token(
        subject=grant.user.user_id,
        client_id=grant.client_id,
        grant_id=grant.id,
        membership_id=grant.user.membership_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=...,
        scope=" ".join(sorted(grant.scopes))
    )
