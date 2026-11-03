from datetime import UTC, datetime
from uuid import uuid4

from ddf.application.uow import UnitOfWork

from src.application.oauth.dtos import RefreshTokenRequest, TokenResponse
from src.application.oauth.models import OAuthGrant
from src.application.oauth.rotation import OAuthGrantRepository
from src.application.security.jwt import verify_refresh_token
from src.domain.oauth.models import Client

from .issue import issue_user_tokens


def _is_valid_oauth_grant(*, grant: OAuthGrant, client: Client, subject: str, now: datetime) -> None:
    """"""

    return not (
        grant.client_id != client.client_id
        or grant.user.user_id != subject
        or not grant.is_active(now)
    )


async def refresh_tokens(
    request: RefreshTokenRequest,
    client: Client,
    *,
    uow: UnitOfWork,
    grant_repository: OAuthGrantRepository,
) -> TokenResponse:
    """"""

    claims = verify_refresh_token(request.refresh_token)

    now = datetime.now(UTC)
    reused = False
    tokens = None

    if (grant := await grant_repository.read(claims.grant_id, for_update=True)) is None:
        raise ...

    if not _is_valid_oauth_grant(grant=grant, client=client, subject=claims.subject, now=now):
        raise ...

    if grant.current_jti != claims.jti:
        grant.revoke(now)
        await grant_repository.update(grant)
        await uow.commit()
        reused = True

    else:
        new_jti = uuid4()
        grant.rotate(expected_jti=claims.jti, new_jti=new_jti, now=now)

        tokens = issue_user_tokens(grant)

        await grant_repository.update(grant)
        await uow.commit()

    if reused:
        raise ...

    return tokens
