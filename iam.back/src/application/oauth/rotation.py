from typing import override

from uuid import UUID

from ddf.application.repositories import Repository

from .models import OAuthGrant


class OAuthGrantRepository(Repository[OAuthGrant]):
    @override
    async def read(self, uid: UUID, for_update: bool | None = None) -> OAuthGrant | None: ...
