from typing import Annotated

from fastapi import Request

from src.domain.sessions.models import AuthenticationSession


async def get_optional_authentication_session(request: Request[...]) -> AuthenticationSession | None: ...
