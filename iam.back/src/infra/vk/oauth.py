from typing import Any

import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from http import HTTPStatus
from urllib.parse import urlencode

import aiohttp
from pydantic import ValidationError

from .config import VkOAuthConfig
from .dtos import VkIdUser, VkTokens
from .exceptions import VkOAuthRequestError, VkOAuthResponseError, VkOAuthStateError


class VkOAuthClient:
    def __init__(self, config: VkOAuthConfig) -> None:
        self._config = config
        self._session: aiohttp.ClientSession | None = None

    @asynccontextmanager
    async def _get_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._config.timeout, connect=self._config.connect_timeout)
            connector = aiohttp.TCPConnector(
                limit=self._config.pool_limit,
                limit_per_host=self._config.pool_limit_per_host,
                keepalive_timeout=self._config.keepalive_timeout,
            )
            self._session = aiohttp.ClientSession(
                base_url=self._config.base_url,
                timeout=timeout,
                connector=connector,
            )

        try:
            yield self._session
        finally:
            pass

    async def _post_request(
        self,
        path: str,
        *,
        params: Mapping[str, str],
        form: Mapping[str, str],
    ) -> Mapping[str, Any]:
        """Выполняет HTTP POST запрос к VK ID и валидирует результат."""

        headers = {"Accept": "application/json"}

        try:
            async with (
                self._get_session() as session,
                session.post(
                    path,
                    params=params,
                    data=form,
                    headers=headers,
                    allow_redirects=False,
                ) as response
            ):
                if not HTTPStatus.OK <= response.status < HTTPStatus.MULTIPLE_CHOICES:
                    raise VkOAuthResponseError(f"VK ID returned HTTP {response.status}")

                data = await response.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise VkOAuthRequestError("VK ID is unavailable") from exc
        except (ValueError, UnicodeError):
            raise VkOAuthResponseError("Invalid VK ID JSON response") from None

        if not isinstance(data, dict):
            raise VkOAuthResponseError("Unexpected VK ID response format")

        if "error" in data:
            raise VkOAuthResponseError("VK ID rejected the request")

        return data

    def authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_challenge: str,
    ) -> str:
        """Формирует URL авторизации VK ID."""

        params = {
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "s256",
        }

        if self._config.scope:
            params["scope"] = self._config.scope

        if self._config.prompt:
            params["prompt"] = self._config.prompt

        return f"{self._config.base_url}/authorize?{urlencode(params)}"

    async def exchange_code(
        self,
        *,
        code: str,
        device_id: str,
        code_verifier: str,
        redirect_uri: str,
        state: str,
    ) -> VkTokens:
        """Обменивает authorization code на токены VK ID."""

        params = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "state": state,
            "device_id": device_id,
        }

        data = await self._post_request("/oauth/auth", params=params, form={"code": code})

        try:
            tokens = VkTokens.model_validate(data)
        except ValidationError as exc:
            raise VkOAuthResponseError("Invalid VK ID response") from exc

        if not secrets.compare_digest(tokens.state, state):
            raise VkOAuthStateError("VK ID state mismatch")

        return tokens

    async def refresh_token(
        self,
        *,
        refresh_token: str,
        device_id: str,
        redirect_uri: str,
        state: str,
    ) -> VkTokens:
        """Обновляет токены VK ID."""

        params = {
            "grant_type": "refresh_token",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "device_id": device_id,
            "state": state,
        }
        form = {"refresh_token": refresh_token}

        data = await self._post_request("/oauth2/auth", params=params, form=form)

        try:
            tokens = VkTokens.model_validate(data)
        except ValidationError as exc:
            raise VkOAuthResponseError("Invalid VK ID response") from exc

        if not secrets.compare_digest(tokens.state, state):
            raise VkOAuthStateError("VK ID state mismatch")

        return tokens

    async def get_user_info(self, access_token: str) -> VkIdUser:
        """Получает профиль пользователя VK ID."""

        data = await self._post_request(
            "/oauth2/user_info",
            params={"client_id": self._config.client_id},
            form={"access_token": access_token},
        )

        try:
            user = VkIdUser.model_validate(data.get("user", {}))
        except ValidationError as exc:
            raise VkOAuthResponseError("Invalid VK ID user info response") from exc

        return user

    async def close(self) -> None:
        if self._session is None or self._session.closed:
            return

        await self._session.close()
        self._session = None


__all__ = ["VkOAuthClient"]
