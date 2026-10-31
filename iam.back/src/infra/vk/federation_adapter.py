from src.application.federations.dtos import AuthorizationCallback, AuthorizationStart, UserInfo
from src.application.federations.exceptions import InvalidProviderCallbackError

from .exceptions import VkOAuthResponseError
from .oauth import VkOAuthClient


class VkFederationAdapter:
    def __init__(self, oauth_client: VkOAuthClient) -> None:
        self._oauth_client = oauth_client

    @property
    def provider(self) -> str:
        return "vk"

    def authorization_url(self, start: AuthorizationStart) -> str:
        return self._oauth_client.authorization_url(
            redirect_uri=str(start.redirect_uri),
            state=start.state,
            code_challenge=start.code_challenge,
        )

    async def authenticate(self, callback: AuthorizationCallback) -> UserInfo:
        params = callback.params
        code, state, device_id = params.get("code"), params.get("state"), params.get("device_id")

        if not code or not state or not device_id:
            raise InvalidProviderCallbackError(self.provider, "Missing VK ID callback parameters")

        if params.get("type") not in (None, "code_v2"):
            raise InvalidProviderCallbackError(self.provider, "Unsupported VK ID authorization type")

        tokens = await self._oauth_client.exchange_code(
            code=code,
            device_id=device_id,
            code_verifier=callback.code_verifier,
            redirect_uri=str(callback.redirect_uri),
            state=state,
        )

        profile = await self._oauth_client.get_user_info(tokens.access_token.get_secret_value())
        subject = str(profile.user_id)

        if tokens.user_id is not None and str(tokens.user_id) != subject:
            raise VkOAuthResponseError("VK ID user identity mismatch")

        name = " ".join(part for part in (profile.first_name, profile.last_name) if part).strip()
        return UserInfo(
            subject=subject,
            email=(profile.email or "").strip() or None,
            email_verified=profile.verified,
            display_name=name or None,
        )


__all__ = ["VkFederationAdapter"]
