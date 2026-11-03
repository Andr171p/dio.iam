from src.application.oauth.dtos import ClientCredentialsRequest, TokenResponse
from src.application.security.jwt import CreateAccessTokenDTO, create_access_token
from src.domain.oauth.models import Client


async def issue_client_token(request: ClientCredentialsRequest, client: Client) -> TokenResponse:
    """Выпускает access токен для аутентифицированного клиента."""
