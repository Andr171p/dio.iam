from http import HTTPStatus

from ddf.application.exceptions import ApplicationError


class UnsupportedProviderError(ApplicationError):
    status_code = HTTPStatus.BAD_REQUEST
    error_code = "unsupported_provider"


class ReauthenticationRequiredError(ApplicationError):
    status_code = HTTPStatus.FORBIDDEN
    error_code = "reauthentication_required"


class InvalidFederationStateError(ApplicationError):
    status_code = HTTPStatus.BAD_REQUEST
    error_code = "invalid_federation_state"

    def __init__(self, message: str = "The federation state is invalid or has expired.") -> None:
        super().__init__(message)


class FederationDeniedError(ApplicationError):
    """Пользователь или провайдер отклонил запрос на авторизацию."""

    status_code = HTTPStatus.BAD_REQUEST
    error_code = "federation_denied"


class InvalidProviderCallbackError(ApplicationError):
    status_code = HTTPStatus.BAD_REQUEST
    error_code = "invalid_provider_callback"

    def __init__(self, provider: str, message: str) -> None:
        super().__init__(f"[{provider}] {message}")
