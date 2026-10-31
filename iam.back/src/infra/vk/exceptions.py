
class VkOAuthError(Exception):
    """Базовая ошибка интеграции с VK ID."""


class VkOAuthRequestError(VkOAuthError):
    """Сетевая ошибка или недоступность VK ID."""


class VkOAuthResponseError(VkOAuthError):
    """VK ID вернул ошибку или некорректный ответ."""


class VkOAuthStateError(VkOAuthError):
    """VK ID вернул несовпадающий state."""
