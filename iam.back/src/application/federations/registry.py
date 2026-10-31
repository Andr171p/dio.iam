from .exceptions import UnsupportedProviderError
from .provider import FederationProvider

_registry: dict[str, FederationProvider] = {}


def register_federation_provider(provider: FederationProvider) -> None:
    if provider.name in _registry:
        raise ValueError(f"Provider {provider.name!r} already registered!")

    _registry[provider.name] = provider


def get_federation_provider(name: str) -> FederationProvider:
    if name not in _registry:
        raise UnsupportedProviderError(f"Unsupported provider: {name}")

    if (provider := _registry[name]).name != name:
        raise RuntimeError("Provider registry mismatch.")

    return provider
