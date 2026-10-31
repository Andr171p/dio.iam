from .adapter import FederationAdapter
from .exceptions import UnsupportedProviderError

_registry: dict[str, FederationAdapter] = {}


def register_federation_adapter(adapter: FederationAdapter) -> None:
    if adapter.provider in _registry:
        raise ValueError(f"Provider {adapter.provider!r} already registered!")

    _registry[adapter.provider] = adapter


def get_federation_adapter(provider: str) -> FederationAdapter:
    if provider not in _registry:
        raise UnsupportedProviderError(f"Unsupported provider: {provider}")

    if (adapter := _registry[provider]).provider != provider:
        raise RuntimeError("Provider registry mismatch.")

    return adapter
