from dataclasses import dataclass

from ddf.domain.models import AggregateRoot

from src.domain.identity.vo import SecretHash

from .types import ClientAuthMethod, GrantType


@dataclass(kw_only=True)
class Client(AggregateRoot):
    """"""

    name: str
    description: str | None = None

    client_id: str
    client_secret_hash: SecretHash
    redirect_uris: set[str]
    auth_method: ClientAuthMethod
    allowed_grant_types: set[GrantType]

    is_active: bool = True
