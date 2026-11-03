from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SecretHash:
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("Secret hash cannot be empty")

    def __repr__(self) -> str:
        return "SecretHash(******)"

    def __str__(self) -> str:
        return "******"

    def get_hashed_value(self) -> str:
        return self.value
