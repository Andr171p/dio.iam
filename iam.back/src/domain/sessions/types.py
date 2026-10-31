from enum import StrEnum


class AuthMethod(StrEnum):
    PASSWORD = "password"
    FEDERATED = "federated"
    PASSKEY = "passkey"
