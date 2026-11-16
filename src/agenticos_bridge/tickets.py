import json
from typing import Literal, TypeVar

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ValidationError

from agenticos_bridge.errors import BridgeError

T = TypeVar("T", bound=BaseModel)
type Purpose = Literal["authorize", "exchange", "refresh"]
TTL: dict[Purpose, int] = {"authorize": 600, "exchange": 90, "refresh": 365 * 86400}


class Tickets:
    """Authenticated encryption; the key never leaves the bridge's server config.

    Tickets carry protocol state in the caller, not a server-side token database.
    Fernet supplies independent encryption/authentication keys, random IVs and age checks.
    Purpose and issuer prevent cross-protocol and cross-deployment substitution.
    """

    def __init__(self, key: str, issuer: str) -> None:
        self.fernet = Fernet(key.encode())
        self.issuer = issuer

    def seal(self, purpose: Purpose, value: BaseModel) -> str:
        envelope = json.dumps(
            {"purpose": purpose, "issuer": self.issuer, "value": value.model_dump(mode="json")}
        )
        return self.fernet.encrypt(envelope.encode()).decode()

    def open(self, purpose: Purpose, ticket: str, model: type[T]) -> T:
        try:
            raw = self.fernet.decrypt(ticket.encode(), ttl=TTL[purpose])
            envelope = json.loads(raw)
            if (
                not isinstance(envelope, dict)
                or envelope.get("purpose") != purpose
                or envelope.get("issuer") != self.issuer
            ):
                raise BridgeError("invalid_ticket")
            return model.model_validate(envelope.get("value"))
        except InvalidToken, UnicodeError, ValueError, ValidationError:
            raise BridgeError("invalid_ticket") from None
