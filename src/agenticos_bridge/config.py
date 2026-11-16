from typing import Self
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agenticos_bridge.errors import BridgeError
from agenticos_bridge.models import Provider


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BRIDGE_", env_file=".env", extra="ignore", hide_input_in_errors=True
    )
    public_url: str
    ticket_key: SecretStr
    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    microsoft_client_id: str = ""
    microsoft_client_secret: SecretStr = SecretStr("")
    slack_client_id: str = ""
    slack_client_secret: SecretStr = SecretStr("")
    # Exact origins; empty means a deliberately closed service until enrollment policy is set.
    allowed_origins: list[str] = []

    @field_validator("public_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            raise ValueError("public_url must be an HTTPS origin")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_credentials(self) -> Self:
        Fernet(self.ticket_key.get_secret_value().encode())
        for provider in ("google", "microsoft", "slack"):
            client_id, secret = self.credentials(provider)
            if bool(client_id) != bool(secret.get_secret_value()):
                raise ValueError(f"Configure both client ID and secret for {provider}")
        return self

    def credentials(self, provider: Provider) -> tuple[str, SecretStr]:
        if provider == "google":
            return self.google_client_id, self.google_client_secret
        if provider == "microsoft":
            return self.microsoft_client_id, self.microsoft_client_secret
        return self.slack_client_id, self.slack_client_secret

    def require_client(self, provider: Provider) -> tuple[str, SecretStr]:
        client_id, secret = self.credentials(provider)
        if not client_id or not secret.get_secret_value():
            raise BridgeError("provider_not_configured")
        return client_id, secret

    def callback(self, provider: Provider) -> str:
        return f"{self.public_url}/v1/oauth/callback/{provider}"
