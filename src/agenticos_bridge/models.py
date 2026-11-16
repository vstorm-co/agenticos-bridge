from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer, field_validator

type Provider = Literal["google", "microsoft", "slack"]
type Challenge = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
type Verifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9._~-]{43,128}$")]
type Ticket = Annotated[str, Field(min_length=1, max_length=24000)]


class StartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Provider
    redirect_uri: Annotated[str, Field(max_length=2048)]
    state: Annotated[str, Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")]
    scopes: Annotated[
        list[Annotated[str, Field(max_length=200)]], Field(min_length=1, max_length=64)
    ]
    code_challenge: Challenge

    @field_validator("redirect_uri")
    @classmethod
    def validate_callback(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            and not (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"})
        ) or (
            not url.hostname
            or url.username
            or url.password
            or url.fragment
            or url.query
            or url.path != "/api/me/mcp-connections/oauth/callback"
            or any(ord(c) <= 32 or c in "\\" for c in value)
        ):
            raise ValueError("Use the AgenticOS HTTPS callback (HTTP only on loopback)")
        _ = url.port
        return value


class StartResponse(BaseModel):
    authorization_url: str
    client_id: str


class ExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Provider
    ticket: Ticket
    code_verifier: Verifier


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Provider
    receipt: Ticket
    refresh_token: Annotated[SecretStr, Field(min_length=1, max_length=16384)]


class Grant(BaseModel):
    access_token: Annotated[SecretStr, Field(min_length=1, max_length=16384)]
    refresh_token: SecretStr | None = None
    expires_in: Annotated[int | None, Field(gt=0)] = None
    scope: str | None = None
    token_type: Literal["Bearer", "bearer"] = "Bearer"


class TokenResponse(BaseModel):
    # Explicit wire serialization lives at this one response boundary.
    access_token: str = Field(repr=False)
    refresh_token: str | None = Field(default=None, repr=False)
    expires_in: int | None = None
    scope: str | None = None
    receipt: str | None = Field(default=None, repr=False)


class FlowTicket(BaseModel):
    enrollment_id: str
    provider: Provider
    client_id: str
    redirect_uri: str
    local_state: str
    scopes: list[str]
    challenge: str
    code: SecretStr | None = None

    @field_serializer("code", when_used="json")
    def serialize_code(self, value: SecretStr | None) -> str | None:
        return value.get_secret_value() if value else None


class RefreshTicket(BaseModel):
    enrollment_id: str
    provider: Provider
    client_id: str
    token_digest: str


class ProviderStatus(BaseModel):
    provider: Provider
    configured: bool
    deployment_allowed: bool
    client_id: str | None
    redirect_uri: str
