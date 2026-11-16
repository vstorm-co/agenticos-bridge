import json
from pathlib import Path
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, TypeAdapter, ValidationError

from agenticos_bridge.config import Settings
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.models import Grant, Provider

SCOPES = TypeAdapter(dict[str, list[str]]).validate_json(
    Path(__file__).with_name("scopes.json").read_text()
)
AUTHORIZE: dict[Provider, str] = {
    "google": "https://accounts.google.com/o/oauth2/v2/auth",
    "microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "slack": "https://slack.com/oauth/v2/authorize",
}
TOKEN: dict[Provider, str] = {
    "google": "https://oauth2.googleapis.com/token",
    "microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    "slack": "https://slack.com/api/oauth.v2.access",
}


class SlackResponse(BaseModel):
    ok: bool
    error: str | None = None
    authed_user: Grant | None = None
    token_type: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None


class ProviderClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client

    def authorize(self, provider: Provider, scopes: list[str], challenge: str, state: str) -> str:
        client_id, _ = self.settings.require_client(provider)
        if not set(scopes) <= set(SCOPES[provider]):
            raise BridgeError("unsupported_scope")
        params = {
            "client_id": client_id,
            "redirect_uri": self.settings.callback(provider),
            "response_type": "code",
            "state": state,
        }
        if provider == "slack":
            params["user_scope"] = ",".join(scopes)
        else:
            params.update(
                scope=" ".join(scopes), code_challenge=challenge, code_challenge_method="S256"
            )
            if provider == "google":
                params.update(access_type="offline", prompt="consent select_account")
            else:
                params["prompt"] = "select_account"
        return AUTHORIZE[provider] + "?" + urlencode(params)

    async def exchange(self, provider: Provider, code: str, verifier: str) -> Grant:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.callback(provider),
        }
        if provider != "slack":
            data["code_verifier"] = verifier
        return await self._request(provider, data)

    async def refresh(self, provider: Provider, token: str) -> Grant:
        return await self._request(
            provider, {"grant_type": "refresh_token", "refresh_token": token}
        )

    async def _request(self, provider: Provider, data: dict[str, str]) -> Grant:
        client_id, secret = self.settings.require_client(provider)
        data.update(client_id=client_id, client_secret=secret.get_secret_value())
        try:
            # No retries: a timeout may have consumed the code or rotating refresh token.
            async with self.client.stream("POST", TOKEN[provider], data=data) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 65536:
                        raise BridgeError("invalid_provider_response", upstream=True)
                if not response.is_success:
                    raise BridgeError("provider_refused_grant", upstream=True)
                if provider == "slack":
                    parsed = SlackResponse.model_validate_json(body)
                    if not parsed.ok:
                        raise BridgeError("provider_refused_grant", upstream=True)
                    if parsed.authed_user is not None:
                        return parsed.authed_user
                    if parsed.token_type != "user" or parsed.access_token is None:
                        raise BridgeError("invalid_provider_response", upstream=True)
                    return Grant.model_validate(parsed.model_dump())
                return Grant.model_validate_json(body)
        except httpx.HTTPError:
            raise BridgeError("provider_unavailable", upstream=True) from None
        except ValidationError, json.JSONDecodeError:
            raise BridgeError("invalid_provider_response", upstream=True) from None
