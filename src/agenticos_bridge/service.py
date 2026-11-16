import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlsplit

from pydantic import SecretStr

from agenticos_bridge.config import Settings
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.models import (
    ExchangeRequest,
    FlowTicket,
    Grant,
    Provider,
    ProviderStatus,
    RefreshRequest,
    RefreshTicket,
    StartRequest,
    StartResponse,
    TokenResponse,
)
from agenticos_bridge.providers import ProviderClient
from agenticos_bridge.tickets import Tickets


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


class OAuthService:
    def __init__(self, settings: Settings, providers: ProviderClient, tickets: Tickets) -> None:
        self.settings = settings
        self.providers = providers
        self.tickets = tickets

    def metadata(self, origin: str | None = None) -> list[ProviderStatus]:
        return [
            ProviderStatus(
                provider=p,
                configured=bool(self.settings.credentials(p)[0]),
                deployment_allowed=origin in self.settings.allowed_origins
                or "*" in self.settings.allowed_origins,
                client_id=self.settings.credentials(p)[0] or None,
                redirect_uri=self.settings.callback(p),
            )
            for p in ("google", "microsoft", "slack")
        ]

    def start(self, request: StartRequest) -> StartResponse:
        client_id, _ = self.settings.require_client(request.provider)
        url = urlsplit(request.redirect_uri)
        origin = f"{url.scheme}://{url.netloc}"
        if origin not in self.settings.allowed_origins and "*" not in self.settings.allowed_origins:
            raise BridgeError("deployment_not_allowed")
        flow = FlowTicket(
            provider=request.provider,
            client_id=client_id,
            redirect_uri=request.redirect_uri,
            local_state=request.state,
            scopes=request.scopes,
            challenge=request.code_challenge,
        )
        ticket = self.tickets.seal("authorize", flow)
        return StartResponse(
            client_id=client_id,
            authorization_url=self.providers.authorize(
                request.provider, request.scopes, request.code_challenge, ticket
            ),
        )

    def _flow(self, purpose: str, provider: Provider, ticket: str) -> FlowTicket:
        if purpose == "authorize":
            flow = self.tickets.open("authorize", ticket, FlowTicket)
        else:
            flow = self.tickets.open("exchange", ticket, FlowTicket)
        client_id, _ = self.settings.require_client(provider)
        if flow.provider != provider or flow.client_id != client_id:
            raise BridgeError("invalid_ticket")
        return flow

    def callback(self, provider: Provider, state: str, code: str | None, error: str | None) -> str:
        flow = self._flow("authorize", provider, state)
        params = {"state": flow.local_state}
        if error or not code:
            params["error"] = "access_denied"
        else:
            flow.code = SecretStr(code)
            params["code"] = self.tickets.seal("exchange", flow)
        return flow.redirect_uri + "?" + urlencode(params)

    async def exchange(self, request: ExchangeRequest) -> TokenResponse:
        flow = self._flow("exchange", request.provider, request.ticket)
        if (
            not secrets.compare_digest(flow.challenge, challenge(request.code_verifier))
            or not flow.code
        ):
            raise BridgeError("invalid_proof")
        grant = await self.providers.exchange(
            request.provider, flow.code.get_secret_value(), request.code_verifier
        )
        return self._response(request.provider, grant)

    async def refresh(self, request: RefreshRequest) -> TokenResponse:
        receipt = self.tickets.open("refresh", request.receipt, RefreshTicket)
        client_id, _ = self.settings.require_client(request.provider)
        if (
            receipt.provider != request.provider
            or receipt.client_id != client_id
            or not secrets.compare_digest(
                receipt.token_digest, digest(request.refresh_token.get_secret_value())
            )
        ):
            raise BridgeError("invalid_proof")
        grant = await self.providers.refresh(
            request.provider, request.refresh_token.get_secret_value()
        )
        if grant.refresh_token is None:
            grant.refresh_token = request.refresh_token
        return self._response(request.provider, grant)

    def _response(self, provider: Provider, grant: Grant) -> TokenResponse:
        receipt = None
        if grant.refresh_token:
            receipt = self.tickets.seal(
                "refresh",
                RefreshTicket(
                    provider=provider,
                    client_id=self.settings.require_client(provider)[0],
                    token_digest=digest(grant.refresh_token.get_secret_value()),
                ),
            )
        return TokenResponse(
            access_token=grant.access_token.get_secret_value(),
            refresh_token=grant.refresh_token.get_secret_value() if grant.refresh_token else None,
            expires_in=grant.expires_in,
            scope=grant.scope,
            receipt=receipt,
        )
