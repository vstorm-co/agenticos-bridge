import asyncio
import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlsplit

from pydantic import SecretStr

from agenticos_bridge.access import AccessRegistry
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
        self.access = AccessRegistry(settings.access_registry.resolve())

    def metadata(self, origin: str | None = None, key: str | None = None) -> list[ProviderStatus]:
        result: list[ProviderStatus] = []
        for provider in ("google", "microsoft", "slack"):
            allowed = False
            try:
                self.access.authenticate(key, provider, origin)
                allowed = origin is not None
            except BridgeError as exc:
                if exc.code != "access_denied":
                    raise
            result.append(
                ProviderStatus(
                    provider=provider,
                    configured=bool(self.settings.credentials(provider)[0]),
                    deployment_allowed=allowed,
                    client_id=self.settings.credentials(provider)[0] or None,
                    redirect_uri=self.settings.callback(provider),
                )
            )
        return result

    def start(self, request: StartRequest, key: str | None = None) -> StartResponse:
        url = urlsplit(request.redirect_uri)
        origin = f"{url.scheme}://{url.netloc}"
        enrollment = self.access.authenticate(key, request.provider, origin)
        client_id, _ = self.settings.require_client(request.provider)
        flow = FlowTicket(
            enrollment_id=enrollment.id,
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
        self.access.require_active(flow.enrollment_id, provider)
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

    async def exchange(self, request: ExchangeRequest, key: str | None = None) -> TokenResponse:
        enrollment = await asyncio.to_thread(self.access.authenticate, key, request.provider)
        flow = await asyncio.to_thread(self._flow, "exchange", request.provider, request.ticket)
        if flow.enrollment_id != enrollment.id:
            raise BridgeError("access_denied")
        if (
            not secrets.compare_digest(flow.challenge, challenge(request.code_verifier))
            or not flow.code
        ):
            raise BridgeError("invalid_proof")
        grant = await self.providers.exchange(
            request.provider, flow.code.get_secret_value(), request.code_verifier
        )
        return self._response(request.provider, grant, enrollment.id)

    async def refresh(self, request: RefreshRequest, key: str | None = None) -> TokenResponse:
        enrollment = await asyncio.to_thread(self.access.authenticate, key, request.provider)
        receipt = self.tickets.open("refresh", request.receipt, RefreshTicket)
        if receipt.enrollment_id != enrollment.id:
            raise BridgeError("access_denied")
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
        return self._response(request.provider, grant, enrollment.id)

    def _response(self, provider: Provider, grant: Grant, enrollment_id: str) -> TokenResponse:
        receipt = None
        if grant.refresh_token:
            receipt = self.tickets.seal(
                "refresh",
                RefreshTicket(
                    enrollment_id=enrollment_id,
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
