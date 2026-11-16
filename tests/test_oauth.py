import asyncio
import base64
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from agenticos_bridge.config import Settings
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.main import create_app
from agenticos_bridge.models import (
    ExchangeRequest,
    FlowTicket,
    RefreshRequest,
    StartRequest,
)
from agenticos_bridge.providers import ProviderClient
from agenticos_bridge.service import OAuthService, challenge
from agenticos_bridge.tickets import Tickets

VERIFIER = "a" * 64
ORIGIN = "https://customer.example"
CALLBACK = ORIGIN + "/api/me/mcp-connections/oauth/callback"


@pytest.fixture
def config() -> Settings:
    return Settings(
        public_url="https://bridge.example",
        ticket_key=SecretStr(Fernet.generate_key().decode()),
        google_client_id="google-app",
        google_client_secret=SecretStr("app-secret"),
        microsoft_client_id="ms-app",
        microsoft_client_secret=SecretStr("ms-secret"),
        slack_client_id="slack-app",
        slack_client_secret=SecretStr("slack-secret"),
        allowed_origins=[ORIGIN],
        _env_file=None,
    )


def request(provider="google") -> StartRequest:
    return StartRequest(
        provider=provider,
        redirect_uri=CALLBACK,
        state="s" * 43,
        code_challenge=challenge(VERIFIER),
        scopes=["openid"] if provider != "slack" else ["channels:read"],
    )


def build(config: Settings, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tickets = Tickets(config.ticket_key.get_secret_value(), config.public_url)
    return OAuthService(config, ProviderClient(config, client), tickets), client


def complete(service: OAuthService, provider="google") -> str:
    started = service.start(request(provider))
    state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
    callback = service.callback(provider, state, "upstream-code-secret", None)
    assert "upstream-code-secret" not in callback
    assert parse_qs(urlsplit(callback).query)["state"] == ["s" * 43]
    return parse_qs(urlsplit(callback).query)["code"][0]


@pytest.mark.parametrize("provider", ["google", "microsoft", "slack"])
def test_round_trip_and_rotation(config, provider):
    calls = []

    def handler(req):
        data = parse_qs(req.content.decode())
        calls.append(data)
        assert data["client_secret"] == [
            {"google": "app-secret", "microsoft": "ms-secret", "slack": "slack-secret"}[provider]
        ]
        if data["grant_type"] == ["authorization_code"]:
            assert data["code"] == ["upstream-code-secret"]
            grant = {
                "access_token": "access-secret",
                "refresh_token": "refresh-secret",
                "expires_in": 3600,
                "scope": "openid",
            }
        else:
            assert data["refresh_token"] == ["refresh-secret"]
            grant = {
                "access_token": "new-access",
                "refresh_token": "rotated-refresh",
                "expires_in": 3600,
            }
        return httpx.Response(
            200, json={"ok": True, "authed_user": grant} if provider == "slack" else grant
        )

    async def scenario():
        service, client = build(config, handler)
        async with client:
            ticket = complete(service, provider)
            result = await service.exchange(
                ExchangeRequest(provider=provider, ticket=ticket, code_verifier=VERIFIER)
            )
            assert result.access_token == "access-secret"
            assert result.receipt and "refresh-secret" not in result.receipt
            assert "access-secret" not in repr(result)
            rotated = await service.refresh(
                RefreshRequest(
                    provider=provider,
                    receipt=result.receipt,
                    refresh_token=SecretStr("refresh-secret"),
                )
            )
            assert rotated.refresh_token == "rotated-refresh"
            assert rotated.receipt != result.receipt
            with pytest.raises(BridgeError, match="invalid_proof"):
                await service.refresh(
                    RefreshRequest(
                        provider=provider,
                        receipt=result.receipt,
                        refresh_token=SecretStr("someone-elses-token"),
                    )
                )
            assert len(calls) == 2

    asyncio.run(scenario())


def test_proofs_fail_before_provider_call(config):
    def never(req):
        pytest.fail("Refused proof reached provider")

    async def scenario():
        service, client = build(config, never)
        async with client:
            ticket = complete(service)
            for provider, verifier in [("google", "b" * 64), ("microsoft", VERIFIER)]:
                with pytest.raises(BridgeError):
                    await service.exchange(
                        ExchangeRequest(provider=provider, ticket=ticket, code_verifier=verifier)
                    )
            with pytest.raises(BridgeError):
                await service.exchange(
                    ExchangeRequest(
                        provider="google", ticket=ticket[:-5] + "xxxxx", code_verifier=VERIFIER
                    )
                )
            config.google_client_id = "replacement-client"
            with pytest.raises(BridgeError):
                await service.exchange(
                    ExchangeRequest(provider="google", ticket=ticket, code_verifier=VERIFIER)
                )

    asyncio.run(scenario())


def test_ticket_expiry_purpose_issuer_and_confidentiality(config):
    tickets = Tickets(config.ticket_key.get_secret_value(), config.public_url)
    flow = FlowTicket(
        provider="google",
        client_id="google-app",
        redirect_uri=CALLBACK,
        local_state="s" * 43,
        scopes=["openid"],
        challenge=challenge(VERIFIER),
        code=SecretStr("code-secret"),
    )
    ticket = tickets.seal("authorize", flow)
    assert b"code-secret" not in base64.urlsafe_b64decode(ticket)
    assert tickets.open("authorize", ticket, FlowTicket).code.get_secret_value() == "code-secret"
    with pytest.raises(BridgeError):
        tickets.open("exchange", ticket, FlowTicket)
    with pytest.raises(BridgeError):
        Tickets(config.ticket_key.get_secret_value(), "https://other.example").open(
            "authorize", ticket, FlowTicket
        )
    raw = tickets.fernet.decrypt(ticket.encode())
    expired = tickets.fernet.encrypt_at_time(raw, int(time.time()) - 601).decode()
    with pytest.raises(BridgeError):
        tickets.open("authorize", expired, FlowTicket)


@pytest.mark.parametrize(
    "uri",
    [
        "http://customer.example/api/me/mcp-connections/oauth/callback",
        "https://user:password@customer.example/api/me/mcp-connections/oauth/callback",
        CALLBACK + "?next=https://evil.example",
        CALLBACK + "#token",
        "https://customer.example/evil",
        "https://customer.example\\@evil.example/api/me/mcp-connections/oauth/callback",
    ],
)
def test_reject_callback_injection(uri):
    with pytest.raises(ValidationError):
        StartRequest.model_validate({**request().model_dump(), "redirect_uri": uri})


def test_enrollment_scope_and_provider_readiness(config):
    async def scenario():
        service, client = build(config, lambda req: httpx.Response(500))
        async with client:
            config.allowed_origins = []
            with pytest.raises(BridgeError, match="deployment_not_allowed"):
                service.start(request())
            config.allowed_origins = [ORIGIN]
            invalid = request()
            invalid.scopes = ["https://evil.example/admin"]
            with pytest.raises(BridgeError, match="unsupported_scope"):
                service.start(invalid)
            config.google_client_id = ""
            with pytest.raises(BridgeError, match="provider_not_configured"):
                service.start(request())

    asyncio.run(scenario())


def test_api_security_errors_headers_and_no_browser_tokens(config, caplog):
    with TestClient(create_app(config)) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        response = client.post(
            "/v1/oauth/refresh", json={"refresh_token": "SECRET-INPUT", "receipt": "bad"}
        )
        assert response.status_code == 422
        assert "SECRET-INPUT" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert client.get("/docs").status_code == 404
        assert client.get(
            "/v1/oauth/callback/google", params={"state": "bad", "code": "SECRET-CODE"}
        ).json() == {"error": "invalid_ticket"}
        assert "SECRET-CODE" not in caplog.text
        oversized = client.post(
            "/v1/oauth/start", content=b"x" * 70000, headers={"content-type": "application/json"}
        )
        assert oversized.status_code == 413


def test_provider_failure_never_returns_upstream_body(config):
    async def scenario():
        for response in [
            httpx.Response(400, text="client_secret=LEAK"),
            httpx.Response(200, json={"unexpected": "LEAK"}),
            httpx.Response(200, content=b"x" * 70000),
        ]:
            service, client = build(config, lambda req, response=response: response)
            async with client:
                ticket = complete(service)
                with pytest.raises(BridgeError) as error:
                    await service.exchange(
                        ExchangeRequest(provider="google", ticket=ticket, code_verifier=VERIFIER)
                    )
                assert "LEAK" not in str(error.value)

    asyncio.run(scenario())


def test_metadata_does_not_offer_shared_app_to_unenrolled_origins(config):
    async def scenario():
        service, client = build(config, lambda req: httpx.Response(500))
        async with client:
            assert all(p.configured and p.deployment_allowed for p in service.metadata(ORIGIN))
            assert not any(
                p.deployment_allowed for p in service.metadata("https://foreign.example")
            )
            config.allowed_origins = ["*"]
            assert all(p.deployment_allowed for p in service.metadata("https://foreign.example"))

    asyncio.run(scenario())


def test_bad_config_errors_hide_secret_input():
    with pytest.raises(ValidationError) as error:
        Settings(
            public_url="https://bridge.example", ticket_key="SECRET-INVALID-KEY", _env_file=None
        )
    assert "SECRET-INVALID-KEY" not in str(error.value)


@pytest.mark.parametrize("provider", ["google", "microsoft", "slack"])
def test_revocation_is_explicit_and_never_exposes_provider_error(config, provider):
    async def scenario():
        service, client = build(
            config,
            lambda req: httpx.Response(
                200 if provider == "slack" else 400,
                json={"ok": False, "error": "invalid_grant", "error_description": "SECRET"},
            ),
        )
        async with client:
            ticket = complete(service, provider)
            with pytest.raises(BridgeError, match="provider_grant_revoked") as refused:
                await service.exchange(
                    ExchangeRequest(provider=provider, ticket=ticket, code_verifier=VERIFIER)
                )
            assert "SECRET" not in str(refused.value)

    asyncio.run(scenario())
