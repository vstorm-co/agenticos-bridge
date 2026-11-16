"""Real SQLite access checks and CLI lifecycle, without provider credentials."""

import asyncio
import json
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from agenticos_bridge.access import AccessRegistry, validate_origin
from agenticos_bridge.cli import main
from agenticos_bridge.config import Settings
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.main import create_app
from agenticos_bridge.models import ExchangeRequest, RefreshRequest, StartRequest
from agenticos_bridge.providers import ProviderClient
from agenticos_bridge.service import OAuthService, challenge
from agenticos_bridge.tickets import Tickets

ORIGIN = "https://customer.example"
VERIFIER = "a" * 64


def issue(registry: AccessRegistry, *, origin: str = ORIGIN):
    return registry.issue(
        origin=origin,
        contact="owner@example.com",
        agreement_reference="review-123",
        providers=["google"],
        expires_at=int(time.time()) + 3600,
    )


@pytest.fixture
def registry(tmp_path: Path) -> AccessRegistry:
    result = AccessRegistry(tmp_path / "access.sqlite3")
    result.initialize()
    return result


def config(registry: AccessRegistry) -> Settings:
    return Settings(
        public_url="https://bridge.example",
        ticket_key=Fernet.generate_key().decode(),
        google_client_id="app",
        google_client_secret="secret",
        access_registry=registry.path,
        _env_file=None,
    )


def test_only_hash_persists_and_expiry_revocation_provider_origin_are_enforced(registry):
    enrollment, key = issue(registry)
    raw = key.get_secret_value()
    assert raw.encode() not in registry.path.read_bytes()
    assert registry.path.stat().st_mode & 0o777 == 0o600
    assert registry.authenticate(raw, "google", ORIGIN) == enrollment
    for invalid_key, provider, origin in [
        (None, "google", ORIGIN),
        ("invalid", "google", ORIGIN),
        (raw + "x", "google", ORIGIN),
        (raw, "slack", ORIGIN),
        (raw, "google", "https://foreign.example"),
    ]:
        with pytest.raises(BridgeError, match="access_denied"):
            registry.authenticate(invalid_key, provider, origin)
    registry.revoke(enrollment.id)
    revoked = registry.list_enrollments()[0].revoked_at
    registry.revoke(enrollment.id)
    assert registry.list_enrollments()[0].revoked_at == revoked
    with pytest.raises(BridgeError, match="access_denied"):
        registry.authenticate(raw, "google")
    second, second_key = issue(registry)
    with sqlite3.connect(registry.path) as db:
        db.execute(
            "UPDATE enrollments SET record = json_set(record, '$.expires_at', ?) WHERE id = ?",
            (int(time.time()) - 1, second.id),
        )
    with pytest.raises(BridgeError, match="access_denied"):
        registry.authenticate(second_key.get_secret_value(), "google")
    with pytest.raises(BridgeError, match="access_denied"):
        registry.revoke("missing")


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*",
        "https://*.example",
        "https://customer.example/",
        "https://customer.example?x=y",
        "http://customer.example",
        "https://user:secret@customer.example",
        "https://customer.example/a",
    ],
)
def test_no_wildcard_or_callback_override(origin):
    with pytest.raises(ValueError):
        validate_origin(origin)


def test_missing_registry_fails_closed(tmp_path):
    registry = AccessRegistry(tmp_path / "missing.sqlite3")
    with pytest.raises(BridgeError, match="access_registry_unavailable"):
        registry.authenticate("ab_unknown.secret", "google")
    assert not registry.path.exists()


def test_no_http_key_management_and_key_never_appears_in_errors(registry):
    with TestClient(create_app(config(registry))) as client:
        enrollment, key = issue(registry)
        start = dict(
            provider="google",
            redirect_uri=ORIGIN + "/api/me/mcp-connections/oauth/callback",
            state="s" * 43,
            scopes=["openid"],
            code_challenge=challenge(VERIFIER),
        )
        assert not any(p["deployment_allowed"] for p in client.get("/v1/providers").json())
        assert client.post("/v1/oauth/start", json=start).status_code == 403
        headers = {"X-AgenticOS-Bridge-Key": key.get_secret_value()}
        assert client.post("/v1/oauth/start", json=start, headers=headers).status_code == 200
        metadata = client.get("/v1/providers", params={"origin": ORIGIN}, headers=headers).json()
        assert metadata[0]["deployment_allowed"]
        registry.revoke(enrollment.id)
        refused = client.post("/v1/oauth/start", json=start, headers=headers)
        assert refused.status_code == 403
        assert refused.json() == {"error": "access_denied"}
        assert key.get_secret_value() not in refused.text
        for path in ["/v1/keys", "/v1/access/issue", "/admin"]:
            assert client.post(path).status_code in {404, 405}


def test_cross_enrollment_exchange_refresh_and_revoked_callback_never_reach_provider(registry):
    first, first_key = issue(registry)
    _, other_key = issue(registry, origin="https://other.example")
    settings = config(registry)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"access_token": "token", "refresh_token": "refresh"})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            service = OAuthService(
                settings,
                ProviderClient(settings, client),
                Tickets(settings.ticket_key.get_secret_value(), settings.public_url),
            )
            request = StartRequest(
                provider="google",
                redirect_uri=ORIGIN + "/api/me/mcp-connections/oauth/callback",
                state="s" * 43,
                scopes=["openid"],
                code_challenge=challenge(VERIFIER),
            )
            started = service.start(request, first_key.get_secret_value())
            state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
            callback = service.callback("google", state, "code", None)
            ticket = parse_qs(urlsplit(callback).query)["code"][0]
            exchange = ExchangeRequest(provider="google", ticket=ticket, code_verifier=VERIFIER)
            with pytest.raises(BridgeError, match="access_denied"):
                await service.exchange(exchange, other_key.get_secret_value())
            with pytest.raises(BridgeError, match="access_denied"):
                await service.exchange(exchange)
            assert not calls
            grant = await service.exchange(exchange, first_key.get_secret_value())
            refresh = RefreshRequest(
                provider="google", receipt=grant.receipt, refresh_token=SecretStr("refresh")
            )
            with pytest.raises(BridgeError, match="access_denied"):
                await service.refresh(refresh, other_key.get_secret_value())
            assert len(calls) == 1
            registry.revoke(first.id)
            with pytest.raises(BridgeError, match="access_denied"):
                service.callback("google", state, "code", None)
            with pytest.raises(BridgeError, match="access_denied"):
                await service.exchange(exchange, first_key.get_secret_value())
            with pytest.raises(BridgeError, match="access_denied"):
                await service.refresh(refresh, first_key.get_secret_value())
            assert len(calls) == 1

    asyncio.run(scenario())


def test_console_issues_once_lists_without_hashes_and_revokes(tmp_path, monkeypatch, capsys):
    path = tmp_path / "access.sqlite3"

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["bridge", "--registry", str(path), *args])
        main()
        return capsys.readouterr().out

    run("init")
    issued = json.loads(
        run(
            "issue",
            "--origin",
            ORIGIN,
            "--contact",
            "owner@example.com",
            "--agreement-reference",
            "review-123",
            "--provider",
            "google",
        )
    )
    assert issued["access_key"].startswith("ab_")
    metadata = run("list")
    assert issued["access_key"] not in metadata and "key_hash" not in metadata
    run("revoke", issued["enrollment"]["id"])
    assert json.loads(run("list"))[0]["revoked_at"]
    with pytest.raises(SystemExit):
        run(
            "issue",
            "--origin",
            ORIGIN,
            "--contact",
            "owner@example.com",
            "--agreement-reference",
            "review-123",
            "--provider",
            "google",
            "--days",
            "0",
        )
