from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agenticos_bridge.config import Settings
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.providers import ProviderClient
from agenticos_bridge.routes import router
from agenticos_bridge.service import OAuthService
from agenticos_bridge.tickets import Tickets


class SecurityHeaders:
    """Bound streamed requests too, and omit input values from error responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        size = 0
        oversized = False

        async def bounded_receive() -> Message:
            nonlocal size, oversized
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > 65536:
                    oversized = True
                    raise BridgeError("request_too_large")
            return message

        async def safe_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                if oversized:
                    message["status"] = 413
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                        (b"strict-transport-security", b"max-age=31536000"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, bounded_receive, safe_send)


async def bridge_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, BridgeError):
        raise exc
    return JSONResponse({"error": exc.code}, status_code=502 if exc.upstream else 400)


async def invalid_request(request: Request, exc: Exception) -> JSONResponse:
    # FastAPI's default contains rejected input, including secrets.
    return JSONResponse({"error": "invalid_request"}, status_code=422)


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        config = settings or Settings()
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=False, limits=httpx.Limits(max_connections=32)
        ) as client:
            app.state.oauth_service = OAuthService(
                config,
                ProviderClient(config, client),
                Tickets(config.ticket_key.get_secret_value(), config.public_url),
            )
            yield

    app = FastAPI(
        title="AgenticOS Bridge", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    app.add_middleware(SecurityHeaders)
    app.add_exception_handler(BridgeError, bridge_error)
    app.add_exception_handler(RequestValidationError, invalid_request)
    app.include_router(router)
    return app
