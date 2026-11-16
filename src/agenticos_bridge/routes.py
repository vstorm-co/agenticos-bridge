import asyncio
from typing import Annotated

from fastapi import APIRouter, Header, Query
from fastapi.responses import RedirectResponse

from agenticos_bridge.dependencies import Service
from agenticos_bridge.models import (
    ExchangeRequest,
    Provider,
    ProviderStatus,
    RefreshRequest,
    StartRequest,
    StartResponse,
    TokenResponse,
)

router = APIRouter()
type AccessKey = Annotated[str | None, Header(alias="X-AgenticOS-Bridge-Key", max_length=256)]


@router.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/v1/providers", response_model=list[ProviderStatus])
async def providers(
    service: Service,
    key: AccessKey = None,
    origin: Annotated[str | None, Query(max_length=2048)] = None,
) -> list[ProviderStatus]:
    return await asyncio.to_thread(service.metadata, origin, key)


@router.post("/v1/oauth/start", response_model=StartResponse)
async def start(request: StartRequest, service: Service, key: AccessKey = None) -> StartResponse:
    return await asyncio.to_thread(service.start, request, key)


@router.get("/v1/oauth/callback/{provider}")
async def callback(
    provider: Provider,
    service: Service,
    state: Annotated[str, Query(min_length=1, max_length=24000)],
    code: Annotated[str | None, Query(max_length=8192)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
) -> RedirectResponse:
    return RedirectResponse(
        await asyncio.to_thread(service.callback, provider, state, code, error), status_code=302
    )


@router.post("/v1/oauth/token", response_model=TokenResponse)
async def exchange(
    request: ExchangeRequest, service: Service, key: AccessKey = None
) -> TokenResponse:
    return await service.exchange(request, key)


@router.post("/v1/oauth/refresh", response_model=TokenResponse)
async def refresh(
    request: RefreshRequest, service: Service, key: AccessKey = None
) -> TokenResponse:
    return await service.refresh(request, key)
