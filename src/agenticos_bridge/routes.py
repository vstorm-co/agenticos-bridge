from typing import Annotated

from fastapi import APIRouter, Query
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


@router.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/v1/providers", response_model=list[ProviderStatus])
async def providers(service: Service) -> list[ProviderStatus]:
    return service.metadata()


@router.post("/v1/oauth/start", response_model=StartResponse)
async def start(request: StartRequest, service: Service) -> StartResponse:
    return service.start(request)


@router.get("/v1/oauth/callback/{provider}")
async def callback(
    provider: Provider,
    service: Service,
    state: Annotated[str, Query(min_length=1, max_length=24000)],
    code: Annotated[str | None, Query(max_length=8192)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
) -> RedirectResponse:
    return RedirectResponse(service.callback(provider, state, code, error), status_code=302)


@router.post("/v1/oauth/token", response_model=TokenResponse)
async def exchange(request: ExchangeRequest, service: Service) -> TokenResponse:
    return await service.exchange(request)


@router.post("/v1/oauth/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest, service: Service) -> TokenResponse:
    return await service.refresh(request)
