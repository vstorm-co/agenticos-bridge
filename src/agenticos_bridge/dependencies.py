from typing import Annotated

from fastapi import Depends, Request

from agenticos_bridge.service import OAuthService


def get_service(request: Request) -> OAuthService:
    service = request.app.state.oauth_service
    if not isinstance(service, OAuthService):
        raise RuntimeError("OAuth service has not started")
    return service


type Service = Annotated[OAuthService, Depends(get_service)]
