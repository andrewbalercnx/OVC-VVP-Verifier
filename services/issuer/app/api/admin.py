"""Admin endpoints for VVP Issuer.

Provides administrative operations like API key config reload.
All endpoints require issuer:admin role.
"""

import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.auth.api_key import get_api_key_store, Principal
from app.auth.roles import require_admin
from app.audit import get_audit_logger

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


class AuthReloadResponse(BaseModel):
    """Response for auth reload endpoint."""

    success: bool
    key_count: int
    version: int
    message: str


@router.post("/auth/reload", response_model=AuthReloadResponse)
async def reload_auth_config(
    request: Request,
    principal: Principal = require_admin,
) -> AuthReloadResponse:
    """Reload API keys configuration from file.

    Forces an immediate reload of the API keys configuration,
    picking up any new, modified, or revoked keys.

    Requires: issuer:admin role
    """
    store = get_api_key_store()
    audit = get_audit_logger()

    success = store.reload()

    if success:
        audit.log_auth_reload(
            principal_id=principal.key_id,
            key_count=store.key_count,
            request=request,
        )
        return AuthReloadResponse(
            success=True,
            key_count=store.key_count,
            version=store.version,
            message=f"Reloaded {store.key_count} API keys",
        )
    else:
        return AuthReloadResponse(
            success=False,
            key_count=store.key_count,
            version=store.version,
            message="Failed to reload API keys",
        )


class AuthStatusResponse(BaseModel):
    """Response for auth status endpoint."""

    enabled: bool
    key_count: int
    version: int
    reload_interval: int


@router.get("/auth/status", response_model=AuthStatusResponse)
async def get_auth_status(
    principal: Principal = require_admin,
) -> AuthStatusResponse:
    """Get current authentication status.

    Returns information about the current auth configuration.

    Requires: issuer:admin role
    """
    from app.config import AUTH_ENABLED, AUTH_RELOAD_INTERVAL

    store = get_api_key_store()

    return AuthStatusResponse(
        enabled=AUTH_ENABLED,
        key_count=store.key_count,
        version=store.version,
        reload_interval=AUTH_RELOAD_INTERVAL,
    )
