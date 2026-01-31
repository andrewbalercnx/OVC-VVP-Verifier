"""Health check endpoints."""
import logging

from fastapi import APIRouter

from app.api.models import HealthResponse
from app.keri.identity import get_identity_manager

log = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    """Health check endpoint.

    Returns service status and number of loaded identities.
    """
    try:
        mgr = await get_identity_manager()
        identities = await mgr.list_identities()
        return HealthResponse(ok=True, identities_loaded=len(identities))
    except Exception as e:
        log.warning(f"Health check warning: {e}")
        return HealthResponse(ok=True, identities_loaded=0)
