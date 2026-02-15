"""Session management endpoints.

Sprint 67: Org context switching for admin users.
"""

import logging
from dataclasses import replace
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from app.auth.api_key import Principal
from app.auth.roles import require_admin
from app.audit import get_audit_logger
from app.db.models import Organization
from app.db.session import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/session", tags=["session"])


class SwitchOrgRequest(BaseModel):
    """Request to switch org context."""

    organization_id: Optional[str] = Field(
        None,
        description="Target org ID. Null reverts to home org.",
    )


class SwitchOrgResponse(BaseModel):
    """Response after org switch."""

    active_org_id: Optional[str] = Field(None, description="Current active org (null = home)")
    active_org_name: Optional[str] = None
    active_org_type: Optional[str] = None
    home_org_id: Optional[str] = Field(None, description="Admin's own org")
    home_org_name: Optional[str] = None


@router.post("/switch-org", response_model=SwitchOrgResponse)
async def switch_org(
    body: SwitchOrgRequest,
    http_request: Request,
    principal: Principal = require_admin,
    db: DBSession = Depends(get_db),
) -> SwitchOrgResponse:
    """Switch the active organization context.

    Sprint 67: Allows admins to "act on behalf of" another org.
    Setting organization_id=null reverts to the admin's home org.

    **Authentication:** Requires `issuer:admin` role.
    """
    from app.auth.session import get_session_store

    audit = get_audit_logger()
    session_store = get_session_store()

    # Resolve the current session
    session_id = None
    if hasattr(http_request, "cookies"):
        session_id = http_request.cookies.get("vvp_session")
    if not session_id:
        raise HTTPException(
            status_code=400,
            detail="Session-based authentication required for org switching.",
        )

    session = await session_store.get(session_id)
    if session is None:
        audit.log(
            action="session.switch_org",
            principal=principal.key_id,
            resource_type="session",
            resource_id=session_id[:8] if session_id else "unknown",
            details={"outcome": "denied", "reason": "session_not_found"},
        )
        raise HTTPException(status_code=401, detail="Session not found or expired")

    # Note: session from get() may be a clone (Sprint 67 principal override).
    # Use session_store.set_active_org() to update the *stored* session.
    from_org = session.active_org_id or session.home_org_id

    if body.organization_id is None:
        # Revert to home org
        await session_store.set_active_org(session_id, None)
        log.info(f"Session {session_id[:8]}... reverted to home org")

        audit.log(
            action="session.switch_org",
            principal=principal.key_id,
            resource_type="session",
            resource_id=session_id[:8],
            details={
                "action_type": "revert",
                "from_org": from_org,
                "to_org": "home",
                "outcome": "success",
            },
        )
    else:
        # Switch to target org
        target_org = db.query(Organization).filter(
            Organization.id == body.organization_id
        ).first()
        if target_org is None:
            audit.log(
                action="session.switch_org",
                principal=principal.key_id,
                resource_type="session",
                resource_id=session_id[:8],
                details={
                    "action_type": "switch",
                    "from_org": from_org,
                    "to_org": body.organization_id,
                    "outcome": "denied",
                    "reason": "org_not_found",
                },
            )
            raise HTTPException(status_code=404, detail="Organization not found")
        if not target_org.enabled:
            audit.log(
                action="session.switch_org",
                principal=principal.key_id,
                resource_type="session",
                resource_id=session_id[:8],
                details={
                    "action_type": "switch",
                    "from_org": from_org,
                    "to_org": body.organization_id,
                    "outcome": "denied",
                    "reason": "org_disabled",
                },
            )
            raise HTTPException(status_code=400, detail="Organization is disabled")

        await session_store.set_active_org(session_id, body.organization_id)
        log.info(
            f"Session {session_id[:8]}... switched to org "
            f"{target_org.name} ({target_org.id[:8]}...)"
        )

        audit.log(
            action="session.switch_org",
            principal=principal.key_id,
            resource_type="session",
            resource_id=session_id[:8],
            details={
                "action_type": "switch",
                "from_org": from_org,
                "to_org": body.organization_id,
                "outcome": "success",
            },
        )

    # Build response using body.organization_id (the new active org),
    # not session.active_org_id (which may be stale on the clone).
    new_active_org_id = body.organization_id
    active_org = None
    if new_active_org_id:
        active_org = db.query(Organization).filter(
            Organization.id == new_active_org_id
        ).first()

    home_org = None
    if session.home_org_id:
        home_org = db.query(Organization).filter(
            Organization.id == session.home_org_id
        ).first()

    return SwitchOrgResponse(
        active_org_id=new_active_org_id,
        active_org_name=active_org.name if active_org else None,
        active_org_type=active_org.org_type if active_org else None,
        home_org_id=session.home_org_id,
        home_org_name=home_org.name if home_org else None,
    )
