"""Identity management endpoints."""
import logging

from fastapi import APIRouter, HTTPException, Request

from app.api.models import (
    CreateIdentityRequest,
    CreateIdentityResponse,
    DeleteResponse,
    IdentityResponse,
    IdentityListResponse,
    OobiResponse,
    RotateIdentityRequest,
    RotateIdentityResponse,
    WitnessPublishDetail,
    WitnessPublishResult,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_readonly
from app.audit import get_audit_logger
from app.config import WITNESS_IURLS, WITNESS_OOBI_BASE_URLS
from app.keri.identity import get_identity_manager
from app.keri.witness import get_witness_publisher
from app.keri.exceptions import (
    IdentityNotFoundError,
    NonTransferableIdentityError,
    InvalidRotationThresholdError,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity", tags=["identity"])


def _get_oobi_base_urls() -> list[str]:
    """Get base URLs for external OOBI generation.

    Uses oobi_base_urls if configured (for public/external URLs),
    otherwise falls back to extracting from iurls for backwards compatibility.
    """
    if WITNESS_OOBI_BASE_URLS:
        return WITNESS_OOBI_BASE_URLS
    # Fallback: extract from iurls (may contain internal Docker hostnames)
    if not WITNESS_IURLS:
        log.warning("No OOBI base URLs configured - OOBIs may be unreachable externally")
    return [iurl.split("/oobi/")[0] for iurl in WITNESS_IURLS if "/oobi/" in iurl]


@router.post("", response_model=CreateIdentityResponse)
async def create_identity(
    request: CreateIdentityRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> CreateIdentityResponse:
    """Create a new KERI identity.

    Creates an identity with the specified parameters and optionally
    publishes its OOBI to configured witnesses.

    Requires: issuer:admin role
    """
    mgr = await get_identity_manager()
    audit = get_audit_logger()

    try:
        # Create the identity
        info = await mgr.create_identity(
            name=request.name,
            transferable=request.transferable,
            icount=request.key_count,
            isith=request.key_threshold,
            ncount=request.next_key_count,
            nsith=request.next_threshold,
        )

        # Generate OOBI URLs using external base URLs
        oobi_urls = [
            mgr.get_oobi_url(info.aid, base_url)
            for base_url in _get_oobi_base_urls()
        ]

        # Publish KEL to witnesses for OOBI resolution
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                kel_bytes = await mgr.get_kel_bytes(info.aid)
                publisher = get_witness_publisher()
                result = await publisher.publish_oobi(info.aid, kel_bytes)

                publish_results = [
                    WitnessPublishResult(
                        url=wr.url,
                        success=wr.success,
                        error=wr.error,
                    )
                    for wr in result.witnesses
                ]

                if not result.threshold_met:
                    log.warning(
                        f"Witness threshold not met for {info.aid}: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish to witnesses: {e}")
                # Don't fail identity creation if witness publishing fails
                # The identity is created, just not published yet

        # Audit log the creation
        audit.log_access(
            action="identity.create",
            principal_id=principal.key_id,
            resource=info.aid,
            details={"name": request.name},
            request=http_request,
        )

        return CreateIdentityResponse(
            identity=IdentityResponse(
                aid=info.aid,
                name=info.name,
                created_at=info.created_at,
                witness_count=info.witness_count,
                key_count=info.key_count,
                sequence_number=info.sequence_number,
                transferable=info.transferable,
            ),
            oobi_urls=oobi_urls,
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Failed to create identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error creating identity")


@router.get("", response_model=IdentityListResponse)
async def list_identities() -> IdentityListResponse:
    """List all managed identities.

    This endpoint is public (no auth required) for UI access.
    """
    mgr = await get_identity_manager()
    identities = await mgr.list_identities()

    return IdentityListResponse(
        identities=[
            IdentityResponse(
                aid=i.aid,
                name=i.name,
                created_at=i.created_at or None,
                witness_count=i.witness_count,
                key_count=i.key_count,
                sequence_number=i.sequence_number,
                transferable=i.transferable,
            )
            for i in identities
        ],
        count=len(identities),
    )


@router.get("/{aid}", response_model=IdentityResponse)
async def get_identity(aid: str) -> IdentityResponse:
    """Get identity information by AID.

    This endpoint is public (no auth required) for UI access.
    """
    mgr = await get_identity_manager()
    info = await mgr.get_identity(aid)

    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {aid}")

    return IdentityResponse(
        aid=info.aid,
        name=info.name,
        created_at=info.created_at or None,
        witness_count=info.witness_count,
        key_count=info.key_count,
        sequence_number=info.sequence_number,
        transferable=info.transferable,
    )


@router.get("/{aid}/oobi", response_model=OobiResponse)
async def get_oobi(aid: str) -> OobiResponse:
    """Get OOBI URLs for an identity.

    This endpoint is public (no auth required) for UI access.
    """
    mgr = await get_identity_manager()
    info = await mgr.get_identity(aid)

    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {aid}")

    oobi_urls = [
        mgr.get_oobi_url(aid, base_url)
        for base_url in _get_oobi_base_urls()
    ]

    return OobiResponse(aid=aid, oobi_urls=oobi_urls)


@router.post("/{aid}/rotate", response_model=RotateIdentityResponse)
async def rotate_identity(
    aid: str,
    request: RotateIdentityRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> RotateIdentityResponse:
    """Rotate the keys for an identity.

    Promotes the current next keys to active signing keys and generates
    new next keys for future rotations. The rotation event is published
    to witnesses for OOBI resolution.

    Requires: issuer:admin role

    Raises:
        404: Identity not found
        400: Non-transferable identity or invalid threshold configuration
    """
    mgr = await get_identity_manager()
    audit = get_audit_logger()

    try:
        # Perform the rotation
        result = await mgr.rotate_identity(
            aid=aid,
            next_key_count=request.next_key_count,
            next_threshold=request.next_threshold,
        )

        # Publish rotation event to witnesses
        publish_results: list[WitnessPublishDetail] | None = None
        threshold_met = True

        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                publisher = get_witness_publisher()
                pub_result = await publisher.publish_event(
                    pre=aid,
                    event_bytes=result.rotation_event_bytes,
                )

                publish_results = [
                    WitnessPublishDetail(
                        witness_url=wr.url,
                        success=wr.success,
                        error=wr.error,
                    )
                    for wr in pub_result.witnesses
                ]
                threshold_met = pub_result.threshold_met

                if not threshold_met:
                    log.warning(
                        f"Witness threshold not met for rotation {aid}: "
                        f"{pub_result.success_count}/{pub_result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish rotation to witnesses: {e}")
                threshold_met = False

        # Audit log the rotation
        audit.log_access(
            action="identity.rotate",
            principal_id=principal.key_id,
            resource=aid,
            details={
                "previous_sn": result.previous_sequence_number,
                "new_sn": result.new_sequence_number,
            },
            request=http_request,
        )

        # Get updated identity info
        updated_info = await mgr.get_identity(aid)

        return RotateIdentityResponse(
            identity=IdentityResponse(
                aid=updated_info.aid,
                name=updated_info.name,
                created_at=updated_info.created_at or None,
                witness_count=updated_info.witness_count,
                key_count=updated_info.key_count,
                sequence_number=updated_info.sequence_number,
                transferable=updated_info.transferable,
            ),
            previous_sequence_number=result.previous_sequence_number,
            publish_results=publish_results,
            publish_threshold_met=threshold_met,
        )

    except IdentityNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except NonTransferableIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except InvalidRotationThresholdError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Failed to rotate identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error rotating identity")


@router.delete("/{aid}", response_model=DeleteResponse)
async def delete_identity(
    aid: str,
    http_request: Request,
    principal: Principal = require_admin,
) -> DeleteResponse:
    """Delete an identity from local storage.

    Note: This only removes the identity from local storage. The identity
    still exists in the KERI ecosystem (witnesses, watchers, etc.) and
    cannot be truly deleted from the global state.

    Requires: issuer:admin role
    """
    mgr = await get_identity_manager()
    audit = get_audit_logger()

    try:
        # Get identity name before deletion for audit
        info = await mgr.get_identity(aid)
        if info is None:
            raise HTTPException(status_code=404, detail=f"Identity not found: {aid}")

        identity_name = info.name

        # Delete the identity
        await mgr.delete_identity(aid)

        # Audit log the deletion
        audit.log_access(
            action="identity.delete",
            principal_id=principal.key_id,
            resource=aid,
            details={"name": identity_name},
            request=http_request,
        )

        return DeleteResponse(
            deleted=True,
            resource_type="identity",
            resource_id=aid,
            message=f"Identity '{identity_name}' removed from local storage. Note: The identity still exists in the KERI ecosystem.",
        )

    except IdentityNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to delete identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error deleting identity")
