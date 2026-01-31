"""Identity management endpoints."""
import logging

from fastapi import APIRouter, HTTPException

from app.api.models import (
    CreateIdentityRequest,
    CreateIdentityResponse,
    IdentityResponse,
    IdentityListResponse,
    OobiResponse,
    WitnessPublishResult,
)
from app.config import WITNESS_IURLS
from app.keri.identity import get_identity_manager
from app.keri.witness import get_witness_publisher

log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity", tags=["identity"])


@router.post("", response_model=CreateIdentityResponse)
async def create_identity(request: CreateIdentityRequest) -> CreateIdentityResponse:
    """Create a new KERI identity.

    Creates an identity with the specified parameters and optionally
    publishes its OOBI to configured witnesses.
    """
    mgr = await get_identity_manager()

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

        # Generate OOBI URLs
        oobi_urls = []
        for iurl in WITNESS_IURLS:
            base_url = iurl.split("/oobi/")[0] if "/oobi/" in iurl else iurl
            oobi_url = mgr.get_oobi_url(info.aid, base_url)
            oobi_urls.append(oobi_url)

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
    """List all managed identities."""
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
    """Get identity information by AID."""
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
    """Get OOBI URLs for an identity."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity(aid)

    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {aid}")

    oobi_urls = []
    for iurl in WITNESS_IURLS:
        base_url = iurl.split("/oobi/")[0] if "/oobi/" in iurl else iurl
        oobi_url = mgr.get_oobi_url(aid, base_url)
        oobi_urls.append(oobi_url)

    return OobiResponse(aid=aid, oobi_urls=oobi_urls)
