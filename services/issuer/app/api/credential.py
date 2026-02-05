"""Credential management endpoints.

Sprint 41: Updated with organization scoping for multi-tenant isolation.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from keri.kering import LikelyDuplicitousError, ValidationError
from sqlalchemy.orm import Session

from app.api.models import (
    DeleteResponse,
    IssueCredentialRequest,
    IssueCredentialResponse,
    CredentialResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    RevokeCredentialRequest,
    RevokeCredentialResponse,
    WitnessPublishResult,
)
from app.auth.api_key import Principal
from app.auth.roles import (
    require_auth,
    check_credential_access_role,
    check_credential_write_role,
    check_credential_admin_role,
)
from app.auth.scoping import (
    can_access_credential,
    get_org_credentials,
    register_credential,
)
from app.audit import get_audit_logger
from app.config import WITNESS_IURLS
from app.db.session import get_db
from app.keri.issuer import get_credential_issuer
from app.keri.witness import get_witness_publisher

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credential", tags=["credential"])


@router.post("/issue", response_model=IssueCredentialResponse)
async def issue_credential(
    request: IssueCredentialRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> IssueCredentialResponse:
    """Issue a new ACDC credential.

    Creates a credential, generates TEL issuance event, and optionally
    publishes to witnesses.

    **Sprint 41:** If the principal has an organization, the credential is
    registered as managed by that organization. System admins issuing without
    an organization create unmanaged credentials.

    Requires: issuer:operator+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system operator+ OR org dossier_manager+)
    check_credential_write_role(principal)

    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    try:
        # Issue the credential
        cred_info, acdc_bytes = await issuer.issue_credential(
            registry_name=request.registry_name,
            schema_said=request.schema_said,
            attributes=request.attributes,
            recipient_aid=request.recipient_aid,
            edges=request.edges,
            rules=request.rules,
            private=request.private,
        )

        # Sprint 41: Register credential with organization if principal has one
        managed = False
        if principal.organization_id:
            register_credential(
                db=db,
                credential_said=cred_info.said,
                organization_id=principal.organization_id,
                schema_said=request.schema_said,
                issuer_aid=cred_info.issuer_aid,
            )
            managed = True
            log.info(
                f"Credential {cred_info.said[:16]}... registered to org {principal.organization_id[:8]}..."
            )

        # Publish anchoring IXN event to witnesses
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                ixn_bytes = await issuer.get_anchor_ixn_bytes(cred_info.said)
                publisher = get_witness_publisher()
                result = await publisher.publish_event(cred_info.issuer_aid, ixn_bytes)

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
                        f"Witness threshold not met for credential {cred_info.said[:16]}...: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish anchor ixn to witnesses: {e}")
                # Don't fail credential issuance if witness publishing fails

        # Audit log the issuance
        audit.log_access(
            action="credential.issue",
            principal_id=principal.key_id,
            resource=cred_info.said,
            details={
                "registry_name": request.registry_name,
                "schema_said": request.schema_said,
                "recipient_aid": request.recipient_aid,
                "organization_id": principal.organization_id,
                "managed": managed,
            },
            request=http_request,
        )

        return IssueCredentialResponse(
            credential=CredentialResponse(
                said=cred_info.said,
                issuer_aid=cred_info.issuer_aid,
                recipient_aid=cred_info.recipient_aid,
                registry_key=cred_info.registry_key,
                schema_said=cred_info.schema_said,
                issuance_dt=cred_info.issuance_dt,
                status=cred_info.status,
                revocation_dt=cred_info.revocation_dt,
            ),
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to issue credential: {e}")
        raise HTTPException(status_code=500, detail="Internal error issuing credential")


@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    registry_key: Optional[str] = None,
    status: Optional[str] = None,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialListResponse:
    """List issued credentials with optional filtering.

    **Sprint 41:** Non-admin users only see credentials owned by their organization.
    System admins can see all credentials.

    Requires: issuer:readonly+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system readonly+ OR org dossier_manager+)
    check_credential_access_role(principal)

    issuer = await get_credential_issuer()

    try:
        # Get all credentials from KERI
        all_credentials = await issuer.list_credentials(
            registry_key=registry_key,
            status=status,
        )

        # Sprint 41: Filter by organization unless admin
        if principal.is_system_admin:
            credentials = all_credentials
        else:
            # Get SAIDs of credentials the principal can access
            org_managed = get_org_credentials(db, principal)
            accessible_saids = {m.said for m in org_managed}
            credentials = [c for c in all_credentials if c.said in accessible_saids]

        return CredentialListResponse(
            credentials=[
                CredentialResponse(
                    said=c.said,
                    issuer_aid=c.issuer_aid,
                    recipient_aid=c.recipient_aid,
                    registry_key=c.registry_key,
                    schema_said=c.schema_said,
                    issuance_dt=c.issuance_dt,
                    status=c.status,
                    revocation_dt=c.revocation_dt,
                )
                for c in credentials
            ],
            count=len(credentials),
        )
    except Exception as e:
        log.exception(f"Failed to list credentials: {e}")
        raise HTTPException(status_code=500, detail="Internal error listing credentials")


@router.get("/{said}", response_model=CredentialDetailResponse)
async def get_credential(
    said: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialDetailResponse:
    """Get credential details by SAID.

    **Sprint 41:** Non-admin users can only access credentials owned by their organization.

    Requires: issuer:readonly+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system readonly+ OR org dossier_manager+)
    check_credential_access_role(principal)

    issuer = await get_credential_issuer()

    try:
        cred_info = await issuer.get_credential(said)

        if cred_info is None:
            raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

        # Sprint 41: Check organization access
        if not can_access_credential(db, principal, said):
            raise HTTPException(
                status_code=403,
                detail="Access denied to this credential",
            )

        return CredentialDetailResponse(
            said=cred_info.said,
            issuer_aid=cred_info.issuer_aid,
            recipient_aid=cred_info.recipient_aid,
            registry_key=cred_info.registry_key,
            schema_said=cred_info.schema_said,
            issuance_dt=cred_info.issuance_dt,
            status=cred_info.status,
            revocation_dt=cred_info.revocation_dt,
            attributes=cred_info.attributes,
            edges=cred_info.edges,
            rules=cred_info.rules,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to get credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error getting credential")


@router.post("/{said}/revoke", response_model=RevokeCredentialResponse)
async def revoke_credential(
    said: str,
    request: RevokeCredentialRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> RevokeCredentialResponse:
    """Revoke an issued credential.

    Creates TEL revocation event and updates credential status.

    **Sprint 41:** Non-admin users can only revoke credentials owned by their organization.

    Requires: issuer:admin OR org:administrator role
    """
    # Sprint 41: Check role access (system admin OR org administrator)
    check_credential_admin_role(principal)

    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    # Sprint 41: Check organization access
    if not can_access_credential(db, principal, said):
        raise HTTPException(
            status_code=403,
            detail="Access denied to this credential",
        )

    try:
        cred_info = await issuer.revoke_credential(said)

        # Publish anchoring IXN event to witnesses
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                ixn_bytes = await issuer.get_anchor_ixn_bytes(said)
                publisher = get_witness_publisher()
                result = await publisher.publish_event(cred_info.issuer_aid, ixn_bytes)

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
                        f"Witness threshold not met for credential revocation {said[:16]}...: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish revocation anchor ixn to witnesses: {e}")
                # Don't fail revocation if witness publishing fails

        # Audit log the revocation
        audit.log_access(
            action="credential.revoke",
            principal_id=principal.key_id,
            resource=said,
            details={"reason": request.reason},
            request=http_request,
        )

        return RevokeCredentialResponse(
            credential=CredentialResponse(
                said=cred_info.said,
                issuer_aid=cred_info.issuer_aid,
                recipient_aid=cred_info.recipient_aid,
                registry_key=cred_info.registry_key,
                schema_said=cred_info.schema_said,
                issuance_dt=cred_info.issuance_dt,
                status=cred_info.status,
                revocation_dt=cred_info.revocation_dt,
            ),
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except LikelyDuplicitousError:
        # Credential was already revoked - keripy sees the second rev as duplicate
        raise HTTPException(status_code=400, detail=f"Credential already revoked: {said}")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to revoke credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error revoking credential")


@router.delete("/{said}", response_model=DeleteResponse)
async def delete_credential(
    said: str,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> DeleteResponse:
    """Delete a credential from local storage.

    Note: This only removes the credential from local storage. The credential
    and its TEL events still exist in the KERI ecosystem and cannot be
    truly deleted from the global state.

    **Sprint 41:** Non-admin users can only delete credentials owned by their organization.

    Requires: issuer:admin OR org:administrator role
    """
    # Sprint 41: Check role access (system admin OR org administrator)
    check_credential_admin_role(principal)

    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    try:
        # Verify credential exists before deletion
        cred_info = await issuer.get_credential(said)
        if cred_info is None:
            raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

        # Sprint 41: Check organization access
        if not can_access_credential(db, principal, said):
            raise HTTPException(
                status_code=403,
                detail="Access denied to this credential",
            )

        # Delete the credential
        await issuer.delete_credential(said)

        # Audit log the deletion
        audit.log_access(
            action="credential.delete",
            principal_id=principal.key_id,
            resource=said,
            details={},
            request=http_request,
        )

        return DeleteResponse(
            deleted=True,
            resource_type="credential",
            resource_id=said,
            message="Credential removed from local storage. Note: The credential still exists in the KERI ecosystem.",
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to delete credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error deleting credential")
