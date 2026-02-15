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
    get_org_aid,
    get_org_credentials,
    get_user_organization,
    register_credential,
)
from app.db.models import ManagedCredential, Organization
from app.audit import get_audit_logger
from app.config import WITNESS_IURLS
from app.db.session import get_db
from app.keri.issuer import get_credential_issuer
from app.keri.witness import get_witness_publisher

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credential", tags=["credential"])


def schema_requires_certification_edge(schema_said: str) -> bool:
    """Check if a schema requires a ``certification`` edge.

    Schema-driven detection using the e.oneOf object-variant pattern
    (same as Sprint 65's parse_schema_edges).
    """
    from app.schema.store import get_schema
    from app.vetter.constants import KNOWN_EXTENDED_SCHEMA_SAIDS

    schema_doc = get_schema(schema_said)
    if schema_doc is None:
        if schema_said in KNOWN_EXTENDED_SCHEMA_SAIDS:
            raise RuntimeError(
                f"Schema {schema_said} is a known extended schema but could not "
                f"be loaded. Cannot enforce certification edge requirement."
            )
        return False

    edges_one_of = schema_doc.get("properties", {}).get("e", {}).get("oneOf")
    if not edges_one_of:
        return False
    edges_obj = next((v for v in edges_one_of if v.get("type") == "object"), None)
    if not edges_obj:
        return False
    return "certification" in edges_obj.get("properties", {})


async def _inject_certification_edge(
    schema_said: str,
    edges: Optional[dict],
    org: Optional[Organization],
) -> Optional[dict]:
    """Inject certification edge for extended schemas.

    Returns updated edges dict, or original edges if not an extended schema.
    """
    if not schema_requires_certification_edge(schema_said):
        return edges

    if org is None:
        raise HTTPException(
            status_code=400,
            detail="Extended schemas require organization context. "
                   "Provide organization_id in the request.",
        )

    from app.vetter.service import resolve_active_vetter_cert
    from app.vetter.constants import VETTER_CERT_SCHEMA_SAID

    cert_info = await resolve_active_vetter_cert(org)
    if cert_info is None:
        raise HTTPException(
            status_code=400,
            detail="Organization has no valid active VetterCertification. "
                   "Issue a VetterCertification before using extended schemas.",
        )

    cert_edge = {
        "n": cert_info.said,
        "s": VETTER_CERT_SCHEMA_SAID,
    }

    edges = dict(edges) if edges else {}

    if "certification" in edges:
        caller_edge = edges["certification"]
        if not isinstance(caller_edge, dict) or "n" not in caller_edge:
            raise HTTPException(
                status_code=400,
                detail="Malformed certification edge. Expected dict with 'n' key.",
            )
        if caller_edge.get("n") != cert_info.said:
            raise HTTPException(
                status_code=400,
                detail="Provided certification edge SAID does not match "
                       "org's active VetterCertification.",
            )
        if caller_edge.get("s") != VETTER_CERT_SCHEMA_SAID:
            raise HTTPException(
                status_code=400,
                detail="Provided certification edge schema does not match "
                       f"VetterCertification schema ({VETTER_CERT_SCHEMA_SAID}).",
            )
    else:
        edges["certification"] = cert_edge

    return edges


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

    # Sprint 61: Block VetterCertification via generic endpoint
    from app.vetter.constants import VETTER_CERT_SCHEMA_SAID
    if request.schema_said == VETTER_CERT_SCHEMA_SAID:
        raise HTTPException(
            status_code=400,
            detail="VetterCertification credentials must be issued via "
                   "POST /vetter-certifications, not the generic issuance endpoint.",
        )

    # Sprint 61: Resolve org context for edge injection
    resolved_org = None
    resolved_org_id = None
    if hasattr(request, "organization_id") and request.organization_id:
        # Admin cross-org: explicit org_id in request
        if not principal.is_system_admin:
            if request.organization_id != principal.organization_id:
                raise HTTPException(
                    status_code=403,
                    detail="Only system admins can specify a different organization_id.",
                )
        resolved_org = db.query(Organization).filter(
            Organization.id == request.organization_id
        ).first()
        if resolved_org is None:
            raise HTTPException(
                status_code=404,
                detail=f"Organization not found: {request.organization_id}",
            )
        resolved_org_id = request.organization_id
    elif principal.organization_id:
        resolved_org = db.query(Organization).filter(
            Organization.id == principal.organization_id
        ).first()
        resolved_org_id = principal.organization_id

    # Sprint 61: Inject certification edge for extended schemas
    edges = request.edges
    edges = await _inject_certification_edge(request.schema_said, edges, resolved_org)

    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    try:
        # Issue the credential
        cred_info, acdc_bytes = await issuer.issue_credential(
            registry_name=request.registry_name,
            schema_said=request.schema_said,
            attributes=request.attributes,
            recipient_aid=request.recipient_aid,
            edges=edges,
            rules=request.rules,
            private=request.private,
        )

        # Sprint 41/61: Register credential with organization
        # Sprint 61: Use resolved_org_id for admin cross-org support
        managed = False
        reg_org_id = resolved_org_id or principal.organization_id
        if reg_org_id:
            register_credential(
                db=db,
                credential_said=cred_info.said,
                organization_id=reg_org_id,
                schema_said=request.schema_said,
                issuer_aid=cred_info.issuer_aid,
            )
            managed = True
            log.info(
                f"Credential {cred_info.said[:16]}... registered to org {reg_org_id[:8]}..."
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
        audit_details = {
            "registry_name": request.registry_name,
            "schema_said": request.schema_said,
            "recipient_aid": request.recipient_aid,
            "organization_id": reg_org_id or principal.organization_id,
            "managed": managed,
        }
        # Sprint 61: Record cross-org context when admin issues for a different org
        if resolved_org_id and resolved_org_id != principal.organization_id:
            audit_details["caller_organization_id"] = principal.organization_id
            audit_details["target_organization_id"] = resolved_org_id
        audit.log_access(
            action="credential.issue",
            principal_id=principal.key_id,
            resource=cred_info.said,
            details=audit_details,
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
    schema_said: Optional[str] = None,
    org_id: Optional[str] = None,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialListResponse:
    """List issued credentials with optional filtering.

    **Sprint 41:** Non-admin users only see credentials owned by their organization.
    System admins can see all credentials.

    **Sprint 63:** Added ``schema_said`` and ``org_id`` query filters.
    ``org_id`` is admin-only and returns credentials visible to the specified org
    (issued by or targeted to that org).

    Requires: issuer:readonly+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system readonly+ OR org dossier_manager+)
    check_credential_access_role(principal)

    # Sprint 63: Validate org_id parameter
    if org_id is not None:
        if not principal.is_system_admin:
            raise HTTPException(
                status_code=403,
                detail="org_id filter requires admin role",
            )
        # Validate org_id format and existence
        import re
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', org_id, re.I):
            raise HTTPException(status_code=400, detail="Invalid org_id format")
        target_org = db.query(Organization).filter(Organization.id == org_id).first()
        if not target_org:
            raise HTTPException(status_code=404, detail="Organization not found")

    issuer = await get_credential_issuer()

    try:
        # Get all credentials from KERI
        all_credentials = await issuer.list_credentials(
            registry_key=registry_key,
            status=status,
        )

        # Filter by organization and determine relationship
        issued_saids: set[str] = set()
        org_aid: str | None = None

        if org_id and principal.is_system_admin:
            # Sprint 63: Admin filtering by specific org — show that org's universe
            target_org = db.query(Organization).filter(Organization.id == org_id).first()
            target_org_aid = target_org.aid if target_org else None

            # Filter to target org's managed credentials
            target_managed = [
                m for m in db.query(ManagedCredential)
                .filter(ManagedCredential.organization_id == org_id)
                .all()
            ]
            issued_saids = {m.said for m in target_managed}
            org_aid = target_org_aid

            # Dual-visibility: issued by OR targeted to the specified org
            credentials = [
                c for c in all_credentials
                if c.said in issued_saids
                or (org_aid and c.recipient_aid == org_aid)
            ]
        elif principal.is_system_admin and not org_id:
            credentials = all_credentials
        else:
            # Credentials the org ISSUED (via ManagedCredential)
            org_managed = get_org_credentials(db, principal)
            issued_saids = {m.said for m in org_managed}

            # Org's AID for subject matching
            org_aid = get_org_aid(db, principal)

            # Include issued OR subject credentials
            credentials = [
                c for c in all_credentials
                if c.said in issued_saids
                or (org_aid and c.recipient_aid == org_aid)
            ]

        # Sprint 63: Apply schema_said filter
        if schema_said:
            credentials = [c for c in credentials if c.schema_said == schema_said]

        # Batch AID-to-org-name lookup
        aids_to_resolve = set()
        for c in credentials:
            aids_to_resolve.add(c.issuer_aid)
            if c.recipient_aid:
                aids_to_resolve.add(c.recipient_aid)
        aid_to_name: dict[str, str] = {}
        if aids_to_resolve:
            try:
                orgs = db.query(Organization.aid, Organization.name).filter(
                    Organization.aid.in_(aids_to_resolve)
                ).all()
                aid_to_name = {o.aid: o.name for o in orgs if o.aid}
            except Exception:
                pass  # Organizations table may not exist in test environments

        # Build response with relationship tagging and org names
        # Sprint 63: When org_id is provided, tag from perspective of that org
        perspective_org_id = org_id if org_id else principal.organization_id
        perspective_issued_saids = issued_saids
        perspective_org_aid = org_aid

        result = []
        for c in credentials:
            relationship = None
            if perspective_org_id:
                if c.said in perspective_issued_saids:
                    relationship = "issued"
                elif perspective_org_aid and c.recipient_aid == perspective_org_aid:
                    relationship = "subject"

            result.append(CredentialResponse(
                said=c.said,
                issuer_aid=c.issuer_aid,
                recipient_aid=c.recipient_aid,
                registry_key=c.registry_key,
                schema_said=c.schema_said,
                issuance_dt=c.issuance_dt,
                status=c.status,
                revocation_dt=c.revocation_dt,
                relationship=relationship,
                issuer_name=aid_to_name.get(c.issuer_aid),
                recipient_name=aid_to_name.get(c.recipient_aid) if c.recipient_aid else None,
            ))

        return CredentialListResponse(
            credentials=result,
            count=len(result),
        )
    except HTTPException:
        raise
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

        # Sprint 41: Check organization access (issued or subject)
        if not can_access_credential(db, principal, said, recipient_aid=cred_info.recipient_aid):
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
