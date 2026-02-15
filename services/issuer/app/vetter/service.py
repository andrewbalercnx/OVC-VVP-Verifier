"""Vetter certification business logic.

Sprint 61: Issue, revoke, and query VetterCertification credentials.
Central resolve_active_vetter_cert() helper prevents semantic drift.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import ManagedCredential, Organization
from app.vetter.constants import VETTER_CERT_SCHEMA_SAID

log = logging.getLogger(__name__)


class CredentialInfo:
    """Minimal credential info returned by resolve_active_vetter_cert."""

    def __init__(self, said: str, attributes: dict, issuer_aid: str, status: str):
        self.said = said
        self.attributes = attributes
        self.issuer_aid = issuer_aid
        self.status = status


async def resolve_active_vetter_cert(
    org: Organization,
) -> Optional[CredentialInfo]:
    """Resolve and validate the org's active VetterCertification.

    Performs full validation:
    1. org.vetter_certification_said is not None
    2. Credential exists in KERI store
    3. Credential schema matches VETTER_CERT_SCHEMA_SAID
    4. Credential status is "issued" (not revoked)
    5. Credential issuer is mock GSMA
    6. Credential issuee AID matches org.aid
    7. If certificationExpiry is present, not expired

    Returns:
        CredentialInfo if valid, None otherwise.
    """
    if not org.vetter_certification_said:
        return None

    from app.keri.registry import get_registry_manager

    registry_mgr = await get_registry_manager()
    reger = registry_mgr.regery.reger

    # Look up credential in KERI store
    said = org.vetter_certification_said
    try:
        creder = reger.creds.get(keys=said)
        if creder is None:
            log.warning(f"Stale pointer: credential {said[:16]}... not found in KERI store")
            return None
    except Exception:
        log.warning(f"Stale pointer: error looking up credential {said[:16]}...")
        return None

    # Check schema
    cred_schema = creder.schema if hasattr(creder, "schema") else None
    if cred_schema != VETTER_CERT_SCHEMA_SAID:
        log.warning(
            f"Stale pointer: credential {said[:16]}... has wrong schema "
            f"({cred_schema}, expected {VETTER_CERT_SCHEMA_SAID})"
        )
        return None

    # Check status (not revoked)
    status = "issued"
    try:
        from keri.vdr import eventing
        state = reger.states.get(keys=said)
        if state is not None:
            if hasattr(state, "et") and state.et in ("rev", "brv"):
                status = "revoked"
    except Exception:
        pass  # If we can't check status, assume issued

    if status == "revoked":
        log.warning(f"Stale pointer: credential {said[:16]}... is revoked")
        return None

    # Check issuer (should be mock GSMA) — fail-closed
    issuer_aid = creder.issuer if hasattr(creder, "issuer") else ""
    from app.org.mock_vlei import get_mock_vlei_manager
    mock_vlei = get_mock_vlei_manager()
    if not mock_vlei.state or not mock_vlei.state.gsma_aid:
        log.warning(
            f"Cannot validate issuer for credential {said[:16]}...: "
            f"Mock GSMA state unavailable — treating cert as inactive"
        )
        return None
    if issuer_aid != mock_vlei.state.gsma_aid:
        log.warning(
            f"Stale pointer: credential {said[:16]}... issued by {issuer_aid[:16]}... "
            f"not mock GSMA {mock_vlei.state.gsma_aid[:16]}..."
        )
        return None

    # Check issuee binding
    attrib = creder.attrib if hasattr(creder, "attrib") else {}
    if attrib.get("i") != org.aid:
        log.warning(
            f"Stale pointer: credential {said[:16]}... issuee {attrib.get('i', 'none')[:16]}... "
            f"doesn't match org AID {org.aid[:16] if org.aid else 'none'}..."
        )
        return None

    # Check expiry
    cert_expiry = attrib.get("certificationExpiry")
    if cert_expiry:
        try:
            expiry_dt = datetime.fromisoformat(cert_expiry)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if expiry_dt < datetime.now(timezone.utc):
                log.warning(f"Stale pointer: credential {said[:16]}... is expired ({cert_expiry})")
                return None
        except (ValueError, TypeError):
            log.warning(f"Could not parse certificationExpiry: {cert_expiry}")

    return CredentialInfo(
        said=said,
        attributes=attrib,
        issuer_aid=issuer_aid,
        status=status,
    )


async def _resolve_cert_attributes(said: str) -> dict:
    """Read credential attributes and status from KERI store.

    Returns dict with ecc_targets, jurisdiction_targets, name,
    certification_expiry, and status. Falls back to empty/default
    values if credential cannot be loaded.
    """
    result = {
        "ecc_targets": [],
        "jurisdiction_targets": [],
        "name": "",
        "certification_expiry": None,
        "status": "issued",
    }
    try:
        from app.keri.registry import get_registry_manager
        registry_mgr = await get_registry_manager()
        reger = registry_mgr.regery.reger

        creder = reger.creds.get(keys=said)
        if creder is not None:
            attrib = creder.attrib if hasattr(creder, "attrib") else {}
            result["ecc_targets"] = attrib.get("ecc_targets", [])
            result["jurisdiction_targets"] = attrib.get("jurisdiction_targets", [])
            result["name"] = attrib.get("name", "")
            result["certification_expiry"] = attrib.get("certificationExpiry")

            # Check revocation status
            try:
                state = reger.states.get(keys=said)
                if state is not None and hasattr(state, "et") and state.et in ("rev", "brv"):
                    result["status"] = "revoked"
            except Exception:
                pass
    except Exception as e:
        log.warning(f"Could not resolve attributes for credential {said[:16]}...: {e}")

    return result


async def issue_vetter_certification(
    db: Session,
    organization_id: str,
    ecc_targets: list[str],
    jurisdiction_targets: list[str],
    name: str,
    certification_expiry: Optional[str] = None,
) -> dict:
    """Issue a VetterCertification ACDC and link to org.

    Returns:
        Dict with credential info for building the response.
    """
    from app.org.mock_vlei import get_mock_vlei_manager
    from app.keri.witness import get_witness_publisher
    from app.keri.identity import get_identity_manager

    # 1. Validate org exists, has AID and registry
    org = (
        db.query(Organization)
        .with_for_update()
        .filter(Organization.id == organization_id)
        .first()
    )
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.aid:
        raise HTTPException(
            status_code=400, detail="Organization has no KERI identity"
        )

    # 3. Check for existing active cert
    if org.vetter_certification_said:
        cert_info = await resolve_active_vetter_cert(org)
        if cert_info is not None:
            raise HTTPException(
                status_code=409,
                detail="Organization already has active VetterCertification. "
                       "Revoke it first.",
            )
        # Stale pointer — auto-clear
        log.warning(
            f"Cleared stale vetter cert pointer for org {organization_id[:8]}... "
            f"(was {org.vetter_certification_said[:16]}...)"
        )
        org.vetter_certification_said = None

    # 3b. Durable secondary guard
    active_managed = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.organization_id == organization_id,
            ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID,
        )
        .all()
    )
    for mc in active_managed:
        # Check if this managed credential is actually active in KERI
        temp_org = Organization(
            id=organization_id,
            name=org.name,
            aid=org.aid,
            vetter_certification_said=mc.said,
        )
        temp_info = await resolve_active_vetter_cert(temp_org)
        if temp_info is not None:
            log.warning(
                f"Durable guard: found active vetter cert {mc.said[:16]}... "
                f"for org {organization_id[:8]}... via ManagedCredential scan"
            )
            raise HTTPException(
                status_code=409,
                detail="Organization already has active VetterCertification. "
                       "Revoke it first.",
            )

    # 5. Issue credential via mock GSMA
    mock_vlei = get_mock_vlei_manager()
    if not mock_vlei.state or not mock_vlei.state.gsma_aid:
        raise HTTPException(
            status_code=500,
            detail="Mock GSMA infrastructure not available",
        )

    cred_said = await mock_vlei.issue_vetter_certification(
        org_aid=org.aid,
        ecc_targets=ecc_targets,
        jurisdiction_targets=jurisdiction_targets,
        name=name,
        certification_expiry=certification_expiry,
    )

    # 6-8. Register ManagedCredential + set pointer — single commit
    managed = ManagedCredential(
        said=cred_said,
        organization_id=organization_id,
        schema_said=VETTER_CERT_SCHEMA_SAID,
        issuer_aid=mock_vlei.state.gsma_aid,
    )
    db.add(managed)
    org.vetter_certification_said = cred_said
    db.commit()
    db.refresh(org)
    db.refresh(managed)

    # 9. Publish to witnesses (best-effort)
    try:
        identity_mgr = await get_identity_manager()
        kel_bytes = await identity_mgr.get_kel_bytes(mock_vlei.state.gsma_aid)
        publisher = get_witness_publisher()
        pub = await publisher.publish_oobi(mock_vlei.state.gsma_aid, kel_bytes)
        log.info(f"Published vetter cert to witnesses: {pub.success_count}/{pub.total_count}")
    except Exception as e:
        log.warning(f"Failed to publish vetter cert to witnesses: {e}")

    return {
        "said": cred_said,
        "issuer_aid": mock_vlei.state.gsma_aid,
        "vetter_aid": org.aid,
        "organization_id": organization_id,
        "organization_name": org.name,
        "ecc_targets": ecc_targets,
        "jurisdiction_targets": jurisdiction_targets,
        "name": name,
        "certification_expiry": certification_expiry,
        "status": "issued",
        "created_at": managed.created_at.isoformat(),
    }


async def revoke_vetter_certification(
    db: Session,
    said: str,
) -> dict:
    """Revoke a VetterCertification and conditionally clear org link."""
    from app.keri.issuer import get_credential_issuer

    # Find the managed credential
    managed = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.said == said,
            ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID,
        )
        .first()
    )
    if managed is None:
        raise HTTPException(status_code=404, detail="VetterCertification not found")

    org = db.query(Organization).filter(
        Organization.id == managed.organization_id
    ).first()

    # Revoke in KERI
    issuer = await get_credential_issuer()
    await issuer.revoke_credential(said)

    # Clear org pointer only if it points to this cert
    if org and org.vetter_certification_said == said:
        org.vetter_certification_said = None

    db.commit()

    # Publish revocation to witnesses (best-effort)
    try:
        from app.keri.witness import get_witness_publisher
        from app.keri.identity import get_identity_manager
        from app.org.mock_vlei import get_mock_vlei_manager
        mock_vlei = get_mock_vlei_manager()
        if mock_vlei.state:
            identity_mgr = await get_identity_manager()
            kel_bytes = await identity_mgr.get_kel_bytes(mock_vlei.state.gsma_aid)
            publisher = get_witness_publisher()
            await publisher.publish_oobi(mock_vlei.state.gsma_aid, kel_bytes)
    except Exception as e:
        log.warning(f"Failed to publish vetter cert revocation to witnesses: {e}")

    # Resolve credential attributes from KERI store (status will be "revoked")
    attrs = await _resolve_cert_attributes(said)

    return {
        "said": said,
        "issuer_aid": managed.issuer_aid,
        "vetter_aid": org.aid if org else "",
        "organization_id": managed.organization_id,
        "organization_name": org.name if org else "",
        "ecc_targets": attrs["ecc_targets"],
        "jurisdiction_targets": attrs["jurisdiction_targets"],
        "name": attrs["name"],
        "certification_expiry": attrs["certification_expiry"],
        "status": "revoked",
        "created_at": managed.created_at.isoformat(),
    }


async def get_org_constraints(
    db: Session,
    organization_id: str,
) -> dict:
    """Get parsed constraints for an org.

    Uses resolve_active_vetter_cert() to validate the credential.
    Returns null constraints if no valid active cert.
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    result = {
        "organization_id": org.id,
        "organization_name": org.name,
        "vetter_certification_said": None,
        "ecc_targets": None,
        "jurisdiction_targets": None,
        "certification_status": None,
        "certification_expiry": None,
    }

    cert_info = await resolve_active_vetter_cert(org)
    if cert_info is None:
        return result

    result["vetter_certification_said"] = cert_info.said
    result["ecc_targets"] = cert_info.attributes.get("ecc_targets", [])
    result["jurisdiction_targets"] = cert_info.attributes.get("jurisdiction_targets", [])
    result["certification_status"] = cert_info.status
    result["certification_expiry"] = cert_info.attributes.get("certificationExpiry")

    return result
