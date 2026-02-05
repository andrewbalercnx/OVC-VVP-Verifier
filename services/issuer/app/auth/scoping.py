"""Credential access scoping for multi-tenant isolation.

Sprint 41: Controls which credentials a principal can access based on
organization ownership. System admins can access all credentials.
"""

import logging
from typing import Sequence

from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.db.models import ManagedCredential, Organization

log = logging.getLogger(__name__)


def get_user_organization(db: Session, principal: Principal) -> Organization | None:
    """Get the organization for a principal.

    Args:
        db: Database session
        principal: The authenticated principal

    Returns:
        Organization if principal belongs to one, None otherwise
    """
    if not principal.organization_id:
        return None

    return db.query(Organization).filter(
        Organization.id == principal.organization_id
    ).first()


def can_access_credential(
    db: Session,
    principal: Principal,
    credential_said: str,
) -> bool:
    """Check if a principal can access a specific credential.

    Access is granted if:
    1. Principal is a system admin (issuer:admin)
    2. Credential is managed and owned by principal's organization
    3. Credential is unmanaged (no ManagedCredential record) - only admins can access

    Args:
        db: Database session
        principal: The authenticated principal
        credential_said: The credential SAID to check

    Returns:
        True if principal can access the credential
    """
    # System admins can access anything
    if principal.is_system_admin:
        return True

    # Must have an organization to access credentials
    if not principal.organization_id:
        log.debug(f"Principal {principal.key_id} has no organization, denying credential access")
        return False

    # Check if credential is managed and owned by principal's org
    managed = db.query(ManagedCredential).filter(
        ManagedCredential.said == credential_said
    ).first()

    if managed is None:
        # Unmanaged credential - only admins can access (already checked above)
        log.debug(f"Credential {credential_said[:16]}... is unmanaged, denying access")
        return False

    if managed.organization_id != principal.organization_id:
        log.debug(
            f"Credential {credential_said[:16]}... belongs to org {managed.organization_id}, "
            f"principal {principal.key_id} is in org {principal.organization_id}"
        )
        return False

    return True


def filter_credentials_by_org(
    db: Session,
    principal: Principal,
    credential_saids: Sequence[str],
) -> list[str]:
    """Filter a list of credential SAIDs to only those accessible by the principal.

    Args:
        db: Database session
        principal: The authenticated principal
        credential_saids: List of credential SAIDs to filter

    Returns:
        List of accessible credential SAIDs
    """
    # System admins can access all
    if principal.is_system_admin:
        return list(credential_saids)

    # No organization = no credentials
    if not principal.organization_id:
        return []

    # Query for all managed credentials owned by principal's org
    managed_saids = set(
        m.said for m in db.query(ManagedCredential.said).filter(
            ManagedCredential.said.in_(credential_saids),
            ManagedCredential.organization_id == principal.organization_id,
        ).all()
    )

    return [said for said in credential_saids if said in managed_saids]


def get_org_credentials(
    db: Session,
    principal: Principal,
    schema_said: str | None = None,
) -> list[ManagedCredential]:
    """Get all credentials accessible by the principal.

    Args:
        db: Database session
        principal: The authenticated principal
        schema_said: Optional filter by schema SAID

    Returns:
        List of ManagedCredential records
    """
    query = db.query(ManagedCredential)

    # System admins can see all
    if not principal.is_system_admin:
        # Non-admins can only see their org's credentials
        if not principal.organization_id:
            return []
        query = query.filter(ManagedCredential.organization_id == principal.organization_id)

    if schema_said:
        query = query.filter(ManagedCredential.schema_said == schema_said)

    return query.order_by(ManagedCredential.created_at.desc()).all()


def require_credential_access(
    db: Session,
    principal: Principal,
    credential_said: str,
) -> None:
    """Raise an exception if principal cannot access the credential.

    Args:
        db: Database session
        principal: The authenticated principal
        credential_said: The credential SAID to check

    Raises:
        PermissionError: If access is denied
    """
    if not can_access_credential(db, principal, credential_said):
        raise PermissionError(
            f"Access denied to credential {credential_said[:16]}..."
        )


def register_credential(
    db: Session,
    credential_said: str,
    organization_id: str,
    schema_said: str,
    issuer_aid: str,
) -> ManagedCredential:
    """Register a newly issued credential for organization ownership.

    Called after successful credential issuance to track ownership.

    Args:
        db: Database session
        credential_said: The credential SAID
        organization_id: The owning organization's ID
        schema_said: The schema SAID
        issuer_aid: The issuer's AID

    Returns:
        The created ManagedCredential record
    """
    managed = ManagedCredential(
        said=credential_said,
        organization_id=organization_id,
        schema_said=schema_said,
        issuer_aid=issuer_aid,
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    log.info(
        f"Registered credential {credential_said[:16]}... "
        f"for org {organization_id[:8]}..."
    )

    return managed


def assign_credential_to_org(
    db: Session,
    credential_said: str,
    organization_id: str,
    schema_said: str,
    issuer_aid: str,
) -> ManagedCredential:
    """Assign an unmanaged credential to an organization.

    Used by admins to assign credentials that were issued without org scoping.

    Args:
        db: Database session
        credential_said: The credential SAID
        organization_id: The target organization's ID
        schema_said: The schema SAID
        issuer_aid: The issuer's AID

    Returns:
        The created ManagedCredential record

    Raises:
        ValueError: If credential is already managed
    """
    existing = db.query(ManagedCredential).filter(
        ManagedCredential.said == credential_said
    ).first()

    if existing:
        raise ValueError(
            f"Credential {credential_said[:16]}... is already managed "
            f"by org {existing.organization_id[:8]}..."
        )

    return register_credential(db, credential_said, organization_id, schema_said, issuer_aid)


def get_credential_owner(
    db: Session,
    credential_said: str,
) -> str | None:
    """Get the organization ID that owns a credential.

    Args:
        db: Database session
        credential_said: The credential SAID

    Returns:
        Organization ID if managed, None otherwise
    """
    managed = db.query(ManagedCredential).filter(
        ManagedCredential.said == credential_said
    ).first()

    return managed.organization_id if managed else None


def validate_dossier_chain_access(
    db: Session,
    principal: Principal,
    credential_saids: list[str],
) -> list[str]:
    """Validate that a principal can access ALL credentials in a dossier chain.

    Sprint 41: Prevents cross-tenant credential leakage via edge references.
    A dossier should only be built if the principal has access to every
    credential in the resulting chain.

    Note: Unmanaged infrastructure credentials (like mock vLEI chain) are
    allowed since they're system-level credentials that support the chain.

    Args:
        db: Database session
        principal: The authenticated principal
        credential_saids: List of credential SAIDs in the dossier chain

    Returns:
        List of inaccessible credential SAIDs (empty if all accessible)
    """
    # System admins can access all credentials
    if principal.is_system_admin:
        return []

    # Principal must have an organization
    if not principal.organization_id:
        # No org = can only access unmanaged credentials
        # Return all managed credentials as inaccessible
        managed_saids = {
            m.said for m in db.query(ManagedCredential.said).filter(
                ManagedCredential.said.in_(credential_saids)
            ).all()
        }
        return [said for said in credential_saids if said in managed_saids]

    # Get all managed credentials in the chain
    managed_creds = db.query(ManagedCredential).filter(
        ManagedCredential.said.in_(credential_saids)
    ).all()

    # Build a map of SAID -> organization_id
    cred_ownership = {m.said: m.organization_id for m in managed_creds}

    # Check each credential
    inaccessible = []
    for said in credential_saids:
        if said in cred_ownership:
            # Managed credential - check org ownership
            if cred_ownership[said] != principal.organization_id:
                inaccessible.append(said)
        # Unmanaged credentials (not in cred_ownership) are allowed
        # These are typically infrastructure credentials (mock vLEI chain)

    return inaccessible
