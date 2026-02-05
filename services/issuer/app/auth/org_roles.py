"""Organization role-based authorization for VVP Issuer.

Sprint 41: Defines organization roles with a hierarchy where administrator
includes dossier_manager permissions.
"""

import logging
from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.db.session import get_db

log = logging.getLogger(__name__)


class OrgRole(str, Enum):
    """Defined organization roles."""

    ADMINISTRATOR = "org:administrator"
    DOSSIER_MANAGER = "org:dossier_manager"


# Org role hierarchy: administrator > dossier_manager
# Administrator can do everything a dossier manager can
ORG_ROLE_HIERARCHY: dict[OrgRole, set[OrgRole]] = {
    OrgRole.ADMINISTRATOR: {OrgRole.ADMINISTRATOR, OrgRole.DOSSIER_MANAGER},
    OrgRole.DOSSIER_MANAGER: {OrgRole.DOSSIER_MANAGER},
}

# Valid org roles for validation
VALID_ORG_ROLES = {OrgRole.ADMINISTRATOR.value, OrgRole.DOSSIER_MANAGER.value}


def get_effective_org_roles(roles: set[str]) -> set[OrgRole]:
    """Expand org roles according to hierarchy.

    Args:
        roles: Set of role strings from the principal

    Returns:
        Expanded set of OrgRole enums including inherited roles
    """
    effective: set[OrgRole] = set()

    for role_str in roles:
        try:
            role = OrgRole(role_str)
            effective.update(ORG_ROLE_HIERARCHY.get(role, {role}))
        except ValueError:
            # Not an org role, skip
            pass

    return effective


def has_org_role(principal: Principal, required_role: OrgRole, org_id: str) -> bool:
    """Check if principal has required org role for specified organization.

    System admins (issuer:admin) bypass org role checks.

    Args:
        principal: The authenticated principal
        required_role: The org role required
        org_id: The organization ID the role must apply to

    Returns:
        True if principal has required role for the org
    """
    # System admins can access any org
    if principal.is_system_admin:
        return True

    # Principal must belong to the organization
    if principal.organization_id != org_id:
        return False

    # Check org roles
    effective_roles = get_effective_org_roles(principal.roles)
    return required_role in effective_roles


def require_org_role(required_role: OrgRole, org_id_param: str = "org_id"):
    """Create a FastAPI dependency that requires a specific org role.

    The org_id is extracted from path parameters. System admins bypass this check.

    Usage:
        @router.post("/organizations/{org_id}/users")
        async def create_org_user(
            org_id: str,
            principal: Principal = require_org_role(OrgRole.ADMINISTRATOR),
        ):
            ...

    Args:
        required_role: The org role required to access the endpoint
        org_id_param: The name of the path parameter containing the org ID

    Returns:
        A FastAPI Depends() that validates the org role
    """

    async def dependency(request: Request, db: Session = Depends(get_db)) -> Principal:
        # Check if auth is enabled
        from app.config import AUTH_ENABLED

        if not AUTH_ENABLED:
            # Return a dummy principal when auth is disabled
            from app.auth.roles import Role
            return Principal(
                key_id="auth-disabled",
                name="Auth Disabled",
                roles={
                    Role.ADMIN.value,
                    Role.OPERATOR.value,
                    Role.READONLY.value,
                    OrgRole.ADMINISTRATOR.value,
                    OrgRole.DOSSIER_MANAGER.value,
                },
            )

        # Get the authenticated user from request state
        if not hasattr(request, "user") or not request.user.is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        principal: Principal = request.user

        # Extract org_id from path parameters
        org_id = request.path_params.get(org_id_param)
        if not org_id:
            raise HTTPException(
                status_code=400,
                detail=f"Missing path parameter: {org_id_param}",
            )

        # Check if principal has required org role
        if not has_org_role(principal, required_role, org_id):
            log.warning(
                f"Access denied for {principal.key_id}: "
                f"requires {required_role.value} for org {org_id}, "
                f"has org={principal.organization_id}, roles={principal.roles}"
            )
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions for this organization",
            )

        return principal

    return Depends(dependency)


def require_org_member(org_id_param: str = "org_id"):
    """Create a FastAPI dependency that requires membership in an organization.

    System admins can access any org. Other users must belong to the org.

    Args:
        org_id_param: The name of the path parameter containing the org ID

    Returns:
        A FastAPI Depends() that validates org membership
    """

    async def dependency(request: Request, db: Session = Depends(get_db)) -> Principal:
        # Check if auth is enabled
        from app.config import AUTH_ENABLED

        if not AUTH_ENABLED:
            from app.auth.roles import Role
            return Principal(
                key_id="auth-disabled",
                name="Auth Disabled",
                roles={Role.ADMIN.value, Role.OPERATOR.value, Role.READONLY.value},
            )

        # Get the authenticated user from request state
        if not hasattr(request, "user") or not request.user.is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        principal: Principal = request.user

        # Extract org_id from path parameters
        org_id = request.path_params.get(org_id_param)
        if not org_id:
            raise HTTPException(
                status_code=400,
                detail=f"Missing path parameter: {org_id_param}",
            )

        # System admins can access any org
        if principal.is_system_admin:
            return principal

        # Check org membership
        if principal.organization_id != org_id:
            log.warning(
                f"Access denied for {principal.key_id}: "
                f"not a member of org {org_id}"
            )
            raise HTTPException(
                status_code=403,
                detail="Not a member of this organization",
            )

        return principal

    return Depends(dependency)


def validate_org_roles(roles: list[str]) -> None:
    """Validate that all roles are valid organization roles.

    Args:
        roles: List of role strings to validate

    Raises:
        HTTPException: If any role is invalid
    """
    invalid_roles = set(roles) - VALID_ORG_ROLES
    if invalid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid organization roles: {invalid_roles}. Valid roles: {VALID_ORG_ROLES}",
        )


# Pre-built dependencies for common org roles
require_org_admin = require_org_role(OrgRole.ADMINISTRATOR)
require_org_dossier_manager = require_org_role(OrgRole.DOSSIER_MANAGER)
