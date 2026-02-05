"""Role-based authorization for VVP Issuer.

Defines roles with a hierarchy where admin includes operator permissions,
and operator includes readonly permissions.
"""

import logging
from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from app.auth.api_key import Principal

log = logging.getLogger(__name__)


class Role(str, Enum):
    """Defined roles for the issuer service."""

    ADMIN = "issuer:admin"
    OPERATOR = "issuer:operator"
    READONLY = "issuer:readonly"


# Role hierarchy: admin > operator > readonly
# Each role includes all permissions of roles below it
ROLE_HIERARCHY: dict[Role, set[Role]] = {
    Role.ADMIN: {Role.ADMIN, Role.OPERATOR, Role.READONLY},
    Role.OPERATOR: {Role.OPERATOR, Role.READONLY},
    Role.READONLY: {Role.READONLY},
}


def get_effective_roles(roles: set[str]) -> set[Role]:
    """Expand roles according to hierarchy.

    Args:
        roles: Set of role strings from the principal

    Returns:
        Expanded set of Role enums including inherited roles
    """
    effective: set[Role] = set()

    for role_str in roles:
        try:
            role = Role(role_str)
            effective.update(ROLE_HIERARCHY.get(role, {role}))
        except ValueError:
            # Unknown role string, skip
            log.warning(f"Unknown role in principal: {role_str}")

    return effective


def require_role(required_role: Role):
    """Create a FastAPI dependency that requires a specific role.

    Usage:
        @router.post("/identity")
        async def create_identity(
            request: CreateIdentityRequest,
            principal: Principal = require_admin,
        ):
            ...

    Args:
        required_role: The role required to access the endpoint

    Returns:
        A FastAPI Depends() that validates the role
    """

    async def dependency(request: Request) -> Principal:
        # Check if auth is enabled
        from app.config import AUTH_ENABLED

        if not AUTH_ENABLED:
            # Return a dummy principal when auth is disabled
            return Principal(
                key_id="auth-disabled",
                name="Auth Disabled",
                roles={Role.ADMIN.value, Role.OPERATOR.value, Role.READONLY.value},
            )

        # Get the authenticated user from request state
        # (set by AuthenticationMiddleware)
        if not hasattr(request, "user") or not request.user.is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="API key required",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        principal: Principal = request.user

        # Check if principal has the required role
        effective_roles = get_effective_roles(principal.roles)

        if required_role not in effective_roles:
            log.warning(
                f"Access denied for {principal.key_id}: "
                f"requires {required_role.value}, has {principal.roles}"
            )
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

        return principal

    return Depends(dependency)


# Pre-built dependencies for common roles
require_admin: Annotated[Principal, Depends] = require_role(Role.ADMIN)
require_operator: Annotated[Principal, Depends] = require_role(Role.OPERATOR)
require_readonly: Annotated[Principal, Depends] = require_role(Role.READONLY)


def require_authenticated():
    """Create a FastAPI dependency that requires authentication but no specific role.

    Sprint 41: Allows org-only principals to access endpoints where they have
    org-level permissions even without system roles.

    Usage:
        @router.get("/organizations/{org_id}")
        async def get_org(
            org_id: str,
            principal: Principal = require_authenticated,
        ):
            # Check org membership manually
            ...
    """

    async def dependency(request: Request) -> Principal:
        # Check if auth is enabled
        from app.config import AUTH_ENABLED

        if not AUTH_ENABLED:
            # Return a dummy principal when auth is disabled
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

        return request.user

    return Depends(dependency)


# Pre-built authentication-only dependency
require_auth: Annotated[Principal, Depends] = require_authenticated()


# =============================================================================
# Sprint 41: Combined System/Org Role Checks
# =============================================================================


class OrgRole(str, Enum):
    """Organization-level roles."""

    ADMINISTRATOR = "org:administrator"
    DOSSIER_MANAGER = "org:dossier_manager"


# Org role hierarchy: administrator > dossier_manager
ORG_ROLE_HIERARCHY: dict[OrgRole, set[OrgRole]] = {
    OrgRole.ADMINISTRATOR: {OrgRole.ADMINISTRATOR, OrgRole.DOSSIER_MANAGER},
    OrgRole.DOSSIER_MANAGER: {OrgRole.DOSSIER_MANAGER},
}


def has_org_role(principal: Principal, required_role: OrgRole) -> bool:
    """Check if a principal has the required org role (respecting hierarchy).

    Args:
        principal: The authenticated principal
        required_role: The org role to check for

    Returns:
        True if principal has the required org role or higher
    """
    for role_str in principal.roles:
        try:
            role = OrgRole(role_str)
            if required_role in ORG_ROLE_HIERARCHY.get(role, {role}):
                return True
        except ValueError:
            # Not an org role, skip
            pass
    return False


def has_system_role(principal: Principal, required_role: Role) -> bool:
    """Check if a principal has the required system role (respecting hierarchy).

    Args:
        principal: The authenticated principal
        required_role: The system role to check for

    Returns:
        True if principal has the required system role or higher
    """
    effective_roles = get_effective_roles(principal.roles)
    return required_role in effective_roles


def check_credential_access_role(principal: Principal) -> None:
    """Check that principal can access credential/dossier APIs.

    Sprint 41: Allows access if principal has:
    - System role: issuer:readonly or higher, OR
    - Org role: org:dossier_manager or higher (scoping enforced elsewhere)

    Raises HTTPException 403 if access denied.
    """
    # System roles allow access
    if has_system_role(principal, Role.READONLY):
        return

    # Org roles allow access (scoping checked elsewhere)
    if has_org_role(principal, OrgRole.DOSSIER_MANAGER):
        return

    log.warning(
        f"Access denied for {principal.key_id}: "
        f"requires system role (issuer:readonly+) or org role (org:dossier_manager+), "
        f"has {principal.roles}"
    )
    raise HTTPException(
        status_code=403,
        detail="Insufficient permissions. Requires issuer:readonly+ or org:dossier_manager+ role.",
    )


def check_credential_write_role(principal: Principal) -> None:
    """Check that principal can write to credential/dossier APIs.

    Sprint 41: Allows access if principal has:
    - System role: issuer:operator or higher, OR
    - Org role: org:dossier_manager or higher (scoping enforced elsewhere)

    Raises HTTPException 403 if access denied.
    """
    # System roles allow access
    if has_system_role(principal, Role.OPERATOR):
        return

    # Org roles allow access (scoping checked elsewhere)
    if has_org_role(principal, OrgRole.DOSSIER_MANAGER):
        return

    log.warning(
        f"Access denied for {principal.key_id}: "
        f"requires system role (issuer:operator+) or org role (org:dossier_manager+), "
        f"has {principal.roles}"
    )
    raise HTTPException(
        status_code=403,
        detail="Insufficient permissions. Requires issuer:operator+ or org:dossier_manager+ role.",
    )


def check_credential_admin_role(principal: Principal) -> None:
    """Check that principal can perform admin operations on credentials.

    Sprint 41: Allows access if principal has:
    - System role: issuer:admin, OR
    - Org role: org:administrator (scoping enforced elsewhere)

    Raises HTTPException 403 if access denied.
    """
    # System admin allows access
    if has_system_role(principal, Role.ADMIN):
        return

    # Org admin allows access (scoping checked elsewhere)
    if has_org_role(principal, OrgRole.ADMINISTRATOR):
        return

    log.warning(
        f"Access denied for {principal.key_id}: "
        f"requires system role (issuer:admin) or org role (org:administrator), "
        f"has {principal.roles}"
    )
    raise HTTPException(
        status_code=403,
        detail="Insufficient permissions. Requires issuer:admin or org:administrator role.",
    )
