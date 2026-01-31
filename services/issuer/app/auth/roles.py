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
