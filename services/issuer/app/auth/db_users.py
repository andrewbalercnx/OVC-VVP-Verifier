"""Database-backed user authentication for VVP Issuer.

Sprint 41: Provides username/password authentication with users stored in SQLAlchemy database.
This complements the file-based UserStore with database persistence for multi-tenant support.
"""

import logging
from typing import Any

import bcrypt as bcrypt_lib
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.db.models import User, UserOrgRole

log = logging.getLogger(__name__)

# Default bcrypt cost factor (2^12 = 4096 iterations)
BCRYPT_COST_FACTOR = 12


class DatabaseUserStore:
    """Manages users with SQLAlchemy database persistence.

    Unlike the file-based UserStore, this class requires a database session
    for each operation. Users are stored in the 'users' table with organization
    roles in the 'user_org_roles' join table.
    """

    def verify(
        self, db: Session, email: str, password: str
    ) -> tuple[Principal | None, str | None]:
        """Verify a user's credentials and return the principal.

        Uses bcrypt.checkpw() for constant-time comparison.

        Args:
            db: Database session
            email: User's email address (case-insensitive)
            password: Raw password

        Returns:
            Tuple of (Principal if valid, error_reason if invalid)
            - (Principal, None) for valid credentials
            - (None, "disabled") for disabled user
            - (None, "oauth_user") for OAuth user (must use OAuth flow)
            - (None, "invalid") for invalid email/password
        """
        email = email.lower()
        user = db.query(User).filter(User.email == email).first()

        if user is None:
            return None, "invalid"

        # OAuth users cannot login with password - they must use OAuth flow
        if user.is_oauth_user:
            log.warning(f"OAuth user attempted password login: {email}")
            return None, "oauth_user"

        if not user.enabled:
            log.warning(f"Disabled user attempted login: {email}")
            return None, "disabled"

        # Skip bcrypt verification if password_hash is empty
        if not user.password_hash:
            return None, "invalid"

        try:
            if bcrypt_lib.checkpw(password.encode(), user.password_hash.encode()):
                # Build complete role set
                roles = self._get_user_roles(db, user)

                return Principal(
                    key_id=f"user:{email}",
                    name=user.name,
                    roles=roles,
                    organization_id=user.organization_id,
                ), None
        except Exception:
            # bcrypt.checkpw can raise on malformed hash
            pass

        return None, "invalid"

    def get_user_by_email(self, db: Session, email: str) -> User | None:
        """Get user by email.

        Args:
            db: Database session
            email: User's email address (case-insensitive)

        Returns:
            User if found, None otherwise
        """
        return db.query(User).filter(User.email == email.lower()).first()

    def get_user_by_id(self, db: Session, user_id: str) -> User | None:
        """Get user by ID.

        Args:
            db: Database session
            user_id: User's UUID

        Returns:
            User if found, None otherwise
        """
        return db.query(User).filter(User.id == user_id).first()

    def list_users(
        self,
        db: Session,
        organization_id: str | None = None,
        include_disabled: bool = False,
    ) -> list[dict[str, Any]]:
        """List users with optional filtering.

        Args:
            db: Database session
            organization_id: Filter by organization (None for all)
            include_disabled: Include disabled users

        Returns:
            List of user info dicts (without password hashes)
        """
        query = db.query(User)

        if organization_id:
            query = query.filter(User.organization_id == organization_id)

        if not include_disabled:
            query = query.filter(User.enabled == True)

        users = query.order_by(User.created_at.desc()).all()

        result = []
        for user in users:
            org_roles = [r.role for r in user.org_roles]
            result.append({
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "system_roles": user.system_roles.split(",") if user.system_roles else [],
                "org_roles": org_roles,
                "organization_id": user.organization_id,
                "enabled": user.enabled,
                "is_oauth_user": user.is_oauth_user,
                "created_at": user.created_at.isoformat(),
            })

        return result

    def create_user(
        self,
        db: Session,
        email: str,
        name: str,
        password: str | None,
        system_roles: list[str] | None = None,
        org_roles: list[str] | None = None,
        organization_id: str | None = None,
        is_oauth_user: bool = False,
    ) -> User:
        """Create a new user.

        Args:
            db: Database session
            email: User's email address
            name: Display name
            password: Raw password (hashed before storage, None for OAuth users)
            system_roles: System roles (issuer:admin, issuer:operator, issuer:readonly)
            org_roles: Organization roles (org:administrator, org:dossier_manager)
            organization_id: Organization UUID (required for org roles)
            is_oauth_user: Whether this is an OAuth-provisioned user

        Returns:
            The created User

        Raises:
            ValueError: If user already exists or invalid configuration
        """
        email = email.lower()

        # Check for existing user
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise ValueError(f"User already exists: {email}")

        # Validate org roles require organization
        if org_roles and not organization_id:
            raise ValueError("Organization ID required when assigning org roles")

        # Hash password if provided
        password_hash = ""
        if password:
            password_hash = hash_password(password)

        # Create user record
        import uuid
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            name=name,
            password_hash=password_hash,
            system_roles=",".join(system_roles) if system_roles else "",
            organization_id=organization_id,
            enabled=True,
            is_oauth_user=is_oauth_user,
        )
        db.add(user)

        # Add org roles
        if org_roles and organization_id:
            for role in org_roles:
                org_role = UserOrgRole(
                    user_id=user.id,
                    org_id=organization_id,
                    role=role,
                )
                db.add(org_role)

        db.commit()
        db.refresh(user)

        log.info(f"Created user: {email} (org={organization_id}, oauth={is_oauth_user})")
        return user

    def update_user(
        self,
        db: Session,
        user_id: str,
        name: str | None = None,
        system_roles: list[str] | None = None,
        org_roles: list[str] | None = None,
        organization_id: str | None = None,
        enabled: bool | None = None,
    ) -> User | None:
        """Update an existing user.

        Args:
            db: Database session
            user_id: User's UUID
            name: New display name (None to keep current)
            system_roles: New system roles (None to keep current)
            org_roles: New org roles (None to keep current, requires organization_id)
            organization_id: New organization (None to keep current)
            enabled: New enabled status (None to keep current)

        Returns:
            Updated User or None if not found
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None

        if name is not None:
            user.name = name

        if system_roles is not None:
            user.system_roles = ",".join(system_roles)

        if organization_id is not None:
            user.organization_id = organization_id

        if enabled is not None:
            user.enabled = enabled

        # Update org roles if provided
        if org_roles is not None:
            # Determine which org to use for roles
            org_id = organization_id if organization_id is not None else user.organization_id

            if org_roles and not org_id:
                raise ValueError("Organization ID required when assigning org roles")

            # Remove existing org roles for this org
            if org_id:
                db.query(UserOrgRole).filter(
                    UserOrgRole.user_id == user_id,
                    UserOrgRole.org_id == org_id,
                ).delete()

                # Add new org roles
                for role in org_roles:
                    org_role = UserOrgRole(
                        user_id=user_id,
                        org_id=org_id,
                        role=role,
                    )
                    db.add(org_role)

        db.commit()
        db.refresh(user)

        log.info(f"Updated user: {user.email}")
        return user

    def delete_user(self, db: Session, user_id: str) -> bool:
        """Delete a user.

        Args:
            db: Database session
            user_id: User's UUID

        Returns:
            True if deleted, False if not found
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        # Delete org roles first (cascade should handle this, but be explicit)
        db.query(UserOrgRole).filter(UserOrgRole.user_id == user_id).delete()

        db.delete(user)
        db.commit()

        log.info(f"Deleted user: {user.email}")
        return True

    def change_password(
        self, db: Session, user_id: str, new_password: str
    ) -> bool:
        """Change a user's password.

        Args:
            db: Database session
            user_id: User's UUID
            new_password: New password (will be hashed)

        Returns:
            True if changed, False if user not found
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        if user.is_oauth_user:
            raise ValueError("Cannot set password for OAuth user")

        user.password_hash = hash_password(new_password)
        db.commit()

        log.info(f"Changed password for user: {user.email}")
        return True

    def _get_user_roles(self, db: Session, user: User) -> set[str]:
        """Get complete role set for a user.

        Combines system roles from user record with org roles from join table.

        Args:
            db: Database session
            user: User record

        Returns:
            Set of all role strings
        """
        roles: set[str] = set()

        # Add system roles
        if user.system_roles:
            roles.update(user.system_roles.split(","))

        # Add org roles
        for org_role in user.org_roles:
            roles.add(org_role.role)

        return roles

    def get_principal_for_user(self, db: Session, user: User) -> Principal:
        """Create a Principal for an authenticated user.

        Args:
            db: Database session
            user: User record

        Returns:
            Principal with all roles
        """
        roles = self._get_user_roles(db, user)

        return Principal(
            key_id=f"user:{user.email}",
            name=user.name,
            roles=roles,
            organization_id=user.organization_id,
        )


def hash_password(password: str, cost_factor: int = BCRYPT_COST_FACTOR) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The raw password to hash
        cost_factor: bcrypt cost factor (default: 12)

    Returns:
        The bcrypt hash string
    """
    salt = bcrypt_lib.gensalt(rounds=cost_factor)
    return bcrypt_lib.hashpw(password.encode(), salt).decode()


# Global store instance (singleton pattern)
_db_user_store: DatabaseUserStore | None = None


def get_db_user_store() -> DatabaseUserStore:
    """Get the global database user store instance."""
    global _db_user_store

    if _db_user_store is None:
        _db_user_store = DatabaseUserStore()

    return _db_user_store


def reset_db_user_store() -> None:
    """Reset the global store (for testing)."""
    global _db_user_store
    _db_user_store = None
