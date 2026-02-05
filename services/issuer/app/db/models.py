"""SQLAlchemy ORM models for VVP Issuer multi-tenant support.

This module defines the database schema for:
- Organizations (tenants with pseudo-LEI and KERI identity)
- Users (belong to organizations with system and org roles)
- Organization API Keys (scoped to organizations)
- Managed Credentials (track credential ownership)
- Mock vLEI State (idempotency for mock infrastructure)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class Organization(Base):
    """Organization (tenant) with pseudo-LEI and KERI identity.

    Each organization represents a tenant in the multi-tenant issuer system.
    Organizations are onboarded with:
    - A deterministic pseudo-LEI for development/testing
    - A KERI Autonomic Identifier (AID)
    - A Legal Entity credential from the mock QVI
    - A credential registry for issuing credentials
    """

    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False, unique=True)
    pseudo_lei = Column(String(20), nullable=False, unique=True)
    aid = Column(String(44), nullable=True)  # KERI AID (44 chars for Ed25519)
    le_credential_said = Column(String(44), nullable=True)  # Legal Entity credential SAID
    registry_key = Column(String(44), nullable=True)  # TEL registry prefix
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    users = relationship("User", back_populates="organization")
    api_keys = relationship("OrgAPIKey", back_populates="organization")
    credentials = relationship("ManagedCredential", back_populates="organization")

    def __repr__(self) -> str:
        return f"<Organization(id={self.id!r}, name={self.name!r}, pseudo_lei={self.pseudo_lei!r})>"


class User(Base):
    """User belonging to an organization.

    Users can have:
    - System roles (issuer:admin, issuer:operator, issuer:readonly)
    - Organization roles (org:administrator, org:dossier_manager) via UserOrgRole

    Note: Organization roles are stored in the user_org_roles table, NOT here.
    The system_roles field only stores system-level roles as comma-separated values.
    """

    __tablename__ = "users"

    id = Column(String(36), primary_key=True)  # UUID
    email = Column(String(255), nullable=False, unique=True)  # Lowercase, globally unique
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=True)  # bcrypt, empty for OAuth users
    system_roles = Column(String(255), default="", nullable=False)  # Comma-separated
    organization_id = Column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )
    enabled = Column(Boolean, default=True, nullable=False)
    is_oauth_user = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="users")
    org_roles = relationship("UserOrgRole", back_populates="user", cascade="all, delete-orphan")

    @property
    def system_roles_set(self) -> set[str]:
        """Get system roles as a set."""
        if not self.system_roles:
            return set()
        return {r.strip() for r in self.system_roles.split(",") if r.strip()}

    @system_roles_set.setter
    def system_roles_set(self, roles: set[str]) -> None:
        """Set system roles from a set."""
        self.system_roles = ",".join(sorted(roles)) if roles else ""

    def __repr__(self) -> str:
        return f"<User(id={self.id!r}, email={self.email!r}, org_id={self.organization_id!r})>"


class UserOrgRole(Base):
    """Canonical storage for user organization roles.

    This is the single source of truth for org roles (org:administrator, org:dossier_manager).
    A user can have multiple org roles for their organization.
    """

    __tablename__ = "user_org_roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(50), nullable=False)  # 'org:administrator' or 'org:dossier_manager'
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="org_roles")

    __table_args__ = (
        UniqueConstraint("user_id", "org_id", "role", name="uq_user_org_role"),
    )

    def __repr__(self) -> str:
        return f"<UserOrgRole(user_id={self.user_id!r}, org_id={self.org_id!r}, role={self.role!r})>"


class OrgAPIKey(Base):
    """API key scoped to an organization.

    Organization API keys can be used for programmatic access to org resources.
    They have org roles (not system roles) and are automatically scoped to their org.
    """

    __tablename__ = "org_api_keys"

    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False)  # bcrypt hash
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    roles = relationship("OrgAPIKeyRole", back_populates="api_key", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<OrgAPIKey(id={self.id!r}, name={self.name!r}, org_id={self.organization_id!r})>"


class OrgAPIKeyRole(Base):
    """Roles assigned to an organization API key.

    Organization API keys can have multiple org roles.
    """

    __tablename__ = "org_api_key_roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(
        String(36), ForeignKey("org_api_keys.id", ondelete="CASCADE"), nullable=False
    )
    role = Column(String(50), nullable=False)  # 'org:administrator' or 'org:dossier_manager'

    # Relationships
    api_key = relationship("OrgAPIKey", back_populates="roles")

    __table_args__ = (
        UniqueConstraint("key_id", "role", name="uq_org_api_key_role"),
    )

    def __repr__(self) -> str:
        return f"<OrgAPIKeyRole(key_id={self.key_id!r}, role={self.role!r})>"


class ManagedCredential(Base):
    """Tracks credential ownership by organization.

    When credentials are issued, a ManagedCredential record is created to
    associate the credential SAID with the issuing organization. This enables
    credential scoping - users can only access credentials from their org.
    """

    __tablename__ = "managed_credentials"

    said = Column(String(44), primary_key=True)  # Credential SAID
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    schema_said = Column(String(44), nullable=False)
    issuer_aid = Column(String(44), nullable=False)  # Which identity issued this
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="credentials")

    def __repr__(self) -> str:
        return f"<ManagedCredential(said={self.said!r}, org_id={self.organization_id!r})>"


class MockVLEIState(Base):
    """Persists mock vLEI infrastructure state for idempotency.

    This table stores the state of the mock GLEIF and QVI identities
    created on startup. It ensures that:
    - The same identities are used across restarts
    - Credential issuance is idempotent
    - Registry keys are preserved
    """

    __tablename__ = "mock_vlei_state"

    id = Column(Integer, primary_key=True, autoincrement=True)  # Single row expected
    gleif_aid = Column(String(44), nullable=False)
    gleif_registry_key = Column(String(44), nullable=False)
    qvi_aid = Column(String(44), nullable=False)
    qvi_credential_said = Column(String(44), nullable=False)
    qvi_registry_key = Column(String(44), nullable=False)
    initialized_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<MockVLEIState(id={self.id}, gleif_aid={self.gleif_aid!r}, qvi_aid={self.qvi_aid!r})>"


# Event listener to normalize email to lowercase before insert/update
@event.listens_for(User.email, "set", propagate=True)
def normalize_email(target: User, value: str, oldvalue: str, initiator) -> str:
    """Normalize email to lowercase."""
    if value is not None:
        return value.lower()
    return value
