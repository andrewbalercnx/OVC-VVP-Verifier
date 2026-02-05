"""Tests for Sprint 41 multi-tenant isolation.

Tests cover:
- Database-backed user authentication
- Organization API key authentication
- Credential scoping by organization
- Dossier chain scoping
- Org role access to endpoints
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock, AsyncMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.api_key import Principal, verify_org_api_key
from app.auth.db_users import DatabaseUserStore, hash_password
from app.auth.scoping import (
    can_access_credential,
    filter_credentials_by_org,
    validate_dossier_chain_access,
)
from app.db.models import Base, Organization, User, UserOrgRole, OrgAPIKey, OrgAPIKeyRole, ManagedCredential


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def test_org(in_memory_db):
    """Create a test organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Test Corp",
        pseudo_lei="5493001234567890AB12",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def other_org(in_memory_db):
    """Create another test organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Other Corp",
        pseudo_lei="5493009876543210XY34",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def test_user(in_memory_db, test_org):
    """Create a test user in test_org."""
    user = User(
        id=str(uuid.uuid4()),
        email="user@testcorp.com",
        name="Test User",
        password_hash=hash_password("password123"),
        system_roles="",
        organization_id=test_org.id,
        enabled=True,
        is_oauth_user=False,
    )
    in_memory_db.add(user)

    # Add org role
    org_role = UserOrgRole(
        user_id=user.id,
        org_id=test_org.id,
        role="org:administrator",
    )
    in_memory_db.add(org_role)

    in_memory_db.commit()
    in_memory_db.refresh(user)
    return user


@pytest.fixture
def test_org_api_key(in_memory_db, test_org):
    """Create a test org API key."""
    import bcrypt
    raw_key = "test-org-api-key-12345"
    key = OrgAPIKey(
        id=str(uuid.uuid4()),
        name="Test API Key",
        key_hash=bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode(),
        organization_id=test_org.id,
        revoked=False,
    )
    in_memory_db.add(key)

    # Add role
    role = OrgAPIKeyRole(
        key_id=key.id,
        role="org:dossier_manager",
    )
    in_memory_db.add(role)

    in_memory_db.commit()
    in_memory_db.refresh(key)
    return key, raw_key


@pytest.fixture
def managed_credentials(in_memory_db, test_org, other_org):
    """Create managed credentials for different organizations."""
    cred1 = ManagedCredential(
        said="SAID_ORG1_CRED1",
        organization_id=test_org.id,
        schema_said="SCHEMA_SAID_1",
        issuer_aid="AID_ISSUER_1",
    )
    cred2 = ManagedCredential(
        said="SAID_ORG1_CRED2",
        organization_id=test_org.id,
        schema_said="SCHEMA_SAID_2",
        issuer_aid="AID_ISSUER_1",
    )
    cred3 = ManagedCredential(
        said="SAID_ORG2_CRED1",
        organization_id=other_org.id,
        schema_said="SCHEMA_SAID_1",
        issuer_aid="AID_ISSUER_2",
    )

    in_memory_db.add_all([cred1, cred2, cred3])
    in_memory_db.commit()

    return {
        "org1_cred1": cred1,
        "org1_cred2": cred2,
        "org2_cred1": cred3,
    }


# =============================================================================
# Test Database User Authentication
# =============================================================================


class TestDatabaseUserAuth:
    """Tests for database-backed user authentication."""

    def test_verify_valid_credentials(self, in_memory_db, test_user, test_org):
        """Test successful authentication with valid credentials."""
        store = DatabaseUserStore()
        principal, error = store.verify(in_memory_db, "user@testcorp.com", "password123")

        assert principal is not None
        assert error is None
        assert principal.key_id == "user:user@testcorp.com"
        assert principal.organization_id == test_org.id
        assert "org:administrator" in principal.roles

    def test_verify_invalid_password(self, in_memory_db, test_user):
        """Test authentication fails with wrong password."""
        store = DatabaseUserStore()
        principal, error = store.verify(in_memory_db, "user@testcorp.com", "wrongpassword")

        assert principal is None
        assert error == "invalid"

    def test_verify_unknown_user(self, in_memory_db):
        """Test authentication fails for unknown user."""
        store = DatabaseUserStore()
        principal, error = store.verify(in_memory_db, "unknown@example.com", "password")

        assert principal is None
        assert error == "invalid"

    def test_verify_disabled_user(self, in_memory_db, test_user):
        """Test authentication fails for disabled user."""
        test_user.enabled = False
        in_memory_db.commit()

        store = DatabaseUserStore()
        principal, error = store.verify(in_memory_db, "user@testcorp.com", "password123")

        assert principal is None
        assert error == "disabled"

    def test_verify_oauth_user(self, in_memory_db, test_org):
        """Test OAuth users cannot use password auth."""
        oauth_user = User(
            id=str(uuid.uuid4()),
            email="oauth@testcorp.com",
            name="OAuth User",
            password_hash="",
            system_roles="",
            organization_id=test_org.id,
            enabled=True,
            is_oauth_user=True,
        )
        in_memory_db.add(oauth_user)
        in_memory_db.commit()

        store = DatabaseUserStore()
        principal, error = store.verify(in_memory_db, "oauth@testcorp.com", "anypassword")

        assert principal is None
        assert error == "oauth_user"


# =============================================================================
# Test Organization API Key Authentication
# =============================================================================


class TestOrgAPIKeyAuth:
    """Tests for organization API key authentication."""

    def test_verify_valid_org_api_key(self, in_memory_db, test_org_api_key, test_org):
        """Test successful authentication with valid org API key."""
        key, raw_key = test_org_api_key

        # Patch get_db_session to use our test DB
        with patch("app.db.session.get_db_session") as mock_session:
            mock_session.return_value.__enter__ = MagicMock(return_value=in_memory_db)
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            principal, error = verify_org_api_key(raw_key)

        assert principal is not None
        assert error is None
        assert principal.key_id.startswith("org_key:")
        assert principal.organization_id == test_org.id
        assert "org:dossier_manager" in principal.roles

    def test_verify_revoked_org_api_key(self, in_memory_db, test_org_api_key):
        """Test authentication fails for revoked key."""
        key, raw_key = test_org_api_key
        key.revoked = True
        in_memory_db.commit()

        with patch("app.db.session.get_db_session") as mock_session:
            mock_session.return_value.__enter__ = MagicMock(return_value=in_memory_db)
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            principal, error = verify_org_api_key(raw_key)

        assert principal is None
        assert error == "revoked"

    def test_verify_invalid_org_api_key(self, in_memory_db, test_org_api_key):
        """Test authentication fails for invalid key."""
        with patch("app.db.session.get_db_session") as mock_session:
            mock_session.return_value.__enter__ = MagicMock(return_value=in_memory_db)
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            principal, error = verify_org_api_key("invalid-key")

        assert principal is None
        assert error == "invalid"


# =============================================================================
# Test Credential Access Scoping
# =============================================================================


class TestCredentialScoping:
    """Tests for credential access scoping by organization."""

    def test_system_admin_can_access_any_credential(self, in_memory_db, managed_credentials):
        """System admins can access all credentials."""
        admin_principal = Principal(
            key_id="user:admin@system.com",
            name="System Admin",
            roles={"issuer:admin"},
            organization_id=None,
        )

        for cred in managed_credentials.values():
            assert can_access_credential(in_memory_db, admin_principal, cred.said) is True

    def test_org_user_can_access_own_credentials(self, in_memory_db, managed_credentials, test_org):
        """Org users can access their organization's credentials."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Can access own org's credentials
        assert can_access_credential(in_memory_db, org_principal, "SAID_ORG1_CRED1") is True
        assert can_access_credential(in_memory_db, org_principal, "SAID_ORG1_CRED2") is True

    def test_org_user_cannot_access_other_org_credentials(self, in_memory_db, managed_credentials, test_org):
        """Org users cannot access other organization's credentials."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Cannot access other org's credentials
        assert can_access_credential(in_memory_db, org_principal, "SAID_ORG2_CRED1") is False

    def test_user_without_org_cannot_access_managed_credentials(self, in_memory_db, managed_credentials):
        """Users without organization cannot access managed credentials."""
        no_org_principal = Principal(
            key_id="user:user@noorg.com",
            name="No Org User",
            roles={"issuer:readonly"},
            organization_id=None,
        )

        for cred in managed_credentials.values():
            assert can_access_credential(in_memory_db, no_org_principal, cred.said) is False

    def test_filter_credentials_by_org(self, in_memory_db, managed_credentials, test_org):
        """Filter credentials returns only accessible ones."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        all_saids = ["SAID_ORG1_CRED1", "SAID_ORG1_CRED2", "SAID_ORG2_CRED1"]
        filtered = filter_credentials_by_org(in_memory_db, org_principal, all_saids)

        assert sorted(filtered) == sorted(["SAID_ORG1_CRED1", "SAID_ORG1_CRED2"])


# =============================================================================
# Test Dossier Chain Scoping
# =============================================================================


class TestDossierChainScoping:
    """Tests for dossier chain access validation."""

    def test_system_admin_can_access_any_chain(self, in_memory_db, managed_credentials):
        """System admins can access any credential chain."""
        admin_principal = Principal(
            key_id="user:admin@system.com",
            name="System Admin",
            roles={"issuer:admin"},
            organization_id=None,
        )

        chain_saids = ["SAID_ORG1_CRED1", "SAID_ORG2_CRED1"]
        inaccessible = validate_dossier_chain_access(in_memory_db, admin_principal, chain_saids)

        assert inaccessible == []

    def test_org_user_chain_all_own_org(self, in_memory_db, managed_credentials, test_org):
        """Org user can access chain with all own org credentials."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        chain_saids = ["SAID_ORG1_CRED1", "SAID_ORG1_CRED2"]
        inaccessible = validate_dossier_chain_access(in_memory_db, org_principal, chain_saids)

        assert inaccessible == []

    def test_org_user_chain_with_cross_org_credential(self, in_memory_db, managed_credentials, test_org):
        """Org user cannot access chain containing other org's credential."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Chain includes credential from other org
        chain_saids = ["SAID_ORG1_CRED1", "SAID_ORG2_CRED1"]
        inaccessible = validate_dossier_chain_access(in_memory_db, org_principal, chain_saids)

        # Should report the cross-org credential as inaccessible
        assert "SAID_ORG2_CRED1" in inaccessible
        assert "SAID_ORG1_CRED1" not in inaccessible

    def test_unmanaged_credentials_allowed_in_chain(self, in_memory_db, test_org):
        """Unmanaged credentials (infrastructure) are allowed in chain."""
        org_principal = Principal(
            key_id="user:user@testcorp.com",
            name="Test User",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Chain includes unmanaged credential (not in ManagedCredential table)
        chain_saids = ["UNMANAGED_INFRA_CRED"]
        inaccessible = validate_dossier_chain_access(in_memory_db, org_principal, chain_saids)

        # Unmanaged credentials should be allowed (they're infrastructure)
        assert inaccessible == []


# =============================================================================
# Test Org Role Access
# =============================================================================


class TestOrgRoleAccess:
    """Tests for org-only principal access to endpoints."""

    def test_org_admin_roles_combined(self, in_memory_db, test_user, test_org):
        """Verify org roles are combined with system roles in principal."""
        store = DatabaseUserStore()
        principal, _ = store.verify(in_memory_db, "user@testcorp.com", "password123")

        # Principal should have org role
        assert "org:administrator" in principal.roles
        # Principal should have organization_id
        assert principal.organization_id == test_org.id

    def test_principal_from_org_api_key(self, in_memory_db, test_org_api_key, test_org):
        """Verify org API keys create principals with org context."""
        key, raw_key = test_org_api_key

        with patch("app.db.session.get_db_session") as mock_session:
            mock_session.return_value.__enter__ = MagicMock(return_value=in_memory_db)
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            principal, _ = verify_org_api_key(raw_key)

        # Principal should have org role
        assert "org:dossier_manager" in principal.roles
        # Principal should have organization_id
        assert principal.organization_id == test_org.id
        # Principal should NOT have system roles
        assert "issuer:admin" not in principal.roles
        assert "issuer:operator" not in principal.roles
        assert "issuer:readonly" not in principal.roles


# =============================================================================
# Test Combined System/Org Role Checks (Sprint 41)
# =============================================================================


class TestCombinedRoleChecks:
    """Tests for combined system/org role authorization.

    Sprint 41: Org-only principals (with org:dossier_manager or org:administrator)
    should be able to access credential/dossier endpoints that were previously
    restricted to system roles only.
    """

    def test_check_credential_access_allows_system_readonly(self):
        """System readonly role can access credential read endpoints."""
        from app.auth.roles import check_credential_access_role

        principal = Principal(
            key_id="user:system@example.com",
            name="System User",
            roles={"issuer:readonly"},
            organization_id=None,
        )

        # Should not raise
        check_credential_access_role(principal)

    def test_check_credential_access_allows_org_dossier_manager(self, test_org):
        """Org dossier_manager role can access credential read endpoints."""
        from app.auth.roles import check_credential_access_role

        principal = Principal(
            key_id="org_key:test-key",
            name="Org API Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )

        # Should not raise
        check_credential_access_role(principal)

    def test_check_credential_access_allows_org_administrator(self, test_org):
        """Org administrator role can access credential read endpoints."""
        from app.auth.roles import check_credential_access_role

        principal = Principal(
            key_id="user:admin@testcorp.com",
            name="Org Admin",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Should not raise (administrator includes dossier_manager permissions)
        check_credential_access_role(principal)

    def test_check_credential_access_denies_no_role(self, test_org):
        """Principal with no relevant roles is denied access."""
        from fastapi import HTTPException
        from app.auth.roles import check_credential_access_role

        principal = Principal(
            key_id="user:nobody@example.com",
            name="No Role User",
            roles=set(),  # No roles
            organization_id=test_org.id,
        )

        with pytest.raises(HTTPException) as exc_info:
            check_credential_access_role(principal)

        assert exc_info.value.status_code == 403

    def test_check_credential_write_allows_system_operator(self):
        """System operator role can access credential write endpoints."""
        from app.auth.roles import check_credential_write_role

        principal = Principal(
            key_id="user:operator@system.com",
            name="Operator",
            roles={"issuer:operator"},
            organization_id=None,
        )

        # Should not raise
        check_credential_write_role(principal)

    def test_check_credential_write_allows_org_dossier_manager(self, test_org):
        """Org dossier_manager role can access credential write endpoints."""
        from app.auth.roles import check_credential_write_role

        principal = Principal(
            key_id="org_key:test-key",
            name="Org API Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )

        # Should not raise
        check_credential_write_role(principal)

    def test_check_credential_write_denies_system_readonly(self):
        """System readonly role cannot access credential write endpoints."""
        from fastapi import HTTPException
        from app.auth.roles import check_credential_write_role

        principal = Principal(
            key_id="user:readonly@system.com",
            name="Readonly User",
            roles={"issuer:readonly"},
            organization_id=None,
        )

        with pytest.raises(HTTPException) as exc_info:
            check_credential_write_role(principal)

        assert exc_info.value.status_code == 403

    def test_check_credential_admin_allows_system_admin(self):
        """System admin role can perform admin operations."""
        from app.auth.roles import check_credential_admin_role

        principal = Principal(
            key_id="user:admin@system.com",
            name="System Admin",
            roles={"issuer:admin"},
            organization_id=None,
        )

        # Should not raise
        check_credential_admin_role(principal)

    def test_check_credential_admin_allows_org_administrator(self, test_org):
        """Org administrator role can perform admin operations on own org."""
        from app.auth.roles import check_credential_admin_role

        principal = Principal(
            key_id="user:admin@testcorp.com",
            name="Org Admin",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Should not raise
        check_credential_admin_role(principal)

    def test_check_credential_admin_denies_org_dossier_manager(self, test_org):
        """Org dossier_manager cannot perform admin operations."""
        from fastapi import HTTPException
        from app.auth.roles import check_credential_admin_role

        principal = Principal(
            key_id="org_key:test-key",
            name="Org API Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )

        with pytest.raises(HTTPException) as exc_info:
            check_credential_admin_role(principal)

        assert exc_info.value.status_code == 403

    def test_check_credential_admin_denies_system_operator(self):
        """System operator cannot perform admin operations."""
        from fastapi import HTTPException
        from app.auth.roles import check_credential_admin_role

        principal = Principal(
            key_id="user:operator@system.com",
            name="Operator",
            roles={"issuer:operator"},
            organization_id=None,
        )

        with pytest.raises(HTTPException) as exc_info:
            check_credential_admin_role(principal)

        assert exc_info.value.status_code == 403


class TestOrgRoleHierarchy:
    """Tests for org role hierarchy (administrator > dossier_manager)."""

    def test_has_org_role_with_administrator(self, test_org):
        """Org administrator includes dossier_manager permissions."""
        from app.auth.roles import has_org_role, OrgRole

        principal = Principal(
            key_id="user:admin@testcorp.com",
            name="Org Admin",
            roles={"org:administrator"},
            organization_id=test_org.id,
        )

        # Administrator has both roles
        assert has_org_role(principal, OrgRole.ADMINISTRATOR) is True
        assert has_org_role(principal, OrgRole.DOSSIER_MANAGER) is True

    def test_has_org_role_with_dossier_manager(self, test_org):
        """Org dossier_manager does not have administrator permissions."""
        from app.auth.roles import has_org_role, OrgRole

        principal = Principal(
            key_id="org_key:test-key",
            name="Org API Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )

        # Dossier manager only has dossier_manager
        assert has_org_role(principal, OrgRole.ADMINISTRATOR) is False
        assert has_org_role(principal, OrgRole.DOSSIER_MANAGER) is True

    def test_has_org_role_with_no_org_roles(self):
        """Principal with only system roles has no org roles."""
        from app.auth.roles import has_org_role, OrgRole

        principal = Principal(
            key_id="user:admin@system.com",
            name="System Admin",
            roles={"issuer:admin"},
            organization_id=None,
        )

        assert has_org_role(principal, OrgRole.ADMINISTRATOR) is False
        assert has_org_role(principal, OrgRole.DOSSIER_MANAGER) is False
