"""Tests for Sprint 67 Phase 2: Schema Authorization.

Tests cover:
- is_schema_authorized() per org type
- get_authorized_schemas() returns correct sets
- Unauthorized schema returns False
- Invalid org type handling
- GET /schema/authorized and /schemas/authorized endpoints
- Cross-org authorization (non-admin → 403, admin → 200)
"""

import uuid

import pytest
from httpx import AsyncClient

from app.auth.api_key import Principal
from app.auth.schema_auth import (
    SCHEMA_AUTHORIZATION,
    get_authorized_schemas,
    is_schema_authorized,
)
from app.db.models import Organization, OrgType


# Schema SAIDs for reference
QVI_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
EXT_LE_SAID = "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV"
VETTER_CERT_SAID = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"
GOVERNANCE_SAID = "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL"
EXT_BRAND_SAID = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"
TN_ALLOC_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
EXT_TN_ALLOC_SAID = "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_"
DE_GCD_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"


# =============================================================================
# SCHEMA_AUTHORIZATION mapping
# =============================================================================


def test_mapping_has_all_org_types():
    """Every OrgType value has an entry in SCHEMA_AUTHORIZATION."""
    for ot in OrgType:
        assert ot in SCHEMA_AUTHORIZATION, f"Missing entry for {ot}"


def test_mapping_no_overlap():
    """No schema SAID appears in more than one org type's set."""
    all_saids = []
    for ot, saids in SCHEMA_AUTHORIZATION.items():
        for said in saids:
            all_saids.append((ot, said))

    seen = {}
    for ot, said in all_saids:
        if said in seen:
            pytest.fail(f"SAID {said} appears in both {seen[said]} and {ot}")
        seen[said] = ot


# =============================================================================
# is_schema_authorized
# =============================================================================


class TestIsSchemaAuthorized:
    """Tests for is_schema_authorized()."""

    def test_root_authority_can_issue_qvi(self):
        assert is_schema_authorized("root_authority", QVI_SAID) is True

    def test_root_authority_cannot_issue_le(self):
        assert is_schema_authorized("root_authority", LE_SAID) is False

    def test_qvi_can_issue_le(self):
        assert is_schema_authorized("qvi", LE_SAID) is True

    def test_qvi_can_issue_ext_le(self):
        assert is_schema_authorized("qvi", EXT_LE_SAID) is True

    def test_qvi_cannot_issue_qvi(self):
        assert is_schema_authorized("qvi", QVI_SAID) is False

    def test_vetter_can_issue_vetter_cert(self):
        assert is_schema_authorized("vetter_authority", VETTER_CERT_SAID) is True

    def test_vetter_can_issue_governance(self):
        assert is_schema_authorized("vetter_authority", GOVERNANCE_SAID) is True

    def test_vetter_cannot_issue_brand(self):
        assert is_schema_authorized("vetter_authority", EXT_BRAND_SAID) is False

    def test_regular_can_issue_brand(self):
        assert is_schema_authorized("regular", EXT_BRAND_SAID) is True

    def test_regular_can_issue_tn_alloc(self):
        assert is_schema_authorized("regular", TN_ALLOC_SAID) is True

    def test_regular_can_issue_ext_tn_alloc(self):
        assert is_schema_authorized("regular", EXT_TN_ALLOC_SAID) is True

    def test_regular_can_issue_de_gcd(self):
        assert is_schema_authorized("regular", DE_GCD_SAID) is True

    def test_regular_cannot_issue_le(self):
        assert is_schema_authorized("regular", LE_SAID) is False

    def test_regular_cannot_issue_vetter_cert(self):
        assert is_schema_authorized("regular", VETTER_CERT_SAID) is False

    def test_invalid_org_type(self):
        assert is_schema_authorized("invalid_type", QVI_SAID) is False

    def test_unknown_schema(self):
        assert is_schema_authorized("regular", "EUnknownSAID123456789012345678901234567890") is False


# =============================================================================
# get_authorized_schemas
# =============================================================================


class TestGetAuthorizedSchemas:
    """Tests for get_authorized_schemas()."""

    def test_root_authority_schemas(self):
        saids = get_authorized_schemas("root_authority")
        assert QVI_SAID in saids
        assert len(saids) == 1

    def test_qvi_schemas(self):
        saids = get_authorized_schemas("qvi")
        assert LE_SAID in saids
        assert EXT_LE_SAID in saids
        assert len(saids) == 2

    def test_vetter_authority_schemas(self):
        saids = get_authorized_schemas("vetter_authority")
        assert VETTER_CERT_SAID in saids
        assert GOVERNANCE_SAID in saids
        assert len(saids) == 2

    def test_regular_schemas(self):
        saids = get_authorized_schemas("regular")
        assert EXT_BRAND_SAID in saids
        assert TN_ALLOC_SAID in saids
        assert EXT_TN_ALLOC_SAID in saids
        assert DE_GCD_SAID in saids
        assert len(saids) == 4

    def test_invalid_org_type_returns_empty(self):
        saids = get_authorized_schemas("nonexistent")
        assert saids == set()


# =============================================================================
# GET /schema/authorized and /schemas/authorized endpoints
# =============================================================================


def _create_test_org(*, org_type="regular"):
    """Create an org in the DB for endpoint tests."""
    from app.db.session import init_database, SessionLocal

    init_database()
    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=f"test-schema-auth-{uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=True,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return org_id
    finally:
        db.close()


class TestSchemaAuthorizedEndpoint:
    """Tests for GET /schema/authorized."""

    @pytest.mark.asyncio
    async def test_returns_schemas_for_regular_org(self, client: AsyncClient):
        org_id = _create_test_org(org_type="regular")
        response = await client.get(f"/schema/authorized?organization_id={org_id}")
        assert response.status_code == 200
        data = response.json()
        saids = {s["said"] for s in data["schemas"]}
        assert EXT_BRAND_SAID in saids
        assert TN_ALLOC_SAID in saids
        assert data["count"] == len(data["schemas"])

    @pytest.mark.asyncio
    async def test_returns_schemas_for_qvi_org(self, client: AsyncClient):
        org_id = _create_test_org(org_type="qvi")
        response = await client.get(f"/schema/authorized?organization_id={org_id}")
        assert response.status_code == 200
        data = response.json()
        saids = {s["said"] for s in data["schemas"]}
        assert LE_SAID in saids
        assert EXT_LE_SAID in saids
        # QVI should NOT see brand or TN schemas
        assert EXT_BRAND_SAID not in saids

    @pytest.mark.asyncio
    async def test_returns_404_for_missing_org(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        response = await client.get(f"/schema/authorized?organization_id={fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_compat_route_works(self, client: AsyncClient):
        """GET /schemas/authorized returns same result as /schema/authorized."""
        org_id = _create_test_org(org_type="vetter_authority")
        r1 = await client.get(f"/schema/authorized?organization_id={org_id}")
        r2 = await client.get(f"/schemas/authorized?organization_id={org_id}")
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json() == r2.json()
        saids = {s["said"] for s in r1.json()["schemas"]}
        assert VETTER_CERT_SAID in saids
        assert GOVERNANCE_SAID in saids


# =============================================================================
# Cross-org authorization tests
# =============================================================================


def _override_principal(principal: Principal):
    """Override require_auth dependency to return a specific principal."""
    import app.main as main_module
    import app.auth.roles as roles_module

    dep_fn = roles_module.require_auth.dependency
    main_module.app.dependency_overrides[dep_fn] = lambda: principal
    return main_module.app, dep_fn


def _clear_override(app, dep_fn):
    """Remove the dependency override."""
    app.dependency_overrides.pop(dep_fn, None)


class TestSchemaAuthorizedCrossOrg:
    """Cross-org authorization tests for /schema/authorized and /schemas/authorized.

    Sprint 67: Non-admin principals MUST NOT query another org's authorized
    schemas (403). System admins CAN query cross-org (200).
    """

    @pytest.mark.asyncio
    async def test_non_admin_cross_org_returns_403_primary(self, client: AsyncClient):
        """Non-admin querying another org's schemas on /schema/authorized → 403."""
        org_a_id = _create_test_org(org_type="regular")
        org_b_id = _create_test_org(org_type="qvi")

        non_admin = Principal(
            key_id="test-nonadmin",
            name="Non-Admin",
            roles={"issuer:readonly"},
            organization_id=org_a_id,
        )
        app, dep_fn = _override_principal(non_admin)
        try:
            resp = await client.get(f"/schema/authorized?organization_id={org_b_id}")
            assert resp.status_code == 403
            assert "system admins" in resp.json()["detail"].lower()
        finally:
            _clear_override(app, dep_fn)

    @pytest.mark.asyncio
    async def test_non_admin_cross_org_returns_403_compat(self, client: AsyncClient):
        """Non-admin querying another org's schemas on /schemas/authorized → 403."""
        org_a_id = _create_test_org(org_type="regular")
        org_b_id = _create_test_org(org_type="qvi")

        non_admin = Principal(
            key_id="test-nonadmin",
            name="Non-Admin",
            roles={"issuer:readonly"},
            organization_id=org_a_id,
        )
        app, dep_fn = _override_principal(non_admin)
        try:
            resp = await client.get(f"/schemas/authorized?organization_id={org_b_id}")
            assert resp.status_code == 403
        finally:
            _clear_override(app, dep_fn)

    @pytest.mark.asyncio
    async def test_admin_cross_org_returns_200_primary(self, client: AsyncClient):
        """Admin querying another org's schemas on /schema/authorized → 200."""
        org_a_id = _create_test_org(org_type="regular")
        org_b_id = _create_test_org(org_type="qvi")

        admin = Principal(
            key_id="test-admin",
            name="Admin",
            roles={"issuer:admin", "issuer:operator", "issuer:readonly"},
            organization_id=org_a_id,
        )
        app, dep_fn = _override_principal(admin)
        try:
            resp = await client.get(f"/schema/authorized?organization_id={org_b_id}")
            assert resp.status_code == 200
            saids = {s["said"] for s in resp.json()["schemas"]}
            assert LE_SAID in saids  # org B is QVI → authorized for LE
        finally:
            _clear_override(app, dep_fn)

    @pytest.mark.asyncio
    async def test_admin_cross_org_returns_200_compat(self, client: AsyncClient):
        """Admin querying another org's schemas on /schemas/authorized → 200."""
        org_a_id = _create_test_org(org_type="regular")
        org_b_id = _create_test_org(org_type="qvi")

        admin = Principal(
            key_id="test-admin",
            name="Admin",
            roles={"issuer:admin", "issuer:operator", "issuer:readonly"},
            organization_id=org_a_id,
        )
        app, dep_fn = _override_principal(admin)
        try:
            resp = await client.get(f"/schemas/authorized?organization_id={org_b_id}")
            assert resp.status_code == 200
            saids = {s["said"] for s in resp.json()["schemas"]}
            assert LE_SAID in saids
        finally:
            _clear_override(app, dep_fn)

    @pytest.mark.asyncio
    async def test_non_admin_own_org_returns_200(self, client: AsyncClient):
        """Non-admin querying own org's schemas → 200 (not cross-org)."""
        org_id = _create_test_org(org_type="regular")

        non_admin = Principal(
            key_id="test-nonadmin",
            name="Non-Admin",
            roles={"issuer:readonly"},
            organization_id=org_id,
        )
        app, dep_fn = _override_principal(non_admin)
        try:
            resp = await client.get(f"/schema/authorized?organization_id={org_id}")
            assert resp.status_code == 200
            saids = {s["said"] for s in resp.json()["schemas"]}
            assert EXT_BRAND_SAID in saids
        finally:
            _clear_override(app, dep_fn)
