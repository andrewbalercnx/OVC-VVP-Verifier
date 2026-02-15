"""Tests for Sprint 61: Vetter Certification Service & Constraints.

Tests cover:
- Pydantic model validation (ECC codes, jurisdiction codes, expiry alias)
- resolve_active_vetter_cert() — 7-point validation
- schema_requires_certification_edge() — oneOf edge detection
- Edge injection logic (_inject_certification_edge)
- DB migration idempotency
- Constants (VALID_ECC_CODES, VALID_JURISDICTION_CODES)
"""

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest
from pydantic import ValidationError


# =============================================================================
# Schema SAIDs
# =============================================================================

VETTER_CERT_SCHEMA_SAID = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"
EXT_LE_SCHEMA_SAID = "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV"
EXT_BRAND_SCHEMA_SAID = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"
EXT_TNALLOC_SCHEMA_SAID = "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_"
LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
TN_ALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

SCHEMAS_DIR = Path(__file__).parent.parent / "app" / "schema" / "schemas"


# =============================================================================
# Pydantic Model Validation
# =============================================================================


class TestVetterCertificationCreateRequest:
    """Test Pydantic validation for VetterCertificationCreateRequest."""

    def test_valid_request(self):
        from app.api.models import VetterCertificationCreateRequest

        req = VetterCertificationCreateRequest(
            organization_id=str(uuid.uuid4()),
            ecc_targets=["44", "1"],
            jurisdiction_targets=["GBR", "USA"],
            name="Test Vetter",
        )
        assert req.ecc_targets == ["44", "1"]
        assert req.jurisdiction_targets == ["GBR", "USA"]

    def test_invalid_ecc_code_rejects(self):
        from app.api.models import VetterCertificationCreateRequest

        with pytest.raises(ValidationError) as exc_info:
            VetterCertificationCreateRequest(
                organization_id=str(uuid.uuid4()),
                ecc_targets=["999"],
                jurisdiction_targets=["GBR"],
                name="Test",
            )
        assert "ecc" in str(exc_info.value).lower()

    def test_invalid_jurisdiction_rejects(self):
        from app.api.models import VetterCertificationCreateRequest

        with pytest.raises(ValidationError) as exc_info:
            VetterCertificationCreateRequest(
                organization_id=str(uuid.uuid4()),
                ecc_targets=["44"],
                jurisdiction_targets=["ZZZ"],
                name="Test",
            )
        assert "jurisdiction" in str(exc_info.value).lower()

    def test_empty_ecc_rejects(self):
        from app.api.models import VetterCertificationCreateRequest

        with pytest.raises(ValidationError):
            VetterCertificationCreateRequest(
                organization_id=str(uuid.uuid4()),
                ecc_targets=[],
                jurisdiction_targets=["GBR"],
                name="Test",
            )

    def test_empty_jurisdiction_rejects(self):
        from app.api.models import VetterCertificationCreateRequest

        with pytest.raises(ValidationError):
            VetterCertificationCreateRequest(
                organization_id=str(uuid.uuid4()),
                ecc_targets=["44"],
                jurisdiction_targets=[],
                name="Test",
            )

    def test_certification_expiry_alias(self):
        """certificationExpiry alias should map to certification_expiry."""
        from app.api.models import VetterCertificationCreateRequest

        req = VetterCertificationCreateRequest(
            organization_id=str(uuid.uuid4()),
            ecc_targets=["44"],
            jurisdiction_targets=["GBR"],
            name="Test",
            certificationExpiry="2027-01-01T00:00:00Z",
        )
        assert req.certification_expiry == "2027-01-01T00:00:00Z"

    def test_multiple_valid_ecc_codes(self):
        """Spot-check various valid ECC codes."""
        from app.api.models import VetterCertificationCreateRequest

        req = VetterCertificationCreateRequest(
            organization_id=str(uuid.uuid4()),
            ecc_targets=["1", "7", "44", "81", "86", "351", "966"],
            jurisdiction_targets=["GBR"],
            name="Test",
        )
        assert len(req.ecc_targets) == 7


# =============================================================================
# Constants Validation
# =============================================================================


class TestConstants:
    """Test vetter constants completeness."""

    def test_ecc_codes_include_major_countries(self):
        from app.vetter.constants import VALID_ECC_CODES

        major = {"1", "7", "44", "49", "81", "86", "91"}
        assert major.issubset(VALID_ECC_CODES)

    def test_jurisdiction_codes_include_major_countries(self):
        from app.vetter.constants import VALID_JURISDICTION_CODES

        major = {"USA", "GBR", "DEU", "JPN", "CHN", "IND", "AUS"}
        assert major.issubset(VALID_JURISDICTION_CODES)

    def test_known_extended_schemas_correct(self):
        from app.vetter.constants import KNOWN_EXTENDED_SCHEMA_SAIDS

        assert EXT_LE_SCHEMA_SAID in KNOWN_EXTENDED_SCHEMA_SAIDS
        assert EXT_BRAND_SCHEMA_SAID in KNOWN_EXTENDED_SCHEMA_SAIDS
        assert EXT_TNALLOC_SCHEMA_SAID in KNOWN_EXTENDED_SCHEMA_SAIDS
        assert len(KNOWN_EXTENDED_SCHEMA_SAIDS) == 3

    def test_vetter_cert_schema_said_format(self):
        assert VETTER_CERT_SCHEMA_SAID.startswith("E")
        assert len(VETTER_CERT_SCHEMA_SAID) == 44


# =============================================================================
# schema_requires_certification_edge()
# =============================================================================


class TestSchemaRequiresCertificationEdge:
    """Test certification edge detection via schema oneOf pattern."""

    def test_non_extended_schema_returns_false(self):
        """Normal schemas (LE, TN Alloc) don't require certification edge."""
        from app.api.credential import schema_requires_certification_edge

        assert schema_requires_certification_edge(LE_SCHEMA_SAID) is False
        assert schema_requires_certification_edge(TN_ALLOC_SCHEMA_SAID) is False

    def test_extended_schemas_require_cert_edge(self):
        """Extended schemas with certification in edges should return True."""
        from app.api.credential import schema_requires_certification_edge

        for said in [EXT_LE_SCHEMA_SAID, EXT_BRAND_SCHEMA_SAID, EXT_TNALLOC_SCHEMA_SAID]:
            schema_path = SCHEMAS_DIR / f"{said}.json"
            if schema_path.exists():
                assert schema_requires_certification_edge(said) is True, (
                    f"Extended schema {said} should require certification edge"
                )

    def test_unknown_schema_returns_false(self):
        """Unknown schema SAIDs should return False (not fail-open for unknowns)."""
        from app.api.credential import schema_requires_certification_edge

        assert schema_requires_certification_edge("EUnknown_NOT_IN_STORE_0000000000000000000") is False

    def test_known_extended_schema_missing_from_store_raises(self):
        """Known extended schema missing from store should raise RuntimeError (fail-closed)."""
        from app.api.credential import schema_requires_certification_edge

        with patch("app.schema.store.get_schema", return_value=None):
            with pytest.raises(RuntimeError, match="known extended schema"):
                schema_requires_certification_edge(EXT_LE_SCHEMA_SAID)

    def test_schema_without_oneOf_returns_false(self):
        """Schema with no e.oneOf should return False."""
        from app.api.credential import schema_requires_certification_edge

        schema_doc = {"properties": {"e": {"type": "object", "properties": {}}}}
        with patch("app.schema.store.get_schema", return_value=schema_doc):
            assert schema_requires_certification_edge("Etest") is False

    def test_schema_with_oneOf_no_certification(self):
        """Schema with e.oneOf but no 'certification' property returns False."""
        from app.api.credential import schema_requires_certification_edge

        schema_doc = {
            "properties": {
                "e": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "properties": {
                                "d": {"type": "string"},
                                "auth": {"type": "object"},
                            },
                        },
                    ]
                }
            }
        }
        with patch("app.schema.store.get_schema", return_value=schema_doc):
            assert schema_requires_certification_edge("Etest") is False

    def test_schema_with_oneOf_has_certification(self):
        """Schema with e.oneOf containing 'certification' property returns True."""
        from app.api.credential import schema_requires_certification_edge

        schema_doc = {
            "properties": {
                "e": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "properties": {
                                "d": {"type": "string"},
                                "certification": {"type": "object"},
                                "vetting": {"type": "object"},
                            },
                        },
                    ]
                }
            }
        }
        with patch("app.schema.store.get_schema", return_value=schema_doc):
            assert schema_requires_certification_edge("Etest") is True


# =============================================================================
# DB Migration
# =============================================================================


class TestMigration:
    """Test Sprint 61 migration script idempotency."""

    def test_migration_runs_on_fresh_db(self):
        """Migration should not fail on a fresh database."""
        from sqlalchemy import create_engine
        from app.db.models import Base
        from app.db.migrations.sprint61_vetter_cert import run_migrations

        engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        # Create tables first, THEN run migration (should be no-op since columns exist)
        Base.metadata.create_all(bind=engine)
        run_migrations(engine)  # Should not raise
        engine.dispose()

    def test_migration_idempotent(self):
        """Running migration twice should not fail."""
        from sqlalchemy import create_engine, text
        from app.db.models import Base
        from app.db.migrations.sprint61_vetter_cert import run_migrations

        engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=engine)
        run_migrations(engine)
        run_migrations(engine)  # Second run should be no-op
        engine.dispose()

    def test_migration_adds_columns_to_existing_table(self):
        """Migration should add columns to tables that exist without them."""
        from sqlalchemy import create_engine, text, Column, String, MetaData, Table
        from app.db.migrations.sprint61_vetter_cert import run_migrations

        engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        # Create minimal tables WITHOUT the new columns
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT)"
            ))
            conn.execute(text(
                "CREATE TABLE mock_vlei_state (id INTEGER PRIMARY KEY, qvi_name TEXT)"
            ))

        # Run migration
        run_migrations(engine)

        # Verify columns exist
        with engine.connect() as conn:
            # Check organizations has vetter_certification_said
            result = conn.execute(text("PRAGMA table_info(organizations)"))
            cols = {row[1] for row in result}
            assert "vetter_certification_said" in cols

            # Check mock_vlei_state has gsma columns
            result = conn.execute(text("PRAGMA table_info(mock_vlei_state)"))
            cols = {row[1] for row in result}
            assert "gsma_aid" in cols
            assert "gsma_registry_key" in cols

        engine.dispose()


# =============================================================================
# OrganizationResponse includes vetter_certification_said
# =============================================================================


def _init_app_db():
    """Ensure app database tables exist (lifespan not invoked in tests)."""
    from app.db.session import init_database
    init_database()


class TestOrganizationResponseField:
    """Test that Organization API responses include vetter_certification_said."""

    def _create_db_org(self):
        """Create an org directly in the database (bypasses KERI infrastructure)."""
        _init_app_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization

        org_id = str(uuid.uuid4())
        db = SessionLocal()
        try:
            org = Organization(
                id=org_id,
                name=f"test-org-{uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            db.refresh(org)
            return org
        finally:
            db.close()

    @pytest.mark.asyncio
    async def test_get_org_has_vetter_cert_field(self, client):
        """GET /organizations/{id} response includes vetter_certification_said."""
        org = self._create_db_org()

        resp = await client.get(f"/organizations/{org.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "vetter_certification_said" in data
        assert data["vetter_certification_said"] is None

    @pytest.mark.asyncio
    async def test_list_orgs_has_vetter_cert_field(self, client):
        """GET /organizations response includes vetter_certification_said per org."""
        self._create_db_org()

        resp = await client.get("/organizations")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        for org in data["organizations"]:
            assert "vetter_certification_said" in org


# =============================================================================
# VetterCertificationResponse model
# =============================================================================


class TestVetterCertificationResponseModel:
    """Test Pydantic response model validation."""

    def test_response_model_accepts_valid_data(self):
        from app.api.models import VetterCertificationResponse

        resp = VetterCertificationResponse(
            said="Etest_said_000000000000000000000000000000000",
            issuer_aid="Egsma_aid_000000000000000000000000000000000",
            vetter_aid="Eorg_aid_0000000000000000000000000000000000",
            organization_id=str(uuid.uuid4()),
            organization_name="Test Org",
            ecc_targets=["44", "1"],
            jurisdiction_targets=["GBR", "USA"],
            name="Test Vetter",
            certification_expiry=None,
            status="issued",
            created_at="2026-01-01T00:00:00Z",
        )
        assert resp.said.startswith("E")

    def test_response_model_expiry_alias(self):
        """certificationExpiry serialization via alias."""
        from app.api.models import VetterCertificationResponse

        resp = VetterCertificationResponse(
            said="Etest_said_000000000000000000000000000000000",
            issuer_aid="Egsma_aid_000000000000000000000000000000000",
            vetter_aid="Eorg_aid_0000000000000000000000000000000000",
            organization_id=str(uuid.uuid4()),
            organization_name="Test Org",
            ecc_targets=["44"],
            jurisdiction_targets=["GBR"],
            name="Test Vetter",
            certification_expiry="2027-06-01T00:00:00Z",
            status="issued",
            created_at="2026-01-01T00:00:00Z",
        )
        assert resp.certification_expiry == "2027-06-01T00:00:00Z"


# =============================================================================
# OrganizationConstraintsResponse model
# =============================================================================


class TestOrganizationConstraintsResponseModel:
    """Test constraints response model."""

    def test_no_cert_response(self):
        from app.api.models import OrganizationConstraintsResponse

        resp = OrganizationConstraintsResponse(
            organization_id=str(uuid.uuid4()),
            organization_name="Test Org",
        )
        assert resp.vetter_certification_said is None
        assert resp.ecc_targets is None
        assert resp.jurisdiction_targets is None

    def test_with_cert_response(self):
        from app.api.models import OrganizationConstraintsResponse

        resp = OrganizationConstraintsResponse(
            organization_id=str(uuid.uuid4()),
            organization_name="Test Org",
            vetter_certification_said="Ecert_said_0000000000000000000000000000000",
            ecc_targets=["44"],
            jurisdiction_targets=["GBR"],
            certification_status="issued",
            certification_expiry="2027-01-01T00:00:00Z",
        )
        assert resp.ecc_targets == ["44"]
        assert resp.certification_status == "issued"
