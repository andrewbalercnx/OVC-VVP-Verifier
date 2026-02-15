"""Tests for Sprint 61: Vetter Certification API endpoints.

Tests cover:
- POST /vetter-certifications — issue VetterCertification for an org
- GET /vetter-certifications — list VetterCertifications
- GET /vetter-certifications/{said} — get by SAID, access control
- DELETE /vetter-certifications/{said} — revoke
- GET /organizations/{org_id}/constraints — constraint visibility
- GET /users/me/constraints — current user constraints
- VetterCert schema guard on generic /credential/issue endpoint
- Authorization checks (admin-only issuance, org-scoped reads)
"""

import uuid
from unittest.mock import patch, AsyncMock

import pytest
from httpx import AsyncClient

from app.db.models import ManagedCredential, Organization


# =============================================================================
# Schema SAIDs
# =============================================================================

VETTER_CERT_SCHEMA_SAID = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"
TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


# =============================================================================
# Helpers
# =============================================================================


def _init_app_db():
    """Ensure app database tables exist (lifespan not invoked in tests)."""
    from app.db.session import init_database
    init_database()


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_db_org(*, aid=None):
    """Create an org directly in the database (bypasses KERI infrastructure)."""
    _init_app_db()
    from app.db.session import SessionLocal

    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=unique_name("org"),
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=aid or f"E{uuid.uuid4().hex[:43]}",
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            enabled=True,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return {
            "id": org.id,
            "name": org.name,
            "aid": org.aid,
        }
    finally:
        db.close()


# =============================================================================
# POST /vetter-certifications
# =============================================================================


@pytest.mark.asyncio
async def test_issue_vetter_certification(client: AsyncClient):
    """Test issuing a VetterCertification for an org."""
    org = _create_db_org()

    mock_result = {
        "said": f"E{uuid.uuid4().hex[:43]}",
        "issuer_aid": f"E{uuid.uuid4().hex[:43]}",
        "vetter_aid": org["aid"],
        "organization_id": org["id"],
        "organization_name": org["name"],
        "ecc_targets": ["44", "1"],
        "jurisdiction_targets": ["GBR", "USA"],
        "name": "ACME Vetter",
        "certification_expiry": None,
        "status": "issued",
        "created_at": "2026-01-01T00:00:00",
    }

    with patch(
        "app.api.vetter_certification.issue_vetter_certification",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = await client.post(
            "/vetter-certifications",
            json={
                "organization_id": org["id"],
                "ecc_targets": ["44", "1"],
                "jurisdiction_targets": ["GBR", "USA"],
                "name": "ACME Vetter",
            },
        )

    assert response.status_code == 200, f"Issue failed: {response.text}"
    data = response.json()
    assert data["said"].startswith("E")
    assert data["organization_id"] == org["id"]
    assert data["organization_name"] == org["name"]
    assert data["ecc_targets"] == ["44", "1"]
    assert data["jurisdiction_targets"] == ["GBR", "USA"]
    assert data["status"] == "issued"


@pytest.mark.asyncio
async def test_issue_vetter_cert_duplicate_409(client: AsyncClient):
    """Issuing when org already has active cert should fail with 409."""
    org = _create_db_org()

    from fastapi import HTTPException

    with patch(
        "app.api.vetter_certification.issue_vetter_certification",
        new_callable=AsyncMock,
        side_effect=HTTPException(
            status_code=409,
            detail="Organization already has active VetterCertification. Revoke it first.",
        ),
    ):
        response = await client.post(
            "/vetter-certifications",
            json={
                "organization_id": org["id"],
                "ecc_targets": ["44"],
                "jurisdiction_targets": ["GBR"],
                "name": "Second Cert",
            },
        )

    assert response.status_code == 409
    assert "already has active" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_issue_vetter_cert_org_not_found(client: AsyncClient):
    """Issuing for a non-existent org should fail with 404."""
    _init_app_db()

    from fastapi import HTTPException

    with patch(
        "app.api.vetter_certification.issue_vetter_certification",
        new_callable=AsyncMock,
        side_effect=HTTPException(status_code=404, detail="Organization not found"),
    ):
        response = await client.post(
            "/vetter-certifications",
            json={
                "organization_id": str(uuid.uuid4()),
                "ecc_targets": ["44"],
                "jurisdiction_targets": ["GBR"],
                "name": "Test",
            },
        )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_issue_vetter_cert_invalid_ecc(client: AsyncClient):
    """Invalid ECC code should fail with 422 (validation error)."""
    response = await client.post(
        "/vetter-certifications",
        json={
            "organization_id": str(uuid.uuid4()),
            "ecc_targets": ["999"],  # Invalid
            "jurisdiction_targets": ["GBR"],
            "name": "Test",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_issue_vetter_cert_invalid_jurisdiction(client: AsyncClient):
    """Invalid jurisdiction code should fail with 422."""
    response = await client.post(
        "/vetter-certifications",
        json={
            "organization_id": str(uuid.uuid4()),
            "ecc_targets": ["44"],
            "jurisdiction_targets": ["XXX"],  # Invalid
            "name": "Test",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_issue_vetter_cert_empty_ecc_fails(client: AsyncClient):
    """Empty ECC targets list should fail (min_length=1)."""
    response = await client.post(
        "/vetter-certifications",
        json={
            "organization_id": str(uuid.uuid4()),
            "ecc_targets": [],
            "jurisdiction_targets": ["GBR"],
            "name": "Test",
        },
    )
    assert response.status_code == 422


# =============================================================================
# GET /vetter-certifications
# =============================================================================


@pytest.mark.asyncio
async def test_list_vetter_certifications(client: AsyncClient):
    """List all VetterCertifications."""
    _init_app_db()
    from app.db.session import SessionLocal

    org = _create_db_org()
    cert_said = f"E{uuid.uuid4().hex[:43]}"

    db = SessionLocal()
    try:
        mc = ManagedCredential(
            said=cert_said,
            organization_id=org["id"],
            schema_said=VETTER_CERT_SCHEMA_SAID,
            issuer_aid=f"E{uuid.uuid4().hex[:43]}",
        )
        db.add(mc)
        db.commit()
    finally:
        db.close()

    response = await client.get("/vetter-certifications")
    assert response.status_code == 200
    data = response.json()

    assert data["count"] >= 1
    saids = [c["said"] for c in data["certifications"]]
    assert cert_said in saids


@pytest.mark.asyncio
async def test_list_vetter_certs_filter_by_org(client: AsyncClient):
    """List VetterCerts filtered by organization_id."""
    _init_app_db()
    from app.db.session import SessionLocal

    org1 = _create_db_org()
    org2 = _create_db_org()
    cert1_said = f"E{uuid.uuid4().hex[:43]}"
    cert2_said = f"E{uuid.uuid4().hex[:43]}"

    db = SessionLocal()
    try:
        db.add(ManagedCredential(
            said=cert1_said,
            organization_id=org1["id"],
            schema_said=VETTER_CERT_SCHEMA_SAID,
            issuer_aid="Egsma",
        ))
        db.add(ManagedCredential(
            said=cert2_said,
            organization_id=org2["id"],
            schema_said=VETTER_CERT_SCHEMA_SAID,
            issuer_aid="Egsma",
        ))
        db.commit()
    finally:
        db.close()

    response = await client.get(
        f"/vetter-certifications?organization_id={org1['id']}"
    )
    assert response.status_code == 200
    data = response.json()

    saids = [c["said"] for c in data["certifications"]]
    assert cert1_said in saids
    assert cert2_said not in saids


# =============================================================================
# GET /vetter-certifications/{said}
# =============================================================================


@pytest.mark.asyncio
async def test_get_vetter_certification(client: AsyncClient):
    """Get a VetterCertification by SAID."""
    _init_app_db()
    from app.db.session import SessionLocal

    org = _create_db_org()
    cert_said = f"E{uuid.uuid4().hex[:43]}"

    db = SessionLocal()
    try:
        db.add(ManagedCredential(
            said=cert_said,
            organization_id=org["id"],
            schema_said=VETTER_CERT_SCHEMA_SAID,
            issuer_aid="Egsma",
        ))
        db.commit()
    finally:
        db.close()

    response = await client.get(f"/vetter-certifications/{cert_said}")
    assert response.status_code == 200
    data = response.json()
    assert data["said"] == cert_said
    assert data["organization_id"] == org["id"]


@pytest.mark.asyncio
async def test_get_vetter_cert_not_found(client: AsyncClient):
    """Get a non-existent VetterCert should 404."""
    _init_app_db()
    response = await client.get(
        "/vetter-certifications/ENotExist12345678901234567890123456789012"
    )
    assert response.status_code == 404


# =============================================================================
# DELETE /vetter-certifications/{said}
# =============================================================================


@pytest.mark.asyncio
async def test_revoke_vetter_certification(client: AsyncClient):
    """Revoke a VetterCertification."""
    org = _create_db_org()
    cert_said = f"E{uuid.uuid4().hex[:43]}"

    mock_result = {
        "said": cert_said,
        "issuer_aid": "Egsma",
        "vetter_aid": org["aid"],
        "organization_id": org["id"],
        "organization_name": org["name"],
        "ecc_targets": [],
        "jurisdiction_targets": [],
        "name": "",
        "certification_expiry": None,
        "status": "revoked",
        "created_at": "2026-01-01T00:00:00",
    }

    with patch(
        "app.api.vetter_certification.revoke_vetter_certification",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = await client.delete(
            f"/vetter-certifications/{cert_said}"
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "revoked"


@pytest.mark.asyncio
async def test_revoke_not_found(client: AsyncClient):
    """Revoking a non-existent VetterCert should 404."""
    _init_app_db()

    from fastapi import HTTPException

    with patch(
        "app.api.vetter_certification.revoke_vetter_certification",
        new_callable=AsyncMock,
        side_effect=HTTPException(status_code=404, detail="VetterCertification not found"),
    ):
        response = await client.delete(
            "/vetter-certifications/ENotExist12345678901234567890123456789012"
        )

    assert response.status_code == 404


# =============================================================================
# GET /organizations/{org_id}/constraints
# =============================================================================


@pytest.mark.asyncio
async def test_get_org_constraints_with_cert(client: AsyncClient):
    """Get constraints for an org with an active VetterCert."""
    org = _create_db_org()

    mock_result = {
        "organization_id": org["id"],
        "organization_name": org["name"],
        "vetter_certification_said": f"E{uuid.uuid4().hex[:43]}",
        "ecc_targets": ["44", "1"],
        "jurisdiction_targets": ["GBR", "USA"],
        "certification_status": "issued",
        "certification_expiry": None,
    }

    with patch(
        "app.api.vetter_certification.get_org_constraints",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = await client.get(f"/organizations/{org['id']}/constraints")

    assert response.status_code == 200
    data = response.json()
    assert data["organization_id"] == org["id"]
    assert data["vetter_certification_said"] is not None
    assert data["ecc_targets"] == ["44", "1"]
    assert data["jurisdiction_targets"] == ["GBR", "USA"]
    assert data["certification_status"] == "issued"


@pytest.mark.asyncio
async def test_get_org_constraints_no_cert(client: AsyncClient):
    """Constraints for org without VetterCert should be null."""
    org = _create_db_org()

    mock_result = {
        "organization_id": org["id"],
        "organization_name": org["name"],
        "vetter_certification_said": None,
        "ecc_targets": None,
        "jurisdiction_targets": None,
        "certification_status": None,
        "certification_expiry": None,
    }

    with patch(
        "app.api.vetter_certification.get_org_constraints",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = await client.get(f"/organizations/{org['id']}/constraints")

    assert response.status_code == 200
    data = response.json()
    assert data["vetter_certification_said"] is None
    assert data["ecc_targets"] is None


@pytest.mark.asyncio
async def test_get_constraints_org_not_found(client: AsyncClient):
    """Constraints for non-existent org should 404."""
    _init_app_db()

    from fastapi import HTTPException

    with patch(
        "app.api.vetter_certification.get_org_constraints",
        new_callable=AsyncMock,
        side_effect=HTTPException(status_code=404, detail="Organization not found"),
    ):
        response = await client.get(
            f"/organizations/{uuid.uuid4()}/constraints"
        )

    assert response.status_code == 404


# =============================================================================
# VetterCert Schema Guard
# =============================================================================


@pytest.mark.asyncio
async def test_generic_issue_rejects_vetter_cert_schema(client: AsyncClient):
    """POST /credential/issue should reject VetterCertification schema.

    The schema guard fires before KERI operations, so we don't need a
    real identity/registry — just send a request with the blocked schema SAID.
    """
    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": "any-registry",
            "schema_said": VETTER_CERT_SCHEMA_SAID,
            "attributes": {"name": "test"},
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 400
    assert "vetter-certifications" in response.json()["detail"].lower()


# =============================================================================
# Authorization Tests (with auth enabled)
# =============================================================================


@pytest.mark.asyncio
async def test_issue_vetter_cert_requires_admin(
    client_with_auth: AsyncClient, operator_headers: dict
):
    """POST /vetter-certifications requires admin role."""
    _init_app_db()
    response = await client_with_auth.post(
        "/vetter-certifications",
        json={
            "organization_id": str(uuid.uuid4()),
            "ecc_targets": ["44"],
            "jurisdiction_targets": ["GBR"],
            "name": "Test",
        },
        headers=operator_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_vetter_certs_requires_admin(
    client_with_auth: AsyncClient, readonly_headers: dict
):
    """GET /vetter-certifications requires admin role."""
    _init_app_db()
    response = await client_with_auth.get(
        "/vetter-certifications",
        headers=readonly_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_delete_vetter_cert_requires_admin(
    client_with_auth: AsyncClient, operator_headers: dict
):
    """DELETE /vetter-certifications/{said} requires admin role."""
    _init_app_db()
    response = await client_with_auth.delete(
        "/vetter-certifications/Etest1234567890123456789012345678901234",
        headers=operator_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_vetter_cert_readonly_allowed(
    client_with_auth: AsyncClient, admin_headers: dict, readonly_headers: dict
):
    """GET /vetter-certifications/{said} is accessible by system readonly role."""
    _init_app_db()
    from app.db.session import SessionLocal

    org = _create_db_org()
    cert_said = f"E{uuid.uuid4().hex[:43]}"

    db = SessionLocal()
    try:
        db.add(ManagedCredential(
            said=cert_said,
            organization_id=org["id"],
            schema_said=VETTER_CERT_SCHEMA_SAID,
            issuer_aid="Egsma",
        ))
        db.commit()
    finally:
        db.close()

    resp = await client_with_auth.get(
        f"/vetter-certifications/{cert_said}",
        headers=readonly_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["said"] == cert_said


@pytest.mark.asyncio
async def test_constraints_requires_auth(
    client_with_auth: AsyncClient,
):
    """GET /organizations/{org_id}/constraints requires authentication."""
    response = await client_with_auth.get(
        f"/organizations/{uuid.uuid4()}/constraints"
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_users_me_constraints_requires_auth(
    client_with_auth: AsyncClient,
):
    """GET /users/me/constraints requires authentication."""
    response = await client_with_auth.get("/users/me/constraints")
    assert response.status_code == 401
