"""Tests for Sprint 65: Credential Edge Integration.

Tests cover:
- Credential issuance with edge payloads including operator (o) field
- Edge payload structure verification ({n, s, o})
- Credential list filtering for edge candidate loading (org_id, schema_said)
- Credential list relationship field for I2I filtering
"""

import pytest
import uuid

from httpx import AsyncClient


# =============================================================================
# Schema SAIDs
# =============================================================================

TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"


# =============================================================================
# Helpers
# =============================================================================


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def create_test_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity."""
    name = name or unique_name("identity")
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    return response.json()["identity"]


async def create_test_registry(
    client: AsyncClient, identity_name: str, registry_name: str = None
) -> dict:
    """Helper to create a test registry."""
    registry_name = registry_name or unique_name("registry")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity_name,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Failed to create registry: {response.text}"
    return response.json()["registry"]


def _create_test_org(org_type: str = "regular") -> str:
    """Create a test org in DB. Returns org_id (Sprint 67: required for cred issuance)."""
    from app.db.session import init_database, SessionLocal
    from app.db.models import Organization

    init_database()
    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=f"edge-test-{uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=f"E{uuid.uuid4().hex[:43]}",
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=True,
        )
        db.add(org)
        db.commit()
        return org_id
    finally:
        db.close()


async def setup_identity_and_registry(client: AsyncClient) -> tuple[dict, dict, str]:
    """Helper to set up identity, registry, and org for tests."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    org_id = _create_test_org("regular")

    # Sprint 67: Sync org AID and registry_key with real KERI identity/registry
    from app.db.session import SessionLocal
    from app.db.models import Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        org.aid = identity["aid"]
        org.registry_key = registry["registry_key"]
        db.commit()
    finally:
        db.close()

    return identity, registry, org_id


# =============================================================================
# Edge Payload Tests
# =============================================================================


class TestCredentialEdgePayload:
    """Tests that credential issuance accepts edge payloads with operator field."""

    @pytest.mark.asyncio
    async def test_issue_with_edges_including_operator(self, client: AsyncClient):
        """Issue a credential with edges that include the 'o' (operator) field."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        # First issue a credential to use as an edge target
        target_response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025551234"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert target_response.status_code == 200
        target_said = target_response.json()["credential"]["said"]

        # Issue another credential with edges referencing the first
        response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025559876"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "edges": {
                    "tnalloc": {
                        "n": target_said,
                        "s": TN_ALLOCATION_SCHEMA,
                        "o": "I2I",
                    },
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert response.status_code == 200
        cred = response.json()["credential"]
        assert cred["said"].startswith("E")

    @pytest.mark.asyncio
    async def test_issue_with_edges_no_operator(self, client: AsyncClient):
        """Issue a credential with edges without the 'o' field (optional)."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        target_response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025551111"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert target_response.status_code == 200
        target_said = target_response.json()["credential"]["said"]

        response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025552222"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "edges": {
                    "myEdge": {
                        "n": target_said,
                        "s": TN_ALLOCATION_SCHEMA,
                    },
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_edge_payload_structure_in_detail(self, client: AsyncClient):
        """Verify edge payload {n, s, o} is preserved in credential detail."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        target_response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025553333"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert target_response.status_code == 200
        target_said = target_response.json()["credential"]["said"]

        # Issue with explicit edge
        issue_response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025554444"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "edges": {
                    "testEdge": {
                        "n": target_said,
                        "s": TN_ALLOCATION_SCHEMA,
                        "o": "NI2I",
                    },
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert issue_response.status_code == 200
        cred_said = issue_response.json()["credential"]["said"]

        # Fetch detail and verify edges
        detail_response = await client.get(f"/credential/{cred_said}")
        assert detail_response.status_code == 200
        detail = detail_response.json()

        assert detail["edges"] is not None
        assert "testEdge" in detail["edges"]
        edge = detail["edges"]["testEdge"]
        assert edge["n"] == target_said
        assert edge["s"] == TN_ALLOCATION_SCHEMA
        assert edge["o"] == "NI2I"


# =============================================================================
# Credential List Filtering Tests
# =============================================================================


class TestCredentialListFiltering:
    """Tests that credential listing supports the filters used by edge pickers."""

    @pytest.mark.asyncio
    async def test_list_by_schema_said(self, client: AsyncClient):
        """GET /credential?schema_said=... filters by schema."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        # Issue credential with TN Allocation schema
        response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025555555"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )
        assert response.status_code == 200

        # List with schema filter
        list_response = await client.get(
            f"/credential?schema_said={TN_ALLOCATION_SCHEMA}"
        )
        assert list_response.status_code == 200
        data = list_response.json()
        assert data["count"] >= 1
        for cred in data["credentials"]:
            assert cred["schema_said"] == TN_ALLOCATION_SCHEMA

    @pytest.mark.asyncio
    async def test_list_includes_status(self, client: AsyncClient):
        """Listed credentials include status field."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025556666"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
                "organization_id": org_id,
            },
        )

        list_response = await client.get("/credential")
        assert list_response.status_code == 200
        data = list_response.json()
        assert data["count"] >= 1
        for cred in data["credentials"]:
            assert "status" in cred
            assert cred["status"] in ("issued", "revoked")
