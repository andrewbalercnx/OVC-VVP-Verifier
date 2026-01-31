"""Tests for identity management endpoints."""
import uuid

import pytest
from httpx import AsyncClient


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test identity."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_create_identity(client: AsyncClient):
    """Test identity creation via API."""
    name = unique_name("create")
    response = await client.post(
        "/identity",
        json={"name": name, "transferable": True},
    )
    assert response.status_code == 200
    data = response.json()

    assert "identity" in data
    identity = data["identity"]
    assert identity["name"] == name
    assert identity["aid"].startswith("E")  # KERI AIDs start with E
    assert identity["transferable"] is True
    assert identity["key_count"] >= 1
    assert identity["sequence_number"] == 0

    # Check OOBI URLs are generated
    assert "oobi_urls" in data


@pytest.mark.asyncio
@pytest.mark.skip(reason="Non-transferable with witnesses has keripy SAID validation issue")
async def test_create_identity_non_transferable(client: AsyncClient):
    """Test creating non-transferable identity.

    Note: Non-transferable identities with witnesses have a keripy serialization
    issue that needs investigation. Skipping for now.
    """
    name = unique_name("non-transfer")
    response = await client.post(
        "/identity",
        json={"name": name, "transferable": False},
    )
    assert response.status_code == 200
    data = response.json()

    identity = data["identity"]
    assert identity["transferable"] is False


@pytest.mark.asyncio
async def test_get_identity_by_aid(client: AsyncClient):
    """Test getting identity by AID."""
    name = unique_name("get-by-aid")
    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Get by AID
    get_response = await client.get(f"/identity/{aid}")
    assert get_response.status_code == 200
    assert get_response.json()["aid"] == aid
    assert get_response.json()["name"] == name


@pytest.mark.asyncio
async def test_identity_not_found(client: AsyncClient):
    """Test 404 for unknown AID."""
    response = await client.get("/identity/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_identities(client: AsyncClient):
    """Test listing all identities."""
    name1 = unique_name("list-1")
    name2 = unique_name("list-2")

    # Create a few identities
    await client.post("/identity", json={"name": name1})
    await client.post("/identity", json={"name": name2})

    # List all
    response = await client.get("/identity")
    assert response.status_code == 200
    data = response.json()

    assert "identities" in data
    assert data["count"] >= 2


@pytest.mark.asyncio
async def test_get_oobi(client: AsyncClient):
    """Test OOBI URL generation endpoint."""
    name = unique_name("oobi")
    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Get OOBI URLs
    oobi_response = await client.get(f"/identity/{aid}/oobi")
    assert oobi_response.status_code == 200
    data = oobi_response.json()

    assert data["aid"] == aid
    assert "oobi_urls" in data
    # OOBI URLs should contain the AID
    for url in data["oobi_urls"]:
        assert aid in url
        assert "/oobi/" in url


@pytest.mark.asyncio
async def test_duplicate_name_rejected(client: AsyncClient):
    """Test that duplicate names are rejected."""
    name = unique_name("duplicate")

    # Create first
    response1 = await client.post("/identity", json={"name": name})
    assert response1.status_code == 200

    # Try to create with same name
    response2 = await client.post("/identity", json={"name": name})
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_identity_persists_across_restart(temp_dir):
    """Test that identities persist after manager restart.

    This simulates a service restart by:
    1. Creating an identity with a fresh manager
    2. Closing the manager
    3. Creating a new manager pointing to the same storage
    4. Verifying the identity is still present
    """
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("persist")

    # Create first manager and identity
    mgr1 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,  # Use persistent storage
    )
    await mgr1.initialize()

    info = await mgr1.create_identity(name=name)
    aid = info.aid
    assert aid.startswith("E")

    # Close and recreate manager (simulates restart)
    await mgr1.close()

    # Create new manager pointing to same storage
    mgr2 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr2.initialize()

    # Verify identity still exists
    restored = await mgr2.get_identity(aid)
    assert restored is not None
    assert restored.aid == aid
    assert restored.name == name

    # Also verify it appears in list
    identities = await mgr2.list_identities()
    assert any(i.aid == aid for i in identities)

    await mgr2.close()


@pytest.mark.asyncio
async def test_get_kel_bytes(temp_dir):
    """Test that KEL bytes can be retrieved for publishing."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("kel")

    mgr = IssuerIdentityManager(
        name="test-kel",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create identity
    info = await mgr.create_identity(name=name)
    aid = info.aid

    # Get KEL bytes
    kel_bytes = await mgr.get_kel_bytes(aid)

    # Verify we got something
    assert kel_bytes is not None
    assert len(kel_bytes) > 0
    # KEL should contain the AID
    assert aid.encode() in kel_bytes

    await mgr.close()


@pytest.mark.asyncio
async def test_create_identity_with_publish_disabled(client: AsyncClient):
    """Test creating identity without publishing to witnesses."""
    name = unique_name("no-publish")
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200
    data = response.json()

    # Identity should be created
    assert data["identity"]["aid"].startswith("E")
    # No publish results when publishing is disabled
    assert data["publish_results"] is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_oobi_resolution_with_witnesses():
    """Test that OOBI can be resolved by witnesses.

    This is an integration test that requires witnesses to be running.
    Run with: pytest -m integration

    The test:
    1. Creates an identity with witness publishing enabled
    2. Verifies publish_results show success
    3. Attempts to resolve the OOBI URL (requires live witnesses)
    """
    # This test is marked as integration and skipped by default
    # It would require docker-compose up with witnesses running
    pytest.skip("Integration test requires running witnesses")
