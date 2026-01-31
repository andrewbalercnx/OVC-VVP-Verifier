"""Tests for schema endpoints."""
import pytest
from httpx import AsyncClient


# Known schema SAIDs from the embedded schema files
KNOWN_EMBEDDED_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"  # Legal Entity vLEI

# Known schema SAIDs from governance registry
KNOWN_LE_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
KNOWN_DE_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"


@pytest.mark.asyncio
async def test_list_schemas(client: AsyncClient):
    """Test listing all available schemas."""
    response = await client.get("/schema")
    assert response.status_code == 200
    data = response.json()

    assert "schemas" in data
    assert "count" in data
    assert data["count"] >= 1

    # Each schema should have at least said and title
    for schema in data["schemas"]:
        assert "said" in schema
        assert "title" in schema


@pytest.mark.asyncio
async def test_get_schema_by_said(client: AsyncClient):
    """Test getting a specific schema by SAID."""
    response = await client.get(f"/schema/{KNOWN_EMBEDDED_SAID}")
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_EMBEDDED_SAID
    assert "title" in data
    assert data["title"] == "Legal Entity vLEI Credential"
    # Full schema document should be included
    assert "schema_document" in data
    assert data["schema_document"] is not None
    assert data["schema_document"]["$id"] == KNOWN_EMBEDDED_SAID


@pytest.mark.asyncio
async def test_schema_not_found(client: AsyncClient):
    """Test 404 for unknown schema SAID."""
    response = await client.get("/schema/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_validate_schema_known_le(client: AsyncClient):
    """Test validating a known LE schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_LE_SAID,
            "credential_type": "LE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_LE_SAID
    assert data["valid"] is True
    assert data["credential_type"] == "LE"


@pytest.mark.asyncio
async def test_validate_schema_known_de(client: AsyncClient):
    """Test validating a known DE schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_DE_SAID,
            "credential_type": "DE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_DE_SAID
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_validate_schema_unknown(client: AsyncClient):
    """Test validating an unknown schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": "Eunknown123456789012345678901234567890123",
            "credential_type": "LE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    # Unknown SAID for LE type should return invalid
    assert data["valid"] is False


@pytest.mark.asyncio
async def test_validate_schema_no_credential_type(client: AsyncClient):
    """Test validating a schema SAID without credential type."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_LE_SAID,
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_LE_SAID
    assert data["valid"] is True
    assert data["credential_type"] is None


@pytest.mark.asyncio
async def test_validate_schema_pending_governance(client: AsyncClient):
    """Test validating schema for type with pending governance.

    APE and TNAlloc have no known schemas, so any SAID should be valid.
    """
    response = await client.post(
        "/schema/validate",
        json={
            "said": "EanySchemaForPendingType123456789012345678",
            "credential_type": "APE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    # APE has no known schemas, so any is valid
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_list_schemas_contains_known(client: AsyncClient):
    """Test that list includes our known embedded schemas."""
    response = await client.get("/schema")
    assert response.status_code == 200
    data = response.json()

    saids = [s["said"] for s in data["schemas"]]
    assert KNOWN_EMBEDDED_SAID in saids


@pytest.mark.asyncio
async def test_schema_has_description(client: AsyncClient):
    """Test that schema response includes description."""
    response = await client.get(f"/schema/{KNOWN_EMBEDDED_SAID}")
    assert response.status_code == 200
    data = response.json()

    assert "description" in data
    # Legal Entity vLEI Credential has a description
    assert data["description"] is not None
    assert len(data["description"]) > 0
