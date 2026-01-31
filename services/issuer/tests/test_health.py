"""Tests for health check endpoint."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_healthz_returns_ok(client: AsyncClient):
    """Test health endpoint returns ok status."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["service"] == "vvp-issuer"
    assert "identities_loaded" in data


@pytest.mark.asyncio
async def test_version_endpoint(client: AsyncClient):
    """Test version endpoint returns git_sha."""
    response = await client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert "git_sha" in data
