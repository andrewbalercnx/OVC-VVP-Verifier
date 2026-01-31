"""Pytest fixtures for VVP Issuer tests."""
import asyncio
import importlib
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator

import pytest
from httpx import AsyncClient, ASGITransport

from app.keri.identity import (
    reset_identity_manager,
    close_identity_manager,
    IssuerIdentityManager,
)
from app.keri.persistence import reset_persistence_manager, PersistenceManager
from app.keri.registry import (
    reset_registry_manager,
    close_registry_manager,
    CredentialRegistryManager,
)
from app.keri.witness import reset_witness_publisher


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def temp_persistence(temp_dir: Path) -> PersistenceManager:
    """Create persistence manager with temporary directory."""
    reset_persistence_manager()
    manager = PersistenceManager(base_dir=temp_dir)
    manager.initialize()
    yield manager
    reset_persistence_manager()


@pytest.fixture
async def temp_identity_manager(temp_dir: Path) -> AsyncGenerator[IssuerIdentityManager, None]:
    """Create identity manager with temporary storage."""
    reset_identity_manager()
    manager = IssuerIdentityManager(
        name="test-issuer",
        base_dir=temp_dir,
        temp=True,  # Use temp mode for faster cleanup
    )
    await manager.initialize()
    yield manager
    await manager.close()
    reset_identity_manager()


@pytest.fixture
async def identity_with_registry(
    client: AsyncClient,
) -> AsyncGenerator[dict, None]:
    """Create an identity for registry tests.

    Uses the client fixture to ensure proper singleton initialization,
    then creates an identity that can be used for registry creation.
    """
    # Create a test identity via API
    response = await client.post(
        "/identity",
        json={"name": "test-issuer-for-registry", "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    identity_data = response.json()
    yield identity_data["identity"]


@pytest.fixture
async def client(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client for API testing with isolated temp storage.

    Sets VVP_ISSUER_DATA_DIR to a temp directory so tests don't pollute
    the user's home directory or leak state between test runs.
    """
    # Set environment variable BEFORE importing the app
    # so config.py picks up the temp directory
    original_env = os.environ.get("VVP_ISSUER_DATA_DIR")
    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)

    # Reset singletons to pick up new config
    reset_identity_manager()
    reset_registry_manager()
    reset_persistence_manager()
    reset_witness_publisher()

    # Import and reload config module to pick up the new env var
    import app.config as config_module
    importlib.reload(config_module)

    from app.main import app as fastapi_app

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    # Close managers to release LMDB locks
    await close_registry_manager()
    await close_identity_manager()

    # Cleanup after test
    reset_identity_manager()
    reset_registry_manager()
    reset_persistence_manager()
    reset_witness_publisher()

    # Restore original environment
    if original_env is not None:
        os.environ["VVP_ISSUER_DATA_DIR"] = original_env
    elif "VVP_ISSUER_DATA_DIR" in os.environ:
        del os.environ["VVP_ISSUER_DATA_DIR"]

    # Reload config to restore original values for other tests
    importlib.reload(config_module)
