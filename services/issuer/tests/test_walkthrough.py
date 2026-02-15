"""Tests for the interactive walkthrough page (Sprint 66)."""
import importlib
import os

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_walkthrough_returns_200(client: AsyncClient):
    """GET /ui/walkthrough returns 200 with HTML content."""
    response = await client.get("/ui/walkthrough")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


@pytest.mark.asyncio
async def test_walkthrough_contains_structural_elements(client: AsyncClient):
    """Response contains the expected walkthrough DOM structure."""
    response = await client.get("/ui/walkthrough")
    body = response.text

    # Split pane layout
    assert 'id="splitPane"' in body
    assert 'id="tutorialContent"' in body
    assert 'id="previewFrame"' in body

    # Navigation buttons
    assert 'id="btnPrev"' in body
    assert 'id="btnNext"' in body

    # Progress indicator
    assert 'id="progressFill"' in body
    assert 'id="stepIndicator"' in body

    # Pane divider for resizing
    assert 'id="paneDivider"' in body


@pytest.mark.asyncio
async def test_walkthrough_contains_step_definitions(client: AsyncClient):
    """Response contains the WALKTHROUGH_STEPS JS array with expected steps."""
    response = await client.get("/ui/walkthrough")
    body = response.text

    assert "WALKTHROUGH_STEPS" in body

    # Verify expected step UI paths are present
    expected_paths = [
        "/ui/",
        "/organizations/ui",
        "/ui/identity",
        "/ui/schemas",
        "/ui/credentials",
        "/ui/dossier",
        "/ui/vvp",
        "/ui/dashboard",
        "/ui/vetter",
        "/ui/help",
    ]
    for path in expected_paths:
        assert f'uiPath: "{path}"' in body, f"Missing step with uiPath: {path}"


@pytest.mark.asyncio
async def test_walkthrough_iframe_element(client: AsyncClient):
    """Iframe element exists with correct initial src."""
    response = await client.get("/ui/walkthrough")
    body = response.text

    # Iframe should exist and initially point to /ui/
    assert "<iframe" in body
    assert 'src="/ui/"' in body
    assert 'title="VVP Issuer UI Preview"' in body


@pytest.mark.asyncio
async def test_walkthrough_accessible_without_auth(client: AsyncClient):
    """Walkthrough accessible when auth is disabled (default test config)."""
    # The `client` fixture sets VVP_AUTH_ENABLED=false
    response = await client.get("/ui/walkthrough")
    assert response.status_code == 200


def test_walkthrough_exempt_when_ui_auth_disabled():
    """When UI auth is disabled, /ui/walkthrough is in the auth-exempt set."""
    original_ui_auth = os.environ.get("VVP_UI_AUTH_ENABLED")
    os.environ["VVP_UI_AUTH_ENABLED"] = "false"
    try:
        import app.config as config_module
        importlib.reload(config_module)
        exempt = config_module.get_auth_exempt_paths()
        assert "/ui/walkthrough" in exempt
    finally:
        if original_ui_auth is not None:
            os.environ["VVP_UI_AUTH_ENABLED"] = original_ui_auth
        else:
            os.environ.pop("VVP_UI_AUTH_ENABLED", None)
        importlib.reload(config_module)


def test_walkthrough_not_exempt_when_ui_auth_enabled():
    """When UI auth is enabled, /ui/walkthrough is NOT in the auth-exempt set.

    This means unauthenticated requests to /ui/walkthrough will receive 401
    from the AuthenticationMiddleware (tested separately in auth integration tests).
    """
    original_ui_auth = os.environ.get("VVP_UI_AUTH_ENABLED")
    os.environ["VVP_UI_AUTH_ENABLED"] = "true"
    try:
        import app.config as config_module
        importlib.reload(config_module)

        assert config_module.UI_AUTH_ENABLED is True
        exempt = config_module.get_auth_exempt_paths()
        assert "/ui/walkthrough" not in exempt
    finally:
        if original_ui_auth is not None:
            os.environ["VVP_UI_AUTH_ENABLED"] = original_ui_auth
        else:
            os.environ.pop("VVP_UI_AUTH_ENABLED", None)
        importlib.reload(config_module)
