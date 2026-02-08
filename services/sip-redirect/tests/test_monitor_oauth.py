"""Tests for monitor OAuth module.

Sprint 50: Tests for OAuthStateStore, PKCE helpers, and domain validation.
"""

import asyncio
from datetime import datetime, timezone

import pytest

from app.monitor.oauth import (
    OAuthState,
    OAuthStateStore,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    is_email_domain_allowed,
    build_authorization_url,
    reset_oauth_state_store,
)


# =============================================================================
# OAuthStateStore tests
# =============================================================================


class TestOAuthStateStore:
    """Test OAuthStateStore."""

    @pytest.fixture(autouse=True)
    def reset_store(self):
        """Reset global store before each test."""
        reset_oauth_state_store()

    def _make_state(self) -> OAuthState:
        """Create a test OAuthState."""
        return OAuthState(
            state=generate_state(),
            nonce=generate_nonce(),
            code_verifier="test-verifier",
            created_at=datetime.now(timezone.utc),
        )

    @pytest.mark.asyncio
    async def test_create_and_get(self):
        """Test creating and retrieving state."""
        store = OAuthStateStore(default_ttl=60)
        oauth_state = self._make_state()

        state_id = await store.create(oauth_state)
        assert state_id is not None
        assert len(state_id) > 20

        retrieved = await store.get(state_id)
        assert retrieved is not None
        assert retrieved.state == oauth_state.state
        assert retrieved.nonce == oauth_state.nonce

    @pytest.mark.asyncio
    async def test_get_and_delete(self):
        """Test one-time retrieval (get_and_delete)."""
        store = OAuthStateStore(default_ttl=60)
        oauth_state = self._make_state()

        state_id = await store.create(oauth_state)

        # First get_and_delete succeeds
        retrieved = await store.get_and_delete(state_id)
        assert retrieved is not None

        # Second get_and_delete returns None (already deleted)
        retrieved2 = await store.get_and_delete(state_id)
        assert retrieved2 is None

    @pytest.mark.asyncio
    async def test_expired_state(self):
        """Test that expired states are rejected."""
        store = OAuthStateStore(default_ttl=0)  # Expires immediately
        oauth_state = self._make_state()

        state_id = await store.create(oauth_state, ttl=0)

        # Wait a moment for expiry
        await asyncio.sleep(0.01)

        retrieved = await store.get(state_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete(self):
        """Test explicit deletion."""
        store = OAuthStateStore(default_ttl=60)
        oauth_state = self._make_state()

        state_id = await store.create(oauth_state)
        assert await store.delete(state_id) is True
        assert await store.delete(state_id) is False  # Already deleted

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        """Test cleanup of expired states."""
        store = OAuthStateStore(default_ttl=0)

        # Create several states that expire immediately
        for _ in range(5):
            await store.create(self._make_state(), ttl=0)

        await asyncio.sleep(0.01)
        removed = await store.cleanup_expired()
        assert removed == 5
        assert store.state_count == 0

    @pytest.mark.asyncio
    async def test_state_count(self):
        """Test state_count property."""
        store = OAuthStateStore(default_ttl=60)
        assert store.state_count == 0

        await store.create(self._make_state())
        await store.create(self._make_state())
        assert store.state_count == 2

    @pytest.mark.asyncio
    async def test_unknown_state_id(self):
        """Test getting a nonexistent state."""
        store = OAuthStateStore(default_ttl=60)
        assert await store.get("nonexistent-id") is None


# =============================================================================
# PKCE tests
# =============================================================================


class TestPKCE:
    """Test PKCE helper functions."""

    def test_generate_pkce_pair(self):
        """Test PKCE pair generation."""
        verifier, challenge = generate_pkce_pair()

        assert len(verifier) > 20
        assert len(challenge) > 20
        assert verifier != challenge

    def test_pkce_pair_uniqueness(self):
        """Test that each call generates unique pairs."""
        v1, c1 = generate_pkce_pair()
        v2, c2 = generate_pkce_pair()

        assert v1 != v2
        assert c1 != c2

    def test_pkce_challenge_is_s256(self):
        """Test that challenge is valid S256 (base64url, no padding)."""
        import base64
        import hashlib

        verifier, challenge = generate_pkce_pair()

        # Recompute challenge from verifier
        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        assert challenge == expected


# =============================================================================
# Domain validation tests
# =============================================================================


class TestDomainValidation:
    """Test email domain validation."""

    def test_empty_allowed_domains_allows_all(self):
        """Test that empty allowed list allows all domains."""
        assert is_email_domain_allowed("user@any.com", []) is True

    def test_matching_domain(self):
        """Test email from allowed domain."""
        assert is_email_domain_allowed("user@rcnx.io", ["rcnx.io"]) is True

    def test_rejected_domain(self):
        """Test email from disallowed domain."""
        assert is_email_domain_allowed("user@evil.com", ["rcnx.io"]) is False

    def test_case_insensitive(self):
        """Test case-insensitive domain matching."""
        assert is_email_domain_allowed("User@RCNX.IO", ["rcnx.io"]) is True

    def test_multiple_allowed_domains(self):
        """Test with multiple allowed domains."""
        allowed = ["rcnx.io", "example.com"]
        assert is_email_domain_allowed("user@rcnx.io", allowed) is True
        assert is_email_domain_allowed("user@example.com", allowed) is True
        assert is_email_domain_allowed("user@other.com", allowed) is False


# =============================================================================
# Authorization URL tests
# =============================================================================


class TestBuildAuthorizationUrl:
    """Test authorization URL building."""

    def test_build_url_contains_required_params(self):
        """Test that authorization URL contains all required parameters."""
        url = build_authorization_url(
            tenant_id="test-tenant",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            state="test-state",
            nonce="test-nonce",
            code_challenge="test-challenge",
        )

        assert "login.microsoftonline.com/test-tenant" in url
        assert "client_id=test-client" in url
        assert "response_type=code" in url
        assert "state=test-state" in url
        assert "nonce=test-nonce" in url
        assert "code_challenge=test-challenge" in url
        assert "code_challenge_method=S256" in url

    def test_state_and_nonce_are_random(self):
        """Test that generate_state and generate_nonce produce unique values."""
        s1, s2 = generate_state(), generate_state()
        n1, n2 = generate_nonce(), generate_nonce()
        assert s1 != s2
        assert n1 != n2
