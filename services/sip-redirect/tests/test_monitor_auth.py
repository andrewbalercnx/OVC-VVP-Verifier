"""Tests for monitor auth module - API key store and session enrichment.

Sprint 50: Tests for MonitorAPIKeyStore, API key login, and session auth_method.
"""

import json
import time

import pytest

from app.monitor.auth import (
    APIKeyConfig,
    LoginRateLimiter,
    MonitorAPIKeyStore,
    Session,
    SessionStore,
    UserStore,
)

try:
    import bcrypt
except ImportError:
    bcrypt = None


# =============================================================================
# MonitorAPIKeyStore tests
# =============================================================================


def _hash_key(raw_key: str) -> str:
    """Helper to create bcrypt hash for test keys."""
    return bcrypt.hashpw(raw_key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@pytest.mark.skipif(bcrypt is None, reason="bcrypt not installed")
class TestMonitorAPIKeyStore:
    """Test MonitorAPIKeyStore."""

    def test_load_keys(self, tmp_path):
        """Test loading keys from JSON file."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-1", "name": "Operations", "hash": _hash_key("secret1"), "revoked": False},
                {"id": "key-2", "name": "CI Pipeline", "hash": _hash_key("secret2"), "revoked": False},
            ]
        }))

        store = MonitorAPIKeyStore(keys_file)
        assert store.key_count == 2

    def test_verify_valid_key(self, tmp_path):
        """Test verifying a valid API key."""
        raw_key = "my-test-key-12345"
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-1", "name": "Test Key", "hash": _hash_key(raw_key)},
            ]
        }))

        store = MonitorAPIKeyStore(keys_file)
        result = store.verify(raw_key)

        assert result is not None
        assert result == ("key-1", "Test Key")

    def test_verify_invalid_key(self, tmp_path):
        """Test verifying an invalid API key."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-1", "name": "Test Key", "hash": _hash_key("correct-key")},
            ]
        }))

        store = MonitorAPIKeyStore(keys_file)
        result = store.verify("wrong-key")

        assert result is None

    def test_verify_revoked_key(self, tmp_path):
        """Test that revoked keys are rejected."""
        raw_key = "revoked-key-12345"
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-1", "name": "Revoked", "hash": _hash_key(raw_key), "revoked": True},
            ]
        }))

        store = MonitorAPIKeyStore(keys_file)
        result = store.verify(raw_key)

        assert result is None

    def test_missing_file(self, tmp_path):
        """Test graceful handling of missing keys file."""
        store = MonitorAPIKeyStore(tmp_path / "nonexistent.json")
        assert store.key_count == 0
        assert store.verify("any-key") is None

    def test_reload_on_mtime_change(self, tmp_path):
        """Test reloading when file changes on disk."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({"keys": []}))

        store = MonitorAPIKeyStore(keys_file)
        assert store.key_count == 0

        # Override reload interval for testing
        store.RELOAD_INTERVAL = 0

        # Write new key
        new_key = "new-key-12345"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-new", "name": "New Key", "hash": _hash_key(new_key)},
            ]
        }))

        # Force mtime check
        result = store.verify(new_key)
        assert result == ("key-new", "New Key")

    def test_key_count_excludes_revoked(self, tmp_path):
        """Test key_count only counts active keys."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"id": "key-1", "name": "Active", "hash": _hash_key("k1")},
                {"id": "key-2", "name": "Revoked", "hash": _hash_key("k2"), "revoked": True},
                {"id": "key-3", "name": "Active2", "hash": _hash_key("k3")},
            ]
        }))

        store = MonitorAPIKeyStore(keys_file)
        assert store.key_count == 2


# =============================================================================
# Session auth_method tests
# =============================================================================


class TestSessionAuthMethod:
    """Test session auth_method field."""

    @pytest.mark.asyncio
    async def test_session_default_auth_method(self):
        """Test session defaults to password auth method."""
        store = SessionStore()
        session = await store.create("admin")
        assert session.auth_method == "password"

    @pytest.mark.asyncio
    async def test_session_api_key_auth_method(self):
        """Test session with api_key auth method."""
        store = SessionStore()
        session = await store.create("ops-key", auth_method="api_key")
        assert session.auth_method == "api_key"

    @pytest.mark.asyncio
    async def test_session_oauth_auth_method(self):
        """Test session with oauth auth method."""
        store = SessionStore()
        session = await store.create("user@rcnx.io", auth_method="oauth")
        assert session.auth_method == "oauth"

    @pytest.mark.asyncio
    async def test_session_auth_method_preserved_on_get(self):
        """Test auth_method preserved through create/get cycle."""
        store = SessionStore()
        session = await store.create("user@rcnx.io", auth_method="oauth")

        retrieved = await store.get(session.session_id)
        assert retrieved is not None
        assert retrieved.auth_method == "oauth"
        assert retrieved.username == "user@rcnx.io"
