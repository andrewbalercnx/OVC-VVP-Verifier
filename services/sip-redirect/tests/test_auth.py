"""Tests for auth module.

Sprint 42: Tests for API key cache and rate limiter.
"""

import pytest
import time
from unittest.mock import patch

from app.auth.api_key import APIKeyCache, extract_api_key
from app.auth.rate_limiter import RateLimiter
from app.sip.models import SIPRequest


class TestAPIKeyCache:
    """Test API key caching."""

    def test_set_and_get(self):
        """Test setting and getting cached keys."""
        cache = APIKeyCache(ttl_seconds=60)

        cache.set("key1", valid=True, org_id="org-123")
        result = cache.get("key1")

        assert result is not None
        assert result.valid is True
        assert result.org_id == "org-123"

    def test_cache_miss(self):
        """Test cache miss for unknown key."""
        cache = APIKeyCache(ttl_seconds=60)

        result = cache.get("unknown-key")
        assert result is None

    def test_expiration(self):
        """Test cache expiration."""
        cache = APIKeyCache(ttl_seconds=1)

        cache.set("key1", valid=True)
        time.sleep(1.1)

        result = cache.get("key1")
        assert result is None

    def test_invalidate(self):
        """Test invalidating a cached key."""
        cache = APIKeyCache(ttl_seconds=60)

        cache.set("key1", valid=True)
        cache.invalidate("key1")

        result = cache.get("key1")
        assert result is None

    def test_clear(self):
        """Test clearing all cached entries."""
        cache = APIKeyCache(ttl_seconds=60)

        cache.set("key1", valid=True)
        cache.set("key2", valid=False)
        cache.clear()

        assert cache.size == 0

    def test_invalid_key_cached(self):
        """Test caching invalid key status."""
        cache = APIKeyCache(ttl_seconds=60)

        cache.set("bad-key", valid=False)
        result = cache.get("bad-key")

        assert result is not None
        assert result.valid is False


class TestExtractAPIKey:
    """Test API key extraction from SIP request."""

    def test_extract_api_key(self):
        """Test extracting API key from request."""
        request = SIPRequest(
            method="INVITE",
            request_uri="sip:test@example.com",
            via=["SIP/2.0/UDP test:5060"],
            from_header="test",
            to_header="test",
            call_id="test",
            cseq="1 INVITE",
            vvp_api_key="my-api-key-12345",
        )

        key = extract_api_key(request)
        assert key == "my-api-key-12345"

    def test_extract_missing_api_key(self):
        """Test extracting when no API key present."""
        request = SIPRequest(
            method="INVITE",
            request_uri="sip:test@example.com",
            via=["SIP/2.0/UDP test:5060"],
            from_header="test",
            to_header="test",
            call_id="test",
            cseq="1 INVITE",
            vvp_api_key=None,
        )

        key = extract_api_key(request)
        assert key is None


class TestRateLimiter:
    """Test rate limiting."""

    def test_allows_burst(self):
        """Test allows burst of requests."""
        limiter = RateLimiter(requests_per_second=1.0, burst_size=5)

        # Should allow 5 requests immediately
        for i in range(5):
            assert limiter.check("key1") is True

    def test_rate_limits_after_burst(self):
        """Test rate limits after burst exhausted."""
        limiter = RateLimiter(requests_per_second=1.0, burst_size=2)

        # Use up burst
        assert limiter.check("key1") is True
        assert limiter.check("key1") is True
        # Should be rate limited now
        assert limiter.check("key1") is False

    def test_refills_over_time(self):
        """Test tokens refill over time."""
        limiter = RateLimiter(requests_per_second=10.0, burst_size=1)

        # Use token
        assert limiter.check("key1") is True
        # Should be rate limited
        assert limiter.check("key1") is False
        # Wait for refill
        time.sleep(0.15)
        # Should be allowed again
        assert limiter.check("key1") is True

    def test_per_key_isolation(self):
        """Test rate limits are per-key."""
        limiter = RateLimiter(requests_per_second=1.0, burst_size=1)

        assert limiter.check("key1") is True
        assert limiter.check("key1") is False  # rate limited
        assert limiter.check("key2") is True  # different key, not limited

    def test_reset_key(self):
        """Test resetting rate limit for a key."""
        limiter = RateLimiter(requests_per_second=1.0, burst_size=1)

        assert limiter.check("key1") is True
        assert limiter.check("key1") is False
        limiter.reset("key1")
        assert limiter.check("key1") is True

    def test_get_retry_after(self):
        """Test getting retry time."""
        limiter = RateLimiter(requests_per_second=10.0, burst_size=1)

        # Use up token
        assert limiter.check("key1") is True
        assert limiter.check("key1") is False

        retry = limiter.get_retry_after("key1")
        assert retry > 0
        assert retry <= 0.1  # Should refill in ~0.1s
