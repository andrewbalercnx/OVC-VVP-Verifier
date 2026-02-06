"""API key extraction and caching.

Sprint 42: Caches validated API keys to reduce issuer API calls.
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

from app.sip.models import SIPRequest

log = logging.getLogger(__name__)


@dataclass
class CachedKey:
    """Cached API key validation result."""

    valid: bool
    org_id: Optional[str]
    expires_at: float


class APIKeyCache:
    """Cache for validated API keys.

    Reduces load on the issuer API by caching validation results.
    Uses a simple time-based expiration.
    """

    def __init__(self, ttl_seconds: int = 60):
        """Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for cached entries (default: 60s)
        """
        self._cache: dict[str, CachedKey] = {}
        self._ttl = ttl_seconds
        self._max_entries = 10000  # Prevent unbounded growth

    def get(self, key: str) -> Optional[CachedKey]:
        """Get cached validation result for key.

        Args:
            key: API key to lookup

        Returns:
            CachedKey if valid and not expired, None otherwise
        """
        entry = self._cache.get(key)
        if entry is None:
            return None

        if time.time() > entry.expires_at:
            del self._cache[key]
            return None

        return entry

    def set(self, key: str, valid: bool, org_id: Optional[str] = None) -> None:
        """Cache a validation result.

        Args:
            key: API key
            valid: Whether the key is valid
            org_id: Organization ID (if valid)
        """
        # Evict oldest entries if cache is full
        if len(self._cache) >= self._max_entries:
            self._evict_expired()
            if len(self._cache) >= self._max_entries:
                # Still full, evict 10% of entries
                to_evict = list(self._cache.keys())[: self._max_entries // 10]
                for k in to_evict:
                    del self._cache[k]

        self._cache[key] = CachedKey(
            valid=valid,
            org_id=org_id,
            expires_at=time.time() + self._ttl,
        )

    def invalidate(self, key: str) -> None:
        """Remove a key from cache.

        Args:
            key: API key to invalidate
        """
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    def _evict_expired(self) -> int:
        """Remove expired entries.

        Returns:
            Number of entries evicted
        """
        now = time.time()
        expired = [k for k, v in self._cache.items() if v.expires_at < now]
        for k in expired:
            del self._cache[k]
        return len(expired)

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)


def extract_api_key(request: SIPRequest) -> Optional[str]:
    """Extract API key from SIP request.

    Looks for X-VVP-API-Key header.

    Args:
        request: Parsed SIP request

    Returns:
        API key string or None if not present
    """
    return request.vvp_api_key
