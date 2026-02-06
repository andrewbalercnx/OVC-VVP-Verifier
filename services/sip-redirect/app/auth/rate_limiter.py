"""Token bucket rate limiter.

Sprint 42: Per-API-key rate limiting to prevent abuse.
"""

import logging
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting.

    Allows bursting up to max_tokens, then refills at rate tokens/second.
    """

    tokens: float
    last_update: float
    max_tokens: float
    refill_rate: float  # tokens per second

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume (default: 1)

        Returns:
            True if tokens were available, False if rate limited
        """
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Refill tokens based on elapsed time
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def get_retry_after(self) -> float:
        """Calculate seconds until next token available.

        Returns:
            Seconds to wait before retrying
        """
        if self.tokens >= 1:
            return 0.0

        # Time needed to refill 1 token
        tokens_needed = 1 - self.tokens
        return tokens_needed / self.refill_rate


class RateLimiter:
    """Per-API-key rate limiter using token bucket algorithm.

    Provides fair rate limiting per API key with configurable
    burst size and requests per second.
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: int = 50,
    ):
        """Initialize rate limiter.

        Args:
            requests_per_second: Sustained request rate per key
            burst_size: Maximum burst size (initial tokens)
        """
        self._buckets: dict[str, TokenBucket] = {}
        self._rps = requests_per_second
        self._burst = float(burst_size)
        self._max_keys = 50000  # Prevent unbounded growth

    def check(self, api_key: str) -> bool:
        """Check if request is allowed for API key.

        Creates a new bucket if this is the first request for the key.

        Args:
            api_key: API key to check

        Returns:
            True if request allowed, False if rate limited
        """
        bucket = self._buckets.get(api_key)

        if bucket is None:
            # Evict old entries if at capacity
            if len(self._buckets) >= self._max_keys:
                self._evict_stale()

            # Create new bucket with full burst allowance
            bucket = TokenBucket(
                tokens=self._burst,
                last_update=time.time(),
                max_tokens=self._burst,
                refill_rate=self._rps,
            )
            self._buckets[api_key] = bucket

        allowed = bucket.consume()
        if not allowed:
            log.debug(f"Rate limited: {api_key[:8]}...")
        return allowed

    def get_retry_after(self, api_key: str) -> float:
        """Get seconds until next request allowed.

        Args:
            api_key: API key to check

        Returns:
            Seconds to wait, 0 if not rate limited
        """
        bucket = self._buckets.get(api_key)
        if bucket is None:
            return 0.0
        return bucket.get_retry_after()

    def reset(self, api_key: str) -> None:
        """Reset rate limit for API key.

        Args:
            api_key: API key to reset
        """
        self._buckets.pop(api_key, None)

    def clear(self) -> None:
        """Clear all rate limit state."""
        self._buckets.clear()

    def _evict_stale(self) -> int:
        """Evict stale entries (not used in last 5 minutes).

        Returns:
            Number of entries evicted
        """
        cutoff = time.time() - 300  # 5 minutes
        stale = [k for k, v in self._buckets.items() if v.last_update < cutoff]
        for k in stale:
            del self._buckets[k]

        if not stale and len(self._buckets) >= self._max_keys:
            # Still full, evict 10% of oldest entries
            sorted_keys = sorted(self._buckets.keys(), key=lambda k: self._buckets[k].last_update)
            to_evict = sorted_keys[: self._max_keys // 10]
            for k in to_evict:
                del self._buckets[k]
            return len(to_evict)

        return len(stale)

    @property
    def active_keys(self) -> int:
        """Number of tracked API keys."""
        return len(self._buckets)
