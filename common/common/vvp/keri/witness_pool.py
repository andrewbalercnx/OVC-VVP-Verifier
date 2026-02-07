"""
Unified witness pool for AID resolution.

Aggregates witnesses from multiple sources:
1. Configured witnesses (Provenant staging) - loaded at init
2. GLEIF witnesses - lazy discovery from well-known OOBI
3. Per-request witnesses - from PASSporT kid OOBI URLs
4. KEL-extracted witnesses - from 'b' field in establishment events

Thread-safe via asyncio.Lock for GLEIF discovery.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

ALLOWED_SCHEMES = {"http", "https"}

# Default timeout for witness queries
DEFAULT_QUERY_TIMEOUT = 5.0

# Default timeout for GLEIF discovery
DEFAULT_DISCOVERY_TIMEOUT = 10.0


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class WitnessEndpoint:
    """A witness endpoint in the pool.

    Attributes:
        url: Normalized base URL (scheme://host:port)
        source: Where this witness came from ("config", "gleif", "oobi", "kel")
        aid: Witness AID if known (for KEL-extracted witnesses)
        added_at: When this witness was added to the pool
    """

    url: str
    source: str
    aid: Optional[str] = None
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# URL Validation
# =============================================================================


def validate_witness_url(url: str) -> Optional[str]:
    """Validate and normalize witness URL.

    Performs security checks and normalizes to base URL format.

    Args:
        url: Raw witness URL (may include path, query, etc.)

    Returns:
        Normalized URL (scheme://host:port) or None if invalid.
    """
    if not url:
        return None

    try:
        parsed = urlparse(url)

        # Scheme allowlist (http/https only - no file://, ftp://, etc.)
        if parsed.scheme not in ALLOWED_SCHEMES:
            log.warning(f"Rejected witness URL with invalid scheme: {parsed.scheme}")
            return None

        # Must have valid netloc (host:port)
        if not parsed.netloc:
            log.warning(f"Rejected witness URL with no host: {url[:50]}")
            return None

        # Normalize to base URL (strip path, query, fragment)
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        return normalized

    except Exception as e:
        log.warning(f"Failed to parse witness URL: {e}")
        return None


def extract_witness_base_url(oobi_url: str) -> Optional[str]:
    """Extract and validate witness base URL from an OOBI URL.

    OOBI URLs follow the pattern:
        http://witness5.stage.provenant.net:5631/oobi/{AID}/witness

    Returns validated: http://witness5.stage.provenant.net:5631

    Args:
        oobi_url: Full OOBI URL from PASSporT kid field.

    Returns:
        Validated and normalized base URL, or None if invalid.
    """
    return validate_witness_url(oobi_url)


# =============================================================================
# WitnessPool Class
# =============================================================================


class WitnessPool:
    """Singleton witness pool with lazy GLEIF discovery.

    Thread-safe via asyncio.Lock for discovery operations.
    Witnesses stored in dict keyed by normalized URL for deduplication.

    Usage:
        pool = get_witness_pool()
        pool.add_from_oobi_url(kid)  # Add per-request witness
        witnesses = await pool.get_all_witnesses()  # Triggers lazy discovery
    """

    def __init__(
        self,
        config_witnesses: Optional[List[str]] = None,
        gleif_oobi_url: Optional[str] = None,
        gleif_discovery_enabled: bool = True,
        cache_ttl_seconds: int = 300,
    ):
        """Initialize witness pool.

        Args:
            config_witnesses: List of pre-configured witness URLs.
            gleif_oobi_url: GLEIF well-known OOBI URL for discovery.
            gleif_discovery_enabled: Whether to attempt GLEIF discovery.
            cache_ttl_seconds: TTL for discovered GLEIF witnesses.
        """
        self._witnesses: Dict[str, WitnessEndpoint] = {}
        self._gleif_discovered: bool = False
        self._gleif_discovery_time: Optional[datetime] = None
        self._gleif_discovery_error: Optional[str] = None
        self._discovery_lock: asyncio.Lock = asyncio.Lock()

        # Configuration
        self._gleif_oobi_url = gleif_oobi_url
        self._gleif_discovery_enabled = gleif_discovery_enabled
        self._cache_ttl_seconds = cache_ttl_seconds

        # Load configured witnesses immediately
        if config_witnesses:
            for url in config_witnesses:
                self._add_witness(url, source="config")

        log.info(
            f"WitnessPool initialized with {len(self._witnesses)} configured witnesses"
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def add_from_oobi_url(self, oobi_url: str) -> bool:
        """Extract and add witness from OOBI URL.

        Called per-request to add witnesses from PASSporT kid field.

        Args:
            oobi_url: Full OOBI URL (e.g., http://witness/oobi/{AID}/witness)

        Returns:
            True if witness was added (new), False if invalid or duplicate.
        """
        return self._add_witness(oobi_url, source="oobi")

    def add_from_kel(self, witness_aids: List[str], base_url: Optional[str] = None) -> int:
        """Add witnesses discovered from KEL events.

        KEL events contain witness AIDs in the 'b' field. If we have a base_url
        (from the OOBI that gave us the KEL), we can construct witness URLs.

        Args:
            witness_aids: List of witness AIDs from KEL 'b' field.
            base_url: Optional base URL to construct witness endpoints.

        Returns:
            Number of witnesses added.
        """
        added = 0
        for aid in witness_aids:
            # If we have a base URL, use it; otherwise just record the AID
            if base_url:
                # Construct witness OOBI URL
                url = f"{base_url}/oobi/{aid}"
                if self._add_witness(url, source="kel", aid=aid):
                    added += 1
            else:
                # Can't construct URL without base, but log for debugging
                log.debug(f"KEL witness AID without base URL: {aid[:16]}...")
        return added

    async def get_all_witnesses(self) -> List[WitnessEndpoint]:
        """Get all witnesses, triggering GLEIF discovery if needed.

        This is the main entry point for getting witnesses. It ensures
        GLEIF discovery has been attempted (if enabled) before returning.

        Returns:
            List of all known witness endpoints.
        """
        if self._gleif_discovery_enabled:
            await self._ensure_gleif_discovered()
        return list(self._witnesses.values())

    def get_witness_urls(self) -> List[str]:
        """Get all witness URLs (synchronous, no discovery).

        Use this when you need URLs without triggering async discovery.

        Returns:
            List of normalized witness URLs.
        """
        return list(self._witnesses.keys())

    async def query_aid(
        self,
        aid: str,
        timeout: float = DEFAULT_QUERY_TIMEOUT,
    ) -> List[bytes]:
        """Query all witnesses for an AID in parallel.

        Queries all known witnesses and returns all successful responses.
        Individual failures are logged but don't fail the overall operation.

        Args:
            aid: The AID to query for.
            timeout: Timeout per witness query.

        Returns:
            List of successful KEL response bytes from witnesses.
        """
        witnesses = await self.get_all_witnesses()
        if not witnesses:
            log.warning("No witnesses available for AID query")
            return []

        async def query_single(witness: WitnessEndpoint) -> Optional[bytes]:
            """Query a single witness, return None on failure."""
            url = f"{witness.url}/oobi/{aid}/witness"
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(url)
                    if response.status_code == 200:
                        log.debug(f"Witness {witness.url} returned KEL for {aid[:16]}...")
                        return response.content
                    else:
                        log.debug(
                            f"Witness {witness.url} returned {response.status_code} for {aid[:16]}..."
                        )
                        return None
            except Exception as e:
                log.debug(f"Witness {witness.url} query failed: {e}")
                return None

        # Query all witnesses in parallel
        tasks = [query_single(w) for w in witnesses]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter successful responses
        successful = []
        for result in results:
            if isinstance(result, bytes) and result:
                successful.append(result)
            elif isinstance(result, Exception):
                log.debug(f"Witness query exception: {result}")

        log.info(
            f"AID query for {aid[:16]}...: {len(successful)}/{len(witnesses)} witnesses responded"
        )
        return successful

    # -------------------------------------------------------------------------
    # Status/Metrics
    # -------------------------------------------------------------------------

    @property
    def configured_count(self) -> int:
        """Count of witnesses from configuration."""
        return sum(1 for w in self._witnesses.values() if w.source == "config")

    @property
    def discovered_count(self) -> int:
        """Count of witnesses from GLEIF discovery."""
        return sum(1 for w in self._witnesses.values() if w.source == "gleif")

    @property
    def oobi_count(self) -> int:
        """Count of witnesses from OOBI URLs."""
        return sum(1 for w in self._witnesses.values() if w.source == "oobi")

    @property
    def kel_count(self) -> int:
        """Count of witnesses from KEL events."""
        return sum(1 for w in self._witnesses.values() if w.source == "kel")

    @property
    def total_count(self) -> int:
        """Total count of witnesses."""
        return len(self._witnesses)

    @property
    def gleif_status(self) -> dict:
        """GLEIF discovery status for diagnostics."""
        return {
            "enabled": self._gleif_discovery_enabled,
            "discovered": self._gleif_discovered,
            "discovery_time": (
                self._gleif_discovery_time.isoformat()
                if self._gleif_discovery_time
                else None
            ),
            "error": self._gleif_discovery_error,
            "cache_expired": self._is_cache_expired(),
        }

    def get_status(self) -> dict:
        """Get full pool status for /admin endpoint."""
        return {
            "configured_witnesses": self.configured_count,
            "discovered_witnesses": self.discovered_count,
            "oobi_witnesses": self.oobi_count,
            "kel_witnesses": self.kel_count,
            "total_witnesses": self.total_count,
            "gleif_discovery": self.gleif_status,
            "witness_urls": list(self._witnesses.keys()),
        }

    # -------------------------------------------------------------------------
    # Internal Methods
    # -------------------------------------------------------------------------

    def _add_witness(
        self, url: str, source: str, aid: Optional[str] = None
    ) -> bool:
        """Add witness after validation.

        Args:
            url: Raw witness URL.
            source: Source identifier ("config", "gleif", "oobi", "kel").
            aid: Optional witness AID.

        Returns:
            True if added (new witness), False if invalid or duplicate.
        """
        normalized = validate_witness_url(url)
        if not normalized:
            return False

        if normalized not in self._witnesses:
            self._witnesses[normalized] = WitnessEndpoint(
                url=normalized,
                source=source,
                aid=aid,
            )
            log.debug(f"Added witness: {normalized} (source={source})")
            return True

        return False

    def _is_cache_expired(self) -> bool:
        """Check if GLEIF discovery cache has expired."""
        if not self._gleif_discovery_time:
            return True

        age = (datetime.now(timezone.utc) - self._gleif_discovery_time).total_seconds()
        return age > self._cache_ttl_seconds

    async def _ensure_gleif_discovered(self) -> None:
        """Lazy GLEIF discovery with lock to prevent concurrent fetches.

        Uses double-check locking pattern to minimize lock contention.
        """
        # Fast path: already discovered and cache valid
        if self._gleif_discovered and not self._is_cache_expired():
            return

        async with self._discovery_lock:
            # Double-check after acquiring lock
            if self._gleif_discovered and not self._is_cache_expired():
                return

            await self._discover_gleif_witnesses()

    async def _discover_gleif_witnesses(self) -> None:
        """Fetch GLEIF well-known OOBI and extract witness endpoints.

        The GLEIF OOBI response contains:
        1. KEL events for the GLEIF Root AID
        2. Reply messages (`rpy`) with witness location schemes

        We parse the /loc/scheme replies to extract witness URLs.
        """
        if not self._gleif_oobi_url:
            log.warning("GLEIF discovery enabled but no OOBI URL configured")
            self._gleif_discovered = True
            return

        log.info(f"Discovering GLEIF witnesses from {self._gleif_oobi_url}")

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_DISCOVERY_TIMEOUT) as client:
                response = await client.get(self._gleif_oobi_url)
                response.raise_for_status()

            content = response.content
            witnesses_found = self._parse_gleif_response(content)

            self._gleif_discovered = True
            self._gleif_discovery_time = datetime.now(timezone.utc)
            self._gleif_discovery_error = None

            log.info(f"GLEIF discovery complete: found {witnesses_found} witnesses")

        except httpx.TimeoutException:
            self._gleif_discovery_error = "Timeout fetching GLEIF OOBI"
            log.error(self._gleif_discovery_error)
            self._gleif_discovered = True  # Mark as attempted to avoid retry storm
            self._gleif_discovery_time = datetime.now(timezone.utc)

        except httpx.HTTPStatusError as e:
            self._gleif_discovery_error = f"HTTP {e.response.status_code} from GLEIF OOBI"
            log.error(self._gleif_discovery_error)
            self._gleif_discovered = True
            self._gleif_discovery_time = datetime.now(timezone.utc)

        except Exception as e:
            self._gleif_discovery_error = f"GLEIF discovery failed: {e}"
            log.error(self._gleif_discovery_error)
            self._gleif_discovered = True
            self._gleif_discovery_time = datetime.now(timezone.utc)

    def _parse_gleif_response(self, content: bytes) -> int:
        """Parse GLEIF OOBI response to extract witness URLs.

        The response is a KERI message stream (JSON objects concatenated).
        We look for 'rpy' messages with '/loc/scheme' route that contain
        witness endpoint URLs.

        Args:
            content: Raw response bytes from GLEIF OOBI.

        Returns:
            Number of witnesses extracted.
        """
        witnesses_added = 0

        # Try to parse as JSON lines/stream
        # KERI responses are often multiple JSON objects concatenated
        text = content.decode("utf-8", errors="replace")

        # Find all JSON objects (simple approach: look for top-level braces)
        depth = 0
        start = None
        objects = []

        for i, char in enumerate(text):
            if char == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    objects.append(text[start : i + 1])
                    start = None

        for obj_str in objects:
            try:
                obj = json.loads(obj_str)

                # Look for reply messages with location scheme
                if obj.get("t") == "rpy" and obj.get("r") == "/loc/scheme":
                    attrs = obj.get("a", {})
                    url = attrs.get("url")
                    if url and self._add_witness(url, source="gleif"):
                        witnesses_added += 1

                # Also check for witness AIDs in establishment events
                # (icp, rot, dip, drt have 'b' field with witness list)
                if obj.get("t") in ("icp", "rot", "dip", "drt"):
                    witness_aids = obj.get("b", [])
                    log.debug(f"Found {len(witness_aids)} witness AIDs in {obj.get('t')} event")

            except json.JSONDecodeError:
                continue

        return witnesses_added


# =============================================================================
# Singleton Access
# =============================================================================

_witness_pool: Optional[WitnessPool] = None


def get_witness_pool() -> WitnessPool:
    """Get or create the witness pool singleton.

    Lazily creates the pool with configuration from common.vvp.dossier.config.

    Returns:
        The singleton WitnessPool instance.
    """
    global _witness_pool

    if _witness_pool is None:
        from common.vvp.dossier.config import (
            GLEIF_WITNESS_CACHE_TTL,
            GLEIF_WITNESS_DISCOVERY_ENABLED,
            GLEIF_WITNESS_OOBI_URL,
            PROVENANT_WITNESS_URLS,
        )

        _witness_pool = WitnessPool(
            config_witnesses=PROVENANT_WITNESS_URLS,
            gleif_oobi_url=GLEIF_WITNESS_OOBI_URL,
            gleif_discovery_enabled=GLEIF_WITNESS_DISCOVERY_ENABLED,
            cache_ttl_seconds=GLEIF_WITNESS_CACHE_TTL,
        )

    return _witness_pool


def reset_witness_pool() -> None:
    """Reset the singleton for testing."""
    global _witness_pool
    _witness_pool = None
