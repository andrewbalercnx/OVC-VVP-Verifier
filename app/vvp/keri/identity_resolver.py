"""
OOBI-based issuer identity resolution.

Discovers identity information (legalName, LEI) for AIDs by querying
KERI witness endpoints for Legal Entity (LE) credentials.

This module provides a fallback mechanism when issuer identity is not
available in the dossier's LE credentials.

Per VVP SS 6.1B: Verifier MAY query external sources for credential data.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class DiscoveredIdentity:
    """Identity discovered from OOBI credential query.

    Attributes:
        aid: The AID this identity is about.
        legal_name: Legal name from LE credential (legalName or vCard ORG).
        lei: Legal Entity Identifier from LE credential.
        source_said: SAID of the LE credential this came from.
        source_url: Witness URL where identity was found (for debugging).
    """

    aid: str
    legal_name: Optional[str] = None
    lei: Optional[str] = None
    source_said: Optional[str] = None
    source_url: str = ""


# =============================================================================
# Identity Cache
# =============================================================================


class IdentityCache:
    """In-memory cache for discovered identities.

    Caches both positive results (identity found) and negative results
    (identity not found) to avoid repeated network queries.

    Attributes:
        _cache: Dict mapping AID to (DiscoveredIdentity or None, timestamp).
        _ttl: Time-to-live in seconds for cache entries.
    """

    def __init__(self, ttl_seconds: float = 300.0):
        """Initialize cache with TTL.

        Args:
            ttl_seconds: Time-to-live for cache entries (default 5 minutes).
        """
        self._cache: Dict[str, tuple[Optional[DiscoveredIdentity], float]] = {}
        self._ttl = ttl_seconds

    def get(self, aid: str) -> tuple[Optional[DiscoveredIdentity], bool]:
        """Get cached identity if not expired.

        Args:
            aid: The AID to look up.

        Returns:
            Tuple of (identity or None, cache_hit). If cache_hit is False,
            the value is not in cache. If cache_hit is True, the identity
            is the cached value (which may be None for negative cache).
        """
        if aid not in self._cache:
            return None, False

        identity, cached_at = self._cache[aid]
        if time.time() - cached_at > self._ttl:
            # Expired
            del self._cache[aid]
            return None, False

        return identity, True

    def set(self, aid: str, identity: Optional[DiscoveredIdentity]) -> None:
        """Cache identity (including None for negative cache).

        Args:
            aid: The AID to cache.
            identity: The discovered identity, or None if not found.
        """
        self._cache[aid] = (identity, time.time())

    def clear(self) -> None:
        """Clear all cached identities."""
        self._cache.clear()

    def __len__(self) -> int:
        """Return number of entries in cache."""
        return len(self._cache)


# Module-level singleton
_identity_cache: Optional[IdentityCache] = None


def get_identity_cache() -> IdentityCache:
    """Get or create the identity cache singleton."""
    global _identity_cache
    if _identity_cache is None:
        _identity_cache = IdentityCache()
    return _identity_cache


# =============================================================================
# Helper Functions
# =============================================================================


def extract_witness_base_url(oobi_url: str) -> Optional[str]:
    """Extract witness base URL from an OOBI URL.

    OOBI URLs follow the pattern:
        http://witness5.stage.provenant.net:5631/oobi/{AID}/witness

    Returns: http://witness5.stage.provenant.net:5631

    Args:
        oobi_url: Full OOBI URL from PASSporT kid field.

    Returns:
        Base URL (scheme://host:port) or None if parsing fails.
    """
    if not oobi_url:
        return None
    try:
        parsed = urlparse(oobi_url)
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return None


def _parse_credentials_response(
    data: Any,
    target_aid: str,
) -> Optional[DiscoveredIdentity]:
    """Parse credentials response for identity information.

    Looks for LE credentials with legalName, LEI, or vCard ORG fields
    where the issuee matches the target AID.

    Args:
        data: JSON response from credentials endpoint (list or dict).
        target_aid: The AID we're looking for identity of.

    Returns:
        DiscoveredIdentity if found, None otherwise.
    """
    credentials = []

    # Normalize to list
    if isinstance(data, dict):
        # Single credential or wrapped response
        if "d" in data and ("a" in data or "sad" in data):
            credentials = [data]
        elif "credentials" in data:
            credentials = data["credentials"]
        elif "creds" in data:
            credentials = data["creds"]
    elif isinstance(data, list):
        credentials = data

    for cred in credentials:
        if not isinstance(cred, dict):
            continue

        # Get attributes - may be under 'a', 'sad.a', or 'attributes'
        attrs = cred.get("a") or cred.get("attributes") or {}
        if "sad" in cred and isinstance(cred["sad"], dict):
            attrs = cred["sad"].get("a", attrs)

        if not isinstance(attrs, dict):
            continue

        # Check if this credential is about the target AID
        issuee = attrs.get("issuee") or attrs.get("i")
        issuer = cred.get("i") or cred.get("issuer")

        # If no explicit issuee, credential may identify its issuer
        if not issuee:
            issuee = issuer

        if issuee != target_aid:
            continue

        # Extract identity fields
        legal_name = attrs.get("legalName")
        lei = attrs.get("LEI")

        # Fallback to vCard ORG
        vcard = attrs.get("vcard")
        if isinstance(vcard, list) and not legal_name:
            for line in vcard:
                if isinstance(line, str) and line.upper().startswith("ORG:"):
                    legal_name = line[4:].strip()
                    break

        if legal_name or lei:
            return DiscoveredIdentity(
                aid=target_aid,
                legal_name=legal_name,
                lei=lei,
                source_said=cred.get("d") or cred.get("said"),
            )

    return None


# =============================================================================
# Discovery Functions
# =============================================================================


async def _query_endpoint(
    url: str,
    timeout: float,
) -> Optional[Any]:
    """Query a single endpoint and return JSON response.

    Args:
        url: Full URL to query.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response or None on any error.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 200:
                return response.json()
            log.debug(f"Identity query returned {response.status_code}: {url}")
    except httpx.TimeoutException:
        log.debug(f"Identity query timeout: {url}")
    except httpx.RequestError as e:
        log.debug(f"Identity query network error: {url} - {e}")
    except json.JSONDecodeError as e:
        log.debug(f"Identity query JSON parse error: {url} - {e}")
    except Exception as e:
        log.debug(f"Identity query failed: {url} - {e}")
    return None


async def discover_issuer_identity(
    aid: str,
    oobi_url: Optional[str] = None,
    timeout: float = 3.0,
    use_cache: bool = True,
) -> Optional[DiscoveredIdentity]:
    """Discover identity for an AID by querying witness endpoints.

    Query strategy:
    1. Check cache first (if use_cache=True)
    2. Extract witness base URL from oobi_url
    3. Try endpoints: /credentials?issuer={aid}, /oobi/{aid}/credentials
    4. Parse response for LE credentials with identity fields
    5. Cache and return result

    Args:
        aid: The AID to discover identity for.
        oobi_url: Optional OOBI URL (e.g., from PASSporT kid) to derive witness.
        timeout: Per-request timeout in seconds.
        use_cache: Whether to use/update the identity cache.

    Returns:
        DiscoveredIdentity if found, None otherwise.
        Never raises exceptions - returns None on any failure.
    """
    # Check cache
    if use_cache:
        cache = get_identity_cache()
        cached, hit = cache.get(aid)
        if hit:
            log.debug(f"Identity cache {'hit' if cached else 'negative'} for {aid[:20]}...")
            return cached

    # Extract witness base URL
    witness_base = extract_witness_base_url(oobi_url) if oobi_url else None

    if not witness_base:
        log.debug(f"No witness URL for identity discovery: {aid[:20]}...")
        if use_cache:
            cache.set(aid, None)
        return None

    # Endpoints to try (in order of preference)
    endpoints = [
        f"{witness_base}/credentials?issuer={aid}",
        f"{witness_base}/oobi/{aid}/credentials",
    ]

    for endpoint in endpoints:
        log.debug(f"Trying identity endpoint: {endpoint}")
        data = await _query_endpoint(endpoint, timeout)

        if data is not None:
            identity = _parse_credentials_response(data, aid)
            if identity:
                identity.source_url = endpoint
                log.info(f"Discovered identity for {aid[:20]}...: {identity.legal_name}")
                if use_cache:
                    cache.set(aid, identity)
                return identity

    # No identity found
    log.debug(f"No identity found for {aid[:20]}...")
    if use_cache:
        cache.set(aid, None)
    return None


async def discover_identities_parallel(
    aids: List[str],
    oobi_url: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, DiscoveredIdentity]:
    """Discover identities for multiple AIDs in parallel.

    Uses asyncio.gather to query all AIDs concurrently, with
    individual timeout per query.

    Args:
        aids: List of AIDs to discover identity for.
        oobi_url: OOBI URL for witness discovery.
        timeout: Per-request timeout in seconds.

    Returns:
        Dict mapping AID to DiscoveredIdentity (only for found identities).
    """
    if not aids:
        return {}

    tasks = [
        discover_issuer_identity(aid, oobi_url=oobi_url, timeout=timeout)
        for aid in aids
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    identity_map: Dict[str, DiscoveredIdentity] = {}
    for aid, result in zip(aids, results):
        if isinstance(result, DiscoveredIdentity):
            identity_map[aid] = result
        elif isinstance(result, Exception):
            log.warning(f"Identity discovery exception for {aid[:20]}...: {result}")

    return identity_map
