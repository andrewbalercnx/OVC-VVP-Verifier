"""URL-keyed dossier cache with SAID index for revocation invalidation.

COMPATIBILITY SHIM: This module re-exports from common.vvp.dossier.cache.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.dossier:
    from common.vvp.dossier import DossierCache, CachedDossier, CacheMetrics

The verifier-specific singleton (get_dossier_cache) uses app.core.config
for configuration and injects the verifier's TELClient factory so that
background revocation checks use the verifier's witness pool.
"""

from typing import Optional

# Re-export core classes from common package
from common.vvp.dossier.cache import (
    CachedDossier,
    CacheMetrics,
    DossierCache,
    _CacheEntry,
)

__all__ = [
    "DossierCache",
    "CachedDossier",
    "CacheMetrics",
    "_CacheEntry",
    "get_dossier_cache",
    "reset_dossier_cache",
]


# Module-level singleton (verifier-specific with app.core.config)
_dossier_cache: Optional[DossierCache] = None


def get_dossier_cache() -> DossierCache:
    """Get or create the dossier cache singleton.

    Configuration is read from app.core.config on first access.
    Injects the verifier's get_tel_client so background revocation checks
    use the verifier's WitnessPool singleton (not common's).
    """
    global _dossier_cache
    if _dossier_cache is None:
        # Import here to avoid circular dependency
        from app.core.config import DOSSIER_CACHE_MAX_ENTRIES, DOSSIER_CACHE_TTL_SECONDS
        from app.vvp.keri.tel_client import get_tel_client

        _dossier_cache = DossierCache(
            ttl_seconds=DOSSIER_CACHE_TTL_SECONDS,
            max_entries=DOSSIER_CACHE_MAX_ENTRIES,
            tel_client_factory=get_tel_client,
        )
    return _dossier_cache


def reset_dossier_cache() -> None:
    """Reset the dossier cache singleton (for testing)."""
    global _dossier_cache
    _dossier_cache = None
