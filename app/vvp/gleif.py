"""GLEIF API client for LEI lookups.

Provides legal entity name resolution from LEI (Legal Entity Identifier)
via the GLEIF public API: https://api.gleif.org/

Per VVP specification, LEIs are used to identify legal entities in
LE (Legal Entity) credentials and appear in vCard NOTE;LEI fields.
"""

import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import httpx

logger = logging.getLogger("vvp.gleif")

# GLEIF API endpoint
GLEIF_API_BASE = "https://api.gleif.org/api/v1"

# Timeout for GLEIF API requests (seconds)
GLEIF_TIMEOUT = 10.0


@dataclass
class LEIRecord:
    """GLEIF LEI record with legal entity information.

    Attributes:
        lei: The 20-character Legal Entity Identifier.
        legal_name: Primary legal name of the entity.
        status: Entity status (ACTIVE, INACTIVE, etc.).
        jurisdiction: Jurisdiction code (e.g., "GB", "US").
        legal_address_city: City from legal address.
        legal_address_country: Country code from legal address.
    """

    lei: str
    legal_name: str
    status: str = "UNKNOWN"
    jurisdiction: Optional[str] = None
    legal_address_city: Optional[str] = None
    legal_address_country: Optional[str] = None


class GLEIFLookupError(Exception):
    """Raised when GLEIF lookup fails."""

    pass


def _parse_lei_response(data: dict) -> LEIRecord:
    """Parse GLEIF API response into LEIRecord.

    Args:
        data: Raw API response JSON.

    Returns:
        Parsed LEIRecord.
    """
    record_data = data.get("data", {})
    attrs = record_data.get("attributes", {})
    entity = attrs.get("entity", {})

    legal_name_obj = entity.get("legalName", {})
    legal_name = legal_name_obj.get("name", "Unknown")

    legal_address = entity.get("legalAddress", {})

    return LEIRecord(
        lei=attrs.get("lei", record_data.get("id", "")),
        legal_name=legal_name,
        status=entity.get("status", "UNKNOWN"),
        jurisdiction=entity.get("jurisdiction"),
        legal_address_city=legal_address.get("city"),
        legal_address_country=legal_address.get("country"),
    )


@lru_cache(maxsize=256)
def lookup_lei(lei: str) -> Optional[LEIRecord]:
    """Look up LEI record from GLEIF API.

    Results are cached in-memory (LRU cache, max 256 entries) to avoid
    repeated API calls for the same LEI.

    Args:
        lei: 20-character Legal Entity Identifier.

    Returns:
        LEIRecord if found, None if not found or error.
    """
    if not lei or len(lei) != 20:
        logger.debug(f"Invalid LEI format: {lei}")
        return None

    url = f"{GLEIF_API_BASE}/lei-records/{lei}"

    try:
        with httpx.Client(timeout=GLEIF_TIMEOUT) as client:
            response = client.get(url)

            if response.status_code == 404:
                logger.debug(f"LEI not found: {lei}")
                return None

            response.raise_for_status()
            data = response.json()
            record = _parse_lei_response(data)
            logger.debug(f"GLEIF lookup success: {lei} -> {record.legal_name}")
            return record

    except httpx.TimeoutException:
        logger.warning(f"GLEIF lookup timeout for LEI: {lei}")
        return None
    except httpx.HTTPStatusError as e:
        logger.warning(f"GLEIF lookup HTTP error for LEI {lei}: {e}")
        return None
    except Exception as e:
        logger.warning(f"GLEIF lookup failed for LEI {lei}: {e}")
        return None


async def lookup_lei_async(lei: str) -> Optional[LEIRecord]:
    """Async version of LEI lookup.

    Args:
        lei: 20-character Legal Entity Identifier.

    Returns:
        LEIRecord if found, None if not found or error.
    """
    if not lei or len(lei) != 20:
        logger.debug(f"Invalid LEI format: {lei}")
        return None

    url = f"{GLEIF_API_BASE}/lei-records/{lei}"

    try:
        async with httpx.AsyncClient(timeout=GLEIF_TIMEOUT) as client:
            response = await client.get(url)

            if response.status_code == 404:
                logger.debug(f"LEI not found: {lei}")
                return None

            response.raise_for_status()
            data = response.json()
            record = _parse_lei_response(data)
            logger.debug(f"GLEIF lookup success: {lei} -> {record.legal_name}")
            return record

    except httpx.TimeoutException:
        logger.warning(f"GLEIF lookup timeout for LEI: {lei}")
        return None
    except httpx.HTTPStatusError as e:
        logger.warning(f"GLEIF lookup HTTP error for LEI {lei}: {e}")
        return None
    except Exception as e:
        logger.warning(f"GLEIF lookup failed for LEI {lei}: {e}")
        return None


def get_legal_name_for_lei(lei: str) -> Optional[str]:
    """Convenience function to get just the legal name for an LEI.

    Args:
        lei: 20-character Legal Entity Identifier.

    Returns:
        Legal name string if found, None otherwise.
    """
    record = lookup_lei(lei)
    return record.legal_name if record else None
