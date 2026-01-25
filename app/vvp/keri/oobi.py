"""OOBI (Out-of-Band Introduction) dereferencer.

OOBIs provide a way to bootstrap KERI communication by resolving a URL
to obtain the Key Event Log (KEL) for an AID.

Per spec §5A Step 4: "Resolve issuer key state at reference time T"
"""

import asyncio
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from .exceptions import OOBIContentInvalidError, ResolutionFailedError


# Accepted content types for OOBI responses
CESR_CONTENT_TYPE = "application/json+cesr"
JSON_CONTENT_TYPE = "application/json"


@dataclass
class OOBIResult:
    """Result of OOBI dereferencing.

    Attributes:
        aid: The AID (Autonomic Identifier) resolved.
        kel_data: Raw KEL data (CESR or JSON encoded).
        witnesses: List of witness URLs/AIDs discovered.
        content_type: Content-Type from OOBI response. Used for routing
            to the appropriate parser (CESR vs JSON).
        error: Error message if resolution partially failed.
    """
    aid: str
    kel_data: bytes
    witnesses: List[str]
    content_type: str = JSON_CONTENT_TYPE
    error: Optional[str] = None


async def dereference_oobi(
    oobi_url: str,
    timeout: float = 5.0,
    max_redirects: int = 3
) -> OOBIResult:
    """Dereference an OOBI URL to fetch KEL data.

    Fetches the OOBI URL and extracts the Key Event Log for the AID.
    Follows redirects up to max_redirects.

    Args:
        oobi_url: The OOBI URL to dereference.
        timeout: Request timeout in seconds.
        max_redirects: Maximum redirects to follow.

    Returns:
        OOBIResult containing the KEL data and metadata.

    Raises:
        ResolutionFailedError: If network/fetch fails (recoverable).
        OOBIContentInvalidError: If content type/format invalid (non-recoverable).
    """
    # Validate URL
    try:
        parsed = urlparse(oobi_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL structure")
    except Exception as e:
        raise ResolutionFailedError(f"Invalid OOBI URL: {e}")

    # Extract AID from URL if present
    # Common OOBI format: http://witness/oobi/{aid}/witness/{witness_aid}
    aid = _extract_aid_from_url(oobi_url)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects
        ) as client:
            response = await client.get(oobi_url)

            # Check for HTTP errors
            if response.status_code >= 400:
                raise ResolutionFailedError(
                    f"OOBI fetch failed: HTTP {response.status_code}"
                )

            # Validate content type
            content_type = response.headers.get("content-type", "").lower()

            # Accept CESR (normative) or JSON (test fallback)
            if CESR_CONTENT_TYPE.lower() not in content_type and \
               JSON_CONTENT_TYPE.lower() not in content_type and \
               "application/octet-stream" not in content_type:
                # Be lenient - if no content type, try to parse anyway
                if content_type and "text" not in content_type:
                    raise OOBIContentInvalidError(
                        f"Invalid OOBI content type: {content_type}, "
                        f"expected {CESR_CONTENT_TYPE} or {JSON_CONTENT_TYPE}"
                    )

            kel_data = response.content

            if not kel_data:
                raise ResolutionFailedError("OOBI response is empty")

            # Extract witnesses from response if available
            witnesses = _extract_witnesses(kel_data, aid)

            # Determine content type for routing
            detected_content_type = JSON_CONTENT_TYPE  # Default
            if CESR_CONTENT_TYPE.lower() in content_type:
                detected_content_type = CESR_CONTENT_TYPE
            elif "application/octet-stream" in content_type:
                # Might be CESR binary - check for CESR markers
                if kel_data and kel_data[0:1] in (b"-", b"0", b"1", b"4", b"5", b"6"):
                    detected_content_type = CESR_CONTENT_TYPE

            return OOBIResult(
                aid=aid,
                kel_data=kel_data,
                witnesses=witnesses,
                content_type=detected_content_type
            )

    except httpx.TimeoutException:
        raise ResolutionFailedError(f"OOBI fetch timeout after {timeout}s")
    except httpx.RequestError as e:
        raise ResolutionFailedError(f"OOBI network error: {e}")
    except OOBIContentInvalidError:
        raise
    except ResolutionFailedError:
        raise
    except Exception as e:
        raise ResolutionFailedError(f"OOBI fetch failed: {e}")


def _extract_aid_from_url(url: str) -> str:
    """Extract AID from OOBI URL path.

    Common formats:
    - /oobi/{aid}
    - /oobi/{aid}/witness/{witness}
    - /oobi/{aid}/controller
    """
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]

    # Look for 'oobi' segment followed by AID
    for i, part in enumerate(path_parts):
        if part.lower() == "oobi" and i + 1 < len(path_parts):
            potential_aid = path_parts[i + 1]
            # KERI AIDs typically start with derivation codes
            if potential_aid and potential_aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                return potential_aid

    # Fallback: return last path segment if it looks like an AID
    if path_parts:
        last = path_parts[-1]
        if last and last[0] in "BDEFGHJKLMNOPQRSTUVWXYZ" and len(last) > 40:
            return last

    return ""


def _extract_witnesses(kel_data: bytes, aid: str) -> List[str]:
    """Extract witness AIDs from KEL data.

    Parses the KEL to find witness lists from establishment events.
    """
    import json

    witnesses = []

    try:
        # Try JSON parsing
        data = json.loads(kel_data.decode("utf-8"))

        if isinstance(data, dict):
            # Single event
            witnesses.extend(data.get("b", []))
        elif isinstance(data, list):
            # Multiple events - get witnesses from most recent establishment
            for event in reversed(data):
                if isinstance(event, dict):
                    event_type = event.get("t", "")
                    if event_type in ("icp", "rot", "dip", "drt"):
                        witnesses.extend(event.get("b", []))
                        break
    except Exception:
        # CESR or malformed - can't extract witnesses
        pass

    return witnesses


async def fetch_kel_from_witnesses(
    aid: str,
    witnesses: List[str],
    timeout: float = 5.0,
    min_responses: int = 1
) -> OOBIResult:
    """Fetch KEL from multiple witnesses for consensus.

    Queries multiple witnesses and returns the KEL with the most
    consistent responses.

    Args:
        aid: The AID to fetch KEL for.
        witnesses: List of witness URLs.
        timeout: Per-request timeout.
        min_responses: Minimum witnesses that must respond.

    Returns:
        OOBIResult with the most consistent KEL.

    Raises:
        ResolutionFailedError: If insufficient witnesses respond.
    """
    if not witnesses:
        raise ResolutionFailedError("No witnesses provided for KEL fetch")

    results = []
    errors = []

    # Fetch from all witnesses in parallel
    async def fetch_one(witness_url: str) -> Optional[OOBIResult]:
        try:
            return await dereference_oobi(witness_url, timeout=timeout)
        except Exception as e:
            errors.append(f"{witness_url}: {e}")
            return None

    tasks = [fetch_one(w) for w in witnesses]
    responses = await asyncio.gather(*tasks)

    results = [r for r in responses if r is not None]

    if len(results) < min_responses:
        raise ResolutionFailedError(
            f"Insufficient witness responses: got {len(results)}, "
            f"need {min_responses}. Errors: {errors[:3]}"
        )

    # Return first successful result
    # TODO: Implement consensus checking across witnesses
    return results[0]
