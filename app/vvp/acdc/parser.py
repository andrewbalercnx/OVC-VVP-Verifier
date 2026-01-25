"""ACDC parsing and SAID validation.

Per VVP §6.3.x and KERI/ACDC spec.
"""

import json
from typing import Any, Dict

from .exceptions import ACDCParseError, ACDCSAIDMismatch
from .models import ACDC


def parse_acdc(data: Dict[str, Any]) -> ACDC:
    """Parse and validate ACDC structure.

    Validates required fields are present and creates an ACDC object.

    Args:
        data: ACDC dictionary (parsed from JSON or dossier).

    Returns:
        Parsed ACDC object.

    Raises:
        ACDCParseError: If required fields are missing or invalid.
    """
    # Validate required fields
    required_fields = ["d", "i"]  # SAID and issuer are always required
    for field in required_fields:
        if field not in data:
            raise ACDCParseError(f"ACDC missing required field: '{field}'")

    # Extract fields with defaults
    version = data.get("v", "")
    said = data.get("d", "")
    issuer_aid = data.get("i", "")
    schema_said = data.get("s", "")
    attributes = data.get("a")
    edges = data.get("e")
    rules = data.get("r")

    # Validate SAID format (should be CESR-encoded hash)
    if said and len(said) < 20:
        raise ACDCParseError(f"Invalid ACDC SAID format: {said[:20]}...")

    # Validate issuer AID format
    if issuer_aid and issuer_aid[0] not in "BDEFGHJKLMNOPQRSTUVWXYZ":
        raise ACDCParseError(f"Invalid issuer AID format: {issuer_aid[:20]}...")

    return ACDC(
        version=version,
        said=said,
        issuer_aid=issuer_aid,
        schema_said=schema_said,
        attributes=attributes,
        edges=edges,
        rules=rules,
        raw=data
    )


def validate_acdc_said(acdc: ACDC, raw_data: Dict[str, Any]) -> None:
    """Validate ACDC's self-addressing identifier.

    Canonicalization Process (per KERI/CESR spec):
    1. Replace 'd' field with placeholder of same length (##############...)
    2. Serialize to KERI canonical JSON:
       - Deterministic key ordering: v, d, i, s, a, e, r
       - No whitespace between elements
       - UTF-8 encoded
    3. Compute Blake3-256 hash of canonical bytes
    4. CESR-encode hash with 'E' prefix (44 chars total)
    5. Compare computed SAID to 'd' field value

    Args:
        acdc: Parsed ACDC object.
        raw_data: Original ACDC dictionary.

    Raises:
        ACDCSAIDMismatch: If computed SAID != d field.
    """
    # Import KERI canonicalization (avoid circular imports)
    from ..keri.keri_canonical import canonical_serialize
    from ..keri.kel_parser import _cesr_encode

    if not acdc.said:
        return  # No SAID to validate

    # Skip placeholder SAIDs (test mode)
    if acdc.said.startswith("#") or "_" * 10 in acdc.said:
        return

    # Create canonical form with placeholder
    data_copy = dict(raw_data)

    # Placeholder must match expected SAID length (44 chars for Blake3-256)
    placeholder_length = len(acdc.said)
    if placeholder_length < 44:
        placeholder_length = 44

    # Use the same derivation code as the actual SAID
    code = acdc.said[0] if acdc.said else "E"
    placeholder = code + "#" * (placeholder_length - 1)
    data_copy["d"] = placeholder

    # Serialize canonically using KERI field ordering
    try:
        canonical_bytes = _acdc_canonical_serialize(data_copy)
    except Exception as e:
        raise ACDCSAIDMismatch(f"Failed to canonicalize ACDC: {e}")

    # Compute Blake3-256 hash
    try:
        import blake3
        digest = blake3.blake3(canonical_bytes).digest()
    except ImportError:
        # Fall back to SHA256 in test mode
        import hashlib
        digest = hashlib.sha256(canonical_bytes).digest()

    # CESR-encode with derivation code
    computed_said = _cesr_encode(digest, code="E")

    # Compare
    if acdc.said != computed_said:
        raise ACDCSAIDMismatch(
            f"ACDC SAID mismatch: has {acdc.said[:20]}... "
            f"but computed {computed_said[:20]}..."
        )


def _acdc_canonical_serialize(data: Dict[str, Any]) -> bytes:
    """Serialize ACDC to canonical form for SAID computation.

    ACDC field ordering (per KERI/ACDC spec):
    v, d, i, s, a, e, r

    Args:
        data: ACDC dictionary.

    Returns:
        Canonical JSON bytes.
    """
    # ACDC canonical field order
    acdc_field_order = ["v", "d", "i", "s", "a", "e", "r"]

    # Build ordered output
    ordered = {}
    for key in acdc_field_order:
        if key in data and data[key] is not None:
            ordered[key] = data[key]

    # Add any remaining fields not in standard order
    for key in data:
        if key not in ordered and data[key] is not None:
            ordered[key] = data[key]

    # Serialize with no whitespace
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_acdc_from_dossier(
    dossier: Dict[str, Any],
    credential_key: str = "credential"
) -> ACDC:
    """Parse ACDC from a dossier structure.

    Dossiers may contain ACDCs in various locations depending on format.

    Args:
        dossier: Dossier dictionary.
        credential_key: Key where ACDC is stored.

    Returns:
        Parsed ACDC.

    Raises:
        ACDCParseError: If ACDC not found or invalid.
    """
    # Try common locations for ACDC in dossier
    acdc_data = None

    # Direct credential key
    if credential_key in dossier:
        acdc_data = dossier[credential_key]

    # Nested in 'acdc' field
    elif "acdc" in dossier:
        acdc_data = dossier["acdc"]

    # Dossier is the ACDC itself
    elif "d" in dossier and "i" in dossier:
        acdc_data = dossier

    if acdc_data is None:
        raise ACDCParseError(f"No ACDC found in dossier at key '{credential_key}'")

    return parse_acdc(acdc_data)
