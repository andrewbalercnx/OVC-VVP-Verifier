"""
VVP-Identity header parser per spec §4.1A and §4.1B.

Parses and validates the VVP-Identity HTTP header, which contains
a base64url-encoded JSON object with caller identity claims.
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from app.core.config import CLOCK_SKEW_SECONDS, MAX_TOKEN_AGE_SECONDS
from app.vvp.exceptions import VVPIdentityError


@dataclass(frozen=True)
class VVPIdentity:
    """Decoded VVP-Identity header per §4.1A.

    Attributes:
        ppt: PASSporT profile type (value not validated in Phase 2)
        kid: Key identifier - opaque OOBI reference per §4.1B
        evd: Evidence/dossier URL - opaque OOBI reference per §4.1B
        iat: Issued-at timestamp (seconds since epoch)
        exp: Expiry timestamp (computed from iat if absent in header)
        exp_provided: True if exp was explicitly provided in the header,
                      False if computed as default. Used for §5.2A binding.
    """
    ppt: str
    kid: str
    evd: str
    iat: int
    exp: int
    exp_provided: bool = False


def parse_vvp_identity(header: Optional[str]) -> VVPIdentity:
    """Parse and validate a VVP-Identity header.

    Args:
        header: Base64url-encoded JSON string from VVP-Identity HTTP header.
                May be None or empty if header was not provided.

    Returns:
        VVPIdentity dataclass with validated fields.

    Raises:
        VVPIdentityError: With code VVP_IDENTITY_MISSING if header is absent/empty,
                         or VVP_IDENTITY_INVALID for any decode/parse/validation error.
    """
    # Step 1: Check for missing/empty header
    if not header or not header.strip():
        raise VVPIdentityError.missing()

    # Step 2: Base64url decode
    decoded_bytes = _base64url_decode(header.strip())

    # Step 3: Parse JSON
    data = _parse_json(decoded_bytes)

    # Step 4: Validate required fields exist with correct types
    ppt = _require_non_empty_string(data, "ppt")
    kid = _require_non_empty_string(data, "kid")
    evd = _require_non_empty_string(data, "evd")
    iat = _require_integer(data, "iat")

    # Step 5: Validate iat is not in the future beyond clock skew
    _validate_iat_not_future(iat)

    # Step 6: Handle optional exp
    exp, exp_provided = _get_optional_exp(data, iat)

    return VVPIdentity(ppt=ppt, kid=kid, evd=evd, iat=iat, exp=exp, exp_provided=exp_provided)


def _base64url_decode(encoded: str) -> bytes:
    """Decode base64url string with padding fix."""
    try:
        # Add padding if needed (base64url may omit trailing =)
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise VVPIdentityError.invalid(f"base64url decode failed: {e}")


def _parse_json(data: bytes) -> dict[str, Any]:
    """Parse JSON bytes into a dictionary."""
    try:
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise VVPIdentityError.invalid("JSON root must be an object")
        return parsed
    except json.JSONDecodeError as e:
        raise VVPIdentityError.invalid(f"JSON parse failed: {e}")
    except UnicodeDecodeError as e:
        raise VVPIdentityError.invalid(f"JSON parse failed: invalid UTF-8: {e}")


def _require_non_empty_string(data: dict[str, Any], field: str) -> str:
    """Validate that a field exists and is a non-empty string."""
    if field not in data:
        raise VVPIdentityError.invalid(f"missing required field: {field}")
    value = data[field]
    if not isinstance(value, str):
        raise VVPIdentityError.invalid(f"field {field} must be a string")
    if not value.strip():
        raise VVPIdentityError.invalid(f"field {field} must not be empty")
    return value


def _require_integer(data: dict[str, Any], field: str) -> int:
    """Validate that a field exists and is an integer."""
    if field not in data:
        raise VVPIdentityError.invalid(f"missing required field: {field}")
    value = data[field]
    # JSON integers are parsed as int, but floats that are whole numbers
    # should also be accepted (e.g., 1737500000.0)
    if isinstance(value, bool):
        # bool is a subclass of int in Python, reject it explicitly
        raise VVPIdentityError.invalid(f"field {field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise VVPIdentityError.invalid(f"field {field} must be an integer")


def _validate_iat_not_future(iat: int) -> None:
    """Validate iat is not in the future beyond clock skew."""
    now = int(time.time())
    max_allowed = now + CLOCK_SKEW_SECONDS
    if iat > max_allowed:
        raise VVPIdentityError.invalid(
            f"iat {iat} is in the future beyond clock skew (max: {max_allowed})"
        )


def _get_optional_exp(data: dict[str, Any], iat: int) -> tuple[int, bool]:
    """Get exp field, computing default if absent.

    Returns:
        Tuple of (exp_value, exp_provided) where exp_provided is True if
        exp was explicitly in the header, False if computed as default.
        This distinction is needed for §5.2A binding validation.
    """
    if "exp" not in data:
        return (iat + MAX_TOKEN_AGE_SECONDS, False)

    value = data["exp"]
    # Same validation as iat
    if isinstance(value, bool):
        raise VVPIdentityError.invalid("field exp must be an integer")
    if isinstance(value, int):
        return (value, True)
    if isinstance(value, float) and value.is_integer():
        return (int(value), True)
    raise VVPIdentityError.invalid("field exp must be an integer")
