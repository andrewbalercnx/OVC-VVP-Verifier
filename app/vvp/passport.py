"""
PASSporT JWT parser and validator per spec §5.0-§5.4.

Parses and validates VVP PASSporT JWTs. Signature verification is deferred
to Phase 4 (requires KERI key state).
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from app.core.config import (
    ALLOW_PASSPORT_EXP_OMISSION,
    ALLOWED_ALGORITHMS,
    CLOCK_SKEW_SECONDS,
    FORBIDDEN_ALGORITHMS,
    MAX_IAT_DRIFT_SECONDS,
    MAX_PASSPORT_VALIDITY_SECONDS,
    MAX_TOKEN_AGE_SECONDS,
)
from app.vvp.exceptions import PassportError
from app.vvp.header import VVPIdentity


@dataclass(frozen=True)
class PassportHeader:
    """Decoded PASSporT JWT header."""
    alg: str
    ppt: str
    kid: str
    typ: Optional[str] = None  # Not validated per v1.4


@dataclass(frozen=True)
class PassportPayload:
    """Decoded PASSporT JWT payload."""
    iat: int
    orig: Optional[dict] = None    # Required by local policy
    dest: Optional[dict] = None    # Required by local policy
    evd: Optional[str] = None      # Required by local policy
    iss: Optional[str] = None
    exp: Optional[int] = None
    card: Optional[dict] = None
    goal: Optional[str] = None
    call_reason: Optional[str] = None  # Mapped from "call-reason"
    origid: Optional[str] = None


@dataclass(frozen=True)
class Passport:
    """Parsed VVP PASSporT."""
    header: PassportHeader
    payload: PassportPayload
    signature: bytes
    raw_header: str      # Base64url-encoded header (for signature verification)
    raw_payload: str     # Base64url-encoded payload (for signature verification)


def parse_passport(jwt: Optional[str]) -> Passport:
    """Parse and validate a VVP PASSporT JWT.

    Args:
        jwt: The PASSporT JWT string (header.payload.signature).

    Returns:
        Passport dataclass with parsed header, payload, and signature.

    Raises:
        PassportError: With appropriate error code on failure.

    Note:
        Signature verification is NOT performed here (deferred to Phase 4).
        This function validates structure, algorithm, and required field presence.
    """
    # Step 1: Check for missing/empty JWT
    if not jwt or not jwt.strip():
        raise PassportError.missing()

    jwt = jwt.strip()

    # Step 2: Split into parts
    parts = jwt.split(".")
    if len(parts) != 3:
        raise PassportError.parse_failed(
            f"JWT must have 3 parts (header.payload.signature), got {len(parts)}"
        )

    raw_header, raw_payload, raw_signature = parts

    # Step 3: Decode and parse header
    header_data = _decode_jwt_part(raw_header, "header")
    header = _parse_header(header_data)

    # Step 4: Validate algorithm
    _validate_algorithm(header.alg)

    # Step 5: Validate ppt is "vvp"
    if header.ppt != "vvp":
        raise PassportError.parse_failed(
            f"ppt must be 'vvp' for VVP PASSporTs, got '{header.ppt}'"
        )

    # Step 6: Decode and parse payload
    payload_data = _decode_jwt_part(raw_payload, "payload")
    payload = _parse_payload(payload_data)

    # Step 7: Decode signature (keep as bytes for Phase 4)
    signature = _decode_signature(raw_signature)

    return Passport(
        header=header,
        payload=payload,
        signature=signature,
        raw_header=raw_header,
        raw_payload=raw_payload,
    )


def validate_passport_binding(
    passport: Passport,
    vvp_identity: VVPIdentity,
    now: Optional[int] = None
) -> None:
    """Validate binding between PASSporT and VVP-Identity per §5.2.

    Args:
        passport: Parsed PASSporT.
        vvp_identity: Parsed VVP-Identity header.
        now: Current timestamp (defaults to time.time()).

    Raises:
        PassportError: If binding validation fails.

    Validates (Normative per spec):
        - ppt in PASSporT matches VVP-Identity ppt (§5.2)
        - kid in PASSporT matches VVP-Identity kid (§5.2) - strict equality
        - iat drift ≤ 5 seconds (§5.2A) - binding violation
        - exp consistency (§5.2A) - binding violation
        - PASSporT not expired (§5.2B) - expiry policy
    """
    if now is None:
        now = int(time.time())

    # §5.2: ppt binding
    if passport.header.ppt != vvp_identity.ppt:
        raise PassportError.parse_failed(
            f"ppt mismatch: PASSporT has '{passport.header.ppt}', "
            f"VVP-Identity has '{vvp_identity.ppt}'"
        )

    # §5.2: kid binding (strict equality in Phase 3)
    if passport.header.kid != vvp_identity.kid:
        raise PassportError.parse_failed(
            f"kid mismatch: PASSporT has '{passport.header.kid}', "
            f"VVP-Identity has '{vvp_identity.kid}'"
        )

    # §5.2A: iat drift
    iat_drift = abs(passport.payload.iat - vvp_identity.iat)
    if iat_drift > MAX_IAT_DRIFT_SECONDS:
        raise PassportError.parse_failed(
            f"iat drift exceeds {MAX_IAT_DRIFT_SECONDS}s: "
            f"PASSporT iat={passport.payload.iat}, VVP-Identity iat={vvp_identity.iat}, "
            f"drift={iat_drift}s"
        )

    # §5.2A: exp > iat (if exp present)
    if passport.payload.exp is not None:
        if passport.payload.exp <= passport.payload.iat:
            raise PassportError.parse_failed(
                f"exp must be greater than iat: exp={passport.payload.exp}, "
                f"iat={passport.payload.iat}"
            )

    # §5.2A: exp consistency between PASSporT and VVP-Identity
    passport_exp = passport.payload.exp
    # VVP-Identity exp is always present (computed if absent in Phase 2)
    identity_exp = vvp_identity.exp

    if passport_exp is not None:
        # Both have exp: check drift
        exp_drift = abs(passport_exp - identity_exp)
        if exp_drift > MAX_IAT_DRIFT_SECONDS:
            raise PassportError.parse_failed(
                f"exp drift exceeds {MAX_IAT_DRIFT_SECONDS}s: "
                f"PASSporT exp={passport_exp}, VVP-Identity exp={identity_exp}, "
                f"drift={exp_drift}s"
            )
    else:
        # PASSporT exp absent - check if VVP-Identity had explicit exp
        # §5.2A: "If VVP-Identity exp is present but PASSporT exp is absent,
        # the verifier MUST treat the PASSporT as expired unless explicitly
        # configured to allow exp omission (default: reject)."
        if vvp_identity.exp_provided and not ALLOW_PASSPORT_EXP_OMISSION:
            raise PassportError.expired(
                f"PASSporT exp absent but VVP-Identity exp explicitly provided "
                f"(VVP-Identity exp={identity_exp}); configure ALLOW_PASSPORT_EXP_OMISSION "
                f"to permit this"
            )

    # §5.2B: Expiry policy
    _validate_expiry(passport, now)


def _decode_jwt_part(encoded: str, part_name: str) -> dict[str, Any]:
    """Decode a base64url-encoded JWT part to a dictionary."""
    try:
        # Add padding if needed
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise PassportError.parse_failed(f"{part_name} base64url decode failed: {e}")

    try:
        parsed = json.loads(decoded_bytes)
        if not isinstance(parsed, dict):
            raise PassportError.parse_failed(f"{part_name} JSON root must be an object")
        return parsed
    except json.JSONDecodeError as e:
        raise PassportError.parse_failed(f"{part_name} JSON parse failed: {e}")
    except UnicodeDecodeError as e:
        raise PassportError.parse_failed(f"{part_name} invalid UTF-8: {e}")


def _decode_signature(encoded: str) -> bytes:
    """Decode a base64url-encoded signature to bytes."""
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise PassportError.parse_failed(f"signature base64url decode failed: {e}")


def _parse_header(data: dict[str, Any]) -> PassportHeader:
    """Parse and validate JWT header fields."""
    # Required fields
    alg = _require_string(data, "alg", "header")
    ppt = _require_string(data, "ppt", "header")
    kid = _require_string(data, "kid", "header")

    # Optional field (not validated)
    typ = data.get("typ")
    if typ is not None and not isinstance(typ, str):
        typ = None  # Ignore non-string typ

    return PassportHeader(alg=alg, ppt=ppt, kid=kid, typ=typ)


def _parse_payload(data: dict[str, Any]) -> PassportPayload:
    """Parse and validate JWT payload fields."""
    # Required by spec §5.2A
    iat = _require_integer(data, "iat", "payload")

    # Required by local policy (VVP-draft)
    orig = _require_dict(data, "orig", "payload")
    dest = _require_dict(data, "dest", "payload")
    evd = _require_string(data, "evd", "payload")

    # Optional fields
    iss = data.get("iss")
    if iss is not None and not isinstance(iss, str):
        iss = None

    exp = _get_optional_integer(data, "exp", "payload")
    card = data.get("card") if isinstance(data.get("card"), dict) else None
    goal = data.get("goal") if isinstance(data.get("goal"), str) else None

    # Map "call-reason" to call_reason
    call_reason = data.get("call-reason")
    if call_reason is not None and not isinstance(call_reason, str):
        call_reason = None

    origid = data.get("origid")
    if origid is not None and not isinstance(origid, str):
        origid = None

    return PassportPayload(
        iat=iat,
        orig=orig,
        dest=dest,
        evd=evd,
        iss=iss,
        exp=exp,
        card=card,
        goal=goal,
        call_reason=call_reason,
        origid=origid,
    )


def _validate_algorithm(alg: str) -> None:
    """Validate algorithm per §5.0, §5.1."""
    # Check forbidden algorithms
    if alg in FORBIDDEN_ALGORITHMS or alg == "none":
        raise PassportError.forbidden_alg(alg)

    # Check allowed algorithms
    if alg not in ALLOWED_ALGORITHMS:
        raise PassportError.forbidden_alg(alg)


def _validate_expiry(passport: Passport, now: int) -> None:
    """Validate expiry per §5.2B."""
    iat = passport.payload.iat
    exp = passport.payload.exp

    if exp is not None:
        # §5.2B: exp - iat must be ≤ MAX_PASSPORT_VALIDITY_SECONDS
        validity_window = exp - iat
        if validity_window > MAX_PASSPORT_VALIDITY_SECONDS:
            raise PassportError.expired(
                f"validity window exceeds {MAX_PASSPORT_VALIDITY_SECONDS}s: "
                f"exp - iat = {validity_window}s"
            )

        # §5.2B: now > exp + CLOCK_SKEW_SECONDS means expired
        if now > exp + CLOCK_SKEW_SECONDS:
            raise PassportError.expired(
                f"token expired: now={now}, exp={exp}, clock_skew={CLOCK_SKEW_SECONDS}"
            )
    else:
        # §5.2B: exp absent, check max-age policy
        max_age_deadline = iat + MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS
        if now > max_age_deadline:
            raise PassportError.expired(
                f"max-age exceeded: now={now}, iat={iat}, "
                f"max_age={MAX_TOKEN_AGE_SECONDS}, clock_skew={CLOCK_SKEW_SECONDS}"
            )


def _require_string(data: dict[str, Any], field: str, part: str) -> str:
    """Require a non-empty string field."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if not isinstance(value, str):
        raise PassportError.parse_failed(f"{part} field {field} must be a string")
    if not value.strip():
        raise PassportError.parse_failed(f"{part} field {field} must not be empty")
    return value


def _require_integer(data: dict[str, Any], field: str, part: str) -> int:
    """Require an integer field."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if isinstance(value, bool):
        raise PassportError.parse_failed(f"{part} field {field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise PassportError.parse_failed(f"{part} field {field} must be an integer")


def _require_dict(data: dict[str, Any], field: str, part: str) -> dict:
    """Require a dict field (local policy)."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if not isinstance(value, dict):
        raise PassportError.parse_failed(f"{part} field {field} must be an object")
    return value


def _get_optional_integer(data: dict[str, Any], field: str, part: str) -> Optional[int]:
    """Get an optional integer field."""
    if field not in data:
        return None
    value = data[field]
    if isinstance(value, bool):
        raise PassportError.parse_failed(f"{part} field {field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise PassportError.parse_failed(f"{part} field {field} must be an integer")
