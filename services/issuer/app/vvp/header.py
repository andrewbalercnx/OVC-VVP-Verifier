"""VVP-Identity header creation per spec §4.1A.

Creates base64url-encoded JSON headers for VVP attestation.
This is the inverse of services/verifier/app/vvp/header.py (parsing).
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Optional

# Maximum validity window per §5.2B
MAX_VALIDITY_SECONDS = 300


@dataclass(frozen=True)
class VVPIdentityHeader:
    """Created VVP-Identity header with metadata.

    Attributes:
        encoded: Base64url-encoded header string (for HTTP header value)
        ppt: PASSporT profile type (always "vvp")
        kid: OOBI URL for issuer key
        evd: URL for dossier evidence
        iat: Issued-at timestamp (seconds since epoch)
        exp: Expiry timestamp (seconds since epoch)
    """

    encoded: str
    ppt: str
    kid: str
    evd: str
    iat: int
    exp: int


def create_vvp_identity_header(
    issuer_oobi: str,
    dossier_url: str,
    iat: Optional[int] = None,
    exp_seconds: int = 300,
) -> VVPIdentityHeader:
    """Create a VVP-Identity header per §4.1A.

    The header is a base64url-encoded JSON object containing caller identity
    claims. The `kid` must be an OOBI URL (not a bare AID) per §4.1B.

    Args:
        issuer_oobi: Full OOBI URL for kid field (NOT a bare AID).
                     Format: {witness_url}/oobi/{aid}/controller
        dossier_url: Full URL for evd field (dossier location).
                     Format: {issuer_base_url}/dossier/{said}
        iat: Issued-at timestamp. Defaults to current time.
        exp_seconds: Validity window in seconds. Capped at MAX_VALIDITY_SECONDS (300)
                     per §5.2B normative requirement.

    Returns:
        VVPIdentityHeader with encoded header and component values.

    Raises:
        ValueError: If issuer_oobi or dossier_url is empty.

    Example:
        >>> header = create_vvp_identity_header(
        ...     issuer_oobi="http://localhost:5642/oobi/EBfdlu8R27Fbx/controller",
        ...     dossier_url="https://issuer.example.com/dossier/EAbcdef123",
        ... )
        >>> print(header.encoded)  # Base64url string for HTTP header
    """
    if not issuer_oobi or not issuer_oobi.strip():
        raise ValueError("issuer_oobi must not be empty")
    if not dossier_url or not dossier_url.strip():
        raise ValueError("dossier_url must not be empty")

    # Use current time if iat not provided
    if iat is None:
        iat = int(time.time())

    # Enforce §5.2B: max validity window is 300 seconds
    exp_seconds = min(exp_seconds, MAX_VALIDITY_SECONDS)
    exp = iat + exp_seconds

    # Build header object per §4.1A
    header_obj = {
        "ppt": "vvp",
        "kid": issuer_oobi,
        "evd": dossier_url,
        "iat": iat,
        "exp": exp,
    }

    # Encode as compact JSON then base64url (no padding)
    json_str = json.dumps(header_obj, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(json_str.encode("utf-8")).decode("ascii").rstrip("=")

    return VVPIdentityHeader(
        encoded=encoded,
        ppt="vvp",
        kid=issuer_oobi,
        evd=dossier_url,
        iat=iat,
        exp=exp,
    )
