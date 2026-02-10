"""RFC 8224 Identity header builder per Sprint 57.

Constructs the standard SIP Identity header value for STIR compliance.
This is the VVP-specific profile: EdDSA algorithm, "vvp" PASSporT type,
and OOBI URL as the info parameter (replacing x5u in traditional STIR).

RFC 8224 §4 ABNF:
    signed-identity-digest SEMI ident-info *(SEMI ident-info-params)
    ident-info = "info" EQUAL LAQUOT absoluteURI RAQUOT
    ident-info-alg = "alg" EQUAL token
    ident-type = "ppt" EQUAL token

Example output:
    eyJhbGci...sig;info=<https://witness.example.com/oobi/AID/controller>;alg=EdDSA;ppt=vvp
"""

from urllib.parse import urlparse


def build_identity_header(passport_jwt: str, issuer_oobi: str) -> str:
    """Build RFC 8224 Identity header value from PASSporT JWT and OOBI URL.

    Per RFC 8224 §4, the Identity header body is the PASSporT compact JWS
    string directly (no angle brackets, no extra base64url encoding).
    The info parameter is an angle-bracketed absolute URI.

    Args:
        passport_jwt: Complete PASSporT compact JWS (header.payload.signature)
        issuer_oobi: Absolute OOBI URL for key resolution (same value as kid
                     in VVP-Identity header). Must be an absolute URI per
                     RFC 8224 ABNF.

    Returns:
        Identity header value string ready for SIP header insertion.

    Raises:
        ValueError: If passport_jwt is empty or issuer_oobi is not an absolute URI.
    """
    if not passport_jwt or not passport_jwt.strip():
        raise ValueError("passport_jwt must not be empty")

    if not issuer_oobi or not issuer_oobi.strip():
        raise ValueError("issuer_oobi must not be empty")

    # Validate issuer_oobi is an absolute URI per RFC 8224 ABNF
    parsed = urlparse(issuer_oobi)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            f"issuer_oobi must be an absolute URI (has scheme and host), "
            f"got: {issuer_oobi}"
        )

    # RFC 8224 §4 format:
    # signed-identity-digest;info=<absoluteURI>;alg=token;ppt=token
    return f"{passport_jwt};info=<{issuer_oobi}>;alg=EdDSA;ppt=vvp"
