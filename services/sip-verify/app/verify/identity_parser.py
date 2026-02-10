"""RFC 8224 Identity header parser.

Sprint 44: Parses the SIP Identity header per RFC 8224 to extract
the PASSporT JWT and header parameters.

Sprint 57: Fixed to comply with RFC 8224 §4 ABNF:
- Body is the PASSporT compact JWS directly (no base64url wrapper)
- info parameter uses angle-bracketed URI: info=<URI>
- Also accepts legacy quoted-string info for backwards compatibility

RFC 8224 §4 ABNF:
    signed-identity-digest SEMI ident-info *(SEMI ident-info-params)
    signed-identity-digest = 1*(base64-char / ".")
    ident-info = "info" EQUAL LAQUOT absoluteURI RAQUOT
    ident-info-alg = "alg" EQUAL token
    ident-type = "ppt" EQUAL token

Example:
    Identity: eyJhbGci...sig;info=<https://witness.example.com/oobi/AID/controller>;alg=EdDSA;ppt=vvp
"""

import logging
import re
from dataclasses import dataclass
from urllib.parse import unquote

log = logging.getLogger(__name__)


class IdentityParseError(Exception):
    """Error parsing Identity header."""

    pass


@dataclass
class ParsedIdentityHeader:
    """Parsed RFC 8224 Identity header.

    Attributes:
        passport_jwt: PASSporT compact JWS string (header.payload.signature).
        info_url: OOBI URL from info parameter.
        algorithm: Signing algorithm (EdDSA for VVP).
        ppt: PASSporT type (vvp).
        raw_body: Original body string from the header.
    """

    passport_jwt: str
    info_url: str
    algorithm: str
    ppt: str
    raw_body: str


def parse_identity_header(header_value: str) -> ParsedIdentityHeader:
    """Parse RFC 8224 Identity header.

    Per RFC 8224 §4:
    - Body is the PASSporT compact JWS (header.payload.signature)
    - info parameter: angle-bracketed URI (info=<URI>)
    - alg parameter: plain token
    - ppt parameter: plain token

    Accepts both RFC 8224 format (body without angle brackets) and
    legacy format (body in angle brackets) for backwards compatibility.

    Args:
        header_value: Raw Identity header value

    Returns:
        ParsedIdentityHeader with extracted fields

    Raises:
        IdentityParseError: If parsing fails
    """
    if not header_value:
        raise IdentityParseError("Empty Identity header")

    header_value = header_value.strip()

    # Extract body — accept both formats for backwards compatibility
    if header_value.startswith("<"):
        # Legacy format: <body>;params (body in angle brackets)
        match = re.match(r"<([^>]+)>(.*)$", header_value)
        if not match:
            raise IdentityParseError("Malformed Identity header: unclosed angle bracket")
        raw_body = match.group(1)
        params_str = match.group(2)
    else:
        # RFC 8224 format: body;params (body is the compact JWS directly)
        parts = header_value.split(";", 1)
        raw_body = parts[0].strip()
        params_str = ";" + parts[1] if len(parts) > 1 else ""

    if not raw_body:
        raise IdentityParseError("Empty Identity body")

    # The body IS the PASSporT compact JWS (no base64url decode needed)
    passport_jwt = raw_body

    # Parse parameters — accept both angle-bracketed and quoted-string info
    params = {}
    if params_str:
        # Match info=<URI> (RFC 8224 standard)
        # Allow optional whitespace around ; per SIP header folding rules
        info_angle_match = re.search(r";\s*info=<([^>]+)>", params_str, re.IGNORECASE)
        if info_angle_match:
            params["info"] = info_angle_match.group(1)

        # Match info="URI" (legacy quoted-string)
        if "info" not in params:
            info_quoted_match = re.search(r';\s*info="([^"]+)"', params_str, re.IGNORECASE)
            if info_quoted_match:
                params["info"] = unquote(info_quoted_match.group(1))

        # Match info=URI (unquoted fallback)
        if "info" not in params:
            info_bare_match = re.search(
                r";\s*info=([^;<>\"]+)", params_str, re.IGNORECASE
            )
            if info_bare_match:
                params["info"] = unquote(info_bare_match.group(1).strip())

        # Match alg and ppt (always plain tokens)
        alg_match = re.search(r";\s*alg=([^;]+)", params_str, re.IGNORECASE)
        if alg_match:
            params["alg"] = alg_match.group(1).strip()

        ppt_match = re.search(r";\s*ppt=([^;]+)", params_str, re.IGNORECASE)
        if ppt_match:
            params["ppt"] = ppt_match.group(1).strip()

    # Extract required parameters
    info_url = params.get("info", "")
    algorithm = params.get("alg", "EdDSA")
    ppt = params.get("ppt", "")

    # Validate VVP requirements
    if not info_url:
        log.warning("Identity header missing info parameter (OOBI URL)")

    if algorithm.upper() not in ("EDDSA", "ED25519"):
        log.warning(f"Identity header has non-EdDSA algorithm: {algorithm}")

    if ppt.lower() != "vvp":
        log.warning(f"Identity header has non-VVP ppt: {ppt}")

    return ParsedIdentityHeader(
        passport_jwt=passport_jwt,
        info_url=info_url,
        algorithm=algorithm,
        ppt=ppt,
        raw_body=raw_body,
    )
