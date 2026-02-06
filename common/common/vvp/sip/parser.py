"""SIP message parser.

Sprint 44: RFC 3261 parser for INVITE handling.
Supports both signing (X-VVP-API-Key) and verification (Identity, P-VVP-*) headers.
"""

import logging
import re
from typing import Optional

from common.vvp.sip.models import SIPRequest

log = logging.getLogger(__name__)

# Regex patterns for SIP parsing
REQUEST_LINE_PATTERN = re.compile(r"^(\w+)\s+(.+?)\s+(SIP/[\d.]+)$")
HEADER_PATTERN = re.compile(r"^([^:]+):\s*(.*)$")

# Pattern to extract phone number from SIP URI
# Handles: sip:+15551234567@domain, sip:15551234567@domain, tel:+15551234567
TN_PATTERN = re.compile(r"(?:sip:|tel:)\+?(\d{10,15})(?:@|$|;)")


def normalize_tn(tn: str) -> str:
    """Normalize telephone number to E.164 format.

    Args:
        tn: Raw phone number (with or without +)

    Returns:
        E.164 format with leading +
    """
    # Remove any non-digit characters except leading +
    digits = re.sub(r"[^\d]", "", tn)

    # Add + prefix if not present
    if not tn.startswith("+"):
        return f"+{digits}"
    return f"+{digits}"


def extract_tn_from_uri(uri: str) -> Optional[str]:
    """Extract and normalize phone number from SIP/TEL URI.

    Args:
        uri: SIP or TEL URI (e.g., "sip:+15551234567@carrier.com")

    Returns:
        E.164 formatted phone number or None if not found
    """
    match = TN_PATTERN.search(uri.lower())
    if match:
        return normalize_tn(match.group(1))
    return None


def parse_sip_request(data: bytes) -> Optional[SIPRequest]:
    """Parse a SIP request from raw bytes.

    Extracts:
    - Request line (method, URI, version)
    - Transaction headers (Via, From, To, Call-ID, CSeq)
    - VVP signing header (X-VVP-API-Key)
    - VVP verification headers (Identity, P-VVP-Identity, P-VVP-Passport)
    - Phone numbers from From/To headers

    Args:
        data: Raw SIP message bytes

    Returns:
        SIPRequest if valid, None if malformed
    """
    try:
        # Decode message
        text = data.decode("utf-8", errors="replace")

        # Split into lines
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines:
            log.warning("Empty SIP message")
            return None

        # Parse request line
        request_line = lines[0].strip()
        match = REQUEST_LINE_PATTERN.match(request_line)
        if not match:
            log.warning(f"Invalid request line: {request_line[:50]}")
            return None

        method, request_uri, sip_version = match.groups()

        # Initialize request
        request = SIPRequest(
            method=method,
            request_uri=request_uri,
            sip_version=sip_version,
            raw=data,
        )

        # Parse headers
        via_headers = []
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break  # End of headers

            match = HEADER_PATTERN.match(line)
            if not match:
                continue

            name = match.group(1).lower()
            value = match.group(2)

            # Standard SIP headers (RFC 3261)
            if name == "via" or name == "v":
                via_headers.append(value)
            elif name == "from" or name == "f":
                request.from_header = value
                request.from_tn = extract_tn_from_uri(value)
            elif name == "to" or name == "t":
                request.to_header = value
                request.to_tn = extract_tn_from_uri(value)
            elif name == "call-id" or name == "i":
                request.call_id = value
            elif name == "cseq":
                request.cseq = value
            elif name == "contact" or name == "m":
                request.contact = value
            elif name == "content-length" or name == "l":
                try:
                    request.content_length = int(value)
                except ValueError:
                    pass

            # VVP signing header (Sprint 42)
            elif name == "x-vvp-api-key":
                request.vvp_api_key = value

            # VVP verification headers (Sprint 44)
            elif name == "identity":
                request.identity_header = value
            elif name == "p-vvp-identity":
                request.p_vvp_identity = value
            elif name == "p-vvp-passport":
                request.p_vvp_passport = value

        request.via = via_headers

        # Validate required headers
        if not request.via:
            log.warning(f"Missing Via header in {method} request")
            return None
        if not request.from_header:
            log.warning(f"Missing From header in {method} request")
            return None
        if not request.to_header:
            log.warning(f"Missing To header in {method} request")
            return None
        if not request.call_id:
            log.warning(f"Missing Call-ID header in {method} request")
            return None
        if not request.cseq:
            log.warning(f"Missing CSeq header in {method} request")
            return None

        log.debug(
            f"Parsed {method} request: from={request.from_tn} to={request.to_tn} "
            f"call_id={request.call_id[:16]}... "
            f"verify_headers={request.has_verification_headers} "
            f"sign_headers={request.has_signing_headers}"
        )
        return request

    except Exception as e:
        log.error(f"Failed to parse SIP request: {e}")
        return None
