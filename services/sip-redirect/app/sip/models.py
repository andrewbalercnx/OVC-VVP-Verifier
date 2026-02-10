"""SIP protocol data models.

Sprint 42: Dataclasses for SIP requests and responses.
Sprint 47: Added headers dict and source_addr for monitoring dashboard.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SIPRequest:
    """Parsed SIP INVITE request.

    Extracts the essential information needed for VVP redirect:
    - Telephone numbers from From/To URIs
    - Authentication via X-VVP-API-Key header
    - Transaction headers for response (Via, From, To, Call-ID, CSeq)
    """

    method: str
    request_uri: str
    sip_version: str = "SIP/2.0"

    # Required transaction headers (RFC 3261)
    via: list[str] = field(default_factory=list)
    from_header: str = ""
    to_header: str = ""
    call_id: str = ""
    cseq: str = ""

    # Extracted telephone numbers (E.164 normalized)
    from_tn: Optional[str] = None
    to_tn: Optional[str] = None

    # VVP-specific header
    vvp_api_key: Optional[str] = None

    # Optional headers
    contact: Optional[str] = None
    content_length: int = 0

    # All headers dict (Sprint 47: for monitoring dashboard)
    headers: dict = field(default_factory=dict)

    # Source address (Sprint 47: for monitoring dashboard)
    source_addr: Optional[str] = None

    # Raw message for debugging
    raw: bytes = b""

    @property
    def is_invite(self) -> bool:
        """Check if this is an INVITE request."""
        return self.method.upper() == "INVITE"


@dataclass
class SIPResponse:
    """SIP response for redirect.

    RFC 3261 requires copying these headers from request:
    - Via (all headers, in order)
    - From (exactly as received)
    - To (with tag added if not present)
    - Call-ID (exactly as received)
    - CSeq (exactly as received)
    """

    status_code: int
    reason_phrase: str
    sip_version: str = "SIP/2.0"

    # Required headers (copied from request)
    via: list[str] = field(default_factory=list)
    from_header: str = ""
    to_header: str = ""
    call_id: str = ""
    cseq: str = ""

    # Response-specific headers
    contact: Optional[str] = None

    # RFC 8224 Identity header (Sprint 57: STIR compliance)
    identity: Optional[str] = None

    # VVP headers for 302 redirect
    vvp_identity: Optional[str] = None
    vvp_passport: Optional[str] = None
    vvp_status: Optional[str] = None    # VALID | INVALID | INDETERMINATE
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None

    # Error reason (for non-2xx responses)
    error_reason: Optional[str] = None

    def to_bytes(self) -> bytes:
        """Serialize response to SIP message bytes."""
        lines = []

        # Status line
        lines.append(f"{self.sip_version} {self.status_code} {self.reason_phrase}")

        # Required headers (copied from request per RFC 3261)
        for via in self.via:
            lines.append(f"Via: {via}")
        lines.append(f"From: {self.from_header}")
        lines.append(f"To: {self.to_header}")
        lines.append(f"Call-ID: {self.call_id}")
        lines.append(f"CSeq: {self.cseq}")

        # Response-specific headers
        if self.contact:
            lines.append(f"Contact: {self.contact}")

        # RFC 8224 Identity header (Sprint 57)
        if self.identity:
            lines.append(f"Identity: {self.identity}")

        # VVP headers for 302 redirect
        if self.vvp_identity:
            lines.append(f"P-VVP-Identity: {self.vvp_identity}")
        if self.vvp_passport:
            lines.append(f"P-VVP-Passport: {self.vvp_passport}")
        if self.brand_name:
            lines.append(f"X-VVP-Brand-Name: {self.brand_name}")
        if self.brand_logo_url:
            lines.append(f"X-VVP-Brand-Logo: {self.brand_logo_url}")
        if self.vvp_status:
            lines.append(f"X-VVP-Status: {self.vvp_status}")

        # Content-Length (always 0 for redirects)
        lines.append("Content-Length: 0")

        # End headers
        lines.append("")
        lines.append("")

        return "\r\n".join(lines).encode("utf-8")
