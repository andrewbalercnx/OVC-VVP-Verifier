"""Pre-built SIP messages for testing.

Sprint 42: Ready-to-use SIP INVITE messages for various test scenarios.
"""

from tests.fixtures.credentials import (
    TEST_TN,
    TEST_API_KEY,
    ACME_CORP,
)


def build_invite(
    from_tn: str = TEST_TN,
    to_tn: str = "+442071234567",
    api_key: str | None = TEST_API_KEY,
    call_id: str = "test-call-id-12345@enterprise.com",
    via_host: str = "192.168.1.100",
    via_port: int = 5060,
) -> bytes:
    """Build a SIP INVITE message for testing.

    Args:
        from_tn: Originating telephone number (E.164)
        to_tn: Destination telephone number (E.164)
        api_key: VVP API key (None to omit header)
        call_id: SIP Call-ID
        via_host: Via header host
        via_port: Via header port

    Returns:
        Complete SIP INVITE message as bytes
    """
    headers = [
        f"INVITE sip:{to_tn}@carrier.example.com SIP/2.0",
        f"Via: SIP/2.0/UDP {via_host}:{via_port};branch=z9hG4bK776asdhds",
        f"From: <sip:{from_tn}@enterprise.example.com>;tag=1928301774",
        f"To: <sip:{to_tn}@carrier.example.com>",
        f"Call-ID: {call_id}",
        "CSeq: 314159 INVITE",
        f"Contact: <sip:{via_host}:{via_port}>",
        "Content-Type: application/sdp",
        "Content-Length: 0",
    ]

    if api_key:
        headers.append(f"X-VVP-API-Key: {api_key}")

    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")


# =============================================================================
# Pre-built Test Messages
# =============================================================================

# Valid INVITE with API key for Acme Corp extension 1001
VALID_INVITE_EXT_1001 = build_invite(
    from_tn=TEST_TN,
    to_tn="+442071234567",
    api_key=TEST_API_KEY,
    call_id="acme-ext-1001-call@acme.example.com",
)

# INVITE without API key (should get 401)
INVITE_NO_API_KEY = build_invite(
    from_tn=TEST_TN,
    to_tn="+442071234567",
    api_key=None,
    call_id="no-auth-call@test.example.com",
)

# INVITE with invalid API key (should get 401)
INVITE_INVALID_API_KEY = build_invite(
    from_tn=TEST_TN,
    to_tn="+442071234567",
    api_key="invalid_api_key_does_not_exist",
    call_id="bad-auth-call@test.example.com",
)

# INVITE with unmapped TN (should get 404)
INVITE_UNMAPPED_TN = build_invite(
    from_tn="+19999999999",  # Not in any mapping
    to_tn="+442071234567",
    api_key=TEST_API_KEY,
    call_id="unmapped-tn-call@test.example.com",
)

# INVITE with TN that doesn't belong to the org (should get 403 or 404)
INVITE_WRONG_ORG_TN = build_invite(
    from_tn="+12025551234",  # Belongs to different org
    to_tn="+442071234567",
    api_key=TEST_API_KEY,
    call_id="wrong-org-call@test.example.com",
)


def build_many_invites(count: int, base_call_id: str = "burst-test") -> list[bytes]:
    """Build many INVITE messages for rate limit testing.

    Args:
        count: Number of messages to generate
        base_call_id: Base call ID (will be suffixed with index)

    Returns:
        List of SIP INVITE messages
    """
    return [
        build_invite(
            from_tn=TEST_TN,
            to_tn="+442071234567",
            api_key=TEST_API_KEY,
            call_id=f"{base_call_id}-{i}@burst.example.com",
        )
        for i in range(count)
    ]


# =============================================================================
# Expected Responses
# =============================================================================

def expected_302_headers() -> dict:
    """Get expected headers for successful 302 response."""
    return {
        "P-VVP-Identity": True,  # Should be present
        "P-VVP-Passport": True,  # Should be present
        "X-VVP-Brand-Name": ACME_CORP["name"],
        "X-VVP-Status": "VALID",
        "Contact": True,  # Should be present
    }


def expected_401_headers() -> dict:
    """Get expected headers for 401 response."""
    return {
        "X-VVP-Status": "INVALID",
    }


def expected_403_headers() -> dict:
    """Get expected headers for 403 response."""
    return {
        "X-VVP-Status": "INVALID",
    }


def expected_404_headers() -> dict:
    """Get expected headers for 404 response."""
    return {
        "X-VVP-Status": "INVALID",
    }
