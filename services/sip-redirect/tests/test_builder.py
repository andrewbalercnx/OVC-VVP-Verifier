"""Tests for SIP response builder.

Sprint 42: Tests for SIP response building with RFC 3261 compliance.
"""

import pytest

from app.sip.models import SIPRequest, SIPResponse
from app.sip.builder import (
    build_302_redirect,
    build_401_unauthorized,
    build_403_forbidden,
    build_404_not_found,
    build_500_error,
)


@pytest.fixture
def sample_request():
    """Create a sample SIP INVITE request."""
    return SIPRequest(
        method="INVITE",
        request_uri="sip:+14445678901@carrier.com",
        sip_version="SIP/2.0",
        via=["SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhds"],
        from_header="<sip:+15551234567@enterprise.com>;tag=1928301774",
        to_header="<sip:+14445678901@carrier.com>",
        call_id="a84b4c76e66710@enterprise.com",
        cseq="314159 INVITE",
        from_tn="+15551234567",
        to_tn="+14445678901",
        vvp_api_key="test-api-key",
    )


class TestBuild302Redirect:
    """Test 302 Moved Temporarily response builder."""

    def test_basic_redirect(self, sample_request):
        """Test basic 302 redirect response."""
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            vvp_identity="base64url-identity",
            vvp_passport="eyJhbGciOiJFZERTQSJ9...",
        )

        assert response.status_code == 302
        assert response.reason_phrase == "Moved Temporarily"
        assert response.vvp_identity == "base64url-identity"
        assert response.vvp_passport == "eyJhbGciOiJFZERTQSJ9..."

    def test_copies_transaction_headers(self, sample_request):
        """Test that transaction headers are copied from request."""
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            vvp_identity="identity",
            vvp_passport="passport",
        )

        # Via should be copied exactly
        assert response.via == sample_request.via
        # From should be copied exactly
        assert response.from_header == sample_request.from_header
        # To should have tag added
        assert sample_request.to_header in response.to_header
        assert ";tag=" in response.to_header
        # Call-ID and CSeq should match
        assert response.call_id == sample_request.call_id
        assert response.cseq == sample_request.cseq

    def test_no_xvvp_headers_in_signing_302(self, sample_request):
        """Signing 302 must NOT include X-VVP brand/status headers.

        Brand name, logo, and status are set exclusively by the
        verification service — not the signing service.
        """
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            vvp_identity="identity",
            vvp_passport="passport",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert "X-VVP-Brand-Name:" not in text
        assert "X-VVP-Brand-Logo:" not in text
        assert "X-VVP-Status:" not in text

    def test_serialization(self, sample_request):
        """Test response serializes correctly."""
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            vvp_identity="test-identity",
            vvp_passport="test-passport",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        # Check status line
        assert text.startswith("SIP/2.0 302 Moved Temporarily\r\n")
        # Check required headers
        assert "Via: SIP/2.0/UDP 192.168.1.1:5060" in text
        assert "From: <sip:+15551234567@enterprise.com>" in text
        assert "To: <sip:+14445678901@carrier.com>" in text
        assert "Call-ID: a84b4c76e66710@enterprise.com\r\n" in text
        assert "CSeq: 314159 INVITE\r\n" in text
        # Check STIR attestation headers
        assert "P-VVP-Identity: test-identity\r\n" in text
        assert "P-VVP-Passport: test-passport\r\n" in text
        # Must NOT include X-VVP headers
        assert "X-VVP-Status:" not in text
        assert "X-VVP-Brand-Name:" not in text
        assert "X-VVP-Brand-Logo:" not in text

    def test_identity_header_in_serialization(self, sample_request):
        """Sprint 57: Test Identity header appears in serialized response."""
        identity_value = "eyJhbGci.payload.sig;info=<https://w.example.com/oobi/AID/controller>;alg=EdDSA;ppt=vvp"
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            identity=identity_value,
            vvp_identity="test-identity",
            vvp_passport="test-passport",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert f"Identity: {identity_value}\r\n" in text

    def test_identity_header_absent_when_none(self, sample_request):
        """Sprint 57: Test Identity header absent when not provided."""
        response = build_302_redirect(
            request=sample_request,
            contact_uri="sip:+14445678901@carrier.com",
            vvp_identity="test-identity",
            vvp_passport="test-passport",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        # Use \r\nIdentity: to avoid matching P-VVP-Identity:
        assert "\r\nIdentity: " not in text


class TestBuild401Unauthorized:
    """Test 401 Unauthorized response builder."""

    def test_unauthorized_response(self, sample_request):
        """Test 401 response with error reason."""
        response = build_401_unauthorized(
            request=sample_request,
            reason="Invalid API key",
        )

        assert response.status_code == 401
        assert response.reason_phrase == "Unauthorized"
        assert response.vvp_status == "INVALID"
        assert response.error_reason == "Invalid API key"

    def test_copies_headers(self, sample_request):
        """Test transaction headers are copied."""
        response = build_401_unauthorized(sample_request, "test")

        assert response.via == sample_request.via
        assert response.call_id == sample_request.call_id
        assert response.cseq == sample_request.cseq


class TestBuild403Forbidden:
    """Test 403 Forbidden response builder."""

    def test_forbidden_response(self, sample_request):
        """Test 403 response."""
        response = build_403_forbidden(
            request=sample_request,
            reason="Rate limit exceeded",
        )

        assert response.status_code == 403
        assert response.reason_phrase == "Forbidden"
        assert response.vvp_status == "INVALID"


class TestBuild404NotFound:
    """Test 404 Not Found response builder."""

    def test_not_found_response(self, sample_request):
        """Test 404 response."""
        response = build_404_not_found(
            request=sample_request,
            reason="No mapping for TN",
        )

        assert response.status_code == 404
        assert response.reason_phrase == "Not Found"
        assert response.vvp_status == "INVALID"


class TestBuild500Error:
    """Test 500 Server Internal Error response builder."""

    def test_error_response(self, sample_request):
        """Test 500 response with INDETERMINATE status."""
        response = build_500_error(
            request=sample_request,
            reason="Database connection failed",
        )

        assert response.status_code == 500
        assert response.reason_phrase == "Server Internal Error"
        assert response.vvp_status == "INDETERMINATE"

    def test_always_includes_vvp_status(self, sample_request):
        """Test VVP status is always present."""
        response = build_500_error(sample_request, "error")
        data = response.to_bytes().decode("utf-8")
        assert "X-VVP-Status: INDETERMINATE\r\n" in data
