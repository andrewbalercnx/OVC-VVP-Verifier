"""Tests for SIP parser.

Sprint 42: Tests for SIP message parsing.
"""

import pytest

from app.sip.parser import parse_sip_request, extract_tn_from_uri, normalize_tn


class TestNormalizeTN:
    """Test TN normalization."""

    def test_with_plus(self):
        """Test TN with + prefix."""
        assert normalize_tn("+15551234567") == "+15551234567"

    def test_without_plus(self):
        """Test TN without + prefix."""
        assert normalize_tn("15551234567") == "+15551234567"


class TestExtractTNFromURI:
    """Test TN extraction from SIP/TEL URIs."""

    def test_sip_uri_with_plus(self):
        """Test extraction from sip: URI with +."""
        result = extract_tn_from_uri("sip:+15551234567@carrier.com")
        assert result == "+15551234567"

    def test_sip_uri_without_plus(self):
        """Test extraction from sip: URI without +."""
        result = extract_tn_from_uri("sip:15551234567@carrier.com")
        assert result == "+15551234567"

    def test_tel_uri(self):
        """Test extraction from tel: URI."""
        result = extract_tn_from_uri("tel:+15551234567")
        assert result == "+15551234567"

    def test_sip_uri_with_params(self):
        """Test extraction from sip: URI with params."""
        result = extract_tn_from_uri("sip:+15551234567@carrier.com;user=phone")
        assert result == "+15551234567"

    def test_invalid_uri(self):
        """Test extraction from invalid URI."""
        result = extract_tn_from_uri("invalid:uri")
        assert result is None


class TestParseSIPRequest:
    """Test SIP request parsing."""

    def test_valid_invite(self):
        """Test parsing a valid INVITE request."""
        message = (
            b"INVITE sip:+14445678901@carrier.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhds\r\n"
            b"From: <sip:+15551234567@enterprise.com>;tag=1928301774\r\n"
            b"To: <sip:+14445678901@carrier.com>\r\n"
            b"Call-ID: a84b4c76e66710@enterprise.com\r\n"
            b"CSeq: 314159 INVITE\r\n"
            b"Contact: <sip:192.168.1.1:5060>\r\n"
            b"Content-Length: 0\r\n"
            b"X-VVP-API-Key: test-api-key-12345\r\n"
            b"\r\n"
        )

        request = parse_sip_request(message)

        assert request is not None
        assert request.method == "INVITE"
        assert request.is_invite is True
        assert request.request_uri == "sip:+14445678901@carrier.com"
        assert request.sip_version == "SIP/2.0"
        assert len(request.via) == 1
        assert "branch=z9hG4bK776asdhds" in request.via[0]
        assert request.from_tn == "+15551234567"
        assert request.to_tn == "+14445678901"
        assert request.call_id == "a84b4c76e66710@enterprise.com"
        assert request.cseq == "314159 INVITE"
        assert request.vvp_api_key == "test-api-key-12345"
        assert request.content_length == 0

    def test_multiple_via_headers(self):
        """Test parsing request with multiple Via headers."""
        message = (
            b"INVITE sip:+14445678901@carrier.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP proxy.carrier.com:5060;branch=z9hG4bK7890\r\n"
            b"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1234\r\n"
            b"From: <sip:+15551234567@enterprise.com>;tag=abc123\r\n"
            b"To: <sip:+14445678901@carrier.com>\r\n"
            b"Call-ID: test-call-id\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        request = parse_sip_request(message)

        assert request is not None
        assert len(request.via) == 2
        assert "proxy.carrier.com" in request.via[0]
        assert "192.168.1.1" in request.via[1]

    def test_missing_via(self):
        """Test parsing fails without Via header."""
        message = (
            b"INVITE sip:+14445678901@carrier.com SIP/2.0\r\n"
            b"From: <sip:+15551234567@enterprise.com>;tag=abc123\r\n"
            b"To: <sip:+14445678901@carrier.com>\r\n"
            b"Call-ID: test-call-id\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )

        request = parse_sip_request(message)
        assert request is None

    def test_missing_from(self):
        """Test parsing fails without From header."""
        message = (
            b"INVITE sip:+14445678901@carrier.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1234\r\n"
            b"To: <sip:+14445678901@carrier.com>\r\n"
            b"Call-ID: test-call-id\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )

        request = parse_sip_request(message)
        assert request is None

    def test_compact_headers(self):
        """Test parsing with compact header names."""
        message = (
            b"INVITE sip:+14445678901@carrier.com SIP/2.0\r\n"
            b"v: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1234\r\n"
            b"f: <sip:+15551234567@enterprise.com>;tag=abc123\r\n"
            b"t: <sip:+14445678901@carrier.com>\r\n"
            b"i: compact-call-id\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"l: 0\r\n"
            b"\r\n"
        )

        request = parse_sip_request(message)

        assert request is not None
        assert len(request.via) == 1
        assert request.from_tn == "+15551234567"
        assert request.to_tn == "+14445678901"
        assert request.call_id == "compact-call-id"
        assert request.content_length == 0

    def test_invalid_request_line(self):
        """Test parsing fails with invalid request line."""
        message = b"INVALID LINE\r\n\r\n"
        request = parse_sip_request(message)
        assert request is None

    def test_empty_message(self):
        """Test parsing fails with empty message."""
        request = parse_sip_request(b"")
        assert request is None
