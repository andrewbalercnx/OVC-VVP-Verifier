"""Tests for SIP parser.

Sprint 44: Tests for shared SIP parser with verification header extraction.
"""

import pytest

from common.vvp.sip.parser import (
    parse_sip_request,
    normalize_tn,
    extract_tn_from_uri,
)


class TestNormalizeTN:
    """Tests for normalize_tn function."""

    def test_normalize_with_plus(self):
        """Phone number with + prefix stays normalized."""
        assert normalize_tn("+15551234567") == "+15551234567"

    def test_normalize_without_plus(self):
        """Phone number without + gets prefix added."""
        assert normalize_tn("15551234567") == "+15551234567"

    def test_normalize_with_dashes(self):
        """Phone number with dashes gets cleaned."""
        assert normalize_tn("1-555-123-4567") == "+15551234567"

    def test_normalize_with_spaces(self):
        """Phone number with spaces gets cleaned."""
        assert normalize_tn("1 555 123 4567") == "+15551234567"


class TestExtractTNFromUri:
    """Tests for extract_tn_from_uri function."""

    def test_sip_uri_with_plus(self):
        """Extract TN from SIP URI with +."""
        assert extract_tn_from_uri("sip:+15551234567@carrier.com") == "+15551234567"

    def test_sip_uri_without_plus(self):
        """Extract TN from SIP URI without +."""
        assert extract_tn_from_uri("sip:15551234567@carrier.com") == "+15551234567"

    def test_tel_uri(self):
        """Extract TN from tel: URI."""
        assert extract_tn_from_uri("tel:+15551234567") == "+15551234567"

    def test_sip_uri_with_params(self):
        """Extract TN from SIP URI with parameters."""
        assert extract_tn_from_uri("sip:+15551234567@carrier.com;tag=abc") == "+15551234567"

    def test_invalid_uri(self):
        """Return None for invalid URI."""
        assert extract_tn_from_uri("not-a-uri") is None

    def test_uri_without_tn(self):
        """Return None for URI without phone number."""
        assert extract_tn_from_uri("sip:alice@example.com") is None


class TestParseSIPRequest:
    """Tests for parse_sip_request function."""

    def test_parse_basic_invite(self):
        """Parse a basic SIP INVITE."""
        message = (
            b"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            b"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            b"To: <sip:+14155551234@pbx.example.com>\r\n"
            b"Call-ID: xyz789@carrier.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)

        assert request is not None
        assert request.method == "INVITE"
        assert request.is_invite is True
        assert request.from_tn == "+15551234567"
        assert request.to_tn == "+14155551234"
        assert request.call_id == "xyz789@carrier.com"
        assert request.cseq == "1 INVITE"
        assert len(request.via) == 1

    def test_parse_invite_with_api_key(self):
        """Parse INVITE with X-VVP-API-Key header (signing)."""
        message = (
            b"INVITE sip:+14155551234@carrier.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP enterprise.com:5060\r\n"
            b"From: <sip:+15551234567@enterprise.com>;tag=abc123\r\n"
            b"To: <sip:+14155551234@carrier.com>\r\n"
            b"Call-ID: xyz789@enterprise.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"X-VVP-API-Key: vvp_test_key_abc123\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)

        assert request is not None
        assert request.vvp_api_key == "vvp_test_key_abc123"
        assert request.has_signing_headers is True
        assert request.has_verification_headers is False

    def test_parse_invite_with_identity(self):
        """Parse INVITE with Identity header (verification)."""
        identity = "eyJhbGciOiJFZERTQSJ9.payload.sig;info=<https://oobi.example.com>;alg=EdDSA;ppt=vvp"
        message = (
            f"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            f"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            f"To: <sip:+14155551234@pbx.example.com>\r\n"
            f"Call-ID: xyz789@carrier.com\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Identity: {identity}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode()
        request = parse_sip_request(message)

        assert request is not None
        assert request.identity_header == identity
        assert request.has_verification_headers is True
        assert request.has_signing_headers is False

    def test_parse_invite_with_p_vvp_headers(self):
        """Parse INVITE with P-VVP-* headers (verification)."""
        vvp_identity = "eyJwcHQiOiJ2dnAiLCJraWQiOiJodHRwczovL29vYmkifQ=="
        vvp_passport = "eyJhbGciOiJFZERTQSJ9.payload.signature"
        message = (
            f"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            f"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            f"To: <sip:+14155551234@pbx.example.com>\r\n"
            f"Call-ID: xyz789@carrier.com\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"P-VVP-Identity: {vvp_identity}\r\n"
            f"P-VVP-Passport: {vvp_passport}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode()
        request = parse_sip_request(message)

        assert request is not None
        assert request.p_vvp_identity == vvp_identity
        assert request.p_vvp_passport == vvp_passport
        assert request.has_verification_headers is True

    def test_parse_invite_with_both_identity_and_p_vvp(self):
        """Parse INVITE with both Identity and P-VVP-* headers."""
        identity = "eyJhbGciOiJFZERTQSJ9.payload.sig;info=<https://oobi>;alg=EdDSA;ppt=vvp"
        vvp_identity = "eyJwcHQiOiJ2dnAifQ=="
        message = (
            f"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            f"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            f"To: <sip:+14155551234@pbx.example.com>\r\n"
            f"Call-ID: xyz789@carrier.com\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Identity: {identity}\r\n"
            f"P-VVP-Identity: {vvp_identity}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode()
        request = parse_sip_request(message)

        assert request is not None
        assert request.identity_header == identity
        assert request.p_vvp_identity == vvp_identity
        assert request.has_verification_headers is True

    def test_parse_multiple_via_headers(self):
        """Parse INVITE with multiple Via headers."""
        message = (
            b"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP proxy1.example.com:5060\r\n"
            b"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            b"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            b"To: <sip:+14155551234@pbx.example.com>\r\n"
            b"Call-ID: xyz789@carrier.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)

        assert request is not None
        assert len(request.via) == 2
        assert "proxy1.example.com" in request.via[0]
        assert "carrier.com" in request.via[1]

    def test_parse_missing_via(self):
        """Return None for INVITE missing Via header."""
        message = (
            b"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            b"From: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            b"To: <sip:+14155551234@pbx.example.com>\r\n"
            b"Call-ID: xyz789@carrier.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)
        assert request is None

    def test_parse_missing_from(self):
        """Return None for INVITE missing From header."""
        message = (
            b"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP carrier.com:5060\r\n"
            b"To: <sip:+14155551234@pbx.example.com>\r\n"
            b"Call-ID: xyz789@carrier.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)
        assert request is None

    def test_parse_invalid_request_line(self):
        """Return None for invalid request line."""
        message = b"INVALID REQUEST LINE\r\n\r\n"
        request = parse_sip_request(message)
        assert request is None

    def test_parse_empty_message(self):
        """Return None for empty message."""
        request = parse_sip_request(b"")
        assert request is None

    def test_parse_compact_headers(self):
        """Parse INVITE with compact header forms."""
        message = (
            b"INVITE sip:+14155551234@pbx.example.com SIP/2.0\r\n"
            b"v: SIP/2.0/UDP carrier.com:5060\r\n"
            b"f: <sip:+15551234567@carrier.com>;tag=abc123\r\n"
            b"t: <sip:+14155551234@pbx.example.com>\r\n"
            b"i: xyz789@carrier.com\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"l: 0\r\n"
            b"\r\n"
        )
        request = parse_sip_request(message)

        assert request is not None
        assert request.from_tn == "+15551234567"
        assert request.call_id == "xyz789@carrier.com"
        assert request.content_length == 0
