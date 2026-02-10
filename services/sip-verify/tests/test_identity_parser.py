"""Tests for RFC 8224 Identity header parser.

Sprint 44: Tests for parsing SIP Identity header.
Sprint 57: Updated for RFC 8224 compliance — body is JWT directly,
info uses angle-bracketed URI.
"""

import pytest

from app.verify.identity_parser import (
    ParsedIdentityHeader,
    parse_identity_header,
    IdentityParseError,
)


class TestParseIdentityHeader:
    """Tests for parse_identity_header function."""

    def test_parse_rfc8224_format(self):
        """Parse RFC 8224 Identity header: JWT;info=<URI>;alg=EdDSA;ppt=vvp."""
        passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.sig"

        header = f"{passport};info=<https://witness.example.com/oobi/EAbc/witness>;alg=EdDSA;ppt=vvp"

        result = parse_identity_header(header)

        assert result.passport_jwt == passport
        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"
        assert result.algorithm == "EdDSA"
        assert result.ppt == "vvp"

    def test_parse_legacy_angle_bracket_body(self):
        """Parse legacy format with body in angle brackets."""
        passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.sig"

        header = f"<{passport}>;info=<https://witness.example.com/oobi/EAbc/witness>;alg=EdDSA;ppt=vvp"

        result = parse_identity_header(header)

        # Body is used directly as JWT (no base64url decode)
        assert result.passport_jwt == passport
        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"

    def test_parse_quoted_info(self):
        """Parse Identity header with quoted info parameter (legacy)."""
        passport = "test.payload.signature"

        header = f'{passport};info="https://witness.example.com/oobi/EAbc/witness";alg=EdDSA;ppt=vvp'

        result = parse_identity_header(header)

        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"

    def test_parse_bare_info(self):
        """Parse Identity header with unquoted info parameter (fallback)."""
        passport = "test.payload.signature"

        header = f"{passport};info=https://example.com/oobi;alg=EdDSA;ppt=vvp"

        result = parse_identity_header(header)

        assert result.info_url == "https://example.com/oobi"

    def test_parse_missing_ppt(self):
        """Parse Identity header without ppt parameter."""
        passport = "test.payload.signature"

        header = f"{passport};info=<https://example.com>;alg=EdDSA"

        result = parse_identity_header(header)

        assert result.ppt == ""  # Empty when not provided

    def test_parse_empty_header_raises(self):
        """Empty header should raise error."""
        with pytest.raises(IdentityParseError, match="Empty"):
            parse_identity_header("")

    def test_parse_empty_body_raises(self):
        """Empty body should raise error."""
        with pytest.raises(IdentityParseError, match="Empty|Malformed"):
            parse_identity_header("<>;info=https://example.com")

    def test_parse_unclosed_bracket_raises(self):
        """Unclosed angle bracket should raise error."""
        with pytest.raises(IdentityParseError, match="unclosed"):
            parse_identity_header("<body")

    def test_parse_url_encoded_info(self):
        """URL-encoded info parameter should be decoded."""
        passport = "test.payload.signature"

        header = f"{passport};info=https%3A%2F%2Fexample.com%2Fpath;alg=EdDSA"

        result = parse_identity_header(header)

        assert result.info_url == "https://example.com/path"

    def test_parse_whitespace_tolerance(self):
        """Parser should tolerate whitespace around semicolons."""
        passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.sig"

        header = f"{passport} ; info=<https://example.com/oobi> ; alg=EdDSA ; ppt=vvp"

        result = parse_identity_header(header)

        assert result.passport_jwt == passport
        assert result.info_url == "https://example.com/oobi"
        assert result.algorithm == "EdDSA"
        assert result.ppt == "vvp"


class TestParsedIdentityHeader:
    """Tests for ParsedIdentityHeader dataclass."""

    def test_dataclass_fields(self):
        """Verify dataclass has expected fields."""
        header = ParsedIdentityHeader(
            passport_jwt="jwt",
            info_url="https://example.com",
            algorithm="EdDSA",
            ppt="vvp",
            raw_body="encoded",
        )

        assert header.passport_jwt == "jwt"
        assert header.info_url == "https://example.com"
        assert header.algorithm == "EdDSA"
        assert header.ppt == "vvp"
        assert header.raw_body == "encoded"
