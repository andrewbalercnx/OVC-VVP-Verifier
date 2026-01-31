"""
Unit tests for Phase 2: VVP-Identity Header Parser
Per VVP_Verifier_Specification_v1.4_FINAL.md §4.1A, §4.1B, §4.2A
"""

import base64
import json
import time
from typing import Any

import pytest

from app.core.config import CLOCK_SKEW_SECONDS, MAX_TOKEN_AGE_SECONDS
from app.vvp.api_models import ErrorCode
from app.vvp.exceptions import VVPIdentityError
from app.vvp.header import VVPIdentity, parse_vvp_identity


def _encode_header(data: dict[str, Any]) -> str:
    """Helper to create a valid base64url-encoded header from a dict."""
    json_bytes = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")


def _valid_header_data(
    ppt: str = "shaken",
    kid: str = "oobi:example.com/keri/aid/123",
    evd: str = "oobi:example.com/dossier/456",
    iat: int | None = None,
    exp: int | None = None,
) -> dict[str, Any]:
    """Helper to create valid header data with defaults."""
    if iat is None:
        iat = int(time.time())
    data: dict[str, Any] = {"ppt": ppt, "kid": kid, "evd": evd, "iat": iat}
    if exp is not None:
        data["exp"] = exp
    return data


# =============================================================================
# Missing Header Tests (§4.2A: VVP_IDENTITY_MISSING)
# =============================================================================


class TestMissingHeader:
    """Tests for VVP_IDENTITY_MISSING error code per §4.2A"""

    def test_none_header(self):
        """None header yields VVP_IDENTITY_MISSING"""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(None)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_MISSING

    def test_empty_string_header(self):
        """Empty string header yields VVP_IDENTITY_MISSING"""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("")
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_MISSING

    def test_whitespace_only_header(self):
        """Whitespace-only header yields VVP_IDENTITY_MISSING"""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("   \t\n  ")
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_MISSING


# =============================================================================
# Valid Header Tests (§4.1A)
# =============================================================================


class TestValidHeader:
    """Tests for successful parsing of valid headers per §4.1A"""

    def test_valid_header_all_fields(self):
        """Valid header with all fields returns VVPIdentity"""
        now = int(time.time())
        data = _valid_header_data(iat=now, exp=now + 300)
        header = _encode_header(data)

        result = parse_vvp_identity(header)

        assert isinstance(result, VVPIdentity)
        assert result.ppt == "shaken"
        assert result.kid == "oobi:example.com/keri/aid/123"
        assert result.evd == "oobi:example.com/dossier/456"
        assert result.iat == now
        assert result.exp == now + 300

    def test_valid_header_without_exp(self):
        """Valid header without exp computes default expiry from iat"""
        now = int(time.time())
        data = _valid_header_data(iat=now)
        header = _encode_header(data)

        result = parse_vvp_identity(header)

        assert result.exp == now + MAX_TOKEN_AGE_SECONDS

    def test_ppt_any_string_value(self):
        """ppt field accepts any non-empty string (value validation deferred)"""
        for ppt_value in ["shaken", "vvp", "custom-profile", "x"]:
            data = _valid_header_data(ppt=ppt_value)
            header = _encode_header(data)

            result = parse_vvp_identity(header)
            assert result.ppt == ppt_value

    def test_kid_evd_opaque_oobi_references(self):
        """kid/evd accept any non-empty string (treated as opaque OOBIs)"""
        # Test various OOBI-like formats that should all be accepted
        test_cases = [
            ("oobi:example.com/aid/123", "oobi:example.com/dossier/456"),
            ("http://witness.example/oobi/EK...", "https://dossier.example/evd/..."),
            ("keri:aid:EKrV...", "cesr://example.com/evd"),
            ("anything", "anything-else"),  # Even non-URL formats
        ]
        for kid, evd in test_cases:
            data = _valid_header_data(kid=kid, evd=evd)
            header = _encode_header(data)

            result = parse_vvp_identity(header)
            assert result.kid == kid
            assert result.evd == evd

    def test_iat_in_future_within_skew(self):
        """iat slightly in the future (within clock skew) is accepted"""
        # iat 100 seconds in future, within 300s clock skew
        future_iat = int(time.time()) + 100
        data = _valid_header_data(iat=future_iat)
        header = _encode_header(data)

        result = parse_vvp_identity(header)
        assert result.iat == future_iat

    def test_iat_exactly_at_skew_boundary(self):
        """iat exactly at clock skew boundary is accepted"""
        boundary_iat = int(time.time()) + CLOCK_SKEW_SECONDS
        data = _valid_header_data(iat=boundary_iat)
        header = _encode_header(data)

        result = parse_vvp_identity(header)
        assert result.iat == boundary_iat

    def test_header_with_padding(self):
        """Base64url with explicit padding is accepted"""
        data = _valid_header_data()
        json_bytes = json.dumps(data).encode("utf-8")
        # Include padding explicitly
        header = base64.urlsafe_b64encode(json_bytes).decode("ascii")

        result = parse_vvp_identity(header)
        assert isinstance(result, VVPIdentity)

    def test_header_without_padding(self):
        """Base64url without padding is accepted"""
        data = _valid_header_data()
        json_bytes = json.dumps(data).encode("utf-8")
        # Strip padding
        header = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")

        result = parse_vvp_identity(header)
        assert isinstance(result, VVPIdentity)


# =============================================================================
# Invalid Header Tests (§4.2A: VVP_IDENTITY_INVALID)
# =============================================================================


class TestInvalidBase64:
    """Tests for base64/decode errors yielding VVP_IDENTITY_INVALID"""

    def test_garbage_input_yields_invalid(self):
        """Garbage input that doesn't decode to valid JSON yields VVP_IDENTITY_INVALID"""
        # Note: Python's base64 decoder is lenient with invalid characters,
        # so "invalid base64" may decode to garbage bytes that then fail JSON parsing
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("not-valid-base64!!!")
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID

    def test_truncated_base64(self):
        """Truncated base64 that decodes to incomplete UTF-8 yields VVP_IDENTITY_INVALID"""
        # Single byte that isn't valid UTF-8
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("_w")  # Decodes to 0xFF which is invalid UTF-8
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID


class TestInvalidJson:
    """Tests for JSON parse errors yielding VVP_IDENTITY_INVALID"""

    def test_invalid_json(self):
        """Invalid JSON yields VVP_IDENTITY_INVALID"""
        # Encode invalid JSON
        invalid_json = base64.urlsafe_b64encode(b"{not valid json}").decode("ascii")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(invalid_json)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "JSON parse failed" in exc_info.value.message

    def test_json_array_instead_of_object(self):
        """JSON array (not object) yields VVP_IDENTITY_INVALID"""
        array_json = base64.urlsafe_b64encode(b'["a", "b"]').decode("ascii")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(array_json)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "JSON root must be an object" in exc_info.value.message


class TestMissingFields:
    """Tests for missing required fields yielding VVP_IDENTITY_INVALID"""

    def test_missing_ppt(self):
        """Missing ppt field yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        del data["ppt"]
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "missing required field: ppt" in exc_info.value.message

    def test_missing_kid(self):
        """Missing kid field yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        del data["kid"]
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "missing required field: kid" in exc_info.value.message

    def test_missing_evd(self):
        """Missing evd field yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        del data["evd"]
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "missing required field: evd" in exc_info.value.message

    def test_missing_iat(self):
        """Missing iat field yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        del data["iat"]
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "missing required field: iat" in exc_info.value.message


class TestTypeValidation:
    """Tests for field type validation yielding VVP_IDENTITY_INVALID"""

    def test_ppt_not_string(self):
        """Non-string ppt yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["ppt"] = 123
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "ppt must be a string" in exc_info.value.message

    def test_kid_not_string(self):
        """Non-string kid yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["kid"] = 123
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "kid must be a string" in exc_info.value.message

    def test_evd_not_string(self):
        """Non-string evd yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["evd"] = ["array"]
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "evd must be a string" in exc_info.value.message

    def test_iat_not_integer(self):
        """Non-integer iat yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["iat"] = "not-an-integer"
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "iat must be an integer" in exc_info.value.message

    def test_iat_boolean_rejected(self):
        """Boolean iat (even True=1) yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["iat"] = True
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID

    def test_exp_not_integer(self):
        """Non-integer exp yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["exp"] = "not-an-integer"
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "exp must be an integer" in exc_info.value.message

    def test_iat_float_whole_number_accepted(self):
        """Float iat that is a whole number is accepted"""
        data = _valid_header_data()
        data["iat"] = 1737500000.0
        header = _encode_header(data)

        result = parse_vvp_identity(header)
        assert result.iat == 1737500000

    def test_exp_float_whole_number_accepted(self):
        """Float exp that is a whole number is accepted"""
        now = int(time.time())
        data = _valid_header_data(iat=now)
        data["exp"] = float(now + 300)
        header = _encode_header(data)

        result = parse_vvp_identity(header)
        assert result.exp == now + 300


class TestEmptyStringFields:
    """Tests for empty string fields yielding VVP_IDENTITY_INVALID"""

    def test_empty_ppt(self):
        """Empty string ppt yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["ppt"] = ""
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "ppt must not be empty" in exc_info.value.message

    def test_whitespace_only_ppt(self):
        """Whitespace-only ppt yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["ppt"] = "   "
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID

    def test_empty_kid(self):
        """Empty string kid yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["kid"] = ""
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "kid must not be empty" in exc_info.value.message

    def test_empty_evd(self):
        """Empty string evd yields VVP_IDENTITY_INVALID"""
        data = _valid_header_data()
        data["evd"] = ""
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "evd must not be empty" in exc_info.value.message


class TestIatValidation:
    """Tests for iat timestamp validation per §4.1A"""

    def test_iat_beyond_clock_skew(self):
        """iat beyond clock skew yields VVP_IDENTITY_INVALID"""
        # iat 400 seconds in future, beyond 300s clock skew
        future_iat = int(time.time()) + CLOCK_SKEW_SECONDS + 100
        data = _valid_header_data(iat=future_iat)
        header = _encode_header(data)

        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(header)
        assert exc_info.value.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "in the future beyond clock skew" in exc_info.value.message

    def test_iat_in_past_accepted(self):
        """iat in the past is accepted (expiry handled separately)"""
        past_iat = int(time.time()) - 1000
        data = _valid_header_data(iat=past_iat)
        header = _encode_header(data)

        result = parse_vvp_identity(header)
        assert result.iat == past_iat


# =============================================================================
# VVPIdentity Dataclass Tests
# =============================================================================


class TestVVPIdentityDataclass:
    """Tests for VVPIdentity dataclass properties"""

    def test_vvpidentity_is_frozen(self):
        """VVPIdentity instances are immutable"""
        data = _valid_header_data()
        header = _encode_header(data)
        result = parse_vvp_identity(header)

        with pytest.raises(AttributeError):
            result.ppt = "modified"  # type: ignore

    def test_vvpidentity_equality(self):
        """VVPIdentity instances with same values are equal"""
        data = _valid_header_data(iat=1737500000, exp=1737503600)
        header = _encode_header(data)

        result1 = parse_vvp_identity(header)
        result2 = parse_vvp_identity(header)

        assert result1 == result2


# =============================================================================
# VVPIdentityError Tests
# =============================================================================


class TestVVPIdentityError:
    """Tests for VVPIdentityError exception"""

    def test_error_has_code_and_message(self):
        """VVPIdentityError carries code and message"""
        error = VVPIdentityError(code="TEST_CODE", message="Test message")
        assert error.code == "TEST_CODE"
        assert error.message == "Test message"
        assert str(error) == "Test message"

    def test_missing_factory(self):
        """VVPIdentityError.missing() creates correct error"""
        error = VVPIdentityError.missing()
        assert error.code == ErrorCode.VVP_IDENTITY_MISSING
        assert "missing" in error.message.lower()

    def test_invalid_factory(self):
        """VVPIdentityError.invalid() creates correct error"""
        error = VVPIdentityError.invalid("test reason")
        assert error.code == ErrorCode.VVP_IDENTITY_INVALID
        assert "test reason" in error.message
