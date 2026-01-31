"""Tests for PSS CESR signature decoding.

Per VVP §6.3.1 - PASSporT signatures use CESR encoding.
"""

import pytest

from app.vvp.keri.cesr import decode_pss_signature
from app.vvp.keri.exceptions import ResolutionFailedError


class TestDecodePssSignature:
    """Tests for decode_pss_signature function."""

    def test_valid_0b_signature(self):
        """Test decoding valid 0B prefix signature."""
        # 0B prefix + 86 chars of base64url = 88 chars total
        # This is a placeholder signature (all A's = all zeros)
        cesr_sig = "0B" + "A" * 86

        result = decode_pss_signature(cesr_sig)

        assert len(result) == 64
        assert isinstance(result, bytes)

    def test_valid_0a_signature(self):
        """Test decoding valid 0A prefix signature."""
        cesr_sig = "0A" + "A" * 86

        result = decode_pss_signature(cesr_sig)

        assert len(result) == 64

    def test_valid_aa_signature(self):
        """Test decoding valid AA prefix (non-indexed) signature."""
        cesr_sig = "AA" + "A" * 86

        result = decode_pss_signature(cesr_sig)

        assert len(result) == 64

    def test_empty_signature_raises(self):
        """Test that empty signature raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError, match="Empty CESR signature"):
            decode_pss_signature("")

    def test_wrong_length_raises(self):
        """Test that wrong length signature raises."""
        # Too short
        with pytest.raises(ResolutionFailedError, match="Invalid CESR signature length"):
            decode_pss_signature("0B" + "A" * 80)

        # Too long
        with pytest.raises(ResolutionFailedError, match="Invalid CESR signature length"):
            decode_pss_signature("0B" + "A" * 90)

    def test_invalid_derivation_code_raises(self):
        """Test that invalid derivation code raises."""
        # XX is not a valid signature derivation code
        with pytest.raises(ResolutionFailedError, match="Invalid CESR signature derivation code"):
            decode_pss_signature("XX" + "A" * 86)

    def test_invalid_base64_raises(self):
        """Test that invalid base64 encoding raises."""
        # Use invalid base64 characters that will cause decode failure
        # Note: Some special chars might be silently ignored by lenient decoders
        # Use a pattern that will definitely produce wrong-length output
        with pytest.raises(ResolutionFailedError, match="Invalid"):
            decode_pss_signature("0B" + "=" * 86)  # All padding chars = invalid

    def test_real_signature_format(self):
        """Test with a realistic signature format."""
        # Generate a realistic-looking signature (random base64url chars)
        import base64
        import os

        # Create 64 random bytes
        raw_sig = os.urandom(64)

        # Encode to base64url without padding
        sig_b64 = base64.urlsafe_b64encode(raw_sig).decode().rstrip("=")

        # Should be 86 chars (64 bytes = 512 bits, ceil(512/6) = 86 base64 chars)
        # Actually 64 bytes -> 86 chars with CESR encoding rules
        # Let's use proper padding
        if len(sig_b64) < 86:
            sig_b64 = sig_b64 + "A" * (86 - len(sig_b64))
        elif len(sig_b64) > 86:
            sig_b64 = sig_b64[:86]

        cesr_sig = "0B" + sig_b64

        result = decode_pss_signature(cesr_sig)

        assert len(result) == 64
        assert isinstance(result, bytes)
