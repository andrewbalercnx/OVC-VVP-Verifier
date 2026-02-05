"""Tests for VVP-Identity header creation."""

import base64
import json
import time

import pytest

from app.vvp.header import (
    create_vvp_identity_header,
    MAX_VALIDITY_SECONDS,
    VVPIdentityHeader,
)
from app.vvp.oobi import build_issuer_oobi, build_dossier_url


class TestBuildIssuerOobi:
    """Tests for OOBI URL construction."""

    def test_basic_oobi(self):
        """Test basic OOBI URL construction."""
        aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        witness_url = "http://localhost:5642"

        result = build_issuer_oobi(aid, witness_url)

        assert result == "http://localhost:5642/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao/controller"

    def test_oobi_strips_trailing_slash(self):
        """Test OOBI URL strips trailing slash from witness URL."""
        aid = "EBfdlu8R27Fbx"
        witness_url = "http://localhost:5642/"

        result = build_issuer_oobi(aid, witness_url)

        assert result == "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"

    def test_oobi_with_https(self):
        """Test OOBI URL with HTTPS witness."""
        aid = "EBfdlu8R27Fbx"
        witness_url = "https://witness.example.com"

        result = build_issuer_oobi(aid, witness_url)

        assert result == "https://witness.example.com/oobi/EBfdlu8R27Fbx/controller"


class TestBuildDossierUrl:
    """Tests for dossier URL construction."""

    def test_basic_dossier_url(self):
        """Test basic dossier URL construction."""
        said = "EAbcdef123456"
        base_url = "https://issuer.example.com"

        result = build_dossier_url(said, base_url)

        assert result == "https://issuer.example.com/dossier/EAbcdef123456"

    def test_dossier_url_strips_trailing_slash(self):
        """Test dossier URL strips trailing slash."""
        said = "EAbcdef123456"
        base_url = "https://issuer.example.com/"

        result = build_dossier_url(said, base_url)

        assert result == "https://issuer.example.com/dossier/EAbcdef123456"


class TestCreateVVPIdentityHeader:
    """Tests for VVP-Identity header creation."""

    def test_creates_valid_header(self):
        """Test creating a valid VVP-Identity header."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"

        header = create_vvp_identity_header(issuer_oobi, dossier_url)

        assert isinstance(header, VVPIdentityHeader)
        assert header.ppt == "vvp"
        assert header.kid == issuer_oobi
        assert header.evd == dossier_url
        assert header.iat > 0
        assert header.exp > header.iat

    def test_header_is_base64url_encoded_json(self):
        """Test that encoded header is valid base64url JSON."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"

        header = create_vvp_identity_header(issuer_oobi, dossier_url)

        # Decode and verify
        padded = header.encoded + "=" * (-len(header.encoded) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        data = json.loads(decoded)

        assert data["ppt"] == "vvp"
        assert data["kid"] == issuer_oobi
        assert data["evd"] == dossier_url
        assert "iat" in data
        assert "exp" in data

    def test_uses_provided_iat(self):
        """Test that provided iat is used."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"
        custom_iat = 1700000000

        header = create_vvp_identity_header(
            issuer_oobi, dossier_url, iat=custom_iat
        )

        assert header.iat == custom_iat

    def test_exp_defaults_to_iat_plus_300(self):
        """Test that exp defaults to iat + 300 seconds."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"
        custom_iat = 1700000000

        header = create_vvp_identity_header(
            issuer_oobi, dossier_url, iat=custom_iat, exp_seconds=300
        )

        assert header.exp == custom_iat + 300

    def test_exp_capped_at_max_validity(self):
        """Test that exp_seconds is capped at MAX_VALIDITY_SECONDS (300)."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"
        custom_iat = 1700000000

        # Request 600 seconds, should be capped at 300
        header = create_vvp_identity_header(
            issuer_oobi, dossier_url, iat=custom_iat, exp_seconds=600
        )

        assert header.exp == custom_iat + MAX_VALIDITY_SECONDS
        assert header.exp == custom_iat + 300

    def test_shorter_exp_allowed(self):
        """Test that exp_seconds shorter than 300 is allowed."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"
        custom_iat = 1700000000

        header = create_vvp_identity_header(
            issuer_oobi, dossier_url, iat=custom_iat, exp_seconds=60
        )

        assert header.exp == custom_iat + 60

    def test_empty_issuer_oobi_raises(self):
        """Test that empty issuer_oobi raises ValueError."""
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"

        with pytest.raises(ValueError, match="issuer_oobi must not be empty"):
            create_vvp_identity_header("", dossier_url)

    def test_empty_dossier_url_raises(self):
        """Test that empty dossier_url raises ValueError."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"

        with pytest.raises(ValueError, match="dossier_url must not be empty"):
            create_vvp_identity_header(issuer_oobi, "")

    def test_whitespace_only_raises(self):
        """Test that whitespace-only values raise ValueError."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"

        with pytest.raises(ValueError):
            create_vvp_identity_header("   ", dossier_url)

        with pytest.raises(ValueError):
            create_vvp_identity_header(issuer_oobi, "   ")

    def test_default_iat_is_current_time(self):
        """Test that default iat is approximately current time."""
        issuer_oobi = "http://localhost:5642/oobi/EBfdlu8R27Fbx/controller"
        dossier_url = "https://issuer.example.com/dossier/EAbcdef123"

        before = int(time.time())
        header = create_vvp_identity_header(issuer_oobi, dossier_url)
        after = int(time.time())

        assert before <= header.iat <= after
