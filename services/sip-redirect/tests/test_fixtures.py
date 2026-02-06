"""Tests to validate test fixtures are correct.

Sprint 42: Ensures test fixtures are properly structured.
"""

import json
from pathlib import Path

import pytest


class TestFixturesLoad:
    """Test that fixtures load correctly."""

    def test_json_data_loads(self):
        """Test that test_data.json is valid JSON."""
        json_path = Path(__file__).parent / "fixtures" / "test_data.json"
        with open(json_path) as f:
            data = json.load(f)

        assert data["organization"]["name"] == "Acme Corp"
        assert data["telephone_numbers"]["extension_1001"]["tn"] == "+441923311000"

    def test_credentials_module_imports(self):
        """Test that credentials module imports correctly."""
        from tests.fixtures.credentials import (
            GLEIF_AID,
            QVI_AID,
            ACME_CORP_AID,
            ACME_SIGNER_AID,
            ACME_CORP,
            TEST_TN,
            get_test_keys,
            get_test_dossier,
        )

        assert GLEIF_AID.startswith("E")
        assert QVI_AID.startswith("E")
        assert ACME_CORP_AID.startswith("E")
        assert ACME_SIGNER_AID.startswith("E")
        assert ACME_CORP["name"] == "Acme Corp"
        assert TEST_TN == "+441923311000"

    def test_sip_messages_module_imports(self):
        """Test that SIP messages module imports correctly."""
        from tests.fixtures.sip_messages import (
            VALID_INVITE_EXT_1001,
            INVITE_NO_API_KEY,
            build_invite,
        )

        assert b"INVITE" in VALID_INVITE_EXT_1001
        assert b"X-VVP-API-Key" in VALID_INVITE_EXT_1001
        assert b"X-VVP-API-Key" not in INVITE_NO_API_KEY

    def test_logo_exists(self):
        """Test that logo SVG exists."""
        logo_path = Path(__file__).parent / "fixtures" / "acme_logo.svg"
        assert logo_path.exists()
        content = logo_path.read_text()
        assert "ACME CORP" in content
        assert "<svg" in content


class TestCredentialStructure:
    """Test credential structure is correct."""

    def test_qvi_credential_structure(self):
        """Test QVI credential has correct structure."""
        from tests.fixtures.credentials import get_qvi_credential, GLEIF_AID, QVI_AID

        cred = get_qvi_credential()

        assert cred["v"].startswith("ACDC")
        assert cred["d"].startswith("E")  # Valid SAID prefix
        assert cred["i"] == GLEIF_AID  # Issuer is GLEIF
        assert cred["a"]["i"] == QVI_AID  # Issuee is QVI
        assert "LEI" in cred["a"]

    def test_le_credential_structure(self):
        """Test LE credential has correct structure."""
        from tests.fixtures.credentials import (
            get_le_credential,
            QVI_AID,
            ACME_CORP_AID,
            QVI_CREDENTIAL_SAID,
        )

        cred = get_le_credential()

        assert cred["i"] == QVI_AID  # Issuer is QVI
        assert cred["a"]["i"] == ACME_CORP_AID  # Issuee is Acme Corp
        assert cred["a"]["personLegalName"] == "Acme Corp"
        assert cred["e"]["qvi"]["n"] == QVI_CREDENTIAL_SAID  # Edge to QVI

    def test_tn_allocation_structure(self):
        """Test TN Allocation credential has correct structure."""
        from tests.fixtures.credentials import (
            get_tn_allocation_credential,
            TEST_TN,
            LE_CREDENTIAL_SAID,
        )

        cred = get_tn_allocation_credential()

        assert TEST_TN in cred["a"]["numbers"]["tn"]
        assert cred["a"]["channel"] == "voice"
        assert cred["e"]["le"]["n"] == LE_CREDENTIAL_SAID  # Edge to LE

    def test_dossier_contains_all_credentials(self):
        """Test dossier contains complete credential chain."""
        from tests.fixtures.credentials import get_test_dossier

        dossier = get_test_dossier()

        assert len(dossier["credentials"]) == 3
        assert dossier["name"] == "Acme Corp VVP Dossier"

        # Verify credential types
        schemas = [c["s"] for c in dossier["credentials"]]
        assert "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao" in schemas  # QVI
        assert "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY" in schemas  # LE
        assert "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ" in schemas  # TN Alloc


class TestVVPHeaders:
    """Test VVP header generation."""

    def test_vvp_identity_structure(self):
        """Test VVP-Identity header has correct structure."""
        import base64
        import json
        from tests.fixtures.credentials import create_test_vvp_identity, TEST_TN

        identity_b64 = create_test_vvp_identity()

        # Decode and parse
        # Add padding if needed
        padding = 4 - len(identity_b64) % 4
        if padding != 4:
            identity_b64 += "=" * padding

        identity_json = base64.urlsafe_b64decode(identity_b64)
        identity = json.loads(identity_json)

        assert identity["alg"] == "EdDSA"
        assert identity["typ"] == "vdp"
        assert identity["orig"]["tn"] == TEST_TN
        assert "iat" in identity
        assert "d" in identity  # Dossier SAID
        assert "i" in identity  # Signer AID

    def test_passport_structure(self):
        """Test PASSporT has correct JWT structure."""
        import base64
        import json
        from tests.fixtures.credentials import create_test_passport

        passport = create_test_passport()

        # Split JWT parts
        parts = passport.split(".")
        assert len(parts) == 3  # header.payload.signature

        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert header["alg"] == "EdDSA"
        assert header["typ"] == "passport"

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        assert payload["attest"] == "A"
        assert "orig" in payload
        assert "dest" in payload
        assert "iat" in payload


class TestSIPMessages:
    """Test SIP message builders."""

    def test_valid_invite_has_required_headers(self):
        """Test valid INVITE has all required headers."""
        from tests.fixtures.sip_messages import VALID_INVITE_EXT_1001

        msg = VALID_INVITE_EXT_1001.decode()

        assert "INVITE" in msg
        assert "Via:" in msg
        assert "From:" in msg
        assert "To:" in msg
        assert "Call-ID:" in msg
        assert "CSeq:" in msg
        assert "X-VVP-API-Key:" in msg

    def test_invite_without_api_key(self):
        """Test INVITE without API key has no auth header."""
        from tests.fixtures.sip_messages import INVITE_NO_API_KEY

        msg = INVITE_NO_API_KEY.decode()

        assert "INVITE" in msg
        assert "X-VVP-API-Key" not in msg

    def test_build_invite_custom(self):
        """Test custom INVITE builder."""
        from tests.fixtures.sip_messages import build_invite

        msg = build_invite(
            from_tn="+12025551234",
            to_tn="+14155551234",
            api_key="custom_key_123",
            call_id="custom-call-id",
        ).decode()

        assert "+12025551234" in msg
        assert "+14155551234" in msg
        assert "custom_key_123" in msg
        assert "custom-call-id" in msg

    def test_build_many_invites(self):
        """Test building multiple INVITEs."""
        from tests.fixtures.sip_messages import build_many_invites

        invites = build_many_invites(10)

        assert len(invites) == 10
        for i, msg in enumerate(invites):
            assert f"burst-test-{i}@" in msg.decode()


class TestKeys:
    """Test key fixtures."""

    def test_all_keys_exist(self):
        """Test all expected keys exist."""
        from tests.fixtures.credentials import get_test_keys

        for identity in ["gleif", "qvi", "acme_corp", "acme_signer"]:
            keys = get_test_keys(identity)
            assert "public" in keys
            assert "private" in keys

    def test_invalid_identity_raises(self):
        """Test invalid identity raises error."""
        from tests.fixtures.credentials import get_test_keys

        with pytest.raises(ValueError):
            get_test_keys("nonexistent")


class TestDossierFormat:
    """Test dossier format for verifier compatibility."""

    def test_dossier_credentials_is_list(self):
        """Test get_dossier_credentials returns a list."""
        from tests.fixtures.credentials import get_dossier_credentials

        creds = get_dossier_credentials()
        assert isinstance(creds, list)
        assert len(creds) == 3

    def test_dossier_credentials_have_required_fields(self):
        """Test each credential has d, i, s fields."""
        from tests.fixtures.credentials import get_dossier_credentials

        creds = get_dossier_credentials()
        for cred in creds:
            assert "d" in cred  # SAID
            assert "i" in cred  # Issuer
            assert "s" in cred  # Schema
            assert cred["d"].startswith("E")  # Valid SAID prefix
            assert cred["i"].startswith("E")  # Valid AID prefix
            assert cred["s"].startswith("E")  # Valid schema SAID prefix

    def test_dossier_json_is_valid_json(self):
        """Test get_dossier_json returns valid JSON."""
        from tests.fixtures.credentials import get_dossier_json

        dossier_str = get_dossier_json()
        parsed = json.loads(dossier_str)
        assert isinstance(parsed, list)
        assert len(parsed) == 3

    def test_dossier_file_matches_function(self):
        """Test acme_dossier.json matches get_dossier_credentials."""
        from tests.fixtures.credentials import get_dossier_credentials

        json_path = Path(__file__).parent / "fixtures" / "acme_dossier.json"
        with open(json_path) as f:
            file_creds = json.load(f)

        func_creds = get_dossier_credentials()

        # Compare SAIDs
        file_saids = [c["d"] for c in file_creds]
        func_saids = [c["d"] for c in func_creds]
        assert file_saids == func_saids


class TestVVPIdentityHeader:
    """Test VVP-Identity header format for verifier."""

    def test_vvp_identity_header_structure(self):
        """Test create_vvp_identity_header has correct structure."""
        import base64
        from tests.fixtures.credentials import create_vvp_identity_header

        header_b64 = create_vvp_identity_header()

        # Decode
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header_json = base64.urlsafe_b64decode(header_b64)
        header = json.loads(header_json)

        # Required fields for verifier
        assert "ppt" in header
        assert "kid" in header
        assert "evd" in header
        assert "iat" in header

        assert header["ppt"] == "shaken"
        assert header["kid"].startswith("E")  # Valid AID
        assert header["evd"].startswith("http")  # Valid URL

    def test_vvp_identity_header_custom_evd(self):
        """Test custom evd URL."""
        import base64
        from tests.fixtures.credentials import create_vvp_identity_header

        custom_url = "http://localhost:8888/test_dossier.json"
        header_b64 = create_vvp_identity_header(evd_url=custom_url)

        # Decode
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert header["evd"] == custom_url


class TestServiceURLs:
    """Test service URL constants."""

    def test_service_urls_defined(self):
        """Test all service URLs are defined."""
        from tests.fixtures.credentials import (
            SIP_SIGNER_HOST,
            SIP_SIGNER_PORT,
            SIP_SIGNER_TLS_PORT,
            VVP_ISSUER_URL,
            VVP_VERIFIER_URL,
            TEST_DOSSIER_URL,
        )

        assert SIP_SIGNER_HOST == "pbx.rcnx.io"
        assert SIP_SIGNER_PORT == 5060
        assert SIP_SIGNER_TLS_PORT == 5061
        assert "rcnx.io" in VVP_ISSUER_URL
        assert "rcnx.io" in VVP_VERIFIER_URL
        assert "rcnx.io" in TEST_DOSSIER_URL
