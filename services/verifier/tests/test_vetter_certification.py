"""Tests for Vetter Certification parsing.

Sprint 44: Coverage improvement tests for certification.py
"""

import pytest
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.vvp.vetter.certification import (
    VetterCertification,
    parse_vetter_certification,
    is_vetter_certification_schema,
    VETTER_CERTIFICATION_SCHEMA_SAIDS,
)


class TestVetterCertificationDataclass:
    """Tests for VetterCertification dataclass."""

    def test_has_ecc_target_true(self):
        """Should return True for matching ECC target."""
        cert = VetterCertification(
            said="ABC123",
            vetter_aid="VETTER1",
            issuer_aid="ISSUER1",
            ecc_targets=["1", "44", "33"],
        )
        assert cert.has_ecc_target("44") is True

    def test_has_ecc_target_false(self):
        """Should return False for non-matching ECC target."""
        cert = VetterCertification(
            said="ABC123",
            vetter_aid="VETTER1",
            issuer_aid="ISSUER1",
            ecc_targets=["1", "44"],
        )
        assert cert.has_ecc_target("99") is False

    def test_has_jurisdiction_target_case_insensitive(self):
        """Jurisdiction target check should be case-insensitive."""
        cert = VetterCertification(
            said="ABC123",
            vetter_aid="VETTER1",
            issuer_aid="ISSUER1",
            jurisdiction_targets=["GBR", "USA"],
        )
        assert cert.has_jurisdiction_target("gbr") is True
        assert cert.has_jurisdiction_target("GBR") is True
        assert cert.has_jurisdiction_target("usa") is True


class TestParseCertificationDict:
    """Tests for parsing certification from dict."""

    def test_parse_minimal_dict(self):
        """Should parse minimal certification dict."""
        acdc = {
            "d": "SAID123",
            "i": "ISSUER_AID",
            "s": "SCHEMA_SAID",
            "a": {
                "i": "VETTER_AID",
            },
        }

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.said == "SAID123"
        assert cert.issuer_aid == "ISSUER_AID"
        assert cert.vetter_aid == "VETTER_AID"

    def test_parse_full_dict(self):
        """Should parse full certification dict with targets."""
        acdc = {
            "d": "SAID123",
            "i": "ISSUER_AID",
            "s": "SCHEMA_SAID",
            "a": {
                "i": "VETTER_AID",
                "ecc_targets": ["1", "44"],
                "jurisdiction_targets": ["USA", "GBR"],
                "name": "Test Vetter",
                "certificationExpiry": "2025-12-31",
            },
        }

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.ecc_targets == ["1", "44"]
        assert cert.jurisdiction_targets == ["USA", "GBR"]
        assert cert.name == "Test Vetter"
        assert cert.expiry == "2025-12-31"


class TestParseCertificationObject:
    """Tests for parsing certification from object."""

    def test_parse_from_object(self):
        """Should parse certification from ACDC-like object."""

        @dataclass
        class MockACDC:
            said: str
            issuer_aid: str
            schema_said: str
            attributes: Optional[Dict[str, Any]] = None
            raw: Optional[Dict[str, Any]] = None

        acdc = MockACDC(
            said="SAID123",
            issuer_aid="ISSUER_AID",
            schema_said="SCHEMA_SAID",
            attributes={"i": "VETTER_AID", "ecc_targets": ["44"]},
        )

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.said == "SAID123"
        assert cert.vetter_aid == "VETTER_AID"
        assert cert.ecc_targets == ["44"]

    def test_parse_from_object_with_raw(self):
        """Should fall back to raw dict when attributes is None."""

        @dataclass
        class MockACDC:
            said: str = ""
            issuer_aid: str = ""
            schema_said: str = ""
            attributes: Optional[Dict[str, Any]] = None
            raw: Dict[str, Any] = None

            def __post_init__(self):
                if self.raw is None:
                    self.raw = {}

        acdc = MockACDC(
            raw={
                "d": "SAID123",
                "i": "ISSUER_AID",
                "s": "SCHEMA_SAID",
                "a": {"i": "VETTER_AID"},
            }
        )

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.said == "SAID123"

    def test_parse_invalid_attributes_type_returns_none(self):
        """Should return None when attributes is invalid type."""

        @dataclass
        class BadAttrsACDC:
            said: str = "SAID123"
            issuer_aid: str = "ISSUER_AID"
            schema_said: str = "SCHEMA_SAID"
            attributes: Any = "not-a-dict"
            raw: Dict[str, Any] = None

        acdc = BadAttrsACDC()
        cert = parse_vetter_certification(acdc)
        assert cert is None


class TestParseCertificationEdgeCases:
    """Edge case tests for certification parsing."""

    def test_compact_attributes_returns_none(self):
        """Should return None for compact (SAID string) attributes."""
        acdc = {
            "d": "SAID123",
            "i": "ISSUER_AID",
            "s": "SCHEMA_SAID",
            "a": "COMPACT_ATTRIBUTES_SAID",  # String instead of dict
        }

        cert = parse_vetter_certification(acdc)
        assert cert is None

    def test_non_list_targets_normalized(self):
        """Should normalize non-list targets to lists."""
        acdc = {
            "d": "SAID123",
            "i": "ISSUER_AID",
            "a": {
                "i": "VETTER_AID",
                "ecc_targets": "44",  # Single value, not list
                "jurisdiction_targets": "GBR",  # Single value, not list
            },
        }

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.ecc_targets == ["44"]
        assert cert.jurisdiction_targets == ["GBR"]

    def test_empty_targets_normalized(self):
        """Should handle empty/None targets."""
        acdc = {
            "d": "SAID123",
            "i": "ISSUER_AID",
            "a": {
                "i": "VETTER_AID",
                "ecc_targets": None,
                "jurisdiction_targets": "",
            },
        }

        cert = parse_vetter_certification(acdc)
        assert cert is not None
        assert cert.ecc_targets == []
        assert cert.jurisdiction_targets == []


class TestIsVetterCertificationSchema:
    """Tests for schema SAID checking."""

    def test_known_schema_returns_true(self):
        """Should return True for known schema SAID."""
        known_said = list(VETTER_CERTIFICATION_SCHEMA_SAIDS)[0]
        assert is_vetter_certification_schema(known_said) is True

    def test_unknown_schema_returns_false(self):
        """Should return False for unknown schema SAID."""
        assert is_vetter_certification_schema("UNKNOWN_SCHEMA") is False
