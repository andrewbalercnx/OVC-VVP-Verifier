"""
Tests for KERI canonical serialization.

These tests verify that our canonical serializer produces output
that matches keripy's serialization for all supported event types.
"""

import json
from base64 import urlsafe_b64decode
from pathlib import Path

import pytest

from app.vvp.keri.keri_canonical import (
    FIELD_ORDER,
    CanonicalSerializationError,
    canonical_serialize,
    get_field_order,
    most_compact_form,
)

# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestFieldOrders:
    """Tests for field order definitions."""

    def test_icp_field_order(self):
        """ICP field order matches keripy."""
        assert FIELD_ORDER["icp"] == [
            "v",
            "t",
            "d",
            "i",
            "s",
            "kt",
            "k",
            "nt",
            "n",
            "bt",
            "b",
            "c",
            "a",
        ]

    def test_rot_field_order(self):
        """ROT field order matches keripy."""
        assert FIELD_ORDER["rot"] == [
            "v",
            "t",
            "d",
            "i",
            "s",
            "p",
            "kt",
            "k",
            "nt",
            "n",
            "bt",
            "br",
            "ba",
            "a",
        ]

    def test_ixn_field_order(self):
        """IXN field order matches keripy."""
        assert FIELD_ORDER["ixn"] == ["v", "t", "d", "i", "s", "p", "a"]

    def test_dip_field_order(self):
        """DIP field order matches keripy."""
        assert FIELD_ORDER["dip"] == [
            "v",
            "t",
            "d",
            "i",
            "s",
            "kt",
            "k",
            "nt",
            "n",
            "bt",
            "b",
            "c",
            "a",
            "di",
        ]

    def test_drt_field_order(self):
        """DRT field order matches keripy."""
        assert FIELD_ORDER["drt"] == [
            "v",
            "t",
            "d",
            "i",
            "s",
            "p",
            "kt",
            "k",
            "nt",
            "n",
            "bt",
            "br",
            "ba",
            "a",
        ]

    def test_get_field_order_known_type(self):
        """get_field_order returns correct order for known types."""
        assert get_field_order("icp") == FIELD_ORDER["icp"]
        assert get_field_order("rot") == FIELD_ORDER["rot"]
        assert get_field_order("ixn") == FIELD_ORDER["ixn"]

    def test_get_field_order_unknown_type(self):
        """get_field_order returns None for unknown types."""
        assert get_field_order("unknown") is None
        assert get_field_order("") is None


class TestCanonicalSerialize:
    """Tests for canonical serialization."""

    def test_simple_icp_event(self):
        """Serialize a simple ICP event."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "icp",
            "d": "ESAID000000000000000000000000000000000000000",
            "i": "DAID0000000000000000000000000000000000000000",
            "s": "0",
            "kt": 1,
            "k": ["DKEY0000000000000000000000000000000000000000"],
            "nt": 1,
            "n": ["ENEXT000000000000000000000000000000000000000"],
            "bt": 0,
            "b": [],
            "c": [],
            "a": [],
        }

        result = canonical_serialize(event)

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed["t"] == "icp"

        # Should have no whitespace (compact)
        assert b" " not in result
        assert b"\n" not in result

        # Field order should be correct
        keys = list(json.loads(result).keys())
        assert keys == FIELD_ORDER["icp"]

    def test_event_missing_type(self):
        """Serialization fails if 't' field is missing."""
        event = {"v": "KERI10JSON000100_", "d": "ESAID"}

        with pytest.raises(CanonicalSerializationError) as exc:
            canonical_serialize(event)

        assert "missing 't'" in str(exc.value)

    def test_unknown_event_type(self):
        """Serialization fails for unknown event types."""
        event = {"v": "KERI10JSON000100_", "t": "unknown", "d": "ESAID"}

        with pytest.raises(CanonicalSerializationError) as exc:
            canonical_serialize(event)

        assert "Unknown event type" in str(exc.value)

    def test_extra_fields_preserved(self):
        """Extra fields not in standard order are preserved at the end."""
        event = {
            "extra_field": "value",
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "d": "ESAID",
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [],
        }

        result = canonical_serialize(event)
        parsed = json.loads(result)

        # Standard fields should come first in order
        keys = list(parsed.keys())
        assert keys[:7] == ["v", "t", "d", "i", "s", "p", "a"]
        # Extra field should be at end
        assert "extra_field" in keys

    def test_utf8_encoding(self):
        """Non-ASCII characters are preserved."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "d": "ESAID",
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [{"text": "日本語"}],
        }

        result = canonical_serialize(event)

        # Should contain raw UTF-8, not escaped
        assert "日本語".encode("utf-8") in result


class TestMostCompactForm:
    """Tests for most compact form generation."""

    def test_placeholder_length(self):
        """Placeholder is 44 characters (SAID length)."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "icp",
            "d": "ESAID000000000000000000000000000000000000000",
            "i": "DAID",
            "s": "0",
            "kt": 1,
            "k": [],
            "nt": 0,
            "n": [],
            "bt": 0,
            "b": [],
            "c": [],
            "a": [],
        }

        result = most_compact_form(event)
        parsed = json.loads(result)

        assert parsed["d"] == "#" * 44

    def test_custom_said_field(self):
        """Can specify a different SAID field."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "icp",
            "d": "original_d",
            "i": "should_be_placeholder",
            "s": "0",
            "kt": 1,
            "k": [],
            "nt": 0,
            "n": [],
            "bt": 0,
            "b": [],
            "c": [],
            "a": [],
        }

        result = most_compact_form(event, said_field="i")
        parsed = json.loads(result)

        assert parsed["i"] == "#" * 44
        assert parsed["d"] == "original_d"

    def test_original_event_unchanged(self):
        """Original event dict is not modified."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "icp",
            "d": "ORIGINAL_SAID",
            "i": "DAID",
            "s": "0",
            "kt": 1,
            "k": [],
            "nt": 0,
            "n": [],
            "bt": 0,
            "b": [],
            "c": [],
            "a": [],
        }

        most_compact_form(event)

        assert event["d"] == "ORIGINAL_SAID"


class TestKeriPyCompatibility:
    """Tests verifying compatibility with keripy output.

    These tests use fixtures generated by keripy to ensure our
    canonical serialization produces identical output.
    """

    @pytest.fixture
    def icp_fixture(self):
        """Load ICP fixture."""
        return load_fixture("icp_keripy.json")

    @pytest.fixture
    def rot_fixture(self):
        """Load ROT fixture."""
        return load_fixture("rot_keripy.json")

    @pytest.fixture
    def ixn_fixture(self):
        """Load IXN fixture."""
        return load_fixture("ixn_keripy.json")

    @pytest.fixture
    def field_orders_fixture(self):
        """Load field orders fixture."""
        return load_fixture("field_orders_keripy.json")

    def test_icp_canonical_matches_keripy(self, icp_fixture):
        """Verify ICP canonical output matches keripy serdering."""
        event = icp_fixture["event"]
        expected = urlsafe_b64decode(icp_fixture["canonical_bytes"])

        actual = canonical_serialize(event)

        assert actual == expected, (
            f"ICP canonical mismatch:\n"
            f"Expected: {expected!r}\n"
            f"Actual:   {actual!r}"
        )

    def test_rot_canonical_matches_keripy(self, rot_fixture):
        """Verify ROT canonical output matches keripy serdering."""
        event = rot_fixture["event"]
        expected = urlsafe_b64decode(rot_fixture["canonical_bytes"])

        actual = canonical_serialize(event)

        assert actual == expected, (
            f"ROT canonical mismatch:\n"
            f"Expected: {expected!r}\n"
            f"Actual:   {actual!r}"
        )

    def test_ixn_canonical_matches_keripy(self, ixn_fixture):
        """Verify IXN canonical output matches keripy serdering."""
        event = ixn_fixture["event"]
        expected = urlsafe_b64decode(ixn_fixture["canonical_bytes"])

        actual = canonical_serialize(event)

        assert actual == expected, (
            f"IXN canonical mismatch:\n"
            f"Expected: {expected!r}\n"
            f"Actual:   {actual!r}"
        )

    def test_field_orders_match_keripy(self, field_orders_fixture):
        """Verify field orderings match keripy definitions."""
        keripy_orders = field_orders_fixture["field_orders"]

        # Check all event types we support
        for event_type in ["icp", "rot", "ixn", "dip", "drt"]:
            expected = keripy_orders.get(event_type)
            actual = FIELD_ORDER.get(event_type)

            assert actual == expected, (
                f"Field order mismatch for {event_type}:\n"
                f"Expected: {expected}\n"
                f"Actual:   {actual}"
            )
