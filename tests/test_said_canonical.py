"""
Tests for KERI SAID computation using canonical serialization.

These tests verify that SAID computation produces correct results
matching keripy's implementation.
"""

import json
from pathlib import Path

import pytest

from app.vvp.keri.exceptions import KELChainInvalidError
from app.vvp.keri.kel_parser import (
    compute_said_canonical,
    validate_event_said_canonical,
)

# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestComputeSaidCanonical:
    """Tests for SAID computation with canonical serialization."""

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

    def test_icp_said_matches_keripy(self, icp_fixture):
        """Computed SAID matches keripy for ICP event."""
        event = icp_fixture["event"]
        expected_said = icp_fixture["said"]

        computed = compute_said_canonical(event)

        assert computed == expected_said, (
            f"ICP SAID mismatch:\n"
            f"Expected: {expected_said}\n"
            f"Computed: {computed}"
        )

    def test_rot_said_matches_keripy(self, rot_fixture):
        """Computed SAID matches keripy for ROT event."""
        event = rot_fixture["event"]
        expected_said = rot_fixture["said"]

        computed = compute_said_canonical(event)

        assert computed == expected_said, (
            f"ROT SAID mismatch:\n"
            f"Expected: {expected_said}\n"
            f"Computed: {computed}"
        )

    def test_ixn_said_matches_keripy(self, ixn_fixture):
        """Computed SAID matches keripy for IXN event."""
        event = ixn_fixture["event"]
        expected_said = ixn_fixture["said"]

        computed = compute_said_canonical(event)

        assert computed == expected_said, (
            f"IXN SAID mismatch:\n"
            f"Expected: {expected_said}\n"
            f"Computed: {computed}"
        )

    def test_require_blake3_when_available(self, icp_fixture):
        """Blake3 is used when require_blake3=True and it's available."""
        event = icp_fixture["event"]

        # Should work without raising (blake3 is installed)
        computed = compute_said_canonical(event, require_blake3=True)

        # Should produce a valid SAID
        assert computed.startswith("E")
        assert len(computed) == 44

    def test_custom_said_field(self):
        """Can compute SAID for a different field."""
        # TEL events have SAID in 'i' field for inception
        event = {
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "d": "ESAID",
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [],
        }

        # Compute SAID for 'i' field
        said_i = compute_said_canonical(event, said_field="i")

        # Should be different from 'd' field SAID
        said_d = compute_said_canonical(event, said_field="d")

        # Both should be valid SAIDs
        assert said_i.startswith("E")
        assert said_d.startswith("E")
        # They should be different because placeholder position differs
        assert said_i != said_d


class TestValidateEventSaidCanonical:
    """Tests for SAID validation with canonical serialization."""

    @pytest.fixture
    def icp_fixture(self):
        """Load ICP fixture."""
        return load_fixture("icp_keripy.json")

    def test_valid_said_passes(self, icp_fixture):
        """Event with correct SAID passes validation."""
        event = icp_fixture["event"]

        # Should not raise
        validate_event_said_canonical(event)

    def test_invalid_said_fails(self, icp_fixture):
        """Event with incorrect SAID fails validation."""
        event = dict(icp_fixture["event"])
        # Modify the SAID to make it invalid
        event["d"] = "EINVALIDSAID00000000000000000000000000000000"

        with pytest.raises(KELChainInvalidError) as exc:
            validate_event_said_canonical(event)

        assert "SAID mismatch" in str(exc.value)

    def test_missing_said_field_passes(self):
        """Event without SAID field passes (nothing to validate)."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [],
        }

        # Should not raise
        validate_event_said_canonical(event)

    def test_placeholder_said_passes(self):
        """Event with placeholder SAID passes (skips validation)."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "d": "#" * 44,
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [],
        }

        # Should not raise (placeholder skipped)
        validate_event_said_canonical(event)

    def test_empty_said_passes(self):
        """Event with empty SAID passes (skips validation)."""
        event = {
            "v": "KERI10JSON000100_",
            "t": "ixn",
            "d": "",
            "i": "DAID",
            "s": "0",
            "p": "EPRIOR",
            "a": [],
        }

        # Should not raise
        validate_event_said_canonical(event)


class TestSaidWithKelStream:
    """Tests using the complete KEL stream fixture."""

    @pytest.fixture
    def kel_stream(self):
        """Load KEL stream fixture."""
        return load_fixture("kel_stream_keripy.json")

    def test_all_events_have_valid_saids(self, kel_stream):
        """All events in KEL stream have valid SAIDs."""
        events = kel_stream["events"]

        for i, event in enumerate(events):
            try:
                validate_event_said_canonical(event)
            except KELChainInvalidError as e:
                pytest.fail(f"Event {i} ({event['t']}) has invalid SAID: {e}")

    def test_computed_saids_match_fixtures(self, kel_stream):
        """Computed SAIDs match the ones in the fixture."""
        events = kel_stream["events"]

        for i, event in enumerate(events):
            expected = event["d"]
            computed = compute_said_canonical(event)

            assert computed == expected, (
                f"Event {i} ({event['t']}) SAID mismatch:\n"
                f"Expected: {expected}\n"
                f"Computed: {computed}"
            )
