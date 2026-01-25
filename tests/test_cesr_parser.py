"""
Tests for CESR stream parser.

These tests verify that the CESR parser correctly handles:
- JSON events with attached signatures
- Count codes for different attachment types
- Error handling for malformed streams
"""

import json
import base64
from pathlib import Path

import pytest

from app.vvp.keri.cesr import (
    CESRMessage,
    CountCode,
    WitnessReceipt,
    _b64_to_int,
    _parse_count_code,
    is_cesr_stream,
    parse_cesr_stream,
)
from app.vvp.keri.exceptions import ResolutionFailedError


# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestB64ToInt:
    """Tests for base64 to integer conversion."""

    def test_single_char(self):
        """Single character conversion."""
        assert _b64_to_int("A") == 0
        assert _b64_to_int("B") == 1
        assert _b64_to_int("Z") == 25
        assert _b64_to_int("a") == 26
        assert _b64_to_int("z") == 51
        assert _b64_to_int("0") == 52
        assert _b64_to_int("9") == 61
        assert _b64_to_int("-") == 62
        assert _b64_to_int("_") == 63

    def test_multi_char(self):
        """Multi-character conversion."""
        # "AA" = 0 * 64 + 0 = 0
        assert _b64_to_int("AA") == 0
        # "AB" = 0 * 64 + 1 = 1
        assert _b64_to_int("AB") == 1
        # "BA" = 1 * 64 + 0 = 64
        assert _b64_to_int("BA") == 64
        # "BB" = 1 * 64 + 1 = 65
        assert _b64_to_int("BB") == 65


class TestParseCountCode:
    """Tests for count code parsing."""

    def test_controller_sigs_code(self):
        """Parse -A count code."""
        data = b"-AAB"  # -A with count 1
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-A"
        assert count == 1
        assert offset == 4

    def test_witness_sigs_code(self):
        """Parse -B count code."""
        data = b"-BAC"  # -B with count 2
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-B"
        assert count == 2
        assert offset == 4

    def test_receipt_couples_code(self):
        """Parse -C count code."""
        data = b"-CAD"  # -C with count 3
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-C"
        assert count == 3
        assert offset == 4

    def test_version_marker(self):
        """Parse CESR version marker."""
        data = b"-_AAAKERI10JSON000000_"
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-_AAA"
        assert offset == 8

    def test_truncated_code(self):
        """Truncated count code raises error."""
        with pytest.raises(ResolutionFailedError):
            _parse_count_code(b"-A", 0)  # Missing count chars

    def test_unknown_code(self):
        """Unknown count code raises error."""
        with pytest.raises(ResolutionFailedError):
            _parse_count_code(b"-XAB", 0)


class TestIsCesrStream:
    """Tests for CESR detection."""

    def test_version_marker(self):
        """Detect CESR version marker."""
        assert is_cesr_stream(b"-_AAAKERI10")

    def test_count_code(self):
        """Detect count code."""
        assert is_cesr_stream(b"-AAB0A...")

    def test_json_only(self):
        """Plain JSON is not detected as CESR."""
        assert not is_cesr_stream(b'{"v":"KERI10JSON"}')

    def test_json_with_attachment(self):
        """JSON followed by count code is CESR."""
        data = b'{"v":"KERI10JSON","t":"icp"}-AAB'
        assert is_cesr_stream(data)

    def test_empty(self):
        """Empty data is not CESR."""
        assert not is_cesr_stream(b"")


class TestParseCesrStream:
    """Tests for CESR stream parsing."""

    def test_empty_stream(self):
        """Empty stream returns empty list."""
        result = parse_cesr_stream(b"")
        assert result == []

    def test_json_only(self):
        """Parse JSON without attachments."""
        event = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID", "i": "DAID"}
        data = json.dumps(event).encode("utf-8")

        result = parse_cesr_stream(data)

        assert len(result) == 1
        assert result[0].event_dict == event
        assert result[0].controller_sigs == []
        assert result[0].witness_receipts == []

    def test_multiple_events(self):
        """Parse multiple JSON events."""
        event1 = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID1", "i": "DAID"}
        event2 = {"v": "KERI10JSON000100_", "t": "rot", "d": "ESAID2", "i": "DAID"}
        data = json.dumps(event1).encode() + b"\n" + json.dumps(event2).encode()

        result = parse_cesr_stream(data)

        assert len(result) == 2
        assert result[0].event_dict["d"] == "ESAID1"
        assert result[1].event_dict["d"] == "ESAID2"

    def test_with_version_marker(self):
        """Parse stream with version marker."""
        event = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID", "i": "DAID"}
        # Version marker is 8 chars total: -_AAA + 3 chars for version/count
        # After the 8-char version marker, JSON follows directly
        data = b"-_AAABAA" + json.dumps(event).encode()

        result = parse_cesr_stream(data)

        assert len(result) == 1
        assert result[0].event_dict == event

    def test_malformed_json(self):
        """Malformed JSON raises error."""
        with pytest.raises(ResolutionFailedError) as exc:
            parse_cesr_stream(b'{"v": "KERI", "t": ')

        assert "Invalid JSON" in str(exc.value) or "Unterminated" in str(exc.value)


class TestCESRMessageDataclass:
    """Tests for CESRMessage dataclass."""

    def test_default_values(self):
        """Default values are correct."""
        msg = CESRMessage(event_bytes=b"{}", event_dict={})
        assert msg.controller_sigs == []
        assert msg.witness_receipts == []
        assert msg.raw == b""

    def test_with_signatures(self):
        """Message with signatures."""
        msg = CESRMessage(
            event_bytes=b"{}",
            event_dict={},
            controller_sigs=[b"sig1", b"sig2"],
        )
        assert len(msg.controller_sigs) == 2

    def test_with_receipts(self):
        """Message with witness receipts."""
        receipt = WitnessReceipt(witness_aid="BWITNESS", signature=b"sig")
        msg = CESRMessage(
            event_bytes=b"{}",
            event_dict={},
            witness_receipts=[receipt],
        )
        assert len(msg.witness_receipts) == 1
        assert msg.witness_receipts[0].witness_aid == "BWITNESS"


class TestWitnessReceiptDataclass:
    """Tests for WitnessReceipt dataclass."""

    def test_creation(self):
        """Create a witness receipt."""
        receipt = WitnessReceipt(witness_aid="BWITNESS", signature=b"sig")
        assert receipt.witness_aid == "BWITNESS"
        assert receipt.signature == b"sig"


class TestWithKeriPyFixtures:
    """Integration tests using keripy-generated fixtures."""

    @pytest.fixture
    def icp_fixture(self):
        """Load ICP fixture."""
        return load_fixture("icp_keripy.json")

    def test_parse_icp_event_bytes(self, icp_fixture):
        """Parse ICP event from canonical bytes."""
        canonical_bytes = base64.urlsafe_b64decode(icp_fixture["canonical_bytes"])

        result = parse_cesr_stream(canonical_bytes)

        assert len(result) == 1
        msg = result[0]
        assert msg.event_dict["t"] == "icp"
        assert msg.event_dict["d"] == icp_fixture["said"]

    def test_parse_kel_stream(self):
        """Parse complete KEL stream from fixture."""
        kel_fixture = load_fixture("kel_stream_keripy.json")
        events = kel_fixture["events"]

        # Concatenate all events as JSON (without CESR attachments for this test)
        data = b"".join(json.dumps(e).encode() for e in events)

        result = parse_cesr_stream(data)

        assert len(result) == len(events)
        for i, msg in enumerate(result):
            assert msg.event_dict["t"] == events[i]["t"]
            assert msg.event_dict["d"] == events[i]["d"]
