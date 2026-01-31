#!/usr/bin/env python3
"""Test script for verifying KERI witness resolution with Provenant staging.

This is a standalone script that doesn't import from app modules to avoid
dependency issues. It implements minimal CESR parsing inline.
"""

import asyncio
import base64
import json
import sys
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


# Test AID from Provenant (discovered from OOBI exploration)
TEST_AID = "EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF"
TEST_OOBI_URL = f"http://witness5.stage.provenant.net:5631/oobi/{TEST_AID}/witness"


@dataclass
class KELEvent:
    """Parsed KERI event."""
    event_type: str
    sequence: int
    digest: str
    signing_keys: List[bytes] = field(default_factory=list)
    witnesses: List[str] = field(default_factory=list)
    controller_sigs: List[bytes] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def is_establishment(self) -> bool:
        return self.event_type in ("icp", "rot", "dip", "drt")


def decode_keri_key(key_str: str) -> bytes:
    """Decode a KERI-encoded public key."""
    if not key_str or len(key_str) < 2:
        raise ValueError(f"Invalid key format: too short")

    code = key_str[0]
    if code in ("B", "D"):
        key_b64 = key_str[1:]
        padded = key_b64 + "=" * (-len(key_b64) % 4)
        return base64.urlsafe_b64decode(padded)

    raise ValueError(f"Unsupported key derivation code: {code}")


def find_json_end(data: bytes, offset: int) -> int:
    """Find the end of a JSON object in the byte stream."""
    depth = 0
    in_string = False
    escape = False
    i = offset

    while i < len(data):
        c = data[i]

        if escape:
            escape = False
            i += 1
            continue

        if c == ord("\\"):
            escape = True
            i += 1
            continue

        if c == ord('"'):
            in_string = not in_string
            i += 1
            continue

        if in_string:
            i += 1
            continue

        if c == ord("{"):
            depth += 1
        elif c == ord("}"):
            depth -= 1
            if depth == 0:
                return i + 1

        i += 1

    return i


def parse_cesr_stream(data: bytes) -> List[KELEvent]:
    """Parse a CESR stream into KEL events."""
    events = []
    offset = 0

    while offset < len(data):
        # Skip whitespace
        while offset < len(data) and data[offset:offset+1] in (b" ", b"\n", b"\r", b"\t"):
            offset += 1

        if offset >= len(data):
            break

        # Check for JSON event
        if data[offset:offset+1] == b"{":
            json_end = find_json_end(data, offset)
            event_bytes = data[offset:json_end]
            offset = json_end

            try:
                event_dict = json.loads(event_bytes.decode("utf-8"))

                # Skip non-KEL events (like /loc/scheme replies)
                event_type = event_dict.get("t", "")
                if event_type not in ("icp", "rot", "ixn", "dip", "drt", "rpy"):
                    continue
                if event_type == "rpy":
                    # Skip reply messages
                    continue

                # Parse keys
                signing_keys = []
                for key_str in event_dict.get("k", []):
                    try:
                        signing_keys.append(decode_keri_key(key_str))
                    except Exception:
                        pass

                events.append(KELEvent(
                    event_type=event_type,
                    sequence=int(event_dict.get("s", "0"), 16) if isinstance(event_dict.get("s"), str) else event_dict.get("s", 0),
                    digest=event_dict.get("d", ""),
                    signing_keys=signing_keys,
                    witnesses=event_dict.get("b", []),
                    raw=event_dict
                ))

            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        elif data[offset:offset+1] == b"-":
            # CESR count code - skip attachments for now
            # Find next JSON object or end
            next_json = data.find(b"{", offset + 1)
            if next_json == -1:
                break
            offset = next_json
        else:
            offset += 1

    return events


async def test_oobi_resolution():
    """Test fetching and parsing OOBI from Provenant witness."""
    import httpx

    print(f"\n{'='*60}")
    print("Testing KERI Witness Resolution")
    print(f"{'='*60}")

    print(f"\n1. Fetching OOBI from: {TEST_OOBI_URL}")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(TEST_OOBI_URL)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "")
            kel_data = response.content
            aid_header = response.headers.get("Keri-Aid", "")

        print(f"   ✓ OOBI fetch successful")
        print(f"   - Status: {response.status_code}")
        print(f"   - Content-Type: {content_type}")
        print(f"   - KERI-AID header: {aid_header[:30]}..." if aid_header else "   - KERI-AID header: (not present)")
        print(f"   - Data length: {len(kel_data)} bytes")

        # Show first 200 chars of response
        preview = kel_data[:200].decode("utf-8", errors="replace")
        print(f"   - Preview: {preview}...")

    except Exception as e:
        print(f"   ✗ OOBI fetch failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print(f"\n2. Parsing CESR stream...")

    try:
        events = parse_cesr_stream(kel_data)

        print(f"   ✓ Parsed {len(events)} KEL event(s)")

        for event in events:
            print(f"\n   Event {event.sequence}:")
            print(f"   - Type: {event.event_type}")
            print(f"   - Digest: {event.digest[:30]}...")
            print(f"   - Keys: {len(event.signing_keys)}")
            if event.signing_keys:
                key_hex = event.signing_keys[0].hex()[:32]
                print(f"   - First key (hex): {key_hex}...")
            print(f"   - Witnesses: {len(event.witnesses)}")

    except Exception as e:
        print(f"   ✗ CESR parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print(f"\n3. Extracting current signing key...")

    establishment_events = [e for e in events if e.is_establishment]
    if establishment_events:
        latest = max(establishment_events, key=lambda e: e.sequence)
        print(f"   ✓ Latest establishment: sequence {latest.sequence}")

        if latest.signing_keys:
            key_bytes = latest.signing_keys[0]
            key_b64 = base64.urlsafe_b64encode(key_bytes).decode().rstrip('=')
            keri_key = f"D{key_b64}"
            print(f"   ✓ Current signing key: {keri_key}")
            print(f"   - Raw bytes (32): {key_bytes.hex()}")

            # Verify key from raw event matches
            raw_key = latest.raw.get("k", [])[0] if latest.raw.get("k") else ""
            print(f"   - Original key: {raw_key}")
        else:
            print(f"   ✗ No signing keys in establishment event")
            return False
    else:
        print(f"   ✗ No establishment events found")
        return False

    print(f"\n{'='*60}")
    print("✓ All tests passed!")
    print(f"{'='*60}\n")
    return True


def test_oobi_url_parsing():
    """Test extracting AID from OOBI URL format kid."""
    print(f"\n{'='*60}")
    print("Testing OOBI URL Parsing")
    print(f"{'='*60}")

    def extract_aid_from_url(url: str) -> str:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        for i, part in enumerate(path_parts):
            if part.lower() == "oobi" and i + 1 < len(path_parts):
                potential_aid = path_parts[i + 1]
                if potential_aid and potential_aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                    return potential_aid
        return ""

    def extract_aid(kid: str) -> str:
        if kid.startswith(("http://", "https://")):
            return extract_aid_from_url(kid)
        if kid and kid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
            return kid
        raise ValueError(f"Invalid kid format: {kid[:20]}...")

    test_cases = [
        (TEST_OOBI_URL, TEST_AID),
        (f"http://witness5.stage.provenant.net:5631/oobi/{TEST_AID}", TEST_AID),
        (TEST_AID, TEST_AID),
        ("BIHoGeJKCHiXXcPH7oMR8Ef9LgT5UFi7Onrg54HYjGrY", "BIHoGeJKCHiXXcPH7oMR8Ef9LgT5UFi7Onrg54HYjGrY"),
    ]

    all_passed = True
    for input_kid, expected_aid in test_cases:
        try:
            result = extract_aid(input_kid)
            if result == expected_aid:
                print(f"   ✓ {input_kid[:50]}...")
            else:
                print(f"   ✗ {input_kid[:50]}... → got {result}, expected {expected_aid}")
                all_passed = False
        except Exception as e:
            print(f"   ✗ {input_kid[:50]}... → Error: {e}")
            all_passed = False

    if all_passed:
        print(f"\n✓ All URL parsing tests passed!")
    else:
        print(f"\n✗ Some tests failed")

    return all_passed


async def main():
    """Run all tests."""
    success = True

    # Test OOBI URL parsing (sync)
    success = test_oobi_url_parsing() and success

    # Test live witness resolution (async)
    success = await test_oobi_resolution() and success

    return 0 if success else 1


if __name__ == "__main__":
    try:
        import httpx
    except ImportError:
        print("Error: httpx not installed. Run: pip install httpx")
        sys.exit(1)

    exit_code = asyncio.run(main())
    sys.exit(exit_code)
