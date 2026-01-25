"""
CESR Stream Parser.

Parses CESR (Composable Event Streaming Representation) encoded streams
containing KERI events and their attachments (signatures, receipts).

This module provides parsing for the subset of CESR needed for VVP
verification, specifically:
- Controller signatures (-A count code)
- Witness receipts (-C count code for non-transferable)
- Attachment groups (-V count code)

Count code reference (CESR V1.0):
- `-A##`: Controller indexed signatures
- `-B##`: Witness indexed signatures
- `-C##`: Non-transferable receipt couples
- `-D##`: Transferable receipt quadruples
- `-V##`: Attachment group

Where `##` is a 2-character base64 count value.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from .exceptions import ResolutionFailedError


class CountCode(Enum):
    """CESR V1 count codes for KEL attachments."""

    CONTROLLER_IDX_SIGS = "-A"  # Indexed controller signatures
    WITNESS_IDX_SIGS = "-B"  # Indexed witness signatures
    NON_TRANS_RECEIPT = "-C"  # Non-transferable receipt couples
    TRANS_RECEIPT_QUAD = "-D"  # Transferable receipt quadruples
    ATTACHMENT_GROUP = "-V"  # Attachment group


# Count code sizes for CESR V1.0
# (hard_size, soft_size, full_size)
COUNT_CODE_SIZES = {
    "-A": (2, 2, 4),
    "-B": (2, 2, 4),
    "-C": (2, 2, 4),
    "-D": (2, 2, 4),
    "-E": (2, 2, 4),
    "-F": (2, 2, 4),
    "-G": (2, 2, 4),
    "-H": (2, 2, 4),
    "-I": (2, 2, 4),
    "-V": (2, 2, 4),
    "--V": (3, 5, 8),
    "-_AAA": (5, 3, 8),  # KERI ACDC Protocol Stack version
}

# Signature sizes by derivation code (bytes)
# These are the raw sizes before base64 encoding
SIGNATURE_SIZES = {
    "0A": 64,  # Ed25519 indexed signature (index 0)
    "0B": 64,  # Ed25519 indexed signature (index 1)
    "0C": 64,  # Ed25519 indexed signature (index 2)
    "0D": 64,  # Ed25519 indexed signature
    "1AAA": 64,  # Ed25519 current only indexed signature
    "2AAA": 64,  # Ed25519 both same indexed signature
    "AA": 64,  # Ed25519 non-indexed (used in receipts)
}


@dataclass
class CESRAttachment:
    """Parsed CESR attachment."""

    code: CountCode
    count: int
    data: bytes


@dataclass
class WitnessReceipt:
    """Receipt from a witness confirming an event."""

    witness_aid: str
    signature: bytes


@dataclass
class CESRMessage:
    """Parsed CESR message with attachments."""

    event_bytes: bytes  # Raw JSON event bytes
    event_dict: dict  # Parsed event dictionary
    controller_sigs: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: bytes = b""  # Original raw bytes for debugging


def _b64_to_int(b64_chars: str) -> int:
    """Convert base64 characters to integer.

    CESR uses a specific base64 alphabet: A-Z, a-z, 0-9, -, _
    Each character represents 6 bits.

    Args:
        b64_chars: Base64 encoded characters.

    Returns:
        Integer value.
    """
    B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    value = 0
    for char in b64_chars:
        value = value * 64 + B64_CHARS.index(char)
    return value


def _parse_count_code(data: bytes, offset: int) -> Tuple[str, int, int]:
    """Parse a CESR count code at the given offset.

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (code, count, new_offset).

    Raises:
        ResolutionFailedError: If count code is invalid.
    """
    if offset >= len(data):
        raise ResolutionFailedError("Unexpected end of CESR stream")

    # Check for version string first
    if data[offset : offset + 5] == b"-_AAA":
        # KERI ACDC version string, 8 chars total
        if offset + 8 > len(data):
            raise ResolutionFailedError("Truncated CESR version string")
        version_data = data[offset : offset + 8].decode("ascii")
        # Return as special marker
        return "-_AAA", 0, offset + 8

    # Check for big count codes (3-char hard code)
    if data[offset : offset + 2] == b"--":
        hard = data[offset : offset + 3].decode("ascii")
        if hard in COUNT_CODE_SIZES:
            _, ss, fs = COUNT_CODE_SIZES[hard]
            if offset + fs > len(data):
                raise ResolutionFailedError(f"Truncated count code {hard}")
            soft = data[offset + 3 : offset + fs].decode("ascii")
            count = _b64_to_int(soft)
            return hard, count, offset + fs

    # Regular count codes (2-char hard code)
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated count code")

    hard = data[offset : offset + 2].decode("ascii")
    if hard not in COUNT_CODE_SIZES:
        raise ResolutionFailedError(f"Unknown count code: {hard}")

    _, ss, fs = COUNT_CODE_SIZES[hard]
    if offset + fs > len(data):
        raise ResolutionFailedError(f"Truncated count code {hard}")

    soft = data[offset + 2 : offset + fs].decode("ascii")
    count = _b64_to_int(soft)

    return hard, count, offset + fs


def _parse_indexed_signature(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Parse an indexed signature primitive.

    Indexed signatures have a 2-4 character derivation code followed by
    base64-encoded signature data.

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (signature_bytes, new_offset).
    """
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated signature")

    # Check common derivation codes
    # Two-char codes like 0A, 0B, AA have different total lengths
    code_2 = data[offset : offset + 2].decode("ascii")

    if code_2 in ("0A", "0B", "0C", "0D", "AA"):
        # Ed25519 signature: 64 bytes raw = 88 chars base64 (with 2-char code)
        # Total primitive size is 88 chars
        sig_end = offset + 88
        if sig_end > len(data):
            raise ResolutionFailedError("Truncated Ed25519 signature")
        sig_b64 = data[offset + 2 : sig_end].decode("ascii")

        # Decode from base64
        import base64

        # Add padding if needed
        padded = sig_b64 + "=" * (-len(sig_b64) % 4)
        try:
            sig_bytes = base64.urlsafe_b64decode(padded)
        except Exception as e:
            raise ResolutionFailedError(f"Invalid signature encoding: {e}")

        return sig_bytes, sig_end

    # 4-char codes like 1AAA, 2AAA
    if offset + 4 <= len(data):
        code_4 = data[offset : offset + 4].decode("ascii")
        if code_4 in ("1AAA", "2AAA"):
            # Ed25519 indexed: total 88 chars
            sig_end = offset + 88
            if sig_end > len(data):
                raise ResolutionFailedError("Truncated Ed25519 indexed signature")
            sig_b64 = data[offset + 4 : sig_end].decode("ascii")

            import base64

            padded = sig_b64 + "=" * (-len(sig_b64) % 4)
            try:
                sig_bytes = base64.urlsafe_b64decode(padded)
            except Exception as e:
                raise ResolutionFailedError(f"Invalid signature encoding: {e}")

            return sig_bytes, sig_end

    raise ResolutionFailedError(f"Unknown signature derivation code at offset {offset}")


def _parse_receipt_couple(data: bytes, offset: int) -> Tuple[WitnessReceipt, int]:
    """Parse a non-transferable receipt couple.

    A receipt couple consists of:
    1. Witness AID (prefix primitive)
    2. Signature (signature primitive)

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (WitnessReceipt, new_offset).
    """
    if offset + 1 > len(data):
        raise ResolutionFailedError("Truncated receipt couple")

    # Parse witness AID (non-transferable prefix)
    # B-prefix AIDs are 44 chars total
    aid_char = chr(data[offset])
    if aid_char == "B":
        # Non-transferable Ed25519 prefix, 44 chars
        aid_end = offset + 44
        if aid_end > len(data):
            raise ResolutionFailedError("Truncated witness AID")
        witness_aid = data[offset:aid_end].decode("ascii")
        offset = aid_end
    elif aid_char == "D":
        # Transferable Ed25519 prefix, 44 chars
        aid_end = offset + 44
        if aid_end > len(data):
            raise ResolutionFailedError("Truncated witness AID")
        witness_aid = data[offset:aid_end].decode("ascii")
        offset = aid_end
    else:
        raise ResolutionFailedError(f"Unknown AID prefix: {aid_char}")

    # Parse signature
    sig_bytes, offset = _parse_indexed_signature(data, offset)

    return WitnessReceipt(witness_aid=witness_aid, signature=sig_bytes), offset


def _find_json_end(data: bytes, offset: int) -> int:
    """Find the end of a JSON object in the byte stream.

    JSON events in CESR are terminated by either:
    1. A count code (starts with '-')
    2. End of stream

    Args:
        data: CESR byte stream.
        offset: Start of JSON object.

    Returns:
        Offset of first byte after JSON object.
    """
    # Simple approach: track brace depth
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

    # If we reach here without finding closing brace
    if depth > 0:
        raise ResolutionFailedError("Unterminated JSON object in CESR stream")

    return i


def parse_cesr_stream(data: bytes) -> List[CESRMessage]:
    """Parse a CESR stream into messages with attachments.

    Args:
        data: Raw CESR byte stream.

    Returns:
        List of CESRMessage objects.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
    if not data:
        return []

    messages = []
    offset = 0

    # Check for CESR version marker
    if data[:5] == b"-_AAA":
        _, _, offset = _parse_count_code(data, 0)

    while offset < len(data):
        # Skip whitespace
        while offset < len(data) and data[offset : offset + 1] in (b" ", b"\n", b"\r", b"\t"):
            offset += 1

        if offset >= len(data):
            break

        # Check if this is a JSON event or attachment
        if data[offset : offset + 1] == b"{":
            # Parse JSON event
            json_end = _find_json_end(data, offset)
            event_bytes = data[offset:json_end]
            offset = json_end

            try:
                event_dict = json.loads(event_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ResolutionFailedError(f"Invalid JSON in CESR stream: {e}")

            # Create message
            message = CESRMessage(
                event_bytes=event_bytes, event_dict=event_dict, raw=event_bytes
            )

            # Parse following attachments
            while offset < len(data):
                # Skip whitespace
                while offset < len(data) and data[offset : offset + 1] in (
                    b" ",
                    b"\n",
                    b"\r",
                    b"\t",
                ):
                    offset += 1

                if offset >= len(data):
                    break

                # Check for count code
                if data[offset : offset + 1] != b"-":
                    # Not a count code, might be next event
                    break

                # Parse count code
                try:
                    code, count, new_offset = _parse_count_code(data, offset)
                except ResolutionFailedError:
                    break

                offset = new_offset

                # Handle different attachment types
                if code == "-A":
                    # Controller indexed signatures
                    for _ in range(count):
                        sig, offset = _parse_indexed_signature(data, offset)
                        message.controller_sigs.append(sig)

                elif code == "-B":
                    # Witness indexed signatures (similar to controller)
                    for _ in range(count):
                        sig, offset = _parse_indexed_signature(data, offset)
                        # Witness indexed sigs go into receipts with empty AID
                        # (The AID is known from context)
                        message.witness_receipts.append(
                            WitnessReceipt(witness_aid="", signature=sig)
                        )

                elif code == "-C":
                    # Non-transferable receipt couples
                    for _ in range(count):
                        receipt, offset = _parse_receipt_couple(data, offset)
                        message.witness_receipts.append(receipt)

                elif code == "-D":
                    # Transferable receipt quadruples - skip for now
                    # These contain: pre + snu + dig + sig
                    # Would need more complex parsing
                    break

                elif code == "-V" or code == "--V":
                    # Attachment group - contains nested attachments
                    # For now, just continue parsing
                    pass

                elif code == "-_AAA":
                    # Version marker, skip
                    pass

                else:
                    # Unknown code, stop parsing attachments
                    break

            messages.append(message)

        elif data[offset : offset + 1] == b"-":
            # Standalone count code (attachment group)
            code, count, new_offset = _parse_count_code(data, offset)
            offset = new_offset
            # Skip the attachment group for now
        else:
            # Unknown content
            raise ResolutionFailedError(
                f"Unexpected byte in CESR stream at offset {offset}: {data[offset:offset+10]!r}"
            )

    return messages


def is_cesr_stream(data: bytes) -> bool:
    """Check if data appears to be a CESR stream.

    Args:
        data: Raw byte data.

    Returns:
        True if data appears to be CESR encoded.
    """
    if not data:
        return False

    # CESR version marker
    if data[:5] == b"-_AAA":
        return True

    # CESR count code
    if data[0:1] == b"-":
        return True

    # JSON with CESR attachments
    if data[0:1] == b"{":
        # Look for count code after JSON
        try:
            json_end = _find_json_end(data, 0)
            if json_end < len(data):
                # Check for count code after JSON
                remaining = data[json_end:].lstrip()
                if remaining and remaining[0:1] == b"-":
                    return True
        except ResolutionFailedError:
            pass

    return False
