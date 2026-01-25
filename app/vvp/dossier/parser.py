"""ACDC JSON parsing per spec §6.1A.

Tier 1 implementation parses JSON structure. Tier 2 adds
full CESR parsing for native KERI formats with signature extraction.

ACDC field conventions:
- d: SAID (Self-Addressing Identifier)
- i: Issuer AID
- s: Schema SAID
- a: Attributes (dict or SAID string for compact form)
- e: Edges to other ACDCs
- r: Rules
"""

import json
from typing import Dict, List, Tuple

from .exceptions import ParseError
from .models import ACDCNode

# Required ACDC fields per spec §6.1A
REQUIRED_FIELDS = frozenset({"d", "i", "s"})


def parse_acdc(data: dict) -> ACDCNode:
    """Parse single ACDC from dict.

    Required fields (§6.1A):
    - d: SAID (Self-Addressing Identifier)
    - i: Issuer AID
    - s: Schema SAID

    Optional fields:
    - a: Attributes (dict or SAID string for compact form)
    - e: Edges to other ACDCs
    - r: Rules

    Args:
        data: Dict parsed from JSON

    Returns:
        ACDCNode with extracted fields

    Raises:
        ParseError: If required fields missing or invalid types
    """
    if not isinstance(data, dict):
        raise ParseError(f"ACDC must be object, got {type(data).__name__}")

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ParseError(f"Missing required ACDC fields: {sorted(missing)}")

    # Validate required field types
    said = data["d"]
    if not isinstance(said, str):
        raise ParseError(f"ACDC 'd' field must be string, got {type(said).__name__}")

    issuer = data["i"]
    if not isinstance(issuer, str):
        raise ParseError(f"ACDC 'i' field must be string, got {type(issuer).__name__}")

    schema = data["s"]
    if not isinstance(schema, str):
        raise ParseError(f"ACDC 's' field must be string, got {type(schema).__name__}")

    return ACDCNode(
        said=said,
        issuer=issuer,
        schema=schema,
        attributes=data.get("a"),
        edges=data.get("e"),
        rules=data.get("r"),
        raw=data,
    )


def _is_cesr_stream(data: bytes) -> bool:
    """Check if data appears to be a CESR stream (without heavy imports).

    Quick heuristic check to avoid importing full CESR parser for simple JSON.
    """
    if not data:
        return False

    # CESR version marker
    if data[:5] == b"-_AAA":
        return True

    # CESR count code at start
    if data[0:1] == b"-":
        return True

    # JSON with CESR attachments - look for count code after JSON
    if data[0:1] == b"{":
        # Find end of JSON object (simple brace counting)
        depth = 0
        in_string = False
        escape = False
        for i, b in enumerate(data):
            if escape:
                escape = False
                continue
            if b == ord("\\"):
                escape = True
                continue
            if b == ord('"'):
                in_string = not in_string
                continue
            if in_string:
                continue
            if b == ord("{"):
                depth += 1
            elif b == ord("}"):
                depth -= 1
                if depth == 0:
                    # Check for count code after JSON
                    remaining = data[i + 1 :].lstrip()
                    if remaining and remaining[0:1] == b"-":
                        return True
                    break

    return False


def parse_dossier(raw: bytes) -> Tuple[List[ACDCNode], Dict[str, bytes]]:
    """Parse dossier from raw bytes, extracting ACDCs and their signatures.

    Supports:
    - Single ACDC object: {...}
    - Array of ACDC objects: [{...}, {...}]
    - CESR stream with attachments: {...}-A##<sig>...

    For CESR format, signatures are extracted from the attachments and
    returned in a dict mapping SAID -> signature bytes.

    Args:
        raw: Raw bytes from HTTP response

    Returns:
        Tuple of (list of ACDCNode, dict mapping SAID -> signature bytes)

    Raises:
        ParseError: If parsing fails or structure is malformed
    """
    signatures: Dict[str, bytes] = {}

    # Check if this is a CESR stream with attachments
    if _is_cesr_stream(raw):
        # Lazy import to avoid triggering pysodium dependency chain
        # when not needed (e.g., for plain JSON dossiers in tests)
        import importlib

        cesr = importlib.import_module("app.vvp.keri.cesr")

        try:
            messages = cesr.parse_cesr_stream(raw)
        except Exception as e:
            raise ParseError(f"Failed to parse CESR stream: {e}")

        nodes = []
        for msg in messages:
            event = msg.event_dict
            # Check if this is an ACDC (has 'd' and 'i' fields)
            if "d" in event and "i" in event:
                try:
                    node = parse_acdc(event)
                    nodes.append(node)
                    # Extract first controller signature if present
                    if msg.controller_sigs:
                        signatures[node.said] = msg.controller_sigs[0]
                except ParseError:
                    # Skip non-ACDC events in the stream
                    continue

        if not nodes:
            raise ParseError("No ACDCs found in CESR stream")

        return nodes, signatures

    # Plain JSON format - no signatures
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")

    if isinstance(data, dict):
        return [parse_acdc(data)], signatures
    elif isinstance(data, list):
        if not data:
            raise ParseError("Empty ACDC array")
        return [parse_acdc(item) for item in data], signatures
    else:
        raise ParseError(f"Expected object or array, got {type(data).__name__}")
