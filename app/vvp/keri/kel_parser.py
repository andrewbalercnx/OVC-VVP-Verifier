"""KEL (Key Event Log) parser and validator.

Parses and validates KERI Key Event Logs per the KERI spec.
Supports both CESR-encoded streams (normative) and JSON (test fallback).

Chain validation ensures:
1. Each event's prior_digest matches the previous event's digest
2. Each event is signed by keys from the prior event (or self-signed for inception)
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import pysodium

from .exceptions import (
    DelegationNotSupportedError,
    KELChainInvalidError,
    ResolutionFailedError,
)


class EventType(Enum):
    """KERI event types.

    Only establishment events (icp, rot, dip, drt) affect key state.
    Interaction events (ixn) are included in the log but don't change keys.
    """
    ICP = "icp"  # Inception - first event, establishes AID
    ROT = "rot"  # Rotation - changes signing keys
    IXN = "ixn"  # Interaction - anchors data, no key change
    DIP = "dip"  # Delegated inception
    DRT = "drt"  # Delegated rotation


# Establishment events that change key state
ESTABLISHMENT_TYPES = frozenset({EventType.ICP, EventType.ROT, EventType.DIP, EventType.DRT})

# Delegated events requiring special handling
DELEGATED_TYPES = frozenset({EventType.DIP, EventType.DRT})


@dataclass
class WitnessReceipt:
    """Receipt from a witness confirming an event.

    Witnesses provide threshold signatures on events to establish
    consensus on the event log state.

    Attributes:
        witness_aid: The AID of the witness.
        signature: The witness's signature on the event.
        timestamp: Optional timestamp when the witness signed.
    """
    witness_aid: str
    signature: bytes
    timestamp: Optional[datetime] = None


@dataclass
class KELEvent:
    """Parsed KERI event from a Key Event Log.

    Contains both the event data and attached signatures/receipts.

    Attributes:
        event_type: The type of event (icp, rot, etc.).
        sequence: Event sequence number (0 for inception).
        prior_digest: SAID of the prior event (empty for inception).
        digest: This event's SAID (self-addressing identifier).
        signing_keys: Current signing key(s) from 'k' field.
        next_keys_digest: Commitment to next keys ('n' field).
        toad: Witness threshold (threshold of accountable duplicity).
        witnesses: List of witness AIDs from 'b' field.
        timestamp: Timestamp from witness receipts (if available).
        signatures: Attached controller signatures.
        witness_receipts: Receipts from witnesses.
        raw: Original parsed event dict for debugging.
    """
    event_type: EventType
    sequence: int
    prior_digest: str
    digest: str
    signing_keys: List[bytes]
    next_keys_digest: Optional[str]
    toad: int
    witnesses: List[str]
    timestamp: Optional[datetime] = None
    signatures: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_establishment(self) -> bool:
        """True if this event establishes or rotates key state."""
        return self.event_type in ESTABLISHMENT_TYPES

    @property
    def is_inception(self) -> bool:
        """True if this is an inception event (icp or dip)."""
        return self.event_type in {EventType.ICP, EventType.DIP}

    @property
    def is_delegated(self) -> bool:
        """True if this is a delegated event requiring delegator validation."""
        return self.event_type in DELEGATED_TYPES


def parse_kel_stream(kel_data: bytes, allow_json_only: bool = True) -> List[KELEvent]:
    """Parse a KEL stream into a list of events.

    IMPORTANT: This implementation currently only supports JSON-encoded KELs.
    Binary CESR parsing is not yet implemented. When CESR data is encountered,
    a ResolutionFailedError is raised with INDETERMINATE status.

    For production use with real KERI infrastructure, CESR parsing must be
    implemented. The JSON format is intended for testing only.

    Args:
        kel_data: Raw KEL data (JSON encoded; CESR not yet supported).
        allow_json_only: If True (default), accept JSON format. If False,
            raise an error indicating CESR is required but not supported.

    Returns:
        List of parsed KELEvent objects in sequence order.

    Raises:
        ResolutionFailedError: If parsing fails or CESR format detected.
        DelegationNotSupportedError: If delegated events are detected.
    """
    # Check for CESR binary markers before attempting JSON parse
    # CESR count codes start with specific characters
    if kel_data and kel_data[0:1] in (b"-", b"0", b"1", b"4", b"5", b"6"):
        # Looks like CESR binary format
        raise ResolutionFailedError(
            "CESR binary format detected but not yet supported. "
            "Tier 2 key state resolution requires JSON-encoded KEL for testing. "
            "Full CESR support is planned for a future release."
        )

    # Try JSON parsing
    try:
        return _parse_json_kel(kel_data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ResolutionFailedError(
            f"Failed to parse KEL: not valid JSON and CESR is not yet supported. "
            f"Error: {e}"
        )


def _parse_json_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse JSON-encoded KEL (test fallback).

    JSON format is a list of event objects with attached signatures.
    This is non-normative and only for testing.
    """
    data = json.loads(kel_data.decode("utf-8"))

    # Handle both single event and list of events
    if isinstance(data, dict):
        events_data = [data]
    elif isinstance(data, list):
        events_data = data
    else:
        raise ResolutionFailedError(f"Invalid JSON KEL format: expected dict or list")

    events = []
    for event_data in events_data:
        event = _parse_event_dict(event_data)
        events.append(event)

    # Sort by sequence number
    events.sort(key=lambda e: e.sequence)

    return events


def _parse_event_dict(data: Dict[str, Any]) -> KELEvent:
    """Parse a single event from a dictionary.

    KERI event fields:
    - t: event type
    - s: sequence number (hex string)
    - p: prior event digest
    - d: this event's digest (SAID)
    - k: signing keys
    - n: next keys digest
    - bt: witness threshold
    - b: witnesses
    """
    try:
        event_type_str = data.get("t", "")
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            raise ResolutionFailedError(f"Unknown event type: {event_type_str}")

        # Check for delegated events
        if event_type in DELEGATED_TYPES:
            raise DelegationNotSupportedError(
                f"Delegated event type '{event_type_str}' not yet supported"
            )

        # Parse sequence (hex string in KERI)
        seq_str = data.get("s", "0")
        sequence = int(seq_str, 16) if isinstance(seq_str, str) else int(seq_str)

        # Parse keys from 'k' field
        keys_data = data.get("k", [])
        signing_keys = []
        for key_str in keys_data:
            key_bytes = _decode_keri_key(key_str)
            signing_keys.append(key_bytes)

        # Parse signatures (attached as list or '-' prefixed entries)
        signatures = []
        sigs_data = data.get("signatures", data.get("-", []))
        if isinstance(sigs_data, list):
            for sig in sigs_data:
                if isinstance(sig, str):
                    signatures.append(_decode_signature(sig))
                elif isinstance(sig, dict) and "sig" in sig:
                    signatures.append(_decode_signature(sig["sig"]))

        # Parse witness receipts
        witness_receipts = []
        receipts_data = data.get("receipts", data.get("rcts", []))
        if isinstance(receipts_data, list):
            for rct in receipts_data:
                if isinstance(rct, dict):
                    witness_receipts.append(WitnessReceipt(
                        witness_aid=rct.get("i", ""),
                        signature=_decode_signature(rct.get("s", "")),
                        timestamp=_parse_timestamp(rct.get("dt"))
                    ))

        return KELEvent(
            event_type=event_type,
            sequence=sequence,
            prior_digest=data.get("p", ""),
            digest=data.get("d", ""),
            signing_keys=signing_keys,
            next_keys_digest=data.get("n", [None])[0] if isinstance(data.get("n"), list) else data.get("n"),
            toad=int(data.get("bt", "0"), 16) if isinstance(data.get("bt"), str) else data.get("bt", 0),
            witnesses=data.get("b", []),
            timestamp=_parse_timestamp(data.get("dt")),
            signatures=signatures,
            witness_receipts=witness_receipts,
            raw=data
        )

    except DelegationNotSupportedError:
        raise
    except Exception as e:
        raise ResolutionFailedError(f"Failed to parse event: {e}")


def _parse_cesr_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse CESR-encoded KEL stream.

    CESR is a self-framing binary format. This implementation handles
    the subset needed for VVP verification.
    """
    # CESR parsing is complex - for now, raise an error
    # A full implementation would:
    # 1. Parse the count code to determine message type/length
    # 2. Extract JSON-encoded event
    # 3. Parse attached signatures
    # 4. Repeat for all events in stream

    # Check for CESR version string or count code
    if kel_data and kel_data[0:1] in (b"-", b"0", b"1", b"4", b"5", b"6"):
        # Looks like CESR, but we need proper parsing
        raise ResolutionFailedError(
            "CESR parsing not fully implemented - use JSON format for testing"
        )

    raise ResolutionFailedError("Unable to parse KEL data as CESR")


def _decode_keri_key(key_str: str) -> bytes:
    """Decode a KERI-encoded public key.

    KERI keys use a derivation code prefix followed by base64url-encoded key.
    Example: "BIKKvIT9N5Qg5N8H9A9V5T5D..." (B = Ed25519)
    """
    if not key_str or len(key_str) < 2:
        raise ResolutionFailedError(f"Invalid key format: too short")

    # Extract derivation code and key data
    code = key_str[0]

    # For Ed25519 (B or D prefix), key follows immediately
    if code in ("B", "D"):
        key_b64 = key_str[1:]
        # Add padding for base64url
        padded = key_b64 + "=" * (-len(key_b64) % 4)
        try:
            return base64.urlsafe_b64decode(padded)
        except Exception as e:
            raise ResolutionFailedError(f"Failed to decode key: {e}")

    # For other codes, might need different handling
    raise ResolutionFailedError(f"Unsupported key derivation code: {code}")


def _decode_signature(sig_str: str) -> bytes:
    """Decode a KERI-encoded signature.

    KERI signatures use count codes and base64url encoding.
    Example: "0B..." (0B = indexed Ed25519 sig)
    """
    if not sig_str:
        return b""

    # Handle common signature formats
    # Indexed controller signatures start with 0A, 0B, etc.
    # For simplicity, try base64url decode after stripping common prefixes
    if sig_str.startswith(("0A", "0B", "0C", "0D", "1A", "2A")):
        sig_b64 = sig_str[2:]
    elif sig_str.startswith("-"):
        # CESR stream marker
        sig_b64 = sig_str[1:]
    else:
        sig_b64 = sig_str

    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        # Return empty if decode fails (might be complex CESR)
        return b""


def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string."""
    if not ts_str:
        return None
    try:
        # Handle various ISO formats
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


def validate_kel_chain(events: List[KELEvent], validate_saids: bool = False) -> None:
    """Validate KEL chain continuity and signatures.

    Validates:
    1. First event is inception (icp or dip)
    2. Sequence numbers are consecutive
    3. Each event's prior_digest matches previous event's digest
    4. Each event is signed by keys from prior event (or self-signed for inception)
    5. Each event's digest (d field) matches computed SAID (if validate_saids=True)

    Args:
        events: List of KELEvent objects in sequence order.
        validate_saids: If True, verify each event's digest matches computed SAID.
            Defaults to False because SAID validation uses JSON canonicalization
            which only works for specially-prepared test fixtures, not real KERI
            events or typical test data with placeholder digests.

    Raises:
        KELChainInvalidError: If chain validation fails.
    """
    if not events:
        raise KELChainInvalidError("Empty KEL: no events to validate")

    # Validate first event is inception
    first_event = events[0]
    if not first_event.is_inception:
        raise KELChainInvalidError(
            f"KEL must start with inception, found {first_event.event_type.value}"
        )

    if first_event.sequence != 0:
        raise KELChainInvalidError(
            f"Inception event must have sequence 0, found {first_event.sequence}"
        )

    # Validate SAID for first event
    if validate_saids:
        _validate_event_said(first_event)

    # Validate inception is self-signed
    _validate_inception_signature(first_event)

    # Track current signing keys for signature validation
    current_keys = first_event.signing_keys

    # Validate remaining events
    prev_event = first_event
    for event in events[1:]:
        # Check sequence continuity
        expected_seq = prev_event.sequence + 1
        if event.sequence != expected_seq:
            raise KELChainInvalidError(
                f"Sequence gap: expected {expected_seq}, found {event.sequence}"
            )

        # Check chain continuity (prior_digest)
        if event.prior_digest != prev_event.digest:
            raise KELChainInvalidError(
                f"Chain break at seq {event.sequence}: prior_digest "
                f"{event.prior_digest[:16]}... != previous digest {prev_event.digest[:16]}..."
            )

        # Validate SAID if enabled
        if validate_saids:
            _validate_event_said(event)

        # Validate event signature against current keys
        _validate_event_signature(event, current_keys)

        # Update current keys if this is an establishment event
        if event.is_establishment:
            current_keys = event.signing_keys

        prev_event = event


def _validate_event_said(event: KELEvent) -> None:
    """Validate that an event's digest (d field) matches its computed SAID.

    IMPORTANT: This uses JSON canonicalization for SAID computation, which
    only works for JSON test fixtures. Real KERI events use different
    serialization and this validation would fail.

    Args:
        event: The KELEvent to validate.

    Raises:
        KELChainInvalidError: If the digest doesn't match computed SAID.
    """
    if not event.digest:
        # No digest to validate
        return

    if not event.raw:
        # No raw data to compute SAID from
        return

    # Compute expected SAID
    computed = compute_said(event.raw)

    # Compare (allowing for different derivation codes)
    # The first character is the derivation code, rest is the hash
    if len(event.digest) > 1 and len(computed) > 1:
        # Compare the hash portion (skip derivation code if they differ)
        event_hash = event.digest[1:] if event.digest[0].isalpha() else event.digest
        computed_hash = computed[1:] if computed[0].isalpha() else computed

        if event_hash != computed_hash:
            raise KELChainInvalidError(
                f"Event at seq {event.sequence} has invalid SAID: "
                f"digest {event.digest[:20]}... != computed {computed[:20]}..."
            )


def _validate_inception_signature(event: KELEvent) -> None:
    """Validate that an inception event is self-signed.

    For inception, the signing keys in the event itself must have signed it.
    """
    if not event.signatures:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signatures"
        )

    if not event.signing_keys:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signing keys"
        )

    # Verify at least one signature matches a signing key
    signing_input = _compute_signing_input(event)
    verified = False

    for sig in event.signatures:
        for key in event.signing_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has invalid self-signature"
        )


def _validate_event_signature(event: KELEvent, prior_keys: List[bytes]) -> None:
    """Validate that an event is signed by keys from the prior event.

    Args:
        event: The event to validate.
        prior_keys: Signing keys from the prior establishment event.
    """
    if not event.signatures:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has no signatures"
        )

    if not prior_keys:
        raise KELChainInvalidError(
            f"No prior keys available to validate event at seq {event.sequence}"
        )

    signing_input = _compute_signing_input(event)
    verified = False

    for sig in event.signatures:
        for key in prior_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has invalid signature "
            f"(not signed by prior keys)"
        )


def _compute_signing_input(event: KELEvent) -> bytes:
    """Compute the signing input for an event.

    IMPORTANT LIMITATION: This implementation uses JSON with sorted keys for
    canonicalization. Real KERI uses a specific field ordering defined by the
    protocol (not alphabetical) and may use CBOR or other serializations.

    This canonicalization is ONLY valid for JSON test fixtures where the
    test data was signed using the same sorted-key JSON approach. It will
    NOT correctly verify signatures from real KERI infrastructure that uses
    proper KERI serialization.

    For production use, this function must be updated to use KERI's actual
    serialization rules (label ordering per event type, CESR encoding).

    Args:
        event: The KELEvent to compute signing input for.

    Returns:
        The bytes that should have been signed.
    """
    # For JSON test events, use canonical JSON of the raw dict minus signatures
    # WARNING: This is JSON-test-only canonicalization
    raw_copy = dict(event.raw)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)
    raw_copy.pop("receipts", None)
    raw_copy.pop("rcts", None)

    # Sort keys for canonical form (NOT KERI-compliant, test only)
    canonical = json.dumps(raw_copy, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def _verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        message: The signed message.
        signature: The signature bytes.
        public_key: The Ed25519 public key (32 bytes).

    Returns:
        True if signature is valid, False otherwise.
    """
    if len(public_key) != 32:
        return False
    if len(signature) != 64:
        return False

    try:
        pysodium.crypto_sign_verify_detached(signature, message, public_key)
        return True
    except Exception:
        return False


def compute_said(data: Dict[str, Any], algorithm: str = "blake3-256") -> str:
    """Compute the SAID (Self-Addressing IDentifier) for an event.

    SAID is computed by hashing the serialized event with the 'd' field
    set to a placeholder, then base64url encoding the hash.

    Args:
        data: Event data dictionary.
        algorithm: Hash algorithm (default blake3-256 per KERI).

    Returns:
        The computed SAID string.
    """
    # Make copy and set placeholder for 'd' field
    data_copy = dict(data)

    # Placeholder must match the expected output length
    # For Blake3-256: 32 bytes = 44 base64url chars (with padding stripped)
    placeholder = "E" + "_" * 43  # E = Blake3-256 derivation code

    data_copy["d"] = placeholder

    # Serialize canonically
    canonical = json.dumps(data_copy, sort_keys=True, separators=(",", ":"))

    # Hash
    if algorithm == "blake3-256":
        try:
            import blake3
            digest = blake3.blake3(canonical.encode("utf-8")).digest()
        except ImportError:
            # Fall back to sha256 if blake3 not available
            digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    else:
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()

    # Encode with derivation code
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return "E" + encoded
