"""Tests for KEL chain validation.

Tests chain continuity and signature verification per PLAN.md:
- Chain continuity: prior_digest matches previous event's digest
- Signature validation: each event signed by keys from prior event
"""

import base64
import json
import pytest
import pysodium

from app.vvp.keri.kel_parser import (
    EventType,
    KELEvent,
    WitnessReceipt,
    validate_kel_chain,
    _compute_signing_input,
    _verify_signature,
)
from app.vvp.keri.exceptions import KELChainInvalidError


def generate_keypair():
    """Generate a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def sign_event(event_dict: dict, private_key: bytes) -> bytes:
    """Sign an event with a private key."""
    # Remove signature-related fields
    raw_copy = dict(event_dict)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)

    # Canonical JSON
    canonical = json.dumps(raw_copy, sort_keys=True, separators=(",", ":"))
    message = canonical.encode("utf-8")

    # Sign
    signature = pysodium.crypto_sign_detached(message, private_key)
    return signature


def encode_keri_key(pk: bytes) -> str:
    """Encode a public key in KERI format (B prefix for Ed25519)."""
    return "B" + base64.urlsafe_b64encode(pk).decode().rstrip("=")


def encode_keri_sig(sig: bytes) -> str:
    """Encode a signature in KERI format (0B prefix for indexed sig)."""
    return "0B" + base64.urlsafe_b64encode(sig).decode().rstrip("=")


def create_valid_kel() -> tuple:
    """Create a valid KEL with proper signatures and chain linkage.

    Returns:
        Tuple of (events, keypairs) where keypairs is list of (pk, sk).
    """
    # Generate keypairs
    pk1, sk1 = generate_keypair()
    pk2, sk2 = generate_keypair()

    # Inception event
    icp_dict = {
        "t": "icp",
        "s": "0",
        "p": "",
        "d": "ESAID_ICP",
        "k": [encode_keri_key(pk1)],
        "n": ["NEXT_KEY_DIGEST"],
        "bt": "0",
        "b": [],
    }
    icp_sig = sign_event(icp_dict, sk1)
    icp_dict["signatures"] = [encode_keri_sig(icp_sig)]

    icp_event = KELEvent(
        event_type=EventType.ICP,
        sequence=0,
        prior_digest="",
        digest="ESAID_ICP",
        signing_keys=[pk1],
        next_keys_digest="NEXT_KEY_DIGEST",
        toad=0,
        witnesses=[],
        signatures=[icp_sig],
        raw=icp_dict,
    )

    # Rotation event (signed by inception key)
    rot_dict = {
        "t": "rot",
        "s": "1",
        "p": "ESAID_ICP",  # Chain link
        "d": "ESAID_ROT",
        "k": [encode_keri_key(pk2)],
        "n": ["NEXT_KEY_DIGEST_2"],
        "bt": "0",
        "b": [],
    }
    rot_sig = sign_event(rot_dict, sk1)  # Signed by PRIOR key
    rot_dict["signatures"] = [encode_keri_sig(rot_sig)]

    rot_event = KELEvent(
        event_type=EventType.ROT,
        sequence=1,
        prior_digest="ESAID_ICP",
        digest="ESAID_ROT",
        signing_keys=[pk2],
        next_keys_digest="NEXT_KEY_DIGEST_2",
        toad=0,
        witnesses=[],
        signatures=[rot_sig],
        raw=rot_dict,
    )

    return [icp_event, rot_event], [(pk1, sk1), (pk2, sk2)]


class TestChainContinuity:
    """Test chain continuity validation."""

    def test_valid_chain_passes(self):
        """Valid chain with correct prior_digest references."""
        events, _ = create_valid_kel()
        # Should not raise
        validate_kel_chain(events)

    def test_empty_kel_raises(self):
        """Empty KEL raises error."""
        with pytest.raises(KELChainInvalidError, match="Empty KEL"):
            validate_kel_chain([])

    def test_kel_must_start_with_inception(self):
        """KEL must start with inception event."""
        pk, sk = generate_keypair()

        rot_dict = {
            "t": "rot",
            "s": "0",  # Wrong: rotation at seq 0
            "p": "PRIOR",
            "d": "SAID",
            "k": [encode_keri_key(pk)],
        }
        rot_sig = sign_event(rot_dict, sk)

        rot_event = KELEvent(
            event_type=EventType.ROT,
            sequence=0,
            prior_digest="PRIOR",
            digest="SAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[rot_sig],
            raw=rot_dict,
        )

        with pytest.raises(KELChainInvalidError, match="must start with inception"):
            validate_kel_chain([rot_event])

    def test_inception_must_be_sequence_zero(self):
        """Inception event must have sequence 0."""
        pk, sk = generate_keypair()

        icp_dict = {
            "t": "icp",
            "s": "1",  # Wrong: inception at seq 1
            "d": "SAID",
            "k": [encode_keri_key(pk)],
        }
        icp_sig = sign_event(icp_dict, sk)

        icp_event = KELEvent(
            event_type=EventType.ICP,
            sequence=1,  # Wrong
            prior_digest="",
            digest="SAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[icp_sig],
            raw=icp_dict,
        )

        with pytest.raises(KELChainInvalidError, match="sequence 0"):
            validate_kel_chain([icp_event])

    def test_sequence_gap_detected(self):
        """Detect gaps in sequence numbers."""
        events, keypairs = create_valid_kel()
        pk1, sk1 = keypairs[0]
        pk3, sk3 = generate_keypair()

        # Create event at seq 3 (skipping seq 2)
        ixn_dict = {
            "t": "ixn",
            "s": "3",  # Gap: missing seq 2
            "p": "ESAID_ROT",
            "d": "ESAID_IXN",
            "a": [],
        }
        ixn_sig = sign_event(ixn_dict, keypairs[1][1])  # Sign with rot key

        ixn_event = KELEvent(
            event_type=EventType.IXN,
            sequence=3,
            prior_digest="ESAID_ROT",
            digest="ESAID_IXN",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[ixn_sig],
            raw=ixn_dict,
        )

        events.append(ixn_event)

        with pytest.raises(KELChainInvalidError, match="Sequence gap"):
            validate_kel_chain(events)

    def test_broken_chain_link_detected(self):
        """Detect broken prior_digest chain."""
        events, keypairs = create_valid_kel()

        # Corrupt the prior_digest
        events[1].prior_digest = "WRONG_DIGEST"

        with pytest.raises(KELChainInvalidError, match="Chain break"):
            validate_kel_chain(events)


class TestSignatureValidation:
    """Test event signature validation."""

    def test_valid_self_signed_inception(self):
        """Inception event self-signed by its own keys."""
        pk, sk = generate_keypair()

        icp_dict = {
            "t": "icp",
            "s": "0",
            "d": "SAID",
            "k": [encode_keri_key(pk)],
        }
        icp_sig = sign_event(icp_dict, sk)

        icp_event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[icp_sig],
            raw=icp_dict,
        )

        # Should not raise
        validate_kel_chain([icp_event])

    def test_inception_without_signature_raises(self):
        """Inception without signature raises error."""
        pk, sk = generate_keypair()

        icp_event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[],  # No signatures
            raw={"t": "icp", "s": "0", "d": "SAID", "k": [encode_keri_key(pk)]},
        )

        with pytest.raises(KELChainInvalidError, match="no signatures"):
            validate_kel_chain([icp_event])

    def test_inception_with_invalid_signature_raises(self):
        """Inception with wrong signature raises error."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()

        icp_dict = {
            "t": "icp",
            "s": "0",
            "d": "SAID",
            "k": [encode_keri_key(pk1)],
        }
        # Sign with wrong key
        wrong_sig = sign_event(icp_dict, sk2)

        icp_event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[pk1],  # Key doesn't match signer
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[wrong_sig],
            raw=icp_dict,
        )

        with pytest.raises(KELChainInvalidError, match="invalid self-signature"):
            validate_kel_chain([icp_event])

    def test_rotation_signed_by_prior_keys(self):
        """Rotation must be signed by prior establishment keys."""
        events, keypairs = create_valid_kel()
        # create_valid_kel() creates a valid chain - should pass
        validate_kel_chain(events)

    def test_rotation_signed_by_wrong_key_raises(self):
        """Rotation signed by its own new key (not prior) raises error."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()

        # Inception
        icp_dict = {
            "t": "icp",
            "s": "0",
            "d": "ESAID_ICP",
            "k": [encode_keri_key(pk1)],
        }
        icp_sig = sign_event(icp_dict, sk1)

        icp_event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID_ICP",
            signing_keys=[pk1],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[icp_sig],
            raw=icp_dict,
        )

        # Rotation - INCORRECTLY signed by new key instead of prior key
        rot_dict = {
            "t": "rot",
            "s": "1",
            "p": "ESAID_ICP",
            "d": "ESAID_ROT",
            "k": [encode_keri_key(pk2)],
        }
        wrong_sig = sign_event(rot_dict, sk2)  # Wrong: should be sk1

        rot_event = KELEvent(
            event_type=EventType.ROT,
            sequence=1,
            prior_digest="ESAID_ICP",
            digest="ESAID_ROT",
            signing_keys=[pk2],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[wrong_sig],
            raw=rot_dict,
        )

        with pytest.raises(KELChainInvalidError, match="invalid signature"):
            validate_kel_chain([icp_event, rot_event])


class TestVerifySignature:
    """Test low-level signature verification."""

    def test_verify_valid_signature(self):
        """Verify a valid Ed25519 signature."""
        pk, sk = generate_keypair()
        message = b"test message"
        signature = pysodium.crypto_sign_detached(message, sk)

        assert _verify_signature(message, signature, pk)

    def test_verify_invalid_signature(self):
        """Reject invalid signature."""
        pk, sk = generate_keypair()
        message = b"test message"
        signature = b"X" * 64  # Invalid signature

        assert not _verify_signature(message, signature, pk)

    def test_verify_wrong_key(self):
        """Reject signature with wrong key."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()

        message = b"test message"
        signature = pysodium.crypto_sign_detached(message, sk1)

        assert not _verify_signature(message, signature, pk2)

    def test_verify_wrong_message(self):
        """Reject signature with modified message."""
        pk, sk = generate_keypair()
        message = b"test message"
        signature = pysodium.crypto_sign_detached(message, sk)

        assert not _verify_signature(b"different message", signature, pk)

    def test_verify_short_key_returns_false(self):
        """Short key returns False (not exception)."""
        assert not _verify_signature(b"msg", b"sig" * 21, b"short")

    def test_verify_short_signature_returns_false(self):
        """Short signature returns False (not exception)."""
        pk, _ = generate_keypair()
        assert not _verify_signature(b"msg", b"short", pk)


class TestComputeSigningInput:
    """Test signing input computation."""

    def test_removes_signatures_field(self):
        """Signing input excludes signatures field."""
        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            signatures=[b"sig"],
            raw={"t": "icp", "s": "0", "d": "SAID", "signatures": ["sig"]},
        )

        signing_input = _compute_signing_input(event)
        data = json.loads(signing_input)

        assert "signatures" not in data

    def test_deterministic_serialization(self):
        """Signing input is deterministically serialized."""
        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            raw={"z": "last", "a": "first", "t": "icp"},
        )

        input1 = _compute_signing_input(event)
        input2 = _compute_signing_input(event)

        assert input1 == input2
        # Keys should be sorted
        assert b'"a":"first"' in input1
