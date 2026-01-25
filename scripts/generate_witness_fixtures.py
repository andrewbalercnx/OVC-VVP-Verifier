#!/usr/bin/env python3
"""Generate witness receipt test fixtures with actual signatures.

This script creates fixtures for testing witness receipt validation.
The fixtures include:
- An event signed by controller
- Witness receipts with valid signatures
- Witness receipts with invalid signatures (for negative tests)
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

# Ensure we can import from the app
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import pysodium
except ImportError:
    print("ERROR: pysodium is required. Install with: pip install pysodium")
    sys.exit(1)

try:
    import blake3
except ImportError:
    print("ERROR: blake3 is required. Install with: pip install blake3")
    sys.exit(1)


def generate_keypair(seed: bytes) -> tuple:
    """Generate Ed25519 keypair from seed."""
    # Ed25519 requires 32-byte seed
    if len(seed) != 32:
        seed = hashlib.sha256(seed).digest()

    public_key, secret_key = pysodium.crypto_sign_seed_keypair(seed)
    return public_key, secret_key


def sign_message(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message with Ed25519."""
    return pysodium.crypto_sign_detached(message, secret_key)


def encode_b_prefix_aid(public_key: bytes) -> str:
    """Encode a public key as a non-transferable (B-prefix) AID."""
    # B-prefix for non-transferable Ed25519: 44 chars total
    b64 = base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")
    return "B" + b64


def cesr_encode(raw: bytes, code: str = "E") -> str:
    """CESR-encode bytes with derivation code."""
    rs = len(raw)
    ls = 0  # lead bytes for 'E' code
    ps = (3 - ((rs + ls) % 3)) % 3
    prepadded = bytes([0] * (ps + ls)) + raw
    b64 = base64.urlsafe_b64encode(prepadded).decode("ascii")
    trimmed = b64[ps:].rstrip("=")
    return code + trimmed


def compute_said(event: dict, said_field: str = "d") -> str:
    """Compute SAID using canonical serialization."""
    # Import the canonical serializer
    from app.vvp.keri.keri_canonical import most_compact_form

    canonical_bytes = most_compact_form(event, said_field=said_field)
    digest = blake3.blake3(canonical_bytes).digest()
    return cesr_encode(digest, code="E")


def main():
    output_dir = Path(__file__).parent.parent / "tests" / "fixtures" / "keri"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate deterministic keys for witnesses
    witness_seeds = [
        b"witness_seed_0__________________",  # Will be hashed to 32 bytes
        b"witness_seed_1__________________",
        b"witness_seed_2__________________",
    ]

    witnesses = []
    for i, seed in enumerate(witness_seeds):
        pub, sec = generate_keypair(seed)
        aid = encode_b_prefix_aid(pub)
        witnesses.append({
            "index": i,
            "aid": aid,
            "public_key": pub,
            "secret_key": sec,
            "public_key_hex": pub.hex(),
        })

    # Generate controller keypair
    controller_pub, controller_sec = generate_keypair(b"controller_seed_for_witness_test")
    controller_aid_b64 = base64.urlsafe_b64encode(controller_pub).decode("ascii").rstrip("=")
    controller_aid = "D" + controller_aid_b64

    # Create an ICP event with witnesses
    event = {
        "v": "KERI10JSON000000_",  # Size will be updated
        "t": "icp",
        "d": "",  # Will be computed
        "i": controller_aid,
        "s": "0",
        "kt": 1,
        "k": [controller_aid],
        "nt": 1,
        "n": ["E" + "_" * 43],  # Placeholder next key digest
        "bt": 2,  # Witness threshold
        "b": [w["aid"] for w in witnesses],
        "c": [],
        "a": []
    }

    # Compute SAID
    event["d"] = compute_said(event)

    # Update version string with size
    from app.vvp.keri.keri_canonical import canonical_serialize
    canonical_bytes = canonical_serialize(event)
    size_hex = f"{len(canonical_bytes):06x}"
    event["v"] = f"KERI10JSON{size_hex}_"

    # Recompute SAID with correct version string
    event["d"] = compute_said(event)
    canonical_bytes = canonical_serialize(event)

    # Sign the event as controller
    controller_sig = sign_message(canonical_bytes, controller_sec)

    # Create witness receipts
    valid_receipts = []
    for w in witnesses:
        sig = sign_message(canonical_bytes, w["secret_key"])
        valid_receipts.append({
            "witness_aid": w["aid"],
            "signature": sig,
            "signature_hex": sig.hex(),
        })

    # Create an invalid signature for testing
    invalid_sig = bytes([0] * 64)  # All zeros - invalid signature
    invalid_receipt = {
        "witness_aid": witnesses[0]["aid"],
        "signature": invalid_sig,
        "signature_hex": invalid_sig.hex(),
    }

    # Build fixture
    fixture = {
        "description": "ICP event with witness receipts for validation testing",
        "event": event,
        "canonical_bytes_hex": canonical_bytes.hex(),
        "controller": {
            "aid": controller_aid,
            "public_key_hex": controller_pub.hex(),
            "signature_hex": controller_sig.hex(),
        },
        "witnesses": [
            {
                "index": w["index"],
                "aid": w["aid"],
                "public_key_hex": w["public_key_hex"],
            }
            for w in witnesses
        ],
        "valid_receipts": [
            {
                "witness_aid": r["witness_aid"],
                "signature_hex": r["signature_hex"],
            }
            for r in valid_receipts
        ],
        "invalid_receipt": {
            "witness_aid": invalid_receipt["witness_aid"],
            "signature_hex": invalid_receipt["signature_hex"],
            "reason": "All-zeros signature that should fail validation",
        },
        "toad": 2,
    }

    # Write fixture
    output_file = output_dir / "witness_receipts_keripy.json"
    with open(output_file, "w") as f:
        json.dump(fixture, f, indent=2)

    print(f"Generated: {output_file}")
    print(f"  Event SAID: {event['d']}")
    print(f"  Witnesses: {len(witnesses)}")
    print(f"  Valid receipts: {len(valid_receipts)}")
    print(f"  Threshold (toad): {event['bt']}")


if __name__ == "__main__":
    main()
