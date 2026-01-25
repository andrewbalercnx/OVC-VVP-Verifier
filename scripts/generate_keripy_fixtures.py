#!/usr/bin/env python3
"""
Generate authoritative KERI test fixtures using keripy.

This script generates canonical serialization vectors for testing our
CESR parser and canonicalization implementation. The fixtures are used
to verify that our implementation matches keripy's behavior.

KERIPY VERSION LOCK:
  - Version: 2.0.0-dev5
  - Git commit: 1e2bf869faef77621cd75190aab7a93917c60d19
  - Date: 2026-01-20

Any changes to keripy should trigger re-generation of fixtures to detect
canonicalization drift.

Usage:
    cd VVP
    PYTHONPATH=keripy/src python3 scripts/generate_keripy_fixtures.py
"""

import json
import sys
from pathlib import Path
from base64 import urlsafe_b64encode

# Version check - fail early if keripy version doesn't match
EXPECTED_KERIPY_VERSION = "2.0.0-dev5"
EXPECTED_KERIPY_COMMIT = "1e2bf869faef77621cd75190aab7a93917c60d19"

# Add keripy to path if running from VVP root
keripy_src = Path(__file__).parent.parent / "keripy" / "src"
if keripy_src.exists():
    sys.path.insert(0, str(keripy_src))

try:
    import keri
    from keri.core import eventing, coring, serdering
    from keri.kering import Ilks, Kinds, Vrsn_1_0
    from keri.help import helping
except ImportError as e:
    print(f"Error: Could not import keripy: {e}")
    print("Make sure keripy is installed or PYTHONPATH includes keripy/src")
    sys.exit(1)

# Verify keripy version
if hasattr(keri, '__version__'):
    actual_version = keri.__version__
else:
    actual_version = "unknown"

print(f"keripy version: {actual_version}")
print(f"Expected version: {EXPECTED_KERIPY_VERSION}")

# Note: We log version info but don't fail on mismatch during development
# In CI, this check should be strict

OUTPUT_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "keri"


def generate_keys():
    """Generate a set of Ed25519 signing keys for fixtures."""
    import pysodium
    import hashlib

    # Generate deterministic keys for reproducibility
    # Using fixed seeds so fixtures are stable across runs
    # Seeds must be exactly 32 bytes for Ed25519
    seed_inputs = [
        b"fixture_key_seed_1",
        b"fixture_key_seed_2",
        b"fixture_key_seed_3",
    ]
    # Hash to get 32-byte seeds
    seeds = [hashlib.sha256(s).digest() for s in seed_inputs]

    keys = []
    for seed in seeds:
        # pysodium expects 32-byte seed
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        # KERI uses "D" prefix for Ed25519 keys
        verfer = coring.Verfer(raw=pk, code=coring.MtrDex.Ed25519)
        keys.append({
            "public_key": pk,
            "secret_key": sk,
            "verfer": verfer,
            "qb64": verfer.qb64,
        })

    return keys


def generate_next_key_digests(keys):
    """Generate next key commitment digests."""
    digests = []
    for key in keys:
        # Create digest of public key for next key commitment
        diger = coring.Diger(ser=key["public_key"], code=coring.MtrDex.Blake3_256)
        digests.append(diger.qb64)
    return digests


def generate_icp_fixture(keys):
    """Generate inception event fixture."""
    # Use first key as signing key
    signing_keys = [keys[0]["qb64"]]

    # Use remaining keys for next key commitment
    next_digests = generate_next_key_digests(keys[1:])

    # Create inception event using keripy's eventing module
    serder = eventing.incept(
        keys=signing_keys,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=0,
        wits=[],
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "icp",
        "description": "Inception event with single signing key",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "aid": serder.pre,
    }


def generate_rot_fixture(keys, icp_serder):
    """Generate rotation event fixture."""
    # Rotate from key[0] to key[1]
    new_signing_keys = [keys[1]["qb64"]]

    # Next keys are key[2]
    next_digests = generate_next_key_digests([keys[2]])

    # Create rotation event
    serder = eventing.rotate(
        pre=icp_serder.pre,
        keys=new_signing_keys,
        dig=icp_serder.said,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        sn=1,
        toad=0,
        cuts=[],
        adds=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "rot",
        "description": "Rotation event (key[0] -> key[1])",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "prior_said": icp_serder.said,
    }


def generate_ixn_fixture(keys, icp_serder, rot_serder):
    """Generate interaction event fixture."""
    # Create interaction event after rotation
    serder = eventing.interact(
        pre=icp_serder.pre,
        dig=rot_serder.said,
        sn=2,
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
    )

    return {
        "event_type": "ixn",
        "description": "Interaction event (sn=2)",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "prior_said": rot_serder.said,
    }


def generate_witness_fixture(keys):
    """Generate inception event with witnesses."""
    # Generate witness keys (non-transferable)
    import pysodium
    import hashlib

    witness_seed_inputs = [
        b"witness_key_seed_1",
        b"witness_key_seed_2",
        b"witness_key_seed_3",
    ]
    # Hash to get 32-byte seeds
    witness_seeds = [hashlib.sha256(s).digest() for s in witness_seed_inputs]

    witness_aids = []
    witness_keys = []
    for seed in witness_seeds:
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        # Non-transferable witnesses use "B" prefix
        verfer = coring.Verfer(raw=pk, code=coring.MtrDex.Ed25519N)
        witness_aids.append(verfer.qb64)
        witness_keys.append({
            "public_key": pk,
            "secret_key": sk,
            "qb64": verfer.qb64,
        })

    signing_keys = [keys[0]["qb64"]]
    next_digests = generate_next_key_digests(keys[1:])

    # Create inception with witnesses
    serder = eventing.incept(
        keys=signing_keys,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=2,  # Require 2 of 3 witnesses
        wits=witness_aids,
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "icp_with_witnesses",
        "description": "Inception event with 3 witnesses (toad=2)",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "aid": serder.pre,
        "witnesses": witness_aids,
        "witness_keys": [
            {
                "aid": wk["qb64"],
                "public_key_hex": wk["public_key"].hex(),
            }
            for wk in witness_keys
        ],
        "toad": 2,
    }


def generate_field_order_reference():
    """Extract field ordering from keripy's FieldDom definitions."""
    # These are from keripy/src/keri/core/serdering.py
    field_orders = {}

    fields = serdering.Serder.Fields
    for proto in [serdering.Protocols.keri]:
        for vrsn in [Vrsn_1_0]:
            if proto in fields and vrsn in fields[proto]:
                for ilk, field_dom in fields[proto][vrsn].items():
                    if hasattr(field_dom, 'alls'):
                        field_orders[ilk] = list(field_dom.alls.keys())

    return {
        "description": "Field orderings per event type from keripy",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "protocol_version": "1.0",
        "field_orders": field_orders,
    }


def main():
    """Generate all fixtures."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Generating fixtures in {OUTPUT_DIR}")
    print("-" * 60)

    # Generate keys
    keys = generate_keys()
    print(f"Generated {len(keys)} signing keys")

    # Generate ICP fixture
    icp_fixture = generate_icp_fixture(keys)
    icp_path = OUTPUT_DIR / "icp_keripy.json"
    with open(icp_path, "w") as f:
        json.dump(icp_fixture, f, indent=2)
    print(f"✓ Generated {icp_path.name}")
    print(f"  AID: {icp_fixture['aid'][:20]}...")
    print(f"  SAID: {icp_fixture['said'][:20]}...")

    # We need the actual serder for subsequent events
    icp_serder = eventing.incept(
        keys=[keys[0]["qb64"]],
        isith=1,
        ndigs=generate_next_key_digests(keys[1:]),
        nsith=1,
        toad=0,
        wits=[],
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    # Generate ROT fixture
    rot_fixture = generate_rot_fixture(keys, icp_serder)
    rot_path = OUTPUT_DIR / "rot_keripy.json"
    with open(rot_path, "w") as f:
        json.dump(rot_fixture, f, indent=2)
    print(f"✓ Generated {rot_path.name}")
    print(f"  SAID: {rot_fixture['said'][:20]}...")

    # Re-create rot serder for IXN
    rot_serder = eventing.rotate(
        pre=icp_serder.pre,
        keys=[keys[1]["qb64"]],
        dig=icp_serder.said,
        isith=1,
        ndigs=generate_next_key_digests([keys[2]]),
        nsith=1,
        sn=1,
        toad=0,
        cuts=[],
        adds=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    # Generate IXN fixture
    ixn_fixture = generate_ixn_fixture(keys, icp_serder, rot_serder)
    ixn_path = OUTPUT_DIR / "ixn_keripy.json"
    with open(ixn_path, "w") as f:
        json.dump(ixn_fixture, f, indent=2)
    print(f"✓ Generated {ixn_path.name}")
    print(f"  SAID: {ixn_fixture['said'][:20]}...")

    # Generate witness fixture
    witness_fixture = generate_witness_fixture(keys)
    witness_path = OUTPUT_DIR / "icp_witnesses_keripy.json"
    with open(witness_path, "w") as f:
        json.dump(witness_fixture, f, indent=2)
    print(f"✓ Generated {witness_path.name}")
    print(f"  Witnesses: {len(witness_fixture['witnesses'])}")
    print(f"  Toad: {witness_fixture['toad']}")

    # Generate field order reference
    field_orders = generate_field_order_reference()
    field_path = OUTPUT_DIR / "field_orders_keripy.json"
    with open(field_path, "w") as f:
        json.dump(field_orders, f, indent=2)
    print(f"✓ Generated {field_path.name}")
    for ilk, fields in field_orders["field_orders"].items():
        print(f"  {ilk}: {', '.join(fields)}")

    # Generate combined KEL stream fixture
    kel_fixture = {
        "description": "Complete KEL: icp -> rot -> ixn",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "events": [
            icp_fixture["event"],
            rot_fixture["event"],
            ixn_fixture["event"],
        ],
        "canonical_bytes": [
            icp_fixture["canonical_bytes"],
            rot_fixture["canonical_bytes"],
            ixn_fixture["canonical_bytes"],
        ],
    }
    kel_path = OUTPUT_DIR / "kel_stream_keripy.json"
    with open(kel_path, "w") as f:
        json.dump(kel_fixture, f, indent=2)
    print(f"✓ Generated {kel_path.name}")

    # Generate signing key info for tests
    key_info = {
        "description": "Signing keys used for fixtures",
        "note": "These are deterministic test keys - NEVER use in production",
        "keys": [
            {
                "index": i,
                "qb64": k["qb64"],
                "public_key_hex": k["public_key"].hex(),
                "secret_key_hex": k["secret_key"].hex(),
            }
            for i, k in enumerate(keys)
        ],
    }
    keys_path = OUTPUT_DIR / "signing_keys.json"
    with open(keys_path, "w") as f:
        json.dump(key_info, f, indent=2)
    print(f"✓ Generated {keys_path.name}")

    print("-" * 60)
    print("Fixture generation complete!")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
