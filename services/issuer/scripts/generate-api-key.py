#!/usr/bin/env python3
"""Generate API keys for VVP Issuer.

Usage:
    python scripts/generate-api-key.py [--prefix PREFIX] [--id KEY_ID] [--name NAME]

Examples:
    # Generate a new key with default settings
    python scripts/generate-api-key.py

    # Generate a key with custom prefix and id
    python scripts/generate-api-key.py --prefix prod --id prod-admin-1 --name "Production Admin"

The script outputs:
1. The raw API key (to be stored securely and provided in X-API-Key header)
2. The bcrypt hash (to be added to api_keys.json)
3. A JSON snippet ready to paste into api_keys.json
"""

import argparse
import json
import secrets
import sys

try:
    import bcrypt
except ImportError:
    print("Error: bcrypt not installed. Run: pip install bcrypt")
    sys.exit(1)

# Default bcrypt cost factor (2^12 = 4096 iterations)
# Higher values are more secure but slower. 12 is a good balance.
BCRYPT_COST_FACTOR = 12


def generate_api_key(prefix: str = "vvp") -> str:
    """Generate a secure random API key.

    Args:
        prefix: Prefix for the key (helps identify key type)

    Returns:
        A secure random API key string
    """
    return f"{prefix}-{secrets.token_urlsafe(24)}"


def hash_api_key(raw_key: str, cost_factor: int = BCRYPT_COST_FACTOR) -> str:
    """Hash an API key using bcrypt.

    Args:
        raw_key: The raw API key to hash
        cost_factor: bcrypt cost factor (default: 12)

    Returns:
        The bcrypt hash string
    """
    salt = bcrypt.gensalt(rounds=cost_factor)
    return bcrypt.hashpw(raw_key.encode(), salt).decode()


def main():
    parser = argparse.ArgumentParser(
        description="Generate API keys for VVP Issuer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--prefix",
        default="vvp",
        help="Key prefix (default: vvp)",
    )
    parser.add_argument(
        "--id",
        dest="key_id",
        help="Key ID for api_keys.json (default: generated from prefix)",
    )
    parser.add_argument(
        "--name",
        help="Human-readable name (default: generated from id)",
    )
    parser.add_argument(
        "--roles",
        default="issuer:readonly",
        help="Comma-separated roles (default: issuer:readonly)",
    )
    parser.add_argument(
        "--cost",
        type=int,
        default=BCRYPT_COST_FACTOR,
        help=f"bcrypt cost factor (default: {BCRYPT_COST_FACTOR})",
    )

    args = parser.parse_args()

    # Generate key
    raw_key = generate_api_key(args.prefix)
    key_hash = hash_api_key(raw_key, args.cost)

    # Generate defaults
    key_id = args.key_id or f"{args.prefix}-key-{secrets.token_hex(4)}"
    name = args.name or f"{args.prefix.title()} API Key"
    roles = [r.strip() for r in args.roles.split(",")]

    # Output
    print("=" * 60)
    print("VVP Issuer API Key Generator")
    print("=" * 60)
    print()
    print("RAW API KEY (keep secret, use in X-API-Key header):")
    print(f"  {raw_key}")
    print()
    print("BCRYPT HASH (for api_keys.json):")
    print(f"  {key_hash}")
    print()
    print("JSON CONFIG (paste into api_keys.json 'keys' array):")
    config = {
        "id": key_id,
        "name": name,
        "hash": key_hash,
        "roles": roles,
        "revoked": False,
    }
    print(json.dumps(config, indent=2))
    print()
    print("=" * 60)
    print("IMPORTANT: Store the raw API key securely. It cannot be")
    print("recovered from the hash. If lost, generate a new key.")
    print("=" * 60)


if __name__ == "__main__":
    main()
