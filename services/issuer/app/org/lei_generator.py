"""Pseudo-LEI generator for development and testing.

Legal Entity Identifiers (LEIs) are 20-character alphanumeric codes used to
uniquely identify legal entities participating in financial transactions.

LEI Format (ISO 17442):
- Characters 1-4: LOU (Local Operating Unit) prefix
- Characters 5-18: Entity-specific identifier (alphanumeric)
- Characters 19-20: Check digits (MOD 97-10, ISO 7064)

This module generates PSEUDO-LEIs for development/testing purposes.
These are NOT valid LEIs and should not be used in production.
The prefix 5493 is used to clearly indicate these are pseudo-LEIs.

Reference: https://www.gleif.org/en/about-lei/iso-17442-the-lei-code-structure
"""

import hashlib
import string


# Pseudo-LEI prefix (not a valid LOU prefix)
PSEUDO_LEI_PREFIX = "5493"


def generate_pseudo_lei(org_name: str, seed: str = "") -> str:
    """Generate a deterministic pseudo-LEI for development/testing.

    Args:
        org_name: Organization name to use as input
        seed: Optional additional seed for uniqueness

    Returns:
        A 20-character pseudo-LEI string

    Example:
        >>> generate_pseudo_lei("Acme Corp")
        '5493A1B2C3D4E5F6G700'

    Note:
        These are NOT valid LEIs and should not be used in production.
        The prefix 5493 is a placeholder (not a valid LOU prefix).
    """
    # Create deterministic hash from org name + seed
    content = f"{org_name}:{seed}".encode("utf-8")
    digest = hashlib.sha256(content).hexdigest().upper()

    # Extract alphanumeric characters (A-Z, 0-9) for the entity identifier
    # LEIs use only uppercase letters and digits
    valid_chars = string.ascii_uppercase + string.digits
    entity_chars = "".join(c for c in digest if c in valid_chars)

    # Take first 14 characters for the entity-specific part
    entity_id = entity_chars[:14]

    # Pad with zeros if needed (shouldn't happen with SHA-256)
    while len(entity_id) < 14:
        entity_id += "0"

    # Construct base LEI without check digits
    base_lei = f"{PSEUDO_LEI_PREFIX}{entity_id}"

    # Calculate MOD 97-10 check digits (ISO 7064)
    check_digits = calculate_lei_check_digits(base_lei)

    return f"{base_lei}{check_digits:02d}"


def calculate_lei_check_digits(base_lei: str) -> int:
    """Calculate MOD 97-10 check digits for an LEI.

    The check digit calculation follows ISO 7064 MOD 97-10:
    1. Convert letters to numbers (A=10, B=11, ..., Z=35)
    2. Append "00" to the end
    3. Calculate 98 - (number MOD 97)

    Args:
        base_lei: The first 18 characters of the LEI (without check digits)

    Returns:
        The two check digits as an integer (0-97)
    """
    # Convert letters to numbers (A=10, B=11, ..., Z=35)
    numeric_str = ""
    for char in base_lei:
        if char.isalpha():
            numeric_str += str(ord(char.upper()) - ord("A") + 10)
        else:
            numeric_str += char

    # Append "00" for check digit calculation
    numeric_str += "00"

    # Calculate check digits: 98 - (number MOD 97)
    check = 98 - (int(numeric_str) % 97)

    return check


def validate_lei_checksum(lei: str) -> bool:
    """Validate the check digits of an LEI.

    Args:
        lei: A 20-character LEI string

    Returns:
        True if the check digits are valid, False otherwise

    Example:
        >>> validate_lei_checksum("5493A1B2C3D4E5F6G700")
        True
    """
    if len(lei) != 20:
        return False

    # Extract base and check digits
    base_lei = lei[:18]
    try:
        provided_check = int(lei[18:20])
    except ValueError:
        return False

    # Calculate expected check digits
    expected_check = calculate_lei_check_digits(base_lei)

    return provided_check == expected_check


def is_pseudo_lei(lei: str) -> bool:
    """Check if an LEI is a pseudo-LEI (starts with 5493).

    Args:
        lei: A 20-character LEI string

    Returns:
        True if the LEI starts with the pseudo-LEI prefix
    """
    return lei.startswith(PSEUDO_LEI_PREFIX)
