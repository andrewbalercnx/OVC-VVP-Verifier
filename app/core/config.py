"""
VVP Verifier configuration constants.
All values derive from VVP_Verifier_Specification_v1.4_FINAL.md

Constants are organized into:
- NORMATIVE: Fixed by spec, cannot be changed without spec revision
- CONFIGURABLE: Defaults per spec, may be overridden by deployment policy
- POLICY: Implementation choices where spec requires enforcement but doesn't specify values
"""

# =============================================================================
# NORMATIVE CONSTANTS (fixed by spec)
# =============================================================================

# Maximum iat drift between VVP-Identity and PASSporT
# §5.2A: "The absolute difference... MUST be ≤ 5 seconds"
# This is NORMATIVE - changing this value violates the spec
MAX_IAT_DRIFT_SECONDS: int = 5

# Allowed algorithms
# §5.1: "EdDSA (Ed25519) as the baseline algorithm"
# §5.0: "VVP mandates alg = EdDSA and explicitly forbids ES256/HMAC/RSA"
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"EdDSA"})

# Forbidden algorithms
# §5.0, §5.1: "reject ES256, HMAC, and RSA algorithms... reject none"
FORBIDDEN_ALGORITHMS: frozenset[str] = frozenset({
    "ES256", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"
})

# =============================================================================
# CONFIGURABLE DEFAULTS (per spec, may be overridden)
# =============================================================================

# Clock skew for iat validation
# §4.1A: "default policy for this project is ±300 seconds"
# Configurable per deployment
CLOCK_SKEW_SECONDS: int = 300

# Maximum token age when exp is absent
# §4.1A, §5.2B: "300 seconds... unless explicitly configured otherwise"
MAX_TOKEN_AGE_SECONDS: int = 300

# Maximum PASSporT validity window
# §5.2B: "Default maximum validity window: 300 seconds"
# §5.2B: "unless explicitly configured otherwise"
MAX_PASSPORT_VALIDITY_SECONDS: int = 300

# Allow PASSporT exp omission when VVP-Identity has explicit exp
# §5.2A: "unless explicitly configured to allow exp omission (default: reject)"
# Default is False (reject) per spec
ALLOW_PASSPORT_EXP_OMISSION: bool = False

# =============================================================================
# POLICY CONSTANTS (spec requires enforcement, values are implementation choice)
# =============================================================================

# Dossier fetch constraints
# §6.1B: "timeouts... size limits" - spec requires enforcement but doesn't specify values
DOSSIER_FETCH_TIMEOUT_SECONDS: int = 5
DOSSIER_MAX_SIZE_BYTES: int = 1_048_576  # 1 MB
DOSSIER_MAX_REDIRECTS: int = 3

# =============================================================================
# EXPERIMENTAL / TEST-ONLY FEATURES
# =============================================================================
# These features are incomplete and NOT spec-compliant. They exist for
# development and testing purposes only. Do NOT enable in production.

# Tier 2 KERI key state resolution via KEL parsing
# LIMITATIONS (see Phase 7 documentation):
# - JSON-only: CESR binary format NOT supported (will reject `application/json+cesr`)
# - Signature canonicalization uses JSON sorted-keys, NOT KERI-compliant Blake3
# - SAID validation disabled by default
#
# These limitations mean Tier 2 cannot verify real KERI events from production
# witnesses. It ONLY works with synthetic test fixtures that use JSON and
# sorted-key canonicalization.
#
# Set to True ONLY for testing. Production requires CESR support (Phase 7+).
TIER2_KEL_RESOLUTION_ENABLED: bool = False
