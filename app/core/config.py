"""
VVP Verifier configuration constants.
All values derive from VVP_Verifier_Specification_v1.4_FINAL.md
"""

# Clock skew for iat validation (§4.1A: "default policy ±300 seconds")
CLOCK_SKEW_SECONDS: int = 300

# Maximum token age when exp is absent (§4.1A, §5.2B: "300 seconds")
MAX_TOKEN_AGE_SECONDS: int = 300

# Maximum PASSporT validity window (§5.2B: "Default maximum validity window: 300 seconds")
# Configurable per §5.2B: "unless explicitly configured otherwise"
MAX_PASSPORT_VALIDITY_SECONDS: int = 300

# Maximum iat drift between VVP-Identity and PASSporT (§5.2A: "MUST be ≤ 5 seconds")
# This is NORMATIVE, not configurable
MAX_IAT_DRIFT_SECONDS: int = 5

# Allowed algorithms (§5.1: "EdDSA (Ed25519) as the baseline algorithm")
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"EdDSA"})

# Forbidden algorithms (§5.0, §5.1: "reject ES256, HMAC, and RSA")
FORBIDDEN_ALGORITHMS: frozenset[str] = frozenset({
    "ES256", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"
})

# Dossier fetch constraints (§6.1B: "timeouts... size limits")
# These are implementation policy; spec requires enforcement but doesn't specify values
DOSSIER_FETCH_TIMEOUT_SECONDS: int = 5
DOSSIER_MAX_SIZE_BYTES: int = 1_048_576  # 1 MB
DOSSIER_MAX_REDIRECTS: int = 3
