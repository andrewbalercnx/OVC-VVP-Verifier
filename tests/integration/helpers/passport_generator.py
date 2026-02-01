"""PASSporT JWT generator for integration tests."""

import base64
import json
import time
from typing import Any

import pysodium


class PassportGenerator:
    """Generate test PASSporT JWTs for integration tests.

    PASSporTs are signed using Ed25519 (EdDSA) as required by VVP spec.
    """

    def __init__(self, signing_key: bytes, public_key: bytes, kid: str):
        """Initialize the passport generator.

        Args:
            signing_key: Ed25519 private key (64 bytes)
            public_key: Ed25519 public key (32 bytes)
            kid: Key identifier (OOBI URL for the signing identity)
        """
        self.signing_key = signing_key
        self.public_key = public_key
        self.kid = kid

    @classmethod
    def generate_keypair(cls, kid: str) -> "PassportGenerator":
        """Generate a new keypair for testing.

        Args:
            kid: Key identifier for the generated key

        Returns:
            PassportGenerator with new keypair
        """
        public_key, private_key = pysodium.crypto_sign_keypair()
        return cls(private_key, public_key, kid)

    def create_passport(
        self,
        orig_tn: str | list[str],
        dest_tn: str | list[str],
        evd_url: str,
        iat: int | None = None,
        exp: int | None = None,
        ppt: str = "vvp",
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a signed PASSporT JWT.

        Args:
            orig_tn: Originating telephone number(s)
            dest_tn: Destination telephone number(s)
            evd_url: Evidence/dossier URL
            iat: Issued-at timestamp (default: current time)
            exp: Optional expiry timestamp
            ppt: PASSporT profile type (default: 'vvp')
            extra_claims: Additional claims to include in payload

        Returns:
            Signed JWT string
        """
        if iat is None:
            iat = int(time.time())

        # Normalize to lists
        if isinstance(orig_tn, str):
            orig_tn = [orig_tn]
        if isinstance(dest_tn, str):
            dest_tn = [dest_tn]

        # Build header
        header = {
            "alg": "EdDSA",
            "typ": "passport",
            "ppt": ppt,
            "kid": self.kid,
        }

        # Build payload
        payload: dict[str, Any] = {
            "orig": {"tn": orig_tn},
            "dest": {"tn": dest_tn},
            "iat": iat,
            "evd": evd_url,
        }
        if exp is not None:
            payload["exp"] = exp
        if extra_claims:
            payload.update(extra_claims)

        # Encode and sign
        header_b64 = self._base64url_encode(json.dumps(header, separators=(",", ":")))
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(",", ":")))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        signature = pysodium.crypto_sign_detached(signing_input, self.signing_key)
        signature_b64 = self._base64url_encode_bytes(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _base64url_encode(self, data: str) -> str:
        """Base64url encode a string."""
        return self._base64url_encode_bytes(data.encode("utf-8"))

    def _base64url_encode_bytes(self, data: bytes) -> str:
        """Base64url encode bytes without padding."""
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def get_aid_from_public_key(self) -> str:
        """Get the KERI AID prefix from the public key.

        Returns a basic (non-delegated) AID prefix using the 'B' code
        for Ed25519 public keys.
        """
        # KERI AID for Ed25519 uses 'B' prefix (44 chars total)
        b64_key = base64.urlsafe_b64encode(self.public_key).decode("ascii").rstrip("=")
        return f"B{b64_key}"
