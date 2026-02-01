"""Verifier API client wrapper for integration tests."""

import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class VerifyResponse:
    """Response from the verify endpoint."""

    request_id: str
    overall_status: str  # VALID, INVALID, INDETERMINATE
    claims: list[dict] | None
    errors: list[dict] | None
    signer_aid: str | None
    delegation_chain: dict | None
    has_variant_limitations: bool
    raw: dict  # Full response for debugging

    @classmethod
    def from_dict(cls, data: dict) -> "VerifyResponse":
        return cls(
            request_id=data.get("request_id", ""),
            overall_status=data.get("overall_status", ""),
            claims=data.get("claims"),
            errors=data.get("errors"),
            signer_aid=data.get("signer_aid"),
            delegation_chain=data.get("delegation_chain"),
            has_variant_limitations=data.get("has_variant_limitations", False),
            raw=data,
        )

    @property
    def is_valid(self) -> bool:
        return self.overall_status == "VALID"

    @property
    def is_invalid(self) -> bool:
        return self.overall_status == "INVALID"

    @property
    def is_indeterminate(self) -> bool:
        return self.overall_status == "INDETERMINATE"

    def get_error_codes(self) -> list[str]:
        """Get list of error codes from response."""
        if not self.errors:
            return []
        return [e.get("code", "") for e in self.errors]


class VerifierClient:
    """Wrapper for verifier API calls in integration tests."""

    def __init__(self, base_url: str):
        """Initialize the verifier client.

        Args:
            base_url: Base URL of the verifier service (e.g., http://localhost:8000)
        """
        self.base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> dict:
        """Check verifier service health."""
        response = await self.client.get("/healthz")
        response.raise_for_status()
        return response.json()

    async def verify(
        self,
        passport_jwt: str,
        vvp_identity: str,
        call_id: str | None = None,
        received_at: str | None = None,
    ) -> VerifyResponse:
        """Verify a PASSporT using the /verify endpoint.

        Args:
            passport_jwt: The PASSporT JWT to verify
            vvp_identity: Base64url-encoded VVP-Identity header JSON
            call_id: Optional call ID (generated if not provided)
            received_at: Optional RFC3339 timestamp (current time if not provided)

        Returns:
            VerifyResponse with verification results
        """
        if call_id is None:
            call_id = str(uuid.uuid4())

        if received_at is None:
            from datetime import datetime, timezone

            received_at = datetime.now(timezone.utc).isoformat()

        response = await self.client.post(
            "/verify",
            headers={"VVP-Identity": vvp_identity},
            json={
                "passport_jwt": passport_jwt,
                "context": {
                    "call_id": call_id,
                    "received_at": received_at,
                },
            },
        )

        # Don't raise for HTTP errors - the verify endpoint returns 200
        # even for invalid passports (status is in the response body)
        if response.status_code != 200:
            return VerifyResponse(
                request_id="",
                overall_status="ERROR",
                claims=None,
                errors=[
                    {
                        "code": "HTTP_ERROR",
                        "message": f"HTTP {response.status_code}: {response.text}",
                    }
                ],
                signer_aid=None,
                delegation_chain=None,
                has_variant_limitations=False,
                raw={"http_status": response.status_code, "body": response.text},
            )

        return VerifyResponse.from_dict(response.json())

    @staticmethod
    def build_vvp_identity(
        kid: str,
        evd: str,
        ppt: str = "vvp",
        iat: int | None = None,
        exp: int | None = None,
    ) -> str:
        """Build a VVP-Identity header value.

        Args:
            kid: Key identifier (OOBI URL)
            evd: Evidence/dossier URL
            ppt: PASSporT profile type (default: 'vvp')
            iat: Issued-at timestamp (default: current time)
            exp: Optional expiry timestamp

        Returns:
            Base64url-encoded JSON string
        """
        if iat is None:
            iat = int(time.time())

        header_dict: dict[str, Any] = {
            "kid": kid,
            "ppt": ppt,
            "evd": evd,
            "iat": iat,
        }
        if exp is not None:
            header_dict["exp"] = exp

        json_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")
