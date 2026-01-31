"""API models for VVP Issuer.

Pydantic models for API requests and responses.
"""
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# Request Models
# =============================================================================


class CreateIdentityRequest(BaseModel):
    """Request to create a new identity."""

    name: str = Field(..., description="Human-readable alias for the identity")
    transferable: bool = Field(True, description="Whether keys can rotate")
    key_count: Optional[int] = Field(None, description="Number of signing keys")
    key_threshold: Optional[str] = Field(None, description="Signing threshold")
    next_key_count: Optional[int] = Field(None, description="Number of next keys")
    next_threshold: Optional[str] = Field(None, description="Next signing threshold")
    publish_to_witnesses: bool = Field(True, description="Publish OOBI to witnesses")


# =============================================================================
# Response Models
# =============================================================================


class IdentityResponse(BaseModel):
    """Response containing identity information."""

    aid: str = Field(..., description="Autonomic Identifier (AID)")
    name: str = Field(..., description="Human-readable alias")
    created_at: Optional[str] = Field(None, description="Creation timestamp (ISO8601)")
    witness_count: int = Field(..., description="Number of witnesses")
    key_count: int = Field(..., description="Number of signing keys")
    sequence_number: int = Field(..., description="Current key event sequence")
    transferable: bool = Field(..., description="Whether keys can rotate")


class OobiResponse(BaseModel):
    """Response containing OOBI URLs."""

    aid: str = Field(..., description="The AID")
    oobi_urls: list[str] = Field(..., description="List of OOBI URLs")


class WitnessPublishResult(BaseModel):
    """Result of publishing to a witness."""

    url: str
    success: bool
    error: Optional[str] = None


class CreateIdentityResponse(BaseModel):
    """Response from identity creation."""

    identity: IdentityResponse
    oobi_urls: list[str] = Field(default_factory=list)
    publish_results: Optional[list[WitnessPublishResult]] = None


class IdentityListResponse(BaseModel):
    """Response listing all identities."""

    identities: list[IdentityResponse]
    count: int


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""

    ok: bool
    service: str = "vvp-issuer"
    identities_loaded: int = 0
