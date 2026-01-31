"""Schema management endpoints."""
import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.models import (
    SchemaResponse,
    SchemaListResponse,
    SchemaValidationRequest,
    SchemaValidationResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_readonly
from common.vvp.schema.registry import (
    is_known_schema,
    KNOWN_SCHEMA_SAIDS,
    SCHEMA_SOURCE,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/schema", tags=["schema"])


# Import schema store functions
from app.schema.store import (
    get_embedded_schema,
    list_embedded_schemas,
    has_embedded_schema,
)


@router.get("", response_model=SchemaListResponse)
async def list_schemas(
    principal: Principal = require_readonly,
) -> SchemaListResponse:
    """List all available schemas.

    Returns schemas from the embedded schema store with their SAIDs and titles.

    Requires: issuer:readonly role
    """
    schemas_dict = list_embedded_schemas()

    schemas = [
        SchemaResponse(
            said=said,
            title=title,
            description=None,
            schema_document=None,
        )
        for said, title in schemas_dict.items()
    ]

    return SchemaListResponse(
        schemas=schemas,
        count=len(schemas),
    )


@router.get("/{said}", response_model=SchemaResponse)
async def get_schema(
    said: str,
    principal: Principal = require_readonly,
) -> SchemaResponse:
    """Get a schema by SAID.

    Args:
        said: The schema's self-addressing identifier ($id field)

    Returns:
        Schema with full document if found

    Requires: issuer:readonly role
    """
    schema_doc = get_embedded_schema(said)

    if schema_doc is None:
        raise HTTPException(status_code=404, detail=f"Schema not found: {said}")

    return SchemaResponse(
        said=said,
        title=schema_doc.get("title", "Untitled"),
        description=schema_doc.get("description"),
        schema_document=schema_doc,
    )


@router.post("/validate", response_model=SchemaValidationResponse)
async def validate_schema(
    request: SchemaValidationRequest,
    principal: Principal = require_readonly,
) -> SchemaValidationResponse:
    """Validate a schema SAID is recognized for issuance.

    Checks if the SAID is in the known schema registry. If a credential_type
    is specified, validates against that specific type's known schemas.

    Args:
        request: Schema validation request with SAID and optional credential type

    Returns:
        Validation result indicating if the schema is recognized

    Requires: issuer:readonly role
    """
    if request.credential_type:
        # Check against specific credential type
        valid = is_known_schema(request.credential_type, request.said)
    else:
        # Check if SAID exists in any type
        valid = any(
            request.said in saids
            for saids in KNOWN_SCHEMA_SAIDS.values()
            if saids  # Skip empty frozensets
        )
        # Also check embedded schemas
        if not valid:
            valid = has_embedded_schema(request.said)

    return SchemaValidationResponse(
        said=request.said,
        valid=valid,
        credential_type=request.credential_type,
    )
