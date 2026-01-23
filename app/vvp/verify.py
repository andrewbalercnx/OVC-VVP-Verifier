"""
VVP Verification stub.
This is a placeholder implementation that will be replaced in Phase 6.
"""

import uuid
from typing import Tuple

from .api_models import (
    VerifyRequest,
    VerifyResponse,
    ClaimNode,
    ClaimStatus,
    ChildLink,
    ErrorDetail,
    ErrorCode,
    derive_overall_status,
)


def verify_vvp(req: VerifyRequest) -> Tuple[str, VerifyResponse]:
    """
    Stub verification function.
    Returns INDETERMINATE with a reason indicating the verifier is not yet implemented.
    """
    request_id = str(uuid.uuid4())

    # Create placeholder claim tree with proper structure per §4.3B
    passport_claim = ClaimNode(
        name="passport_verified",
        status=ClaimStatus.INDETERMINATE,
        reasons=["VERIFIER_NOT_YET_IMPLEMENTED"],
    )
    dossier_claim = ClaimNode(
        name="dossier_verified",
        status=ClaimStatus.INDETERMINATE,
        reasons=["VERIFIER_NOT_YET_IMPLEMENTED"],
    )

    root_claim = ClaimNode(
        name="caller_authorised",
        status=ClaimStatus.INDETERMINATE,
        reasons=["Verification engine not yet implemented"],
        children=[
            ChildLink(required=True, node=passport_claim),
            ChildLink(required=True, node=dossier_claim),
        ],
    )

    claims = [root_claim]
    errors = None

    overall_status = derive_overall_status(claims, errors)

    resp = VerifyResponse(
        request_id=request_id,
        overall_status=overall_status,
        claims=claims,
        errors=errors,
    )

    return request_id, resp
