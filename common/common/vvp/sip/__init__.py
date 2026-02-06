"""Shared SIP protocol handling module.

Sprint 44: Extracted from services/sip-redirect for reuse by both
sip-redirect (signing) and sip-verify (verification) services.
"""

from common.vvp.sip.models import SIPRequest, SIPResponse
from common.vvp.sip.parser import parse_sip_request, normalize_tn, extract_tn_from_uri
from common.vvp.sip.builder import (
    build_302_redirect,
    build_400_bad_request,
    build_401_unauthorized,
    build_403_forbidden,
    build_404_not_found,
    build_500_error,
)

__all__ = [
    # Models
    "SIPRequest",
    "SIPResponse",
    # Parser
    "parse_sip_request",
    "normalize_tn",
    "extract_tn_from_uri",
    # Builders
    "build_302_redirect",
    "build_400_bad_request",
    "build_401_unauthorized",
    "build_403_forbidden",
    "build_404_not_found",
    "build_500_error",
]
