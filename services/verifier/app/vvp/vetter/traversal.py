"""Edge traversal to find Vetter Certification credentials.

This module provides functions to traverse credential edges and
locate the Vetter Certification credential that constrains a
given credential's issuer.
"""

import logging
from typing import Any, Optional

from app.vvp.vetter.certification import (
    VetterCertification,
    is_vetter_certification_schema,
    parse_vetter_certification,
)

log = logging.getLogger(__name__)

# Spec-required edge name for vetter certification backlink
# Per VVP Multichannel Vetters spec: credentials must use "certification" edge
SPEC_CERTIFICATION_EDGE_NAME = "certification"

# Alternative edge names that may appear in legacy dossiers
# These are logged as warnings but still processed for backward compatibility
LEGACY_CERTIFICATION_EDGE_NAMES = ["vetter", "vetter_cert", "cert"]


def find_vetter_certification(
    credential: Any,
    dossier_acdcs: dict[str, Any],
) -> Optional[VetterCertification]:
    """Find the Vetter Certification for a credential via required edge.

    Per the VVP Multichannel Vetters spec: "Each of these credentials
    contains an edge, which is a backlink to CertificationB."

    This function ONLY finds certifications via explicit edges. Credentials
    without a proper certification edge will return None, indicating the
    credential is not spec-compliant for vetter constraint validation.

    Args:
        credential: The ACDC to find certification for (dict or object)
        dossier_acdcs: All ACDCs in the current dossier, keyed by SAID

    Returns:
        VetterCertification if found via edge, None if no edge or not found
    """
    # Extract edges from credential
    edges = _get_edges(credential)
    if not edges:
        log.debug("Credential has no edges - missing required certification backlink")
        return None

    # First check for spec-required "certification" edge
    if SPEC_CERTIFICATION_EDGE_NAME in edges:
        result = _resolve_certification_edge(
            edges[SPEC_CERTIFICATION_EDGE_NAME],
            SPEC_CERTIFICATION_EDGE_NAME,
            dossier_acdcs,
        )
        if result:
            return result

    # Check for legacy edge names with warning
    for edge_name in LEGACY_CERTIFICATION_EDGE_NAMES:
        if edge_name not in edges:
            continue

        log.warning(
            f"Credential uses non-standard edge name '{edge_name}' instead of "
            f"spec-required 'certification' - consider updating credential"
        )
        result = _resolve_certification_edge(
            edges[edge_name],
            edge_name,
            dossier_acdcs,
        )
        if result:
            return result

    # No certification edge found - credential is not spec-compliant
    # NOTE: We intentionally do NOT fall back to issuer-AID matching
    # as this would bypass the spec requirement for explicit backlink edges
    log.debug(
        "No certification edge found - credential missing required "
        "backlink to vetter certification"
    )
    return None


def _resolve_certification_edge(
    edge_ref: Any,
    edge_name: str,
    dossier_acdcs: dict[str, Any],
) -> Optional[VetterCertification]:
    """Resolve a certification edge to a VetterCertification.

    Args:
        edge_ref: The edge reference (dict or string SAID)
        edge_name: Name of the edge (for logging)
        dossier_acdcs: All ACDCs in the dossier

    Returns:
        VetterCertification if found and valid, None otherwise
    """
    cert_said = _extract_edge_said(edge_ref)
    if not cert_said:
        log.debug(f"Edge '{edge_name}' has no SAID reference")
        return None

    # Try to find certification in dossier
    if cert_said not in dossier_acdcs:
        log.debug(
            f"Certification SAID {cert_said[:16]}... "
            f"referenced by '{edge_name}' edge not found in dossier"
        )
        return None

    cert_acdc = dossier_acdcs[cert_said]

    # Verify it's actually a vetter certification
    schema_said = _get_schema_said(cert_acdc)
    if schema_said and is_vetter_certification_schema(schema_said):
        parsed = parse_vetter_certification(cert_acdc)
        if parsed:
            log.debug(
                f"Found vetter certification {cert_said[:16]}... "
                f"via edge '{edge_name}'"
            )
            return parsed

    # May still be a vetter certification with unknown schema
    # Try parsing anyway (handles custom schemas with same structure)
    parsed = parse_vetter_certification(cert_acdc)
    if parsed and parsed.ecc_targets and parsed.jurisdiction_targets:
        log.debug(
            f"Found vetter certification {cert_said[:16]}... "
            f"via edge '{edge_name}' (schema not in known list)"
        )
        return parsed

    log.debug(
        f"Credential {cert_said[:16]}... referenced by '{edge_name}' "
        f"is not a valid vetter certification"
    )
    return None


def _get_edges(credential: Any) -> Optional[dict[str, Any]]:
    """Extract edges dict from credential."""
    if isinstance(credential, dict):
        edges = credential.get("e")
    else:
        edges = getattr(credential, "edges", None)
        if edges is None:
            raw = getattr(credential, "raw", {})
            edges = raw.get("e") if raw else None

    if isinstance(edges, str):
        # Compact form - edges is a SAID, not a dict
        return None

    return edges if isinstance(edges, dict) else None


def _extract_edge_said(edge_ref: Any) -> Optional[str]:
    """Extract SAID from an edge reference.

    Handles both formats:
    - Dict format: {"n": "<SAID>", "s": "<schema_said>"}
    - String format: "<SAID>"
    """
    if isinstance(edge_ref, str):
        return edge_ref
    if isinstance(edge_ref, dict):
        return edge_ref.get("n")
    return None


def _get_schema_said(acdc: Any) -> Optional[str]:
    """Extract schema SAID from ACDC."""
    if isinstance(acdc, dict):
        return acdc.get("s")
    return getattr(acdc, "schema_said", None) or getattr(acdc, "schema", None)


def _get_issuer_aid(credential: Any) -> Optional[str]:
    """Extract issuer AID from credential."""
    if isinstance(credential, dict):
        return credential.get("i")
    return getattr(credential, "issuer_aid", None)


def get_certification_edge_said(credential: Any) -> Optional[str]:
    """Get the SAID of the certification edge from a credential.

    This is useful for checking if a credential has a certification
    edge without fully resolving it.

    Args:
        credential: The ACDC to check

    Returns:
        SAID of the certification edge target, or None if not present
    """
    edges = _get_edges(credential)
    if not edges:
        return None

    # Check spec-required edge name first
    if SPEC_CERTIFICATION_EDGE_NAME in edges:
        return _extract_edge_said(edges[SPEC_CERTIFICATION_EDGE_NAME])

    # Check legacy edge names
    for edge_name in LEGACY_CERTIFICATION_EDGE_NAMES:
        if edge_name in edges:
            return _extract_edge_said(edges[edge_name])

    return None


def has_certification_edge(credential: Any) -> bool:
    """Check if a credential has a certification edge.

    Args:
        credential: The ACDC to check

    Returns:
        True if the credential has a certification edge
    """
    return get_certification_edge_said(credential) is not None
