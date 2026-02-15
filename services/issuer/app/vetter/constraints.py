"""Vetter constraint validation for Sprint 62.

Two-layer architecture:
- Layer 1: Pure constraint checks (no KERI dependency) — testable in isolation
- Layer 2: Endpoint adapters that resolve context and call Layer 1

Enforcement points use these adapters:
- validate_issuance_constraints(): org-level cert resolution (pre-edge)
- validate_credential_edge_constraints(): single credential edge resolution
- validate_dossier_constraints(): batch credential edge resolution
- validate_signing_constraints(): dossier walk + TN ECC + jurisdiction
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import app.config as _cfg
from app.vetter.constants import (
    KNOWN_EXTENDED_SCHEMA_SAIDS,
    VALID_ECC_CODES,
    VETTER_CERT_SCHEMA_SAID,
)

log = logging.getLogger(__name__)


# =============================================================================
# Layer 1: Pure constraint checks
# =============================================================================


@dataclass
class ConstraintCheckResult:
    """Result of a single constraint check."""

    check_type: str  # "ecc" | "jurisdiction" | "missing_cert_edge" | "unresolvable_cert"
    credential_type: str  # "TN" | "Identity" | "Brand" | "Unknown"
    target_value: str  # e.g., "44" or "GBR"
    allowed_values: list[str] = field(default_factory=list)
    is_authorized: bool = True
    reason: str = ""


def extract_ecc_from_tn(tn: str) -> Optional[str]:
    """Extract E.164 country code from a phone number.

    Strips leading '+', then performs longest-prefix match against known
    ITU-T E.164 country calling codes.

    Returns:
        Country calling code string (e.g., "44") or None if unrecognized.
    """
    if not tn:
        return None
    digits = tn.lstrip("+")
    if not digits:
        return None
    # Longest-prefix match: try 3-digit, 2-digit, 1-digit
    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in VALID_ECC_CODES:
            return prefix
    return None


def check_tn_ecc_constraint(
    tn: str,
    ecc_targets: list[str],
) -> ConstraintCheckResult:
    """Check TN country code against VetterCert ecc_targets (§5 check 8)."""
    ecc = extract_ecc_from_tn(tn)
    if ecc is None:
        return ConstraintCheckResult(
            check_type="ecc",
            credential_type="TN",
            target_value=tn,
            allowed_values=ecc_targets,
            is_authorized=True,  # Can't check — skip rather than fail
            reason=f"Could not extract country code from TN: {tn}",
        )
    is_auth = ecc in ecc_targets
    return ConstraintCheckResult(
        check_type="ecc",
        credential_type="TN",
        target_value=ecc,
        allowed_values=ecc_targets,
        is_authorized=is_auth,
        reason="" if is_auth else f"TN country code {ecc} not in vetter ECC targets {ecc_targets}",
    )


def check_jurisdiction_constraint(
    code: str,
    jurisdiction_targets: list[str],
    credential_type: str,
) -> ConstraintCheckResult:
    """Check jurisdiction against VetterCert jurisdiction_targets (§5 checks 7 & 9)."""
    is_auth = code in jurisdiction_targets
    return ConstraintCheckResult(
        check_type="jurisdiction",
        credential_type=credential_type,
        target_value=code,
        allowed_values=jurisdiction_targets,
        is_authorized=is_auth,
        reason="" if is_auth else (
            f"{credential_type} jurisdiction {code} not in vetter "
            f"jurisdiction targets {jurisdiction_targets}"
        ),
    )


# =============================================================================
# Schema-to-credential-type mapping
# =============================================================================

# Extended TNAlloc schema SAID
_EXT_TNALLOC_SAID = "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_"
# Extended Legal Entity schema SAID
_EXT_LE_SAID = "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV"
# Extended Brand schema SAID
_EXT_BRAND_SAID = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"


def _schema_to_credential_type(schema_said: str) -> str:
    """Map schema SAID to credential type name."""
    if schema_said == _EXT_TNALLOC_SAID:
        return "TN"
    elif schema_said == _EXT_LE_SAID:
        return "Identity"
    elif schema_said == _EXT_BRAND_SAID:
        return "Brand"
    return "Unknown"


# =============================================================================
# Layer 2: Endpoint adapters
# =============================================================================


async def validate_issuance_constraints(
    schema_said: str,
    attributes: dict,
    org,  # Organization ORM model
) -> list[ConstraintCheckResult]:
    """Issuance-time: resolve org's active VetterCert, check attribute values.

    Uses org-level cert resolution because the credential being issued hasn't
    been created yet and has no edge to resolve.

    Returns empty list if schema not extended or no active cert.
    """
    if schema_said not in KNOWN_EXTENDED_SCHEMA_SAIDS:
        log.debug("VETTER_CONSTRAINT_SKIPPED", extra={"schema_said": schema_said, "reason": "base_schema"})
        return []

    from app.vetter.service import resolve_active_vetter_cert

    cert_info = await resolve_active_vetter_cert(org)
    if cert_info is None:
        # Org hasn't onboarded to vetter constraints yet — skip
        return []

    ecc_targets = cert_info.attributes.get("ecc_targets", [])
    jurisdiction_targets = cert_info.attributes.get("jurisdiction_targets", [])
    results = []

    if schema_said == _EXT_TNALLOC_SAID:
        # Extract TN(s) from attributes
        numbers = attributes.get("numbers", {})
        tns = []
        if isinstance(numbers, dict):
            for key in ("tn", "rangeStart"):
                if key in numbers:
                    tns.append(numbers[key])
        elif isinstance(numbers, list):
            tns.extend(numbers)
        elif isinstance(numbers, str):
            tns.append(numbers)
        for tn in tns:
            result = check_tn_ecc_constraint(str(tn), ecc_targets)
            _log_evaluation(schema_said, result)
            results.append(result)

    elif schema_said == _EXT_LE_SAID:
        country = attributes.get("country")
        if country:
            result = check_jurisdiction_constraint(country, jurisdiction_targets, "Identity")
            _log_evaluation(schema_said, result)
            results.append(result)

    elif schema_said == _EXT_BRAND_SAID:
        assertion_country = attributes.get("assertionCountry")
        if assertion_country:
            result = check_jurisdiction_constraint(assertion_country, jurisdiction_targets, "Brand")
            _log_evaluation(schema_said, result)
            results.append(result)

    return results


async def validate_credential_edge_constraints(
    credential_said: str,
) -> list[ConstraintCheckResult]:
    """Credential-edge-level: resolve VetterCert from credential's certification edge.

    1. Load credential from KERI store
    2. Check if schema is extended — if not, skip (base schema)
    3. Extract 'certification' edge SAID — if missing on extended, violation
    4. Load VetterCert, parse ecc/jurisdiction targets
    5. Run appropriate constraint check based on credential type
    """
    from app.keri.registry import get_registry_manager

    registry_mgr = await get_registry_manager()
    reger = registry_mgr.regery.reger

    # Load credential
    try:
        creder = reger.creds.get(keys=credential_said)
        if creder is None:
            return []
    except Exception:
        return []

    schema_said = creder.schema if hasattr(creder, "schema") else ""
    if schema_said not in KNOWN_EXTENDED_SCHEMA_SAIDS:
        log.debug("VETTER_CONSTRAINT_SKIPPED", extra={"schema_said": schema_said, "reason": "base_schema"})
        return []

    cred_type = _schema_to_credential_type(schema_said)
    attrib = creder.attrib if hasattr(creder, "attrib") else {}

    # Extract certification edge
    edges = creder.edge if hasattr(creder, "edge") else {}
    if isinstance(edges, dict):
        cert_edge = edges.get("certification")
    else:
        cert_edge = None

    if cert_edge is None:
        # Extended schema MUST have certification edge — violation per Sprint 40
        result = ConstraintCheckResult(
            check_type="missing_cert_edge",
            credential_type=cred_type,
            target_value=credential_said[:16],
            is_authorized=False,
            reason="Extended credential missing required certification edge",
        )
        _log_evaluation(schema_said, result)
        return [result]

    # Resolve VetterCert from edge
    cert_said = cert_edge.get("n") if isinstance(cert_edge, dict) else None
    if not cert_said:
        result = ConstraintCheckResult(
            check_type="unresolvable_cert",
            credential_type=cred_type,
            target_value=credential_said[:16],
            is_authorized=False,
            reason="Certification edge has no credential SAID reference",
        )
        _log_evaluation(schema_said, result)
        return [result]

    # Load the VetterCert credential
    try:
        vetter_creder = reger.creds.get(keys=cert_said)
        if vetter_creder is None:
            result = ConstraintCheckResult(
                check_type="unresolvable_cert",
                credential_type=cred_type,
                target_value=credential_said[:16],
                is_authorized=False,
                reason=f"VetterCertification {cert_said[:16]}... not found in KERI store",
            )
            _log_evaluation(schema_said, result)
            return [result]
    except Exception:
        result = ConstraintCheckResult(
            check_type="unresolvable_cert",
            credential_type=cred_type,
            target_value=credential_said[:16],
            is_authorized=False,
            reason=f"Error loading VetterCertification {cert_said[:16]}...",
        )
        _log_evaluation(schema_said, result)
        return [result]

    # Check VetterCert schema
    vc_schema = vetter_creder.schema if hasattr(vetter_creder, "schema") else ""
    if vc_schema != VETTER_CERT_SCHEMA_SAID:
        result = ConstraintCheckResult(
            check_type="unresolvable_cert",
            credential_type=cred_type,
            target_value=credential_said[:16],
            is_authorized=False,
            reason=f"Certification edge points to non-VetterCert schema: {vc_schema[:16]}...",
        )
        _log_evaluation(schema_said, result)
        return [result]

    # Check VetterCert revocation
    try:
        state = reger.states.get(keys=cert_said)
        if state is not None and hasattr(state, "et") and state.et in ("rev", "brv"):
            result = ConstraintCheckResult(
                check_type="unresolvable_cert",
                credential_type=cred_type,
                target_value=credential_said[:16],
                is_authorized=False,
                reason="VetterCertification is revoked",
            )
            _log_evaluation(schema_said, result)
            return [result]
    except Exception:
        pass

    # Check expiry
    vc_attrib = vetter_creder.attrib if hasattr(vetter_creder, "attrib") else {}
    cert_expiry = vc_attrib.get("certificationExpiry")
    if cert_expiry:
        from datetime import datetime, timezone
        try:
            expiry_dt = datetime.fromisoformat(cert_expiry)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if expiry_dt < datetime.now(timezone.utc):
                result = ConstraintCheckResult(
                    check_type="unresolvable_cert",
                    credential_type=cred_type,
                    target_value=credential_said[:16],
                    is_authorized=False,
                    reason=f"VetterCertification expired ({cert_expiry})",
                )
                _log_evaluation(schema_said, result)
                return [result]
        except (ValueError, TypeError):
            pass

    # Extract constraint targets from VetterCert
    ecc_targets = vc_attrib.get("ecc_targets", [])
    jurisdiction_targets = vc_attrib.get("jurisdiction_targets", [])
    results = []

    if schema_said == _EXT_TNALLOC_SAID:
        numbers = attrib.get("numbers", {})
        tns = []
        if isinstance(numbers, dict):
            for key in ("tn", "rangeStart"):
                if key in numbers:
                    tns.append(numbers[key])
        elif isinstance(numbers, list):
            tns.extend(numbers)
        elif isinstance(numbers, str):
            tns.append(numbers)
        for tn in tns:
            result = check_tn_ecc_constraint(str(tn), ecc_targets)
            _log_evaluation(schema_said, result)
            results.append(result)

    elif schema_said == _EXT_LE_SAID:
        country = attrib.get("country")
        if country:
            result = check_jurisdiction_constraint(country, jurisdiction_targets, "Identity")
            _log_evaluation(schema_said, result)
            results.append(result)

    elif schema_said == _EXT_BRAND_SAID:
        assertion_country = attrib.get("assertionCountry")
        if assertion_country:
            result = check_jurisdiction_constraint(assertion_country, jurisdiction_targets, "Brand")
            _log_evaluation(schema_said, result)
            results.append(result)

    return results


async def validate_dossier_constraints(
    credential_saids: list[str],
) -> list[ConstraintCheckResult]:
    """Dossier-creation-time: validate constraints for each credential in dossier.

    For each credential, resolves VetterCert via its certification edge and
    validates constraints. This is credential-edge-centric, not org-centric.
    """
    all_results = []
    for said in credential_saids:
        try:
            results = await validate_credential_edge_constraints(said)
            all_results.extend(results)
        except Exception as e:
            log.warning(f"Constraint check failed for credential {said[:16]}...: {e}")
    return all_results


async def validate_signing_constraints(
    orig_tn: str,
    dossier_said: str,
) -> list[ConstraintCheckResult]:
    """Signing-time: resolve dossier credential chain, check ALL constraints.

    Walks the dossier to find all credentials with certification edges,
    then validates each one. Also checks orig_tn ECC against each TN
    credential's VetterCert.
    """
    from app.keri.registry import get_registry_manager

    registry_mgr = await get_registry_manager()
    reger = registry_mgr.regery.reger

    # Load root dossier credential to find edges
    try:
        root_creder = reger.creds.get(keys=dossier_said)
        if root_creder is None:
            return []
    except Exception:
        return []

    # Walk edges to collect credential SAIDs
    edges = root_creder.edge if hasattr(root_creder, "edge") else {}
    cred_saids = []
    if isinstance(edges, dict):
        for edge_name, edge_val in edges.items():
            if edge_name == "d":
                continue  # SAID placeholder, not an edge
            if isinstance(edge_val, dict) and "n" in edge_val:
                cred_saids.append(edge_val["n"])

    # Also validate the root credential itself (it may have a certification edge)
    all_saids = [dossier_said] + cred_saids

    # Validate constraints for root + all edge credentials
    results = await validate_dossier_constraints(all_saids)

    # Additionally check orig_tn ECC against any TN credential's VetterCert
    # (the dossier constraint check above already validates per-credential,
    # but we also want to check the signing TN specifically)
    for said in cred_saids:
        try:
            creder = reger.creds.get(keys=said)
            if creder is None:
                continue
            schema = creder.schema if hasattr(creder, "schema") else ""
            if schema != _EXT_TNALLOC_SAID:
                continue
            # This is a TN credential — check orig_tn against its VetterCert
            edge_data = creder.edge if hasattr(creder, "edge") else {}
            cert_edge = edge_data.get("certification") if isinstance(edge_data, dict) else None
            if cert_edge is None:
                continue
            cert_said = cert_edge.get("n") if isinstance(cert_edge, dict) else None
            if not cert_said:
                continue
            vc_creder = reger.creds.get(keys=cert_said)
            if vc_creder is None:
                continue
            vc_attrib = vc_creder.attrib if hasattr(vc_creder, "attrib") else {}
            ecc_targets = vc_attrib.get("ecc_targets", [])
            # Check the signing TN's ECC
            tn_result = check_tn_ecc_constraint(orig_tn, ecc_targets)
            if not tn_result.is_authorized:
                tn_result.reason = f"Signing TN {orig_tn} ECC: {tn_result.reason}"
                _log_evaluation(schema, tn_result)
                results.append(tn_result)
        except Exception as e:
            log.warning(f"Signing TN ECC check failed for credential {said[:16]}...: {e}")

    return results


# =============================================================================
# Telemetry helpers
# =============================================================================


def _log_evaluation(schema_said: str, result: ConstraintCheckResult) -> None:
    """Structured log for constraint evaluation (per reviewer recommendation)."""
    log.info(
        "VETTER_CONSTRAINT_EVALUATED",
        extra={
            "schema_said": schema_said,
            "schema_type": "extended" if schema_said in KNOWN_EXTENDED_SCHEMA_SAIDS else "base",
            "check_type": result.check_type,
            "is_authorized": result.is_authorized,
            "enforcement_mode": "enforce" if _cfg.ENFORCE_VETTER_CONSTRAINTS else "soft",
        },
    )
