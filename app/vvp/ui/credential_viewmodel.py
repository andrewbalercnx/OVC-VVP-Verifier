"""Credential card view-model adapter.

This module provides dataclasses and an adapter function to normalize
raw ACDC credentials into a template-friendly view-model. This decouples
templates from ACDC field naming variations across schemas.

Per Sprint 21 plan (PLAN_Credential_Card_UI.md):
- Normalizes schema-specific attribute fields (tn, phone, legalName, etc.)
- Separates ClaimStatus (VALID/INVALID/INDETERMINATE) from revocation state
- Handles edges as strings, dicts with 'n', or dicts with 'd'
- Surfaces compact/partial variant limitations for UI banners
- Checks issuer against TRUSTED_ROOT_AIDS for trust anchor display
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import TRUSTED_ROOT_AIDS
from app.vvp.acdc.models import ACDC, ACDCChainResult


# =============================================================================
# View-Model Dataclasses
# =============================================================================


@dataclass
class RevocationStatus:
    """Revocation state (independent of ClaimStatus).

    ClaimStatus values are VALID/INVALID/INDETERMINATE based on chain validation.
    RevocationStatus tracks the TEL/registry state separately.

    Attributes:
        state: ACTIVE, REVOKED, or UNKNOWN.
        checked_at: RFC3339 timestamp of last check, or None if not checked.
        source: Where the revocation data came from (witness, oobi, inline, unknown).
        error: Error message if the revocation check failed.
    """

    state: str = "UNKNOWN"
    checked_at: Optional[str] = None
    source: str = "unknown"
    error: Optional[str] = None


@dataclass
class IssuerInfo:
    """Issuer identity information.

    Attributes:
        aid: Full issuer AID string.
        aid_short: Truncated AID for display (first 16 chars + "...").
        is_trusted_root: True if this AID is in TRUSTED_ROOT_AIDS.
    """

    aid: str
    aid_short: str
    is_trusted_root: bool


@dataclass
class AttributeDisplay:
    """Normalized attribute for display.

    Attributes:
        label: Human-readable label (e.g., "Phone Number", "Legal Name").
        value: Display value, or special markers like "—" or "(redacted)".
        css_class: Optional CSS class for styling (e.g., "attr-bool-true", "attr-date").
        tooltip: Normative description for mouseover, from FIELD_DESCRIPTIONS.
        raw_key: Original field key (for Raw Contents display).
    """

    label: str
    value: str
    css_class: str = ""
    tooltip: str = ""
    raw_key: str = ""


@dataclass
class AttributeSection:
    """Group of related attributes for collapsible display.

    Attributes:
        name: Section header (e.g., "Dates & Times", "Identity").
        css_class: CSS class for styling (e.g., "section-dates").
        attributes: List of attributes in this section.
        initially_open: Whether section should be expanded by default.
    """

    name: str
    css_class: str
    attributes: List[AttributeDisplay]
    initially_open: bool = True


@dataclass
class EdgeLink:
    """Normalized edge link for chain expansion.

    Attributes:
        said: Target credential SAID, or None if edge is malformed.
        label: Human-readable label (e.g., "Vetted By", "Legal Entity").
        available: True if the target credential exists in the current dossier.
    """

    said: Optional[str]
    label: str
    available: bool


@dataclass
class VariantLimitations:
    """Surfaces data limitations for compact/partial variants.

    Templates use this to display banners and disable features when
    credential data is incomplete.

    Attributes:
        has_variant_limitations: True if any limitation applies.
        missing_edge_targets: SAIDs of edges not found in dossier.
        redacted_fields: Field names that have placeholder values.
        is_compact: True if attributes is a SAID reference (not expanded).
        is_partial: True if some fields have placeholder values.
    """

    has_variant_limitations: bool = False
    missing_edge_targets: List[str] = field(default_factory=list)
    redacted_fields: List[str] = field(default_factory=list)
    is_compact: bool = False
    is_partial: bool = False


@dataclass
class RawACDCData:
    """Raw ACDC data for debug/details panel.

    Attributes:
        attributes: Original attributes dict or SAID string.
        edges: Original edges dict.
        source_format: Format the credential was parsed from (json, cesr).
    """

    attributes: Any = None
    edges: Optional[Dict[str, Any]] = None
    source_format: str = "json"


@dataclass
class CredentialCardViewModel:
    """Normalized view model for credential card rendering.

    This is the main output of build_credential_card_vm(). Templates
    should use this rather than accessing raw ACDC fields directly.

    Attributes:
        said: Credential SAID (from acdc.d / acdc.said).
        schema_said: Schema SAID (from acdc.s / acdc.schema_said).
        credential_type: Inferred type (APE, DE, TNAlloc, vLEI, LE, unknown).
        variant: ACDC variant (full, compact, partial).
        status: ClaimStatus from chain validation (VALID, INVALID, INDETERMINATE).
        revocation: Revocation state (separate from status).
        issuer: Issuer identity info.
        primary: Primary attribute for prominent display.
        secondary: Up to 3 secondary attributes (for backwards compatibility).
        sections: Categorized attribute sections for collapsible display.
        edges: Normalized edge links for chain expansion.
        limitations: Variant limitations for UI banners.
        raw: Original data for debug panel.
        raw_contents: All fields with tooltips for Raw Contents section.
    """

    said: str
    schema_said: str
    credential_type: str
    variant: str
    status: str
    revocation: RevocationStatus
    issuer: IssuerInfo
    primary: AttributeDisplay
    secondary: List[AttributeDisplay]
    sections: List[AttributeSection]
    edges: Dict[str, EdgeLink]
    limitations: VariantLimitations
    raw: RawACDCData
    raw_contents: List[AttributeDisplay] = field(default_factory=list)


# =============================================================================
# Mapping Constants
# =============================================================================

# Primary attribute source fields by credential type (checked in order)
PRIMARY_ATTRIBUTE_SOURCES: Dict[str, List[tuple[str, str]]] = {
    "APE": [("tn", "Phone Number"), ("phone", "Phone Number"), ("number", "Phone Number")],
    "DE": [("name", "Delegate Name"), ("delegateName", "Delegate Name")],
    "TNAlloc": [("tn", "Number Block"), ("block", "Number Block"), ("range", "Number Range")],
    "vLEI": [("legalName", "Legal Name"), ("LEI", "LEI")],
    "LE": [("legalName", "Legal Name"), ("LEI", "LEI")],
}

# Edge key to display label mapping
EDGE_LABELS: Dict[str, str] = {
    "vetting": "Vetted By",
    "le": "Legal Entity",
    "delegation": "Delegated By",
    "jl": "Jurisdiction",
    "jurisdiction": "Jurisdiction",
    "parent": "Parent",
    "auth": "Authorized By",
}

# Fields to exclude from secondary attributes
EXCLUDED_SECONDARY_FIELDS: Set[str] = {"d", "dt", "i", "s", "v", "n"}

# Attribute category mappings for collapsible sections
# Maps category key to (display name, list of field names)
ATTRIBUTE_CATEGORIES: Dict[str, Tuple[str, List[str]]] = {
    "identity": ("Identity", ["LEI", "legalName", "lids", "issuee", "role", "subject"]),
    "dates": ("Dates & Times", ["dt", "startDate", "endDate", "issuanceDate", "expirationDate"]),
    "permissions": ("Permissions", ["c_goal", "channel", "doNotOriginate", "authorized"]),
    "numbers": ("Numbers & Ranges", ["tn", "phone", "numbers", "rangeStart", "rangeEnd"]),
}

# Normative field descriptions from ToIP ACDC Specification
# See: https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md
FIELD_DESCRIPTIONS: Dict[str, str] = {
    # Top-level ACDC fields (normative from ToIP spec)
    "v": "Version String: Encodes protocol type, version, and serialization kind.",
    "t": "Message Type: Identifies the ACDC type or purpose.",
    "d": "SAID (Self-Addressing Identifier): Self-referential cryptographic digest that uniquely identifies this ACDC.",
    "u": "UUID: Salty nonce for privacy protection, enables compact disclosure.",
    "i": "Issuer AID: Autonomic Identifier of the issuer, established via KERI Key State.",
    "rd": "Registry Digest: SAID of the credential registry for revocation status.",
    "s": "Schema: SAID reference or embedded JSON Schema defining credential structure.",
    "a": "Attributes: Nested field map containing the credential's payload data.",
    "A": "Attribute Aggregate: Blinded aggregate of selectively disclosable attributes.",
    "e": "Edges: References to other ACDCs via SAIDs, establishing the credential chain.",
    "r": "Rules: Ricardian contract clauses defining legal terms and conditions.",
    "n": "Node: Target SAID of an edge reference to another ACDC.",
    "o": "Operator: Edge operator defining relationship semantics (AND, OR, etc.).",
    "w": "Weight: Edge weight for weighted threshold operators.",
    "l": "Legal/Liability: Terms, warranties, and conditions for credential use.",
    # Common attribute fields (descriptive, not normatively defined in ACDC spec)
    "dt": "Datetime: ISO 8601 / RFC-3339 formatted timestamp.",
    "LEI": "Legal Entity Identifier: 20-character ISO 17442 identifier for legal entities.",
    "legalName": "Legal Name: Official registered name of the legal entity.",
    "lids": "LEI Data Source: Source identifier for LEI data verification.",
    "issuee": "Issuee: AID or identifier of the credential subject/holder.",
    "role": "Role: Assigned role or function within the credential context.",
    "subject": "Subject: The entity or topic this credential describes.",
    "startDate": "Start Date: Effective start date/time for credential validity.",
    "endDate": "End Date: Expiration date/time for credential validity.",
    "issuanceDate": "Issuance Date: Date/time when this credential was issued.",
    "expirationDate": "Expiration Date: Date/time when this credential expires.",
    "c_goal": "Credential Goals: Authorized purposes or use cases for this credential.",
    "channel": "Channel: Communication channel type (voice, data, etc.).",
    "doNotOriginate": "Do Not Originate: Flag indicating call origination restrictions.",
    "authorized": "Authorized: Boolean flag for authorization status.",
    "tn": "Telephone Number: E.164 formatted telephone number or number block.",
    "phone": "Phone: Telephone number in E.164 or national format.",
    "numbers": "Numbers: Range or set of telephone numbers.",
    "rangeStart": "Range Start: First number in an allocated telephone number range.",
    "rangeEnd": "Range End: Last number in an allocated telephone number range.",
    "vcard": "vCard: Contact information in vCard format (RFC 6350).",
}


# =============================================================================
# Helper Functions
# =============================================================================


def normalize_edge(edge_value: Any) -> Optional[str]:
    """Extract target SAID from edge value.

    Edges can be:
    - A string (direct SAID reference)
    - A dict with 'n' (node) key
    - A dict with 'd' (digest) key
    - A list of the above (returns first valid)

    Args:
        edge_value: Raw edge value from ACDC.

    Returns:
        Target SAID string, or None if edge is malformed/empty.
    """
    if edge_value is None:
        return None

    if isinstance(edge_value, str):
        return edge_value if edge_value else None

    if isinstance(edge_value, dict):
        return edge_value.get("n") or edge_value.get("d")

    if isinstance(edge_value, list):
        # Return first valid SAID from list
        for item in edge_value:
            result = normalize_edge(item)
            if result:
                return result
        return None

    return None


def _truncate_aid(aid: str, length: int = 16) -> str:
    """Truncate AID for display."""
    if len(aid) <= length:
        return aid
    return f"{aid[:length]}..."


def _is_iso_date(value: str) -> bool:
    """Check if string looks like ISO 8601 date.

    Args:
        value: String to check.

    Returns:
        True if value matches YYYY-MM-DD pattern at start.
    """
    if len(value) < 10:
        return False
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", value))


def _format_date(iso_string: str) -> str:
    """Format ISO date to human-readable.

    Args:
        iso_string: ISO 8601 date string.

    Returns:
        Formatted date like "Nov 25, 2024 08:20 PM", or original if parse fails.
    """
    try:
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %I:%M %p")
    except (ValueError, AttributeError):
        return iso_string


def _is_redacted_value(value: Any) -> bool:
    """Check if a value is a redaction placeholder.

    ACDC partial disclosure uses specific placeholder values:
    - "_" : Full redaction placeholder
    - "_:type" : Typed placeholder (e.g., "_:string", "_:date")
    - "" : Empty string
    - "#" : Hash marker
    - "[REDACTED]" : Explicit redaction marker

    Args:
        value: The value to check.

    Returns:
        True if the value appears to be a redaction placeholder.
    """
    if value is None:
        return False
    if not isinstance(value, str):
        return False
    # ACDC partial disclosure placeholders
    if value == "_":
        return True
    if value.startswith("_:"):
        return True
    # Common redaction patterns
    if value in ("", "#", "[REDACTED]"):
        return True
    return False


def _format_value(value: Any, key: str = "") -> Tuple[str, str]:
    """Format a single attribute value for display.

    Args:
        value: The raw attribute value.
        key: The attribute key (unused, for future extension).

    Returns:
        Tuple of (formatted_value, css_class).
    """
    if value is None:
        return "—", "attr-null"

    # Check for redaction placeholders BEFORE other formatting
    if _is_redacted_value(value):
        return "(redacted)", "attr-redacted"

    if isinstance(value, bool):
        return ("Yes" if value else "No"), ("attr-bool-true" if value else "attr-bool-false")

    if isinstance(value, str):
        if _is_iso_date(value):
            return _format_date(value), "attr-date"
        return value, ""

    if isinstance(value, list):
        return ", ".join(str(v) for v in value), "attr-array"

    return str(value), ""


def _get_field_tooltip(key: str) -> str:
    """Get normative description for a field key.

    Looks up the field in FIELD_DESCRIPTIONS, trying both the full key
    and the base key (for nested fields like "numbers.rangeStart").

    Args:
        key: Field key, possibly with dot notation for nested fields.

    Returns:
        Description string, or empty string if not found.
    """
    # Try exact match first
    if key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[key]

    # Try base key (before first dot)
    base_key = key.split(".")[0]
    if base_key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[base_key]

    # Try last segment (for nested keys like "numbers.rangeStart")
    last_key = key.split(".")[-1]
    if last_key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[last_key]

    return ""


def _flatten_nested(
    attributes: Dict[str, Any],
    parent_key: str = "",
) -> List[Tuple[str, Any]]:
    """Flatten nested dicts to list of (dotted_key, value) pairs.

    Args:
        attributes: Dictionary of attributes, possibly nested.
        parent_key: Prefix for nested keys (used in recursion).

    Returns:
        List of (key, value) tuples with nested keys using dot notation.
    """
    items: List[Tuple[str, Any]] = []
    for key, value in attributes.items():
        if key.startswith("_") or key in EXCLUDED_SECONDARY_FIELDS:
            continue
        full_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(_flatten_nested(value, full_key))
        else:
            items.append((full_key, value))
    return items


def _build_attribute_sections(
    attributes: Any,
    primary_field: Optional[str] = None,
) -> List[AttributeSection]:
    """Build categorized attribute sections for collapsible display.

    Groups attributes into predefined categories (Identity, Dates, etc.)
    and formats values appropriately.

    Args:
        attributes: ACDC attributes dict.
        primary_field: Field used for primary display (excluded from sections).

    Returns:
        List of AttributeSection with categorized attributes.
    """
    if not isinstance(attributes, dict):
        return []

    # Flatten all attributes including nested
    flat = _flatten_nested(attributes)

    # Categorize each attribute
    categorized: Dict[str, List[AttributeDisplay]] = {
        "identity": [],
        "dates": [],
        "permissions": [],
        "numbers": [],
        "other": [],
    }

    for key, value in flat:
        if key == primary_field:
            continue

        # Skip empty values
        if value is None or value == "":
            continue

        formatted, css_class = _format_value(value, key)
        attr = AttributeDisplay(
            label=key.replace("_", " ").replace(".", " › ").title(),
            value=formatted,
            css_class=css_class,
            tooltip=_get_field_tooltip(key),
            raw_key=key,
        )

        # Find category based on base key (before any dots)
        category_found = "other"
        base_key = key.split(".")[0]
        for cat_key, (_, fields) in ATTRIBUTE_CATEGORIES.items():
            if base_key in fields or key in fields:
                category_found = cat_key
                break

        categorized[category_found].append(attr)

    # Build sections (only non-empty)
    sections: List[AttributeSection] = []
    for cat_key, (cat_name, _) in ATTRIBUTE_CATEGORIES.items():
        if categorized[cat_key]:
            sections.append(
                AttributeSection(
                    name=cat_name,
                    css_class=f"section-{cat_key}",
                    attributes=categorized[cat_key],
                )
            )

    if categorized["other"]:
        sections.append(
            AttributeSection(
                name="Other Attributes",
                css_class="section-other",
                attributes=categorized["other"],
            )
        )

    return sections


def _build_raw_contents(acdc_dict: Dict[str, Any]) -> List[AttributeDisplay]:
    """Build raw contents list with tooltips for all ACDC fields.

    This provides a complete view of all fields in the credential,
    with normative descriptions from the ToIP ACDC specification.

    Args:
        acdc_dict: Full ACDC dictionary including top-level fields.

    Returns:
        List of AttributeDisplay for all fields with tooltips.
    """
    result: List[AttributeDisplay] = []

    def add_field(key: str, value: Any, prefix: str = "") -> None:
        """Recursively add fields, flattening nested dicts."""
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            # Add the dict itself as a container
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value="{...}",
                    css_class="attr-object",
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )
            # Recursively add nested fields
            for nested_key, nested_value in value.items():
                add_field(nested_key, nested_value, full_key)
        elif isinstance(value, list):
            # Format list as JSON-like representation
            if len(value) <= 3:
                display_val = "[" + ", ".join(repr(v) for v in value) + "]"
            else:
                display_val = "[" + ", ".join(repr(v) for v in value[:3]) + ", ...]"
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value=display_val,
                    css_class="attr-array",
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )
        else:
            # Format scalar value
            formatted, css_class = _format_value(value, key)
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value=formatted,
                    css_class=css_class,
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )

    # Add all top-level fields in order
    for key, value in acdc_dict.items():
        add_field(key, value)

    return result


def _get_primary_attribute(
    credential_type: str,
    attributes: Any,
    said: str,
) -> AttributeDisplay:
    """Extract primary attribute based on credential type.

    Args:
        credential_type: Inferred credential type.
        attributes: ACDC attributes (dict or SAID string for compact).
        said: Credential SAID (fallback for unknown types).

    Returns:
        AttributeDisplay with label and value.
    """
    # Compact variant: attributes is a SAID string
    if isinstance(attributes, str):
        return AttributeDisplay(
            label="Credential",
            value=f"{_truncate_aid(said, 16)}",
        )

    # Not a dict: can't extract attributes
    if not isinstance(attributes, dict):
        return AttributeDisplay(
            label="Credential",
            value=f"{_truncate_aid(said, 16)}",
        )

    # Try to find primary attribute for this type
    sources = PRIMARY_ATTRIBUTE_SOURCES.get(credential_type, [])
    for field_name, label in sources:
        value = attributes.get(field_name)
        if value:
            # Handle list values (e.g., multiple phone numbers)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:3])
                if len(attributes.get(field_name, [])) > 3:
                    value += "..."
            return AttributeDisplay(label=label, value=str(value))

    # Fallback: truncated SAID
    return AttributeDisplay(
        label=credential_type.upper() if credential_type != "unknown" else "Credential",
        value=f"{_truncate_aid(said, 16)}",
    )


def _get_secondary_attributes(
    attributes: Any,
    primary_field: Optional[str] = None,
    max_count: int = 3,
) -> List[AttributeDisplay]:
    """Extract secondary attributes for display.

    Args:
        attributes: ACDC attributes dict.
        primary_field: Field used for primary (exclude from secondary).
        max_count: Maximum number of secondary attributes.

    Returns:
        List of AttributeDisplay for secondary attributes.
    """
    if not isinstance(attributes, dict):
        return []

    result = []
    for key, value in attributes.items():
        # Skip excluded fields
        if key in EXCLUDED_SECONDARY_FIELDS:
            continue
        # Skip primary field
        if key == primary_field:
            continue
        # Skip internal fields
        if key.startswith("_"):
            continue
        # Skip empty values
        if value is None or value == "":
            continue

        # Format the value
        if isinstance(value, list):
            display_value = ", ".join(str(v) for v in value[:2])
            if len(value) > 2:
                display_value += "..."
        elif isinstance(value, dict):
            display_value = "(complex)"
        else:
            display_value = str(value)
            if len(display_value) > 50:
                display_value = display_value[:47] + "..."

        # Human-readable label
        label = key.replace("_", " ").title()

        result.append(AttributeDisplay(label=label, value=display_value))

        if len(result) >= max_count:
            break

    return result


def _detect_redacted_fields(attributes: Any) -> List[str]:
    """Detect fields with placeholder/redacted values.

    Partial variants may have placeholder values per ACDC spec:
    - "_" : Full redaction placeholder
    - "_:type" : Typed placeholder (e.g., "_:string", "_:date")
    - "" : Empty string
    - "#" : Hash marker
    - "[REDACTED]" : Explicit redaction marker

    Args:
        attributes: ACDC attributes dict.

    Returns:
        List of field names that appear redacted.
    """
    if not isinstance(attributes, dict):
        return []

    redacted = []
    for key, value in attributes.items():
        if key.startswith("_"):
            continue

        # ACDC partial disclosure placeholders
        if value == "_":
            redacted.append(key)
        elif isinstance(value, str) and value.startswith("_:"):
            # Typed placeholder like "_:string", "_:date", "_:datetime"
            redacted.append(key)
        # Common redaction patterns
        elif value == "" or value == "#" or value == "[REDACTED]":
            redacted.append(key)
        elif isinstance(value, str) and value.startswith("E") and len(value) == 44:
            # Might be a SAID placeholder for unexpanded nested data
            # This is a heuristic; real detection would need schema info
            pass

    return redacted


def _build_edges(
    edges: Optional[Dict[str, Any]],
    available_saids: Optional[Set[str]],
) -> tuple[Dict[str, EdgeLink], List[str]]:
    """Build normalized edge links.

    Args:
        edges: Raw ACDC edges dict.
        available_saids: Set of SAIDs available in dossier for expansion.

    Returns:
        Tuple of (edges dict, list of missing SAIDs).
    """
    if not edges or not isinstance(edges, dict):
        return {}, []

    result = {}
    missing = []
    available = available_saids or set()

    for key, value in edges.items():
        # Skip metadata fields
        if key in ("d", "n"):
            continue

        said = normalize_edge(value)
        label = EDGE_LABELS.get(key, key.replace("_", " ").title())

        is_available = said in available if said else False
        if said and not is_available:
            missing.append(said)

        result[key] = EdgeLink(
            said=said,
            label=label,
            available=is_available,
        )

    return result, missing


# =============================================================================
# Main Adapter Function
# =============================================================================


def build_credential_card_vm(
    acdc: ACDC,
    chain_result: Optional[ACDCChainResult] = None,
    revocation_result: Optional[dict] = None,
    available_saids: Optional[Set[str]] = None,
) -> CredentialCardViewModel:
    """Build view model from raw ACDC and validation results.

    This is the main entry point for converting ACDC data to a
    template-friendly view model.

    Args:
        acdc: Parsed ACDC credential.
        chain_result: Optional chain validation result for status.
        revocation_result: Optional revocation check result dict with keys:
            - status: "ACTIVE", "REVOKED", or "UNKNOWN"
            - checked_at: RFC3339 timestamp
            - source: "witness", "oobi", "inline", "unknown"
            - error: Optional error message
        available_saids: Set of credential SAIDs available in dossier
            (for determining which edge links can be expanded).

    Returns:
        CredentialCardViewModel ready for template rendering.
    """
    # Extract basic info
    said = acdc.said
    schema_said = acdc.schema_said
    credential_type = acdc.credential_type
    variant = acdc.variant

    # Determine status from chain result
    if chain_result and chain_result.status:
        status = chain_result.status
    else:
        status = "INDETERMINATE"

    # Build revocation status
    if revocation_result:
        revocation = RevocationStatus(
            state=revocation_result.get("status", "UNKNOWN"),
            checked_at=revocation_result.get("checked_at"),
            source=revocation_result.get("source", "unknown"),
            error=revocation_result.get("error"),
        )
    else:
        revocation = RevocationStatus()

    # Build issuer info
    issuer_aid = acdc.issuer_aid
    issuer = IssuerInfo(
        aid=issuer_aid,
        aid_short=_truncate_aid(issuer_aid),
        is_trusted_root=issuer_aid in TRUSTED_ROOT_AIDS,
    )

    # Build primary attribute
    primary = _get_primary_attribute(credential_type, acdc.attributes, said)

    # Determine which field was used for primary (if any)
    primary_field = None
    if isinstance(acdc.attributes, dict):
        sources = PRIMARY_ATTRIBUTE_SOURCES.get(credential_type, [])
        for field_name, _ in sources:
            if acdc.attributes.get(field_name):
                primary_field = field_name
                break

    # Build secondary attributes (for backwards compatibility)
    secondary = _get_secondary_attributes(acdc.attributes, primary_field)

    # Build attribute sections (new categorized display)
    sections = _build_attribute_sections(acdc.attributes, primary_field)

    # Build edges
    edges, missing_edges = _build_edges(acdc.edges, available_saids)

    # Detect limitations
    is_compact = variant == "compact" or not isinstance(acdc.attributes, dict)
    redacted_fields = _detect_redacted_fields(acdc.attributes)
    is_partial = variant == "partial" or len(redacted_fields) > 0

    limitations = VariantLimitations(
        has_variant_limitations=is_compact or is_partial or len(missing_edges) > 0,
        missing_edge_targets=missing_edges,
        redacted_fields=redacted_fields,
        is_compact=is_compact,
        is_partial=is_partial,
    )

    # Mark redacted fields in secondary attributes
    if redacted_fields:
        for attr in secondary:
            # Check if this attribute's source field is redacted
            field_key = attr.label.lower().replace(" ", "_")
            if field_key in redacted_fields or attr.value in ("", "#", "[REDACTED]"):
                attr.value = "(redacted)"

    # Build raw data for debug
    raw = RawACDCData(
        attributes=acdc.attributes,
        edges=acdc.edges,
        source_format="cesr" if acdc.signature else "json",
    )

    # Build raw contents for "Raw Contents" collapsible section with tooltips
    # Include all top-level ACDC fields
    acdc_full_dict: Dict[str, Any] = {
        "d": acdc.said,
        "i": acdc.issuer_aid,
        "s": acdc.schema_said,
    }
    if isinstance(acdc.attributes, dict):
        acdc_full_dict["a"] = acdc.attributes
    elif acdc.attributes:
        acdc_full_dict["a"] = acdc.attributes  # SAID string for compact
    if acdc.edges:
        acdc_full_dict["e"] = acdc.edges
    # Include any additional fields from the raw ACDC
    if hasattr(acdc, "raw") and isinstance(acdc.raw, dict):
        for key in ("v", "t", "u", "rd", "r"):
            if key in acdc.raw:
                acdc_full_dict[key] = acdc.raw[key]

    raw_contents = _build_raw_contents(acdc_full_dict)

    return CredentialCardViewModel(
        said=said,
        schema_said=schema_said,
        credential_type=credential_type,
        variant=variant,
        status=status,
        revocation=revocation,
        issuer=issuer,
        primary=primary,
        secondary=secondary,
        sections=sections,
        edges=edges,
        limitations=limitations,
        raw=raw,
        raw_contents=raw_contents,
    )
