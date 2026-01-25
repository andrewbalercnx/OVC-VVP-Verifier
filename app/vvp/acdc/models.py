"""ACDC (Authentic Chained Data Container) models.

Per KERI/ACDC spec and VVP §6.3.x credential types.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ACDC:
    """Parsed ACDC credential.

    ACDC structure per KERI spec:
    - v: Version string (e.g., "ACDC10JSON00...")
    - d: SAID (self-addressing identifier) - Blake3-256 hash
    - i: Issuer AID
    - s: Schema SAID
    - a: Attributes (credential data)
    - e: Edges (references to other credentials)
    - r: Rules (credential rules/policies)

    Attributes:
        version: ACDC version string from 'v' field.
        said: Self-addressing identifier from 'd' field.
        issuer_aid: Issuer's AID from 'i' field.
        schema_said: Schema SAID from 's' field.
        attributes: Credential attributes from 'a' field.
        edges: Credential chain edges from 'e' field.
        rules: Credential rules from 'r' field.
        raw: Original parsed dictionary for debugging.
        signature: Attached signature bytes (if parsed from CESR).
    """
    version: str
    said: str
    issuer_aid: str
    schema_said: str
    attributes: Optional[Dict[str, Any]] = None
    edges: Optional[Dict[str, Any]] = None
    rules: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None

    @property
    def credential_type(self) -> str:
        """Infer credential type from schema or attributes.

        Returns:
            Credential type string (e.g., 'APE', 'DE', 'TNAlloc', 'LE').
        """
        # Check for type in attributes
        if self.attributes:
            if "LEI" in self.attributes:
                return "LE"  # Legal Entity credential
            if "phone" in self.attributes or "tn" in self.attributes:
                return "TNAlloc"  # TN Allocation credential

        # Check edges for credential type hints
        if self.edges:
            if "vetting" in self.edges or "le" in self.edges:
                return "APE"  # Auth Phone Entity
            if "delegation" in self.edges:
                return "DE"  # Delegate Entity

        return "unknown"

    @property
    def is_root_credential(self) -> bool:
        """Check if this credential has no parent edges.

        Root credentials (from GLEIF/QVI) have no edges or only
        self-references.
        """
        if not self.edges:
            return True
        # Check for empty edges or only metadata fields
        for key in self.edges:
            if key not in ('d', 'n'):  # Skip digest/nonce
                return False
        return True


@dataclass
class ACDCChainResult:
    """Result of ACDC chain validation.

    Attributes:
        chain: List of credentials from leaf to root.
        root_aid: The trusted root AID that anchored the chain.
        validated: Whether the chain was successfully validated.
        errors: List of any validation errors encountered.
    """
    chain: List[ACDC] = field(default_factory=list)
    root_aid: Optional[str] = None
    validated: bool = False
    errors: List[str] = field(default_factory=list)
