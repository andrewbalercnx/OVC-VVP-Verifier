"""OOBI URL construction helpers per §4.1B.

The VVP spec requires that `kid` and `evd` fields be OOBI URLs (not bare AIDs).
These helpers construct compliant OOBI URLs from component parts.
"""


def build_issuer_oobi(issuer_aid: str, witness_url: str) -> str:
    """Construct OOBI URL for issuer identity per §4.1B.

    The kid field in both VVP-Identity header and PASSporT header MUST be
    an OOBI URL that allows verifiers to resolve the issuer's key state.

    Args:
        issuer_aid: The issuer's KERI AID (e.g., "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")
        witness_url: Base URL of a witness (e.g., "http://localhost:5642")

    Returns:
        OOBI URL in format: {witness_url}/oobi/{aid}/controller

    Example:
        >>> build_issuer_oobi("EBfdlu8R27Fbx", "http://localhost:5642")
        'http://localhost:5642/oobi/EBfdlu8R27Fbx/controller'
    """
    return f"{witness_url.rstrip('/')}/oobi/{issuer_aid}/controller"


def build_dossier_url(dossier_said: str, issuer_base_url: str) -> str:
    """Construct dossier URL for the evd field.

    The evd field references the dossier that contains the credential evidence.
    The issuer hosts dossiers at a public endpoint for verifier dereferencing.

    Args:
        dossier_said: The SAID of the dossier (content-addressed identifier)
        issuer_base_url: Base URL of the issuer service (e.g., "https://issuer.example.com")

    Returns:
        Dossier URL in format: {issuer_base_url}/dossier/{said}

    Example:
        >>> build_dossier_url("EAbcdef123", "https://issuer.example.com")
        'https://issuer.example.com/dossier/EAbcdef123'
    """
    return f"{issuer_base_url.rstrip('/')}/dossier/{dossier_said}"
