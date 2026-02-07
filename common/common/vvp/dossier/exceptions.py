"""Dossier-specific exceptions.

These exceptions are service-agnostic. Individual services (verifier, issuer)
can map these to their specific error codes if needed.

Per spec §6.1B:
- Fetch failures → typically INDETERMINATE (recoverable)
- Parse/structure failures → typically INVALID (non-recoverable)
"""


class DossierError(Exception):
    """Base exception for dossier operations.

    Attributes:
        code: Error code string for categorization
        message: Human-readable error message
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class FetchError(DossierError):
    """HTTP fetch failures.

    Used when:
    - Network timeout
    - HTTP error status
    - Too many redirects
    - Response too large
    - Invalid content-type
    """

    def __init__(self, message: str = "Dossier fetch failed"):
        super().__init__("DOSSIER_FETCH_FAILED", message)


class ParseError(DossierError):
    """JSON/structure parse failures.

    Used when:
    - Invalid JSON
    - Missing required ACDC fields
    - Unexpected data types
    """

    def __init__(self, message: str = "Dossier parse failed"):
        super().__init__("DOSSIER_PARSE_FAILED", message)


class GraphError(DossierError):
    """DAG structure invalid.

    Used when:
    - Cycle detected in DAG
    - No root node found
    - Multiple root nodes found (when not aggregate)
    - Duplicate SAIDs
    """

    def __init__(self, message: str = "Dossier graph invalid"):
        super().__init__("DOSSIER_GRAPH_INVALID", message)
