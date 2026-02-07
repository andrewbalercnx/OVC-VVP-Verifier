"""Dossier-specific exceptions.

COMPATIBILITY SHIM: This module re-exports from common.vvp.dossier.exceptions.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.dossier:
    from common.vvp.dossier import FetchError, ParseError, GraphError

Per spec §6.1B:
- Fetch failures → INDETERMINATE (recoverable)
- Parse/structure failures → INVALID (non-recoverable)
"""

# Re-export all exceptions from common package
from common.vvp.dossier.exceptions import (
    DossierError,
    FetchError,
    GraphError,
    ParseError,
)

__all__ = [
    "DossierError",
    "FetchError",
    "ParseError",
    "GraphError",
]
