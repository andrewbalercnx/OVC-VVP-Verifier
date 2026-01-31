"""ACDC Schema SAID Registry.

COMPATIBILITY SHIM: This module re-exports from common.vvp.schema.registry.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.schema:
    from common.vvp.schema import KNOWN_SCHEMA_SAIDS, is_known_schema
"""

# Re-export from common package
from common.vvp.schema.registry import (
    SCHEMA_REGISTRY_VERSION,
    KNOWN_SCHEMA_SAIDS,
    SCHEMA_SOURCE,
    get_known_schemas,
    is_known_schema,
    has_governance_schemas,
)

__all__ = [
    "SCHEMA_REGISTRY_VERSION",
    "KNOWN_SCHEMA_SAIDS",
    "SCHEMA_SOURCE",
    "get_known_schemas",
    "is_known_schema",
    "has_governance_schemas",
]
