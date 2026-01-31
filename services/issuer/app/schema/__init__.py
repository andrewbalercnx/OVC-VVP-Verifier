"""Schema store for VVP Issuer."""

from app.schema.importer import (
    SchemaImporter,
    SchemaImportError,
    get_schema_importer,
    reset_schema_importer,
)
from app.schema.said import (
    SAIDComputationError,
    SAIDVerificationError,
    compute_schema_said,
    create_schema_template,
    inject_said,
    verify_schema_said,
)
from app.schema.store import (
    SCHEMA_SOURCE_CUSTOM,
    SCHEMA_SOURCE_EMBEDDED,
    SCHEMA_SOURCE_IMPORTED,
    add_schema,
    get_embedded_schema,
    get_embedded_schema_count,
    get_schema,
    get_schema_count,
    get_schema_source,
    has_embedded_schema,
    has_schema,
    list_all_schemas,
    list_embedded_schemas,
    reload_all_schemas,
    reload_embedded_schemas,
    reload_user_schemas,
    remove_schema,
)

__all__ = [
    # SAID computation
    "SAIDComputationError",
    "SAIDVerificationError",
    "compute_schema_said",
    "inject_said",
    "verify_schema_said",
    "create_schema_template",
    # Schema import
    "SchemaImporter",
    "SchemaImportError",
    "get_schema_importer",
    "reset_schema_importer",
    # Schema store
    "SCHEMA_SOURCE_EMBEDDED",
    "SCHEMA_SOURCE_IMPORTED",
    "SCHEMA_SOURCE_CUSTOM",
    "get_schema",
    "get_schema_source",
    "has_schema",
    "list_all_schemas",
    "get_schema_count",
    "add_schema",
    "remove_schema",
    "reload_all_schemas",
    "reload_user_schemas",
    # Embedded schemas (legacy)
    "get_embedded_schema",
    "has_embedded_schema",
    "list_embedded_schemas",
    "get_embedded_schema_count",
    "reload_embedded_schemas",
]
