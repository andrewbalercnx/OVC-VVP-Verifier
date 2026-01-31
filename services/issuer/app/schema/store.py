"""Schema store for VVP Issuer.

This module provides storage for vLEI schema documents with support for:
- Embedded schemas (read-only, bundled with application)
- User-added schemas (writable, persisted to local storage)

Schema Sources:
- Embedded: services/issuer/app/schema/schemas/ (read-only)
- User-added: ~/.vvp-issuer/schemas/ or /data/vvp-issuer/schemas/ (writable)
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Directory containing embedded schema JSON files (read-only)
EMBEDDED_SCHEMAS_DIR = Path(__file__).parent / "schemas"

# User schemas directory (writable)
# Use /data/vvp-issuer/schemas if available (Docker), else ~/.vvp-issuer/schemas
_DATA_DIR = Path("/data/vvp-issuer")
if _DATA_DIR.exists():
    USER_SCHEMAS_DIR = _DATA_DIR / "schemas"
else:
    USER_SCHEMAS_DIR = Path.home() / ".vvp-issuer" / "schemas"

# Schema sources
SCHEMA_SOURCE_EMBEDDED = "embedded"
SCHEMA_SOURCE_IMPORTED = "imported"
SCHEMA_SOURCE_CUSTOM = "custom"

# Embedded schema cache: SAID -> schema document
_embedded_schemas: dict[str, dict[str, Any]] = {}

# User-added schema cache: SAID -> (schema document, source)
_user_schemas: dict[str, tuple[dict[str, Any], str]] = {}

# Flags to track if schemas have been loaded
_embedded_loaded = False
_user_loaded = False


def _load_embedded_schemas() -> None:
    """Load all embedded schema JSON files into memory.

    Scans the schemas/ directory for .json files, loads each one,
    and indexes by the $id field (SAID).
    """
    global _embedded_loaded, _embedded_schemas

    if _embedded_loaded:
        return

    if not EMBEDDED_SCHEMAS_DIR.exists():
        log.warning(f"Embedded schemas directory not found: {EMBEDDED_SCHEMAS_DIR}")
        _embedded_loaded = True
        return

    loaded_count = 0
    for json_file in EMBEDDED_SCHEMAS_DIR.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                schema_doc = json.load(f)

            # Index by $id (SAID)
            schema_said = schema_doc.get("$id")
            if schema_said:
                _embedded_schemas[schema_said] = schema_doc
                loaded_count += 1
                log.debug(f"Loaded embedded schema: {schema_said[:20]}... from {json_file.name}")
            else:
                log.warning(f"Schema file missing $id: {json_file.name}")

        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in schema file {json_file.name}: {e}")
        except Exception as e:
            log.error(f"Error loading schema file {json_file.name}: {e}")

    _embedded_loaded = True
    if loaded_count > 0:
        log.info(f"Loaded {loaded_count} embedded schemas from {EMBEDDED_SCHEMAS_DIR}")


def _load_user_schemas() -> None:
    """Load all user-added schema JSON files into memory.

    Scans the user schemas directory for .json files, loads each one,
    and indexes by the $id field (SAID).
    """
    global _user_loaded, _user_schemas

    if _user_loaded:
        return

    if not USER_SCHEMAS_DIR.exists():
        log.debug(f"User schemas directory not found: {USER_SCHEMAS_DIR}")
        _user_loaded = True
        return

    loaded_count = 0
    for json_file in USER_SCHEMAS_DIR.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                schema_doc = json.load(f)

            # Index by $id (SAID)
            schema_said = schema_doc.get("$id")
            if schema_said:
                # Determine source from metadata or filename
                source = schema_doc.get("_source", SCHEMA_SOURCE_IMPORTED)
                _user_schemas[schema_said] = (schema_doc, source)
                loaded_count += 1
                log.debug(f"Loaded user schema: {schema_said[:20]}... from {json_file.name}")
            else:
                log.warning(f"User schema file missing $id: {json_file.name}")

        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in user schema file {json_file.name}: {e}")
        except Exception as e:
            log.error(f"Error loading user schema file {json_file.name}: {e}")

    _user_loaded = True
    if loaded_count > 0:
        log.info(f"Loaded {loaded_count} user schemas from {USER_SCHEMAS_DIR}")


def get_embedded_schema(schema_said: str) -> dict[str, Any] | None:
    """Get an embedded schema by SAID.

    Args:
        schema_said: The schema's self-addressing identifier ($id field).

    Returns:
        The schema document dict if found, None otherwise.
    """
    _load_embedded_schemas()
    return _embedded_schemas.get(schema_said)


def has_embedded_schema(schema_said: str) -> bool:
    """Check if a schema is available in the embedded store.

    Args:
        schema_said: The schema's self-addressing identifier.

    Returns:
        True if schema is embedded, False otherwise.
    """
    _load_embedded_schemas()
    return schema_said in _embedded_schemas


def list_embedded_schemas() -> dict[str, str]:
    """List all embedded schemas with their titles.

    Returns:
        Dict mapping SAID to schema title.
    """
    _load_embedded_schemas()
    return {
        said: schema.get("title", "Untitled")
        for said, schema in _embedded_schemas.items()
    }


def get_embedded_schema_count() -> int:
    """Get the number of embedded schemas.

    Returns:
        Count of loaded schemas.
    """
    _load_embedded_schemas()
    return len(_embedded_schemas)


def reload_embedded_schemas() -> int:
    """Force reload of embedded schemas.

    Useful for testing or after adding new schema files.

    Returns:
        Count of loaded schemas.
    """
    global _embedded_loaded, _embedded_schemas
    _embedded_loaded = False
    _embedded_schemas = {}
    _load_embedded_schemas()
    return len(_embedded_schemas)


# ============================================================================
# User-added schema functions
# ============================================================================


def get_schema(schema_said: str) -> dict[str, Any] | None:
    """Get a schema by SAID from any source.

    Searches embedded schemas first, then user-added schemas.

    Args:
        schema_said: The schema's self-addressing identifier ($id field).

    Returns:
        The schema document dict if found, None otherwise.
    """
    _load_embedded_schemas()
    _load_user_schemas()

    # Check embedded first
    if schema_said in _embedded_schemas:
        return _embedded_schemas[schema_said]

    # Then check user schemas
    if schema_said in _user_schemas:
        return _user_schemas[schema_said][0]

    return None


def get_schema_source(schema_said: str) -> str | None:
    """Get the source of a schema (embedded, imported, custom).

    Args:
        schema_said: The schema's self-addressing identifier.

    Returns:
        Source string or None if not found.
    """
    _load_embedded_schemas()
    _load_user_schemas()

    if schema_said in _embedded_schemas:
        return SCHEMA_SOURCE_EMBEDDED
    if schema_said in _user_schemas:
        return _user_schemas[schema_said][1]
    return None


def has_schema(schema_said: str) -> bool:
    """Check if a schema is available from any source.

    Args:
        schema_said: The schema's self-addressing identifier.

    Returns:
        True if schema exists, False otherwise.
    """
    _load_embedded_schemas()
    _load_user_schemas()
    return schema_said in _embedded_schemas or schema_said in _user_schemas


def list_all_schemas() -> list[dict[str, Any]]:
    """List all schemas with their metadata.

    Returns:
        List of schema info dicts with 'said', 'title', 'source' keys.
    """
    _load_embedded_schemas()
    _load_user_schemas()

    schemas = []

    # Add embedded schemas
    for said, schema in _embedded_schemas.items():
        schemas.append({
            "said": said,
            "title": schema.get("title", "Untitled"),
            "description": schema.get("description", ""),
            "source": SCHEMA_SOURCE_EMBEDDED,
        })

    # Add user schemas
    for said, (schema, source) in _user_schemas.items():
        schemas.append({
            "said": said,
            "title": schema.get("title", "Untitled"),
            "description": schema.get("description", ""),
            "source": source,
        })

    return schemas


def get_schema_count() -> int:
    """Get the total number of schemas.

    Returns:
        Count of all schemas (embedded + user).
    """
    _load_embedded_schemas()
    _load_user_schemas()
    return len(_embedded_schemas) + len(_user_schemas)


def add_schema(
    schema: dict[str, Any],
    source: str = SCHEMA_SOURCE_IMPORTED,
) -> str:
    """Add a schema to user storage.

    Args:
        schema: Schema document with $id field.
        source: Source identifier (imported, custom).

    Returns:
        The schema SAID.

    Raises:
        ValueError: If schema missing $id or already exists as embedded.
    """
    _load_embedded_schemas()
    _load_user_schemas()

    schema_said = schema.get("$id")
    if not schema_said:
        raise ValueError("Schema missing required $id field")

    if schema_said in _embedded_schemas:
        raise ValueError(f"Cannot overwrite embedded schema: {schema_said[:20]}...")

    # Ensure user schemas directory exists
    USER_SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)

    # Add source metadata
    schema_with_meta = dict(schema)
    schema_with_meta["_source"] = source

    # Save to file
    filename = f"{schema_said}.json"
    filepath = USER_SCHEMAS_DIR / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(schema_with_meta, f, indent=2)

    # Update cache
    _user_schemas[schema_said] = (schema_with_meta, source)

    log.info(f"Added user schema: {schema_said[:20]}... ({source})")
    return schema_said


def remove_schema(schema_said: str) -> bool:
    """Remove a user-added schema.

    Args:
        schema_said: The schema's SAID.

    Returns:
        True if removed, False if not found.

    Raises:
        ValueError: If trying to remove an embedded schema.
    """
    _load_embedded_schemas()
    _load_user_schemas()

    if schema_said in _embedded_schemas:
        raise ValueError(f"Cannot remove embedded schema: {schema_said[:20]}...")

    if schema_said not in _user_schemas:
        return False

    # Remove file
    filename = f"{schema_said}.json"
    filepath = USER_SCHEMAS_DIR / filename

    if filepath.exists():
        filepath.unlink()

    # Remove from cache
    del _user_schemas[schema_said]

    log.info(f"Removed user schema: {schema_said[:20]}...")
    return True


def reload_user_schemas() -> int:
    """Force reload of user-added schemas.

    Returns:
        Count of loaded user schemas.
    """
    global _user_loaded, _user_schemas
    _user_loaded = False
    _user_schemas = {}
    _load_user_schemas()
    return len(_user_schemas)


def reload_all_schemas() -> tuple[int, int]:
    """Force reload of all schemas.

    Returns:
        Tuple of (embedded_count, user_count).
    """
    embedded = reload_embedded_schemas()
    user = reload_user_schemas()
    return embedded, user
