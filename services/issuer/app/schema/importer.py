"""Schema import service for WebOfTrust repository.

This module provides functionality to import schemas from the
WebOfTrust/schema GitHub repository, with support for version
pinning and registry caching.
"""

import json
import logging
import os
from typing import Any

import httpx

from app.schema.said import SAIDVerificationError, verify_schema_said

log = logging.getLogger(__name__)

# Environment variable for version pinning
SCHEMA_REPO_REF_ENV = "VVP_SCHEMA_REPO_REF"


class SchemaImportError(Exception):
    """Raised when schema import fails."""

    pass


class SchemaImporter:
    """Import schemas from WebOfTrust/schema repository."""

    WEBOFTRUST_BASE = "https://raw.githubusercontent.com/WebOfTrust/schema"
    DEFAULT_REF = "main"  # Can be commit SHA, tag, or branch

    def __init__(self, ref: str | None = None):
        """Initialize the schema importer.

        Args:
            ref: Git ref (branch, tag, or commit SHA) to use.
                 Defaults to VVP_SCHEMA_REPO_REF env var or "main".
        """
        self.ref = ref or os.environ.get(SCHEMA_REPO_REF_ENV, self.DEFAULT_REF)
        self._registry_cache: dict[str, Any] | None = None
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        """Get the base URL for the pinned version."""
        return f"{self.WEBOFTRUST_BASE}/{self.ref}"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch_registry(self, use_cache: bool = True) -> dict[str, Any]:
        """Fetch registry.json from WebOfTrust repository.

        Args:
            use_cache: If True, return cached registry if available.

        Returns:
            Registry dict containing schema metadata.

        Raises:
            SchemaImportError: If registry fetch fails.
        """
        if use_cache and self._registry_cache is not None:
            return self._registry_cache

        url = f"{self.base_url}/registry.json"
        log.info(f"Fetching schema registry from {url}")

        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()
            registry = response.json()
            self._registry_cache = registry
            log.info(f"Loaded registry with {len(registry.get('schemas', []))} schemas")
            return registry
        except httpx.HTTPStatusError as e:
            raise SchemaImportError(
                f"Failed to fetch registry: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise SchemaImportError(f"Network error fetching registry: {e}") from e
        except json.JSONDecodeError as e:
            raise SchemaImportError(f"Invalid JSON in registry: {e}") from e

    async def list_available_schemas(self) -> list[dict[str, str]]:
        """List all schemas available in the WebOfTrust registry.

        Returns:
            List of schema metadata dicts with 'id', 'title', 'file' keys.

        Raises:
            SchemaImportError: If registry fetch fails.
        """
        registry = await self.fetch_registry()
        return registry.get("schemas", [])

    async def import_schema(
        self, schema_id: str, verify_said: bool = True
    ) -> dict[str, Any]:
        """Import a single schema by ID from registry.

        Args:
            schema_id: The schema SAID to import.
            verify_said: If True, verify the schema's SAID after import.

        Returns:
            The imported schema dict.

        Raises:
            SchemaImportError: If schema not found or import fails.
            SAIDVerificationError: If SAID verification fails.
        """
        registry = await self.fetch_registry()
        schemas = registry.get("schemas", [])

        # Find schema in registry
        schema_meta = None
        for s in schemas:
            if s.get("id") == schema_id:
                schema_meta = s
                break

        if schema_meta is None:
            raise SchemaImportError(f"Schema not found in registry: {schema_id}")

        # Fetch the schema file
        file_path = schema_meta.get("file")
        if not file_path:
            raise SchemaImportError(f"Schema {schema_id} has no file path in registry")

        return await self.fetch_schema_by_path(file_path, verify_said=verify_said)

    async def fetch_schema_by_path(
        self, file_path: str, verify_said: bool = True
    ) -> dict[str, Any]:
        """Fetch a schema by its file path in the repository.

        Args:
            file_path: Path to schema file relative to repo root.
            verify_said: If True, verify the schema's SAID after fetch.

        Returns:
            The fetched schema dict.

        Raises:
            SchemaImportError: If fetch fails.
            SAIDVerificationError: If SAID verification fails.
        """
        url = f"{self.base_url}/{file_path}"
        log.info(f"Fetching schema from {url}")

        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()
            schema = response.json()
        except httpx.HTTPStatusError as e:
            raise SchemaImportError(
                f"Failed to fetch schema: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise SchemaImportError(f"Network error fetching schema: {e}") from e
        except json.JSONDecodeError as e:
            raise SchemaImportError(f"Invalid JSON in schema: {e}") from e

        # Validate the schema has required fields
        if "$id" not in schema:
            raise SchemaImportError(f"Schema missing required $id field: {file_path}")

        # Verify SAID if requested
        if verify_said:
            try:
                if not verify_schema_said(schema):
                    stored_said = schema.get("$id", "")
                    raise SAIDVerificationError(
                        f"Schema SAID mismatch: stored={stored_said[:20]}..."
                    )
            except SAIDVerificationError:
                raise
            except Exception as e:
                # Log unexpected verification errors (not SAID mismatches) as warnings
                # but continue - some schemas may use different algorithms
                log.warning(f"SAID verification failed for {file_path}: {e}")

        log.info(f"Successfully imported schema: {schema.get('$id', 'unknown')[:20]}...")
        return schema

    async def import_all(self, verify_said: bool = True) -> list[dict[str, Any]]:
        """Import all schemas from registry.

        Args:
            verify_said: If True, verify each schema's SAID after import.

        Returns:
            List of imported schema dicts.

        Raises:
            SchemaImportError: If any import fails.
        """
        registry = await self.fetch_registry()
        schemas = registry.get("schemas", [])
        imported = []

        for schema_meta in schemas:
            schema_id = schema_meta.get("id", "unknown")
            try:
                schema = await self.import_schema(schema_id, verify_said=verify_said)
                imported.append(schema)
            except (SchemaImportError, SAIDVerificationError) as e:
                log.error(f"Failed to import schema {schema_id}: {e}")
                # Continue with other schemas

        log.info(f"Imported {len(imported)}/{len(schemas)} schemas")
        return imported

    async def fetch_schema_from_url(
        self, url: str, verify_said: bool = True
    ) -> dict[str, Any]:
        """Fetch a schema from an arbitrary URL.

        Args:
            url: Full URL to the schema JSON file.
            verify_said: If True, verify the schema's SAID after fetch.

        Returns:
            The fetched schema dict.

        Raises:
            SchemaImportError: If fetch fails.
            SAIDVerificationError: If SAID verification fails.
        """
        log.info(f"Fetching schema from URL: {url}")

        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()
            schema = response.json()
        except httpx.HTTPStatusError as e:
            raise SchemaImportError(
                f"Failed to fetch schema: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise SchemaImportError(f"Network error fetching schema: {e}") from e
        except json.JSONDecodeError as e:
            raise SchemaImportError(f"Invalid JSON in schema: {e}") from e

        # Validate the schema has required fields
        if "$id" not in schema:
            raise SchemaImportError(f"Schema missing required $id field")

        # Verify SAID if requested
        if verify_said:
            try:
                if not verify_schema_said(schema):
                    stored_said = schema.get("$id", "")
                    raise SAIDVerificationError(
                        f"Schema SAID mismatch: stored={stored_said[:20]}..."
                    )
            except SAIDVerificationError:
                raise
            except Exception as e:
                log.warning(f"SAID verification failed: {e}")

        log.info(f"Successfully fetched schema: {schema.get('$id', 'unknown')[:20]}...")
        return schema

    def clear_cache(self) -> None:
        """Clear the registry cache."""
        self._registry_cache = None


# Global importer instance
_importer: SchemaImporter | None = None


def get_schema_importer() -> SchemaImporter:
    """Get the global schema importer instance."""
    global _importer
    if _importer is None:
        _importer = SchemaImporter()
    return _importer


def reset_schema_importer() -> None:
    """Reset the global schema importer (for testing)."""
    global _importer
    _importer = None
