"""Azure Blob Storage helper for serving dossiers in integration tests.

This module provides an Azure Blob Storage-based dossier server that mirrors
the MockDossierServer interface but uses real Azure blob storage for serving
dossiers. Used in Azure mode integration tests for full lifecycle testing.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from azure.storage.blob import (
        BlobServiceClient,
        ContainerClient,
        generate_blob_sas,
        BlobSasPermissions,
        ContentSettings,
    )
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AzureBlobDossierServer:
    """Azure Blob Storage-based dossier server.

    Uploads dossiers to Azure Blob Storage and generates SAS URLs for
    public access. Used in Azure integration tests where the verifier
    fetches dossiers from real HTTP endpoints.

    The interface mirrors MockDossierServer for easy substitution.
    """

    CONTAINER_NAME = "test-dossiers"
    SAS_EXPIRY_HOURS = 24

    def __init__(self, connection_string: str | None = None):
        """Initialize the Azure blob helper.

        Args:
            connection_string: Azure Storage connection string.
                If not provided, reads from VVP_AZURE_STORAGE_CONNECTION_STRING.

        Raises:
            ImportError: If azure-storage-blob is not installed.
            ValueError: If no connection string is provided or found.
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure integration tests. "
                "Install with: pip install azure-storage-blob"
            )

        self.connection_string = connection_string or os.getenv(
            "VVP_AZURE_STORAGE_CONNECTION_STRING"
        )
        if not self.connection_string:
            raise ValueError(
                "Azure Storage connection string required. "
                "Set VVP_AZURE_STORAGE_CONNECTION_STRING environment variable."
            )

        self._blob_service: BlobServiceClient | None = None
        self._container: ContainerClient | None = None
        self._uploaded_blobs: list[str] = []  # Track for cleanup
        self._session_prefix: str = ""  # Unique prefix for this test session
        self.base_url: str = ""  # For interface compatibility

    async def start(self) -> str:
        """Initialize connection and ensure container exists.

        Returns:
            Base URL of the blob storage container (for logging/display).
        """
        self._blob_service = BlobServiceClient.from_connection_string(
            self.connection_string
        )

        # Create container if it doesn't exist
        self._container = self._blob_service.get_container_client(self.CONTAINER_NAME)
        try:
            await self._run_sync(self._container.create_container)
        except Exception as e:
            # Container might already exist
            if "ContainerAlreadyExists" not in str(e):
                raise

        # Generate unique prefix for this test session
        self._session_prefix = f"test-{uuid.uuid4().hex[:8]}"

        # Get account URL for base_url
        self.base_url = self._blob_service.url
        return self.base_url

    async def stop(self) -> None:
        """Clean up uploaded blobs from this test session."""
        if self._container:
            for blob_name in self._uploaded_blobs:
                try:
                    await self._run_sync(
                        lambda: self._container.delete_blob(blob_name)
                    )
                except Exception:
                    pass  # Best effort cleanup
        self._uploaded_blobs.clear()

    def serve_dossier(
        self,
        said: str,
        content: bytes,
        content_type: str = "application/json",
    ) -> str:
        """Upload a dossier and return its SAS URL.

        Args:
            said: Credential SAID (used in blob name).
            content: Dossier content bytes.
            content_type: MIME type (application/json or application/cesr).

        Returns:
            Full SAS URL where dossier can be fetched publicly.
        """
        blob_name = f"{self._session_prefix}/{said}"

        # Determine file extension for content type
        if content_type == "application/cesr":
            blob_name += ".cesr"
        else:
            blob_name += ".json"

        # Upload blob
        blob_client = self._container.get_blob_client(blob_name)
        blob_client.upload_blob(
            content,
            overwrite=True,
            content_settings=ContentSettings(content_type=content_type),
        )
        self._uploaded_blobs.append(blob_name)

        # Generate SAS URL
        sas_url = self._generate_sas_url(blob_name)
        return sas_url

    def get_dossier_url(self, said: str, format: str = "json") -> str:
        """Get URL for a previously uploaded dossier.

        Args:
            said: Credential SAID.
            format: 'json' or 'cesr'.

        Returns:
            Full SAS URL for the dossier.
        """
        blob_name = f"{self._session_prefix}/{said}"
        if format == "cesr":
            blob_name += ".cesr"
        else:
            blob_name += ".json"

        return self._generate_sas_url(blob_name)

    def clear(self) -> None:
        """Clear all uploaded dossiers from this session."""
        if self._container:
            for blob_name in self._uploaded_blobs:
                try:
                    self._container.delete_blob(blob_name)
                except Exception:
                    pass
        self._uploaded_blobs.clear()

    def _generate_sas_url(self, blob_name: str) -> str:
        """Generate a SAS URL for a blob with read permissions.

        Args:
            blob_name: Name of the blob.

        Returns:
            Full URL with SAS token for public read access.
        """
        # Parse account info from connection string
        account_name = self._parse_account_name()
        account_key = self._parse_account_key()

        # Generate SAS token
        sas_token = generate_blob_sas(
            account_name=account_name,
            container_name=self.CONTAINER_NAME,
            blob_name=blob_name,
            account_key=account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.now(timezone.utc) + timedelta(hours=self.SAS_EXPIRY_HOURS),
        )

        # Build full URL
        blob_url = f"https://{account_name}.blob.core.windows.net/{self.CONTAINER_NAME}/{blob_name}"
        return f"{blob_url}?{sas_token}"

    def _parse_account_name(self) -> str:
        """Parse account name from connection string."""
        for part in self.connection_string.split(";"):
            if part.startswith("AccountName="):
                return part.split("=", 1)[1]
        raise ValueError("Could not parse AccountName from connection string")

    def _parse_account_key(self) -> str:
        """Parse account key from connection string."""
        for part in self.connection_string.split(";"):
            if part.startswith("AccountKey="):
                return part.split("=", 1)[1]
        raise ValueError("Could not parse AccountKey from connection string")

    @staticmethod
    async def _run_sync(func):
        """Run a synchronous function in an async context.

        Azure SDK's sync operations can be run directly since they're
        designed to work in both sync and async contexts.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func)


class DossierServerProtocol:
    """Protocol defining the dossier server interface.

    Both MockDossierServer and AzureBlobDossierServer implement this
    interface, allowing tests to work with either implementation.
    """

    base_url: str

    async def start(self) -> str:
        """Start the server and return base URL."""
        ...

    async def stop(self) -> None:
        """Stop the server and cleanup."""
        ...

    def serve_dossier(
        self, said: str, content: bytes, content_type: str = "application/json"
    ) -> str:
        """Register/upload a dossier and return its URL."""
        ...

    def get_dossier_url(self, said: str, format: str = "json") -> str:
        """Get URL for a dossier."""
        ...

    def clear(self) -> None:
        """Clear all dossiers."""
        ...
