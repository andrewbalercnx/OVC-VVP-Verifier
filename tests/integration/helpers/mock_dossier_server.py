"""Mock HTTP server for serving dossiers in integration tests."""

import asyncio
from typing import Any

from aiohttp import web


class MockDossierServer:
    """In-memory HTTP server for dossier serving.

    Used in local/docker integration tests to serve dossiers built
    by the issuer, making them accessible to the verifier via EVD URL.
    """

    def __init__(self, port: int = 0):
        """Initialize the mock server.

        Args:
            port: Port to bind to. 0 means auto-assign.
        """
        self.port = port
        self.base_url: str = ""
        self._dossiers: dict[str, tuple[bytes, str]] = {}  # said -> (content, content_type)
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> str:
        """Start the server.

        Returns:
            Base URL of the running server (e.g., http://127.0.0.1:8888)
        """
        self._app = web.Application()
        self._app.router.add_get("/dossier/{said}", self._handle_dossier)
        self._app.router.add_get("/dossier/{said}.cesr", self._handle_dossier_cesr)
        self._app.router.add_get("/dossier/{said}.json", self._handle_dossier_json)
        self._app.router.add_get("/health", self._handle_health)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await self._site.start()

        # Get actual port if 0 was specified
        sockets = self._site._server.sockets
        if sockets:
            actual_port = sockets[0].getsockname()[1]
        else:
            actual_port = self.port

        self.base_url = f"http://127.0.0.1:{actual_port}"
        return self.base_url

    async def stop(self) -> None:
        """Stop the server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self._app = None

    def serve_dossier(
        self,
        said: str,
        content: bytes,
        content_type: str = "application/json",
    ) -> str:
        """Register a dossier to be served.

        Args:
            said: Credential SAID (used as path)
            content: Dossier content bytes
            content_type: MIME type (application/json or application/cesr)

        Returns:
            Full URL where dossier will be served
        """
        self._dossiers[said] = (content, content_type)
        return f"{self.base_url}/dossier/{said}"

    def get_dossier_url(self, said: str, format: str = "json") -> str:
        """Get URL for a dossier.

        Args:
            said: Credential SAID
            format: 'json' or 'cesr'

        Returns:
            Full URL for the dossier
        """
        if format == "cesr":
            return f"{self.base_url}/dossier/{said}.cesr"
        return f"{self.base_url}/dossier/{said}"

    def clear(self) -> None:
        """Clear all registered dossiers."""
        self._dossiers.clear()

    async def _handle_dossier(self, request: web.Request) -> web.Response:
        """Handle dossier GET request."""
        said = request.match_info["said"]
        return self._get_dossier_response(said)

    async def _handle_dossier_cesr(self, request: web.Request) -> web.Response:
        """Handle dossier GET request with .cesr extension."""
        said = request.match_info["said"]
        return self._get_dossier_response(said, force_content_type="application/cesr")

    async def _handle_dossier_json(self, request: web.Request) -> web.Response:
        """Handle dossier GET request with .json extension."""
        said = request.match_info["said"]
        return self._get_dossier_response(said, force_content_type="application/json")

    def _get_dossier_response(
        self, said: str, force_content_type: str | None = None
    ) -> web.Response:
        """Get response for a dossier request."""
        if said not in self._dossiers:
            return web.Response(
                status=404,
                text=f"Dossier not found: {said}",
                content_type="text/plain",
            )

        content, content_type = self._dossiers[said]
        if force_content_type:
            content_type = force_content_type

        return web.Response(
            body=content,
            content_type=content_type,
            headers={
                "X-Dossier-Said": said,
            },
        )

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.Response(
            text='{"status": "ok"}',
            content_type="application/json",
        )
