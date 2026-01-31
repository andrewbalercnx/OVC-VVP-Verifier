"""Witness interaction for VVP Issuer.

Handles OOBI publishing to KERI witnesses for identity discovery.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import (
    WITNESS_IURLS,
    WITNESS_TIMEOUT_SECONDS,
    WITNESS_RECEIPT_THRESHOLD,
)

log = logging.getLogger(__name__)


@dataclass
class WitnessResult:
    """Result of publishing to a single witness."""

    url: str
    success: bool
    error: Optional[str] = None
    response_time_ms: Optional[int] = None


@dataclass
class PublishResult:
    """Result of publishing to all witnesses."""

    aid: str
    success_count: int
    total_count: int
    threshold_met: bool
    witnesses: list[WitnessResult]


class WitnessPublisher:
    """Publishes identity events to KERI witnesses.

    Handles HTTP-based OOBI publishing to witness endpoints.
    Uses configurable threshold for success determination.
    """

    def __init__(
        self,
        witness_urls: Optional[list[str]] = None,
        timeout: float = WITNESS_TIMEOUT_SECONDS,
        threshold: int = WITNESS_RECEIPT_THRESHOLD,
    ):
        """Initialize witness publisher.

        Args:
            witness_urls: List of witness HTTP URLs
            timeout: HTTP timeout in seconds
            threshold: Minimum witnesses for success
        """
        self._witness_urls = witness_urls or self._extract_urls_from_iurls()
        self._timeout = timeout
        self._threshold = threshold

    def _extract_urls_from_iurls(self) -> list[str]:
        """Extract base URLs from OOBI iurls."""
        urls = []
        for iurl in WITNESS_IURLS:
            # iurls format: http://host:port/oobi/{aid}/controller
            # Extract: http://host:port
            parts = iurl.split("/oobi/")
            if parts:
                urls.append(parts[0])
        return urls

    async def publish_oobi(
        self,
        aid: str,
        kel_bytes: bytes,
    ) -> PublishResult:
        """Publish identity KEL to witnesses.

        Posts the inception event to each witness endpoint
        to establish the identity's OOBI resolution.

        Args:
            aid: The AID being published
            kel_bytes: Serialized KEL events (inception + signatures)

        Returns:
            PublishResult with per-witness results
        """
        if not self._witness_urls:
            log.warning("No witness URLs configured for publishing")
            return PublishResult(
                aid=aid,
                success_count=0,
                total_count=0,
                threshold_met=False,
                witnesses=[],
            )

        results: list[WitnessResult] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            tasks = [
                self._publish_to_witness(client, url, aid, kel_bytes)
                for url in self._witness_urls
            ]
            task_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to WitnessResult
        for i, result in enumerate(task_results):
            if isinstance(result, Exception):
                results.append(
                    WitnessResult(
                        url=self._witness_urls[i],
                        success=False,
                        error=str(result),
                    )
                )
            else:
                results.append(result)

        success_count = sum(1 for r in results if r.success)

        return PublishResult(
            aid=aid,
            success_count=success_count,
            total_count=len(results),
            threshold_met=success_count >= self._threshold,
            witnesses=results,
        )

    async def _publish_to_witness(
        self,
        client: httpx.AsyncClient,
        url: str,
        aid: str,
        kel_bytes: bytes,
    ) -> WitnessResult:
        """Publish to a single witness."""
        start = datetime.now(timezone.utc)

        try:
            # Post KEL to witness endpoint
            # Witnesses accept CESR-encoded messages at root endpoint
            response = await client.post(
                url,
                content=kel_bytes,
                headers={"Content-Type": "application/cesr"},
            )

            elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

            if response.status_code in (200, 202):
                log.info(f"Published {aid[:16]}... to {url} ({elapsed_ms}ms)")
                return WitnessResult(
                    url=url,
                    success=True,
                    response_time_ms=elapsed_ms,
                )
            else:
                log.warning(f"Witness {url} returned {response.status_code}")
                return WitnessResult(
                    url=url,
                    success=False,
                    error=f"HTTP {response.status_code}",
                    response_time_ms=elapsed_ms,
                )

        except httpx.TimeoutException:
            log.warning(f"Timeout publishing to {url}")
            return WitnessResult(
                url=url,
                success=False,
                error="Timeout",
            )
        except Exception as e:
            log.error(f"Failed to publish to {url}: {e}")
            return WitnessResult(
                url=url,
                success=False,
                error=str(e),
            )


# Module-level singleton
_witness_publisher: Optional[WitnessPublisher] = None


def get_witness_publisher() -> WitnessPublisher:
    """Get or create the witness publisher singleton."""
    global _witness_publisher
    if _witness_publisher is None:
        _witness_publisher = WitnessPublisher()
    return _witness_publisher


def reset_witness_publisher() -> None:
    """Reset the singleton (for testing)."""
    global _witness_publisher
    _witness_publisher = None
