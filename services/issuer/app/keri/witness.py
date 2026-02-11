"""Witness interaction for VVP Issuer.

Handles OOBI publishing to KERI witnesses for identity discovery.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from keri.core import serdering

from app.config import (
    WITNESS_IURLS,
    WITNESS_TIMEOUT_SECONDS,
    WITNESS_RECEIPT_THRESHOLD,
)

# CESR HTTP format constants (from keripy httping)
CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"

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

        Implements the witness receipt protocol:
        1. Send event to each witness, collect their receipts
        2. Send all receipts back to all witnesses for full witnessing

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
        receipts: dict[str, bytes] = {}  # url -> receipt bytes

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # Phase 1: Send event to each witness and collect receipts
            tasks = [
                self._publish_to_witness(client, url, aid, kel_bytes)
                for url in self._witness_urls
            ]
            phase1_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect successful receipts
            for i, result in enumerate(phase1_results):
                url = self._witness_urls[i]
                if isinstance(result, tuple):  # (WitnessResult, receipt_bytes)
                    wr, receipt = result
                    results.append(wr)
                    if wr.success and receipt:
                        receipts[url] = receipt
                elif isinstance(result, Exception):
                    results.append(
                        WitnessResult(url=url, success=False, error=str(result))
                    )
                else:
                    results.append(result)

            # Phase 2: Distribute all receipts to all witnesses
            # Each witness needs receipts from OTHER witnesses so the event
            # can be marked fullyWitnessed (required for OOBI resolution)
            if len(receipts) > 1:
                log.info(f"Distributing {len(receipts)} receipts ({sum(len(r) for r in receipts.values())} bytes) to witnesses")
                all_receipts = bytearray()
                for rct in receipts.values():
                    all_receipts.extend(rct)

                for url in receipts:
                    try:
                        await self._send_receipts(client, url, bytes(all_receipts))
                        log.info(f"Distributed receipts to {url}")
                    except Exception as e:
                        log.warning(f"Failed to distribute receipts to {url}: {e}")

        success_count = sum(1 for r in results if r.success)

        return PublishResult(
            aid=aid,
            success_count=success_count,
            total_count=len(results),
            threshold_met=success_count >= self._threshold,
            witnesses=results,
        )

    async def publish_event(
        self,
        pre: str,
        event_bytes: bytes,
    ) -> PublishResult:
        """Publish a KERI/ACDC event to witnesses.

        Generic method for publishing any CESR-encoded event (KEL, TEL, etc.)
        to configured witnesses. This is semantically equivalent to publish_oobi
        but named more generally for TEL and credential events.

        Args:
            pre: The identifier prefix (AID or registry key)
            event_bytes: CESR-encoded event with signatures

        Returns:
            PublishResult with per-witness results
        """
        return await self.publish_oobi(aid=pre, kel_bytes=event_bytes)

    async def _publish_to_witness(
        self,
        client: httpx.AsyncClient,
        url: str,
        aid: str,
        kel_bytes: bytes,
    ) -> tuple[WitnessResult, Optional[bytes]]:
        """Publish to a single witness and collect receipt.

        Uses CESR HTTP format as expected by keripy witnesses:
        - POST to /receipts endpoint
        - Content-Type: application/cesr+json
        - Body: JSON event (the inception/rotation/interaction event)
        - CESR-ATTACHMENT header: signatures and other attachments

        Returns:
            Tuple of (WitnessResult, receipt_bytes or None)
        """
        start = datetime.now(timezone.utc)

        try:
            # Parse CESR message to extract event JSON and attachments
            # The kel_bytes contains: [event JSON][CESR attachments]
            msg = bytearray(kel_bytes)
            serder = serdering.SerderKERI(raw=msg)
            event_json = bytes(serder.raw)  # JSON event body
            attachments = bytes(msg[serder.size:])  # Everything after the event

            # Build request with CESR HTTP format
            receipts_url = f"{url.rstrip('/')}/receipts"
            headers = {
                "Content-Type": CESR_CONTENT_TYPE,
                CESR_ATTACHMENT_HEADER: attachments.decode("utf-8"),
            }

            response = await client.post(
                receipts_url,
                content=event_json,
                headers=headers,
            )

            elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

            if response.status_code == 200:
                # 200 means witness returned a receipt
                receipt_bytes = response.content
                log.info(f"Published {aid[:16]}... to {receipts_url} ({elapsed_ms}ms), got receipt")
                return (
                    WitnessResult(url=url, success=True, response_time_ms=elapsed_ms),
                    receipt_bytes,
                )
            elif response.status_code == 202:
                # 202 means event escrowed but no receipt yet
                log.info(f"Published {aid[:16]}... to {receipts_url} ({elapsed_ms}ms), escrowed")
                return (
                    WitnessResult(url=url, success=True, response_time_ms=elapsed_ms),
                    None,
                )
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = f": {error_data.get('description', '')}"
                except Exception:
                    pass
                log.warning(f"Witness {receipts_url} returned {response.status_code}{error_detail}")
                return (
                    WitnessResult(
                        url=url,
                        success=False,
                        error=f"HTTP {response.status_code}{error_detail}",
                        response_time_ms=elapsed_ms,
                    ),
                    None,
                )

        except httpx.TimeoutException:
            log.warning(f"Timeout publishing to {url}")
            return (WitnessResult(url=url, success=False, error="Timeout"), None)
        except Exception as e:
            log.error(f"Failed to publish to {url}: {e}")
            return (WitnessResult(url=url, success=False, error=str(e)), None)

    async def _send_receipts(
        self,
        client: httpx.AsyncClient,
        url: str,
        receipt_bytes: bytes,
    ) -> None:
        """Send receipts to a witness.

        This distributes receipts from other witnesses so each witness
        has the full complement needed for fullyWitnessed.

        Receipts are sent to the root endpoint (/) which is the generic
        CESR message handler (HttpEnd) on keripy witnesses. It feeds raw
        bytes into the parser's input stream for processing.
        """
        root_url = f"{url.rstrip('/')}"
        headers = {"Content-Type": "application/cesr"}

        response = await client.put(root_url, content=receipt_bytes, headers=headers)
        if response.status_code not in (200, 202, 204):
            log.warning(f"Failed to distribute receipts to {url}: HTTP {response.status_code}")


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
