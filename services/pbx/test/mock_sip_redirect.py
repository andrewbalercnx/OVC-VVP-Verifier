#!/usr/bin/env python3
"""Mock VVP SIP Redirect Services.

Sprint 43: Provides mock signing and verification services for PBX testing.

Signing Service (port 5070):
- Receives SIP INVITE
- Adds X-VVP-* headers (Brand-Name, Brand-Logo, Status)
- Returns 302 redirect to original destination

Verification Service (port 5071):
- Receives SIP INVITE with VVP headers
- Validates/extracts headers
- Returns 302 redirect with verified status

Usage:
    python mock_sip_redirect.py

The server listens on:
- UDP 5070: Mock signing service
- UDP 5071: Mock verification service
"""

import asyncio
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("mock-sip-redirect")


@dataclass
class SIPRequest:
    """Parsed SIP request."""

    method: str
    request_uri: str
    via: str
    from_header: str
    to_header: str
    call_id: str
    cseq: str
    contact: Optional[str] = None
    from_tn: Optional[str] = None
    to_tn: Optional[str] = None
    raw: str = ""


def parse_sip_request(data: bytes) -> Optional[SIPRequest]:
    """Parse SIP request from raw bytes."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if not lines:
            return None

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        method = parts[0]
        request_uri = parts[1]

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if not line or line.startswith(" "):
                continue
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        # Extract TNs from URI
        from_tn = None
        to_tn = None

        from_match = re.search(r"sip:(\+?\d+)@", headers.get("from", ""))
        if from_match:
            from_tn = from_match.group(1)

        to_match = re.search(r"sip:(\+?\d+)@", request_uri)
        if to_match:
            to_tn = to_match.group(1)

        return SIPRequest(
            method=method,
            request_uri=request_uri,
            via=headers.get("via", ""),
            from_header=headers.get("from", ""),
            to_header=headers.get("to", ""),
            call_id=headers.get("call-id", ""),
            cseq=headers.get("cseq", ""),
            contact=headers.get("contact"),
            from_tn=from_tn,
            to_tn=to_tn,
            raw=text,
        )
    except Exception as e:
        log.error(f"Failed to parse SIP request: {e}")
        return None


def build_302_response(
    request: SIPRequest,
    contact_uri: str,
    vvp_status: str = "VALID",
    brand_name: str = "Test Corporation Ltd",
    brand_logo: str = "https://example.com/logo.png",
) -> bytes:
    """Build SIP 302 Moved Temporarily response with VVP headers."""
    # URL-encode values for SIP headers
    encoded_brand = quote(brand_name)
    encoded_logo = quote(brand_logo)

    response = f"""SIP/2.0 302 Moved Temporarily
Via: {request.via}
From: {request.from_header}
To: {request.to_header};tag=vvp-mock
Call-ID: {request.call_id}
CSeq: {request.cseq}
Contact: <{contact_uri}>
X-VVP-Brand-Name: {encoded_brand}
X-VVP-Brand-Logo: {encoded_logo}
X-VVP-Status: {vvp_status}
Content-Length: 0

"""
    return response.replace("\n", "\r\n").encode("utf-8")


def build_error_response(request: SIPRequest, code: int, reason: str) -> bytes:
    """Build SIP error response."""
    response = f"""SIP/2.0 {code} {reason}
Via: {request.via}
From: {request.from_header}
To: {request.to_header};tag=vvp-mock-err
Call-ID: {request.call_id}
CSeq: {request.cseq}
Content-Length: 0

"""
    return response.replace("\n", "\r\n").encode("utf-8")


class MockSigningService:
    """Mock VVP Signing Service.

    Receives INVITE, adds VVP attestation headers, returns 302 to loopback.
    """

    def __init__(self, port: int = 5070, loopback_host: str = "127.0.0.1", loopback_port: int = 5080):
        self.port = port
        self.loopback_host = loopback_host
        self.loopback_port = loopback_port
        self.brand_name = "VVP Mock Brand"
        self.brand_logo = "https://vvp.example.com/logo.png"

    async def handle_invite(self, request: SIPRequest, addr: tuple) -> bytes:
        """Handle incoming INVITE by adding VVP headers and redirecting."""
        log.info(f"[SIGNING] INVITE from {addr}: {request.from_tn} -> {request.to_tn}")

        # Extract destination from original request URI
        # Route to loopback (verification) service
        dest_tn = request.to_tn or "unknown"
        contact_uri = f"sip:{dest_tn}@{self.loopback_host}:{self.loopback_port}"

        log.info(f"[SIGNING] Redirecting to {contact_uri} with VVP headers")

        return build_302_response(
            request=request,
            contact_uri=contact_uri,
            vvp_status="VALID",
            brand_name=self.brand_name,
            brand_logo=self.brand_logo,
        )


class MockVerificationService:
    """Mock VVP Verification Service.

    Receives INVITE with VVP headers, validates, returns 302 to final destination.
    """

    def __init__(self, port: int = 5071, pbx_host: str = "127.0.0.1", pbx_port: int = 5060):
        self.port = port
        self.pbx_host = pbx_host
        self.pbx_port = pbx_port

    async def handle_invite(self, request: SIPRequest, addr: tuple) -> bytes:
        """Handle incoming INVITE by validating VVP headers and redirecting."""
        log.info(f"[VERIFY] INVITE from {addr}: {request.from_tn} -> {request.to_tn}")

        # In a real service, we'd validate the VVP headers here
        # For mock, just pass through with the same headers

        # Extract VVP headers from raw request
        vvp_status = "VALID"
        brand_name = "VVP Mock Brand"
        brand_logo = "https://vvp.example.com/logo.png"

        for line in request.raw.split("\r\n"):
            if line.lower().startswith("x-vvp-status:"):
                vvp_status = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-vvp-brand-name:"):
                brand_name = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-vvp-brand-logo:"):
                brand_logo = line.split(":", 1)[1].strip()

        log.info(f"[VERIFY] VVP Status: {vvp_status}, Brand: {brand_name}")

        # Route to PBX internal profile
        dest_tn = request.to_tn or "unknown"
        contact_uri = f"sip:{dest_tn}@{self.pbx_host}:{self.pbx_port}"

        log.info(f"[VERIFY] Redirecting to {contact_uri}")

        return build_302_response(
            request=request,
            contact_uri=contact_uri,
            vvp_status=vvp_status,
            brand_name=brand_name,
            brand_logo=brand_logo,
        )


class SIPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for SIP messages."""

    def __init__(self, handler, service_name: str):
        self.handler = handler
        self.service_name = service_name
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"[{self.service_name}] UDP listener ready")

    def datagram_received(self, data: bytes, addr: tuple):
        log.debug(f"[{self.service_name}] Received {len(data)} bytes from {addr}")

        request = parse_sip_request(data)
        if not request:
            log.warning(f"[{self.service_name}] Failed to parse SIP message")
            return

        if request.method != "INVITE":
            log.info(f"[{self.service_name}] Ignoring {request.method}")
            # Send 200 OK for non-INVITE methods (like ACK)
            return

        # Handle asynchronously
        asyncio.create_task(self._handle_and_respond(request, addr))

    async def _handle_and_respond(self, request: SIPRequest, addr: tuple):
        try:
            response = await self.handler.handle_invite(request, addr)
            self.transport.sendto(response, addr)
            log.info(f"[{self.service_name}] Sent 302 response to {addr}")
        except Exception as e:
            log.error(f"[{self.service_name}] Error handling INVITE: {e}")
            error_response = build_error_response(request, 500, "Server Error")
            self.transport.sendto(error_response, addr)


async def main():
    """Start both mock services."""
    log.info("Starting VVP Mock SIP Redirect Services")

    loop = asyncio.get_running_loop()

    # Create services
    # Signing service redirects directly to PBX external profile
    signing_service = MockSigningService(
        port=5070,
        loopback_host="127.0.0.1",  # Redirect to PBX external profile
        loopback_port=5080,
    )
    # Verification service (not currently used in this flow, but available for testing)
    verification_service = MockVerificationService(
        port=5071,
        pbx_host="127.0.0.1",
        pbx_port=5080,
    )

    # Start UDP listeners
    signing_transport, _ = await loop.create_datagram_endpoint(
        lambda: SIPProtocol(signing_service, "SIGNING"),
        local_addr=("0.0.0.0", 5070),
    )
    verification_transport, _ = await loop.create_datagram_endpoint(
        lambda: SIPProtocol(verification_service, "VERIFY"),
        local_addr=("0.0.0.0", 5071),
    )

    log.info("Mock Signing Service listening on UDP 5070")
    log.info("Mock Verification Service listening on UDP 5071")
    log.info("Press Ctrl+C to stop")

    try:
        await asyncio.Event().wait()  # Run forever
    finally:
        signing_transport.close()
        verification_transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down")
        sys.exit(0)
