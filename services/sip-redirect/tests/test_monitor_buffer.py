"""Tests for Sprint 48: SIPEvent response_vvp_headers and buffer backward compat.

Tests cover:
- SIPEvent with response_vvp_headers field
- Backward compatibility (events without response_vvp_headers)
- Buffer serialization includes response_vvp_headers
"""

import pytest

from app.monitor.buffer import SIPEvent, SIPEventBuffer


def _make_event_data(**overrides):
    """Create minimal event data dict for testing."""
    defaults = {
        "service": "SIGNING",
        "source_addr": "10.0.0.1:5060",
        "method": "INVITE",
        "request_uri": "sip:1006@pbx.rcnx.io",
        "call_id": "test-call-123",
        "from_tn": "1001",
        "to_tn": "1006",
        "api_key_prefix": "test1234",
        "headers": {"Via": "SIP/2.0/UDP 10.0.0.1"},
        "vvp_headers": {"X-VVP-API-Key": "test1234..."},
        "response_code": 302,
        "vvp_status": "VALID",
        "response_vvp_headers": {
            "P-VVP-Identity": "base64data",
            "X-VVP-Status": "VALID",
        },
        "redirect_uri": "sip:1006@10.0.0.2",
        "error": None,
    }
    defaults.update(overrides)
    return defaults


class TestSIPEventResponseVvpHeaders:
    """Test SIPEvent with response_vvp_headers field."""

    async def test_event_with_response_vvp_headers(self):
        """Event stores response VVP headers from signing."""
        buffer = SIPEventBuffer(max_size=10)

        event_id = await buffer.add(_make_event_data(
            response_vvp_headers={
                "P-VVP-Identity": "base64data",
                "P-VVP-Passport": "jwt.token.here",
                "X-VVP-Status": "VALID",
                "X-VVP-Brand-Name": "Test Corp",
            },
        ))

        events = await buffer.get_all()
        assert len(events) == 1
        assert events[0]["response_vvp_headers"]["P-VVP-Identity"] == "base64data"
        assert events[0]["response_vvp_headers"]["X-VVP-Brand-Name"] == "Test Corp"

    async def test_backward_compat_no_response_vvp_headers(self):
        """Events without response_vvp_headers get empty dict default."""
        buffer = SIPEventBuffer(max_size=10)

        # Omit response_vvp_headers from event data
        data = _make_event_data()
        del data["response_vvp_headers"]

        event_id = await buffer.add(data)

        events = await buffer.get_all()
        assert len(events) == 1
        assert events[0]["response_vvp_headers"] == {}

    async def test_response_vvp_headers_in_get_since(self):
        """get_since returns response_vvp_headers in serialized events."""
        buffer = SIPEventBuffer(max_size=10)

        await buffer.add(_make_event_data(
            response_vvp_headers={"X-VVP-Status": "VALID"},
        ))

        events = await buffer.get_since(0)
        assert len(events) == 1
        assert events[0]["response_vvp_headers"]["X-VVP-Status"] == "VALID"

    async def test_response_vvp_headers_in_subscriber(self):
        """Subscribers receive response_vvp_headers in event dict."""
        buffer = SIPEventBuffer(max_size=10)
        queue = await buffer.subscribe()

        await buffer.add(_make_event_data(
            response_vvp_headers={"X-VVP-Brand-Logo": "https://example.com/logo.png"},
        ))

        event = queue.get_nowait()
        assert event["response_vvp_headers"]["X-VVP-Brand-Logo"] == "https://example.com/logo.png"

        await buffer.unsubscribe(queue)

    async def test_verification_event(self):
        """Verification events have correct service and response headers."""
        buffer = SIPEventBuffer(max_size=10)

        await buffer.add(_make_event_data(
            service="VERIFICATION",
            vvp_headers={
                "Identity": "jwt.token;info=<url>;alg=ES256",
                "P-VVP-Identity": "base64data",
            },
            response_vvp_headers={
                "X-VVP-Status": "VALID",
                "X-VVP-Brand-Name": "Test Corp",
                "X-VVP-Brand-Logo": "https://example.com/logo.png",
                "X-VVP-Caller-ID": "+15551234567",
            },
        ))

        events = await buffer.get_all()
        assert events[0]["service"] == "VERIFICATION"
        assert events[0]["response_vvp_headers"]["X-VVP-Caller-ID"] == "+15551234567"
