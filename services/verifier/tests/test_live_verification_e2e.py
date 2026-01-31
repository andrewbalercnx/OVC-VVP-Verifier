"""E2E integration tests for live verification flow.

These tests verify the complete verification pipeline using the test JWT,
including:
- JWT parsing and signature verification
- OOBI dereferencing from witnesses
- CESR stream parsing with real witness responses
- KEL parsing (filtering non-KEL events like 'rpy')
- SAID validation for self-addressing identifiers
- Dossier fetching and ACDC extraction
- GLEIF LEI lookup (if available)

These tests require network access and are marked with @pytest.mark.integration.
They are the primary way to catch parsing issues that only appear with real data.

Run with: pytest -m integration tests/test_live_verification_e2e.py -v
"""

import pytest

# The test JWT from the simple verification page
TEST_JWT = """eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0IiwicHB0IjoidnZwIiwia2lkIjoiaHR0cDovL3dpdG5lc3M1LnN0YWdlLnByb3ZlbmFudC5uZXQ6NTYzMS9vb2JpL0VHYXk1dWZCcUFhbmJoRmFfcWUtS01GVVBKSG44SjBNRmJhOTZ5eVdSckxGL3dpdG5lc3MifQ.eyJvcmlnIjp7InRuIjpbIjQ0Nzg4NDY2NjIwMCJdfSwiZGVzdCI6eyJ0biI6WyI0NDc3Njk3MTAyODUiXX0sImlhdCI6MTc2OTE4MzMwMiwiY2FyZCI6WyJDQVRFR09SSUVTOiIsIkxPR087SEFTSD1zaGEyNTYtNDBiYWM2ODZhM2YwYjQ4MjUzZGU1NWIzNGY1NTJjODA3MGJhZjIyZjgxMjU1YWFjNDQ5NzIxYzg3OWM3MTZhNDtWQUxVRT1VUkk6aHR0cHM6Ly9vcmlnaW4tY2VsbC1mcmFua2Z1cnQuczMuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb20vYnJhbmQtYXNzZXRzL3JpY2gtY29ubmV4aW9ucy9sb2dvLnBuZyIsIk5PVEU7TEVJOjk4NDUwMERFRTc1MzdBMDdZNjE1IiwiT1JHOlJpY2ggQ29ubmV4aW9ucyJdLCJjYWxsX3JlYXNvbiI6bnVsbCwiZ29hbCI6bnVsbCwiZXZkIjoiaHR0cHM6Ly9vcmlnaW4uZGVtby5wcm92ZW5hbnQubmV0L3YxL2FnZW50L3B1YmxpYy9FSGxWWFVKLWRZS3F0UGR2enRkQ0ZKRWJreXI2elgyZFgxMmh3ZEU5eDhleS9kb3NzaWVyLmNlc3IiLCJvcmlnSWQiOiIiLCJleHAiOjE3NjkxODM2MDIsInJlcXVlc3RfaWQiOiIifQ.OvoaiAwt1dgPb6gLkK7ufWoL2qzdtmudyyiL38oqB0wfaicGSG4B_QFtHY2vS2w-PYZ6LhN9dWXpsOHtpKAXCw""".strip()

# The OOBI URL from the JWT kid header
TEST_OOBI_URL = "http://witness5.stage.provenant.net:5631/oobi/EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF/witness"

# The dossier URL from the JWT evd claim
TEST_DOSSIER_URL = "https://origin.demo.provenant.net/v1/agent/public/EHlVXUJ-dYKqtPdvztdCFJEbkyr6zX2dX12hwdE9x8ey/dossier.cesr"

# Known LEI from the test JWT
TEST_LEI = "984500DEE7537A07Y615"
EXPECTED_LEGAL_NAME = "RICH CONNEXIONS LTD"


@pytest.mark.integration
class TestOOBICESRParsing:
    """Tests for OOBI CESR parsing from real witnesses."""

    def test_fetch_and_parse_oobi_response(self):
        """Fetch OOBI from witness and parse CESR stream.

        This test catches:
        - CESR count code parsing errors (e.g., -V quadlet vs byte count)
        - Non-KEL event filtering (rpy, qry, etc.)
        """
        import urllib.request
        from app.vvp.keri.cesr import parse_cesr_stream
        from app.vvp.keri.kel_parser import _parse_cesr_kel

        # Fetch OOBI data
        with urllib.request.urlopen(TEST_OOBI_URL, timeout=10) as resp:
            data = resp.read()

        # Parse CESR stream - should not raise
        messages = parse_cesr_stream(data)
        assert len(messages) > 0, "CESR stream should contain messages"

        # Check event types
        event_types = [m.event_dict.get("t") for m in messages]
        assert "icp" in event_types, "Should have ICP event"

        # Parse as KEL - should filter non-KEL events
        events = _parse_cesr_kel(data)
        assert len(events) >= 1, "Should have at least one KEL event"

        # All KEL events should be valid types
        for event in events:
            assert event.event_type.value in ("icp", "rot", "ixn", "dip", "drt")

    def test_oobi_icp_event_has_valid_said(self):
        """Verify ICP event SAID validates correctly.

        This test catches:
        - Self-addressing identifier SAID computation errors
        - Canonical serialization issues
        """
        import urllib.request
        from app.vvp.keri.kel_parser import _parse_cesr_kel, validate_event_said_canonical

        # Fetch and parse
        with urllib.request.urlopen(TEST_OOBI_URL, timeout=10) as resp:
            data = resp.read()

        events = _parse_cesr_kel(data)
        icp_event = events[0]

        # Validate SAID - should not raise
        from app.vvp.keri.cesr import parse_cesr_stream
        messages = parse_cesr_stream(data)
        icp_dict = messages[0].event_dict

        try:
            validate_event_said_canonical(icp_dict)
        except Exception as e:
            pytest.fail(f"ICP SAID validation failed: {e}")


@pytest.mark.integration
class TestDossierParsing:
    """Tests for dossier fetching and parsing."""

    def test_fetch_and_parse_dossier(self):
        """Fetch dossier from evd URL and parse ACDCs.

        This test catches:
        - Dossier format issues
        - CESR parsing in dossier content
        - ACDC extraction errors
        """
        import httpx
        from app.vvp.dossier.parser import parse_dossier

        # Fetch dossier
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(TEST_DOSSIER_URL)
            resp.raise_for_status()
            dossier_data = resp.content

        # Parse dossier - should not raise
        nodes, signatures = parse_dossier(dossier_data)

        assert len(nodes) > 0, "Dossier should contain ACDCs"

        # Verify basic ACDC structure
        for node in nodes:
            assert node.said, f"ACDC missing SAID"
            assert node.issuer, f"ACDC {node.said[:16]}... missing issuer"

    def test_dossier_dag_builds_successfully(self):
        """Verify DAG can be built from dossier ACDCs."""
        import httpx
        from app.vvp.dossier.parser import parse_dossier
        from app.vvp.dossier.validator import build_dag

        # Fetch and parse
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(TEST_DOSSIER_URL)
            dossier_data = resp.content

        nodes, _ = parse_dossier(dossier_data)
        dag = build_dag(nodes)

        assert dag is not None
        assert len(dag.nodes) > 0


@pytest.mark.integration
class TestJWTParsing:
    """Tests for JWT parsing."""

    def test_parse_test_jwt(self):
        """Parse the test JWT and extract payload."""
        from app.vvp.passport import parse_passport

        passport = parse_passport(TEST_JWT)

        assert passport.header.alg == "EdDSA"
        assert passport.header.typ == "passport"
        assert passport.header.ppt == "vvp"
        assert passport.header.kid is not None

        assert passport.payload.evd == TEST_DOSSIER_URL
        assert passport.payload.iat > 0

    def test_jwt_kid_contains_oobi_url(self):
        """Verify JWT kid header contains valid OOBI URL."""
        from app.vvp.passport import parse_passport

        passport = parse_passport(TEST_JWT)

        assert passport.header.kid is not None
        assert passport.header.kid.startswith("http")
        assert "oobi" in passport.header.kid


@pytest.mark.integration
class TestGLEIFLookup:
    """Tests for GLEIF LEI lookup."""

    def test_lookup_known_lei(self):
        """Look up the LEI from the test JWT."""
        from app.vvp.gleif import lookup_lei

        # Clear cache to ensure fresh lookup
        lookup_lei.cache_clear()

        record = lookup_lei(TEST_LEI)

        assert record is not None
        assert record.lei == TEST_LEI
        assert record.legal_name == EXPECTED_LEGAL_NAME
        assert record.status == "ACTIVE"


@pytest.mark.integration
class TestFullVerificationFlow:
    """End-to-end tests for complete verification flow."""

    def test_complete_verification_via_http(self):
        """Run complete verification via HTTP endpoint.

        This is the definitive E2E test that exercises the entire
        verification pipeline through the actual HTTP API.
        """
        from fastapi.testclient import TestClient
        from app.main import app
        from app.vvp.passport import parse_passport
        from datetime import datetime, timezone

        # Parse JWT to get iat for time-based verification
        passport = parse_passport(TEST_JWT)
        jwt_time = datetime.fromtimestamp(passport.payload.iat, tz=timezone.utc)

        client = TestClient(app)

        # Call the simple-verify endpoint (uses JWT time internally)
        response = client.post(
            "/ui/simple-verify",
            data={
                "jwt": TEST_JWT,
                "use_jwt_time": "on",  # Use JWT time for old JWTs
            },
        )

        # Check HTTP response
        assert response.status_code == 200, f"HTTP error: {response.status_code}"

        # Response should contain credential cards or error message
        html = response.text

        # Check for parsing errors that should have been caught
        assert "Unknown event type" not in html, "Parsing error: Unknown event type"
        assert "Unexpected byte" not in html, "Parsing error: Unexpected byte in CESR"
        assert "Failed to parse event" not in html, "Parsing error detected"

        # Check for successful graph rendering (credential cards present)
        # The response should contain either credential cards or a valid error
        has_credentials = "credential-card" in html or "VALID" in html or "INDETERMINATE" in html
        has_valid_error = "expired" in html.lower() or "revoked" in html.lower()

        assert has_credentials or has_valid_error, (
            f"Response should contain credentials or valid error, got: {html[:500]}..."
        )
