"""Tests for the unified witness pool.

Coverage target: app/vvp/keri/witness_pool.py
"""

import asyncio
import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.vvp.keri.witness_pool import (
    WitnessPool,
    WitnessEndpoint,
    validate_witness_url,
    extract_witness_base_url,
    get_witness_pool,
    reset_witness_pool,
    ALLOWED_SCHEMES,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the singleton before and after each test."""
    reset_witness_pool()
    yield
    reset_witness_pool()


@pytest.fixture
def sample_gleif_response():
    """Sample GLEIF OOBI response with witness location schemes."""
    # This mimics the real GLEIF response with /loc/scheme replies
    return b''.join([
        json.dumps({
            "v": "KERI10JSON000000_",
            "t": "rpy",
            "d": "ESAID1",
            "r": "/loc/scheme",
            "a": {
                "eid": "BNfDO63ZpGc3xiFb0-jIOUnbr_bA-ixMva5cZb3s4BHB",
                "scheme": "http",
                "url": "http://5.161.69.25:5623/"
            }
        }).encode(),
        json.dumps({
            "v": "KERI10JSON000000_",
            "t": "rpy",
            "d": "ESAID2",
            "r": "/loc/scheme",
            "a": {
                "eid": "BDwydI_FJJ-tvAtCl1tIu_VQqYTI3Q0JyHDhO1v2hZBt",
                "scheme": "http",
                "url": "http://51.161.130.60:5623/"
            }
        }).encode(),
        json.dumps({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2",
            "i": "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2",
            "s": "0",
            "b": ["BNfDO63ZpGc3xiFb0-jIOUnbr_bA-ixMva5cZb3s4BHB"]
        }).encode(),
    ])


# =============================================================================
# URL Validation Tests
# =============================================================================


class TestValidateWitnessUrl:
    """Tests for validate_witness_url function."""

    def test_valid_http_url(self):
        """HTTP URLs are accepted."""
        result = validate_witness_url("http://witness.example.com:5623")
        assert result == "http://witness.example.com:5623"

    def test_valid_https_url(self):
        """HTTPS URLs are accepted."""
        result = validate_witness_url("https://witness.example.com:5623")
        assert result == "https://witness.example.com:5623"

    def test_url_with_path_normalized(self):
        """Paths are stripped during normalization."""
        result = validate_witness_url(
            "http://witness.example.com:5623/oobi/EAID123/witness"
        )
        assert result == "http://witness.example.com:5623"

    def test_url_with_query_normalized(self):
        """Query strings are stripped during normalization."""
        result = validate_witness_url(
            "http://witness.example.com:5623?foo=bar"
        )
        assert result == "http://witness.example.com:5623"

    def test_file_scheme_rejected(self):
        """file:// scheme is rejected (SSRF prevention)."""
        result = validate_witness_url("file:///etc/passwd")
        assert result is None

    def test_ftp_scheme_rejected(self):
        """ftp:// scheme is rejected."""
        result = validate_witness_url("ftp://ftp.example.com")
        assert result is None

    def test_missing_scheme_rejected(self):
        """URLs without scheme are rejected."""
        result = validate_witness_url("witness.example.com:5623")
        assert result is None

    def test_missing_host_rejected(self):
        """URLs without host are rejected."""
        result = validate_witness_url("http://")
        assert result is None

    def test_empty_string_rejected(self):
        """Empty strings return None."""
        result = validate_witness_url("")
        assert result is None

    def test_none_rejected(self):
        """None returns None."""
        result = validate_witness_url(None)
        assert result is None

    def test_malformed_url_rejected(self):
        """Malformed URLs return None."""
        result = validate_witness_url("not a url at all")
        assert result is None


class TestExtractWitnessBaseUrl:
    """Tests for extract_witness_base_url function."""

    def test_extract_from_oobi_url(self):
        """Extract base URL from full OOBI URL."""
        result = extract_witness_base_url(
            "http://witness5.stage.provenant.net:5631/oobi/EAID123/witness"
        )
        assert result == "http://witness5.stage.provenant.net:5631"

    def test_extract_with_https(self):
        """Extract base URL from HTTPS OOBI URL."""
        result = extract_witness_base_url(
            "https://witness.example.com/oobi/EAID/witness/BWIT"
        )
        assert result == "https://witness.example.com"

    def test_invalid_url_returns_none(self):
        """Invalid URLs return None."""
        result = extract_witness_base_url("not-a-url")
        assert result is None


# =============================================================================
# WitnessEndpoint Tests
# =============================================================================


class TestWitnessEndpoint:
    """Tests for WitnessEndpoint dataclass."""

    def test_create_endpoint(self):
        """Create a witness endpoint."""
        endpoint = WitnessEndpoint(
            url="http://witness.example.com:5623",
            source="config",
        )
        assert endpoint.url == "http://witness.example.com:5623"
        assert endpoint.source == "config"
        assert endpoint.aid is None
        assert endpoint.added_at is not None

    def test_endpoint_with_aid(self):
        """Create endpoint with witness AID."""
        endpoint = WitnessEndpoint(
            url="http://witness.example.com:5623",
            source="kel",
            aid="BNfDO63ZpGc3xiFb0-jIOUnbr_bA-ixMva5cZb3s4BHB",
        )
        assert endpoint.aid == "BNfDO63ZpGc3xiFb0-jIOUnbr_bA-ixMva5cZb3s4BHB"


# =============================================================================
# WitnessPool Basic Tests
# =============================================================================


class TestWitnessPoolInit:
    """Tests for WitnessPool initialization."""

    def test_init_with_config_witnesses(self):
        """Initialize with configured witnesses."""
        pool = WitnessPool(
            config_witnesses=[
                "http://witness1.example.com:5631",
                "http://witness2.example.com:5631",
            ],
            gleif_discovery_enabled=False,
        )
        assert pool.configured_count == 2
        assert pool.total_count == 2

    def test_init_validates_urls(self):
        """Invalid URLs are rejected during init."""
        pool = WitnessPool(
            config_witnesses=[
                "http://valid.example.com:5631",
                "file:///invalid",  # Should be rejected
                "not-a-url",  # Should be rejected
            ],
            gleif_discovery_enabled=False,
        )
        # Only the valid URL should be added
        assert pool.configured_count == 1

    def test_init_empty_list(self):
        """Initialize with empty witness list."""
        pool = WitnessPool(
            config_witnesses=[],
            gleif_discovery_enabled=False,
        )
        assert pool.total_count == 0


class TestWitnessPoolAddFrom:
    """Tests for adding witnesses from various sources."""

    def test_add_from_oobi_url(self):
        """Add witness from OOBI URL."""
        pool = WitnessPool(gleif_discovery_enabled=False)
        result = pool.add_from_oobi_url(
            "http://witness5.stage.provenant.net:5631/oobi/EAID/witness"
        )
        assert result is True
        assert pool.oobi_count == 1

    def test_add_duplicate_url_rejected(self):
        """Duplicate URLs are not added."""
        pool = WitnessPool(gleif_discovery_enabled=False)
        pool.add_from_oobi_url("http://witness.example.com:5631/oobi/EAID")
        result = pool.add_from_oobi_url("http://witness.example.com:5631/oobi/OTHER")
        # Same base URL, different path - should be deduplicated
        assert result is False
        assert pool.oobi_count == 1

    def test_add_from_kel(self):
        """Add witnesses from KEL with base URL.

        Note: When using the same base_url for multiple witness AIDs,
        they normalize to the same URL and get deduplicated. This is
        expected behavior - we only need to track unique witness endpoints.
        """
        pool = WitnessPool(gleif_discovery_enabled=False)
        count = pool.add_from_kel(
            witness_aids=["BWIT1", "BWIT2"],
            base_url="http://witness.example.com:5631",
        )
        # Both AIDs normalize to same base URL, so only 1 unique witness
        assert count == 1
        assert pool.kel_count == 1

    def test_add_from_kel_multiple_bases(self):
        """Add witnesses from KEL with different base URLs."""
        pool = WitnessPool(gleif_discovery_enabled=False)
        # Add first witness
        count1 = pool.add_from_kel(
            witness_aids=["BWIT1"],
            base_url="http://witness1.example.com:5631",
        )
        # Add second witness with different base
        count2 = pool.add_from_kel(
            witness_aids=["BWIT2"],
            base_url="http://witness2.example.com:5631",
        )
        assert count1 == 1
        assert count2 == 1
        assert pool.kel_count == 2

    def test_add_invalid_url_rejected(self):
        """Invalid URLs return False."""
        pool = WitnessPool(gleif_discovery_enabled=False)
        result = pool.add_from_oobi_url("not-a-valid-url")
        assert result is False


# =============================================================================
# GLEIF Discovery Tests
# =============================================================================


class TestGleifDiscovery:
    """Tests for GLEIF witness discovery."""

    @pytest.mark.asyncio
    async def test_lazy_discovery(self, sample_gleif_response):
        """GLEIF discovery happens on first get_all_witnesses call."""
        pool = WitnessPool(
            config_witnesses=[],
            gleif_oobi_url="https://www.gleif.org/.well-known/keri/oobi/EROOT",
            gleif_discovery_enabled=True,
            cache_ttl_seconds=300,
        )

        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = sample_gleif_response
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            witnesses = await pool.get_all_witnesses()

            # Should have discovered 2 witnesses from /loc/scheme replies
            assert pool.discovered_count == 2
            assert pool.gleif_status["discovered"] is True

    @pytest.mark.asyncio
    async def test_discovery_caching(self, sample_gleif_response):
        """GLEIF discovery results are cached."""
        pool = WitnessPool(
            config_witnesses=[],
            gleif_oobi_url="https://www.gleif.org/.well-known/keri/oobi/EROOT",
            gleif_discovery_enabled=True,
            cache_ttl_seconds=300,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = sample_gleif_response
        mock_response.raise_for_status = MagicMock()

        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            # First call triggers discovery
            await pool.get_all_witnesses()
            # Second call should use cache
            await pool.get_all_witnesses()

            # HTTP should only be called once
            assert call_count == 1

    @pytest.mark.asyncio
    async def test_discovery_failure_graceful(self):
        """Discovery failure doesn't prevent using configured witnesses."""
        pool = WitnessPool(
            config_witnesses=["http://configured.example.com:5631"],
            gleif_oobi_url="https://www.gleif.org/.well-known/keri/oobi/EROOT",
            gleif_discovery_enabled=True,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            witnesses = await pool.get_all_witnesses()

            # Should still have the configured witness
            assert len(witnesses) == 1
            assert pool.gleif_status["error"] is not None

    @pytest.mark.asyncio
    async def test_discovery_disabled(self):
        """GLEIF discovery can be disabled."""
        pool = WitnessPool(
            config_witnesses=["http://witness.example.com:5631"],
            gleif_oobi_url="https://www.gleif.org/.well-known/keri/oobi/EROOT",
            gleif_discovery_enabled=False,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            witnesses = await pool.get_all_witnesses()

            # HTTP should not be called
            mock_client_class.assert_not_called()
            assert len(witnesses) == 1


# =============================================================================
# Concurrency Tests
# =============================================================================


class TestConcurrency:
    """Tests for thread-safety and concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_discovery_single_fetch(self, sample_gleif_response):
        """Multiple concurrent get_all_witnesses calls result in single fetch."""
        pool = WitnessPool(
            config_witnesses=[],
            gleif_oobi_url="https://www.gleif.org/.well-known/keri/oobi/EROOT",
            gleif_discovery_enabled=True,
        )

        fetch_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal fetch_count
            fetch_count += 1
            # Simulate network delay
            await asyncio.sleep(0.1)
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = sample_gleif_response
            mock_response.raise_for_status = MagicMock()
            return mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            # Start multiple concurrent requests
            tasks = [pool.get_all_witnesses() for _ in range(5)]
            results = await asyncio.gather(*tasks)

            # All should get the same result
            assert all(len(r) == 2 for r in results)
            # But only one HTTP request should have been made
            assert fetch_count == 1


# =============================================================================
# Query Tests
# =============================================================================


class TestQueryAid:
    """Tests for querying witnesses for an AID."""

    @pytest.mark.asyncio
    async def test_query_all_witnesses(self):
        """Query returns all successful responses."""
        pool = WitnessPool(
            config_witnesses=[
                "http://witness1.example.com:5631",
                "http://witness2.example.com:5631",
            ],
            gleif_discovery_enabled=False,
        )

        async def mock_get(url, *args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b'{"kel": "data"}'
            return mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            results = await pool.query_aid("EAID123")

            # Should get responses from both witnesses
            assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_partial_failure(self):
        """Partial failures don't prevent success."""
        pool = WitnessPool(
            config_witnesses=[
                "http://witness1.example.com:5631",
                "http://witness2.example.com:5631",
            ],
            gleif_discovery_enabled=False,
        )

        call_count = 0

        async def mock_get(url, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if "witness1" in url:
                raise httpx.TimeoutException("timeout")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b'{"kel": "data"}'
            return mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            results = await pool.query_aid("EAID123")

            # Should get one successful response
            assert len(results) == 1


# =============================================================================
# Status Tests
# =============================================================================


class TestStatus:
    """Tests for pool status and metrics."""

    def test_get_status(self):
        """get_status returns comprehensive information."""
        pool = WitnessPool(
            config_witnesses=["http://witness.example.com:5631"],
            gleif_oobi_url="https://gleif.org/oobi",
            gleif_discovery_enabled=True,
        )

        status = pool.get_status()

        assert "configured_witnesses" in status
        assert "discovered_witnesses" in status
        assert "gleif_discovery" in status
        assert "witness_urls" in status
        assert status["configured_witnesses"] == 1

    def test_gleif_status(self):
        """gleif_status provides discovery details."""
        pool = WitnessPool(
            gleif_oobi_url="https://gleif.org/oobi",
            gleif_discovery_enabled=True,
        )

        status = pool.gleif_status

        assert status["enabled"] is True
        assert status["discovered"] is False
        assert status["discovery_time"] is None


# =============================================================================
# Singleton Tests
# =============================================================================


class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_witness_pool_returns_same_instance(self):
        """get_witness_pool returns the same instance."""
        with patch.dict("os.environ", {
            "VVP_GLEIF_WITNESS_DISCOVERY": "false"
        }):
            pool1 = get_witness_pool()
            pool2 = get_witness_pool()
            assert pool1 is pool2

    def test_reset_witness_pool(self):
        """reset_witness_pool clears the singleton."""
        with patch.dict("os.environ", {
            "VVP_GLEIF_WITNESS_DISCOVERY": "false"
        }):
            pool1 = get_witness_pool()
            reset_witness_pool()
            pool2 = get_witness_pool()
            assert pool1 is not pool2
