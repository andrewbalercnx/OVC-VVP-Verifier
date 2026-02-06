"""Tests for GLEIF LEI lookup functionality."""

import pytest
from unittest.mock import patch, Mock

from app.vvp.gleif import lookup_lei, get_legal_name_for_lei, LEIRecord, _parse_lei_response


class TestParseLeiResponse:
    """Tests for GLEIF API response parsing."""

    def test_parse_valid_response(self):
        """Parse a complete GLEIF API response."""
        response = {
            "data": {
                "type": "lei-records",
                "id": "984500DEE7537A07Y615",
                "attributes": {
                    "lei": "984500DEE7537A07Y615",
                    "entity": {
                        "legalName": {
                            "name": "RICH CONNEXIONS LTD",
                            "language": "en"
                        },
                        "status": "ACTIVE",
                        "jurisdiction": "GB",
                        "legalAddress": {
                            "city": "Ware",
                            "country": "GB"
                        }
                    }
                }
            }
        }

        record = _parse_lei_response(response)

        assert record.lei == "984500DEE7537A07Y615"
        assert record.legal_name == "RICH CONNEXIONS LTD"
        assert record.status == "ACTIVE"
        assert record.jurisdiction == "GB"
        assert record.legal_address_city == "Ware"
        assert record.legal_address_country == "GB"

    def test_parse_minimal_response(self):
        """Parse a minimal response with missing fields."""
        response = {
            "data": {
                "id": "TESTLEI12345678901234",
                "attributes": {
                    "entity": {
                        "legalName": {
                            "name": "Test Company"
                        }
                    }
                }
            }
        }

        record = _parse_lei_response(response)

        assert record.lei == "TESTLEI12345678901234"
        assert record.legal_name == "Test Company"
        assert record.status == "UNKNOWN"
        assert record.jurisdiction is None

    def test_parse_empty_response(self):
        """Parse empty response returns defaults."""
        response = {}

        record = _parse_lei_response(response)

        assert record.lei == ""
        assert record.legal_name == "Unknown"
        assert record.status == "UNKNOWN"


class TestLookupLei:
    """Tests for LEI lookup function."""

    def test_invalid_lei_format_returns_none(self):
        """Invalid LEI format should return None without API call."""
        assert lookup_lei("short") is None
        assert lookup_lei("") is None
        assert lookup_lei(None) is None
        assert lookup_lei("toolong12345678901234567890") is None

    @patch("app.vvp.gleif.httpx.Client")
    def test_lookup_success(self, mock_client_class):
        """Successful API lookup returns LEIRecord."""
        # Clear LRU cache to avoid stale data
        lookup_lei.cache_clear()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "id": "12345678901234567890",
                "attributes": {
                    "lei": "12345678901234567890",
                    "entity": {
                        "legalName": {"name": "Test Corp"},
                        "status": "ACTIVE"
                    }
                }
            }
        }

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        result = lookup_lei("12345678901234567890")

        assert result is not None
        assert result.legal_name == "Test Corp"
        assert result.lei == "12345678901234567890"

    @patch("app.vvp.gleif.httpx.Client")
    def test_lookup_not_found_returns_none(self, mock_client_class):
        """404 response returns None."""
        lookup_lei.cache_clear()

        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        result = lookup_lei("00000000000000000000")

        assert result is None


class TestGetLegalNameForLei:
    """Tests for convenience function."""

    @patch("app.vvp.gleif.lookup_lei")
    def test_returns_legal_name_when_found(self, mock_lookup):
        """Returns just the legal name string."""
        mock_lookup.return_value = LEIRecord(
            lei="12345678901234567890",
            legal_name="Test Company Ltd"
        )

        result = get_legal_name_for_lei("12345678901234567890")

        assert result == "Test Company Ltd"

    @patch("app.vvp.gleif.lookup_lei")
    def test_returns_none_when_not_found(self, mock_lookup):
        """Returns None when LEI not found."""
        mock_lookup.return_value = None

        result = get_legal_name_for_lei("99999999999999999999")

        assert result is None


class TestLookupLeiExceptionHandling:
    """Tests for exception handling in lookup_lei."""

    @patch("app.vvp.gleif.httpx.Client")
    def test_lookup_timeout_returns_none(self, mock_client_class):
        """Timeout exception returns None."""
        import httpx
        lookup_lei.cache_clear()

        mock_client = Mock()
        mock_client.get.side_effect = httpx.TimeoutException("Connection timed out")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        result = lookup_lei("11111111111111111111")
        assert result is None

    @patch("app.vvp.gleif.httpx.Client")
    def test_lookup_http_error_returns_none(self, mock_client_class):
        """HTTP status error returns None."""
        import httpx
        lookup_lei.cache_clear()

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Internal Server Error", request=Mock(), response=mock_response
        )

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        result = lookup_lei("22222222222222222222")
        assert result is None

    @patch("app.vvp.gleif.httpx.Client")
    def test_lookup_generic_exception_returns_none(self, mock_client_class):
        """Generic exception returns None."""
        lookup_lei.cache_clear()

        mock_client = Mock()
        mock_client.get.side_effect = Exception("Unexpected error")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        result = lookup_lei("33333333333333333333")
        assert result is None


class TestLookupLeiAsync:
    """Tests for async LEI lookup function."""

    @pytest.mark.asyncio
    async def test_async_invalid_lei_format_returns_none(self):
        """Invalid LEI format should return None without API call."""
        from app.vvp.gleif import lookup_lei_async

        assert await lookup_lei_async("short") is None
        assert await lookup_lei_async("") is None
        assert await lookup_lei_async(None) is None
        assert await lookup_lei_async("toolong12345678901234567890") is None

    @pytest.mark.asyncio
    @patch("app.vvp.gleif.httpx.AsyncClient")
    async def test_async_lookup_not_found_returns_none(self, mock_client_class):
        """Async 404 response returns None."""
        from unittest.mock import AsyncMock
        from app.vvp.gleif import lookup_lei_async

        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        result = await lookup_lei_async("55555555555555555555")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.vvp.gleif.httpx.AsyncClient")
    async def test_async_lookup_timeout_returns_none(self, mock_client_class):
        """Async timeout returns None."""
        import httpx
        from unittest.mock import AsyncMock
        from app.vvp.gleif import lookup_lei_async

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.TimeoutException("Async timeout")
        mock_client_class.return_value = mock_client

        result = await lookup_lei_async("66666666666666666666")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.vvp.gleif.httpx.AsyncClient")
    async def test_async_lookup_http_error_returns_none(self, mock_client_class):
        """Async HTTP error returns None."""
        import httpx
        from unittest.mock import AsyncMock
        from app.vvp.gleif import lookup_lei_async

        mock_response = Mock()
        mock_response.status_code = 503

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.HTTPStatusError(
            "Service Unavailable", request=Mock(), response=mock_response
        )
        mock_client_class.return_value = mock_client

        result = await lookup_lei_async("77777777777777777777")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.vvp.gleif.httpx.AsyncClient")
    async def test_async_lookup_generic_error_returns_none(self, mock_client_class):
        """Async generic exception returns None."""
        from unittest.mock import AsyncMock
        from app.vvp.gleif import lookup_lei_async

        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Unexpected async error")
        mock_client_class.return_value = mock_client

        result = await lookup_lei_async("88888888888888888888")
        assert result is None


@pytest.mark.integration
class TestLiveGleifLookup:
    """Live integration tests for GLEIF API.

    These require network access and are skipped by default.
    Run with: pytest -m integration tests/test_gleif.py
    """

    def test_live_lookup_known_lei(self):
        """Test live lookup of a known LEI."""
        lookup_lei.cache_clear()

        # Rich Connexions Ltd - used in test JWT
        result = lookup_lei("984500DEE7537A07Y615")

        assert result is not None
        assert result.legal_name == "RICH CONNEXIONS LTD"
        assert result.status == "ACTIVE"
        assert result.jurisdiction == "GB"

    def test_live_lookup_invalid_lei_returns_none(self):
        """Test that invalid LEI returns None."""
        lookup_lei.cache_clear()

        result = lookup_lei("00000000000000000000")

        assert result is None
