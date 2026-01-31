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
