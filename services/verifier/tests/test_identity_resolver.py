"""Tests for OOBI-based issuer identity resolution.

Tests the identity_resolver module which provides discovery of issuer
identity information (legalName, LEI) from KERI witness endpoints.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.vvp.keri.identity_resolver import (
    DiscoveredIdentity,
    IdentityCache,
    _parse_credentials_response,
    discover_identities_parallel,
    discover_issuer_identity,
    extract_witness_base_url,
    get_identity_cache,
)


# =============================================================================
# DiscoveredIdentity Tests
# =============================================================================


class TestDiscoveredIdentity:
    """Tests for the DiscoveredIdentity dataclass."""

    def test_creates_with_required_field(self):
        """DiscoveredIdentity requires only aid field."""
        identity = DiscoveredIdentity(aid="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")
        assert identity.aid == "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        assert identity.legal_name is None
        assert identity.lei is None
        assert identity.source_said is None
        assert identity.source_url == ""

    def test_creates_with_all_fields(self):
        """DiscoveredIdentity can have all optional fields populated."""
        identity = DiscoveredIdentity(
            aid="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            legal_name="ACME Corporation",
            lei="5493001KJTIIGC8Y1R17",
            source_said="EAbcdefg123456789",
            source_url="http://witness.example.com/credentials",
        )
        assert identity.legal_name == "ACME Corporation"
        assert identity.lei == "5493001KJTIIGC8Y1R17"
        assert identity.source_said == "EAbcdefg123456789"
        assert identity.source_url == "http://witness.example.com/credentials"


# =============================================================================
# IdentityCache Tests
# =============================================================================


class TestIdentityCache:
    """Tests for the IdentityCache class."""

    def test_cache_miss_returns_false_hit(self):
        """Get returns (None, False) for cache miss."""
        cache = IdentityCache()
        identity, hit = cache.get("EUnknownAID")
        assert identity is None
        assert hit is False

    def test_cache_set_and_get(self):
        """Cache stores and retrieves identity."""
        cache = IdentityCache()
        identity = DiscoveredIdentity(
            aid="ETestAID123",
            legal_name="Test Corp",
        )
        cache.set("ETestAID123", identity)

        retrieved, hit = cache.get("ETestAID123")
        assert hit is True
        assert retrieved is not None
        assert retrieved.legal_name == "Test Corp"

    def test_cache_negative_result(self):
        """Cache stores negative results (None) with hit=True."""
        cache = IdentityCache()
        cache.set("ENotFoundAID", None)

        retrieved, hit = cache.get("ENotFoundAID")
        assert hit is True
        assert retrieved is None

    def test_cache_ttl_expiration(self):
        """Expired entries return cache miss."""
        cache = IdentityCache(ttl_seconds=0.1)  # 100ms TTL
        identity = DiscoveredIdentity(aid="EExpiredAID", legal_name="Expired")
        cache.set("EExpiredAID", identity)

        # Immediately should hit
        _, hit = cache.get("EExpiredAID")
        assert hit is True

        # After TTL should miss
        time.sleep(0.15)
        _, hit = cache.get("EExpiredAID")
        assert hit is False

    def test_cache_clear(self):
        """Clear removes all entries."""
        cache = IdentityCache()
        cache.set("EAID1", DiscoveredIdentity(aid="EAID1"))
        cache.set("EAID2", DiscoveredIdentity(aid="EAID2"))
        assert len(cache) == 2

        cache.clear()
        assert len(cache) == 0
        _, hit = cache.get("EAID1")
        assert hit is False

    def test_cache_len(self):
        """Cache reports correct length."""
        cache = IdentityCache()
        assert len(cache) == 0
        cache.set("EAID1", DiscoveredIdentity(aid="EAID1"))
        assert len(cache) == 1
        cache.set("EAID2", None)  # Negative cache
        assert len(cache) == 2


class TestGetIdentityCache:
    """Tests for the singleton cache accessor."""

    def test_returns_same_instance(self):
        """get_identity_cache returns singleton."""
        cache1 = get_identity_cache()
        cache2 = get_identity_cache()
        assert cache1 is cache2


# =============================================================================
# extract_witness_base_url Tests
# =============================================================================


class TestExtractWitnessBaseUrl:
    """Tests for extracting witness base URL from OOBI URLs."""

    def test_extracts_http_url(self):
        """Extracts base URL from HTTP OOBI URL."""
        oobi = "http://witness5.stage.provenant.net:5631/oobi/EBfdlu8R27Fbx/witness"
        base = extract_witness_base_url(oobi)
        assert base == "http://witness5.stage.provenant.net:5631"

    def test_extracts_https_url(self):
        """Extracts base URL from HTTPS OOBI URL."""
        oobi = "https://secure-witness.example.com:8443/oobi/ETestAID/witness"
        base = extract_witness_base_url(oobi)
        assert base == "https://secure-witness.example.com:8443"

    def test_extracts_url_without_port(self):
        """Extracts base URL when no explicit port."""
        oobi = "https://witness.example.com/oobi/ETestAID/witness"
        base = extract_witness_base_url(oobi)
        assert base == "https://witness.example.com"

    def test_returns_none_for_empty_url(self):
        """Returns None for empty string."""
        assert extract_witness_base_url("") is None

    def test_returns_none_for_none(self):
        """Returns None for None input."""
        assert extract_witness_base_url(None) is None  # type: ignore

    def test_returns_none_for_invalid_url(self):
        """Returns None for malformed URL."""
        assert extract_witness_base_url("not-a-url") is None
        assert extract_witness_base_url("/relative/path") is None


# =============================================================================
# _parse_credentials_response Tests
# =============================================================================


class TestParseCredentialsResponse:
    """Tests for parsing witness credentials response."""

    def test_parses_list_of_credentials(self):
        """Parses identity from list of credentials."""
        target_aid = "EIssueeAID123456"
        response = [
            {
                "d": "ESaidOfCredential",
                "i": "EIssuerAID",
                "a": {
                    "issuee": "EIssueeAID123456",
                    "legalName": "Target Corporation",
                    "LEI": "5493001KJTIIGC8Y1R17",
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.aid == target_aid
        assert identity.legal_name == "Target Corporation"
        assert identity.lei == "5493001KJTIIGC8Y1R17"
        assert identity.source_said == "ESaidOfCredential"

    def test_parses_single_credential_dict(self):
        """Parses identity from single credential (not wrapped in list)."""
        target_aid = "ESingleCredAID"
        response = {
            "d": "ESingleSAID",
            "i": "EIssuerAID",
            "a": {
                "issuee": "ESingleCredAID",
                "legalName": "Single Corp",
            },
        }

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Single Corp"

    def test_parses_wrapped_credentials_response(self):
        """Parses identity from wrapped 'credentials' list."""
        target_aid = "EWrappedAID"
        response = {
            "credentials": [
                {
                    "d": "EWrappedSAID",
                    "a": {
                        "issuee": "EWrappedAID",
                        "legalName": "Wrapped Corp",
                    },
                }
            ]
        }

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Wrapped Corp"

    def test_parses_creds_wrapper(self):
        """Parses identity from 'creds' wrapper (alternative format)."""
        target_aid = "ECredsAID"
        response = {
            "creds": [
                {
                    "d": "ECredsSAID",
                    "a": {
                        "issuee": "ECredsAID",
                        "legalName": "Creds Corp",
                    },
                }
            ]
        }

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Creds Corp"

    def test_parses_sad_wrapper(self):
        """Parses identity from nested 'sad' structure."""
        target_aid = "ESadAID"
        response = [
            {
                "d": "ESadSAID",
                "sad": {
                    "a": {
                        "issuee": "ESadAID",
                        "legalName": "SAD Corp",
                    },
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "SAD Corp"

    def test_falls_back_to_issuer_if_no_issuee(self):
        """Uses issuer as identity target if no issuee field."""
        target_aid = "EIssuerIsTarget"
        response = [
            {
                "d": "ENoIssuee",
                "i": "EIssuerIsTarget",
                "a": {
                    "legalName": "Self-Issued Corp",
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Self-Issued Corp"

    def test_extracts_org_from_vcard(self):
        """Falls back to vCard ORG field for legal name."""
        target_aid = "EVcardAID"
        response = [
            {
                "d": "EVcardSAID",
                "i": "EIssuer",
                "a": {
                    "issuee": "EVcardAID",
                    "LEI": "VCARDLEI123",
                    "vcard": [
                        "BEGIN:VCARD",
                        "VERSION:4.0",
                        "ORG:VCard Organization Ltd",
                        "END:VCARD",
                    ],
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "VCard Organization Ltd"
        assert identity.lei == "VCARDLEI123"

    def test_legal_name_takes_precedence_over_vcard(self):
        """legalName field takes precedence over vCard ORG."""
        target_aid = "EPrecedenceAID"
        response = [
            {
                "d": "EPrecedenceSAID",
                "a": {
                    "issuee": "EPrecedenceAID",
                    "legalName": "Official Legal Name",
                    "vcard": ["ORG:VCard Org Name"],
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Official Legal Name"

    def test_returns_none_for_wrong_issuee(self):
        """Returns None if no credential matches target AID."""
        target_aid = "ETargetNotFound"
        response = [
            {
                "d": "EOtherSAID",
                "a": {
                    "issuee": "EDifferentAID",
                    "legalName": "Different Corp",
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is None

    def test_returns_none_for_no_identity_fields(self):
        """Returns None if credential has no identity fields."""
        target_aid = "ENoIdentityAID"
        response = [
            {
                "d": "ENoIdentitySAID",
                "a": {
                    "issuee": "ENoIdentityAID",
                    "someOtherField": "value",
                },
            }
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is None

    def test_returns_none_for_empty_list(self):
        """Returns None for empty credentials list."""
        identity = _parse_credentials_response([], "EAnyAID")
        assert identity is None

    def test_returns_none_for_non_dict_credentials(self):
        """Skips non-dict items in credentials list."""
        target_aid = "ESkipNonDict"
        response = [
            "not a dict",
            123,
            None,
            {
                "d": "EValidSAID",
                "a": {
                    "issuee": "ESkipNonDict",
                    "legalName": "Valid After Junk",
                },
            },
        ]

        identity = _parse_credentials_response(response, target_aid)
        assert identity is not None
        assert identity.legal_name == "Valid After Junk"


# =============================================================================
# discover_issuer_identity Tests (Async)
# =============================================================================


class TestDiscoverIssuerIdentity:
    """Tests for async issuer identity discovery."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear identity cache before each test."""
        get_identity_cache().clear()
        yield
        get_identity_cache().clear()

    @pytest.mark.asyncio
    async def test_returns_none_without_oobi_url(self):
        """Returns None when no OOBI URL provided."""
        identity = await discover_issuer_identity("ETestAID")
        assert identity is None

    @pytest.mark.asyncio
    async def test_returns_none_for_invalid_oobi_url(self):
        """Returns None for unparseable OOBI URL."""
        identity = await discover_issuer_identity(
            "ETestAID",
            oobi_url="not-a-valid-url",
        )
        assert identity is None

    @pytest.mark.asyncio
    async def test_caches_negative_result(self):
        """Caches negative result (no identity found)."""
        identity = await discover_issuer_identity(
            "ENegativeCacheAID",
            oobi_url=None,
            use_cache=True,
        )
        assert identity is None

        # Check cache has negative entry
        cache = get_identity_cache()
        cached, hit = cache.get("ENegativeCacheAID")
        assert hit is True
        assert cached is None

    @pytest.mark.asyncio
    async def test_returns_cached_identity(self):
        """Returns cached identity without network query."""
        # Pre-populate cache
        cache = get_identity_cache()
        cached_identity = DiscoveredIdentity(
            aid="ECachedAID",
            legal_name="Cached Corp",
        )
        cache.set("ECachedAID", cached_identity)

        # Should return cached value without making HTTP request
        identity = await discover_issuer_identity(
            "ECachedAID",
            oobi_url="http://witness.example.com/oobi/ECachedAID/witness",
            use_cache=True,
        )
        assert identity is not None
        assert identity.legal_name == "Cached Corp"

    @pytest.mark.asyncio
    async def test_bypasses_cache_when_disabled(self):
        """Skips cache when use_cache=False."""
        # Pre-populate cache with different value
        cache = get_identity_cache()
        cache.set(
            "EBypassCacheAID",
            DiscoveredIdentity(aid="EBypassCacheAID", legal_name="Old Value"),
        )

        # With use_cache=False and no network, should return None
        identity = await discover_issuer_identity(
            "EBypassCacheAID",
            oobi_url=None,  # No URL means no network
            use_cache=False,
        )
        assert identity is None

    @pytest.mark.asyncio
    async def test_discovers_identity_from_witness(self):
        """Successfully discovers identity from mocked witness endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "d": "EDiscoveredSAID",
                "i": "EIssuerAID",
                "a": {
                    "issuee": "EDiscoverTargetAID",
                    "legalName": "Discovered Corporation",
                    "LEI": "DISC123456789",
                },
            }
        ]

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_async_client

            identity = await discover_issuer_identity(
                "EDiscoverTargetAID",
                oobi_url="http://witness.example.com:5631/oobi/EDiscoverTargetAID/witness",
                use_cache=False,
            )

            assert identity is not None
            assert identity.aid == "EDiscoverTargetAID"
            assert identity.legal_name == "Discovered Corporation"
            assert identity.lei == "DISC123456789"
            assert identity.source_url == "http://witness.example.com:5631/credentials?issuer=EDiscoverTargetAID"

    @pytest.mark.asyncio
    async def test_tries_second_endpoint_on_first_failure(self):
        """Falls back to second endpoint if first returns nothing."""
        first_response = MagicMock()
        first_response.status_code = 404

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.json.return_value = [
            {
                "d": "ESecondEndpointSAID",
                "a": {
                    "issuee": "EFallbackAID",
                    "legalName": "Fallback Corp",
                },
            }
        ]

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            if "credentials?issuer" in url:
                return first_response
            return second_response

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = mock_get
            mock_client.return_value.__aenter__.return_value = mock_async_client

            identity = await discover_issuer_identity(
                "EFallbackAID",
                oobi_url="http://witness.example.com/oobi/EFallbackAID/witness",
                use_cache=False,
            )

            assert identity is not None
            assert identity.legal_name == "Fallback Corp"
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_handles_timeout_gracefully(self):
        """Returns None on timeout without raising."""
        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.return_value.__aenter__.return_value = mock_async_client

            identity = await discover_issuer_identity(
                "ETimeoutAID",
                oobi_url="http://witness.example.com/oobi/ETimeoutAID/witness",
                use_cache=False,
            )

            assert identity is None

    @pytest.mark.asyncio
    async def test_handles_network_error_gracefully(self):
        """Returns None on network error without raising."""
        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = httpx.RequestError("connection failed")
            mock_client.return_value.__aenter__.return_value = mock_async_client

            identity = await discover_issuer_identity(
                "ENetworkErrorAID",
                oobi_url="http://witness.example.com/oobi/ENetworkErrorAID/witness",
                use_cache=False,
            )

            assert identity is None

    @pytest.mark.asyncio
    async def test_caches_discovered_identity(self):
        """Caches successfully discovered identity."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "d": "ECacheMeSAID",
                "a": {
                    "issuee": "ECacheMeAID",
                    "legalName": "Cache Me Corp",
                },
            }
        ]

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_async_client

            identity = await discover_issuer_identity(
                "ECacheMeAID",
                oobi_url="http://witness.example.com/oobi/ECacheMeAID/witness",
                use_cache=True,
            )

            assert identity is not None
            assert identity.legal_name == "Cache Me Corp"

        # Verify cached
        cache = get_identity_cache()
        cached, hit = cache.get("ECacheMeAID")
        assert hit is True
        assert cached is not None
        assert cached.legal_name == "Cache Me Corp"


# =============================================================================
# discover_identities_parallel Tests
# =============================================================================


class TestDiscoverIdentitiesParallel:
    """Tests for parallel identity discovery."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear identity cache before each test."""
        get_identity_cache().clear()
        yield
        get_identity_cache().clear()

    @pytest.mark.asyncio
    async def test_returns_empty_dict_for_empty_list(self):
        """Returns empty dict when no AIDs provided."""
        result = await discover_identities_parallel([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_discovers_multiple_identities(self):
        """Discovers identities for multiple AIDs in parallel."""
        responses = {
            "EAID1": [{"d": "ESAID1", "a": {"issuee": "EAID1", "legalName": "Corp One"}}],
            "EAID2": [{"d": "ESAID2", "a": {"issuee": "EAID2", "legalName": "Corp Two"}}],
        }

        async def mock_get(url):
            mock_response = MagicMock()
            for aid, data in responses.items():
                if f"issuer={aid}" in url:
                    mock_response.status_code = 200
                    mock_response.json.return_value = data
                    return mock_response
            mock_response.status_code = 404
            return mock_response

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = mock_get
            mock_client.return_value.__aenter__.return_value = mock_async_client

            result = await discover_identities_parallel(
                ["EAID1", "EAID2"],
                oobi_url="http://witness.example.com/oobi/X/witness",
            )

            assert len(result) == 2
            assert result["EAID1"].legal_name == "Corp One"
            assert result["EAID2"].legal_name == "Corp Two"

    @pytest.mark.asyncio
    async def test_returns_only_found_identities(self):
        """Only returns identities for AIDs where discovery succeeded."""

        async def mock_get(url):
            mock_response = MagicMock()
            if "issuer=EFoundAID" in url:
                mock_response.status_code = 200
                mock_response.json.return_value = [
                    {"d": "EFoundSAID", "a": {"issuee": "EFoundAID", "legalName": "Found Corp"}}
                ]
            else:
                mock_response.status_code = 404
            return mock_response

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = mock_get
            mock_client.return_value.__aenter__.return_value = mock_async_client

            result = await discover_identities_parallel(
                ["EFoundAID", "ENotFoundAID"],
                oobi_url="http://witness.example.com/oobi/X/witness",
            )

            assert len(result) == 1
            assert "EFoundAID" in result
            assert "ENotFoundAID" not in result

    @pytest.mark.asyncio
    async def test_handles_exceptions_gracefully(self):
        """Handles exceptions for individual AIDs without failing others."""

        async def mock_get(url):
            if "issuer=EExceptionAID" in url:
                raise httpx.RequestError("connection failed")
            mock_response = MagicMock()
            if "issuer=ESuccessAID" in url:
                mock_response.status_code = 200
                mock_response.json.return_value = [
                    {"d": "ESuccessSAID", "a": {"issuee": "ESuccessAID", "legalName": "Success Corp"}}
                ]
            else:
                mock_response.status_code = 404
            return mock_response

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = mock_get
            mock_client.return_value.__aenter__.return_value = mock_async_client

            result = await discover_identities_parallel(
                ["ESuccessAID", "EExceptionAID"],
                oobi_url="http://witness.example.com/oobi/X/witness",
            )

            # Should have success even though one failed
            assert len(result) == 1
            assert "ESuccessAID" in result
            assert result["ESuccessAID"].legal_name == "Success Corp"

    @pytest.mark.asyncio
    async def test_runs_queries_in_parallel(self):
        """Verifies queries run concurrently, not sequentially."""
        call_times = []

        async def mock_get(url):
            call_times.append(time.time())
            await asyncio.sleep(0.1)  # Simulate network latency
            mock_response = MagicMock()
            mock_response.status_code = 404
            return mock_response

        with patch("app.vvp.keri.identity_resolver.httpx.AsyncClient") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.side_effect = mock_get
            mock_client.return_value.__aenter__.return_value = mock_async_client

            start = time.time()
            await discover_identities_parallel(
                ["EAID1", "EAID2", "EAID3"],
                oobi_url="http://witness.example.com/oobi/X/witness",
            )
            elapsed = time.time() - start

            # If parallel: ~0.1s total (plus overhead)
            # If sequential: ~0.3s+ total
            # Use 0.25s as threshold to allow for overhead
            assert elapsed < 0.25, f"Queries took {elapsed}s - not parallel"
