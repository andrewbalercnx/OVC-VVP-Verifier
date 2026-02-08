"""Integration tests for Sprint 51: Verification Result Cache with verify_callee_vvp().

Tests cache hit/miss flows, cache_hit field, and callee-specific phase re-evaluation
through the full verify_callee_vvp() pipeline.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.vvp.api_models import (
    CallContext,
    ClaimStatus,
    SipContext,
)
from app.vvp.verify_callee import verify_callee_vvp


# =============================================================================
# Shared fixtures
# =============================================================================

EVD_URL = "http://callee-cache-test.example.com/dossier.cesr"
SIGNER_AID = "EAbcCalleeTest12345"
PASSPORT_KID = f"http://witness.example.com/oobi/{SIGNER_AID}/witness/EXyz"


@pytest.fixture
def callee_context():
    return CallContext(
        call_id="callee-test-123",
        received_at="2024-01-01T00:00:00Z",
        sip=SipContext(
            from_uri="sip:+15551234567@example.com",
            to_uri="sip:+15559876543@example.com",
            invite_time="2024-01-01T00:00:00Z",
            cseq=1,
        ),
    )


class _CalleePatchedPipeline:
    """Context manager wrapping all patches for a full VALID callee pipeline."""

    def __init__(self):
        self.mocks = {}
        self._patches = []

    def __enter__(self):
        sync_targets = {
            "vvp": "app.vvp.verify_callee.parse_vvp_identity",
            "passport": "app.vvp.verify_callee.parse_passport",
            "binding": "app.vvp.verify_callee.validate_passport_binding",
            "fetch": "app.vvp.verify_callee.fetch_dossier",
            "parse": "app.vvp.verify_callee.parse_dossier",
            "build": "app.vvp.verify_callee.build_dag",
            "validate": "app.vvp.verify_callee.validate_dag",
        }
        async_targets = {
            "sig": "app.vvp.verify_callee.verify_passport_signature_tier2",
            "chain": "app.vvp.acdc.validate_credential_chain",
            "revocation": "app.vvp.verify.check_dossier_revocations",
        }
        for name, target in sync_targets.items():
            p = patch(target)
            self.mocks[name] = p.start()
            self._patches.append(p)
        for name, target in async_targets.items():
            p = patch(target, new_callable=AsyncMock)
            self.mocks[name] = p.start()
            self._patches.append(p)

        self._configure_valid_defaults()
        return self

    def __exit__(self, *args):
        for p in self._patches:
            p.stop()

    def _configure_valid_defaults(self):
        m = self.mocks
        m["vvp"].return_value = MagicMock(evd=EVD_URL)

        m["passport"].return_value = MagicMock(
            header=MagicMock(kid=PASSPORT_KID),
            payload=MagicMock(
                orig={"tn": ["+15551234567"]},
                card=None,
                goal=None,
                iat=time.time(),
                exp=time.time() + 300,
                call_id="callee-test-123",
                cseq=1,
            ),
        )
        m["binding"].return_value = None
        m["sig"].return_value = None  # callee uses verify_passport_signature_tier2 (no return)

        m["fetch"].return_value = b"[]"
        m["parse"].return_value = ([], {})

        dag = MagicMock()
        dag.root_said = "SAID_ROOT_CALLEE"
        dag.is_aggregate = False
        dag.nodes = {
            "SAID_ROOT_CALLEE": MagicMock(
                issuer=SIGNER_AID,
                raw={"v": "1.0", "s": "SCHEMA_SAID", "a": {}, "i": SIGNER_AID},
                edges=[],
            )
        }
        dag.root_saids = ["SAID_ROOT_CALLEE"]
        dag.warnings = []
        m["build"].return_value = dag
        m["validate"].return_value = None

        chain_result = MagicMock()
        chain_result.root_aid = "EGLEIF0000000000"
        chain_result.validated = True
        chain_result.has_variant_limitations = False
        chain_result.status = "VALID"
        m["chain"].return_value = chain_result

        # Revocation: VALID (no revocations)
        from app.vvp.verify_callee import ClaimBuilder

        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.add_evidence("all_credentials_unrevoked")
        m["revocation"].return_value = (revocation_claim, [])


# =============================================================================
# Tests
# =============================================================================


class TestCalleeVerifyCachingIntegration:
    """Integration tests for the verification result cache through verify_callee_vvp()."""

    @pytest.mark.asyncio
    async def test_first_call_stores_in_cache(self, callee_context):
        """First call with VALID chain stores in verification cache."""
        with _CalleePatchedPipeline() as pp:
            _, resp1 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Chain should be called (full pipeline)
            assert pp.mocks["chain"].call_count >= 1

            # Check cache was populated
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            assert cache.size >= 1

    @pytest.mark.asyncio
    async def test_second_call_hits_cache(self, callee_context):
        """Second call with same signer hits verification cache."""
        with _CalleePatchedPipeline() as pp:
            # First call — populates cache
            _, resp1 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            chain_calls_1 = pp.mocks["chain"].call_count

            # Second call — should hit cache
            _, resp2 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Chain should NOT be called again (cache hit)
            assert pp.mocks["chain"].call_count == chain_calls_1

    @pytest.mark.asyncio
    async def test_cache_hit_field_false_on_miss(self, callee_context):
        """cache_hit is False on first call (cache miss)."""
        with _CalleePatchedPipeline():
            _, resp = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            assert resp.cache_hit is False

    @pytest.mark.asyncio
    async def test_cache_hit_field_true_on_hit(self, callee_context):
        """cache_hit is True on second call (cache hit)."""
        with _CalleePatchedPipeline():
            # First call — miss
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Second call — hit
            _, resp2 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            assert resp2.cache_hit is True

    @pytest.mark.asyncio
    async def test_cache_hit_in_json_serialization(self, callee_context):
        """cache_hit field appears in model_dump() output."""
        with _CalleePatchedPipeline():
            _, resp = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            dumped = resp.model_dump()
            assert "cache_hit" in dumped
            assert dumped["cache_hit"] is False

    @pytest.mark.asyncio
    async def test_different_kid_is_cache_miss(self, callee_context):
        """Different passport kid → separate cache entry (verification cache miss)."""
        with _CalleePatchedPipeline() as pp:
            # First call
            _, resp1 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            chain_calls_1 = pp.mocks["chain"].call_count

            # Change passport kid
            other_kid = "http://other-witness.example.com/oobi/EDifferent123/witness/EXyz"
            pp.mocks["passport"].return_value = MagicMock(
                header=MagicMock(kid=other_kid),
                payload=MagicMock(
                    orig={"tn": ["+15551234567"]},
                    card=None,
                    goal=None,
                    iat=time.time(),
                    exp=time.time() + 300,
                    call_id="callee-test-123",
                    cseq=1,
                ),
            )

            # Second call — different kid → cache miss
            _, resp2 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Chain should be called again
            assert pp.mocks["chain"].call_count > chain_calls_1

    @pytest.mark.asyncio
    async def test_invalid_chain_not_cached(self, callee_context):
        """INVALID chain result is NOT cached (VALID-only policy)."""
        with _CalleePatchedPipeline() as pp:
            from app.vvp.acdc import ACDCChainInvalid

            pp.mocks["chain"].side_effect = ACDCChainInvalid("No trusted root")

            # First call — INVALID chain
            _, resp1 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Chain should be called
            chain_calls_1 = pp.mocks["chain"].call_count
            assert chain_calls_1 >= 1

            # Second call — should NOT hit cache (INVALID was not cached)
            _, resp2 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            assert pp.mocks["chain"].call_count > chain_calls_1

    @pytest.mark.asyncio
    async def test_cache_disabled_via_feature_flag(self, callee_context):
        """Cache disabled → chain validation runs on every call."""
        with _CalleePatchedPipeline() as pp:
            with patch(
                "app.core.config.VVP_VERIFICATION_CACHE_ENABLED", False
            ):
                _, _ = await verify_callee_vvp(
                    "header1", "jwt1", callee_context
                )
                chain_count = pp.mocks["chain"].call_count

                _, _ = await verify_callee_vvp(
                    "header1", "jwt1", callee_context
                )
                assert pp.mocks["chain"].call_count > chain_count

    @pytest.mark.asyncio
    async def test_cache_hit_evidence_in_dossier_claim(self, callee_context):
        """Cache hit adds 'cache_hit:dossier_verification' evidence."""
        with _CalleePatchedPipeline():
            # First call — miss
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Second call — hit
            _, resp2 = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Find the dossier claim in the response tree
            if resp2.claims:
                dossier_claim = resp2.claims[0].children[1].node
                evidence_str = " ".join(dossier_claim.evidence)
                assert "cache_hit:dossier_verification" in evidence_str

    @pytest.mark.asyncio
    async def test_revocation_skipped_on_cache_hit(self, callee_context):
        """Revocation check is skipped on cache hit (uses cached status)."""
        with _CalleePatchedPipeline() as pp:
            # First call
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            rev_calls_1 = pp.mocks["revocation"].call_count

            # Second call — cache hit
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Revocation check should NOT be called again
            assert pp.mocks["revocation"].call_count == rev_calls_1

    @pytest.mark.asyncio
    async def test_fetch_skipped_on_cache_hit(self, callee_context):
        """Dossier fetch is skipped on cache hit."""
        with _CalleePatchedPipeline() as pp:
            # First call
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )
            fetch_calls_1 = pp.mocks["fetch"].call_count

            # Second call — cache hit
            _, _ = await verify_callee_vvp(
                "header1", "jwt1", callee_context
            )

            # Fetch should NOT be called again
            assert pp.mocks["fetch"].call_count == fetch_calls_1
