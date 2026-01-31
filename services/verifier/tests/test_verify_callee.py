"""Unit tests for Phase 12 callee verification (Sprint 19)."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.vvp.api_models import (
    ClaimStatus,
    ClaimNode,
    ChildLink,
    ErrorCode,
    VerifyCalleeRequest,
    CallContext,
    SipContext,
)
from app.vvp.verify_callee import (
    ClaimBuilder,
    validate_dialog_match,
    validate_issuer_match,
    _extract_aid_from_kid,
    validate_callee_tn_rights,
    verify_callee_vvp,
)
from app.vvp.goal import (
    is_goal_subset,
    validate_goal_overlap,
    verify_goal_overlap,
)


# =============================================================================
# Dialog Matching Tests (§5B Step 1)
# =============================================================================


class TestDialogMatching:
    """Test dialog matching (call-id/cseq validation)."""

    def test_valid_dialog_match(self):
        """Both call-id and cseq match."""
        passport = MagicMock()
        passport.payload.call_id = "abc123@host.example.com"
        passport.payload.cseq = 101

        result = validate_dialog_match(
            passport,
            context_call_id="abc123@host.example.com",
            sip_cseq=101,
        )

        assert result.status == ClaimStatus.VALID
        assert any("call_id_matched" in e for e in result.evidence)
        assert any("cseq_matched" in e for e in result.evidence)

    def test_missing_passport_call_id(self):
        """PASSporT missing call-id claim."""
        passport = MagicMock()
        passport.payload.call_id = None
        passport.payload.cseq = 101

        result = validate_dialog_match(
            passport,
            context_call_id="abc123@host.example.com",
            sip_cseq=101,
        )

        assert result.status == ClaimStatus.INVALID
        assert "missing call-id" in result.reasons[0]

    def test_missing_passport_cseq(self):
        """PASSporT missing cseq claim."""
        passport = MagicMock()
        passport.payload.call_id = "abc123@host.example.com"
        passport.payload.cseq = None

        result = validate_dialog_match(
            passport,
            context_call_id="abc123@host.example.com",
            sip_cseq=101,
        )

        assert result.status == ClaimStatus.INVALID
        assert "missing cseq" in result.reasons[0]

    def test_call_id_mismatch(self):
        """call-id doesn't match."""
        passport = MagicMock()
        passport.payload.call_id = "wrong-call-id"
        passport.payload.cseq = 101

        result = validate_dialog_match(
            passport,
            context_call_id="abc123@host.example.com",
            sip_cseq=101,
        )

        assert result.status == ClaimStatus.INVALID
        assert "call-id mismatch" in result.reasons[0]

    def test_cseq_mismatch(self):
        """cseq doesn't match."""
        passport = MagicMock()
        passport.payload.call_id = "abc123@host.example.com"
        passport.payload.cseq = 999

        result = validate_dialog_match(
            passport,
            context_call_id="abc123@host.example.com",
            sip_cseq=101,
        )

        assert result.status == ClaimStatus.INVALID
        assert "cseq mismatch" in result.reasons[0]


# =============================================================================
# Issuer Verification Tests (§5B Step 9)
# =============================================================================


class TestIssuerVerification:
    """Test issuer verification (dossier issuer == kid)."""

    def test_valid_issuer_match(self):
        """Dossier issuer matches kid AID."""
        kid_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"

        result = validate_issuer_match(
            passport_kid=kid_aid,
            dossier_issuer_aid=kid_aid,
        )

        assert result.status == ClaimStatus.VALID
        assert any("issuer_matched:verified" in e for e in result.evidence)

    def test_issuer_match_with_oobi_kid(self):
        """kid is OOBI URL, extracts AID correctly."""
        kid_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        oobi_kid = f"http://witness.example.com/oobi/{kid_aid}/witness/EXyz"

        result = validate_issuer_match(
            passport_kid=oobi_kid,
            dossier_issuer_aid=kid_aid,
        )

        assert result.status == ClaimStatus.VALID

    def test_issuer_mismatch(self):
        """Dossier issuer doesn't match kid."""
        result = validate_issuer_match(
            passport_kid="EKid12345678901234567890123456789012345678901",
            dossier_issuer_aid="EDossier12345678901234567890123456789012345",
        )

        assert result.status == ClaimStatus.INVALID
        assert "Issuer mismatch" in result.reasons[0]


class TestExtractAidFromKid:
    """Test AID extraction from kid (OOBI URL or bare AID)."""

    def test_bare_aid(self):
        """Extract AID from bare AID string."""
        aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        result = _extract_aid_from_kid(aid)
        assert result == aid

    def test_oobi_url_with_aid(self):
        """Extract AID from OOBI URL."""
        aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        oobi = f"http://witness.example.com/oobi/{aid}/witness/EWitness"
        result = _extract_aid_from_kid(oobi)
        assert result == aid

    def test_oobi_url_https(self):
        """Extract AID from HTTPS OOBI URL."""
        aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        oobi = f"https://witness.example.com/oobi/{aid}"
        result = _extract_aid_from_kid(oobi)
        assert result == aid


# =============================================================================
# Goal Overlap Tests (§5B Step 14)
# =============================================================================


class TestGoalSubset:
    """Test is_goal_subset function."""

    def test_equal_goals_are_subsets(self):
        """Equal goals are considered subsets of each other."""
        assert is_goal_subset("billing", "billing") is True
        assert is_goal_subset("billing.payment", "billing.payment") is True

    def test_more_specific_is_subset(self):
        """More specific goal is subset of less specific."""
        assert is_goal_subset("billing.payment", "billing") is True
        assert is_goal_subset("billing.payment.confirm", "billing.payment") is True
        assert is_goal_subset("billing.payment.confirm", "billing") is True

    def test_less_specific_not_subset_of_more_specific(self):
        """Less specific goal is NOT a subset of more specific."""
        assert is_goal_subset("billing", "billing.payment") is False
        assert is_goal_subset("billing.payment", "billing.payment.confirm") is False

    def test_unrelated_goals_not_subsets(self):
        """Unrelated goals are not subsets."""
        assert is_goal_subset("billing", "support") is False
        assert is_goal_subset("billing.payment", "support.callback") is False

    def test_partial_match_not_subset(self):
        """Partial string matches without . separator are not subsets."""
        assert is_goal_subset("billings", "billing") is False  # Not "billing." prefix


class TestGoalOverlap:
    """Test validate_goal_overlap function."""

    def test_both_goals_none(self):
        """When both goals are None, overlap is not required."""
        status, results = validate_goal_overlap(None, None)
        # Both None defaults to callee_goal None path first
        assert status == ClaimStatus.VALID
        assert "callee_goal_absent" in results[0]

    def test_callee_goal_none(self):
        """When callee goal is None, overlap is not required."""
        status, results = validate_goal_overlap(None, "billing")
        assert status == ClaimStatus.VALID
        assert "callee_goal_absent" in results[0]

    def test_caller_goal_none(self):
        """When caller goal is None, overlap is not required."""
        status, results = validate_goal_overlap("billing", None)
        assert status == ClaimStatus.VALID
        assert "caller_goal_absent" in results[0]

    def test_callee_subset_of_caller(self):
        """Callee goal is subset of caller goal - VALID."""
        status, results = validate_goal_overlap("billing.payment", "billing")
        assert status == ClaimStatus.VALID
        assert "subset_of_caller" in results[0]

    def test_caller_subset_of_callee(self):
        """Caller goal is subset of callee goal - VALID."""
        status, results = validate_goal_overlap("billing", "billing.payment")
        assert status == ClaimStatus.VALID
        assert "subset_of_callee" in results[0]

    def test_equal_goals(self):
        """Equal goals overlap - VALID."""
        status, results = validate_goal_overlap("billing", "billing")
        assert status == ClaimStatus.VALID

    def test_incompatible_goals(self):
        """Incompatible goals don't overlap - INVALID."""
        status, results = validate_goal_overlap("billing", "support")
        assert status == ClaimStatus.INVALID
        assert "do not overlap" in results[0]


class TestVerifyGoalOverlap:
    """Test verify_goal_overlap function (ClaimBuilder wrapper)."""

    def test_returns_none_when_callee_goal_absent(self):
        """Returns None when callee has no goal (claim omitted)."""
        callee_passport = MagicMock()
        callee_passport.payload.goal = None

        caller_passport = MagicMock()
        caller_passport.payload.goal = "billing"

        result = verify_goal_overlap(callee_passport, caller_passport)
        assert result is None

    def test_returns_none_when_caller_goal_absent(self):
        """Returns None when caller has no goal (claim omitted)."""
        callee_passport = MagicMock()
        callee_passport.payload.goal = "billing"

        caller_passport = MagicMock()
        caller_passport.payload.goal = None

        result = verify_goal_overlap(callee_passport, caller_passport)
        assert result is None

    def test_returns_claim_when_both_goals_present(self):
        """Returns ClaimBuilder when both goals present."""
        callee_passport = MagicMock()
        callee_passport.payload.goal = "billing.payment"

        caller_passport = MagicMock()
        caller_passport.payload.goal = "billing"

        result = verify_goal_overlap(callee_passport, caller_passport)
        assert result is not None
        assert result.name == "goal_overlap_verified"
        assert result.status == ClaimStatus.VALID

    def test_invalid_when_goals_incompatible(self):
        """Returns INVALID claim when goals don't overlap."""
        callee_passport = MagicMock()
        callee_passport.payload.goal = "billing"

        caller_passport = MagicMock()
        caller_passport.payload.goal = "support"

        result = verify_goal_overlap(callee_passport, caller_passport)
        assert result is not None
        assert result.status == ClaimStatus.INVALID


# =============================================================================
# ClaimBuilder Tests
# =============================================================================


class TestClaimBuilder:
    """Test ClaimBuilder helper class."""

    def test_starts_valid(self):
        builder = ClaimBuilder("test")
        assert builder.status == ClaimStatus.VALID
        assert builder.reasons == []
        assert builder.evidence == []

    def test_fail_to_invalid(self):
        builder = ClaimBuilder("test")
        builder.fail(ClaimStatus.INVALID, "reason")
        assert builder.status == ClaimStatus.INVALID
        assert "reason" in builder.reasons

    def test_build_creates_claim_node(self):
        builder = ClaimBuilder("test_claim")
        builder.fail(ClaimStatus.INDETERMINATE, "reason")
        builder.add_evidence("ev1")
        node = builder.build()
        assert node.name == "test_claim"
        assert node.status == ClaimStatus.INDETERMINATE


# =============================================================================
# Integration Tests (Mocked)
# =============================================================================


class TestVerifyCalleeVVPIntegration:
    """Integration tests for verify_callee_vvp orchestration."""

    @pytest.fixture
    def valid_callee_context(self):
        return CallContext(
            call_id="abc123@host.example.com",
            received_at="2024-01-01T00:00:00Z",
            sip=SipContext(
                from_uri="sip:+15551234567@example.com",
                to_uri="sip:+15559876543@example.com",
                invite_time="2024-01-01T00:00:00Z",
                cseq=101,
            )
        )

    @pytest.mark.asyncio
    async def test_missing_vvp_identity_returns_invalid(self, valid_callee_context):
        req_id, resp = await verify_callee_vvp(
            vvp_identity_raw="",  # Invalid/empty
            passport_jwt="dummy",
            context=valid_callee_context,
        )

        assert resp.overall_status == ClaimStatus.INVALID
        # Should have error about VVP-Identity

    @pytest.mark.asyncio
    async def test_dialog_mismatch_returns_invalid(self, valid_callee_context):
        """Dialog matching failure returns INVALID with DIALOG_MISMATCH error."""
        with (
            patch("app.vvp.verify_callee.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify_callee.parse_passport") as mock_passport,
            patch("app.vvp.verify_callee.validate_passport_binding") as mock_binding,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid="http://witness.example.com/oobi/EAbc/witness/EXyz"),
                payload=MagicMock(
                    call_id="wrong-call-id",  # Mismatch
                    cseq=101,
                    card=None,
                    goal=None,
                )
            )
            mock_binding.return_value = None

            req_id, resp = await verify_callee_vvp(
                vvp_identity_raw="valid-identity",
                passport_jwt="dummy",
                context=valid_callee_context,
            )

            assert resp.overall_status == ClaimStatus.INVALID
            assert any(e.code == ErrorCode.DIALOG_MISMATCH for e in resp.errors)

    @pytest.mark.asyncio
    async def test_claim_tree_structure(self, valid_callee_context):
        """Verify the callee claim tree structure per approved plan."""
        import time

        with (
            patch("app.vvp.verify_callee.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify_callee.parse_passport") as mock_passport,
            patch("app.vvp.verify_callee.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify_callee.verify_passport_signature_tier2") as mock_sig,
            patch("app.vvp.verify_callee.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify_callee.parse_dossier") as mock_parse,
            patch("app.vvp.verify_callee.build_dag") as mock_build,
            patch("app.vvp.verify_callee.validate_dag") as mock_validate,
        ):
            now = int(time.time())
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"),
                payload=MagicMock(
                    call_id="abc123@host.example.com",
                    cseq=101,
                    orig={"tn": "+15551234567"},
                    dest={"tn": ["+15559876543"]},
                    iat=now,  # Valid issued-at time
                    exp=now + 300,  # Valid expiry (5 minutes)
                    card=None,  # No card = no brand claim
                    goal=None,  # No goal = no goal overlap claim
                )
            )
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_dag.nodes = {}
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            req_id, resp = await verify_callee_vvp(
                vvp_identity_raw="valid-identity",
                passport_jwt="dummy",
                context=valid_callee_context,
            )

            # Verify tree structure
            assert len(resp.claims) == 1
            root = resp.claims[0]
            assert root.name == "callee_verified"

            # Find passport_verified child
            passport_child = None
            for child in root.children:
                if child.node.name == "passport_verified":
                    passport_child = child
                    break

            assert passport_child is not None

            # passport_verified should have dialog_matched, timing_valid, signature_valid as REQUIRED children
            passport_child_names = {gc.node.name for gc in passport_child.node.children}
            assert "dialog_matched" in passport_child_names
            assert "timing_valid" in passport_child_names
            assert "signature_valid" in passport_child_names

            # All passport children should be REQUIRED
            for grandchild in passport_child.node.children:
                assert grandchild.required is True

            # Find dossier_verified child
            dossier_child = None
            for child in root.children:
                if child.node.name == "dossier_verified":
                    dossier_child = child
                    break

            assert dossier_child is not None

            # dossier_verified should have structure_valid, acdc_signatures_valid, chain, revocation, issuer
            dossier_child_names = {gc.node.name for gc in dossier_child.node.children}
            assert "structure_valid" in dossier_child_names
            assert "acdc_signatures_valid" in dossier_child_names
            assert "chain_verified" in dossier_child_names
            assert "revocation_clear" in dossier_child_names
            assert "issuer_matched" in dossier_child_names

            # All dossier children should be REQUIRED
            for grandchild in dossier_child.node.children:
                assert grandchild.required is True


# =============================================================================
# Endpoint Validation Tests
# =============================================================================


class TestEndpointValidation:
    """Test /verify-callee endpoint validation."""

    @pytest.fixture
    def valid_request(self):
        return VerifyCalleeRequest(
            passport_jwt="dummy.jwt.token",
            context=CallContext(
                call_id="abc123@host.example.com",
                received_at="2024-01-01T00:00:00Z",
                sip=SipContext(
                    from_uri="sip:+15551234567@example.com",
                    to_uri="sip:+15559876543@example.com",
                    invite_time="2024-01-01T00:00:00Z",
                    cseq=101,
                )
            ),
            caller_passport_jwt=None,
        )

    def test_request_model_accepts_valid_input(self, valid_request):
        """Valid request passes model validation."""
        assert valid_request.passport_jwt == "dummy.jwt.token"
        assert valid_request.context.call_id == "abc123@host.example.com"
        assert valid_request.context.sip.cseq == 101

    def test_request_model_caller_passport_optional(self):
        """caller_passport_jwt is optional."""
        req = VerifyCalleeRequest(
            passport_jwt="dummy.jwt.token",
            context=CallContext(
                call_id="abc123",
                received_at="2024-01-01T00:00:00Z",
                sip=SipContext(
                    from_uri="sip:+15551234567@example.com",
                    to_uri="sip:+15559876543@example.com",
                    invite_time="2024-01-01T00:00:00Z",
                    cseq=101,
                )
            ),
        )
        assert req.caller_passport_jwt is None
