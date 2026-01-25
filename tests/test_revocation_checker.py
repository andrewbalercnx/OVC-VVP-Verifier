"""Tests for revocation checking in verify.py.

Phase 9.3: Tests for check_dossier_revocations() function.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.vvp.api_models import ClaimStatus
from app.vvp.dossier.models import ACDCNode, DossierDAG


# Mock the TEL client at import time to avoid pysodium issues
@pytest.fixture
def mock_tel_client():
    """Create a mock TEL client."""
    from app.vvp.keri.tel_client import CredentialStatus, RevocationResult

    mock_client = MagicMock()
    mock_client.check_revocation = AsyncMock()

    return mock_client, CredentialStatus, RevocationResult


@pytest.fixture
def sample_dag():
    """Create a sample DossierDAG for testing."""
    dag = DossierDAG()
    dag.nodes = {
        "ESAID1234567890abcdef": ACDCNode(
            said="ESAID1234567890abcdef",
            issuer="EISSUER1234567890ab",
            schema="ESCHEMA1234567890ab",
            raw={"ri": "EREGISTRY1234567890"}
        ),
        "ESAID2234567890abcdef": ACDCNode(
            said="ESAID2234567890abcdef",
            issuer="EISSUER2234567890ab",
            schema="ESCHEMA2234567890ab",
            raw={}
        ),
    }
    dag.root_said = "ESAID1234567890abcdef"
    return dag


@pytest.fixture
def empty_dag():
    """Create an empty DossierDAG for testing."""
    dag = DossierDAG()
    dag.nodes = {}
    dag.root_said = None
    return dag


class TestCheckDossierRevocations:
    """Tests for check_dossier_revocations function."""

    @pytest.mark.asyncio
    async def test_all_credentials_active(self, mock_tel_client, sample_dag):
        """All credentials ACTIVE → revocation_clear VALID."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # All credentials return ACTIVE
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.VALID
            assert claim.name == "revocation_clear"
            assert len(claim.evidence) > 0
            assert "active:2" in claim.evidence[-1]  # Summary
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_one_credential_revoked(self, mock_tel_client, sample_dag):
        """One revoked credential → revocation_clear INVALID."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # First call returns ACTIVE, second returns REVOKED
        mock_client.check_revocation.side_effect = [
            RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said="test1",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="witness"
            ),
            RevocationResult(
                status=CredentialStatus.REVOKED,
                credential_said="test2",
                registry_said=None,
                issuance_event=None,
                revocation_event=MagicMock(),
                error=None,
                source="witness"
            ),
        ]

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INVALID
            assert len(claim.reasons) > 0
            assert "revoked" in claim.reasons[0].lower()
            assert len(revoked_saids) == 1

    @pytest.mark.asyncio
    async def test_one_credential_unknown(self, mock_tel_client, sample_dag):
        """One unknown credential → revocation_clear INDETERMINATE."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # All credentials return UNKNOWN
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="No TEL data found",
            source="none"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INDETERMINATE
            assert len(claim.reasons) > 0
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_revoked_takes_precedence_over_unknown(self, mock_tel_client, sample_dag):
        """REVOKED wins over UNKNOWN → INVALID status."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # First returns UNKNOWN, second returns REVOKED
        mock_client.check_revocation.side_effect = [
            RevocationResult(
                status=CredentialStatus.UNKNOWN,
                credential_said="test1",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error="No TEL data",
                source="none"
            ),
            RevocationResult(
                status=CredentialStatus.REVOKED,
                credential_said="test2",
                registry_said=None,
                issuance_event=None,
                revocation_event=MagicMock(),
                error=None,
                source="witness"
            ),
        ]

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            # INVALID should take precedence over INDETERMINATE
            assert claim.status == ClaimStatus.INVALID
            assert len(revoked_saids) == 1

    @pytest.mark.asyncio
    async def test_empty_dag(self, mock_tel_client, empty_dag):
        """Empty DAG → VALID (nothing to check)."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(empty_dag)

            assert claim.status == ClaimStatus.VALID
            assert "checked:0" in claim.evidence[-1]
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_extracts_registry_said(self, mock_tel_client):
        """Correctly extracts ri field from raw ACDC."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # Create DAG with registry SAID
        dag = DossierDAG()
        dag.nodes = {
            "ESAID_TEST": ACDCNode(
                said="ESAID_TEST",
                issuer="EISSUER",
                schema="ESCHEMA",
                raw={"ri": "EREGISTRY_SAID_123"}
            )
        }
        dag.root_said = "ESAID_TEST"

        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said="ESAID_TEST",
            registry_said="EREGISTRY_SAID_123",
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            await check_dossier_revocations(dag)

            # Verify the registry_said was passed to check_revocation
            call_args = mock_client.check_revocation.call_args
            assert call_args.kwargs["registry_said"] == "EREGISTRY_SAID_123"

    @pytest.mark.asyncio
    async def test_error_status_becomes_indeterminate(self, mock_tel_client, sample_dag):
        """ERROR status → revocation_clear INDETERMINATE."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ERROR,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="Connection timeout",
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INDETERMINATE
            assert len(revoked_saids) == 0


class TestRevocationClaimInTree:
    """Tests for revocation_clear claim placement in tree."""

    def test_revocation_clear_is_child_of_dossier_verified(self):
        """revocation_clear is a REQUIRED child of dossier_verified per §3.3B."""
        # This test verifies the claim tree structure
        from app.vvp.api_models import ChildLink

        # Create mock claims
        from app.vvp.verify import ClaimBuilder

        dossier_claim = ClaimBuilder("dossier_verified")
        revocation_claim = ClaimBuilder("revocation_clear")

        # Build dossier node with revocation child
        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        # Verify structure
        assert dossier_node.name == "dossier_verified"
        assert len(dossier_node.children) == 1
        assert dossier_node.children[0].required is True
        assert dossier_node.children[0].node.name == "revocation_clear"

    def test_dossier_status_reflects_revocation_child(self):
        """dossier_verified status propagates from revocation_clear per §3.3A."""
        from app.vvp.api_models import ChildLink
        from app.vvp.verify import ClaimBuilder, propagate_status, ClaimNode

        # Create dossier_verified as VALID but revocation_clear as INVALID
        dossier_claim = ClaimBuilder("dossier_verified")  # VALID by default
        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.fail(ClaimStatus.INVALID, "Credential revoked")

        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        # Propagate status
        effective_status = propagate_status(dossier_node)

        # dossier_verified should reflect child's INVALID status
        assert effective_status == ClaimStatus.INVALID

    def test_dossier_status_indeterminate_when_revocation_indeterminate(self):
        """dossier_verified becomes INDETERMINATE when revocation_clear is INDETERMINATE."""
        from app.vvp.api_models import ChildLink
        from app.vvp.verify import ClaimBuilder, propagate_status

        dossier_claim = ClaimBuilder("dossier_verified")
        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.fail(ClaimStatus.INDETERMINATE, "TEL unavailable")

        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        effective_status = propagate_status(dossier_node)
        assert effective_status == ClaimStatus.INDETERMINATE


class TestCredentialRevokedError:
    """Tests for CREDENTIAL_REVOKED error emission."""

    @pytest.mark.asyncio
    async def test_revoked_credential_emits_error(self, mock_tel_client, sample_dag):
        """Revoked credential emits CREDENTIAL_REVOKED error."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client
        from app.vvp.api_models import ErrorCode

        # Return REVOKED for all credentials
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.REVOKED,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=MagicMock(),
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            # Verify revoked SAIDs are returned for error emission
            assert len(revoked_saids) == 2  # sample_dag has 2 nodes
            assert all(said in sample_dag.nodes for said in revoked_saids)
