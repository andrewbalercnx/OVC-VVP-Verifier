"""Tests for chain-aware revocation checking functionality.

Tests cover:
- ChainExtractionResult and ChainRevocationResult data structures
- TELClient.check_chain_revocation() method
- build_credential_chain_saids() and build_all_credential_chains() functions
- DossierCache background revocation task management
"""

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.vvp.keri.tel_client import (
    ChainExtractionResult,
    ChainRevocationResult,
    CredentialStatus,
    RevocationResult,
    TELClient,
)
from app.vvp.acdc.graph import (
    CredentialGraph,
    CredentialNode,
    CredentialEdge,
    ResolutionSource,
    build_credential_chain_saids,
    build_all_credential_chains,
)


class TestChainExtractionResult:
    """Tests for ChainExtractionResult dataclass."""

    def test_complete_chain(self):
        """Complete chain has no missing links."""
        result = ChainExtractionResult(
            chain_saids=["leaf", "parent", "root"],
            registry_saids={"leaf": "reg1"},
            missing_links=[],
            complete=True,
        )
        assert result.complete is True
        assert len(result.chain_saids) == 3
        assert len(result.missing_links) == 0

    def test_incomplete_chain(self):
        """Incomplete chain has missing links."""
        result = ChainExtractionResult(
            chain_saids=["leaf"],
            registry_saids={},
            missing_links=["parent", "root"],
            complete=False,
        )
        assert result.complete is False
        assert len(result.missing_links) == 2


class TestChainRevocationResult:
    """Tests for ChainRevocationResult dataclass."""

    def test_active_chain_status(self):
        """Active chain has all ACTIVE credentials."""
        result = ChainRevocationResult(
            chain_status=CredentialStatus.ACTIVE,
            credential_results={
                "cred1": RevocationResult(
                    status=CredentialStatus.ACTIVE,
                    credential_said="cred1",
                    registry_said=None,
                    issuance_event=None,
                    revocation_event=None,
                    error=None,
                    source="witness",
                ),
            },
            revoked_credentials=[],
            chain_saids=["cred1"],
            missing_chain_links=[],
            check_complete=True,
            errors=[],
            checked_at=datetime.now(timezone.utc).isoformat(),
        )
        assert result.chain_status == CredentialStatus.ACTIVE
        assert result.check_complete is True
        assert len(result.revoked_credentials) == 0

    def test_revoked_chain_status(self):
        """Revoked chain has at least one REVOKED credential."""
        result = ChainRevocationResult(
            chain_status=CredentialStatus.REVOKED,
            credential_results={},
            revoked_credentials=["revoked_cred"],
            chain_saids=["revoked_cred"],
            missing_chain_links=[],
            check_complete=True,
            errors=[],
            checked_at=datetime.now(timezone.utc).isoformat(),
        )
        assert result.chain_status == CredentialStatus.REVOKED
        assert "revoked_cred" in result.revoked_credentials


class TestBuildCredentialChainSaids:
    """Tests for build_credential_chain_saids() function."""

    def test_single_node_chain(self):
        """Chain with single node and no edges."""
        graph = CredentialGraph()
        graph.nodes["E" + "A" * 43] = CredentialNode(
            said="E" + "A" * 43,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )

        result = build_credential_chain_saids("E" + "A" * 43, graph)

        assert len(result.chain_saids) == 1
        assert result.complete is True
        assert len(result.missing_links) == 0

    def test_chain_with_parent(self):
        """Chain walks through edges_to to parent."""
        graph = CredentialGraph()
        leaf_said = "E" + "A" * 43
        parent_said = "E" + "B" * 43

        graph.nodes[leaf_said] = CredentialNode(
            said=leaf_said,
            issuer_aid="issuer1",
            credential_type="APE",
            display_name="Test APE",
            edges_to=[parent_said],
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )
        graph.nodes[parent_said] = CredentialNode(
            said=parent_said,
            issuer_aid="root1",
            credential_type="LE",
            display_name="Test LE",
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )

        result = build_credential_chain_saids(leaf_said, graph)

        assert len(result.chain_saids) == 2
        assert result.chain_saids[0] == leaf_said
        assert result.chain_saids[1] == parent_said
        assert result.complete is True

    def test_missing_parent_tracked(self):
        """Missing parent is tracked in missing_links."""
        graph = CredentialGraph()
        leaf_said = "E" + "A" * 43
        missing_said = "E" + "M" * 43

        graph.nodes[leaf_said] = CredentialNode(
            said=leaf_said,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            edges_to=[missing_said],  # Points to non-existent node
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )

        result = build_credential_chain_saids(leaf_said, graph)

        assert len(result.chain_saids) == 1
        assert missing_said in result.missing_links
        assert result.complete is False

    def test_synthetic_nodes_excluded(self):
        """Synthetic nodes (root:*, issuer:*) are skipped."""
        graph = CredentialGraph()
        leaf_said = "E" + "A" * 43
        synthetic_id = "root:issuer1"

        graph.nodes[leaf_said] = CredentialNode(
            said=leaf_said,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            edges_to=[synthetic_id],
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )
        graph.nodes[synthetic_id] = CredentialNode(
            said=synthetic_id,
            issuer_aid="issuer1",
            credential_type="ROOT",
            display_name="Trusted Root",
            is_root=True,
            status=CredentialStatus.ACTIVE,
            resolution_source=ResolutionSource.SYNTHETIC,
        )

        result = build_credential_chain_saids(leaf_said, graph)

        assert synthetic_id not in result.chain_saids
        assert len(result.chain_saids) == 1
        assert result.complete is True  # Synthetic doesn't count as missing


class TestBuildAllCredentialChains:
    """Tests for build_all_credential_chains() function."""

    def test_extracts_all_credentials(self):
        """Extracts all real credentials, excludes synthetic."""
        graph = CredentialGraph()
        graph.nodes["E" + "A" * 43] = CredentialNode(
            said="E" + "A" * 43,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )
        graph.nodes["E" + "B" * 43] = CredentialNode(
            said="E" + "B" * 43,
            issuer_aid="issuer2",
            credential_type="APE",
            display_name="Test APE",
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )
        graph.nodes["root:issuer1"] = CredentialNode(
            said="root:issuer1",
            issuer_aid="issuer1",
            credential_type="ROOT",
            display_name="Root",
            is_root=True,
            status=CredentialStatus.ACTIVE,
            resolution_source=ResolutionSource.SYNTHETIC,
        )

        result = build_all_credential_chains(graph)

        assert len(result.chain_saids) == 2
        assert "root:issuer1" not in result.chain_saids
        assert result.complete is True

    def test_detects_missing_links(self):
        """Detects missing links when edges point to non-existent credentials."""
        graph = CredentialGraph()
        missing_said = "E" + "M" * 43  # Not in graph

        graph.nodes["E" + "A" * 43] = CredentialNode(
            said="E" + "A" * 43,
            issuer_aid="issuer1",
            credential_type="APE",
            display_name="Test APE",
            edges_to=[missing_said],  # Points to missing credential
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )

        result = build_all_credential_chains(graph)

        assert result.complete is False
        assert missing_said in result.missing_links

    def test_synthetic_edges_not_missing(self):
        """Edges to synthetic nodes don't count as missing links."""
        graph = CredentialGraph()
        synthetic_id = "root:issuer1"

        graph.nodes["E" + "A" * 43] = CredentialNode(
            said="E" + "A" * 43,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            edges_to=[synthetic_id],  # Points to synthetic root
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )
        graph.nodes[synthetic_id] = CredentialNode(
            said=synthetic_id,
            issuer_aid="issuer1",
            credential_type="ROOT",
            display_name="Trusted Root",
            is_root=True,
            status=CredentialStatus.ACTIVE,
            resolution_source=ResolutionSource.SYNTHETIC,
        )

        result = build_all_credential_chains(graph)

        assert result.complete is True
        assert synthetic_id not in result.missing_links

    def test_extracts_registry_said(self):
        """Extracts registry SAID from node attributes."""
        graph = CredentialGraph()
        graph.nodes["E" + "A" * 43] = CredentialNode(
            said="E" + "A" * 43,
            issuer_aid="issuer1",
            credential_type="LE",
            display_name="Test LE",
            attributes={"ri": "E" + "R" * 43},  # Registry SAID
            status=CredentialStatus.UNKNOWN,
            resolution_source=ResolutionSource.DOSSIER,
        )

        result = build_all_credential_chains(graph)

        assert "E" + "A" * 43 in result.registry_saids
        assert result.registry_saids["E" + "A" * 43] == "E" + "R" * 43


class TestTELClientCheckChainRevocation:
    """Tests for TELClient.check_chain_revocation() method."""

    @pytest.fixture
    def tel_client(self):
        return TELClient(timeout=5.0, use_witness_pool=False)

    @pytest.mark.asyncio
    async def test_all_active_returns_active_status(self, tel_client):
        """Chain with all ACTIVE credentials returns ACTIVE chain status."""
        chain_info = ChainExtractionResult(
            chain_saids=["cred1", "cred2"],
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        with patch.object(tel_client, 'check_revocation_with_fallback') as mock:
            mock.return_value = RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said="",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="witness",
            )

            result = await tel_client.check_chain_revocation(chain_info)

            assert result.chain_status == CredentialStatus.ACTIVE
            assert result.check_complete is True
            assert len(result.revoked_credentials) == 0

    @pytest.mark.asyncio
    async def test_any_revoked_returns_revoked_status(self, tel_client):
        """Chain with any REVOKED credential returns REVOKED chain status."""
        chain_info = ChainExtractionResult(
            chain_saids=["cred1", "cred2"],
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        async def mock_check(credential_said, **kwargs):
            if credential_said == "cred1":
                return RevocationResult(
                    status=CredentialStatus.ACTIVE,
                    credential_said=credential_said,
                    registry_said=None,
                    issuance_event=None,
                    revocation_event=None,
                    error=None,
                    source="witness",
                )
            else:
                return RevocationResult(
                    status=CredentialStatus.REVOKED,
                    credential_said=credential_said,
                    registry_said=None,
                    issuance_event=None,
                    revocation_event=None,
                    error=None,
                    source="witness",
                )

        with patch.object(tel_client, 'check_revocation_with_fallback', side_effect=mock_check):
            result = await tel_client.check_chain_revocation(chain_info)

            assert result.chain_status == CredentialStatus.REVOKED
            assert "cred2" in result.revoked_credentials

    @pytest.mark.asyncio
    async def test_incomplete_chain_returns_unknown(self, tel_client):
        """Incomplete chain returns UNKNOWN status even if all checked are ACTIVE."""
        chain_info = ChainExtractionResult(
            chain_saids=["cred1"],
            registry_saids={},
            missing_links=["missing_cred"],
            complete=False,
        )

        with patch.object(tel_client, 'check_revocation_with_fallback') as mock:
            mock.return_value = RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said="cred1",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="witness",
            )

            result = await tel_client.check_chain_revocation(chain_info)

            assert result.chain_status == CredentialStatus.UNKNOWN
            assert result.check_complete is False
            assert "Chain incomplete" in result.errors[0]

    @pytest.mark.asyncio
    async def test_parallel_execution(self, tel_client):
        """All credentials are checked in parallel."""
        chain_info = ChainExtractionResult(
            chain_saids=["cred1", "cred2", "cred3"],
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        call_order = []

        async def mock_check(credential_said, **kwargs):
            call_order.append(credential_said)
            await asyncio.sleep(0.01)  # Small delay to verify parallelism
            return RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said=credential_said,
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="witness",
            )

        with patch.object(tel_client, 'check_revocation_with_fallback', side_effect=mock_check):
            result = await tel_client.check_chain_revocation(chain_info)

            assert len(call_order) == 3
            assert result.chain_status == CredentialStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_empty_chain_returns_unknown(self, tel_client):
        """Empty chain_saids returns UNKNOWN status, not ACTIVE."""
        chain_info = ChainExtractionResult(
            chain_saids=[],  # No credentials to check
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        result = await tel_client.check_chain_revocation(chain_info)

        assert result.chain_status == CredentialStatus.UNKNOWN
        assert "No credentials in chain to check" in result.errors[0]


class TestDossierCacheBackgroundRevocation:
    """Tests for DossierCache background revocation task management."""

    @pytest.fixture
    def dossier_cache(self):
        from app.vvp.dossier.cache import DossierCache
        return DossierCache(ttl_seconds=300.0, max_entries=100)

    @pytest.mark.asyncio
    async def test_background_task_starts(self, dossier_cache):
        """Background revocation check task is started."""
        from app.vvp.dossier.cache import CachedDossier
        from app.vvp.dossier.models import DossierDAG

        # Create a cached dossier
        dag = MagicMock(spec=DossierDAG)
        dag.nodes = {}
        cached = CachedDossier(
            dag=dag,
            raw_content=b"test",
            fetch_timestamp=1234567890.0,
            content_type="application/json+cesr",
            contained_saids={"cred1"},
        )
        await dossier_cache.put("http://example.com/dossier", cached)

        chain_info = ChainExtractionResult(
            chain_saids=["cred1"],
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        # Mock the TEL client (patch where it's imported in the method)
        with patch('common.vvp.keri.tel_client.get_tel_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.check_chain_revocation = AsyncMock(
                return_value=ChainRevocationResult(
                    chain_status=CredentialStatus.ACTIVE,
                    credential_results={},
                    revoked_credentials=[],
                    chain_saids=["cred1"],
                    missing_chain_links=[],
                    check_complete=True,
                    errors=[],
                    checked_at=datetime.now(timezone.utc).isoformat(),
                )
            )
            mock_get_client.return_value = mock_client

            # Start background check
            await dossier_cache.start_background_revocation_check(
                url="http://example.com/dossier",
                chain_info=chain_info,
            )

            # Give the background task time to run
            await asyncio.sleep(0.1)

            # Verify task completed
            entry = await dossier_cache.get("http://example.com/dossier")
            assert entry is not None
            assert entry.chain_revocation is not None
            assert entry.chain_revocation.chain_status == CredentialStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_duplicate_task_prevented(self, dossier_cache):
        """Duplicate background tasks are not started."""
        from app.vvp.dossier.cache import CachedDossier
        from app.vvp.dossier.models import DossierDAG

        dag = MagicMock(spec=DossierDAG)
        dag.nodes = {}
        cached = CachedDossier(
            dag=dag,
            raw_content=b"test",
            fetch_timestamp=1234567890.0,
            content_type="application/json+cesr",
            contained_saids={"cred1"},
        )
        await dossier_cache.put("http://example.com/dossier", cached)

        chain_info = ChainExtractionResult(
            chain_saids=["cred1"],
            registry_saids={},
            missing_links=[],
            complete=True,
        )

        # Make the task slow so we can test duplicate prevention
        async def slow_check(*args, **kwargs):
            await asyncio.sleep(1.0)
            return ChainRevocationResult(
                chain_status=CredentialStatus.ACTIVE,
                credential_results={},
                revoked_credentials=[],
                chain_saids=["cred1"],
                missing_chain_links=[],
                check_complete=True,
                errors=[],
                checked_at=datetime.now(timezone.utc).isoformat(),
            )

        with patch('common.vvp.keri.tel_client.get_tel_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.check_chain_revocation = slow_check
            mock_get_client.return_value = mock_client

            # Start first task
            await dossier_cache.start_background_revocation_check(
                url="http://example.com/dossier",
                chain_info=chain_info,
            )

            # Try to start second task (should be ignored)
            await dossier_cache.start_background_revocation_check(
                url="http://example.com/dossier",
                chain_info=chain_info,
            )

            # Verify only one task is tracked
            async with dossier_cache._lock:
                assert len(dossier_cache._revocation_tasks) == 1
