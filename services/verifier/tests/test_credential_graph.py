"""Tests for credential graph builder."""

import pytest

from app.vvp.acdc import (
    ACDC,
    CredentialGraph,
    CredentialNode,
    CredentialStatus,
    ResolutionSource,
    build_credential_graph,
    credential_graph_to_dict,
)


class TestBuildCredentialGraph:
    """Tests for build_credential_graph function."""

    def test_single_credential_from_root(self):
        """Test graph with single credential from trusted root."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        # Should have 2 nodes: credential + synthetic root
        assert len(graph.nodes) == 2
        assert acdc.said in graph.nodes
        assert graph.root_aid == root_aid
        assert graph.trust_path_valid is True

        # Check credential node
        node = graph.nodes[acdc.said]
        assert node.credential_type == "LE"
        assert node.in_dossier is True
        assert "LEI" in node.attributes

    def test_chain_with_edges(self):
        """Test graph with credential chain via edges."""
        root_aid = "D" + "R" * 43
        le_said = "E" + "L" * 43
        ape_said = "E" + "A" * 43
        trusted_roots = {root_aid}

        # LE credential from root
        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        # APE credential with vetting edge to LE
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": le_said}},
            raw={}
        )

        dossier = {le_said: le_cred, ape_said: ape_cred}
        graph = build_credential_graph(dossier, trusted_roots)

        # Should have 3 nodes: LE, APE, synthetic root
        assert len(graph.nodes) == 3

        # Check APE node has edge to LE
        ape_node = graph.nodes[ape_said]
        assert le_said in ape_node.edges_to
        assert ape_node.credential_type == "APE"

        # Check edges
        edge_types = {(e.from_said, e.edge_type) for e in graph.edges}
        assert (ape_said, "vetting") in edge_types
        assert (le_said, "issued_by") in edge_types

    def test_layers_computed_correctly(self):
        """Test that layers are computed from root to leaves."""
        root_aid = "D" + "R" * 43
        le_said = "E" + "L" * 43
        ape_said = "E" + "A" * 43
        trusted_roots = {root_aid}

        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "1234"},
            raw={}
        )

        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": le_said}},
            raw={}
        )

        dossier = {le_said: le_cred, ape_said: ape_cred}
        graph = build_credential_graph(dossier, trusted_roots)

        # Layer 0 should be root
        assert len(graph.layers) >= 2
        assert any("root:" in said for said in graph.layers[0])

        # LE should come after root
        # APE should come after LE

    def test_no_trusted_root(self):
        """Test graph when no credential chains to root."""
        trusted_roots = {"D" + "X" * 43}  # Different from issuer

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,  # Not in trusted_roots
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        assert graph.root_aid is None
        assert graph.trust_path_valid is False

    def test_revocation_status_applied(self):
        """Test that revocation status is applied to nodes."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        revocation = {acdc.said: CredentialStatus.REVOKED}

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots, revocation)

        node = graph.nodes[acdc.said]
        assert node.status == CredentialStatus.REVOKED

    def test_empty_dossier(self):
        """Test empty dossier produces empty graph."""
        graph = build_credential_graph({}, {"D" + "R" * 43})

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert graph.trust_path_valid is False


class TestCredentialNode:
    """Tests for CredentialNode display name generation."""

    def test_le_display_name_with_lei(self):
        """Test LE credential display name."""
        root_aid = "D" + "R" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, {root_aid})

        node = graph.nodes[acdc.said]
        assert "Legal Entity" in node.display_name
        assert "984500DEE7537A07Y615" in node.display_name

    def test_tnalloc_display_name(self):
        """Test TNAlloc credential display name."""
        root_aid = "D" + "R" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"tn": ["+1555*"]},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, {root_aid})

        node = graph.nodes[acdc.said]
        assert "TN Allocation" in node.display_name
        assert "+1555*" in node.display_name


class TestCredentialGraphToDict:
    """Tests for JSON serialization."""

    def test_serialization_format(self):
        """Test that graph serializes to expected format."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "1234"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)
        result = credential_graph_to_dict(graph)

        # Check structure
        assert "nodes" in result
        assert "edges" in result
        assert "rootAid" in result
        assert "trustPathValid" in result
        assert "layers" in result

        # Check node structure
        cred_node = next(n for n in result["nodes"] if n["id"] == acdc.said)
        assert cred_node["issuer"] == root_aid
        assert cred_node["type"] == "LE"
        assert cred_node["inDossier"] is True
        assert cred_node["schemaSaid"] == "E" + "S" * 43

    def test_root_node_in_serialization(self):
        """Test that synthetic root node is included."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)
        result = credential_graph_to_dict(graph)

        # Find root node
        root_nodes = [n for n in result["nodes"] if n["isRoot"]]
        assert len(root_nodes) == 1
        assert root_nodes[0]["type"] == "ROOT"


class TestKnownRootDisplayNames:
    """Tests for known root display names."""

    def test_gleif_root_name(self):
        """Test GLEIF External root gets proper display name."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        trusted_roots = {gleif_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=gleif_aid,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        root_node = next(n for n in graph.nodes.values() if n.is_root)
        assert root_node.display_name == "GLEIF External"
