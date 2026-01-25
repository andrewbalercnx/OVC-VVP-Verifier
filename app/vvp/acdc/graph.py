"""Credential graph builder for ACDC chain visualization.

Builds a directed graph of credentials from dossier to trusted root,
suitable for UI visualization.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .models import ACDC


class CredentialStatus(str, Enum):
    """Credential revocation status."""
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class ResolutionSource(str, Enum):
    """Where the credential was obtained from."""
    DOSSIER = "dossier"
    OOBI = "oobi"
    REGISTRY = "registry"
    SYNTHETIC = "synthetic"  # For trusted root placeholder


@dataclass
class CredentialNode:
    """Node in the credential graph for visualization."""

    # Identity
    said: str
    issuer_aid: str

    # Type and display
    credential_type: str  # LE, APE, DE, TNAlloc, Unknown
    display_name: str

    # Key attributes for display
    attributes: Dict[str, Any] = field(default_factory=dict)

    # Status
    status: CredentialStatus = CredentialStatus.UNKNOWN

    # Graph relationships
    edges_to: List[str] = field(default_factory=list)  # SAIDs this references (parents)

    # Resolution info
    in_dossier: bool = False
    resolution_source: ResolutionSource = ResolutionSource.DOSSIER
    schema_said: str = ""

    # For trusted root nodes (synthetic)
    is_root: bool = False


@dataclass
class CredentialEdge:
    """Edge in the credential graph."""
    from_said: str
    to_said: str
    edge_type: str  # "vetting", "delegation", "jl", "issued_by"


@dataclass
class CredentialGraph:
    """Complete credential chain as a directed graph."""

    nodes: Dict[str, CredentialNode] = field(default_factory=dict)
    edges: List[CredentialEdge] = field(default_factory=list)

    # Root info
    root_aid: Optional[str] = None
    trust_path_valid: bool = False

    # Layers for hierarchical visualization (root first)
    layers: List[List[str]] = field(default_factory=list)

    # Errors during graph building
    errors: List[str] = field(default_factory=list)


def build_credential_graph(
    dossier_acdcs: Dict[str, ACDC],
    trusted_roots: Set[str],
    revocation_status: Optional[Dict[str, CredentialStatus]] = None,
) -> CredentialGraph:
    """Build a credential graph from dossier ACDCs.

    Args:
        dossier_acdcs: ACDCs from the dossier (SAID -> ACDC).
        trusted_roots: Set of trusted root AIDs.
        revocation_status: Optional revocation status for each SAID.

    Returns:
        CredentialGraph suitable for visualization.
    """
    graph = CredentialGraph()
    revocation_status = revocation_status or {}

    # Build nodes from dossier ACDCs
    for said, acdc in dossier_acdcs.items():
        node = _build_node_from_acdc(acdc, revocation_status.get(said))
        node.in_dossier = True
        graph.nodes[said] = node

        # Build edges from this node's edges field
        if acdc.edges:
            for edge_name, edge_ref in acdc.edges.items():
                if edge_name in ('d', 'n'):
                    continue

                target_said = None
                if isinstance(edge_ref, str):
                    target_said = edge_ref
                elif isinstance(edge_ref, dict):
                    target_said = edge_ref.get('n') or edge_ref.get('d')

                if target_said:
                    node.edges_to.append(target_said)
                    graph.edges.append(CredentialEdge(
                        from_said=said,
                        to_said=target_said,
                        edge_type=edge_name
                    ))

    # Add synthetic nodes for issuers that are trusted roots
    _add_issuer_nodes(graph, dossier_acdcs, trusted_roots)

    # Compute layers for hierarchical display
    _compute_layers(graph, trusted_roots)

    # Check if we have a valid path to root
    graph.trust_path_valid = graph.root_aid is not None

    return graph


def _build_node_from_acdc(
    acdc: ACDC,
    status: Optional[CredentialStatus] = None
) -> CredentialNode:
    """Build a CredentialNode from an ACDC."""

    # Extract display attributes
    display_attrs = {}
    if acdc.attributes:
        # Common display fields
        for key in ['LEI', 'lids', 'tn', 'phone', 'name', 'loa', 'dt']:
            if key in acdc.attributes:
                value = acdc.attributes[key]
                # Handle lids array (LEI list)
                if key == 'lids' and isinstance(value, list) and value:
                    display_attrs['LEI'] = value[0]
                else:
                    display_attrs[key] = value

    # Generate display name
    cred_type = acdc.credential_type
    display_name = _generate_display_name(cred_type, display_attrs)

    return CredentialNode(
        said=acdc.said,
        issuer_aid=acdc.issuer_aid,
        credential_type=cred_type,
        display_name=display_name,
        attributes=display_attrs,
        status=status or CredentialStatus.UNKNOWN,
        schema_said=acdc.schema_said or "",
        resolution_source=ResolutionSource.DOSSIER,
    )


def _generate_display_name(cred_type: str, attrs: Dict[str, Any]) -> str:
    """Generate a human-readable display name for a credential."""

    if cred_type == "LE":
        lei = attrs.get('LEI', '')
        if lei:
            return f"Legal Entity: {lei[:20]}..."
        return "Legal Entity Credential"

    elif cred_type == "APE":
        return "Auth Phone Entity"

    elif cred_type == "DE":
        return "Delegate Entity"

    elif cred_type == "TNAlloc":
        tn = attrs.get('tn') or attrs.get('phone')
        if tn:
            if isinstance(tn, list):
                tn = tn[0] if tn else ""
            return f"TN Allocation: {tn}"
        return "TN Allocation"

    return f"Credential ({cred_type})"


def _add_issuer_nodes(
    graph: CredentialGraph,
    dossier_acdcs: Dict[str, ACDC],
    trusted_roots: Set[str]
) -> None:
    """Add synthetic nodes for issuers and trusted roots."""

    # Find all issuer AIDs
    issuer_aids = {acdc.issuer_aid for acdc in dossier_acdcs.values()}

    # Add edges from credentials to their issuers
    for said, acdc in dossier_acdcs.items():
        issuer_aid = acdc.issuer_aid

        # Check if issuer is a trusted root
        if issuer_aid in trusted_roots:
            # Add synthetic root node if not exists
            root_node_id = f"root:{issuer_aid}"
            if root_node_id not in graph.nodes:
                graph.nodes[root_node_id] = CredentialNode(
                    said=root_node_id,
                    issuer_aid=issuer_aid,
                    credential_type="ROOT",
                    display_name=_get_root_display_name(issuer_aid),
                    is_root=True,
                    status=CredentialStatus.ACTIVE,
                    resolution_source=ResolutionSource.SYNTHETIC,
                )
                graph.root_aid = issuer_aid

            # Add issued_by edge
            graph.edges.append(CredentialEdge(
                from_said=said,
                to_said=root_node_id,
                edge_type="issued_by"
            ))
            graph.nodes[said].edges_to.append(root_node_id)


def _get_root_display_name(aid: str) -> str:
    """Get display name for a trusted root AID."""
    # Known roots
    known_roots = {
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao": "GLEIF External",
    }
    return known_roots.get(aid, f"Trusted Root: {aid[:16]}...")


def _compute_layers(graph: CredentialGraph, trusted_roots: Set[str]) -> None:
    """Compute layers for hierarchical visualization.

    Layer 0 = root, increasing layers toward leaf credentials.
    """
    if not graph.nodes:
        return

    # Find root nodes
    root_nodes = [
        said for said, node in graph.nodes.items()
        if node.is_root
    ]

    if not root_nodes:
        # No root found - just return nodes in order
        graph.layers = [list(graph.nodes.keys())]
        return

    # BFS from roots to compute layers
    visited: Set[str] = set()
    layers: List[List[str]] = []
    current_layer = root_nodes

    while current_layer:
        layers.append(current_layer)
        visited.update(current_layer)

        # Find nodes that point TO any node in current layer
        next_layer = []
        for said, node in graph.nodes.items():
            if said in visited:
                continue
            # Check if this node has an edge to any node in current layer
            if any(edge_to in current_layer for edge_to in node.edges_to):
                next_layer.append(said)

        current_layer = next_layer

    # Add any remaining nodes not connected to root
    remaining = [said for said in graph.nodes if said not in visited]
    if remaining:
        layers.append(remaining)
        graph.errors.append("Some credentials not connected to trusted root")

    graph.layers = layers


def credential_graph_to_dict(graph: CredentialGraph) -> Dict[str, Any]:
    """Convert CredentialGraph to a JSON-serializable dict for API response."""
    return {
        "nodes": [
            {
                "id": node.said,
                "issuer": node.issuer_aid,
                "type": node.credential_type,
                "displayName": node.display_name,
                "attributes": node.attributes,
                "status": node.status.value,
                "inDossier": node.in_dossier,
                "isRoot": node.is_root,
                "schemaSaid": node.schema_said,
                "edgesTo": node.edges_to,
            }
            for node in graph.nodes.values()
        ],
        "edges": [
            {
                "from": edge.from_said,
                "to": edge.to_said,
                "type": edge.edge_type,
            }
            for edge in graph.edges
        ],
        "rootAid": graph.root_aid,
        "trustPathValid": graph.trust_path_valid,
        "layers": graph.layers,
        "errors": graph.errors,
    }
