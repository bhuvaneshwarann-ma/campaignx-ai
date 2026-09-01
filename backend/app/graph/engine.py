import networkx as nx
from typing import Dict, Any, List, Optional
import math


class ThreatGraphEngine:
    """
    NetworkX-based threat graph engine with multi-hop expansion, depth filtering,
    and React Flow serialization format.
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def build_subgraph_for_entity(
        self,
        root_id: str,
        depth: int = 1,
        max_nodes: int = 100
    ) -> Dict[str, Any]:
        """
        Extracts an ego subgraph centered around root_id up to depth (1 to 5 hops).
        Returns nodes and edges serialized for React Flow.
        """
        depth = max(1, min(5, depth))

        if root_id not in self.graph:
            return {"nodes": [], "edges": [], "stats": {"node_count": 0, "edge_count": 0}}

        # Ego subgraph with radius = depth
        sub_nodes = nx.single_source_shortest_path_length(self.graph.to_undirected(), root_id, cutoff=depth)
        selected_nodes = list(sub_nodes.keys())[:max_nodes]
        sub = self.graph.subgraph(selected_nodes)

        return self.serialize_react_flow(sub, root_id=root_id)

    def serialize_react_flow(self, g: nx.MultiDiGraph, root_id: Optional[str] = None) -> Dict[str, Any]:
        """Serializes NetworkX graph to React Flow format with layout coordinates."""
        nodes = []
        edges = []
        node_list = list(g.nodes(data=True))
        n_count = len(node_list)

        # Circular layout or coordinate generation
        for i, (node_id, data) in enumerate(node_list):
            if root_id and node_id == root_id:
                x, y = 350.0, 250.0
            else:
                angle = (2 * math.pi * i) / max(1, n_count)
                radius = 220 + (50 * (i % 3))
                x = 350.0 + radius * math.cos(angle)
                y = 250.0 + radius * math.sin(angle)

            nodes.append({
                "id": str(node_id),
                "type": data.get("type", "Entity"),
                "data": {
                    "label": data.get("label", str(node_id)),
                    "type": data.get("type", "Entity"),
                    "risk_score": data.get("risk_score", 0.0),
                    "is_root": bool(root_id and node_id == root_id),
                    "metadata": data.get("metadata", {})
                },
                "position": {"x": round(x, 1), "y": round(y, 1)}
            })

        for u, v, key, data in g.edges(keys=True, data=True):
            edges.append({
                "id": f"edge-{u}-{v}-{key}",
                "source": str(u),
                "target": str(v),
                "label": data.get("type", "ASSOCIATED_WITH"),
                "animated": data.get("is_predicted", False),
                "data": {
                    "type": data.get("type", "ASSOCIATED_WITH"),
                    "confidence": data.get("confidence", 1.0),
                    "is_verified": data.get("is_verified", True),
                    "evidence_id": data.get("evidence_id")
                }
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "density": round(nx.density(g), 3) if len(nodes) > 1 else 0.0
            }
        }


graph_engine = ThreatGraphEngine()
