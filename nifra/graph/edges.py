from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx


class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"
    TOOL_CALL = "tool_call"
    RETRIEVAL = "retrieval"
    OUTPUT = "output"


@dataclass(frozen=True)
class EdgeSpec:
    source_node_type: str
    target_node_type: str
    edge_type: EdgeType
    default_validated: bool = False
    risk_weight: float = 1.0


# Known high-risk edge patterns used to infer missing edges
# When a source and target node co-occur, these edges are inferred
DEFAULT_EDGE_PATTERNS: list[EdgeSpec] = [
    EdgeSpec("external_document", "rag_loader", EdgeType.DATA_FLOW, default_validated=False, risk_weight=1.3),
    EdgeSpec("user_input", "prompt_template", EdgeType.DATA_FLOW, default_validated=False, risk_weight=1.2),
    EdgeSpec("rag_loader", "prompt_template", EdgeType.RETRIEVAL, default_validated=False, risk_weight=1.3),
    EdgeSpec("prompt_template", "llm_client", EdgeType.DATA_FLOW, default_validated=True, risk_weight=1.0),
    EdgeSpec("llm_client", "agent_executor", EdgeType.DATA_FLOW, default_validated=True, risk_weight=1.0),
    EdgeSpec("agent_executor", "agent_tool", EdgeType.TOOL_CALL, default_validated=False, risk_weight=1.5),
    EdgeSpec("agent_tool", "data_sink", EdgeType.DATA_FLOW, default_validated=False, risk_weight=1.4),
    EdgeSpec("llm_client", "output", EdgeType.OUTPUT, default_validated=False, risk_weight=1.2),
]


class EdgeInferrer:
    """
    Infer edges between detected nodes using pattern matching and co-occurrence.
    """

    def __init__(self, graph: "nx.DiGraph") -> None:
        self._graph = graph

    def infer_edges(self) -> None:
        """Add inferred edges to the graph based on known patterns."""
        # Group live node IDs by their node_type string
        nodes_by_type: dict[str, list[str]] = {}
        for node_id, data in self._graph.nodes(data=True):
            ntype = data.get("node_type", "")
            nodes_by_type.setdefault(ntype, []).append(node_id)

        for spec in DEFAULT_EDGE_PATTERNS:
            sources = nodes_by_type.get(spec.source_node_type, [])
            targets = nodes_by_type.get(spec.target_node_type, [])
            for src in sources:
                for tgt in targets:
                    if src != tgt and not self._graph.has_edge(src, tgt):
                        src_file = self._graph.nodes[src].get("source_file")
                        tgt_file = self._graph.nodes[tgt].get("source_file")
                        # Consider same-file co-occurrence as stronger signal
                        same_file = (
                            src_file is not None
                            and tgt_file is not None
                            and src_file == tgt_file
                        )
                        self._graph.add_edge(
                            src,
                            tgt,
                            edge_type=spec.edge_type.value,
                            validated=spec.default_validated,
                            risk_weight=spec.risk_weight * (1.1 if same_file else 1.0),
                            same_file=same_file,
                        )
