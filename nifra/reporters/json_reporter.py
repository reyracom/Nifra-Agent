from __future__ import annotations

import json
from pathlib import Path

from nifra.graph.builder import AttackSurfaceGraph
from nifra.reasoning.engine import ReasoningResult


class JSONReporter:
    """Serialize full scan results to JSON."""

    def render(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
    ) -> str:
        data = {
            "nifra_version": "0.1.0",
            "project": project_name,
            "risk_level": reasoning_result.risk_level,
            "summary": {
                "nodes": attack_surface.node_count,
                "edges": attack_surface.edge_count,
                "findings": len(attack_surface.findings),
                "exploit_chains": len(reasoning_result.exploit_chains),
                "critical": sum(1 for c in reasoning_result.exploit_chains if c.severity == "critical"),
                "high": sum(1 for c in reasoning_result.exploit_chains if c.severity == "high"),
                "medium": sum(1 for c in reasoning_result.exploit_chains if c.severity == "medium"),
                "low": sum(1 for c in reasoning_result.exploit_chains if c.severity == "low"),
            },
            "exploit_chains": [c.to_dict() for c in reasoning_result.exploit_chains],
            "attack_graph": attack_surface.to_dict(),
        }
        return json.dumps(data, indent=2)

    def write(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
        output_path: Path,
    ) -> None:
        content = self.render(attack_surface, reasoning_result, project_name)
        output_path.write_text(content, encoding="utf-8")
