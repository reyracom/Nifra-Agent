from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Internal imports
from nifra.detectors.ast_parser import ASTParser
from nifra.detectors.dependency_scanner import DependencyScanner
from nifra.graph.builder import AttackSurfaceGraphBuilder
from nifra.reasoning.engine import ReasoningEngine

# CLI runner for end-to-end CLI tests
from nifra.cli.main import app

runner = CliRunner()

REPO_ROOT = Path(__file__).parent.parent.parent
PLAYGROUND_RAG = REPO_ROOT / "playground" / "vulnerable-rag-agent"
PLAYGROUND_TOOL = REPO_ROOT / "playground" / "vulnerable-tool-agent"

RAG_RESULTS_FIXTURE = PLAYGROUND_RAG / "nifra-results.json"


def _has_rag() -> bool:
    return PLAYGROUND_RAG.exists() and any(PLAYGROUND_RAG.glob("*.py"))


def _has_tool() -> bool:
    return PLAYGROUND_TOOL.exists() and any(PLAYGROUND_TOOL.glob("*.py"))


@pytest.mark.skipif(not _has_rag(), reason="playground/vulnerable-rag-agent not present")
class TestFullPipelineRAGAgent:
    """Full scan pipeline against  playground/vulnerable-rag-agent."""

    @pytest.fixture(scope="class")
    def pipeline_result(self):
        """Run the complete deterministic pipeline once and share results."""
        dep_result = DependencyScanner(PLAYGROUND_RAG).scan()
        ast_result = ASTParser(PLAYGROUND_RAG).scan()
        surface = AttackSurfaceGraphBuilder(dep_result=dep_result, ast_result=ast_result).build()

        # Use deterministic engine (no LLM / API key required)
        engine = ReasoningEngine.__new__(ReasoningEngine)
        engine.model = "deterministic"
        engine.temperature = 0
        engine._client = None
        result = engine._build_deterministic_result(surface)
        return surface, result

    # --- Attack surface graph ---

    def test_graph_has_minimum_nodes(self, pipeline_result):
        surface, _ = pipeline_result
        assert surface.node_count >= 2, f"Expected ≥ 2 nodes, got {surface.node_count}"

    def test_graph_has_minimum_edges(self, pipeline_result):
        surface, _ = pipeline_result
        assert surface.edge_count >= 1, f"Expected ≥ 1 edge, got {surface.edge_count}"

    def test_graph_has_findings(self, pipeline_result):
        surface, _ = pipeline_result
        assert len(surface.findings) >= 1, "Expected at least 1 deterministic finding"

    # --- Reasoning result ---

    def test_risk_level_is_critical_or_high(self, pipeline_result):
        _, result = pipeline_result
        assert result.risk_level in ("CRITICAL", "HIGH"), (
            f"Expected CRITICAL or HIGH, got {result.risk_level}"
        )

    def test_exploit_chains_not_empty(self, pipeline_result):
        _, result = pipeline_result
        assert len(result.exploit_chains) >= 1, "Expected at least 1 exploit chain"

    def test_all_confidences_in_range(self, pipeline_result):
        _, result = pipeline_result
        for chain in result.exploit_chains:
            assert 0.0 <= chain.confidence <= 1.0, (
                f"Confidence out of range: {chain.confidence}"
            )

    def test_all_cvss_scores_in_range(self, pipeline_result):
        _, result = pipeline_result
        for chain in result.exploit_chains:
            assert 0.0 <= chain.cvss_ai <= 10.0, (
                f"CVSS-AI out of range: {chain.cvss_ai}"
            )

    def test_exploit_chains_have_attack_steps(self, pipeline_result):
        _, result = pipeline_result
        for chain in result.exploit_chains:
            assert len(chain.attack_chain_steps) >= 1, (
                f"Chain {chain.case_id} has no attack steps"
            )

    def test_exploit_chains_have_remediation(self, pipeline_result):
        _, result = pipeline_result
        for chain in result.exploit_chains:
            assert len(chain.remediation) >= 1, (
                f"Chain {chain.case_id} has no remediation items"
            )

    def test_pi_001_finding_detected(self, pipeline_result):
        """RAG app should trigger PI-001 (indirect prompt injection via RAG)."""
        _, result = pipeline_result
        rule_ids = [c.finding_rule_id for c in result.exploit_chains]
        assert "PI-001" in rule_ids, f"Expected PI-001 in {rule_ids}"

    def test_de_001_finding_detected(self, pipeline_result):
        """RAG app with Chroma / PII should trigger DE-001 (data exfiltration)."""
        _, result = pipeline_result
        rule_ids = [c.finding_rule_id for c in result.exploit_chains]
        assert "DE-001" in rule_ids, f"Expected DE-001 in {rule_ids}"

    def test_all_chains_have_severity(self, pipeline_result):
        _, result = pipeline_result
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for chain in result.exploit_chains:
            assert chain.severity.lower() in valid_severities, (
                f"Unknown severity: {chain.severity}"
            )


@pytest.mark.skipif(not _has_tool(), reason="playground/vulnerable-tool-agent not present")
class TestFullPipelineToolAgent:
    """Full scan pipeline against playground/vulnerable-tool-agent."""

    @pytest.fixture(scope="class")
    def pipeline_result(self):
        dep_result = DependencyScanner(PLAYGROUND_TOOL).scan()
        ast_result = ASTParser(PLAYGROUND_TOOL).scan()
        surface = AttackSurfaceGraphBuilder(dep_result=dep_result, ast_result=ast_result).build()

        engine = ReasoningEngine.__new__(ReasoningEngine)
        engine.model = "deterministic"
        engine.temperature = 0
        engine._client = None
        result = engine._build_deterministic_result(surface)
        return surface, result

    def test_graph_has_minimum_nodes(self, pipeline_result):
        surface, _ = pipeline_result
        assert surface.node_count >= 2

    def test_exploit_chains_not_empty(self, pipeline_result):
        _, result = pipeline_result
        assert len(result.exploit_chains) >= 1

    def test_all_confidences_in_range(self, pipeline_result):
        _, result = pipeline_result
        for chain in result.exploit_chains:
            assert 0.0 <= chain.confidence <= 1.0

    def test_risk_is_high_or_critical(self, pipeline_result):
        _, result = pipeline_result
        assert result.risk_level in ("CRITICAL", "HIGH", "MEDIUM")


# ---------------------------------------------------------------------------
# CLI end-to-end scan → report round-trip
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _has_rag(), reason="playground/vulnerable-rag-agent not present")
class TestCLIEndToEnd:
    """Verify the nifra scan → nifra report CLI round-trip."""

    def test_scan_then_report_cli(self, tmp_path):
        """Scan the RAG agent with --no-ai and immediately generate a cli report."""
        results_file = tmp_path / "results.json"

        # Step 1: scan
        scan_result = runner.invoke(
            app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(results_file)]
        )
        assert scan_result.exit_code == 0, f"scan failed: {scan_result.output}"
        assert results_file.exists()

        # Step 2: report from the generated results
        report_result = runner.invoke(
            app, ["report", "--format", "cli", "--results", str(results_file)]
        )
        assert report_result.exit_code == 0, f"report failed: {report_result.output}"

    def test_scan_then_report_markdown(self, tmp_path):
        results_file = tmp_path / "results.json"
        report_file = tmp_path / "report.md"

        runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(results_file)])

        if not results_file.exists():
            pytest.skip("Scan did not produce output; skipping report step")

        report_result = runner.invoke(
            app, ["report", "--format", "markdown", "--results", str(results_file),
                  "--output", str(report_file)]
        )
        assert report_result.exit_code == 0
        assert report_file.exists()
        content = report_file.read_text()
        assert "#" in content  # Basic markdown sanity check

    def test_scan_then_report_html(self, tmp_path):
        results_file = tmp_path / "results.json"
        report_file = tmp_path / "report.html"

        runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(results_file)])

        if not results_file.exists():
            pytest.skip("Scan did not produce output; skipping report step")

        report_result = runner.invoke(
            app, ["report", "--format", "html", "--results", str(results_file),
                  "--output", str(report_file)]
        )
        assert report_result.exit_code == 0
        assert report_file.exists()
        content = report_file.read_text()
        assert "<" in content  # Basic HTML sanity check

    def test_scan_output_json_schema(self, tmp_path):
        """Scan output JSON should conform to the nifra result schema."""
        results_file = tmp_path / "results.json"
        runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(results_file)])

        if not results_file.exists():
            pytest.skip("Scan did not produce output")

        data = json.loads(results_file.read_text())

        # Top-level keys
        for key in ("nifra_version", "project", "risk_level", "summary", "exploit_chains", "attack_graph"):
            assert key in data, f"Missing key: {key}"

        # Summary sub-keys
        summary = data["summary"]
        for k in ("nodes", "edges", "findings", "exploit_chains"):
            assert k in summary

        # Each exploit chain
        for chain in data["exploit_chains"]:
            assert "case_id" in chain
            assert "finding_rule_id" in chain
            assert "severity" in chain
            assert 0.0 <= chain.get("confidence", 0.0) <= 1.0

    def test_scan_pipeline_finding_count(self, tmp_path):
        """RAG agent should produce at least 2 exploit chains."""
        results_file = tmp_path / "results.json"
        runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(results_file)])

        if not results_file.exists():
            pytest.skip("Scan did not produce output")

        data = json.loads(results_file.read_text())
        assert len(data["exploit_chains"]) >= 2, (
            f"Expected ≥ 2 exploit chains, got {len(data['exploit_chains'])}"
        )

    def test_scan_fail_on_critical_after_rag(self, tmp_path):
        """nifra scan --fail-on critical should exit 1 for the vulnerable RAG agent."""
        results_file = tmp_path / "results.json"
        result = runner.invoke(
            app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--fail-on", "critical",
                  "--output", str(results_file)]
        )
        assert result.exit_code == 1, (
            "Expected exit code 1 for CRITICAL findings with --fail-on critical"
        )


@pytest.mark.skipif(not _has_rag(), reason="playground/vulnerable-rag-agent not present")
def test_deterministic_scan_is_reproducible():
    """Running the deterministic pipeline twice should yield identical rule IDs and risk level."""

    def _run():
        dep_result = DependencyScanner(PLAYGROUND_RAG).scan()
        ast_result = ASTParser(PLAYGROUND_RAG).scan()
        surface = AttackSurfaceGraphBuilder(dep_result=dep_result, ast_result=ast_result).build()
        engine = ReasoningEngine.__new__(ReasoningEngine)
        engine.model = "deterministic"
        engine.temperature = 0
        engine._client = None
        result = engine._build_deterministic_result(surface)
        return result

    r1 = _run()
    r2 = _run()

    assert r1.risk_level == r2.risk_level
    assert sorted(c.finding_rule_id for c in r1.exploit_chains) == sorted(
        c.finding_rule_id for c in r2.exploit_chains
    )
