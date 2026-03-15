from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from nifra.reporters.sarif_reporter import SARIFReporter, _SARIF_SCHEMA, _SEVERITY_LEVEL
from nifra.reasoning.engine import ExploitChain, ReasoningResult


def _make_chain(
    case_id: str = "001",
    rule_id: str = "PI-001",
    severity: str = "critical",
    confidence: float = 0.9,
    reproducible: bool = True,
    payload: str | None = "malicious payload",
) -> ExploitChain:
    return ExploitChain(
        case_id=case_id,
        finding_rule_id=rule_id,
        severity=severity,
        attack_chain_steps=["Step 1", "Step 2", "Step 3"],
        reasoning="The RAG loader ingests untrusted documents without validation.",
        impact="System prompt disclosure and PII exfiltration.",
        adversarial_payload=payload,
        exploit_reproducible=reproducible,
        confidence=confidence,
        cvss_ai=9.1,
        remediation=[
            {"action": "Add document trust validation"},
            {"action": "Restrict database tool to read-only"},
        ],
    )


def _make_attack_surface():
    surface = MagicMock()
    surface.node_count = 5
    surface.edge_count = 4
    surface.findings = []
    return surface

class TestSARIFReporterStructure:
    def test_sarif_schema_and_version(self):
        reporter = SARIFReporter()
        result = reporter.render(_make_attack_surface(), ReasoningResult(), "test-project")
        assert result["$schema"] == _SARIF_SCHEMA
        assert result["version"] == "2.1.0"

    def test_has_single_run(self):
        reporter = SARIFReporter()
        result = reporter.render(_make_attack_surface(), ReasoningResult(), "test-project")
        assert "runs" in result
        assert len(result["runs"]) == 1

    def test_tool_driver_fields(self):
        reporter = SARIFReporter()
        result = reporter.render(_make_attack_surface(), ReasoningResult(), "test-project")
        driver = result["runs"][0]["tool"]["driver"]
        assert driver["name"] == "NIfra"
        assert driver["version"] == "0.2.0"
        assert "reyracom" in driver["informationUri"]

    def test_run_properties_populated(self):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "my-agent")
        props = sarif["runs"][0]["properties"]
        assert props["project"] == "my-agent"
        assert props["totalFindings"] == 1
        assert props["criticalFindings"] == 1
        assert props["riskLevel"] == "CRITICAL"

    def test_empty_findings_produces_valid_sarif(self):
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), ReasoningResult(), "empty-project")
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

class TestSARIFRules:
    def test_rule_id_and_name(self):
        chain = _make_chain(rule_id="PI-001")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "PI-001"
        assert "PI-001" in rules[0]["name"]

    def test_critical_rule_level_is_error(self):
        chain = _make_chain(severity="critical")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        level = sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"]
        assert level == "error"

    def test_high_rule_level_is_error(self):
        chain = _make_chain(severity="high")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        level = sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"]
        assert level == "error"

    def test_medium_rule_level_is_warning(self):
        chain = _make_chain(severity="medium")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        level = sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"]
        assert level == "warning"

    def test_low_rule_level_is_note(self):
        chain = _make_chain(severity="low")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        level = sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"]
        assert level == "note"

    def test_rules_deduped_for_same_rule_id(self):
        chains = [
            _make_chain(case_id="001", rule_id="PI-001"),
            _make_chain(case_id="002", rule_id="PI-001"),  # same rule
        ]
        result_obj = ReasoningResult(exploit_chains=chains)
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # deduped

    def test_different_rules_not_deduped(self):
        chains = [
            _make_chain(case_id="001", rule_id="PI-001"),
            _make_chain(case_id="002", rule_id="TA-001"),
        ]
        result_obj = ReasoningResult(exploit_chains=chains)
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_known_rule_has_help_uri(self):
        chain = _make_chain(rule_id="PI-001")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in rule
        assert "owasp.org" in rule["helpUri"]

    def test_high_confidence_rule_has_high_precision(self):
        chain = _make_chain(confidence=0.9)
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        precision = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["precision"]
        assert precision == "high"

    def test_low_confidence_rule_has_medium_precision(self):
        chain = _make_chain(confidence=0.5)
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        precision = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["precision"]
        assert precision == "medium"

class TestSARIFResults:
    def test_result_count_matches_chains(self):
        chains = [_make_chain(case_id=str(i)) for i in range(3)]
        result_obj = ReasoningResult(exploit_chains=chains)
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        assert len(sarif["runs"][0]["results"]) == 3

    def test_result_has_rule_id(self):
        chain = _make_chain(rule_id="TA-001")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "TA-001"

    def test_result_message_contains_reasoning(self):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "RAG loader" in msg

    def test_result_message_contains_impact(self):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "Impact" in msg
        assert "PII exfiltration" in msg

    def test_result_properties_have_case_id(self):
        chain = _make_chain(case_id="042")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["caseId"] == "042"

    def test_result_has_cvss_and_confidence(self):
        chain = _make_chain(confidence=0.87)
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["confidence"] == 0.87
        assert props["cvssAi"] == pytest.approx(9.1)

    def test_reproducible_result_includes_payload(self):
        chain = _make_chain(reproducible=True, payload="EVIL PAYLOAD")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["adversarialPayload"] == "EVIL PAYLOAD"

    def test_non_reproducible_result_excludes_payload(self):
        chain = _make_chain(reproducible=False, payload="EVIL PAYLOAD")
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "adversarialPayload" not in props

    def test_result_has_fixes(self):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert len(result["fixes"]) <= 3

    def test_none_payload_not_in_result(self):
        chain = _make_chain(payload=None)
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        sarif = reporter.render(_make_attack_surface(), result_obj, "p")
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "adversarialPayload" not in props

class TestSARIFSerialization:
    def test_render_json_returns_string(self):
        reporter = SARIFReporter()
        content = reporter.render_json(_make_attack_surface(), ReasoningResult(), "p")
        assert isinstance(content, str)

    def test_render_json_is_valid_json(self):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        content = reporter.render_json(_make_attack_surface(), result_obj, "p")
        parsed = json.loads(content)
        assert parsed["version"] == "2.1.0"

    def test_render_json_indented(self):
        reporter = SARIFReporter()
        content = reporter.render_json(_make_attack_surface(), ReasoningResult(), "p")
        assert "\n" in content  # indented output

    def test_write_creates_file(self, tmp_path: Path):
        chain = _make_chain()
        result_obj = ReasoningResult(exploit_chains=[chain])
        reporter = SARIFReporter()
        output_path = tmp_path / "results.sarif"
        reporter.write(_make_attack_surface(), result_obj, "my-project", output_path)
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["version"] == "2.1.0"

    def test_write_file_contains_project_name(self, tmp_path: Path):
        reporter = SARIFReporter()
        output_path = tmp_path / "out.sarif"
        reporter.write(_make_attack_surface(), ReasoningResult(), "awesome-agent", output_path)
        data = json.loads(output_path.read_text())
        assert data["runs"][0]["properties"]["project"] == "awesome-agent"

class TestSeverityMapping:
    @pytest.mark.parametrize("severity,expected_level", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
        ("unknown", "warning"),  # fallback
    ])
    def test_severity_level_mapping(self, severity, expected_level):
        assert _SEVERITY_LEVEL.get(severity, "warning") == expected_level
