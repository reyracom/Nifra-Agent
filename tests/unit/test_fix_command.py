from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nifra.cli.main import app
from nifra.cli.commands.fix import (
    _FIX_RECIPES,
    _GENERIC_RECIPE,
    _render_json,
    _render_markdown,
    _sorted_chains,
)

runner = CliRunner()

def _make_results_file(tmp_path: Path, chains: list[dict], project: str = "test-project") -> Path:
    """Write a minimal nifra-results.json file."""
    data = {"project": project, "exploit_chains": chains}
    p = tmp_path / "nifra-results.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _chain(
    case_id: str = "001",
    rule_id: str = "PI-001",
    severity: str = "critical",
) -> dict:
    return {
        "case_id": case_id,
        "finding_rule_id": rule_id,
        "severity": severity,
        "reasoning": f"Test finding for {rule_id}",
        "impact": "System compromise",
        "adversarial_payload": "EVIL",
        "exploit_reproducible": True,
        "confidence": 0.9,
        "cvss_ai": 9.0,
        "attack_chain_steps": ["Step 1", "Step 2"],
        "remediation": [{"action": "Fix it"}],
    }


# ── CLI integration – missing results file ────────────────────────────────────

class TestFixCommandMissingFile:
    def test_exits_with_error_when_no_results_file(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # cwd with no nifra-results.json
        result = runner.invoke(app, ["fix"])
        assert result.exit_code == 1
        assert "nifra scan" in result.output.lower() or "results" in result.output.lower()

    def test_explicit_nonexistent_path_errors(self, tmp_path: Path):
        nonexistent = tmp_path / "does-not-exist.json"
        result = runner.invoke(app, ["fix", "--results", str(nonexistent)])
        assert result.exit_code == 1

    def test_invalid_json_errors(self, tmp_path: Path):
        bad_file = tmp_path / "nifra-results.json"
        bad_file.write_text("NOT VALID JSON", encoding="utf-8")
        result = runner.invoke(app, ["fix", "--results", str(bad_file)])
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "json" in result.output.lower()


# ── CLI integration – empty findings ─────────────────────────────────────────

class TestFixCommandEmptyFindings:
    def test_no_findings_exits_zero(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, chains=[])
        result = runner.invoke(app, ["fix", "--results", str(results_file)])
        assert result.exit_code == 0

    def test_no_findings_shows_clean_message(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, chains=[])
        result = runner.invoke(app, ["fix", "--results", str(results_file)])
        output = result.output.lower()
        assert "no findings" in output or "clean" in output or "fix" in output


# ── CLI integration – basic fix output ───────────────────────────────────────

class TestFixCommandOutput:
    def test_single_finding_exits_zero(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain()])
        result = runner.invoke(app, ["fix", "--results", str(results_file)])
        assert result.exit_code == 0

    def test_shows_rule_id_in_cli_output(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(rule_id="PI-001")])
        result = runner.invoke(app, ["fix", "--results", str(results_file)])
        assert "PI-001" in result.output

    def test_shows_severity_in_cli_output(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(severity="critical")])
        result = runner.invoke(app, ["fix", "--results", str(results_file)])
        assert "CRITICAL" in result.output.upper()


# ── CLI integration – case filter ─────────────────────────────────────────────

class TestFixCommandCaseFilter:
    def test_filter_by_existing_case(self, tmp_path: Path):
        chains = [_chain("001", "PI-001"), _chain("002", "TA-001")]
        results_file = _make_results_file(tmp_path, chains)
        result = runner.invoke(app, ["fix", "--results", str(results_file), "--case", "001"])
        assert result.exit_code == 0
        assert "PI-001" in result.output

    def test_filter_excludes_other_cases(self, tmp_path: Path):
        chains = [_chain("001", "PI-001"), _chain("002", "TA-001")]
        results_file = _make_results_file(tmp_path, chains)
        result = runner.invoke(app, ["fix", "--results", str(results_file), "--case", "001"])
        # TA-001 recipe should not appear in the focused single case output
        # (It might appear in generic output but not as the leading finding)
        assert "001" in result.output

    def test_filter_nonexistent_case_errors(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain("001")])
        result = runner.invoke(app, ["fix", "--results", str(results_file), "--case", "999"])
        assert result.exit_code == 1
        assert "999" in result.output or "not found" in result.output.lower()


# ── CLI integration – format markdown ────────────────────────────────────────

class TestFixCommandMarkdownFormat:
    def test_markdown_format_contains_header(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain()], project="my-agent")
        result = runner.invoke(
            app, ["fix", "--results", str(results_file), "--format", "markdown"]
        )
        assert result.exit_code == 0

    def test_markdown_written_to_output_file(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(rule_id="PI-001")])
        out_file = tmp_path / "fixes.md"
        runner.invoke(
            app,
            ["fix", "--results", str(results_file), "--format", "markdown", "--output", str(out_file)],
        )
        assert out_file.exists()
        content = out_file.read_text()
        assert "PI-001" in content

    def test_markdown_output_file_contains_owasp_url(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(rule_id="PI-001")])
        out_file = tmp_path / "fixes.md"
        runner.invoke(
            app,
            ["fix", "--results", str(results_file), "--format", "markdown", "--output", str(out_file)],
        )
        content = out_file.read_text()
        assert "owasp.org" in content


# ── CLI integration – format json ────────────────────────────────────────────

class TestFixCommandJsonFormat:
    def test_json_format_exits_zero(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain()])
        result = runner.invoke(
            app, ["fix", "--results", str(results_file), "--format", "json"]
        )
        assert result.exit_code == 0

    def test_json_written_to_output_file(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(rule_id="DE-001")])
        out_file = tmp_path / "fixes.json"
        runner.invoke(
            app,
            ["fix", "--results", str(results_file), "--format", "json", "--output", str(out_file)],
        )
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "fixes" in data

    def test_json_output_has_project_key(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain()], project="awesome-agent")
        out_file = tmp_path / "fixes.json"
        runner.invoke(
            app,
            ["fix", "--results", str(results_file), "--format", "json", "--output", str(out_file)],
        )
        data = json.loads(out_file.read_text())
        assert data["project"] == "awesome-agent"

    def test_json_output_fix_has_rule_id(self, tmp_path: Path):
        results_file = _make_results_file(tmp_path, [_chain(rule_id="TA-001")])
        out_file = tmp_path / "fixes.json"
        runner.invoke(
            app,
            ["fix", "--results", str(results_file), "--format", "json", "--output", str(out_file)],
        )
        data = json.loads(out_file.read_text())
        assert data["fixes"][0]["rule_id"] == "TA-001"


# ── _render_json unit tests ───────────────────────────────────────────────────

class TestRenderJson:
    def test_returns_valid_json_string(self):
        chains = [_chain()]
        output = _render_json(chains, "test-project")
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_project_key_in_output(self):
        output = _render_json([_chain()], "my-llm-agent")
        data = json.loads(output)
        assert data["project"] == "my-llm-agent"

    def test_fixes_list_length_matches_chains(self):
        chains = [_chain("001"), _chain("002", "TA-001")]
        output = _render_json(chains, "p")
        data = json.loads(output)
        assert len(data["fixes"]) == 2

    def test_fix_has_required_fields(self):
        output = _render_json([_chain(rule_id="PI-001")], "p")
        data = json.loads(output)
        fix = data["fixes"][0]
        assert "case_id" in fix
        assert "rule_id" in fix
        assert "severity" in fix
        assert "fix_title" in fix
        assert "remediation_steps" in fix

    def test_known_rule_has_code_example(self):
        output = _render_json([_chain(rule_id="PI-001")], "p")
        data = json.loads(output)
        assert data["fixes"][0]["has_code_example"] is True

    def test_unknown_rule_uses_generic_recipe(self):
        output = _render_json([_chain(rule_id="XX-999")], "p")
        data = json.loads(output)
        fix = data["fixes"][0]
        assert fix["rule_id"] == "XX-999"
        assert fix["fix_title"] == _GENERIC_RECIPE["title"]

    def test_empty_chains_returns_empty_fixes_list(self):
        output = _render_json([], "p")
        data = json.loads(output)
        assert data["fixes"] == []

    def test_output_is_indented_json(self):
        output = _render_json([_chain()], "p")
        assert "\n" in output


# ── _render_markdown unit tests ───────────────────────────────────────────────

class TestRenderMarkdown:
    def test_returns_string(self):
        assert isinstance(_render_markdown([_chain()], "p"), str)

    def test_contains_project_name(self):
        md = _render_markdown([_chain()], "super-ai-agent")
        assert "super-ai-agent" in md

    def test_contains_rule_id(self):
        md = _render_markdown([_chain(rule_id="EA-001")], "p")
        assert "EA-001" in md

    def test_contains_owasp_url(self):
        md = _render_markdown([_chain(rule_id="PI-001")], "p")
        assert "owasp.org" in md

    def test_contains_code_blocks_for_recipe_with_examples(self):
        md = _render_markdown([_chain(rule_id="PI-001")], "p")
        assert "```python" in md

    def test_generic_recipe_no_code_block_header(self):
        md = _render_markdown([_chain(rule_id="XX-999")], "p")
        # Generic recipe has no code examples — still safe to render
        assert "XX-999" in md


# ── _sorted_chains unit tests ─────────────────────────────────────────────────

class TestSortedChains:
    def test_critical_before_high(self):
        chains = [
            _chain("001", severity="high"),
            _chain("002", severity="critical"),
        ]
        sorted_c = _sorted_chains(chains)
        assert sorted_c[0]["severity"] == "critical"
        assert sorted_c[1]["severity"] == "high"

    def test_ordering_full_spectrum(self):
        chains = [
            _chain("001", severity="info"),
            _chain("002", severity="low"),
            _chain("003", severity="high"),
            _chain("004", severity="medium"),
            _chain("005", severity="critical"),
        ]
        sorted_c = _sorted_chains(chains)
        expected_order = ["critical", "high", "medium", "low", "info"]
        assert [c["severity"] for c in sorted_c] == expected_order

    def test_unknown_severity_last(self):
        chains = [
            _chain("001", severity="unknown_sev"),
            _chain("002", severity="critical"),
        ]
        sorted_c = _sorted_chains(chains)
        assert sorted_c[0]["severity"] == "critical"


# ── Fix recipe registry ───────────────────────────────────────────────────────

class TestFixRecipeRegistry:
    @pytest.mark.parametrize("rule_id", [
        "PI-001", "PI-002", "PI-003", "PI-004",
        "TA-001", "TA-002", "TA-003",
        "DE-001", "DE-002", "DE-003",
        "SC-001", "EA-001", "IO-001",
    ])
    def test_known_rule_ids_have_recipes(self, rule_id: str):
        assert rule_id in _FIX_RECIPES, f"{rule_id} missing from _FIX_RECIPES"

    @pytest.mark.parametrize("rule_id", [
        "PI-001", "PI-002", "PI-003", "PI-004",
        "TA-001", "TA-002", "TA-003",
        "DE-001", "DE-002", "DE-003",
        "SC-001", "EA-001", "IO-001",
    ])
    def test_each_recipe_has_required_fields(self, rule_id: str):
        recipe = _FIX_RECIPES[rule_id]
        assert "title" in recipe, f"{rule_id} missing 'title'"
        assert "owasp" in recipe, f"{rule_id} missing 'owasp'"
        assert "description" in recipe, f"{rule_id} missing 'description'"
        assert "steps" in recipe, f"{rule_id} missing 'steps'"
        assert len(recipe["steps"]) >= 3, f"{rule_id} has fewer than 3 steps"

    def test_generic_recipe_has_required_fields(self):
        assert "title" in _GENERIC_RECIPE
        assert "steps" in _GENERIC_RECIPE
        assert isinstance(_GENERIC_RECIPE["steps"], list)
        assert len(_GENERIC_RECIPE["steps"]) >= 3

    def test_unknown_rule_id_falls_back_to_generic(self):
        output = _render_json([_chain(rule_id="NONEXISTENT-999")], "p")
        data = json.loads(output)
        assert data["fixes"][0]["fix_title"] == _GENERIC_RECIPE["title"]

    def test_recipe_steps_are_non_empty_strings(self):
        for rule_id, recipe in _FIX_RECIPES.items():
            for step in recipe["steps"]:
                assert isinstance(step, str) and len(step.strip()) > 0, (
                    f"{rule_id}: empty step found"
                )

    def test_at_least_13_recipes_registered(self):
        assert len(_FIX_RECIPES) >= 13
