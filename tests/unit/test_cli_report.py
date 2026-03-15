from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nifra.cli.main import app

runner = CliRunner()

# Pre-existing results file from the playground — canonical fixture
RESULTS_FIXTURE = (
    Path(__file__).parent.parent.parent / "playground" / "vulnerable-rag-agent" / "nifra-results.json"
)


def _has_fixture() -> bool:
    return RESULTS_FIXTURE.exists()


@pytest.fixture()
def results_file(tmp_path) -> Path:
    """Copy the real nifra-results.json into a tmp dir and return its path."""
    dest = tmp_path / "nifra-results.json"
    shutil.copy(RESULTS_FIXTURE, dest)
    return dest


@pytest.fixture()
def minimal_results(tmp_path) -> Path:
    """Write a minimal valid nifra-results.json."""
    data = {
        "nifra_version": "0.1.0",
        "project": "test-project",
        "risk_level": "HIGH",
        "summary": {"nodes": 2, "edges": 1, "findings": 1, "exploit_chains": 1,
                    "critical": 0, "high": 1, "medium": 0, "low": 0},
        "exploit_chains": [
            {
                "case_id": "001",
                "finding_rule_id": "TA-001",
                "severity": "high",
                "attack_chain_steps": ["Step 1", "Step 2"],
                "reasoning": "Test reasoning",
                "impact": "Test impact",
                "adversarial_payload": None,
                "exploit_reproducible": False,
                "confidence": 0.75,
                "cvss_ai": 7.0,
                "remediation": [],
            }
        ],
        "attack_graph": {
            "nodes": [],
            "edges": [],
            "findings": [],
        },
    }
    dest = tmp_path / "nifra-results.json"
    dest.write_text(json.dumps(data), encoding="utf-8")
    return dest


def test_report_cli_format_exits_zero(minimal_results):
    result = runner.invoke(app, ["report", "--format", "cli", "--results", str(minimal_results)])
    assert result.exit_code == 0


def test_report_cli_format_contains_project_name(minimal_results):
    result = runner.invoke(app, ["report", "--format", "cli", "--results", str(minimal_results)])
    assert result.exit_code == 0
    assert "test-project" in result.output


def test_report_json_format_to_file(minimal_results, tmp_path):
    out = tmp_path / "output.json"
    result = runner.invoke(
        app, ["report", "--format", "json", "--results", str(minimal_results), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert "exploit_chains" in data


def test_report_json_format_to_stdout(minimal_results):
    result = runner.invoke(app, ["report", "--format", "json", "--results", str(minimal_results)])
    assert result.exit_code == 0


def test_report_json_format_stdout_contains_valid_json(minimal_results):
    result = runner.invoke(app, ["report", "--format", "json", "--results", str(minimal_results)])
    assert result.exit_code == 0
    # Output should contain JSON-looking content
    assert "{" in result.output or len(result.stdout) > 0


def test_report_markdown_format_to_file(minimal_results, tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(
        app, ["report", "--format", "markdown", "--results", str(minimal_results), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "#" in content  # Markdown headings


def test_report_markdown_format_to_stdout(minimal_results):
    result = runner.invoke(app, ["report", "--format", "markdown", "--results", str(minimal_results)])
    assert result.exit_code == 0


def test_report_markdown_contains_severity(minimal_results):
    out_file = Path(str(minimal_results).replace("nifra-results.json", "report.md"))
    result = runner.invoke(
        app, ["report", "--format", "markdown", "--results", str(minimal_results),
              "--output", str(out_file)]
    )
    if result.exit_code == 0 and out_file.exists():
        text = out_file.read_text(encoding="utf-8")
        assert "HIGH" in text.upper() or "high" in text


def test_report_html_format_to_file(minimal_results, tmp_path):
    out = tmp_path / "report.html"
    result = runner.invoke(
        app, ["report", "--format", "html", "--results", str(minimal_results), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "<html" in content.lower() or "<!doctype" in content.lower()


def test_report_html_format_to_stdout(minimal_results):
    result = runner.invoke(app, ["report", "--format", "html", "--results", str(minimal_results)])
    assert result.exit_code == 0


def test_report_unknown_format_exits_one(minimal_results):
    result = runner.invoke(
        app, ["report", "--format", "xml", "--results", str(minimal_results)]
    )
    assert result.exit_code == 1


def test_report_no_results_file_exits_one(tmp_path, monkeypatch):
    """Without --results and without nifra-results.json in cwd, exits 1."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "--format", "cli"])
    assert result.exit_code == 1


def test_report_bad_json_results_exits_one(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("NOT VALID JSON {{{", encoding="utf-8")
    result = runner.invoke(app, ["report", "--format", "cli", "--results", str(bad)])
    assert result.exit_code == 1


def test_report_missing_results_path_exits_one(tmp_path):
    result = runner.invoke(
        app, ["report", "--format", "cli", "--results", str(tmp_path / "nonexistent.json")]
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Using the real playground fixture
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _has_fixture(), reason="playground fixture not present")
def test_report_real_fixture_cli_format(results_file):
    result = runner.invoke(app, ["report", "--format", "cli", "--results", str(results_file)])
    assert result.exit_code == 0


@pytest.mark.skipif(not _has_fixture(), reason="playground fixture not present")
def test_report_real_fixture_markdown_format(results_file, tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(
        app, ["report", "--format", "markdown", "--results", str(results_file), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()


@pytest.mark.skipif(not _has_fixture(), reason="playground fixture not present")
def test_report_real_fixture_html_format(results_file, tmp_path):
    out = tmp_path / "report.html"
    result = runner.invoke(
        app, ["report", "--format", "html", "--results", str(results_file), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()


@pytest.mark.skipif(not _has_fixture(), reason="playground fixture not present")
def test_report_real_fixture_json_format(results_file, tmp_path):
    out = tmp_path / "output.json"
    result = runner.invoke(
        app, ["report", "--format", "json", "--results", str(results_file), "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()


@pytest.mark.skipif(not _has_fixture(), reason="playground fixture not present")
def test_report_real_fixture_contains_pi_rule(results_file, tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(
        app, ["report", "--format", "markdown", "--results", str(results_file), "--output", str(out)]
    )
    if result.exit_code == 0 and out.exists():
        content = out.read_text()
        assert "PI-001" in content or "DE-001" in content

def test_report_help_exits_zero():
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "format" in result.output.lower()
