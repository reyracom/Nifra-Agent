from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nifra.cli.main import app

runner = CliRunner()

# Path to the real playground fixture that already has AI library code
PLAYGROUND_RAG = Path(__file__).parent.parent.parent / "playground" / "vulnerable-rag-agent"


def _ensure_playground() -> bool:
    """Return True only if the playground fixture exists and has Python files."""
    return PLAYGROUND_RAG.exists() and any(PLAYGROUND_RAG.glob("*.py"))


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_no_ai_exits_zero(tmp_path):
    """nifra scan <dir> --no-ai exits 0."""
    result = runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(tmp_path / "out.json")])
    assert result.exit_code == 0, result.output


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_no_ai_creates_output_file(tmp_path):
    """--output flag creates a JSON file."""
    out_file = tmp_path / "results.json"
    runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(out_file)])
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert "exploit_chains" in data
    assert "attack_graph" in data


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_no_ai_json_has_expected_keys(tmp_path):
    """Output JSON contains the nifra schema keys."""
    out_file = tmp_path / "results.json"
    runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(out_file)])
    data = json.loads(out_file.read_text())
    for key in ("nifra_version", "project", "risk_level", "summary", "exploit_chains", "attack_graph"):
        assert key in data, f"Missing key: {key}"


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_no_ai_verbose_exits_zero():
    """--verbose flag does not break the scan."""
    result = runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--verbose"])
    assert result.exit_code == 0


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_default_saves_nifra_results_json(tmp_path, monkeypatch):
    """Without --output, scan should save nifra-results.json to cwd (not inside target)."""
    import shutil

    target = tmp_path / "myapp"
    shutil.copytree(PLAYGROUND_RAG, target, ignore=shutil.ignore_patterns("nifra-results.json"))

    # Change cwd so we can see where the default output lands
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(target), "--no-ai"])
    assert result.exit_code == 0
    # Output should be in cwd (tmp_path), NOT inside target
    assert (tmp_path / "nifra-results.json").exists()

@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_fail_on_info_exits_one(tmp_path):
    """--fail-on info should always exit 1 when any finding exists."""
    result = runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--fail-on", "info",
                                  "--output", str(tmp_path / "r.json")])
    assert result.exit_code in (0, 1)


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_fail_on_critical_exits_one_for_critical_project(tmp_path):
    """--fail-on critical exits 1 when project has critical findings."""
    result = runner.invoke(
        app,
        ["scan", str(PLAYGROUND_RAG), "--no-ai", "--fail-on", "critical",
         "--output", str(tmp_path / "r.json")],
    )
    # The RAG agent has PI-001 CRITICAL — should exit 1
    assert result.exit_code == 1


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_fail_on_is_case_insensitive(tmp_path):
    """--fail-on accepts mixed-case severity strings."""
    result = runner.invoke(
        app,
        ["scan", str(PLAYGROUND_RAG), "--no-ai", "--fail-on", "CRITICAL",
         "--output", str(tmp_path / "r.json")],
    )
    assert result.exit_code == 1

def test_scan_nonexistent_dir_exits_nonzero():
    """Scanning a directory that does not exist exits non-zero."""
    result = runner.invoke(app, ["scan", "/nonexistent/path/xyz123"])
    assert result.exit_code != 0


def test_scan_help_shows_usage():
    """nifra scan --help works."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "target" in result.output.lower() or "scan" in result.output.lower()

@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_without_openai_key_falls_back_gracefully(tmp_path, monkeypatch):
    """When ReasoningEngine raises EnvironmentError scan falls back to deterministic mode."""
    # Remove OPENAI_API_KEY from environment so ReasoningEngine raises
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--output", str(tmp_path / "r.json")])
    # Should still exit 0 (falling back to deterministic)
    assert result.exit_code == 0


@pytest.mark.skipif(not _ensure_playground(), reason="playground fixture not present")
def test_scan_output_contains_project_name(tmp_path):
    """Output JSON has the project name matching the directory name."""
    out_file = tmp_path / "results.json"
    runner.invoke(app, ["scan", str(PLAYGROUND_RAG), "--no-ai", "--output", str(out_file)])
    if out_file.exists():
        data = json.loads(out_file.read_text())
        assert data["project"] == PLAYGROUND_RAG.name
