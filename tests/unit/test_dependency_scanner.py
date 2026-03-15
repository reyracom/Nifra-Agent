from pathlib import Path
import tempfile
import json

from nifra.detectors.dependency_scanner import DependencyScanner, DependencyScanResult, DetectedLibrary


def _proj_with_reqs(content: str) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "requirements.txt").write_text(content, encoding="utf-8")
    return tmp


def test_detects_openai():
    proj = _proj_with_reqs("openai>=1.0.0\nrequests\n")
    result = DependencyScanner(proj).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "openai" in names


def test_detects_langchain():
    proj = _proj_with_reqs("langchain==0.2.0\nlangchain-core\n")
    result = DependencyScanner(proj).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "langchain" in names


def test_ignores_non_ai():
    proj = _proj_with_reqs("flask>=2.0\nrequests\npytest\n")
    result = DependencyScanner(proj).scan()
    assert result.detected_libraries == []


# ---------------------------------------------------------------------------
# pyproject.toml scanning
# ---------------------------------------------------------------------------

def test_detects_openai_from_pyproject_toml():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "pyproject.toml").write_text(
        '[project]\ndependencies = ["openai>=1.0", "requests"]\n',
        encoding="utf-8"
    )
    result = DependencyScanner(tmp).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "openai" in names


def test_detects_langchain_from_pyproject_toml():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "pyproject.toml").write_text(
        '[project]\ndependencies = ["langchain>=0.2", "anthropic"]\n',
        encoding="utf-8"
    )
    result = DependencyScanner(tmp).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "langchain" in names
    assert "anthropic" in names


def test_pyproject_toml_not_present_returns_empty():
    tmp = Path(tempfile.mkdtemp())
    # No pyproject.toml — scanner should silently return nothing
    result = DependencyScanner(tmp).scan()
    assert result.detected_libraries == []


# ---------------------------------------------------------------------------
# package.json scanning
# ---------------------------------------------------------------------------

def test_detects_langchain_from_package_json():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "package.json").write_text(
        json.dumps({
            "dependencies": {"langchain": "^0.2.0", "express": "^4.0.0"}
        }),
        encoding="utf-8"
    )
    result = DependencyScanner(tmp).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "langchain" in names


def test_detects_ai_from_package_json_dev_deps():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "package.json").write_text(
        json.dumps({
            "dependencies": {"express": "^4.0.0"},
            "devDependencies": {"ai": "^3.0.0"},
        }),
        encoding="utf-8"
    )
    result = DependencyScanner(tmp).scan()
    names = [lib.name for lib in result.detected_libraries]
    assert "ai" in names


def test_ignores_node_modules_package_json():
    tmp = Path(tempfile.mkdtemp())
    node_mod = tmp / "node_modules" / "some-pkg"
    node_mod.mkdir(parents=True)
    (node_mod / "package.json").write_text(
        json.dumps({"dependencies": {"langchain": "0.2.0"}}),
        encoding="utf-8"
    )
    result = DependencyScanner(tmp).scan()
    assert result.detected_libraries == []


# ---------------------------------------------------------------------------
# DependencyScanResult flags
# ---------------------------------------------------------------------------

def test_has_llm_set_when_llm_detected():
    proj = _proj_with_reqs("openai>=1.0\n")
    result = DependencyScanner(proj).scan()
    assert result.has_llm is True


def test_has_agent_set_when_framework_detected():
    proj = _proj_with_reqs("langchain>=0.2\n")
    result = DependencyScanner(proj).scan()
    assert result.has_agent is True


def test_has_vector_store_set_when_chromadb_detected():
    proj = _proj_with_reqs("chromadb>=0.4\n")
    result = DependencyScanner(proj).scan()
    assert result.has_vector_store is True


def test_ai_stack_summary_not_empty_when_libs_detected():
    libs = [
        DetectedLibrary(name="openai", version="1.0", vendor="openai", type="llm_client", risk_weight=1.0, source_file="requirements.txt"),
        DetectedLibrary(name="langchain", version="0.2", vendor="langchain", type="agent_framework", risk_weight=1.2, source_file="requirements.txt"),
    ]
    result = DependencyScanResult(project_path=Path("/test"), detected_libraries=libs)
    summary = result.ai_stack_summary
    assert "Openai" in summary or "openai" in summary.lower()


def test_ai_stack_summary_empty_when_no_libs():
    result = DependencyScanResult(project_path=Path("/test"))
    assert result.ai_stack_summary == ""
