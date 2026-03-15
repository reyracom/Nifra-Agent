from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Known AI/LLM library patterns and their classifications
AI_LIBRARY_PATTERNS: dict[str, dict] = {
    # OpenAI ecosystem
    "openai": {"vendor": "openai", "type": "llm_client", "risk_weight": 1.0},
    # LangChain ecosystem
    "langchain": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.2},
    "langchain-core": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.2},
    "langchain-community": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.3},
    "langgraph": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.4},
    # LlamaIndex ecosystem
    "llama-index": {"vendor": "llamaindex", "type": "rag_framework", "risk_weight": 1.2},
    "llama-index-core": {"vendor": "llamaindex", "type": "rag_framework", "risk_weight": 1.2},
    # Anthropic
    "anthropic": {"vendor": "anthropic", "type": "llm_client", "risk_weight": 1.0},
    # Google
    "google-generativeai": {"vendor": "google", "type": "llm_client", "risk_weight": 1.0},
    "vertexai": {"vendor": "google", "type": "llm_client", "risk_weight": 1.0},
    # Microsoft
    "semantic-kernel": {"vendor": "microsoft", "type": "agent_framework", "risk_weight": 1.2},
    # AutoGen / CrewAI (agentic)
    "pyautogen": {"vendor": "microsoft", "type": "agent_framework", "risk_weight": 1.5},
    "autogen": {"vendor": "microsoft", "type": "agent_framework", "risk_weight": 1.5},
    "crewai": {"vendor": "crew", "type": "agent_framework", "risk_weight": 1.5},
    # Cohere
    "cohere": {"vendor": "cohere", "type": "llm_client", "risk_weight": 1.0},
    # Vector stores
    "chromadb": {"vendor": "chroma", "type": "vector_store", "risk_weight": 0.8},
    "pinecone-client": {"vendor": "pinecone", "type": "vector_store", "risk_weight": 0.8},
    "weaviate-client": {"vendor": "weaviate", "type": "vector_store", "risk_weight": 0.8},
    "qdrant-client": {"vendor": "qdrant", "type": "vector_store", "risk_weight": 0.8},
    "faiss-cpu": {"vendor": "meta", "type": "vector_store", "risk_weight": 0.7},
    # Haystack
    "haystack-ai": {"vendor": "deepset", "type": "rag_framework", "risk_weight": 1.2},
}


@dataclass
class DetectedLibrary:
    name: str
    version: Optional[str]
    vendor: str
    type: str  # llm_client | agent_framework | rag_framework | vector_store
    risk_weight: float
    source_file: str


@dataclass
class DependencyScanResult:
    project_path: Path
    detected_libraries: list[DetectedLibrary] = field(default_factory=list)
    has_llm: bool = False
    has_agent: bool = False
    has_rag: bool = False
    has_vector_store: bool = False

    @property
    def ai_stack_summary(self) -> str:
        parts = [lib.vendor.capitalize() for lib in self.detected_libraries]
        return " + ".join(dict.fromkeys(parts))  # deduplicate preserving order


class DependencyScanner:
    """
    Scan project dependency files for AI/LLM library usage.

    Supports:
      - requirements.txt
      - pyproject.toml (project.dependencies)
      - setup.py / setup.cfg (partial)
      - package.json (Node.js)
    """

    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path

    def scan(self) -> DependencyScanResult:
        result = DependencyScanResult(project_path=self.project_path)

        for scanner in [self._scan_requirements_txt, self._scan_pyproject_toml, self._scan_package_json]:
            libs = scanner()
            result.detected_libraries.extend(libs)

        result.has_llm = any(lib.type == "llm_client" for lib in result.detected_libraries)
        result.has_agent = any(lib.type == "agent_framework" for lib in result.detected_libraries)
        result.has_rag = any(lib.type == "rag_framework" for lib in result.detected_libraries)
        result.has_vector_store = any(lib.type == "vector_store" for lib in result.detected_libraries)

        return result

    def _scan_requirements_txt(self) -> list[DetectedLibrary]:
        """Parse requirements.txt (and requirements-*.txt variants)."""
        _MAX_DEP_BYTES = 10 * 1024 * 1024  # 10 MB
        found: list[DetectedLibrary] = []
        patterns = list(self.project_path.rglob("requirements*.txt"))
        for req_file in patterns:
            if any(p in req_file.parts for p in {".venv", "venv", "env", "site-packages"}):
                continue
            try:
                if req_file.stat().st_size > _MAX_DEP_BYTES:
                    continue
                for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Strip version specifiers: package>=1.0,<2.0 → package
                    pkg_name = re.split(r"[><=!~\[\s;]", line)[0].strip().lower()
                    if pkg_name in AI_LIBRARY_PATTERNS:
                        meta = AI_LIBRARY_PATTERNS[pkg_name]
                        # Extract version if present
                        version_match = re.search(r"[><=!~]+\s*([\d.\w]+)", line)
                        version = version_match.group(1) if version_match else None
                        found.append(DetectedLibrary(
                            name=pkg_name,
                            version=version,
                            vendor=meta["vendor"],
                            type=meta["type"],
                            risk_weight=meta["risk_weight"],
                            source_file=str(req_file.relative_to(self.project_path)),
                        ))
            except OSError:
                continue
        return found

    def _scan_pyproject_toml(self) -> list[DetectedLibrary]:
        """Parse pyproject.toml — supports both PEP 621 and Poetry formats."""
        found: list[DetectedLibrary] = []
        toml_file = self.project_path / "pyproject.toml"
        if not toml_file.exists():
            return found
        try:
            try:
                import tomllib  # Python 3.11+
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore
                except ImportError:
                    # Manual TOML parsing fallback
                    return self._scan_pyproject_toml_regex(toml_file)

            with open(toml_file, "rb") as f:
                data = tomllib.load(f)

            deps: list[str] = []
            # PEP 621 format
            deps += data.get("project", {}).get("dependencies", [])
            # Poetry format
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            deps += list(poetry_deps.keys())

            for dep in deps:
                pkg_name = re.split(r"[><=!~\[\s;@]", str(dep))[0].strip().lower()
                if pkg_name in AI_LIBRARY_PATTERNS:
                    meta = AI_LIBRARY_PATTERNS[pkg_name]
                    found.append(DetectedLibrary(
                        name=pkg_name,
                        version=None,
                        vendor=meta["vendor"],
                        type=meta["type"],
                        risk_weight=meta["risk_weight"],
                        source_file="pyproject.toml",
                    ))
        except Exception:
            pass
        return found

    def _scan_pyproject_toml_regex(self, toml_file: Path) -> list[DetectedLibrary]:
        """Fallback regex-based pyproject.toml parser."""
        _MAX_DEP_BYTES = 10 * 1024 * 1024  # 10 MB
        found: list[DetectedLibrary] = []
        try:
            if toml_file.stat().st_size > _MAX_DEP_BYTES:
                return found
            content = toml_file.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(r'["\']([a-zA-Z0-9_\-]+)[><=!~\[\s"\'@]', content):
                pkg_name = match.group(1).lower()
                if pkg_name in AI_LIBRARY_PATTERNS:
                    meta = AI_LIBRARY_PATTERNS[pkg_name]
                    found.append(DetectedLibrary(
                        name=pkg_name,
                        version=None,
                        vendor=meta["vendor"],
                        type=meta["type"],
                        risk_weight=meta["risk_weight"],
                        source_file="pyproject.toml",
                    ))
        except OSError:
            pass
        return found

    def _scan_package_json(self) -> list[DetectedLibrary]:
        """Parse Node.js package.json dependencies."""
        found: list[DetectedLibrary] = []
        NODE_AI_PATTERNS: dict[str, dict] = {
            "openai": {"vendor": "openai", "type": "llm_client", "risk_weight": 1.0},
            "@anthropic-ai/sdk": {"vendor": "anthropic", "type": "llm_client", "risk_weight": 1.0},
            "@langchain/core": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.2},
            "@langchain/openai": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.2},
            "langchain": {"vendor": "langchain", "type": "agent_framework", "risk_weight": 1.2},
            "ai": {"vendor": "vercel", "type": "llm_client", "risk_weight": 1.0},
            "@google/generative-ai": {"vendor": "google", "type": "llm_client", "risk_weight": 1.0},
        }
        for pkg_json in self.project_path.rglob("package.json"):
            if "node_modules" in pkg_json.parts:
                continue
            try:
                if pkg_json.stat().st_size > 10 * 1024 * 1024:
                    continue
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for pkg_name, version in all_deps.items():
                    if pkg_name in NODE_AI_PATTERNS:
                        meta = NODE_AI_PATTERNS[pkg_name]
                        found.append(DetectedLibrary(
                            name=pkg_name,
                            version=str(version).lstrip("^~>="),
                            vendor=meta["vendor"],
                            type=meta["type"],
                            risk_weight=meta["risk_weight"],
                            source_file=str(pkg_json.relative_to(self.project_path)),
                        ))
            except (OSError, json.JSONDecodeError):
                continue
        return found
