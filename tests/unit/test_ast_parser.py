from pathlib import Path
import tempfile
import textwrap

from nifra.detectors.ast_parser import ASTParser
from nifra.detectors.pattern_registry import (
    PATTERN_BY_NAME,
    PATTERN_REGISTRY,
    HIGH_RISK_PATTERNS,
    PatternCategory,
    FrameworkPattern,
)


def _write_temp_py(code: str) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "app.py").write_text(textwrap.dedent(code), encoding="utf-8")
    return tmp


def test_detects_openai_init():
    proj = _write_temp_py("""
        from openai import OpenAI
        client = OpenAI()
    """)
    result = ASTParser(proj).scan()
    assert any(p.pattern_type == "llm_init" and "OpenAI" in p.class_or_func for p in result.patterns)


def test_detects_chatopenai():
    proj = _write_temp_py("""
        from langchain.chat_models import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o")
    """)
    result = ASTParser(proj).scan()
    assert any(p.class_or_func == "ChatOpenAI" for p in result.patterns)


def test_detects_agent_executor():
    proj = _write_temp_py("""
        from langchain.agents import AgentExecutor
        agent = AgentExecutor(agent=a, tools=tools)
    """)
    result = ASTParser(proj).scan()
    assert any(p.pattern_type == "agent_init" for p in result.patterns)


def test_detects_tool_decorator():
    proj = _write_temp_py("""
        from langchain.tools import tool
        @tool
        def search_database(query: str) -> str:
            return ""
    """)
    result = ASTParser(proj).scan()
    assert any(p.pattern_type == "tool_registration" for p in result.patterns)


def test_detects_dangerous_sink():
    proj = _write_temp_py("""
        result = eval(llm_output)
    """)
    result = ASTParser(proj).scan()
    assert any(p.pattern_type == "dangerous_sink" for p in result.patterns)


def test_skips_venv():
    proj = _write_temp_py("")
    venv_dir = proj / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "evil.py").write_text("exec('rm -rf /')", encoding="utf-8")
    result = ASTParser(proj).scan()
    # .venv should be skipped
    assert not any(".venv" in p.file_path for p in result.patterns)


# ---------------------------------------------------------------------------
# PatternRegistry
# ---------------------------------------------------------------------------

def test_pattern_registry_is_non_empty():
    assert len(PATTERN_REGISTRY) > 0


def test_pattern_by_name_lookup_openai():
    p = PATTERN_BY_NAME["OpenAI"]
    assert p.vendor == "openai"
    assert p.category == PatternCategory.LLM_CLIENT


def test_pattern_by_name_lookup_agent_executor():
    p = PATTERN_BY_NAME["AgentExecutor"]
    assert p.category == PatternCategory.AGENT_FRAMEWORK
    assert p.risk_multiplier >= 1.4


def test_pattern_by_name_lookup_retrieval_qa():
    p = PATTERN_BY_NAME["RetrievalQA"]
    assert p.category == PatternCategory.RAG_FRAMEWORK


def test_high_risk_patterns_contains_agent_executor():
    assert "AgentExecutor" in HIGH_RISK_PATTERNS


def test_high_risk_patterns_threshold_is_1_4():
    for name in HIGH_RISK_PATTERNS:
        assert PATTERN_BY_NAME[name].risk_multiplier >= 1.4


def test_pattern_categories_are_valid_enum_values():
    valid = {c.value for c in PatternCategory}
    for p in PATTERN_REGISTRY:
        assert p.category.value in valid


def test_framework_pattern_is_frozen():
    """FrameworkPattern must be immutable (frozen dataclass)."""
    p = PATTERN_BY_NAME["ChatOpenAI"]
    import pytest
    with pytest.raises((AttributeError, TypeError)):
        p.vendor = "changed"  # type: ignore


def test_pattern_registry_all_have_positive_risk_multiplier():
    for p in PATTERN_REGISTRY:
        assert p.risk_multiplier > 0


def test_all_category_types_represented():
    categories = {p.category for p in PATTERN_REGISTRY}
    # At minimum these core categories must exist
    assert PatternCategory.LLM_CLIENT in categories
    assert PatternCategory.AGENT_FRAMEWORK in categories
    assert PatternCategory.RAG_FRAMEWORK in categories
