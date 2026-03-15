from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
import pytest

from nifra.detectors.ast_parser import AICodePattern, ASTScanResult
from nifra.detectors.dependency_scanner import DependencyScanResult
from nifra.graph.builder import (
    AttackSurfaceGraph,
    AttackSurfaceGraphBuilder,
    _infer_source_type,
    _infer_tool_capability,
    _infer_vendor,
)
from nifra.graph.edges import EdgeInferrer
from nifra.graph.nodes import AgentToolNode, BaseNode, NodeType, TrustLevel

def _dep(path: Path = Path("/fake/app")) -> DependencyScanResult:
    return DependencyScanResult(project_path=path)


def _ast(patterns=None) -> ASTScanResult:
    result = ASTScanResult(project_path=Path("/fake/app"))
    result.patterns = patterns or []
    return result


def _pat(
    pattern_type: str,
    class_or_func: str = "ChatOpenAI",
    file_path: str = "app.py",
    line_number: int = 10,
    extra: dict | None = None,
) -> AICodePattern:
    return AICodePattern(
        pattern_type=pattern_type,
        class_or_func=class_or_func,
        file_path=file_path,
        line_number=line_number,
        context_snippet=f"{class_or_func}()",
        extra=extra or {},
    )


def _simple_surface(nodes=2, edges=1) -> AttackSurfaceGraph:
    g = nx.DiGraph()
    g.add_node("n1", node_type="llm_client", label="ChatOpenAI", source_file="app.py")
    g.add_node("n2", node_type="user_input", label="User Input", source_file=None)
    if edges:
        g.add_edge("n2", "n1")
    return AttackSurfaceGraph(graph=g, project_path=Path("/test"))

class TestAttackSurfaceGraph:
    def test_node_count(self):
        assert _simple_surface().node_count == 2

    def test_edge_count(self):
        assert _simple_surface().edge_count == 1

    def test_node_count_zero_edges(self):
        assert _simple_surface(edges=0).edge_count == 0

    def test_get_nodes_by_type_returns_match(self):
        surface = _simple_surface()
        nodes = surface.get_nodes_by_type(NodeType.LLM_CLIENT)
        assert len(nodes) == 1
        assert nodes[0]["label"] == "ChatOpenAI"

    def test_get_nodes_by_type_no_match(self):
        surface = _simple_surface()
        assert surface.get_nodes_by_type(NodeType.RAG_LOADER) == []

    def test_to_dict_keys(self):
        d = _simple_surface().to_dict()
        assert set(d.keys()) == {"nodes", "edges", "findings"}

    def test_to_dict_node_count(self):
        d = _simple_surface().to_dict()
        assert len(d["nodes"]) == 2

    def test_to_dict_edge_count(self):
        d = _simple_surface().to_dict()
        assert len(d["edges"]) == 1

    def test_to_dict_findings_empty_by_default(self):
        assert _simple_surface().to_dict()["findings"] == []

    def test_to_json_returns_string(self):
        result = _simple_surface().to_json()
        assert isinstance(result, str)

    def test_to_json_is_parseable(self):
        parsed = json.loads(_simple_surface().to_json())
        assert isinstance(parsed, dict)

    def test_to_json_has_nodes(self):
        assert "nodes" in json.loads(_simple_surface().to_json())

    def test_findings_default_empty(self):
        assert _simple_surface().findings == []

class TestInferVendor:
    def test_openai_variants(self):
        for cls in ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "ChatOpenAI"):
            assert _infer_vendor(cls) == "openai"

    def test_anthropic_variants(self):
        for cls in ("ChatAnthropic", "Anthropic", "AsyncAnthropic"):
            assert _infer_vendor(cls) == "anthropic"

    def test_google_variants(self):
        for cls in ("ChatGoogleGenerativeAI", "GoogleGenerativeAI", "ChatVertexAI", "VertexAI"):
            assert _infer_vendor(cls) == "google"

    def test_cohere(self):
        assert _infer_vendor("ChatCohere") == "cohere"

    def test_groq(self):
        assert _infer_vendor("ChatGroq") == "groq"

    def test_mistral(self):
        assert _infer_vendor("ChatMistralAI") == "mistral"

    def test_unknown_returns_unknown(self):
        assert _infer_vendor("MyCustomLLMWrapper") == "unknown"
        assert _infer_vendor("") == "unknown"

class TestInferToolCapability:
    def test_shell_variations(self):
        assert _infer_tool_capability("bash_tool") == "shell"
        assert _infer_tool_capability("run_terminal_command") == "shell"
        assert _infer_tool_capability("subprocess_tool") == "shell"

    def test_code_exec_variations(self):
        assert _infer_tool_capability("python_repl") == "code_exec"
        assert _infer_tool_capability("execute_code") == "code_exec"
        assert _infer_tool_capability("code_interpreter") == "code_exec"

    def test_filesystem_variations(self):
        assert _infer_tool_capability("read_file") == "filesystem"
        assert _infer_tool_capability("write_file") == "filesystem"
        assert _infer_tool_capability("filesystem_tool") == "filesystem"

    def test_database_variations(self):
        assert _infer_tool_capability("sql_query") == "db"
        assert _infer_tool_capability("database_tool") == "db"
        assert _infer_tool_capability("run_sqlite") == "db"

    def test_http_variations(self):
        assert _infer_tool_capability("http_get") == "http"
        assert _infer_tool_capability("web_scraper") == "http"
        assert _infer_tool_capability("fetch_url") == "http"

    def test_email_variations(self):
        assert _infer_tool_capability("send_email") == "email"
        assert _infer_tool_capability("mail_sender") == "email"

    def test_search_variations(self):
        assert _infer_tool_capability("google_search") == "search"
        assert _infer_tool_capability("tavily_search") == "search"
        assert _infer_tool_capability("ddg_searcher") == "search"

    def test_unknown_returns_unknown(self):
        assert _infer_tool_capability("do_nothing_tool") == "unknown"
        assert _infer_tool_capability("") == "unknown"

class TestInferSourceType:
    def test_https_url(self):
        assert _infer_source_type("https://docs.example.com/guide.html") == "url"

    def test_http_url(self):
        assert _infer_source_type("http://internal.corp/api") == "url"

    def test_s3_cloud(self):
        assert _infer_source_type("s3://my-bucket/docs/report.pdf") == "cloud_storage"

    def test_gcs_cloud(self):
        assert _infer_source_type("gs://gcs-bucket/data.txt") == "cloud_storage"

    def test_azure_cloud(self):
        assert _infer_source_type("azure://container/blob") == "cloud_storage"

    def test_pdf_file(self):
        assert _infer_source_type("./docs/quarterly_report.pdf") == "file"

    def test_docx_file(self):
        assert _infer_source_type("/home/user/brief.docx") == "file"

    def test_html_file(self):
        assert _infer_source_type("manual.html") == "file"

    def test_txt_file(self):
        assert _infer_source_type("data.txt") == "file"

    def test_md_file(self):
        assert _infer_source_type("README.md") == "file"

    def test_empty_string_is_unknown(self):
        assert _infer_source_type("") == "unknown"

    def test_generic_path_is_unknown(self):
        assert _infer_source_type("some/unrecognized/path") == "unknown"

class TestEdgeInferrer:
    def test_external_document_to_rag_loader(self):
        g = nx.DiGraph()
        g.add_node("doc1", node_type="external_document", source_file="app.py")
        g.add_node("rag1", node_type="rag_loader", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("doc1", "rag1")

    def test_user_input_to_prompt_template(self):
        g = nx.DiGraph()
        g.add_node("ui1", node_type="user_input", source_file="app.py")
        g.add_node("pt1", node_type="prompt_template", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("ui1", "pt1")

    def test_rag_loader_to_prompt_template(self):
        g = nx.DiGraph()
        g.add_node("rag1", node_type="rag_loader", source_file="app.py")
        g.add_node("pt1", node_type="prompt_template", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("rag1", "pt1")

    def test_prompt_template_to_llm_client(self):
        g = nx.DiGraph()
        g.add_node("pt1", node_type="prompt_template", source_file="app.py")
        g.add_node("llm1", node_type="llm_client", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("pt1", "llm1")

    def test_llm_client_to_agent_executor(self):
        g = nx.DiGraph()
        g.add_node("llm1", node_type="llm_client", source_file="app.py")
        g.add_node("ae1", node_type="agent_executor", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("llm1", "ae1")

    def test_agent_executor_to_agent_tool(self):
        g = nx.DiGraph()
        g.add_node("ae1", node_type="agent_executor", source_file="app.py")
        g.add_node("tool1", node_type="agent_tool", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("ae1", "tool1")

    def test_agent_tool_to_data_sink(self):
        g = nx.DiGraph()
        g.add_node("tool1", node_type="agent_tool", source_file="app.py")
        g.add_node("sink1", node_type="data_sink", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g.has_edge("tool1", "sink1")

    def test_no_duplicate_edges_added(self):
        g = nx.DiGraph()
        g.add_node("doc1", node_type="external_document", source_file="app.py")
        g.add_node("rag1", node_type="rag_loader", source_file="app.py")
        g.add_edge("doc1", "rag1")  # pre-existing
        EdgeInferrer(g).infer_edges()
        assert g.number_of_edges() == 1

    def test_no_self_loops(self):
        g = nx.DiGraph()
        g.add_node("n1", node_type="rag_loader", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert not g.has_edge("n1", "n1")

    def test_same_file_flag_set(self):
        g = nx.DiGraph()
        g.add_node("doc1", node_type="external_document", source_file="app.py")
        g.add_node("rag1", node_type="rag_loader", source_file="app.py")
        EdgeInferrer(g).infer_edges()
        assert g["doc1"]["rag1"]["same_file"] is True

    def test_cross_file_flag_set(self):
        g = nx.DiGraph()
        g.add_node("doc1", node_type="external_document", source_file="loaders.py")
        g.add_node("rag1", node_type="rag_loader", source_file="chain.py")
        EdgeInferrer(g).infer_edges()
        assert g["doc1"]["rag1"]["same_file"] is False

    def test_edge_type_stored(self):
        g = nx.DiGraph()
        g.add_node("doc1", node_type="external_document", source_file="a.py")
        g.add_node("rag1", node_type="rag_loader", source_file="a.py")
        EdgeInferrer(g).infer_edges()
        assert "edge_type" in g["doc1"]["rag1"]

    def test_risk_weight_stored(self):
        g = nx.DiGraph()
        g.add_node("ae1", node_type="agent_executor", source_file="a.py")
        g.add_node("tool1", node_type="agent_tool", source_file="a.py")
        EdgeInferrer(g).infer_edges()
        assert g["ae1"]["tool1"]["risk_weight"] > 0

    def test_empty_graph_no_error(self):
        g = nx.DiGraph()
        EdgeInferrer(g).infer_edges()  # must not raise
        assert g.number_of_edges() == 0

class TestAttackSurfaceGraphBuilderNodes:
    def test_llm_init_creates_llm_client_node(self):
        surface = AttackSurfaceGraphBuilder(_dep(), _ast([_pat("llm_init", "ChatOpenAI")])).build()
        nodes = surface.get_nodes_by_type(NodeType.LLM_CLIENT)
        assert len(nodes) == 1
        assert nodes[0]["label"] == "ChatOpenAI"

    def test_llm_init_sets_vendor(self):
        surface = AttackSurfaceGraphBuilder(_dep(), _ast([_pat("llm_init", "ChatOpenAI")])).build()
        nodes = surface.get_nodes_by_type(NodeType.LLM_CLIENT)
        assert nodes[0]["vendor"] == "openai"

    def test_llm_init_auto_creates_user_input_node(self):
        surface = AttackSurfaceGraphBuilder(_dep(), _ast([_pat("llm_init", "ChatOpenAI")])).build()
        ui_nodes = surface.get_nodes_by_type(NodeType.USER_INPUT)
        assert len(ui_nodes) == 1

    def test_agent_init_creates_agent_executor_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("agent_init", "AgentExecutor", extra={"tools": ["t1", "t2"]})])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.AGENT_EXECUTOR)
        assert len(nodes) == 1
        assert nodes[0]["tool_count"] == 2

    def test_agent_init_auto_creates_user_input_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("agent_init", "AgentExecutor")])
        ).build()
        assert len(surface.get_nodes_by_type(NodeType.USER_INPUT)) == 1

    def test_tool_registration_creates_agent_tool_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("tool_registration", "python_repl", extra={"tool_name": "python_repl"})])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.AGENT_TOOL)
        assert len(nodes) == 1
        assert nodes[0]["tool_name"] == "python_repl"

    def test_tool_registration_code_exec_is_destructive(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("tool_registration", "python_repl", extra={"tool_name": "python_repl"})])
        ).build()
        tool = surface.get_nodes_by_type(NodeType.AGENT_TOOL)[0]
        assert tool["capability"] == "code_exec"
        assert tool["is_destructive"] is True

    def test_tool_registration_search_not_destructive(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("tool_registration", "tavily_search", extra={"tool_name": "tavily_search"})])
        ).build()
        tool = surface.get_nodes_by_type(NodeType.AGENT_TOOL)[0]
        assert tool["is_destructive"] is False

    def test_rag_chain_creates_rag_loader_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("rag_chain", "RetrievalQA")])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.RAG_LOADER)
        assert len(nodes) == 1
        assert nodes[0]["has_content_validation"] is False

    def test_document_loader_creates_external_doc_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("document_loader", "PDFLoader", extra={"source": "https://docs.example.com"})])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.EXTERNAL_DOCUMENT)
        assert len(nodes) == 1

    def test_document_loader_url_source_type(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("document_loader", "PDFLoader", extra={"source": "https://docs.example.com"})])
        ).build()
        doc = surface.get_nodes_by_type(NodeType.EXTERNAL_DOCUMENT)[0]
        assert doc["source_type"] == "url"

    def test_prompt_template_creates_node(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("prompt_template", "SystemMessagePromptTemplate")])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.PROMPT_TEMPLATE)
        assert len(nodes) == 1

    def test_dangerous_sink_creates_data_sink_code_exec(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("dangerous_sink", "eval")])
        ).build()
        sinks = surface.get_nodes_by_type(NodeType.DATA_SINK)
        assert len(sinks) == 1
        assert sinks[0]["sink_type"] == "code_exec"

    def test_vector_store_creates_data_sink_with_pii(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("vector_store_init", "Chroma")])
        ).build()
        sinks = surface.get_nodes_by_type(NodeType.DATA_SINK)
        assert len(sinks) == 1
        assert sinks[0]["contains_pii"] is True
        assert sinks[0]["sink_type"] == "vector_db"

    def test_empty_patterns_no_user_input(self):
        surface = AttackSurfaceGraphBuilder(_dep(), _ast([])).build()
        assert surface.get_nodes_by_type(NodeType.USER_INPUT) == []

    def test_node_id_format(self):
        surface = AttackSurfaceGraphBuilder(
            _dep(), _ast([_pat("llm_init", "ChatOpenAI")])
        ).build()
        nodes = surface.get_nodes_by_type(NodeType.LLM_CLIENT)
        # ID should start with prefix
        ids = [n.get("id", "") for n in surface.to_dict()["nodes"]]
        assert any("llm_" in nid for nid in ids)

class TestAttackSurfaceGraphBuilderRules:
    def test_rag_pipeline_triggers_pi001(self):
        patterns = [
            _pat("document_loader", "PDFLoader"),
            _pat("rag_chain", "RetrievalQA"),
            _pat("llm_init", "ChatOpenAI"),
        ]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        rule_ids = [f.rule_id for f in surface.findings]
        assert "PI-001" in rule_ids

    def test_code_exec_tool_triggers_ta001(self):
        patterns = [
            _pat("tool_registration", "python_repl", extra={"tool_name": "python_repl"}),
        ]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        rule_ids = [f.rule_id for f in surface.findings]
        assert "TA-001" in rule_ids

    def test_dangerous_sink_with_llm_triggers_sc002(self):
        patterns = [
            _pat("dangerous_sink", "eval"),
            _pat("llm_init", "ChatOpenAI"),
        ]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        rule_ids = [f.rule_id for f in surface.findings]
        assert "SC-002" in rule_ids

    def test_vector_store_with_llm_triggers_de001(self):
        patterns = [
            _pat("vector_store_init", "Chroma"),
            _pat("llm_init", "ChatOpenAI"),
        ]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        rule_ids = [f.rule_id for f in surface.findings]
        assert "DE-001" in rule_ids

    def test_empty_patterns_no_findings(self):
        surface = AttackSurfaceGraphBuilder(_dep(), _ast([])).build()
        assert surface.findings == []

    def test_findings_have_valid_severity(self):
        patterns = [_pat("tool_registration", "python_repl", extra={"tool_name": "python_repl"})]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        for f in surface.findings:
            assert f.severity.value in ("critical", "high", "medium", "low", "info")

    def test_findings_have_non_empty_remediation(self):
        patterns = [_pat("tool_registration", "python_repl", extra={"tool_name": "python_repl"})]
        surface = AttackSurfaceGraphBuilder(_dep(), _ast(patterns)).build()
        for f in surface.findings:
            assert len(f.remediation) > 0


# ---------------------------------------------------------------------------
# AgentToolNode.risk_category property
# ---------------------------------------------------------------------------

class TestAgentToolNodeRiskCategory:
    def _make_tool(self, capability: str) -> AgentToolNode:
        return AgentToolNode(
            id="tool_001",
            label="test_tool",
            source_file="app.py",
            tool_name="test_tool",
            capability=capability,
        )

    def test_code_exec_is_critical(self):
        assert self._make_tool("code_exec").risk_category == "critical"

    def test_filesystem_is_critical(self):
        assert self._make_tool("filesystem").risk_category == "critical"

    def test_shell_is_critical(self):
        assert self._make_tool("shell").risk_category == "critical"

    def test_db_is_high(self):
        assert self._make_tool("db").risk_category == "high"

    def test_email_is_high(self):
        assert self._make_tool("email").risk_category == "high"

    def test_http_is_high(self):
        assert self._make_tool("http").risk_category == "high"

    def test_search_is_medium(self):
        assert self._make_tool("search").risk_category == "medium"

    def test_unknown_is_medium(self):
        assert self._make_tool("unknown").risk_category == "medium"


# ---------------------------------------------------------------------------
# BaseNode.to_dict
# ---------------------------------------------------------------------------

class TestBaseNodeToDict:
    def test_to_dict_has_required_keys(self):
        from nifra.graph.nodes import UserInputNode
        node = UserInputNode(id="ui_001", label="User Input", source_file="app.py")
        d = node.to_dict()
        for key in ("id", "label", "node_type", "source_file", "line_number", "trust_level", "risk_weight"):
            assert key in d

    def test_to_dict_node_type_is_string(self):
        from nifra.graph.nodes import UserInputNode
        node = UserInputNode(id="ui_001", label="User Input", source_file=None)
        d = node.to_dict()
        assert isinstance(d["node_type"], str)
        assert d["node_type"] == "user_input"
